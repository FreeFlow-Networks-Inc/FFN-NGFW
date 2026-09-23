#!/usr/bin/env python3
"""Install the MP boot owner for a locally selected, commissioned platform.

Enables next-boot detection. Never starts/stops/restarts the running hardware.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'opt'))
from ffn_hardware_boot import fingerprint, matches, validate_profile, Services
from ffn_hwdetect import detect


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--platform', required=True, type=Path)
    p.add_argument('--transports', required=True, type=Path,
                   help='JSON cp/dp SSH config paths and host aliases, never passwords')
    p.add_argument('--enroll-hardware', action='store_true',
                   help='Bind an explicitly selected platform to this MP PCI/DMI fingerprint when DMI has no model')
    a = p.parse_args()
    if os.name != 'posix' or os.geteuid() != 0:
        raise SystemExit('Run on the Linux management plane as root')
    profile = json.loads((a.platform / 'boot.json').read_text())
    validate_profile(profile)
    if json.loads((a.platform / 'platform.json').read_text())['platform'] != profile['platform']:
        raise SystemExit('Platform declaration does not match boot profile')
    inventory = detect()
    identity = fingerprint(inventory) if a.enroll_hardware else None
    if not matches(profile, inventory, identity):
        raise SystemExit('Selected module does not match this MP hardware; nothing installed')
    transports = json.loads(a.transports.read_text())
    service = Services(transports)
    for plane in ('cp', 'dp'):
        service.command(plane, ['show', 'ffn-plane@'+plane+'.service'])
        if not Path(transports[plane]['ssh_config']).is_file():
            raise SystemExit('Provision the pinned SSH transport first: '+plane)
    units = profile.get('mp_boot_units', [])
    for unit in units:
        step = next((s for s in profile['steps'] if s['plane']=='mp' and s['unit']==unit), None)
        if step is None or service.show(step).get('LoadState') != 'loaded':
            raise SystemExit('Commission the existing MP boot service before enrolling it')
    backup = Path('/var/backups/ffn/hardware-boot-'+str(time.time_ns()))
    def install(source, target, text=None):
        target = Path(target)
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            saved = backup / target.relative_to('/')
            saved.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(target, saved)
        tmp = target.with_suffix(target.suffix+'.new')
        if text is None:
            shutil.copyfile(source, tmp)
        else:
            tmp.write_text(text)
        tmp.chmod(0o644)
        tmp.replace(target)
    destination = Path('/etc/ffn-ngfw/platforms') / profile['platform']
    install(a.platform / 'boot.json', destination / 'boot.json')
    lock = a.platform / 'plane-images.json'
    if lock.exists():
        install(lock, destination / lock.name)
    for name in ('ffn_hardware_boot.py', 'ffn_hwdetect.py', 'ffn_hwprobe.py',
                 'ffn_plane_images.py', 'ffn_controld_client.py'):
        install(ROOT / 'opt' / name, Path('/usr/local/lib/ffn') / name)
    entry = {'profile': str(destination / 'boot.json'), 'transports': transports}
    if identity:
        entry['enrolled_identity'] = identity
    install(None, '/etc/ffn-ngfw/hardware-boot.json', json.dumps({'schema':1,'platforms':[entry]}, indent=2)+'\n')
    install(ROOT / 'systemd/ffn-hardware-boot.service', '/etc/systemd/system/ffn-hardware-boot.service')
    install(None, '/etc/systemd/system/ffn-configd.service.d/40-hardware-boot.conf',
            '[Unit]\nRequires=ffn-hardware-boot.service\nAfter=ffn-hardware-boot.service\n')
    subprocess.run(['systemctl', 'daemon-reload'], check=True)
    # Remove independent multi-user startup so detection runs before OCTEON.
    # No --now: the running service and dataplane remain untouched.
    for unit in units:
        subprocess.run(['systemctl', 'disable', unit], check=True)
    subprocess.run(['systemctl', 'enable', 'ffn-hardware-boot.service'], check=True)
    print(json.dumps({'installed':True, 'owner':'mp', 'effective':'next boot',
                      'platform':profile['platform'], 'backup':str(backup),
                      'running_hardware_changed':False, 'reboot_required_now':False}))


if __name__ == '__main__':
    main()
