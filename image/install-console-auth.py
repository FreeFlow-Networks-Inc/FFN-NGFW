#!/usr/bin/env python3
"""Configure FFN database-backed SSH identities while preserving Linux root login."""
import argparse
import grp
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
sys.path.insert(0,'/opt/ffn-ngfw-v2')


def pam_rules(kind):
    helper='/usr/bin/python3 /opt/ffn-ngfw/ffn_pam_console.py'
    extra=' expose_authtok' if kind=='auth' else ''
    return ('# FFN database administrators; nonmembers retain Linux authentication\n'
            +kind+' [success=ignore default=1] pam_succeed_if.so quiet user ingroup ffn-console\n'
            +kind+' [success=done default=die] pam_exec.so quiet'+extra+' '+helper+'\n')


def merge_pam(source):
    for kind,anchor in [('auth','@include common-auth'),('account','@include common-account')]:
        rules=pam_rules(kind)
        if rules in source:continue
        if source.count(anchor)!=1:raise ValueError('Unexpected SSH PAM stack')
        source=source.replace(anchor,rules+anchor)
    return source


def merge_nss(source):
    lines=source.splitlines(keepends=True);found=False
    for index,line in enumerate(lines):
        if line.startswith('passwd:'):
            found=True
            if 'extrausers' not in line.split('#')[0].split():
                config,sep,comment=line.rstrip('\n').partition('#')
                lines[index]=config.rstrip()+' extrausers'+(' #'+comment if sep else '')+'\n'
    if not found:raise ValueError('Missing passwd NSS service')
    return ''.join(lines)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--database',required=True,type=Path)
    args=parser.parse_args()
    if os.getuid()!=0:raise SystemExit('Root required')
    subprocess.run(['dpkg-query','-W','libnss-extrausers'],check=True,stdout=subprocess.DEVNULL)
    try:grp.getgrnam('ffn-console')
    except KeyError:subprocess.run(['groupadd','--system','ffn-console'],check=True)
    from ffn_console_accounts import sync
    result=sync(str(args.database))
    for name in result['local_cli_users']:
        subprocess.run(['usermod','-a','-G','ffn-console',name],check=True)
    targets={'/etc/nsswitch.conf':merge_nss(Path('/etc/nsswitch.conf').read_text()),
             '/etc/pam.d/sshd':merge_pam(Path('/etc/pam.d/sshd').read_text()),
             '/etc/ssh/sshd_config.d/50-ffn-console.conf':
             'Match Group ffn-console\n    DisableForwarding yes\n    PermitUserRC no\n    X11Forwarding no\nMatch all\n',
             '/etc/systemd/system/ffn-managementd.service.d/50-console-identities.conf':
             '[Service]\nEnvironment=FFN_CONSOLE_IDENTITIES=1\n'}
    backup=Path('/var/backups/ffn/console-auth-'+str(time.time_ns()));backup.mkdir(parents=True)
    existed={}
    for name,text in targets.items():
        path=Path(name);path.parent.mkdir(parents=True,exist_ok=True);existed[name]=path.exists()
        if path.exists():
            saved=backup/path.relative_to('/');saved.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(path,saved)
        temp=path.with_name(path.name+'.ffn-new');temp.write_text(text);temp.chmod(0o644);temp.replace(path)
    try:subprocess.run(['sshd','-t'],check=True)
    except Exception:
        for name,was_present in existed.items():
            path=Path(name)
            if was_present:shutil.copy2(backup/path.relative_to('/'),path)
            else:path.unlink(missing_ok=True)
        raise
    (backup/'manifest.json').write_text(json.dumps(existed))
    subprocess.run(['systemctl','daemon-reload'],check=True)
    subprocess.run(['systemctl','restart','ffn-managementd'],check=True)
    subprocess.run(['systemctl','reload','ssh'],check=True)
    print(json.dumps({'backup':str(backup),**result}))


if __name__=='__main__':main()
