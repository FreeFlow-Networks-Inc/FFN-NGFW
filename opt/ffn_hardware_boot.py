#!/usr/bin/env python3
"""MP-owned boot discovery and ordered activation of installed platform owners.

Only a locally provisioned platform manifest can name services. No executable
code is fetched/imported from discovery results or supplied through the WebUI.
"""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import subprocess
import sys
import time

CONFIG = Path('/etc/ffn-ngfw/hardware-boot.json')
STATE = Path('/var/lib/ffn-ngfw/hardware-boot/state.json')
BOOT_ID = Path('/proc/sys/kernel/random/boot_id')


def fingerprint(inventory):
    system = inventory.get('system', {})
    identity = {k: system.get(k, '') for k in ('vendor', 'product', 'board', 'arch')}
    identity['pci'] = sorted((d.get('address'), d.get('vendor_id'), d.get('device_id'))
                             for d in inventory.get('pci', {}).get('devices', []))
    return hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()


def validate_profile(profile):
    if profile.get('schema') != 1 or not re.fullmatch(r'[a-z][a-z0-9-]+', profile.get('platform', '')):
        raise ValueError('Unsupported boot profile')
    match = profile['match']
    if not match.get('products') or not match.get('pci_required') or not match.get('architectures'):
        raise ValueError('Boot profile needs explicit MP hardware identities')
    if not 1 <= len(profile['steps']) <= 32:
        raise ValueError('Invalid service graph')
    names = set()
    for step in profile['steps']:
        if (not re.fullmatch(r'[a-z0-9-]+', step['id']) or step['id'] in names or
                step['plane'] not in ('mp', 'cp', 'dp') or
                not re.fullmatch(r'[A-Za-z0-9@_.-]+\.service', step['unit']) or
                type(step['timeout']) is not int or not 1 <= step['timeout'] <= 1800):
            raise ValueError('Invalid boot step')
        if any(dep not in names for dep in step.get('after', [])):
            raise ValueError('Boot dependencies must precede their consumers')
        names.add(step['id'])
    for role, paths in profile['acknowledgments'].items():
        if role not in ('cp', 'dp') or not isinstance(paths, list):
            raise ValueError('Invalid plane acknowledgment requirements')
        if any(not re.fullmatch(r'[a-zA-Z0-9_.]+', path) for path in paths):
            raise ValueError('Invalid acknowledgment path')
    if set(profile['acknowledgments']) != {'cp', 'dp'}:
        raise ValueError('Both CP and DP acknowledgments required')


def matches(profile, inventory, enrolled=None):
    validate_profile(profile)
    system, pci = inventory.get('system', {}), inventory.get('pci', {})
    match = profile['match']
    if system.get('os') != 'Linux' or system.get('arch') not in match['architectures']:
        return False
    if pci.get('source') != 'sysfs' or not pci.get('available'):
        return False
    ids = [d.get('vendor_id', '') + ':' + d.get('device_id', '') for d in pci.get('devices', [])
           if d.get('identity_complete') and not d.get('physical_function')]
    if any(ids.count(key) < count for key, count in match['pci_required'].items()):
        return False
    return (system.get('product', '').strip().upper() in [p.upper() for p in match['products']]
            or (enrolled is not None and fingerprint(inventory) == enrolled))


def select(config, inventory):
    if config.get('schema') != 1 or not isinstance(config.get('platforms'), list) or len(config['platforms']) > 16:
        raise ValueError('Invalid installed boot configuration')
    found = []
    for entry in config.get('platforms', []):
        path = Path(entry['profile'])
        if not path.is_absolute():
            raise ValueError('Boot profile path must be absolute')
        profile = json.loads(path.read_text())
        if matches(profile, inventory, entry.get('enrolled_identity')):
            found.append((entry, profile))
    if len(found) > 1:
        raise ValueError('Ambiguous hardware: multiple installed boot profiles match')
    if found:
        return found[0]
    return None


def acknowledgments(profile, control, max_age=None):
    result, errors = {}, []
    for role, paths in profile['acknowledgments'].items():
        agents = [a for a in control.get('agents', {}).values() if a.get('role') == role and
                  (a.get('last_observation') or {}).get('platform') == profile['platform']]
        if len(agents) != 1:
            errors.append(role + ': expected one matching agent')
            continue
        agent = agents[0]
        age, ttl = agent.get('age_seconds'), agent.get('stale_after_seconds')
        valid = all(type(v) in (int, float) and math.isfinite(v) and v >= 0 for v in (age, ttl))
        if (not valid or not agent.get('fresh') or not agent.get('connected') or age >= ttl or
                (max_age is not None and age > max_age)):
            errors.append(role + ': waiting for a fresh acknowledgment')
            continue
        sample = agent['last_observation']
        if not sample.get('boot_id') or sample.get('report', {}).get('boot_id') != sample['boot_id']:
            errors.append(role + ': boot identity missing or inconsistent')
            continue
        for path in ['ready'] + paths:
            value = sample.get('report', {})
            for key in path.split('.'):
                value = value.get(key) if isinstance(value, dict) else None
            if value is not True:
                errors.append(role + ': ' + path + ' not acknowledged')
        result[role] = sample['boot_id']
    return result, errors


def write_state(path, state):
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix('.new')
    with temp.open('w') as f:
        json.dump(state, f, indent=2)
        f.flush()
        os.fsync(f.fileno())
    temp.chmod(0o644)
    temp.replace(path)


class Services:
    def __init__(self, transports):
        self.transports = transports

    def command(self, plane, arguments):
        command = ['/usr/bin/systemctl', *arguments]
        if plane == 'mp':
            return command
        transport = self.transports[plane]
        path, host = transport['ssh_config'], transport['host']
        if (not Path(path).is_absolute() or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*', host)):
            raise ValueError('Invalid provisioned SSH transport')
        # SSH config owns credentials, host keys and any CP-to-DP proxy path.
        return ['/usr/bin/ssh', '-F', path, '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
                '-o', 'ConnectTimeout=5', '-o', 'ServerAliveInterval=5', '-o', 'ServerAliveCountMax=2',
                host, *command]

    def show(self, step):
        result = subprocess.run(self.command(step['plane'], ['show', step['unit'],
            '--property=LoadState,ActiveState,SubState,Type,Result,ExecMainStatus,ExecMainExitTimestampMonotonic']),
            capture_output=True, text=True, check=True, timeout=20)
        return dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)

    def start(self, step):
        subprocess.run(self.command(step['plane'], ['start', '--no-block', step['unit']]),
                       capture_output=True, check=True, timeout=20)


def service_ready(observed):
    if observed.get('ActiveState') == 'active':
        return True
    # Existing successful oneshots without RemainAfterExit are completed work,
    # not services to re-run. A never-started unit has exit timestamp zero.
    return (observed.get('ActiveState') == 'inactive' and observed.get('Type') == 'oneshot' and
            observed.get('Result') == 'success' and observed.get('ExecMainStatus') == '0' and
            str(observed.get('ExecMainExitTimestampMonotonic', '')).isdigit() and
            int(observed['ExecMainExitTimestampMonotonic']) > 0)


def orchestrate(config, inventory, boot_id, state_path=STATE, services=None, observe=None,
                clock=time.monotonic, sleep=time.sleep):
    """Caller serializes this MP worker; a submitted start is never replayed this boot."""
    state = {'schema': 1, 'owner': 'mp', 'mp_boot_id': boot_id, 'phase': 'detected',
             'hardware_ready': False, 'forwarding_verified': False, 'steps': {}}
    prior = json.loads(state_path.read_text()) if state_path.exists() else {}
    if prior.get('mp_boot_id') == boot_id:
        state['steps'] = prior.get('steps', {})
    try:
        selected = select(config, inventory)
    except Exception as error:
        state.update(phase='failed', error=str(error))
        write_state(state_path, state)
        raise
    if not selected:
        special = inventory.get('accelerators') or inventory.get('specialized', {}).get('octeon', {}).get('present')
        reliable = inventory.get('pci', {}).get('available') and inventory.get('pci', {}).get('source') == 'sysfs'
        state.update(phase='unsupported' if special or not reliable else 'generic',
                     reason='No matching installed CP/DP boot profile')
        write_state(state_path, state)
        return state
    entry, profile = selected
    state.update(platform=profile['platform'], requirements=profile['acknowledgments'])
    state['profile_digest'] = hashlib.sha256(json.dumps([entry, profile], sort_keys=True).encode()).hexdigest()
    if observe is None:
        from ffn_controld_client import ControldClient
        observe = ControldClient(timeout=10).control_status
    if prior.get('mp_boot_id') == boot_id:
        if (prior.get('profile_digest') == state['profile_digest'] and
                prior.get('platform') == profile['platform'] and prior.get('phase') == 'ready'):
            ids, errors = acknowledgments(profile, observe())
            if errors or ids != prior.get('plane_boot_ids'):
                return dict(prior, phase='degraded', hardware_ready=False,
                            waiting_for=errors or ['Plane boot identity changed'])
            return prior
        if prior.get('steps'):
            raise RuntimeError('This MP boot already attempted hardware startup; inspect status before recovery')
    services = services or Services(entry.get('transports', {}))
    try:
        # Optional downloads are stage-only. Existing commissioned boot owners
        # remain usable without Internet; no new release is activated here.
        lock = Path(entry['profile']).with_name('plane-images.json')
        if lock.exists():
            from ffn_plane_images import stage
            try:
                state['images'] = stage(json.loads(lock.read_text()), offline=True)
            except (ValueError, OSError) as error:
                state['images'] = {'state': 'not-cached', 'error': str(error)}
        for step in profile['steps']:
            state['phase'] = 'starting'
            state['current_step'] = step['id']
            observed = services.show(step)
            if observed.get('LoadState') != 'loaded' or observed.get('ActiveState') == 'failed':
                raise RuntimeError(step['id'] + ': service missing or failed; explicit recovery required')
            state['steps'][step['id']] = {'plane': step['plane'], 'unit': step['unit'], 'state': 'observed'}
            if not service_ready(observed) and observed.get('ActiveState') != 'activating':
                state['steps'][step['id']]['state'] = 'start-submitted'
                write_state(state_path, state)  # Persist intent BEFORE any side effect.
                services.start(step)
            deadline = clock() + step['timeout']
            while not service_ready(observed):
                if clock() >= deadline or observed.get('ActiveState') == 'failed':
                    raise RuntimeError(step['id'] + ': startup not acknowledged')
                sleep(1)
                observed = services.show(step)
            state['steps'][step['id']]['state'] = 'active'
            write_state(state_path, state)
        state['phase'] = 'waiting-agents'
        write_state(state_path, state)
        since, deadline = clock(), clock() + 120
        stable = None
        while clock() < deadline:
            ids, errors = acknowledgments(profile, observe(), max_age=clock() - since)
            if not errors:
                if stable == ids:
                    state.update(phase='ready', hardware_ready=True, plane_boot_ids=ids)
                    state.pop('current_step', None)
                    state.pop('waiting_for', None)
                    write_state(state_path, state)
                    return state
                stable = ids
            else:
                stable = None
            state['waiting_for'] = errors or ['Confirming stable plane boot identities']
            write_state(state_path, state)
            sleep(2)
        raise RuntimeError('Hardware agents did not acknowledge required readiness')
    except Exception as error:
        state.update(phase='failed', error=str(error), hardware_ready=False)
        write_state(state_path, state)
        raise


def status(control=None, path=STATE, boot_path=BOOT_ID):
    try:
        state = json.loads(path.read_text())
        if state.get('mp_boot_id') != boot_path.read_text().strip():
            return {'phase': 'stale', 'hardware_ready': False, 'owner': 'mp'}
        if state.get('phase') == 'ready':
            profile = {'platform': state['platform'], 'acknowledgments': state['requirements']}
            ids, errors = acknowledgments(profile, control or {})
            if errors or ids != state.get('plane_boot_ids'):
                state.update(phase='degraded', hardware_ready=False,
                             waiting_for=errors or ['Plane boot identity changed; recovery acknowledgment required'])
        return state
    except (OSError, ValueError, KeyError, TypeError):
        return {'phase': 'unavailable', 'hardware_ready': False, 'owner': 'mp'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('plan', 'run', 'status'))
    parser.add_argument('--config', type=Path, default=CONFIG)
    args = parser.parse_args()
    if args.action == 'status':
        from ffn_controld_client import ControldClient
        print(json.dumps(ControldClient().query('state/hardware-boot'), indent=2))
        return
    from ffn_hwdetect import detect
    inventory = detect()
    config = json.loads(args.config.read_text())
    if args.action == 'plan':
        match = select(config, inventory)
        print(json.dumps({'owner': 'mp', 'profile': match[1] if match else None}, indent=2))
        return
    import fcntl
    if os.geteuid() != 0:
        raise SystemExit('MP root execution required')
    for path in [args.config, *[Path(e['profile']) for e in config.get('platforms', [])]]:
        st = path.stat()
        if st.st_uid != 0 or st.st_mode & 0o022:
            raise SystemExit('Boot configuration must be root-owned and not group/world writable')
    STATE.parent.mkdir(parents=True, exist_ok=True)
    with STATE.with_suffix('.lock').open('w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        result = orchestrate(config, inventory, BOOT_ID.read_text().strip())
        print(json.dumps(result, indent=2))
        if result['phase'] not in ('ready', 'generic'):
            raise SystemExit(1)


if __name__ == '__main__':
    main()
