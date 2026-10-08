#!/usr/bin/env python3
"""Configuration convergence: did the committed configuration reach every subsystem?

After each processor boot the lifecycle supervisor replays the committed
configuration through configd (`ffn-lifecycle-reconcile`); its receipt proves
that configd accepted the replay. This module proves the effect, subsystem by
subsystem, from the running configuration and live observations:

  committed-replay       the replay receipt belongs to this MP boot and the
                         current CP/DP boots, reached `applied`, and its
                         generation is the running configuration;
  faceplate              every configured front port is enabled or disabled
                         as committed and holds the committed speed (module
                         resolved for optics);
  aggregates             every committed aggregate is active and applied at
                         the running revision;
  interface-management   the interface management profiles are enforced on
                         the dataplane (ffn_ifmgmt_audit);
  security-runtime       the Security collector publishes a fresh health record;
  management-access      the MP's interface-service tunnel is running and the
                         dataplane front end reports its channel ready, so the
                         management profiles' listeners reach the manager.

States per subsystem: converged, drift, failed, pending, unavailable. The
overall state is the worst of them. Nothing here changes anything; `reapply`
starts the lifecycle's own replay unit and reports that it did.
"""
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from xml.etree import ElementTree as ET

sys.path.insert(0, '/usr/local/lib/ffn')

CONFIG = Path('/var/lib/ffn-ngfw/config/running-config.xml')
RECEIPT = Path('/var/lib/ffn/lifecycle/reconcile-result.json')
REQUEST = Path('/var/lib/ffn/lifecycle/reconcile-request.json')
LIFECYCLE = Path('/run/ffn-lifecycle/mp.json')
LIFECYCLE_JOURNAL = Path('/var/lib/ffn/lifecycle/mp.json')
BOOT_ID = Path('/proc/sys/kernel/random/boot_id')
HEALTH = '/run/ffn-security-health.json'   # on the dataplane, where the Security collector runs
REPLAY_UNIT = 'ffn-lifecycle-reconcile.service'
HEALTH_FRESH_SECONDS = 30
HEALTH_SPLIT = 'FFN_CONVERGENCE_HEALTH_SPLIT'
# One dataplane round trip: the record, the DP's own clock to judge its age by, and the DP boot it must belong to.
HEALTH_COLLECT = 'cat %s 2>/dev/null; echo %s; cat /proc/uptime; cat /proc/sys/kernel/random/boot_id' % (HEALTH, HEALTH_SPLIT)
RANK = {'converged': 0, 'unavailable': 1, 'pending': 2, 'drift': 3, 'failed': 4}


def read_json(path):
    try:
        return json.loads(Path(path).read_text())
    except (OSError, ValueError):
        return None


def generation(path=CONFIG):
    try:
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()
    except OSError:
        return None


def subsystem(name, plane, state, summary, details=(), **extra):
    if state not in RANK:
        raise ValueError('unknown convergence state')
    return dict(id=name, plane=plane, state=state, summary=summary, details=list(details), **extra)


# ---------------------------------------------------------------- committed replay
def processor_boots(lifecycle):
    """Current CP/DP boot identities as the supervisor recorded them."""
    for source in lifecycle:
        value = read_json(source) if source else None
        if isinstance(value, dict) and isinstance(value.get('processor_boots'), dict):
            return value['processor_boots']
    return None


def replay(receipt, mp_boot, boots, current_generation):
    if receipt is None:
        return subsystem('committed-replay', 'mp', 'pending', 'No replay receipt for this boot yet',
                         ['the lifecycle supervisor has not replayed the committed configuration'])
    details = []
    if receipt.get('mp_boot_id') != mp_boot:
        return subsystem('committed-replay', 'mp', 'pending', 'Replay receipt is from a previous MP boot',
                         ['receipt boot ' + str(receipt.get('mp_boot_id'))[:8] + ', current ' + str(mp_boot)[:8]])
    if boots is not None and receipt.get('processor_boots') != boots:
        return subsystem('committed-replay', 'mp', 'pending', 'CP or DP booted after the last replay',
                         ['receipt boots ' + json.dumps(receipt.get('processor_boots')) + ', current ' + json.dumps(boots)])
    state = receipt.get('state')
    if state == 'applying':
        return subsystem('committed-replay', 'mp', 'pending', 'Replay in progress', [])
    if state == 'failed':
        return subsystem('committed-replay', 'mp', 'failed', 'Replay failed: ' + str(receipt.get('reason'))[:200],
                         [str(e)[:200] for e in (receipt.get('apply') or {}).get('errors', [])][:8])
    if state != 'applied':
        return subsystem('committed-replay', 'mp', 'failed', 'Replay receipt in unknown state ' + str(state))
    if receipt.get('config_sha256') != current_generation:
        return subsystem('committed-replay', 'mp', 'drift', 'Running configuration changed since the replay',
                         ['replayed ' + str(receipt.get('config_sha256'))[:12] + ', running ' + str(current_generation)[:12],
                          'a commit applies the change; a reapply replays all of it'])
    outcome = receipt.get('apply') or {}
    if outcome.get('errors'):
        details = [str(e)[:200] for e in outcome['errors']][:8]
        return subsystem('committed-replay', 'mp', 'failed', 'Replay applied with errors', details)
    return subsystem('committed-replay', 'mp', 'converged', 'Committed configuration replayed for the current boots',
                     ['generation ' + str(current_generation)[:12]], generation=current_generation)


# ---------------------------------------------------------------- faceplate
def device(root):
    devices = root.findall('./devices/entry')
    if len(devices) != 1:
        raise ValueError('One local device configuration required')
    return devices[0]


def faceplate_expectations(root):
    """Per front port: enabled and speed as the committed configuration requires."""
    entries = device(root).findall('./network/interface/ethernet/entry')
    members = set()
    for entry in entries:
        if entry.findtext('aggregate-group'):
            match = re.fullmatch(r'ethernet1/(\d+)', entry.get('name', ''))
            if match:
                members.add(int(match[1]))
    expected = {}
    for entry in entries:
        match = re.fullmatch(r'ethernet1/(\d+)', entry.get('name', ''))
        if not match:
            continue
        port = int(match[1])
        configured = entry.find('layer3') is not None or port in members
        state = entry.findtext('link-state', 'auto')
        expected[port] = dict(interface=entry.get('name'), enabled=configured and state != 'down',
                              speed=entry.findtext('link-speed', 'auto'), member=port in members,
                              configured=configured)
    return expected


def faceplate(root, status):
    if not isinstance(status, dict) or not isinstance(status.get('ports'), list):
        return subsystem('faceplate', 'cp', 'unavailable', 'Faceplate state is not observable',
                         [str((status or {}).get('error', 'no faceplate resource'))[:200]])
    expected = faceplate_expectations(root)
    ports = {p.get('port'): p for p in status['ports'] if isinstance(p, dict)}
    drift, pending, notes = [], [], []
    for port, want in sorted(expected.items()):
        if not want['configured']:
            continue
        row = ports.get(port)
        if row is None or not row.get('available'):
            pending.append('%s: port not available on the control plane' % want['interface'])
            continue
        if row.get('media') == 'sfp' and not row.get('optics'):
            # The transmitter and module could not be read this time (cage I2C);
            # neither the administrative state nor the speed can be judged.
            pending.append('%s: SFP cage state not observable' % want['interface'])
            continue
        if row.get('enabled') is None:
            pending.append('%s: administrative state unknown' % want['interface'])
        elif bool(row.get('enabled')) != want['enabled']:
            drift.append('%s: %s, committed %s' % (want['interface'], 'enabled' if row.get('enabled') else 'disabled',
                                                   'enabled' if want['enabled'] else 'disabled'))
        if want['member'] or not row.get('speed_configuration'):
            continue
        acceptable = {want['speed']}
        module = row.get('module') or {}
        if row.get('media') == 'sfp' and module.get('optical') and module.get('speeds') == [1000]:
            # 1000BASE-X with Clause 37 reads back as auto until the switch
            # daemon restarts with the 1000BASE-X readback rule.
            acceptable |= {'1000', 'auto'}
        if row.get('configured_speed') not in acceptable:
            drift.append('%s: speed %s, committed %s' % (want['interface'], row.get('configured_speed'), want['speed']))
        if want['enabled'] and row.get('link') is False:
            notes.append('%s: enabled, link down' % want['interface'])
    if drift:
        return subsystem('faceplate', 'cp', 'drift', '%d front port(s) differ from the committed configuration' % len(drift),
                         drift + pending + notes)
    if pending:
        return subsystem('faceplate', 'cp', 'pending', '%d front port(s) not yet observable' % len(pending), pending + notes)
    count = sum(1 for w in expected.values() if w['configured'])
    return subsystem('faceplate', 'cp', 'converged', '%d configured front port(s) match' % count, notes)


# ---------------------------------------------------------------- aggregates
def aggregates(root, status):
    configured = [e.get('name') for e in device(root).findall('./network/interface/aggregate-ethernet/entry')
                  if e.find('layer3') is not None or e.find('./units') is not None]
    if not configured:
        return subsystem('aggregates', 'dp', 'converged', 'No aggregates committed')
    if not isinstance(status, dict) or not isinstance(status.get('aggregates'), list):
        return subsystem('aggregates', 'dp', 'unavailable', 'Aggregate state is not observable',
                         [str((status or {}).get('error', 'no aggregate resource'))[:200]])
    rows = {r.get('ae_name'): r for r in status['aggregates'] if isinstance(r, dict)}
    drift, pending = [], []
    for name in configured:
        row = rows.get(name)
        if row is None:
            pending.append(name + ': not observed by the aggregate owner')
            continue
        if row.get('applied') is True:
            continue
        blockers = [str(b.get('message') or b.get('code')) for b in row.get('blockers', []) if isinstance(b, dict)]
        (pending if row.get('state') in ('negotiating', 'inactive', None) and not row.get('committed') is False else drift).append(
            '%s: %s%s' % (name, row.get('state', 'unknown'), ('; ' + '; '.join(blockers[:3])) if blockers else ''))
    if drift:
        return subsystem('aggregates', 'dp', 'drift', '%d aggregate(s) not applied at the running revision' % len(drift), drift + pending)
    if pending:
        return subsystem('aggregates', 'dp', 'pending', '%d aggregate(s) not yet active' % len(pending), pending)
    return subsystem('aggregates', 'dp', 'converged', '%d aggregate(s) applied' % len(configured))


# ---------------------------------------------------------------- interface management
def interface_management(root, views):
    if views is None:
        return subsystem('interface-management', 'dp', 'unavailable', 'Dataplane enforcement is not observable',
                         ['no dataplane relay for the interface-management audit'])
    try:
        import ffn_ifmgmt_audit as audit
        ruleset, published, boot = views
        report = audit.audit(root, ruleset, published, boot)
    except Exception as error:
        return subsystem('interface-management', 'dp', 'unavailable', 'Interface-management audit failed',
                         [str(error)[:200]])
    if report['consistent']:
        return subsystem('interface-management', 'dp', 'converged',
                         '%d managed interface(s) enforced as committed' % len(report['interfaces']))
    codes = sorted({f['code'] for f in report['findings']})
    stale = {'published-missing', 'published-stale', 'table-missing'}
    state = 'pending' if set(codes) <= stale else 'drift'
    details = ['%s %s: %s' % (f['code'], f.get('interface') or f.get('device') or '-', f['detail']) for f in report['findings']][:12]
    return subsystem('interface-management', 'dp', state, '%d finding(s): %s' % (len(report['findings']), ', '.join(codes)), details)


# ---------------------------------------------------------------- security runtime
def parse_health(output):
    """(record, dp uptime seconds, dp boot id) from the HEALTH_COLLECT output; the record is None when absent."""
    head, marker, tail = output.partition(HEALTH_SPLIT)
    if not marker:
        raise ValueError('dataplane health collection returned no marker')
    lines = [line.strip() for line in tail.strip().splitlines() if line.strip()]
    if len(lines) < 2:
        raise ValueError('dataplane health collection returned no uptime or boot id')
    uptime = float(lines[0].split()[0])
    try:
        record = json.loads(head)
    except ValueError:
        record = None
    return (record if isinstance(record, dict) else None), uptime, lines[1]


def security_runtime(record, uptime, dp_boot):
    """The Security collector's own record, read on the dataplane: it stamps the DP boot and the DP monotonic
    clock, so its age is judged against the DP's uptime, never against the management plane's clock."""
    if not isinstance(record, dict):
        return subsystem('security-runtime', 'dp', 'unavailable', 'Security collector health is not published',
                         ['no ' + HEALTH + ' on the dataplane'])
    if record.get('boot_id') != dp_boot:
        return subsystem('security-runtime', 'dp', 'pending', 'Security collector health is from another dataplane boot')
    try:
        age = max(0.0, float(uptime) - float(record.get('monotonic')))
    except (TypeError, ValueError):
        return subsystem('security-runtime', 'dp', 'pending', 'Security collector health carries no clock')
    if age > HEALTH_FRESH_SECONDS:
        return subsystem('security-runtime', 'dp', 'pending', 'Security collector health is stale (%d s)' % age)
    events = record.get('events') if isinstance(record.get('events'), dict) else {}
    faults = [str(f)[:200] for f in (record.get('error'), events.get('error')) if f]
    if faults:
        return subsystem('security-runtime', 'dp', 'failed', 'Security collector reports a fault', faults)
    if not record.get('collector_ready') or not events.get('ready'):
        return subsystem('security-runtime', 'dp', 'pending', 'Security collector is not ready',
                         ['collector_ready=%s events.ready=%s' % (record.get('collector_ready'), events.get('ready'))])
    return subsystem('security-runtime', 'dp', 'converged', 'Security collector healthy',
                     ['forwarding revision %s' % record.get('forwarding_revision')])


# ---------------------------------------------------------------- management access
TUNNEL_UNIT = 'ffn-interface-service-tunnel.service'
# Services the manager itself provides through the tunnel; a profile may permit
# others (user-id, response pages, SNMP) that this appliance has no provider for.
CORE_SERVICES = {('tcp', 22), ('tcp', 443), ('tcp', 8443)}
DP_SERVICES_STATUS = '/run/ffn-interface-services/status.json'


def unit_active(unit=TUNNEL_UNIT, run=subprocess.run):
    try:
        result = run(['systemctl', 'is-active', unit], capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return None
    return result.stdout.strip() or None


def management_access(tunnel_state, dp_status, now):
    """The profile listeners on the dataplane reach the manager only through the
    MP-owned tunnel; a stopped tunnel accepts every connection and drops it."""
    if tunnel_state is None:
        return subsystem('management-access', 'mp', 'unavailable', 'Interface-service tunnel state unknown')
    if tunnel_state != 'active':
        return subsystem('management-access', 'mp', 'drift', 'Interface-service tunnel is ' + tunnel_state,
                         ['dataplane listeners accept connections but cannot reach the manager',
                          'start ' + TUNNEL_UNIT + '; a control-daemon restart stops it'])
    if not isinstance(dp_status, dict):
        return subsystem('management-access', 'dp', 'unavailable', 'Dataplane service status is not observable',
                         ['tunnel active; ' + DP_SERVICES_STATUS + ' unreadable'])
    services = [s for s in dp_status.get('services', []) if isinstance(s, dict)]
    if not dp_status.get('channel_ready'):
        return subsystem('management-access', 'dp', 'pending', 'Dataplane service channel not ready',
                         ['%d profile listener(s) waiting for the upstream channel' % len(services)])
    unverified = [s for s in services if not s.get('provider_listening')]
    core = [s for s in unverified if (s.get('protocol'), s.get('port')) in CORE_SERVICES]
    notes = ['%s %s/%d: no provider on this appliance' % (s.get('interface'), s.get('protocol'), s.get('port', 0))
             for s in unverified if s not in core]
    if core:
        return subsystem('management-access', 'dp', 'pending', '%d management listener(s) without a verified provider' % len(core),
                         ['%s %s/%d: %s' % (s.get('interface'), s.get('protocol'), s.get('port', 0), s.get('state')) for s in core][:8] + notes[:8])
    return subsystem('management-access', 'dp', 'converged',
                     '%d profile listener(s) reach the manager' % (len(services) - len(unverified)), notes[:8])


# ---------------------------------------------------------------- assessment
def overall(subsystems):
    return max((s['state'] for s in subsystems), key=lambda s: RANK[s], default='unavailable')


def assess(config_path=CONFIG, receipt_path=RECEIPT, lifecycle=(LIFECYCLE, LIFECYCLE_JOURNAL), boot_id_path=BOOT_ID,
           dp_health=None, resources=None, dp_views=None, clock=time.time, tunnel=None, dp_status=None):
    """resources: {('faceplate','status'): result-or-None, ('aggregate','status'): ...};
    dp_health: callable returning (record, dp uptime, dp boot id) for the Security collector, or None;
    dp_views: callable returning (ruleset, published, boot_id) for the interface audit, or None;
    tunnel: callable returning the tunnel unit's systemd state, or None to skip the access check;
    dp_status: callable returning the dataplane front end's status record, or None."""
    resources = resources or {}
    now = clock()
    try:
        root = ET.parse(config_path).getroot()
    except (OSError, ET.ParseError) as error:
        return dict(schema=1, checked_at=now, overall='unavailable', generation=None,
                    subsystems=[subsystem('committed-replay', 'mp', 'unavailable', 'Running configuration unreadable', [str(error)[:200]])],
                    actions=[])
    current = generation(config_path)
    try:
        mp_boot = Path(boot_id_path).read_text().strip()
    except OSError:
        mp_boot = None
    boots = processor_boots(lifecycle)
    subsystems = [replay(read_json(receipt_path), mp_boot, boots, current)]
    for check, key in ((faceplate, ('faceplate', 'status')), (aggregates, ('aggregates', 'status'))):
        try:
            subsystems.append(check(root, resources.get(key)))
        except Exception as error:
            subsystems.append(subsystem(check.__name__, 'cp' if check is faceplate else 'dp', 'unavailable',
                                        check.__name__ + ' check failed', [str(error)[:200]]))
    views = None
    if dp_views is not None:
        try:
            views = dp_views()
        except Exception as error:
            subsystems.append(subsystem('interface-management', 'dp', 'unavailable', 'Dataplane collection failed', [str(error)[:200]]))
    if dp_views is None or views is not None:
        subsystems.append(interface_management(root, views))
    if dp_health is not None:
        try:
            subsystems.append(security_runtime(*dp_health()))
        except Exception as error:
            subsystems.append(subsystem('security-runtime', 'dp', 'unavailable', 'Dataplane health collection failed', [str(error)[:200]]))
    else:
        subsystems.append(security_runtime(None, None, None))
    if tunnel is not None:
        status = None
        try:
            status = dp_status() if dp_status is not None else None
        except Exception:
            status = None
        subsystems.append(management_access(tunnel(), status, now))
    state = overall(subsystems)
    actions = ['reapply'] if any(s['state'] in ('drift', 'failed') for s in subsystems) else []
    return dict(schema=1, checked_at=now, overall=state, generation=current, mp_boot_id=mp_boot, processor_boots=boots,
                subsystems=subsystems, actions=actions)


def reapply(request_path=REQUEST, lifecycle=(LIFECYCLE, LIFECYCLE_JOURNAL), boot_id_path=BOOT_ID, unit=REPLAY_UNIT,
            run=subprocess.run):
    """Start the lifecycle's replay unit for the current boots; never fabricate a request."""
    request = read_json(request_path)
    try:
        mp_boot = Path(boot_id_path).read_text().strip()
    except OSError:
        mp_boot = None
    boots = processor_boots(lifecycle)
    if not isinstance(request, dict) or request.get('mp_boot_id') != mp_boot:
        return dict(started=False, reason='no replay request for this MP boot; the lifecycle supervisor issues it after the planes boot')
    if boots is not None and request.get('processor_boots') != boots:
        return dict(started=False, reason='the replay request is for other CP/DP boots; wait for the supervisor')
    try:
        result = run(['systemctl', 'start', '--no-block', unit], capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.SubprocessError) as error:
        return dict(started=False, reason='could not start ' + unit + ': ' + str(error)[:200])
    if result.returncode:
        return dict(started=False, reason=(result.stderr or result.stdout or 'systemctl failed').strip()[:300])
    return dict(started=True, unit=unit, processor_boots=boots)


def main(argv=None):
    import argparse
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--json', action='store_true')
    parser.add_argument('--no-planes', action='store_true', help='skip the control-plane resources and the dataplane audit')
    args = parser.parse_args(argv)
    resources, views = {}, None
    if not args.no_planes:
        try:
            sys.path.insert(0, '/opt/ffn-ngfw')
            from ffn_controld_client import get
            import uuid
            client = get()
            for key in (('faceplate', 'status'), ('aggregates', 'status')):
                answer = client.plane_request({'v': 1, 'id': str(uuid.uuid4()), 'resource': key[0], 'action': key[1], 'payload': {}})
                resources[key] = answer.get('result') if isinstance(answer, dict) and answer.get('ok') else {'error': str((answer or {}).get('error'))}
        except Exception as error:
            resources = {('faceplate', 'status'): {'error': str(error)}, ('aggregates', 'status'): {'error': str(error)}}
        try:
            import ffn_ifmgmt_audit as audit
            if Path('/etc/ffn-ngfw/ssh-cp.conf').exists():
                views = lambda: audit.collect(audit.run_dp)
        except ImportError:
            views = None
    status = health = None
    if views is not None:
        import ffn_ifmgmt_audit as audit
        status = lambda: json.loads(audit.run_dp('cat ' + DP_SERVICES_STATUS))
        health = lambda: parse_health(audit.run_dp(HEALTH_COLLECT))
    report = assess(resources=resources, dp_views=views, tunnel=None if args.no_planes else unit_active, dp_status=status,
                    dp_health=health)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print('overall: ' + report['overall'] + '   generation ' + str(report.get('generation'))[:12])
        for s in report['subsystems']:
            print('  %-22s %-4s %-11s %s' % (s['id'], s['plane'], s['state'], s['summary']))
            for d in s['details']:
                print('      - ' + d)
    return 0 if report['overall'] == 'converged' else 1


if __name__ == '__main__':
    sys.exit(main())
