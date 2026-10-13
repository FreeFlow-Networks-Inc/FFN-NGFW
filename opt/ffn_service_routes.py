#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Service routes: which interface the firewall's own services leave through.

PAN-OS semantics: the management plane's services (DNS, NTP, updates, email,
syslog, LDAP, RADIUS, SNMP traps) use the MGT port unless a service route
names a dataplane interface, in which case that service's traffic leaves the
dataplane interface with that interface's address, exempt from the security
policy as traffic the firewall itself originated.

Committed tree (PAN-OS shape, under the local device):

    deviceconfig/system/route/service/entry[@name=SERVICE]/source/
        interface   a layer3 faceplate interface (ethernet1/N, aeN, subinterfaces)
        address     one of that interface's static IPv4 addresses (default: its first)

How a routed service reaches the dataplane on this chassis: the MP sends it
over the internal PCIe link (MP 127.1.1.1 -> CP 127.1.1.2 -> DP 127.1.2.2);
the CP forwards it (ffn-service-route-forward.service, platform); the DP's
root namespace hands it to the forwarding namespace over a veth pair
(svcrt0 127.1.3.1 <-> svcrt1 127.1.3.2), where policy routing picks the
configured egress interface and source translation gives it the configured
address. Returns retrace the path. The MP only needs policy-routing rules
keyed by the service's ports (a default route in a dedicated table).

Dataplane intent, applied through the platform's `service-routes` plane
resource like the DHCP server's (`/etc/ffn/service-routes.json`):

    {"revision": N, "configuration": "<commit digest>",
     "routes": {SERVICE: {"interface": "ethernet1/5", "device": "p5",
                          "address": "203.0.113.10", "ports": [["tcp", 443]]}}}

Command line: status | validate | apply (JSON on stdin) | boot (re-install the
stored intent) on the DP; mp-status | mp-apply (JSON on stdin) | mp-boot on the MP.
"""
import ipaddress
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

SERVICES = {
    'dns': dict(label='DNS', ports=[('udp', 53), ('tcp', 53)]),
    'ntp': dict(label='NTP', ports=[('udp', 123)]),
    'updates': dict(label='FFN updates (HTTPS)', ports=[('tcp', 443)]),
    'email': dict(label='Email', ports=[('tcp', 25), ('tcp', 465), ('tcp', 587)]),
    'syslog': dict(label='Syslog', ports=[('udp', 514), ('tcp', 514), ('tcp', 6514)]),
    'ldap': dict(label='LDAP', ports=[('tcp', 389), ('tcp', 636)]),
    'radius': dict(label='RADIUS', ports=[('udp', 1812), ('udp', 1813)]),
    'snmp-trap': dict(label='SNMP trap', ports=[('udp', 162)]),
}
DEVICE = re.compile(r'(p[1-9][0-9]{0,2}|ae[1-9][0-9]{0,2})(\.[1-9][0-9]{0,3})?\Z')

# Internal addressing of the management-plane path (the PCIe transport's own
# addresses, plus the dataplane's veth pair).
MP_ADDRESS = '127.1.1.1'
MP_DEVICE = 'ffnnet0'
MP_NEXT_HOP = '127.1.1.2'
CP_ADDRESS_TO_DP = '127.1.2.1'
DP_CP_DEVICE = 'ffndp0'
LINK_ROOT_DEVICE = 'svcrt0'
LINK_DATA_DEVICE = 'svcrt1'
LINK_ROOT_ADDRESS = '127.1.3.1'
LINK_DATA_ADDRESS = '127.1.3.2'
LINK_PREFIX = 30
NAMESPACE = os.environ.get('FFN_SERVICE_ROUTES_NAMESPACE', 'ffn-data')   # the override exists for an integration run on a build host
TABLE = 100               # MP and DP root namespace: "towards the dataplane"
RULE_BASE = 1000          # MP rule preferences
DATA_RULE_BASE = 2000     # forwarding-namespace rule preferences
DATA_TABLE_BASE = 200     # forwarding-namespace per-egress-interface tables
DATA_TABLE_SPAN = 32      # at most this many distinct egress interfaces
RULE_SPAN = 100
NFT_TABLE = 'ffn_service_routes'
INTENT = Path(os.environ.get('FFN_SERVICE_ROUTES_INTENT', '/etc/ffn/service-routes.json'))
RUN = Path(os.environ.get('FFN_SERVICE_ROUTES_RUN', '/run/ffn-service-routes'))
MP_INTENT = Path(os.environ.get('FFN_SERVICE_ROUTES_MP_INTENT', '/etc/ffn-ngfw/service-routes.json'))


# ---------------------------------------------------------------- the committed tree
def local_device(root):
    return next((e for e in root.findall('devices/entry') if e.get('name') == 'localhost.localdomain'), None)


def configured(root):
    """{service: {'interface': logical name, 'address': text or ''}} from the committed tree; ValueError on a bad entry."""
    device = local_device(root)
    result = {}
    if device is None:
        return result
    for entry in device.findall('deviceconfig/system/route/service/entry'):
        name = entry.get('name', '')
        if name not in SERVICES:
            raise ValueError('service route %r: unknown service (known: %s)' % (name, ', '.join(sorted(SERVICES))))
        interface = (entry.findtext('source/interface') or '').strip()
        if not interface:
            continue   # an entry without a source uses the management interface
        result[name] = dict(interface=interface, address=(entry.findtext('source/address') or '').strip())
    return result


def compile_intent(root):
    """{'routes': {service: {interface, device, address, ports}}} for the committed tree; ValueError names a bad entry."""
    from ffn_dhcp_intent import dp_device, interface_inventory
    wanted = configured(root)
    routes = {}
    if not wanted:
        return dict(routes=routes)
    inventory = interface_inventory(root)
    for service, source in sorted(wanted.items()):
        what = 'service route %s' % service
        info = inventory.get(source['interface'])
        if info is None:
            raise ValueError('%s: %s is not a layer3 dataplane interface in the configuration' % (what, source['interface']))
        if info.get('dhcp_client'):
            raise ValueError('%s: %s takes its address from DHCP; a static address is required' % (what, source['interface']))
        own = [str(ipaddress.ip_interface(a).ip) for a in info['addresses'] if ipaddress.ip_interface(a).version == 4]
        if not own:
            raise ValueError('%s: %s has no static IPv4 address' % (what, source['interface']))
        address = source['address'] or own[0]
        if address not in own:
            raise ValueError('%s: %s is not an address of %s' % (what, address, source['interface']))
        try:
            device = dp_device(source['interface'])
        except ValueError as error:
            raise ValueError('%s: %s' % (what, error))
        routes[service] = dict(interface=source['interface'], device=device, address=address,
                               ports=[[proto, port] for proto, port in SERVICES[service]['ports']])
    return dict(routes=routes)


def validate_intent(request):
    """The dataplane's own rules for an intent; the normalised routes or ValueError."""
    if not isinstance(request, dict) or not isinstance(request.get('routes'), dict):
        raise ValueError('intent must carry a routes object')
    routes = {}
    for service, spec in request['routes'].items():
        what = 'service route %s' % service
        if service not in SERVICES or not isinstance(spec, dict):
            raise ValueError(what + ': unknown service or invalid entry')
        device = spec.get('device')
        if not isinstance(device, str) or not DEVICE.fullmatch(device):
            raise ValueError(what + ': device must be a dataplane device')
        try:
            address = str(ipaddress.IPv4Address(spec.get('address')))
        except (ValueError, TypeError):
            raise ValueError(what + ': address must be an IPv4 address')
        ports = spec.get('ports')
        if (not isinstance(ports, list) or not ports or len(ports) > 16 or
                any(not isinstance(p, list) or len(p) != 2 or p[0] not in ('tcp', 'udp') or type(p[1]) is not int or not 1 <= p[1] <= 65535 for p in ports)):
            raise ValueError(what + ': ports are [protocol, port] pairs')
        routes[service] = dict(interface=str(spec.get('interface', ''))[:63], device=device, address=address, ports=[[p[0], p[1]] for p in ports])
    return routes


def intent_digest(routes):
    import hashlib
    return hashlib.sha256(json.dumps(routes, sort_keys=True).encode()).hexdigest()


# ---------------------------------------------------------------- kernel helpers
def run(argv, check=True, ns=None, input_text=None):
    if ns:
        argv = ['ip', 'netns', 'exec', ns] + list(argv)
    result = subprocess.run(list(argv), capture_output=True, text=True, timeout=30, input=input_text)
    if check and result.returncode:
        raise RuntimeError('%s: %s' % (' '.join(argv[:4]), (result.stderr or result.stdout).strip()[-300:]))
    return result.stdout


def ip(*args, ns=None, as_json=False, check=True):
    argv = ['ip'] + (['-j'] if as_json else []) + (['-n', ns] if ns else []) + list(args)
    out = run(argv, check=check)
    return json.loads(out or '[]') if as_json else out


def sysctl(name, value, ns=None):
    run(['sysctl', '-q', '-w', '%s=%s' % (name, value)], ns=ns, check=False)


def atomic(path, value):
    path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + '.' + str(os.getpid()) + '.tmp')
    temporary.write_text(json.dumps(value, sort_keys=True))
    temporary.chmod(0o644)
    temporary.replace(path)


def boot_id():
    try:
        return Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    except OSError:
        return None


def read_intent(path=INTENT):
    try:
        value = json.loads(path.read_text())
        if type(value.get('revision')) is not int:
            raise ValueError('revision')
        return value
    except (OSError, ValueError, AttributeError):
        return dict(revision=0, routes={})


def rules_in_span(base, ns=None):
    """Our rule preferences, as (pref, rule) pairs."""
    return [(r.get('priority'), r) for r in ip('rule', 'show', ns=ns, as_json=True) if type(r.get('priority')) is int and base <= r['priority'] < base + RULE_SPAN]


def clear_rules(base, ns=None):
    for pref, _ in rules_in_span(base, ns):
        while rules_in_span(base, ns) and any(p == pref for p, _ in rules_in_span(base, ns)):
            ip('rule', 'del', 'pref', str(pref), ns=ns, check=False)


def egress_gateway(device, ns=NAMESPACE):
    """(gateway or None, onlink) for the device's default route in the main table, else the first gateway route."""
    routes = ip('route', 'show', 'dev', device, ns=ns, as_json=True)
    for row in routes:
        if row.get('dst') == 'default' and row.get('gateway'):
            return row['gateway'], 'onlink' in (row.get('flags') or [])
    for row in routes:
        if row.get('gateway'):
            return row['gateway'], 'onlink' in (row.get('flags') or [])
    return None, False


# ---------------------------------------------------------------- dataplane
def ensure_link():
    """The veth pair between the DP's root namespace and the forwarding namespace, addressed and up."""
    root_links = {r['ifname'] for r in ip('link', 'show', as_json=True)}
    data_links = {r['ifname'] for r in ip('link', 'show', ns=NAMESPACE, as_json=True)}
    if LINK_ROOT_DEVICE not in root_links or LINK_DATA_DEVICE not in data_links:
        if LINK_ROOT_DEVICE in root_links:
            ip('link', 'del', LINK_ROOT_DEVICE)
        if LINK_DATA_DEVICE in data_links:
            ip('link', 'del', LINK_DATA_DEVICE, ns=NAMESPACE)
        ip('link', 'add', LINK_ROOT_DEVICE, 'type', 'veth', 'peer', 'name', LINK_DATA_DEVICE, 'netns', NAMESPACE)
    ip('addr', 'replace', '%s/%d' % (LINK_ROOT_ADDRESS, LINK_PREFIX), 'dev', LINK_ROOT_DEVICE)
    ip('addr', 'replace', '%s/%d' % (LINK_DATA_ADDRESS, LINK_PREFIX), 'dev', LINK_DATA_DEVICE, ns=NAMESPACE)
    ip('link', 'set', LINK_ROOT_DEVICE, 'up')
    ip('link', 'set', LINK_DATA_DEVICE, 'up', ns=NAMESPACE)
    # 127/8 is routable only where the kernel is told so; the internal transport already relies on it
    for device in (LINK_ROOT_DEVICE, DP_CP_DEVICE):
        sysctl('net.ipv4.conf.%s.route_localnet' % device, 1)
        sysctl('net.ipv4.conf.%s.rp_filter' % device, 0)
    sysctl('net.ipv4.conf.all.rp_filter', 0)
    sysctl('net.ipv4.ip_forward', 1)
    sysctl('net.ipv4.conf.%s.route_localnet' % LINK_DATA_DEVICE, 1, ns=NAMESPACE)
    sysctl('net.ipv4.conf.%s.rp_filter' % LINK_DATA_DEVICE, 0, ns=NAMESPACE)
    # root namespace: service traffic from the MP goes into the forwarding namespace; replies go back to the CP
    ip('route', 'replace', '127.1.1.0/24', 'via', CP_ADDRESS_TO_DP, 'dev', DP_CP_DEVICE)
    if not any(r.get('src') == MP_ADDRESS and r.get('table') == str(TABLE) for _, r in rules_in_span(TABLE)):
        clear_rules(TABLE)
        ip('rule', 'add', 'pref', str(TABLE), 'from', MP_ADDRESS, 'iif', DP_CP_DEVICE, 'lookup', str(TABLE))
    ip('route', 'replace', 'default', 'via', LINK_DATA_ADDRESS, 'dev', LINK_ROOT_DEVICE, 'table', str(TABLE))
    # forwarding namespace: the way back to the MP
    ip('route', 'replace', '127.1.1.0/24', 'via', LINK_ROOT_ADDRESS, 'dev', LINK_DATA_DEVICE, ns=NAMESPACE)


def install(routes):
    """Policy routing and source translation in the forwarding namespace for the given routes."""
    ensure_link()
    devices = sorted({spec['device'] for spec in routes.values()})
    if len(devices) > DATA_TABLE_SPAN:
        raise ValueError('service routes name more than %d egress interfaces' % DATA_TABLE_SPAN)
    tables = {device: DATA_TABLE_BASE + i for i, device in enumerate(devices)}
    clear_rules(DATA_RULE_BASE, NAMESPACE)
    for i in range(DATA_TABLE_SPAN):
        ip('route', 'flush', 'table', str(DATA_TABLE_BASE + i), ns=NAMESPACE, check=False)
    problems = []
    for device, table in tables.items():
        gateway, onlink = egress_gateway(device)
        argv = ['route', 'replace', 'default'] + (['via', gateway] if gateway else []) + ['dev', device, 'table', str(table)] + (['onlink'] if onlink else [])
        try:
            ip(*argv, ns=NAMESPACE)
        except RuntimeError as error:
            problems.append('%s: %s' % (device, str(error)[-160:]))
    pref = DATA_RULE_BASE
    for service in sorted(routes):
        spec = routes[service]
        for proto, port in spec['ports']:
            ip('rule', 'add', 'pref', str(pref), 'from', MP_ADDRESS, 'ipproto', proto, 'dport', str(port), 'lookup', str(tables[spec['device']]), ns=NAMESPACE)
            pref += 1
    lines = []
    seen = set()
    for service in sorted(routes):
        spec = routes[service]
        key = (spec['device'], spec['address'])
        if key in seen:
            continue
        seen.add(key)
        lines.append('  ip saddr %s oifname "%s" snat to %s' % (MP_ADDRESS, spec['device'], spec['address']))
    existing = run(['nft', 'list', 'table', 'ip', NFT_TABLE], ns=NAMESPACE, check=False)
    script = ('delete table ip %s\n' % NFT_TABLE) if existing.strip() else ''
    if lines:
        script += 'table ip %s {\n chain postrouting {\n  type nat hook postrouting priority srcnat - 10; policy accept;\n%s\n }\n}\n' % (NFT_TABLE, '\n'.join(lines))
    if script:
        run(['nft', '-f', '-'], ns=NAMESPACE, input_text=script)
    return dict(tables=tables, problems=problems)


def link_index():
    rows = ip('link', 'show', LINK_DATA_DEVICE, ns=NAMESPACE, as_json=True, check=False) if True else []
    return rows[0]['ifindex'] if rows else None


def publish(intent, extra=None):
    status = dict(schema=1, boot_id=boot_id(), revision=intent['revision'], configuration=intent.get('configuration'),
                  routes=intent.get('routes', {}), link=dict(device=LINK_DATA_DEVICE, index=link_index(), address=MP_ADDRESS),
                  applied_at=time.time(), **(extra or {}))
    atomic(RUN / 'status.json', status)
    return status


def running_status():
    try:
        value = json.loads((RUN / 'status.json').read_text())
    except (OSError, ValueError):
        return None
    if value.get('boot_id') != boot_id():
        return None
    live = dict(link_index=link_index(), rules=len(rules_in_span(DATA_RULE_BASE, NAMESPACE)),
                nft=bool(run(['nft', 'list', 'table', 'ip', NFT_TABLE], ns=NAMESPACE, check=False).strip()))
    value['live'] = live
    return value


def status():
    intent = read_intent()
    return dict(config=dict(revision=intent['revision'], configuration=intent.get('configuration'), routes=intent.get('routes', {}),
                            digest=intent_digest(intent.get('routes', {}))), boot_id=boot_id(), running=running_status())


def apply(request, clock=time.time):
    if not isinstance(request, dict) or set(request) - {'revision', 'routes', 'configuration'}:
        raise ValueError('apply takes revision, routes and configuration')
    current = read_intent()
    if type(request.get('revision')) is not int or request['revision'] != current['revision']:
        raise ValueError('revision conflict; refresh status')
    routes = validate_intent(request)
    intent = dict(revision=current['revision'] + 1, configuration=request.get('configuration'), applied_at=clock(), routes=routes)
    atomic(INTENT, intent)
    result = install(routes)
    publish(intent, dict(tables=result['tables'], problems=result['problems']))
    return status()


def boot():
    """Re-install the stored intent after a boot or a network-owner restart (the DP unit)."""
    intent = read_intent()
    result = install(validate_intent(intent) if intent.get('routes') else {})
    publish(intent, dict(tables=result['tables'], problems=result['problems']))
    return status()


# ---------------------------------------------------------------- management plane
def mp_apply(routes):
    """Policy-routing rules on the MP: the routed services' ports leave through the internal link."""
    sysctl('net.ipv4.conf.%s.route_localnet' % MP_DEVICE, 1)
    ip('route', 'replace', 'default', 'via', MP_NEXT_HOP, 'dev', MP_DEVICE, 'src', MP_ADDRESS, 'table', str(TABLE))
    clear_rules(RULE_BASE)
    pref = RULE_BASE
    for service in sorted(routes):
        for proto, port in routes[service]['ports']:
            ip('rule', 'add', 'pref', str(pref), 'ipproto', proto, 'dport', str(port), 'lookup', str(TABLE))
            pref += 1
    atomic(MP_INTENT, dict(routes=routes, applied_at=time.time()))
    return mp_status()


def mp_status():
    rules = [dict(pref=p, proto=r.get('ipproto'), dport=r.get('dport')) for p, r in rules_in_span(RULE_BASE)]
    table = ip('route', 'show', 'table', str(TABLE), as_json=True, check=False)
    try:
        stored = json.loads(MP_INTENT.read_text()).get('routes', {})
    except (OSError, ValueError, AttributeError):
        stored = {}
    return dict(rules=rules, table=table, routes=stored, digest=intent_digest(stored))


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    action = argv[0] if argv else 'status'
    try:
        if action == 'status':
            result = status()
        elif action == 'boot':
            result = boot()
        elif action == 'mp-status':
            result = mp_status()
        elif action == 'mp-boot':
            try:
                stored = json.loads(MP_INTENT.read_text()).get('routes', {})
            except (OSError, ValueError, AttributeError):
                stored = {}
            result = mp_apply(validate_intent(dict(routes=stored)))
        elif action in ('validate', 'apply', 'mp-apply'):
            data = sys.stdin.buffer.read((1 << 20) + 1)
            if len(data) > (1 << 20):
                raise ValueError('request exceeds 1 MiB')
            request = json.loads(data) if data.strip() else {}
            if action == 'validate':
                result = dict(validated=True, services=sorted(validate_intent(request)))
            elif action == 'apply':
                result = apply(request)
            else:
                result = mp_apply(validate_intent(request))
        else:
            raise SystemExit('usage: ffn_service_routes.py status|validate|apply|boot|mp-status|mp-apply|mp-boot')
    except (ValueError, OSError, RuntimeError) as error:
        print(json.dumps({'error': str(error)[:512]}))
        return 2
    print(json.dumps(result))
    return 0


if __name__ == '__main__':
    sys.exit(main())
