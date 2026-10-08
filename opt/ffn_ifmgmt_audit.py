#!/usr/bin/env python3
"""Detect drift between committed interface management profiles and their enforcement.

Three views of every Layer 3 interface:

* expected: what the committed configuration requires, built with the same
  `ffn_interface_management.profile` the dataplane uses (services, permitted
  sources) plus the interface's addresses;
* published: what the dataplane network owner recorded as enforced
  (`/run/ffn-interface-profiles/<device>.json`), bound to the DP boot it was
  written in;
* live: what the dataplane firewall holds now (`nft -j list ruleset`, tables
  `ffn_ifmgmt_<device>`).

Differences are findings with a code; nothing is changed. Exit status 0 means
every view agrees, 1 means findings, 2 means the audit could not run.
"""
import argparse
import ipaddress
import json
import re
import subprocess
import sys
from xml.etree import ElementTree as ET

sys.path.insert(0, '/usr/local/lib/ffn')
import ffn_interface_management as management

PROFILE_DIR = '/run/ffn-interface-profiles'
NAMESPACE = 'ffn-data'
SPLIT = 'FFN_IFMGMT_AUDIT_SPLIT'
DP = ['ssh', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes', '-o', 'ConnectTimeout=5',
      '-o', 'UserKnownHostsFile=/etc/ffn-ngfw/plane_boot_known_hosts',
      '-o', 'ProxyCommand=ssh -F /etc/ffn-ngfw/ssh-cp.conf -W %h:%p ffn-cp', 'root@127.1.2.2']
# Every rule the generator emits besides the per-address service accepts.
BASELINE = ('iifname-return', 'invalid-drop', 'established-accept', 'icmp-errors', 'icmpv6-errors',
            'neighbor-discovery', 'dhcp4', 'dhcp6', 'final-drop')
ICMP_ERRORS = ['destination-unreachable', 'parameter-problem', 'time-exceeded']
ICMPV6_ERRORS = ['destination-unreachable', 'packet-too-big', 'parameter-problem', 'time-exceeded']
NEIGHBOR_DISCOVERY = ['nd-neighbor-advert', 'nd-neighbor-solicit', 'nd-router-advert']


def device_name(interface):
    """Linux device of a firewall interface: ethernet1/N is pN, others keep their name."""
    match = re.fullmatch(r'ethernet1/(\d+)((?:\.\d+)?)', interface)
    if match:
        return 'p' + match[1] + match[2]
    if re.fullmatch(r'ae\d+(?:\.\d+)?', interface):
        return interface
    return None


def address_objects(root, device):
    """ip-netmask address objects: shared first, then device and virtual-system scopes."""
    objects = {}
    containers = [root.find('./shared/address'), device.find('./address')]
    containers += [vsys.find('./address') for vsys in device.findall('./vsys/entry')]
    for container in containers:
        if container is None:
            continue
        for entry in container.findall('./entry'):
            value = entry.findtext('ip-netmask')
            if value:
                objects[entry.get('name')] = value.strip()
    return objects


def resolve_addresses(layer3, objects):
    addresses, unresolved = [], []
    for entry in layer3.findall('./ip/entry'):
        name = entry.get('name') or ''
        value = objects.get(name, name)
        try:
            addresses.append(str(ipaddress.ip_interface(value)))
        except ValueError:
            unresolved.append(name)
    return addresses, unresolved


def expected(root):
    """Per Linux device: the configuration's requirement, or an error finding."""
    devices = root.findall('./devices/entry')
    if len(devices) != 1:
        raise ValueError('One local device configuration required')
    device = devices[0]
    objects = address_objects(root, device)
    result, findings = {}, []
    entries = [(e, 'physical') for e in device.findall('./network/interface/ethernet/entry')]
    entries += [(e, 'aggregate') for e in device.findall('./network/interface/aggregate-ethernet/entry')]
    for entry, kind in entries:
        interface = entry.get('name', '')
        layer3 = entry.find('layer3')
        if layer3 is None:
            continue
        nodes = [(interface, layer3)] + [(unit.get('name', ''), unit) for unit in layer3.findall('./units/entry')]
        for name, node in nodes:
            dev = device_name(name)
            if dev is None:
                findings.append(dict(interface=name, device=None, code='device-unknown',
                                     detail='no Linux device mapping for this interface name'))
                continue
            profile_name = node.findtext('interface-management-profile') or ''
            try:
                permissions = management.profile(device, profile_name)
            except ValueError as error:
                findings.append(dict(interface=name, device=dev, code='profile-missing', detail=str(error)))
                continue
            addresses, unresolved = resolve_addresses(node, objects)
            for value in unresolved:
                findings.append(dict(interface=name, device=dev, code='address-unresolved',
                                     detail='address object is not an ip-netmask: ' + value))
            result[dev] = dict(interface=name, kind=kind, profile=profile_name, ping=permissions['ping'],
                               tcp=list(permissions['tcp']), udp=list(permissions['udp']),
                               sources=list(permissions['sources']), addresses=sorted(addresses))
    return result, findings


def _right_values(right):
    if isinstance(right, dict):
        if 'set' in right:
            values = []
            for item in right['set']:
                values.extend(_right_values(item))
            return values
        if 'prefix' in right:
            return [right['prefix']['addr'] + '/' + str(right['prefix']['len'])]
        if 'range' in right:
            return ['-'.join(str(v) for v in right['range'])]
    if isinstance(right, list):
        return [str(v) for v in right]
    return [str(right)]


def _network(value):
    try:
        return str(ipaddress.ip_network(value, strict=False))
    except ValueError:
        return value


def _address(value):
    try:
        return str(ipaddress.ip_interface(value).ip)
    except ValueError:
        return value


def classify_rule(rule):
    """One nft rule as (kind, data): a baseline element, a service accept, or other."""
    matches, verdict, has_counter = [], None, False
    for expr in rule.get('expr', []):
        if 'match' in expr:
            matches.append(expr['match'])
        elif 'counter' in expr:
            has_counter = True
        else:
            verdict = next(iter(expr))
    fields = {}
    for match in matches:
        left, right, op = match.get('left', {}), match.get('right'), match.get('op')
        if 'meta' in left:
            fields['meta.' + left['meta'].get('key', '')] = (op, _right_values(right))
        elif 'ct' in left:
            fields['ct.' + left['ct'].get('key', '')] = (op, _right_values(right))
        elif 'payload' in left:
            payload = left['payload']
            fields[payload.get('protocol', '') + '.' + payload.get('field', '')] = (op, _right_values(right))
    if verdict == 'return' and 'meta.iifname' in fields and fields['meta.iifname'][0] == '!=':
        return 'iifname-return', fields['meta.iifname'][1][0]
    if verdict == 'drop' and fields.get('ct.state', (None, []))[1] == ['invalid'] and len(fields) == 1:
        return 'invalid-drop', None
    if verdict == 'accept' and 'ct.direction' in fields and 'ct.state' in fields:
        return 'established-accept', None
    if verdict == 'drop' and not fields:
        return 'final-drop', None
    if verdict == 'accept' and not any(k.endswith('.daddr') for k in fields):
        values = {k: sorted(v[1]) for k, v in fields.items()}
        if values == {'icmp.type': ICMP_ERRORS}:
            return 'icmp-errors', None
        if values == {'icmpv6.type': ICMPV6_ERRORS}:
            return 'icmpv6-errors', None
        if values == {'icmpv6.type': NEIGHBOR_DISCOVERY, 'ip6.hoplimit': ['255']}:
            return 'neighbor-discovery', None
        if values == {'udp.sport': ['67'], 'udp.dport': ['68']}:
            return 'dhcp4', None
        if values == {'ip6.saddr': ['fe80::/10'], 'udp.sport': ['547'], 'udp.dport': ['546']}:
            return 'dhcp6', None
    if verdict == 'accept':
        family = 'ip6' if any(k.startswith('ip6.') or k.startswith('icmpv6.') for k in fields) else 'ip'
        daddr = fields.get(family + '.daddr')
        if daddr is not None:
            service = dict(family=family, addresses=sorted(_address(v) for v in daddr[1]),
                           sources=sorted(_network(v) for v in fields.get(family + '.saddr', (None, []))[1]))
            echo = fields.get(('icmpv6' if family == 'ip6' else 'icmp') + '.type')
            if echo is not None and echo[1] == ['echo-request']:
                return 'service', dict(service, kind='ping')
            for proto in ('tcp', 'udp'):
                ports = fields.get(proto + '.dport')
                if ports is not None:
                    return 'service', dict(service, kind=proto, ports=sorted(int(p) for p in ports[1]))
        return 'other-accept', fields
    return 'other', fields


def live(ruleset):
    """Per ffn_ifmgmt table: device, baseline elements present, service accepts, other accepts."""
    tables = {}
    for item in ruleset.get('nftables', []):
        if 'table' in item and item['table'].get('family') == 'inet' and item['table'].get('name', '').startswith('ffn_ifmgmt_'):
            tables[item['table']['name']] = dict(device=None, baseline=set(), services=[], other=[], rules=0)
    for item in ruleset.get('nftables', []):
        rule = item.get('rule')
        if not rule or rule.get('table') not in tables:
            continue
        table = tables[rule['table']]
        table['rules'] += 1
        kind, data = classify_rule(rule)
        if kind == 'iifname-return':
            table['device'] = data
            table['baseline'].add(kind)
        elif kind in BASELINE:
            table['baseline'].add(kind)
        elif kind == 'service':
            table['services'].append(data)
        elif kind == 'other-accept':
            table['other'].append(data)
    return tables


def expected_services(entry):
    services = []
    for family, version in (('ip', 4), ('ip6', 6)):
        addresses = sorted({_address(a) for a in entry['addresses'] if ipaddress.ip_interface(a).version == version})
        sources = sorted(s for s in entry['sources'] if ipaddress.ip_network(s).version == version)
        if not addresses or (entry['sources'] and not sources):
            continue
        base = dict(family=family, addresses=addresses, sources=sources)
        if entry['ping']:
            services.append(dict(base, kind='ping'))
        for proto in ('tcp', 'udp'):
            if entry[proto]:
                services.append(dict(base, kind=proto, ports=sorted(entry[proto])))
    return services


def describe(service):
    text = service['kind'] + (' ' + ','.join(str(p) for p in service['ports']) if 'ports' in service else '')
    text += ' to ' + ','.join(service['addresses'])
    if service['sources']:
        text += ' from ' + ','.join(service['sources'])
    return text


def compare(expected_view, published, tables, boot_id):
    findings = []
    seen = set()
    for dev, entry in sorted(expected_view.items()):
        name = 'ffn_ifmgmt_' + dev.replace('.', '_').replace('-', '_')
        seen.add(name)
        record = published.get(dev)
        wanted = expected_services(entry)
        interface = entry['interface']
        if record is None:
            findings.append(dict(interface=interface, device=dev, code='published-missing',
                                 detail='the dataplane owner has not recorded an enforcement for this interface'))
        else:
            if record.get('boot_id') != boot_id:
                findings.append(dict(interface=interface, device=dev, code='published-stale',
                                     detail='enforcement record is from another dataplane boot'))
            settings = record.get('settings', {})
            recorded = settings.get('management', {})
            differences = [k for k in ('ping', 'tcp', 'udp', 'sources')
                           if recorded.get(k) != (entry[k] if k != 'ping' else entry['ping'])]
            if sorted(settings.get('addresses', [])) != entry['addresses']:
                differences.append('addresses')
            if differences:
                findings.append(dict(interface=interface, device=dev, code='published-differs',
                                     detail='recorded enforcement differs from the committed configuration in ' + ', '.join(differences)))
        table = tables.get(name)
        if table is None:
            findings.append(dict(interface=interface, device=dev, code='table-missing',
                                 detail='no ' + name + ' table on the dataplane'))
            continue
        if table['device'] not in (None, dev):
            findings.append(dict(interface=interface, device=dev, code='device-mismatch',
                                 detail='table matches ingress ' + str(table['device'])))
        for element in BASELINE:
            if element not in table['baseline']:
                findings.append(dict(interface=interface, device=dev, code='baseline-missing', detail=element))
        for service in wanted:
            if service not in table['services']:
                findings.append(dict(interface=interface, device=dev, code='service-missing', detail=describe(service)))
        for service in table['services']:
            if service not in wanted:
                findings.append(dict(interface=interface, device=dev, code='service-extra', detail=describe(service)))
        for other in table['other']:
            findings.append(dict(interface=interface, device=dev, code='accept-unexpected', detail=json.dumps(other, sort_keys=True)))
    for name, table in sorted(tables.items()):
        if name not in seen:
            findings.append(dict(interface=None, device=table['device'], code='table-unexpected',
                                 detail=name + ' exists without a configured Layer 3 interface'))
    for dev in sorted(set(published) - set(expected_view)):
        findings.append(dict(interface=None, device=dev, code='published-unexpected',
                             detail='enforcement recorded for an interface the configuration does not manage'))
    return findings


def parse_published(text):
    """Records as the collection script prints them: a path line, the JSON line, a blank line."""
    records = {}
    lines = [line for line in text.splitlines() if line.strip()]
    for index in range(0, len(lines) - 1, 2):
        path, body = lines[index], lines[index + 1]
        try:
            value = json.loads(body)
        except ValueError:
            continue
        if isinstance(value, dict) and value.get('interface'):
            records[value['interface']] = value
    return records


COLLECT = ('ip netns exec %s nft -j list ruleset; echo %s; for f in %s/*.json; do [ -f "$f" ] || continue; '
           'echo "$f"; cat "$f"; echo; done; echo %s; cat /proc/sys/kernel/random/boot_id')


def collect(run, namespace=NAMESPACE, profile_dir=PROFILE_DIR):
    """Run the collection script through `run(script) -> text` and split the views."""
    text = run(COLLECT % (namespace, SPLIT, profile_dir, SPLIT))
    parts = text.split(SPLIT)
    if len(parts) != 3:
        raise RuntimeError('dataplane collection returned an unexpected shape')
    ruleset = json.loads(parts[0]) if parts[0].strip() else {'nftables': []}
    return ruleset, parse_published(parts[1]), parts[2].strip()


def run_dp(script, argv=DP, timeout=20):
    result = subprocess.run(argv + [script], capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError('dataplane collection failed: ' + result.stderr[-300:])
    if len(result.stdout) > 8 * 1024 * 1024:
        raise RuntimeError('dataplane ruleset exceeds the audit limit')
    return result.stdout


def run_local(script, timeout=20):
    result = subprocess.run(['sh', '-c', script], capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError('local collection failed: ' + result.stderr[-300:])
    return result.stdout


def audit(root, ruleset, published, boot_id):
    expected_view, findings = expected(root)
    tables = live(ruleset)
    findings += compare(expected_view, published, tables, boot_id)
    interfaces = {dev: dict(entry, findings=[f['code'] for f in findings if f.get('device') == dev])
                  for dev, entry in expected_view.items()}
    return dict(schema=1, consistent=not findings, dataplane_boot_id=boot_id, interfaces=interfaces,
                tables=sorted(tables), findings=findings)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--config', default='/var/lib/ffn-ngfw/config/running-config.xml')
    source = parser.add_mutually_exclusive_group()
    source.add_argument('--dp', action='store_true', help='collect from the dataplane over the MP relay path (default)')
    source.add_argument('--local', action='store_true', help='collect on this host (run on the dataplane)')
    source.add_argument('--ruleset', help='saved nft -j list ruleset output, with --profiles and --boot-id')
    parser.add_argument('--profiles', help='saved collection text of the published records')
    parser.add_argument('--boot-id', default='')
    parser.add_argument('--json', action='store_true')
    args = parser.parse_args(argv)
    try:
        root = ET.parse(args.config).getroot()
        if args.ruleset:
            with open(args.ruleset) as f:
                ruleset = json.load(f)
            published = parse_published(open(args.profiles).read()) if args.profiles else {}
            boot_id = args.boot_id
        else:
            ruleset, published, boot_id = collect(run_local if args.local else run_dp)
        report = audit(root, ruleset, published, boot_id)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError, ET.ParseError) as error:
        print(json.dumps({'error': str(error)[:500]}) if args.json else 'audit error: ' + str(error)[:500])
        return 2
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        for dev, entry in sorted(report['interfaces'].items()):
            services = ['ping'] if entry['ping'] else []
            services += ['tcp ' + ','.join(map(str, entry['tcp']))] if entry['tcp'] else []
            services += ['udp ' + ','.join(map(str, entry['udp']))] if entry['udp'] else []
            print('%-14s %-10s profile=%-14s %s addresses=%s %s' % (
                entry['interface'], dev, entry['profile'] or '-', ' '.join(services) or 'no services',
                ','.join(entry['addresses']) or '-', 'OK' if not entry['findings'] else 'FINDINGS: ' + ','.join(entry['findings'])))
        for finding in report['findings']:
            print('  %s %s %s: %s' % (finding['code'], finding.get('interface') or '-', finding.get('device') or '-', finding['detail']))
        print('consistent' if report['consistent'] else '%d finding(s)' % len(report['findings']))
    return 0 if report['consistent'] else 1


if __name__ == '__main__':
    sys.exit(main())
