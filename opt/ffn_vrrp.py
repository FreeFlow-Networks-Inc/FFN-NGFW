# SPDX-License-Identifier: GPL-2.0-or-later
"""Candidate VRRP configuration and provider-independent commissioning plans.

The MP owns configuration. Nothing in this module changes addresses or firewall
rules. In particular, a valid plan is not evidence of an elected router or of
hardware forwarding. Until a runtime provider is commissioned, enabled entries
fail Commit rather than silently exposing a nonfunctional shared gateway.
"""
import copy
import ipaddress
import json
import re
import xml.etree.ElementTree as ET

from ffn_policy_config import PolicyError, node_at, parse, revision, save_candidate
from ffn_interface_addresses import address_choices, resolve_address

NETWORK = "./devices/entry[@name='localhost.localdomain']/network"
PATH = NETWORK + '/vrrp'
NAME = re.compile(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,62}\Z')
DEFAULTS = {
    'participate': dict(enabled=False, scope='vsys1', interface='', family='ipv4',
                        vrid=1, priority=100, advert_ms=1000, preempt=True,
                        virtual_addresses=[], track_interfaces=[]),
    'passthrough': dict(enabled=False, scope='vsys1', domain='', family='both'),
}
RUNTIME = ('VRRP runtime is not commissioned: election/VIP ownership, management-profile '
           'protection, and scoped Layer 2 forwarding require dataplane verification')


def fail(message):
    raise PolicyError(message)


def inventory(root, scope):
    device = root.find("./devices/entry[@name='localhost.localdomain']")
    owner = next((v for v in device.findall('vsys/entry') if v.get('name') == scope), None) if device is not None else None
    if owner is None:
        fail('Select an existing virtual system')
    owners = device.findall('vsys/entry')
    imported = {v.get('name'): {m.text for m in v.findall('import/network/interface/member')}
                for v in owners}
    interfaces = {}
    for kind in ('ethernet', 'aggregate-ethernet', 'vlan'):
        for parent in device.findall('network/interface/' + kind + '/entry'):
            base = parent.get('name', '')
            rows = [(parent, parent.find('layer3'), 'layer3'),
                    (parent, parent.find('layer2'), 'layer2')]
            for mode in ('layer2', 'layer3'):
                rows += [(u, u, mode) for u in parent.findall(mode + '/units/entry')]
            if kind == 'vlan':
                rows += [(u, u, 'layer3') for u in parent.findall('units/entry')]
            for entry, layer, mode in rows:
                name = entry.get('name', '')
                if layer is None or not name or entry is parent and (parent.find('aggregate-group') is not None or parent.findtext('aggregate-only') == 'yes'):
                    continue
                explicit = [v for v, names in imported.items() if name in names]
                inherited = [v for v, names in imported.items() if base in names]
                selected = explicit or inherited or ([owners[0].get('name')] if len(owners) == 1 else [])
                if selected != [scope]:
                    continue
                if name in interfaces:
                    fail('Ambiguous interface configuration: ' + name)
                interfaces[name] = dict(name=name, mode=mode, addresses=[a.get('name', '') for a in layer.findall('ip/entry')])
    domains = {}
    for entry in device.findall('network/vlan/entry'):
        name = entry.get('name', '')
        members = [m.text for m in entry.findall('interface/member')]
        if name and len(members) >= 2 and len(set(members)) == len(members) and all(m in interfaces and interfaces[m]['mode'] == 'layer2' for m in members):
            if name in domains:
                fail('Duplicate VLAN domain: ' + name)
            domains[name] = sorted(members)
    return owner, interfaces, domains


def choices(root, scope):
    owner, interfaces, domains = inventory(root, scope)
    return dict(interfaces=list(interfaces.values()), domains=domains,
                addresses=address_choices(root, owner),
                scopes=[v.get('name') for v in root.findall("./devices/entry[@name='localhost.localdomain']/vsys/entry")])


def string_list(value, field, minimum=0):
    if not isinstance(value, list) or not minimum <= len(value) <= 64 or any(not isinstance(x, str) or not x or len(x) > 255 for x in value):
        fail(field + ' must be a bounded list of names or addresses')
    if len(set(value)) != len(value):
        fail(field + ' contains duplicates')


def validate(root, spec):
    if not isinstance(spec, dict) or not isinstance(spec.get('mode'), str) or spec['mode'] not in DEFAULTS:
        fail('Select participate or passthrough')
    mode = spec['mode']
    if set(spec) != set(DEFAULTS[mode]) | {'name', 'mode'}:
        fail('VRRP fields do not match the selected mode')
    if not isinstance(spec['name'], str) or not NAME.fullmatch(spec['name']):
        fail('Invalid VRRP entry name')
    if type(spec['enabled']) is not bool or not isinstance(spec['scope'], str):
        fail('Invalid enabled state or virtual system')
    owner, interfaces, domains = inventory(root, spec['scope'])
    result = copy.deepcopy(spec)
    if not isinstance(spec['family'], str): fail('Invalid address family')
    if mode == 'passthrough':
        if not isinstance(spec['domain'], str) or spec['domain'] not in domains:
            fail('Select a configured VLAN domain containing at least two Layer 2 interfaces in this virtual system')
        if spec['family'] not in ('ipv4', 'ipv6', 'both'):
            fail('Invalid address family')
        result['interfaces'] = domains[spec['domain']]
        result['forwarding_scope'] = 'same-bridge-and-vlan-only'
    else:
        if not isinstance(spec['interface'], str) or interfaces.get(spec['interface'], {}).get('mode') != 'layer3':
            fail('Select a configured Layer 3 data interface in this virtual system')
        if spec['family'] not in ('ipv4', 'ipv6'):
            fail('Select IPv4 or IPv6')
        for key, low, high in (('vrid', 1, 255), ('priority', 1, 254), ('advert_ms', 10, 40950)):
            if type(spec[key]) is not int or not low <= spec[key] <= high:
                fail(key + ' must be an integer from ' + str(low) + ' to ' + str(high))
        if spec['advert_ms'] % 10:
            fail('VRRPv3 advertisement interval must be a multiple of 10 ms')
        if type(spec['preempt']) is not bool:
            fail('Preempt must be true or false')
        string_list(spec['virtual_addresses'], 'Virtual addresses', 1)
        string_list(spec['track_interfaces'], 'Tracked interfaces')
        if spec['interface'] in spec['track_interfaces']:
            fail('The VRRP interface is already tracked automatically')
        if any(interfaces.get(i, {}).get('mode') != 'layer3' for i in spec['track_interfaces']):
            fail('Tracked interfaces must be configured Layer 3 interfaces in this virtual system')
        try:
            addresses = [ipaddress.ip_interface(resolve_address(v, root, owner)) for v in spec['virtual_addresses']]
            local = [ipaddress.ip_interface(resolve_address(v, root, owner)) for v in interfaces[spec['interface']]['addresses']]
        except ValueError as error:
            fail(str(error))
        family = 4 if spec['family'] == 'ipv4' else 6
        for address in addresses:
            ip = address.ip
            if address.version != family or ip.is_multicast or ip.is_unspecified or ip.is_loopback or ip.is_link_local:
                fail('Virtual addresses must be unicast host addresses of the selected family')
            if family == 4 and address.network.prefixlen < 31 and ip in (address.network.network_address, address.network.broadcast_address):
                fail('Virtual address is a subnet or broadcast address')
            if any(ip == a.ip for a in local):
                fail('Virtual address must differ from the permanent interface address; address-owner priority 255 is not implemented')
            if not any(a.version == family and ip in a.network and address.network == a.network for a in local):
                fail('Virtual address prefix must match a configured interface subnet')
        if len({a.ip for a in addresses}) != len(addresses):
            fail('Duplicate virtual address after object resolution')
        result['resolved_addresses'] = [str(a) for a in addresses]
        result['version'] = 3
        result['virtual_mac'] = '00:00:5e:00:%02x:%02x' % (1 if family == 4 else 2, spec['vrid'])
        result['initial_state'] = 'BACKUP'
    families = ('ipv4', 'ipv6') if spec['family'] == 'both' else (spec['family'],)
    result['advertisements'] = [dict(family=f, protocol=112, destination='224.0.0.18' if f == 'ipv4' else 'ff02::12', hop_limit=255) for f in families]
    result['route_advertisements'] = False
    return result


def serialize(spec):
    entry = ET.Element('entry', name=spec['name'])
    ET.SubElement(entry, 'settings').text = json.dumps(spec, sort_keys=True, separators=(',', ':'), allow_nan=False)
    return entry


def describe(entry):
    try:
        def pairs(items):
            result = {}
            for key, value in items:
                if key in result: raise ValueError('Duplicate JSON key')
                result[key] = value
            return result
        def constant(value): raise ValueError('Nonfinite JSON number: ' + value)
        spec = json.loads(entry.findtext('settings', ''), object_pairs_hook=pairs, parse_constant=constant)
        if (not isinstance(spec, dict) or spec.get('name') != entry.get('name') or set(entry.attrib) != {'name'}
                or len(entry) != 1 or entry[0].tag != 'settings' or entry[0].attrib or len(entry[0])):
            raise ValueError('Unsupported imported settings')
        return spec
    except (ValueError, TypeError) as error:
        fail('Malformed VRRP entry ' + entry.get('name', '') + ': ' + str(error))


def plan(root):
    rows, blockers, names, identities, vips, domains = [], [], set(), set(), set(), set()
    for entry in root.findall(PATH + '/entry'):
        name = entry.get('name', '')
        try:
            if name in names: fail('Duplicate VRRP entry name')
            names.add(name)
            row = validate(root, describe(entry))
            if row['enabled']:
                if row['mode'] == 'participate':
                    key = (row['interface'], row['family'], row['vrid'])
                    if key in identities: fail('Duplicate VRID on the same interface and address family')
                    identities.add(key)
                    for value in row['resolved_addresses']:
                        key = (row['interface'], str(ipaddress.ip_interface(value).ip))
                        if key in vips: fail('Virtual address belongs to another enabled VRRP entry')
                        vips.add(key)
                else:
                    for advert in row['advertisements']:
                        key = (row['domain'], advert['family'])
                        if key in domains: fail('Overlapping passthrough settings for this VLAN domain')
                        domains.add(key)
            rows.append(row)
        except PolicyError as error:
            blockers.append(dict(scope='device', kind='vrrp', name=name, reason=str(error)))
    containers = root.findall(PATH)
    if len(containers) > 1 or any(c.attrib or any(e.tag != 'entry' for e in c) for c in containers):
        blockers.append(dict(scope='device', kind='vrrp', name='', reason='Unsupported or duplicate VRRP container'))
    return dict(valid=not blockers, entries=rows, blockers=blockers, applied=False, runtime=RUNTIME)


def activation_blockers(root):
    result = plan(root)
    return result['blockers'] + [dict(scope=r['scope'], kind='vrrp', name=r['name'], reason=RUNTIME)
                                 for r in result['entries'] if r['enabled']]


def request(controller, args):
    action, source = args['action'], args.get('source', 'candidate')
    if source not in ('candidate', 'running') or action not in ('vrrp-list', 'vrrp-create', 'vrrp-update', 'vrrp-delete'):
        fail('Invalid VRRP operation')
    path = controller.directory / (source + '-config.xml')
    xml = path.read_bytes(); root = parse(xml)
    scope = args.get('scope', 'vsys1')
    if action == 'vrrp-list':
        compiled = plan(root)
        return dict(source=source, revision=revision(xml), defaults=DEFAULTS, choices=choices(root, scope),
                    entries=[describe(e) for e in root.findall(PATH + '/entry')], plan=compiled, requires_commit=True)
    if source != 'candidate': raise PolicyError('Running configuration is read only', 403)
    user = args.get('user')
    if not user: raise PolicyError('Authenticated actor required', 403)
    if controller.commit:
        state = controller.commit.lock_status()
        if state['locked'] and state.get('holder') != user: raise PolicyError('Configuration is locked by another administrator', 423)
    if args.get('revision') != revision(xml): raise PolicyError('Candidate changed. Refresh before retrying', 409)
    name = args.get('name')
    if not isinstance(name, str) or not NAME.fullmatch(name): fail('Invalid VRRP entry name')
    parent = root.find(PATH)
    entries = root.findall(PATH + '/entry')
    if len({e.get('name') for e in entries}) != len(entries): fail('Duplicate VRRP entries must be repaired')
    entry = next((e for e in entries if e.get('name') == name), None)
    if action == 'vrrp-create' and entry is not None: raise PolicyError('VRRP entry already exists', 409)
    if action != 'vrrp-create' and entry is None: raise PolicyError('VRRP entry not found', 404)
    if entry is not None:
        previous = describe(entry)
        mode = previous.get('mode')
        if not isinstance(mode, str) or mode not in DEFAULTS or set(previous) != set(DEFAULTS[mode]) | {'name', 'mode'}:
            fail('Imported VRRP fields are protected; repair unfamiliar settings before editing')
    if action == 'vrrp-delete': parent.remove(entry)
    else:
        spec = args.get('entry'); validate(root, spec)
        if spec['name'] != name: fail('Remove and recreate to rename a VRRP entry')
        if parent is None:
            network = root.find(NETWORK)
            if network is None: fail('Configure network interfaces first')
            parent = node_at(network, 'vrrp')
        if entry is not None: parent.remove(entry)
        parent.append(serialize(spec))
    compiled = plan(root)
    if compiled['blockers']: fail('; '.join(b['reason'] for b in compiled['blockers']))
    return save_candidate(path, xml, root)
