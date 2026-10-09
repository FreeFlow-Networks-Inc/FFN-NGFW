# SPDX-License-Identifier: GPL-2.0-or-later
"""The committed DHCP server tree as the dataplane intent.

Shared by the console's configuration module, the platform provider that
applies a commit, and the convergence check. It depends only on the daemon's
own validation rules and the interface address resolver, never on the web
framework, so configd and the operator command can import it.

PAN-OS shape, under the local device's network tree:

    network/dhcp/interface/entry[@name='ae1.69']/server/
        mode enabled|disabled, probe-ip yes|no
        ip-pool/member            "10.1.0.100-10.1.0.199" (or one address)
        reserved/entry[@name=IP]  mac, description
        option/lease/{timeout (minutes) | unlimited}, gateway, subnet-mask,
        option/dns/{primary,secondary}, ntp/{primary,secondary}, wins/{primary,secondary}, dns-suffix

The server address is the interface's first IPv4 address in the same tree;
pools and reservations must lie in its network.
"""
import ipaddress
import re

import ffn_dhcp_server as daemon

INTERFACE = re.compile(r'(ethernet1/([1-9][0-9]{0,3})|ae([1-9][0-9]{0,2}))(\.([1-9][0-9]{0,3}))?\Z')
RANGE = re.compile(r'\s*([0-9.]{7,15})\s*(?:-\s*([0-9.]{7,15})\s*)?\Z')
OPTION_PAIRS = (('dns', 'dns'), ('ntp', 'ntp'), ('wins', 'wins'))


def yes(value):
    return (value or '').strip().lower() in ('yes', 'true', '1')


def local_device(root):
    return next((e for e in root.findall('devices/entry') if e.get('name') == 'localhost.localdomain'), None)


def dp_device(name):
    """ethernet1/N(.T) -> pN(.T); aeN(.T) keeps its name. Other kinds have no dataplane device."""
    match = INTERFACE.fullmatch(name or '')
    if not match:
        raise ValueError('%s: only ethernet1/N, aeN and their subinterfaces can serve DHCP' % name)
    base = 'p' + match.group(2) if match.group(2) else 'ae' + match.group(3)
    return base + ('.' + match.group(5) if match.group(5) else '')


def interface_inventory(root):
    """Layer3 interfaces the dataplane can serve on, with their resolved IPv4 addresses; ValueError when objects do not resolve."""
    from ffn_interface_addresses import interface_nodes, resolved_config
    result = {}
    device = local_device(root)
    if device is None:
        return result
    clients = {e.get('name') for e in device.findall('network/interface/ethernet/entry') if yes(e.findtext('layer3/dhcp-client/enable'))}
    try:
        resolved = resolved_config(root)
    except ValueError as error:
        raise ValueError('interface addresses cannot be resolved: ' + str(error))
    for name, _owner, nodes in interface_nodes(resolved):
        if not INTERFACE.fullmatch(name):
            continue
        addresses = []
        for node in nodes:
            try:
                value = ipaddress.ip_interface(node.get('name', ''))
            except ValueError:
                continue
            if value.version == 4:
                addresses.append(str(value))
        result[name] = dict(addresses=addresses, dhcp_client=name in clients)
    for name in clients:
        result.setdefault(name, dict(addresses=[], dhcp_client=True))
    return result


def describe(entry):
    """The API view of one network/dhcp/interface entry."""
    import xml.etree.ElementTree as ET
    server = entry.find('server')
    if server is None:
        server = ET.Element('server')
    option = server.find('option')
    if option is None:
        option = ET.Element('option')
    lease = option.find('lease')
    if lease is not None and lease.find('unlimited') is not None:
        lease_minutes = None
    else:
        text = lease.findtext('timeout') if lease is not None else None
        lease_minutes = int(text) if text and text.isdigit() else 1440
    options = dict(gateway=option.findtext('gateway', '') or '', subnet_mask=option.findtext('subnet-mask', '') or '',
                   dns_suffix=option.findtext('dns-suffix', '') or '')
    for tag, key in OPTION_PAIRS:
        node = option.find(tag)
        options[key] = [v for v in ((node.findtext('primary') if node is not None else None),
                                    (node.findtext('secondary') if node is not None else None)) if v]
    return dict(interface=entry.get('name', ''), mode='disabled' if (server.findtext('mode') or 'enabled').strip() == 'disabled' else 'enabled',
                probe_ip=yes(server.findtext('probe-ip')), lease_minutes=lease_minutes,
                pools=[m.text.strip() for m in server.findall('ip-pool/member') if m.text and m.text.strip()],
                reserved=[dict(ip=e.get('name', ''), mac=(e.findtext('mac') or '').strip().lower(), description=e.findtext('description', '') or '')
                          for e in server.findall('reserved/entry')],
                options=options)


def parse_pool(text):
    match = RANGE.fullmatch(text or '')
    if not match:
        raise ValueError('pool "%s" is not an address or a first-last range' % text)
    return [match.group(1), match.group(2) or match.group(1)]


def server_spec(described, address):
    """The dataplane daemon's intent for one described server, validated by the daemon's rules."""
    options = described['options']
    spec = dict(interface=described['interface'], address=address, pools=[parse_pool(p) for p in described['pools']],
                reserved={r['mac'].lower(): r['ip'] for r in described['reserved']},
                lease=None if described['lease_minutes'] is None else int(described['lease_minutes']) * 60,
                probe=bool(described['probe_ip']), options={})
    if len(spec['reserved']) != len(described['reserved']):
        raise ValueError('reservation MAC addresses must be unique')
    if options.get('gateway'):
        spec['options']['gateway'] = options['gateway']
    if options.get('subnet_mask'):
        spec['options']['subnet_mask'] = options['subnet_mask']
    for key in ('dns', 'ntp', 'wins'):
        if options.get(key):
            spec['options'][key] = list(options[key])
    if options.get('dns_suffix'):
        spec['options']['domain'] = options['dns_suffix']
    return daemon.validate_server(dp_device(described['interface']), spec)


def compile_intent(root):
    """{'servers': {dp device: spec}} for every enabled server in the tree; ValueError names a bad one."""
    device = local_device(root)
    servers = {}
    if device is None:
        return dict(servers=servers)
    inventory = None
    for entry in device.findall('network/dhcp/interface/entry'):
        described = describe(entry)
        if described['mode'] != 'enabled':
            continue
        name = described['interface']
        if inventory is None:
            inventory = interface_inventory(root)
        addresses = inventory.get(name, {}).get('addresses', [])
        if not addresses:
            raise ValueError(name + ': the interface has no static IPv4 address to serve from')
        try:
            servers[dp_device(name)] = server_spec(described, addresses[0])
        except ValueError as error:
            raise ValueError(name + ': ' + str(error))
    return dict(servers=servers)
