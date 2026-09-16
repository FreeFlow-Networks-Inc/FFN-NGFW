"""Configured Layer 3 interface inventory and static-route validation."""
import ipaddress


def inventory(configured, routers, aliases=None):
    aliases = aliases or {}
    reverse = {value: key for key, value in aliases.items()}
    owners = {}
    for router in routers:
        if router['name'] == 'default':
            continue
        for name in router.get('interfaces', []):
            owners[reverse.get(name, name)] = router['name']
    rows = {}
    for kind, entries in configured.items():
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if entry.get('mode') != 'layer3':
                continue
            names = [entry['name'], *entry.get('sub_interfaces', [])]
            for name in names:
                if not name or name in ('loopback', 'vlan', 'tunnel'):
                    continue
                rows[name] = {'name': name, 'kind': kind,
                              'addresses': entry.get('ip_addresses', []) if name == entry['name'] else [],
                              'virtual_router': owners.get(name, 'default'),
                              'alias': aliases.get(name)}
    return sorted(rows.values(), key=lambda row: row['name'])


def validate_route(route, router, interfaces):
    result = dict(route)
    try:
        network = ipaddress.ip_network(result['dest_cidr'], strict=True)
    except (ValueError, KeyError) as error:
        raise ValueError('Destination must be a network prefix, such as 0.0.0.0/0') from error
    hop = str(result.get('next_hop') or '').strip()
    if hop:
        try:
            address = ipaddress.ip_address(hop)
        except ValueError as error:
            raise ValueError('Next hop must be an IP address') from error
        if address.version != network.version or address.is_multicast or address.is_unspecified:
            raise ValueError('Next hop must be a unicast address matching the destination family')
    dev = result.get('dev') or None
    if dev:
        row = next((row for row in interfaces if dev in (row['name'], row.get('alias'))), None)
        if row is None:
            raise ValueError('Select a configured Layer 3 interface from Network > Interfaces')
        if row['virtual_router'] != router:
            raise ValueError('Interface belongs to virtual router ' + row['virtual_router'])
    if not hop and not dev:
        raise ValueError('A next hop or outgoing interface is required')
    metric = result.get('metric', 0)
    if type(metric) is not int or not 0 <= metric <= 4294967295:
        raise ValueError('Metric must be an integer between 0 and 4294967295')
    result.update(dest_cidr=str(network), next_hop=hop, dev=dev, metric=metric)
    return result
