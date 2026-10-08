#!/usr/bin/env python3
"""Read-only IPv4 next-hop observations for hardware offload planning.

Run inside the DP namespace. These bounded snapshots are not an admission
lease: hardware still needs ordered route/neighbor/session invalidation.
No addresses, VLANs, ports, MACs or hardware table IDs are allocated here.
"""
import hashlib
import ipaddress
import json
import re
import subprocess
import time


# Neighbour states the kernel itself forwards with (NUD_VALID). A forwarded
# flow gives the kernel no transport confirmation, so under traffic an entry
# cycles REACHABLE -> STALE -> DELAY -> PROBE -> REACHABLE every reachable_time
# while its link address stays the same; only the address or a failed entry
# changes what a next hop means.
NUD_VALID = frozenset(('PERMANENT', 'NOARP', 'REACHABLE', 'PROBE', 'STALE', 'DELAY'))


def fingerprint(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def neighbor_valid(neighbor):
    if 'valid' in neighbor:
        return neighbor['valid'] is True
    return bool(set(neighbor.get('state', [])) & NUD_VALID) and bool(neighbor.get('lladdr'))


def project_neighbor(row):
    return dict({k: row[k] for k in ('dst', 'dev', 'lladdr') if k in row}, valid=neighbor_valid(row))


def project_linkinfo(info):
    # Bridge info carries hello/gc/topology-change timers that advance every
    # second, and bond slave data changes with LACP; planning reads only the
    # kind and the VLAN identity.
    result = {k: info[k] for k in ('info_kind', 'info_slave_kind') if k in info}
    data = info.get('info_data')
    if isinstance(data, dict):
        result['info_data'] = {k: data[k] for k in ('id', 'protocol') if k in data}
    return result


def snapshot(deadline):
    result = {}
    commands = {
        'links': ['-d', '-j', 'link', 'show'],
        'addresses': ['-4', '-j', 'address', 'show'],
        'routes': ['-4', '-j', 'route', 'show', 'table', 'main'],
        'rules': ['-4', '-j', 'rule', 'show'],
        'neighbors': ['-4', '-j', 'neigh', 'show'],
    }
    # Keep ownership/topology and reject changes, but not address lifetimes or
    # traffic counters that naturally advance between two observations.
    fields = {
        'links': ('ifindex', 'ifname', 'ifalias', 'address', 'mtu', 'flags', 'link',
                  'link_index', 'master', 'linkinfo'),
        'addresses': ('ifindex', 'ifname', 'addr_info'),
    }
    for key, args in commands.items():
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ValueError('L3 observation exceeded its freshness budget')
        response = subprocess.run(['ip', *args], capture_output=True, text=True,
                                  timeout=min(1, remaining), check=True)
        if len(response.stdout) > 2 * 1024 * 1024:
            raise ValueError('L3 inventory exceeds limit')
        rows = json.loads(response.stdout)
        if not isinstance(rows, list) or len(rows) > 8192:
            raise ValueError('Invalid or oversized L3 inventory')
        if key in fields:
            rows = [{k: row[k] for k in fields[key] if k in row} for row in rows]
        if key == 'links':
            for row in rows:
                if isinstance(row.get('linkinfo'), dict):
                    row['linkinfo'] = project_linkinfo(row['linkinfo'])
        if key == 'addresses':
            for row in rows:
                row['addr_info'] = [{k: a[k] for k in ('family', 'local', 'prefixlen') if k in a}
                                    for a in row.get('addr_info', [])]
        if key == 'neighbors':
            # The neighbour state machine advances under traffic without
            # changing the next hop; keep only what planning depends on.
            rows = [project_neighbor(row) for row in rows]
        result[key] = sorted(rows, key=lambda row: json.dumps(row, sort_keys=True))
    return result


def unicast_mac(value):
    if not isinstance(value, str) or not re.fullmatch(r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}', value):
        raise ValueError('Unresolved Ethernet MAC address')
    raw = bytes.fromhex(value.replace(':', ''))
    if not any(raw) or raw[0] & 1:
        raise ValueError('Unicast Ethernet MAC address required')
    return value.lower()


def main_table_only(state):
    expected = {(0, 'local'), (32766, 'main'), (32767, 'default')}
    actual = set()
    tables = {253: 'default', 254: 'main', 255: 'local'}
    for rule in state['rules']:
        if (set(rule) - {'priority', 'src', 'table', 'protocol'} or rule.get('src') != 'all'):
            raise ValueError('Policy routing requires a qualified hardware route resolver')
        actual.add((rule.get('priority'), tables.get(rule.get('table'), rule.get('table'))))
    if actual != expected or len(state['rules']) != 3:
        raise ValueError('Policy routing requires a qualified hardware route resolver')


def attachment(name, bindings, state):
    binding = bindings.get(name)
    if not isinstance(binding, dict):
        raise ValueError('No acknowledged binding for ' + name)
    links = [row for row in state['links'] if row['ifname'] == binding.get('device')]
    if len(links) != 1:
        raise ValueError('Bound interface is missing: ' + name)
    link = links[0]
    if link['ifindex'] != binding.get('index') or link.get('ifalias', '') != binding.get('alias'):
        raise ValueError('Interface ownership changed: ' + name)
    if not {'UP', 'LOWER_UP'} <= set(link.get('flags', [])):
        raise ValueError('Interface has no operational carrier: ' + name)
    if link.get('master'):
        raise ValueError('Bridged or VRF attachment requires hardware qualification: ' + name)
    kind = link.get('linkinfo', {}).get('info_kind')
    result = dict(interface=name, device=link['ifname'], index=link['ifindex'],
                  alias=link.get('ifalias', ''), source_mac=unicast_mac(link.get('address')),
                  mtu=link['mtu'], vlan=None)
    if kind == 'vlan':
        data = link['linkinfo']['info_data']
        tag = data.get('id')
        if data.get('protocol', '802.1Q') != '802.1Q' or type(tag) is not int or not 1 <= tag <= 4094:
            raise ValueError('Unsupported VLAN attachment')
        parents = [p for p in state['links'] if p['ifindex'] == link.get('link_index') or
                   p['ifname'] == link.get('link')]
        if len(parents) != 1 or parents[0].get('linkinfo', {}).get('info_kind') == 'vlan':
            raise ValueError('Missing or stacked VLAN parent')
        parent = parents[0]
        if not {'UP', 'LOWER_UP'} <= set(parent.get('flags', [])) or parent.get('master'):
            raise ValueError('VLAN parent is not an operational standalone attachment')
        result.update(vlan=tag, parent={k: parent.get(k) for k in ('ifname', 'ifindex', 'ifalias')})
    elif kind not in (None, 'tun'):
        raise ValueError('Unsupported hardware attachment kind: ' + str(kind))
    return result


def route_for(destination, state):
    """The one main-table unicast route that forwards to `destination`, or a reason it cannot be used."""
    address = ipaddress.IPv4Address(destination)
    if address.is_unspecified or address.is_multicast or address.is_loopback or address.is_link_local:
        raise ValueError('Destination requires the software exception path')
    if any(a.get('local') == str(address) for row in state['addresses'] for a in row.get('addr_info', [])):
        raise ValueError('Firewall-local destination must remain on the management-profile path')
    choices = []
    for route in state['routes']:
        network = ipaddress.IPv4Network(route['dst'] if route.get('dst', 'default') != 'default' else '0.0.0.0/0')
        if address in network:
            metric = route.get('metric', 0)
            if type(metric) is not int:
                raise ValueError('Unsupported route metric')
            choices.append((network.prefixlen, -metric, route))
    if not choices:
        raise ValueError('No route to ' + destination)
    rank = max((prefix, metric) for prefix, metric, _ in choices)
    routes = [route for prefix, metric, route in choices if (prefix, metric) == rank]
    if len(routes) != 1:
        raise ValueError('Ambiguous or multipath route')
    route = routes[0]
    if (route.get('type', 'unicast') != 'unicast' or
        any(k in route for k in ('nexthops', 'nhid', 'encap', 'via', 'expires')) or
        route.get('tos', 0) not in (0, '0x00') or route.get('flags') or
        route.get('table', 'main') not in ('main', 254)):
        raise ValueError('Selected route requires the software exception path')
    return route


def select_pair(pairs, forward_destination, reverse_destination, bindings, state):
    """The interface pair the routes select, provided the rule authorises it.

    A security rule between zones yields every ingress/egress combination of
    their interfaces; a session actually enters where the reverse route for
    its original source points and leaves where the forward route for its
    translated destination points. One pair, when a rule has one, is verified
    against the routes by resolve(); with several, the routes choose and the
    rule must list the choice. Nothing is guessed from traffic.
    """
    if not pairs:
        raise ValueError('No interface pair is authorised for this session')
    if len(pairs) == 1:
        return list(pairs[0])
    forward_dev = route_for(forward_destination, state).get('dev')
    reverse_dev = route_for(reverse_destination, state).get('dev')
    matches = [list(pair) for pair in pairs
               if (bindings.get(pair[0]) or {}).get('device') == reverse_dev
               and (bindings.get(pair[1]) or {}).get('device') == forward_dev]
    if len(matches) != 1:
        raise ValueError('Routes select %s to %s, which the rule does not authorise as an interface pair'
                         % (reverse_dev, forward_dev))
    return matches[0]


def resolve(destination, outgoing, bindings, state):
    route = route_for(destination, state)
    target = attachment(outgoing, bindings, state)
    if route.get('dev') != target['device']:
        raise ValueError('Route egress disagrees with the authorized interface pair')
    neighbor_ip = str(ipaddress.IPv4Address(route.get('gateway', destination)))
    neighbors = [n for n in state['neighbors'] if n.get('dev') == target['device'] and n.get('dst') == neighbor_ip]
    if len(neighbors) != 1:
        raise ValueError('Next-hop neighbor is unresolved: ' + neighbor_ip)
    neighbor = neighbors[0]
    if not neighbor_valid(neighbor):
        raise ValueError('Next-hop neighbor is not valid for forwarding: ' + neighbor_ip)
    metrics = route.get('metrics', [])
    if metrics:
        # MTU locks, encapsulation metrics and other route attributes need an
        # explicit hardware implementation rather than assuming link MTU.
        raise ValueError('Route metrics require hardware qualification')
    target.update(destination=destination, next_hop=neighbor_ip,
                  destination_mac=unicast_mac(neighbor.get('lladdr')), route=route,
                  decrement_ttl=True, exceptions=['ttl-expired', 'mtu-exceeded', 'ipv4-fragments'])
    return target


def plan(row, bindings, state):
    result = dict(available=False, hardware_admission=False, blockers=[], directions=[],
                  snapshot_digest=fingerprint(state))
    if not row['software_candidate']:
        result['blockers'] = ['Session is not an acknowledged software candidate']
        return result
    try:
        main_table_only(state)
        # Routing follows DNAT but precedes SNAT. The actual conntrack tuples
        # supply each direction's post-translation destination.
        incoming, outgoing = select_pair(row['rule']['interface_pairs'], row['translated']['destination'],
                                         row['original']['source'], bindings, state)
        attachment(incoming, bindings, state)
        forward = resolve(row['translated']['destination'], outgoing, bindings, state)
        reverse = resolve(row['original']['source'], incoming, bindings, state)
        result.update(available=True, directions=[forward, reverse], pair=[incoming, outgoing])
    except (ValueError, KeyError, TypeError) as error:
        result['blockers'] = [str(error)]
    return result
