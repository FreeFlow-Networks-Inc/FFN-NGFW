#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Runtime per-port Linux L2/L3 configuration; TAP packet backend is separate.

All interfaces live in ffn-data, never in the management namespace. A revision
check and flock serialize MP changes. Only changed ports are reconfigured.
"""
import argparse
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess as S
import sys

NS = 'ffn-data'
MAX_PORTS = 4096
PORT_BACKEND = 'tap'
REQUIRE_ATTACHMENT = False
STATE = Path('/etc/ffn/network.json')
OVERLAY_STATE = Path('/etc/ffn/overlay.json')

def run(*args):
    result = S.run(args, capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError('%s: %s' % (' '.join(args), result.stderr.strip()))
    return result.stdout

def ip(*args):
    return run('ip', '-n', NS, *args)

def validate_port(name, settings):
    if not isinstance(settings, dict):
        raise ValueError('port settings must be an object')
    if not isinstance(name, str) or not re.fullmatch(r'p[1-9][0-9]{0,3}', name) or int(name[1:]) > MAX_PORTS:
        raise ValueError('port name exceeds the selected backend capacity')
    if set(settings) - {'mode', 'vlans', 'pvid', 'addresses', 'mtu', 'vrf', 'management'}:
        raise ValueError('unknown per-port setting')
    if 'management' in settings:
        from ffn_interface_management import validate as validate_management
        validate_management(settings['management'])
        if settings.get('mode') != 'l3':
            raise ValueError('interface management requires l3 mode')
    mode = settings.get('mode')
    if mode not in ('disabled', 'l2', 'l3'):
        raise ValueError('mode must be disabled, l2 or l3')
    if 'vrf' in settings and mode != 'l3':
        raise ValueError('VRF membership requires l3 mode')
    mtu = settings.get('mtu', 1500)
    if type(mtu) is not int or not 1280 <= mtu <= 9000:
        raise ValueError('mtu must be 1280..9000')
    if mode == 'l2':
        vlans = settings.get('vlans', [])
        if not vlans or any(type(v) is not int or not 1 <= v <= 4094 for v in vlans):
            raise ValueError('l2 requires allowed VLAN IDs 1..4094')
        if len(set(vlans)) != len(vlans):
            raise ValueError('duplicate VLAN')
        if 'pvid' in settings and (type(settings['pvid']) is not int or settings['pvid'] not in vlans):
            raise ValueError('native/access pvid must be an allowed VLAN')
        if 'addresses' in settings:
            raise ValueError('l2 ports cannot carry routed addresses')
    else:
        if 'vlans' in settings or 'pvid' in settings:
            raise ValueError('VLAN membership is only valid for l2 mode')
        if mode == 'disabled' and 'addresses' in settings:
            raise ValueError('disabled ports cannot carry addresses')
        for address in settings.get('addresses', []):
            addr = ipaddress.ip_interface(address)
            if addr.ip.is_multicast or addr.ip.is_unspecified or addr.ip.is_loopback:
                raise ValueError('invalid routed address')
    return settings

def routing_interfaces(cfg):
    """Routing view; selected adapters may add separately owned interfaces.

    These entries are never added to cfg['ports'] or reconfigured by this
    controller. An adapter must validate their saved settings before returning.
    """
    return cfg['ports']


def attached_interfaces(attachment):
    """Interfaces available to new routes and ingress policy rules."""
    return {'p%d' % number for number in attachment['ports']}


def validate(cfg):
    if not {'revision', 'ports'} <= set(cfg) or set(cfg)-{'revision', 'ports', 'routes', 'vrfs', 'rules'} or type(cfg['revision']) is not int or cfg['revision'] < 0:
        raise ValueError('configuration requires revision and ports')
    if not isinstance(cfg['ports'], dict):
        raise ValueError('ports must be an object')
    vrfs = cfg.get('vrfs', {})
    if not isinstance(vrfs, dict) or len(vrfs) > 64:
        raise ValueError('vrfs must be an object with at most 64 virtual routers')
    for name, table in vrfs.items():
        if (not re.fullmatch(r'vrf-[a-z0-9-]{1,11}', name) or type(table) is not int
                or not 1000 <= table <= 65535):
            raise ValueError('VRF names must be vrf-NAME (15 chars max), tables 1000..65535')
    if len(set(vrfs.values())) != len(vrfs):
        raise ValueError('VRF table IDs must be unique')
    for name, settings in cfg['ports'].items():
        validate_port(name, settings)
    interfaces = routing_interfaces(cfg)
    addresses = set()
    for name, settings in interfaces.items():
        if 'vrf' in settings and settings['vrf'] not in vrfs:
            raise ValueError('port references an undefined VRF')
        for address in settings.get('addresses', []):
            key = (settings.get('vrf'), str(ipaddress.ip_interface(address).ip))
            if key in addresses:
                raise ValueError('duplicate local IP address')
            addresses.add(key)
    routes = cfg.get('routes', [])
    if not isinstance(routes, list) or len(routes) > 1024:
        raise ValueError('routes must be a list of at most 1024 entries')
    keys = set()
    for route in routes:
        if not isinstance(route, dict) or set(route)-{'dst', 'via', 'dev', 'metric', 'type', 'table', 'nexthops', 'track_link', 'monitor', 'onlink'}:
            raise ValueError('unknown route setting')
        from ffn_route_monitor import validate as validate_monitor
        monitor=validate_monitor(route.get('monitor'),route.get('dst'))
        if any(type(route[k]) is not bool for k in ('onlink','track_link') if k in route):
            raise ValueError('Route flags must be boolean')
        if route.get('onlink') and not route.get('via'): raise ValueError('On-link gateway requires via')
        if monitor['enabled'] and (not route.get('track_link') or not route.get('dev')):
            raise ValueError('Path monitoring requires a tracked route with explicit egress')
        if route.get('track_link') and ('nexthops' in route or route.get('type','unicast')!='unicast'):
            raise ValueError('Link tracking currently requires a single unicast next hop')
        destination = ipaddress.ip_network(route.get('dst', ''), strict=True)
        if str(destination) != route['dst']:
            raise ValueError('route destination must be a canonical prefix; use /0 for default')
        metric = route.get('metric', 100)
        if type(metric) is not int or not 0 <= metric < 4278198272:
            raise ValueError('route metric must be 0..4278198271')
        table = route.get('table', 254)
        if type(table) is not int or (table != 254 and table not in vrfs.values()):
            raise ValueError('route table must be main (254) or a configured VRF table')
        key = (table, str(destination), metric)
        if key in keys:
            raise ValueError('duplicate route destination and metric')
        keys.add(key)
        kind = route.get('type', 'unicast')
        if 'nexthops' in route:
            hops = route['nexthops']
            if kind != 'unicast' or 'dev' in route or 'via' in route or not isinstance(hops, list) or not 2 <= len(hops) <= 16:
                raise ValueError('ECMP requires 2..16 nexthops and no top-level via/dev')
            seen = set()
            for hop in hops:
                if not isinstance(hop, dict) or set(hop)-{'dev','via','weight'} or 'dev' not in hop:
                    raise ValueError('invalid ECMP next hop')
                weight = hop.get('weight', 1)
                if type(weight) is not int or not 1 <= weight <= 256:
                    raise ValueError('ECMP weight must be 1..256')
                identity = (hop['dev'], hop.get('via'))
                if identity in seen:
                    raise ValueError('duplicate ECMP next hop')
                seen.add(identity)
                single = {k:v for k,v in route.items() if k != 'nexthops'}
                single.update({k:v for k,v in hop.items() if k != 'weight'})
                validate({'revision':cfg['revision'], 'ports':cfg['ports'], 'vrfs':vrfs, 'routes':[single]})
            continue
        if kind == 'blackhole':
            if 'via' in route or 'dev' in route:
                raise ValueError('blackhole routes cannot specify via or dev')
            continue
        if kind != 'unicast':
            raise ValueError('route type must be unicast or blackhole')
        port = interfaces.get(route.get('dev'), {})
        if port.get('mode') != 'l3':
            raise ValueError('route dev must be a configured l3 port')
        if vrfs.get(port.get('vrf'), 254) != table:
            raise ValueError('route and egress port must belong to the same virtual router')
        if 'via' in route:
            gateway = ipaddress.ip_address(route['via'])
            if (gateway.version != destination.version or gateway.is_multicast
                    or gateway.is_unspecified or gateway.is_loopback or (port.get('vrf'), str(gateway)) in addresses):
                raise ValueError('invalid next-hop address')
            reachable = gateway.version == 6 and gateway.is_link_local
            for value in port.get('addresses', []):
                interface = ipaddress.ip_interface(value)
                if gateway.version == interface.version and gateway in interface.network:
                    if gateway.version == 4 and interface.network.prefixlen < 31 and gateway in (
                            interface.network.network_address, interface.network.broadcast_address):
                        continue
                    reachable = True
            if not reachable and not route.get('onlink') and not route.get('track_link'):
                raise ValueError('next hop must be directly reachable on route dev')
    rules = cfg.get('rules', [])
    if not isinstance(rules, list) or len(rules) > 256:
        raise ValueError('rules must be a list of at most 256 source-routing policies')
    priorities = set()
    for rule in rules:
        if not isinstance(rule, dict) or not {'from','iif','table','priority'} <= set(rule) or set(rule)-{'from','to','iif','table','priority'}:
            raise ValueError('policy requires from, iif, table and priority; optional to')
        source = ipaddress.ip_network(rule['from'], strict=True)
        if str(source) != rule['from']:
            raise ValueError('policy source must be a canonical prefix')
        if 'to' in rule:
            target = ipaddress.ip_network(rule['to'], strict=True)
            if target.version != source.version or str(target) != rule['to']:
                raise ValueError('policy destination must be canonical and match source family')
        if interfaces.get(rule['iif'], {}).get('mode') != 'l3':
            raise ValueError('policy ingress must be a configured l3 port')
        if type(rule['table']) is not int or rule['table'] not in vrfs.values():
            raise ValueError('policy table must select a configured virtual router')
        priority = rule['priority']
        if type(priority) is not int or not 100 <= priority <= 999 or (source.version, priority) in priorities:
            raise ValueError('policy priority must be unique per family, in 100..999')
        priorities.add((source.version, priority))
    return cfg


def configure_rule(action, rule):
    family = '-4' if ipaddress.ip_network(rule['from']).version == 4 else '-6'
    if action == 'add':
        existing = json.loads(ip(family, '-j', 'rule', 'show'))
        if any(r.get('priority') == rule['priority'] for r in existing):
            raise RuntimeError('policy priority is already occupied')
    args = [family, 'rule', action, 'priority', str(rule['priority']), 'from', rule['from']]
    if 'to' in rule:
        args += ['to', rule['to']]
    args += ['iif', rule['iif'], 'table', str(rule['table'])]
    ip(*args)


def configure_route(action, route):
    if route.get('track_link'):
        from ffn_static_routes import apply
        return apply(sys.modules[__name__],route,delete=action=='del')
    return raw_configure_route(action,route)


def raw_configure_route(action, route):
    family = '-4' if ipaddress.ip_network(route['dst']).version == 4 else '-6'
    args = [family, 'route', action]
    if route.get('type') == 'blackhole':
        args.append('blackhole')
    args.append(route['dst'])
    if 'via' in route:
        args += ['via', route['via']]
    if 'dev' in route:
        args += ['dev', route['dev']]
    if route.get('onlink') and route.get('via'): args += ['onlink']
    args += ['metric', str(route.get('metric', 100)), 'proto', 'static']
    args += ['table', str(route.get('table', 254))]
    for hop in route.get('nexthops', []):
        args += ['nexthop']
        if 'via' in hop:
            args += ['via', hop['via']]
        args += ['dev', hop['dev'], 'weight', str(hop.get('weight', 1))]
    ip(*args)


def route_ports(route):
    return {route.get('dev')} | {h['dev'] for h in route.get('nexthops', [])}


def route_present(route):
    family = '-4' if ipaddress.ip_network(route['dst']).version == 4 else '-6'
    rows = json.loads(ip(family, '-j', 'route', 'show', 'table', str(route.get('table',254))))
    for row in rows:
        dst = ('0.0.0.0/0' if family == '-4' else '::/0') if row.get('dst') == 'default' else row.get('dst')
        if (dst == route['dst'] and row.get('metric',0) == route.get('metric',100)
                and row.get('protocol') == 'static' and row.get('type','unicast') == route.get('type','unicast')
                and ('onlink' in row.get('flags',[])) == bool(route.get('onlink'))
                and row.get('gateway') == route.get('via') and row.get('dev') == route.get('dev')
                and not route.get('nexthops')):
            return True
    return False


def lookup(cfg, request):
    if not isinstance(request, dict) or set(request)-{'dst','src','vrf'} or 'dst' not in request:
        raise ValueError('lookup requires dst, with optional src and vrf')
    destination = ipaddress.ip_address(request['dst'])
    args = ['-4' if destination.version == 4 else '-6', '-j', 'route', 'get', str(destination)]
    if 'src' in request:
        source = ipaddress.ip_address(request['src'])
        if source.version != destination.version:
            raise ValueError('lookup addresses must have the same family')
        args += ['from', str(source)]
    if 'vrf' in request:
        if request['vrf'] not in cfg.get('vrfs', {}):
            raise ValueError('unknown virtual router')
        args += ['vrf', request['vrf']]
    return {'lookup': json.loads(ip(*args))}


def create_vrf(name, table):
    for family in ('-4', '-6'):
        existing = json.loads(ip(family, '-j', 'route', 'show', 'table', 'all'))
        if any(str(r.get('table')) == str(table) for r in existing):
            raise RuntimeError('VRF table already contains unmanaged routes')
    ip('link', 'add', name, 'type', 'vrf', 'table', str(table))
    installed = []
    try:
        ip('link', 'set', name, 'up')
        # Prevent an unresolved lookup falling through to the main table.
        for family in ('-4', '-6'):
            ip(family, 'route', 'add', 'unreachable', 'default', 'table', str(table),
               'metric', '4278198272', 'proto', 'static')
            installed.append(family)
    except BaseException:
        for family in reversed(installed):
            ip(family, 'route', 'del', 'unreachable', 'default', 'table', str(table),
               'metric', '4278198272', 'proto', 'static')
        ip('link', 'delete', name)
        raise


def delete_vrf(name, table):
    for family in ('-4', '-6'):
        for route in json.loads(ip(family, '-j', 'route', 'show', 'table', str(table))):
            if not (route.get('type') == 'unreachable' and route.get('dst') == 'default'
                    and route.get('metric') == 4278198272 and route.get('protocol') == 'static'):
                raise RuntimeError('virtual router still has routes; refusing removal')
    removed = []
    try:
        for family in ('-4', '-6'):
            ip(family, 'route', 'del', 'unreachable', 'default', 'table', str(table),
               'metric', '4278198272', 'proto', 'static')
            removed.append(family)
        ip('link', 'delete', name)
    except BaseException:
        for family in removed:
            ip(family, 'route', 'add', 'unreachable', 'default', 'table', str(table),
               'metric', '4278198272', 'proto', 'static')
        raise

def exists():
    return any(x['name'] == NS for x in json.loads(run('ip', '-j', 'netns', 'list') or '[]'))

def remember_tap_mac(name, current):
    """Preserve the first real TAP identity across namespace/DP recreation.

    Call under the network owner lock. This is per-appliance runtime identity,
    never a site address or a MAC copied from a development appliance.
    """
    def valid(value):
        return (isinstance(value,str) and re.fullmatch(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}',value)
                and value!='00:00:00:00:00:00' and not int(value[:2],16)&1)
    if not re.fullmatch(r'p[1-9][0-9]*',name) or not valid(current):raise ValueError('Invalid TAP identity')
    path=STATE.with_name('port-macs.json')
    saved=json.loads(path.read_text()) if path.exists() else {}
    if not isinstance(saved,dict) or any(not re.fullmatch(r'p[1-9][0-9]*',key) or not valid(value) for key,value in saved.items()):
        raise ValueError('Invalid persisted TAP identities')
    if name in saved:return saved[name]
    saved[name]=current;path.parent.mkdir(parents=True,exist_ok=True)
    temp=path.with_name(path.name+'.'+str(os.getpid())+'.tmp')
    with temp.open('w') as stream:
        os.chmod(temp,0o600);json.dump(saved,stream);stream.flush();os.fsync(stream.fileno())
    temp.replace(path)
    fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(fd)
    finally:os.close(fd)
    return current


def configure_port(name, settings, create=False):
    if create:
        if PORT_BACKEND == 'native':
            ip('-j', 'link', 'show', 'dev', name)  # Must already be provisioned in the data namespace.
        else:
            run('ip', 'netns', 'exec', NS, 'ip', 'tuntap', 'add', 'dev', name, 'mode', 'tap')
    current = json.loads(ip('-j', 'link', 'show', 'dev', name))[0]
    if PORT_BACKEND == 'tap':
        identity=remember_tap_mac(name,current['address'])
        if current['address']!=identity:
            if not create:raise RuntimeError('TAP MAC changed outside the network owner; refusing live identity replacement')
            ip('link','set',name,'address',identity)
    ip('link', 'set', name, 'down')
    if 'management' in settings:
        from ffn_interface_management import apply as apply_management
        apply_management(NS, name, settings)
    if 'master' in current:
        if current['master'] == 'br-data':
            run('ip', 'netns', 'exec', NS, 'bridge', 'vlan', 'del', 'dev', name, 'vid', '1-4094')
        ip('link', 'set', name, 'nomaster')
    ip('address', 'flush', 'dev', name)
    ip('link', 'set', name, 'mtu', str(settings.get('mtu', 1500)))
    mode = settings['mode']
    if mode == 'l2':
        ip('link', 'set', name, 'master', 'br-data')
        for vlan in settings['vlans']:
            flags = ('pvid', 'untagged') if vlan == settings.get('pvid') else ()
            run('ip', 'netns', 'exec', NS, 'bridge', 'vlan', 'add', 'dev', name, 'vid', str(vlan), *flags)
    elif mode == 'l3':
        if 'vrf' in settings:
            ip('link', 'set', name, 'master', settings['vrf'])
        for address in settings.get('addresses', []):
            ip('address', 'add', address, 'dev', name)
    if mode != 'disabled':
        ip('link', 'set', name, 'up')

def start(cfg):
    if PORT_BACKEND == 'native':
        if not exists(): raise RuntimeError('provision the isolated data namespace first')
        for name in cfg['ports']: ip('-j', 'link', 'show', 'dev', name)
    else:
        if exists(): raise RuntimeError('ffn-data already exists')
        run('ip', 'netns', 'add', NS)
    try:
        ip('link', 'set', 'lo', 'up')
        ip('link', 'add', 'br-data', 'type', 'bridge', 'vlan_filtering', '1', 'vlan_default_pvid', '0', 'stp_state', '1')
        ip('link', 'set', 'br-data', 'up')
        for name, table in cfg.get('vrfs', {}).items():
            create_vrf(name, table)
        for setting in ('net.ipv4.ip_forward=1', 'net.ipv6.conf.all.forwarding=1',
                        'net.ipv4.conf.all.send_redirects=0', 'net.ipv4.conf.default.send_redirects=0'):
            run('ip', 'netns', 'exec', NS, 'python3', '-c',
                "import sys; from pathlib import Path; k,v=sys.argv[1].split('='); "
                "Path('/proc/sys/'+k.replace('.', '/')).write_text(v+'\\n')", setting)
        for name, settings in cfg['ports'].items():
            configure_port(name, settings, create=True)
        for route in cfg.get('routes', []):
            configure_route('add', route)
        for rule in cfg.get('rules', []):
            configure_rule('add', rule)
    except BaseException:
        if PORT_BACKEND != 'native': run('ip', 'netns', 'delete', NS)
        raise

def save(cfg):
    temp = STATE.with_suffix('.tmp')
    with temp.open('w') as f:
        json.dump(cfg, f, indent=2)
        f.write('\n')
        f.flush()
        os.fsync(f.fileno())
    temp.replace(STATE)
    directory = os.open(STATE.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)

def backend():
    if PORT_BACKEND == 'native':
        links = json.loads(ip('-j', 'link')) if exists() else []
        return {'transport': 'native Linux interfaces', 'ports': [int(x['ifname'][1:]) for x in links if re.fullmatch(r'p[1-9][0-9]{0,3}', x['ifname'])], 'max_mtu': 9000}
    path = Path('/run/ffn-fabric.json')
    if path.exists():
        state = json.loads(path.read_text())
        if Path('/proc', str(state['pid'])).exists():
            return state
    return {'transport': 'TAP; no physical backend attached', 'ports': []}

def prepare(cfg, request):
    if not isinstance(request, dict):
        raise ValueError('request must be an object')
    if ('revision' not in request or set(request)-{'revision', 'ports', 'routes', 'vrfs', 'rules'}
            or not ({'ports', 'routes', 'vrfs', 'rules'} & set(request)) or type(request['revision']) is not int
            or request['revision'] != cfg['revision'] or not isinstance(request.get('ports', {}), dict)):
        raise ValueError('revision conflict or invalid request; fetch status first')
    if PORT_BACKEND == 'native' and set(request.get('ports', {})) - set(cfg['ports']):
        raise ValueError('native interfaces must be provisioned before runtime configuration')
    new = json.loads(json.dumps(cfg))
    new['ports'].update(request.get('ports', {}))
    if 'routes' in request:
        new['routes'] = request['routes']
    if 'vrfs' in request:
        new['vrfs'] = request['vrfs']
    if 'rules' in request:
        new['rules'] = request['rules']
    new['revision'] += 1
    validate(new)
    old_vrfs, new_vrfs = cfg.get('vrfs', {}), new.get('vrfs', {})
    if any(name in new_vrfs and new_vrfs[name] != table for name, table in old_vrfs.items()):
        raise ValueError('remove a virtual router before changing its table ID')
    attachment = backend()
    if REQUIRE_ATTACHMENT:
        attached = attached_interfaces(attachment)
        needed = {name for name, settings in request.get('ports', {}).items() if settings['mode'] != 'disabled'}
        for route in request.get('routes', []):
            if route.get('track_link'): continue  # Stored intent; runtime checks attachment/link.
            needed.update(port for port in route_ports(route) if port)
        needed.update(rule['iif'] for rule in request.get('rules', []))
        if needed - attached:
            raise ValueError('requested ports are not attached to the commissioned physical backend')
    for number in attachment['ports']:
        settings = new['ports'].get('p%d' % number, {})
        if settings.get('mtu', 1500) > attachment.get('max_mtu', 1500):
            raise ValueError('active fabric currently supports MTU up to 1500')
    if not exists():
        raise RuntimeError('network service is stopped')
    changed = [p for p in request.get('ports', {}) if cfg['ports'].get(p) != new['ports'][p]]
    for name, settings in request.get('ports', {}).items():
        if name not in changed and settings.get('mode') == 'l3' and live_addresses(name) != set(settings.get('addresses', [])):
            changed.append(name)
    old_routes, new_routes = cfg.get('routes', []), new.get('routes', [])
    retained = [r for r in old_routes if r in new_routes]
    rewired = {p for p in changed if without_management(cfg['ports'].get(p, {})) != without_management(new['ports'][p])
               and not address_update(cfg['ports'].get(p, {}), new['ports'][p])}
    if any(route_ports(r).intersection(rewired) for r in retained):
        raise ValueError('remove dependent routes before reconfiguring their ports')
    old_rules, new_rules = cfg.get('rules', []), new.get('rules', [])
    if any(r in new_rules and r['iif'] in rewired for r in old_rules):
        raise ValueError('remove dependent policies before reconfiguring their ingress ports')
    overlay = OVERLAY_STATE
    if overlay.exists():
        used = {c['underlay'] for c in json.loads(overlay.read_text())['links'].values()}
        if used.intersection(rewired):
            raise ValueError('remove dependent overlays before reconfiguring their underlay ports')
    return new, changed


def without_management(settings):
    return {k:v for k,v in settings.items() if k != 'management'}


def address_update(before, after):
    """L3 address edits do not change the port's link, MTU or VRF owner."""
    return (before.get('mode') == after.get('mode') == 'l3' and
            {k:v for k,v in before.items() if k not in ('addresses', 'management')} ==
            {k:v for k,v in after.items() if k not in ('addresses', 'management')})


def live_addresses(name):
    return {str(ipaddress.ip_interface(str(a['local'])+'/'+str(a['prefixlen'])))
            for row in json.loads(ip('-j', 'address', 'show', 'dev', name))
            for a in row.get('addr_info', []) if a.get('scope') == 'global'}


def update_port(name, before, after):
    if 'management' in before and 'management' not in after:
        from ffn_interface_management import apply as apply_management
        apply_management(NS, name, before, remove=True)
    if address_update(before, after):
        # Read actual addresses so the surrounding transaction can also undo a
        # partially completed edit. Add replacements before removing old IPs.
        current = live_addresses(name)
        wanted = {str(ipaddress.ip_interface(a)) for a in after.get('addresses', [])}
        owned = {str(ipaddress.ip_interface(a)) for a in before.get('addresses', [])}
        # Linux otherwise deletes all secondary IPv4 addresses on the same
        # subnet when the primary is removed, including the new replacement.
        key = 'net.ipv4.conf.' + name + '.promote_secondaries'
        promotion = run('ip', 'netns', 'exec', NS, 'sysctl', '-n', key).strip()
        if promotion not in ('0', '1'): raise RuntimeError('Invalid secondary address promotion state')
        try:
            run('ip', 'netns', 'exec', NS, 'sysctl', '-qw', key + '=1')
            for address in sorted(wanted - current):
                ip('address', 'add', address, 'dev', name)
            for address in sorted((current & owned) - wanted):
                ip('address', 'del', address, 'dev', name)
        finally:
            run('ip', 'netns', 'exec', NS, 'sysctl', '-qw', key + '=' + promotion)
        if not wanted <= live_addresses(name):
            raise RuntimeError('Interface address readback mismatch')
        if 'management' in after:
            from ffn_interface_management import apply as apply_management
            apply_management(NS, name, after)
    elif without_management(before) == without_management(after) and 'management' in after:
        from ffn_interface_management import apply as apply_management
        apply_management(NS, name, after)
    else:
        configure_port(name, after, create=not before)


def patch(cfg, request):
    new, changed = prepare(cfg, request)
    old_vrfs, new_vrfs = cfg.get('vrfs', {}), new.get('vrfs', {})
    old_routes, new_routes = cfg.get('routes', []), new.get('routes', [])
    old_rules, new_rules = cfg.get('rules', []), new.get('rules', [])
    applied = []
    removed_routes, added_routes = [], []
    added_vrfs, removed_vrfs = [], []
    added_rules, removed_rules = [], []
    try:
        for name, table in new_vrfs.items():
            if name not in old_vrfs:
                create_vrf(name, table)
                added_vrfs.append(name)
        for rule in old_rules:
            if rule not in new_rules:
                configure_rule('del', rule)
                removed_rules.append(rule)
        for route in old_routes:
            if route not in new_routes:
                configure_route('del', route)
                removed_routes.append(route)
        for name in changed:
            applied.append(name)
            update_port(name, cfg['ports'].get(name, {}), new['ports'][name])
        for route in new_routes:
            if route not in old_routes or (not route.get('nexthops') and not route_present(route)):
                configure_route('add', route)
                added_routes.append(route)
        for rule in new_rules:
            if rule not in old_rules:
                configure_rule('add', rule)
                added_rules.append(rule)
        for name, table in old_vrfs.items():
            if name not in new_vrfs:
                delete_vrf(name, table)
                removed_vrfs.append((name, table))
        save(new)
    except BaseException as original:
        failures = []
        for rule in reversed(added_rules):
            try:
                configure_rule('del', rule)
            except Exception as error:
                failures.append(str(error))
        for name, table in removed_vrfs:
            try:
                create_vrf(name, table)
            except Exception as error:
                failures.append(str(error))
        for route in reversed(added_routes):
            try:
                configure_route('del', route)
            except Exception as error:
                failures.append(str(error))
        for name in reversed(applied):
            try:
                if name in cfg['ports']:
                    update_port(name, new['ports'][name], cfg['ports'][name])
                else:
                    ip('link', 'delete', name)
            except Exception as error:
                failures.append(str(error))
        for route in removed_routes:
            try:
                configure_route('add', route)
            except Exception as error:
                failures.append(str(error))
        for rule in removed_rules:
            try:
                configure_rule('add', rule)
            except Exception as error:
                failures.append(str(error))
        for name in reversed(added_vrfs):
            try:
                delete_vrf(name, new_vrfs[name])
            except Exception as error:
                failures.append(str(error))
        raise RuntimeError('update failed: %s; rollback errors: %s' % (original, failures)) from original
    return {'revision': new['revision'], 'changed_ports': changed, 'config': new}

def main():
    global PORT_BACKEND
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('action', choices=('check', 'validate', 'apply', 'patch', 'stop', 'status', 'lookup', 'health'))
    p.add_argument('--config', type=Path, default=STATE)
    p.add_argument('--backend', choices=('tap','native'), default=PORT_BACKEND)
    args = p.parse_args()
    PORT_BACKEND = args.backend
    global_state = args.config
    if global_state != STATE:
        if args.action != 'check':
            p.error('alternate config is permitted only for validation')
    with open('/run/ffn-network.lock', 'w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        cfg = validate(json.loads(global_state.read_text()))
        if args.action == 'health':
            import time
            request=json.load(sys.stdin)
            boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
            if (set(request)!={'revision','boot_id','links'} or request['revision']!=cfg['revision'] or request['boot_id']!=boot
                    or not isinstance(request['links'],dict) or len(request['links'])>MAX_PORTS
                    or any(not re.fullmatch(r'p[1-9][0-9]{0,3}',k) or type(v) is not bool for k,v in request['links'].items())):
                raise ValueError('Invalid or obsolete hardware link observation')
            value=dict(request,observed=time.monotonic());path=Path('/run/ffn-route-links.json');temp=path.with_suffix('.tmp')
            temp.write_text(json.dumps(value));temp.chmod(0o600);temp.replace(path)
            result={'acknowledged':True,'revision':cfg['revision']}
        elif args.action == 'apply':
            start(cfg)
            result = {'started': True, 'config': cfg}
        elif args.action == 'validate':
            proposed, changed = prepare(cfg, json.load(sys.stdin))
            result = {'validated': True, 'config': proposed, 'changed_ports': changed}
        elif args.action == 'patch':
            result = patch(cfg, json.load(sys.stdin))
        elif args.action == 'lookup':
            result = lookup(cfg, json.load(sys.stdin))
        elif args.action == 'stop':
            if PORT_BACKEND == 'native': raise RuntimeError('native namespace teardown requires explicit provisioning tools')
            if exists():
                run('ip', 'netns', 'delete', NS)
            result = {'stopped': True}
        elif args.action == 'status':
            result = {'config': cfg, 'running': exists(), 'backend': backend()}
            result['boot_id']=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
            from ffn_static_routes import load as route_health
            result['route_health']=route_health()
            import time
            result['route_health']['fresh']=0<=time.monotonic()-result['route_health'].get('observed',0)<=60
            try:
                services=json.loads(Path('/run/ffn-interface-services/status.json').read_text())
                services['fresh']=(services.get('boot_id')==result['boot_id'] and
                                   0<=time.monotonic()-services.get('observed',0)<=10)
                result['interface_services']=services
            except (OSError,ValueError):
                result['interface_services']={'fresh':False,'channel_ready':False,'services':[]}
            if result['running']:
                result['interfaces'] = json.loads(ip('-j', 'address'))
                result['routes'] = json.loads(ip('-j', 'route'))
                result['routes6'] = json.loads(ip('-6', '-j', 'route'))
                result['vrf_routes'] = {name: {'ipv4': json.loads(ip('-4', '-j', 'route', 'show', 'table', str(table))),
                                              'ipv6': json.loads(ip('-6', '-j', 'route', 'show', 'table', str(table)))}
                                        for name, table in cfg.get('vrfs', {}).items()}
                result['rules'] = {'ipv4': json.loads(ip('-4', '-j', 'rule', 'show')),
                                   'ipv6': json.loads(ip('-6', '-j', 'rule', 'show'))}
        else:
            result = {'validated': True, 'config': cfg}
        print(json.dumps(result, indent=2))

if __name__ == '__main__':
    try:
        main()
    except ValueError as error:
        print(json.dumps({'error': str(error)}))
        raise SystemExit(2)
