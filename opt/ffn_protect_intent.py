# SPDX-License-Identifier: GPL-2.0-or-later
"""The committed FFN Protect tree as the dataplane intent.

Shared by the console's configuration module, the platform provider that
applies a commit, and the convergence check. It depends on the daemon's own
validation rules and the interface address resolver only, never on the web
framework, so configd and the operator command can import it.

PAN-OS shape, simplified to what FFN serves:

    vsys/entry/global-protect/global-protect-portal/entry[@name]/
        portal-config/local-address/{interface, ip/ipv4}
        portal-config/certificate              (shared/certificate entry name)
        portal-config/client-auth/entry/authentication-profile
        portal-config/login-lifetime           (seconds)
        client-config/connect-method           user-logon | on-demand | pre-logon
        client-config/gateways/external/list/entry[@name=host]/{priority, description}
        client-config/root-ca/member           (certificate names the agent installs)
    vsys/entry/global-protect/global-protect-gateway/entry[@name]/
        local-address/{interface, ip/ipv4}, certificate, client-auth/entry/authentication-profile
        tunnel-interface                        (a tunnel unit whose first IPv4 address is the gateway's)
        remote-user-tunnel-configs/entry/{ip-pool/member, dns/member, dns-suffix/member,
                                          split-tunneling/{access-route, exclude-access-route}/member}
        ipsec-crypto                            aes-128-cbc | aes-256-cbc | none (SSL only)
        idle-timeout, login-lifetime (seconds), mtu, hip-collection yes|no
    shared/certificate/entry[@name]/{public-key, private-key, chain}
    shared/authentication-profile/entry[@name]/method/{local-database | ldap/server-profile | radius/server-profile}
                                               /allow-list/member
    shared/server-profile/ldap/entry[@name]/{server/entry/{address, port}, ssl, verify-server-certificate,
                                             bind-dn-template, ca, timeout}
    shared/server-profile/radius/entry[@name]/{server/entry/{ip-address, port}, secret, timeout}
    shared/local-user-database/user/entry[@name]/phash
    network/interface/tunnel/entry/units/entry[@name='tunnel.N']/ip/entry[@name='a.b.c.d/n']

The portal and gateway addresses must be static IPv4 addresses of the named
dataplane interface; the compiled intent carries the interface's device name.
"""
import ipaddress
import re

import ffn_protect_gateway as daemon
from ffn_dhcp_intent import dp_device, interface_inventory, local_device, yes

RANGE = re.compile(r'\s*([0-9.]{7,15})\s*(?:-\s*([0-9.]{7,15})\s*)?\Z')


def members(node, path):
    parent = node.find(path) if node is not None else None
    return [m.text.strip() for m in parent.findall('member')] if parent is not None else []


def parse_pool(text):
    """'a.b.c.d-e.f.g.h' or one address as [first, last]; ValueError otherwise."""
    match = RANGE.fullmatch(text or '')
    if not match:
        raise ValueError('pool %r is not an address or address range' % text)
    first = str(ipaddress.IPv4Address(match.group(1)))
    last = str(ipaddress.IPv4Address(match.group(2))) if match.group(2) else first
    return [first, last]


def text_int(node, tag, default):
    value = (node.findtext(tag) or '').strip() if node is not None else ''
    if not value:
        return default
    if not value.isdigit():
        raise ValueError('%s must be a number' % tag)
    return int(value)


def shared(root):
    node = root.find('shared')
    return node if node is not None else root.find('devices/entry/shared')


def certificates(root):
    """{name: {certificate, private_key, chain}} from the shared certificate store."""
    result = {}
    store = shared(root)
    for entry in (store.findall('certificate/entry') if store is not None else []):
        name = entry.get('name', '')
        result[name] = dict(certificate=(entry.findtext('public-key') or '').strip() + '\n',
                            private_key=(entry.findtext('private-key') or '').strip() + '\n',
                            chain=((entry.findtext('chain') or '').strip() + '\n') if (entry.findtext('chain') or '').strip() else '')
    return result


def users(root):
    store = shared(root)
    result = {}
    for entry in (store.findall('local-user-database/user/entry') if store is not None else []):
        phash = (entry.findtext('phash') or '').strip()
        if phash:
            result[entry.get('name', '')] = dict(phash=phash)
    return result


def auth_profiles(root):
    """{name: profile} in the daemon's shape; a profile that names a missing server profile raises."""
    store = shared(root)
    result = {}
    if store is None:
        return result
    ldap = {e.get('name', ''): e for e in store.findall('server-profile/ldap/entry')}
    radius = {e.get('name', ''): e for e in store.findall('server-profile/radius/entry')}
    for entry in store.findall('authentication-profile/entry'):
        name = entry.get('name', '')
        method = entry.find('method')
        row = None
        if method is None or method.find('local-database') is not None or len(method) == 0:
            row = dict(method='local')
        elif method.find('ldap') is not None:
            profile = ldap.get((method.findtext('ldap/server-profile') or '').strip())
            if profile is None:
                raise ValueError('authentication profile %s: LDAP server profile is missing' % name)
            row = dict(method='ldap', bind_template=(profile.findtext('bind-dn-template') or '').strip(),
                       ssl=yes(profile.findtext('ssl') or 'yes'), verify=yes(profile.findtext('verify-server-certificate') or 'yes'),
                       ca=(profile.findtext('ca') or '').strip(), timeout=text_int(profile, 'timeout', 5),
                       servers=[dict(host=(s.findtext('address') or '').strip(), port=text_int(s, 'port', 636)) for s in profile.findall('server/entry')])
        elif method.find('radius') is not None:
            profile = radius.get((method.findtext('radius/server-profile') or '').strip())
            if profile is None:
                raise ValueError('authentication profile %s: RADIUS server profile is missing' % name)
            row = dict(method='radius', secret=(profile.findtext('secret') or ''), timeout=text_int(profile, 'timeout', 5),
                       servers=[dict(host=(s.findtext('ip-address') or s.findtext('address') or '').strip(), port=text_int(s, 'port', 1812))
                                for s in profile.findall('server/entry')])
        else:
            raise ValueError('authentication profile %s: unsupported method' % name)
        allow = members(entry, 'allow-list')
        if allow and allow != ['all']:
            row['allow'] = allow
        result[name] = row
    return result


def tunnel_units(root):
    """{unit: first IPv4 interface address} for every configured tunnel unit."""
    device = local_device(root)
    result = {}
    if device is None:
        return result
    for unit in device.findall('network/interface/tunnel/entry/units/entry') + device.findall('network/interface/tunnel/units/entry'):
        addresses = [e.get('name', '') for e in unit.findall('ip/entry')]
        result[unit.get('name', '')] = addresses[0] if addresses else None
    return result


def local_address(node, inventory, what):
    """(device, address) for a portal's or gateway's local-address, checked against the interface's own addresses."""
    interface = (node.findtext('local-address/interface') or '').strip()
    address = (node.findtext('local-address/ip/ipv4') or '').strip()
    if not interface:
        raise ValueError(what + ': no interface')
    info = inventory.get(interface)
    if info is None:
        raise ValueError(what + ': %s is not a layer3 dataplane interface in the configuration' % interface)
    if info.get('dhcp_client'):
        raise ValueError(what + ': %s takes its address from DHCP; a static address is required' % interface)
    own = [str(ipaddress.ip_interface(a).ip) for a in info['addresses'] if ipaddress.ip_interface(a).version == 4]
    if not own:
        raise ValueError(what + ': %s has no static IPv4 address' % interface)
    if address and address not in own:
        raise ValueError(what + ': %s is not an address of %s' % (address, interface))
    return dp_device(interface), address or own[0]


def portal_spec(entry, inventory):
    name = entry.get('name', '')
    what = 'portal ' + name
    config, client = entry.find('portal-config'), entry.find('client-config')
    if config is None:
        raise ValueError(what + ': portal-config is missing')
    device, address = local_address(config, inventory, what)
    auth = [(e.findtext('authentication-profile') or '').strip() for e in config.findall('client-auth/entry')]
    gateways = []
    for g in (client.findall('gateways/external/list/entry') if client is not None else []):
        gateways.append(dict(name=g.get('name', ''), priority=text_int(g, 'priority', 1), description=(g.findtext('description') or '').strip()))
    return dict(interface=device, address=address, certificate=(config.findtext('certificate') or '').strip(),
                auth_profile=auth[0] if auth else '', login_lifetime=text_int(config, 'login-lifetime', 2592000),
                connect_method=(client.findtext('connect-method') or 'user-logon').strip() if client is not None else 'user-logon',
                gateways=gateways, root_ca_names=members(client, 'root-ca'))


def gateway_spec(entry, inventory, units):
    name = entry.get('name', '')
    what = 'gateway ' + name
    device, address = local_address(entry, inventory, what)
    auth = [(e.findtext('authentication-profile') or '').strip() for e in entry.findall('client-auth/entry')]
    tunnel = (entry.findtext('tunnel-interface') or '').strip()
    if tunnel not in units:
        raise ValueError(what + ': tunnel interface %r is not configured' % tunnel)
    if not units[tunnel]:
        raise ValueError(what + ': tunnel interface %s has no IPv4 address' % tunnel)
    configs = entry.findall('remote-user-tunnel-configs/entry')
    config = configs[0] if configs else None
    pools = [parse_pool(m) for m in members(config, 'ip-pool')]
    crypto = (entry.findtext('ipsec-crypto') or 'aes-128-cbc').strip()
    return dict(interface=device, address=address, certificate=(entry.findtext('certificate') or '').strip(), auth_profile=auth[0] if auth else '',
                tunnel=tunnel, tunnel_address=units[tunnel], pools=pools, dns=members(config, 'dns'), dns_suffix=members(config, 'dns-suffix'),
                access_routes=members(config, 'split-tunneling/access-route'), exclude_routes=members(config, 'split-tunneling/exclude-access-route'),
                tunnel_mode='ssl-only' if crypto == 'none' else 'esp-ssl', crypto='aes-128-cbc' if crypto == 'none' else crypto,
                idle_timeout=text_int(entry, 'idle-timeout', 3600), login_lifetime=text_int(entry, 'login-lifetime', 2592000),
                mtu=text_int(entry, 'mtu', 1400), hip=yes(entry.findtext('hip-collection') or 'no'))


def describe(root):
    """Every portal and gateway as the console shows it, with per-entry problems instead of one failure."""
    device = local_device(root)
    inventory, units = {}, tunnel_units(root)
    problems = []
    try:
        inventory = interface_inventory(root)
    except ValueError as error:
        problems.append(str(error))
    portals, gateways = [], []
    for vsys in (device.findall('vsys/entry') if device is not None else []):
        for entry in vsys.findall('global-protect/global-protect-portal/entry'):
            row = dict(name=entry.get('name', ''), vsys=vsys.get('name', ''), problems=list(problems))
            try:
                row.update(portal_spec(entry, inventory))
            except ValueError as error:
                row['problems'].append(str(error))
            portals.append(row)
        for entry in vsys.findall('global-protect/global-protect-gateway/entry'):
            row = dict(name=entry.get('name', ''), vsys=vsys.get('name', ''), problems=list(problems))
            try:
                row.update(gateway_spec(entry, inventory, units))
            except ValueError as error:
                row['problems'].append(str(error))
            gateways.append(row)
    return dict(portals=portals, gateways=gateways, tunnel_units=units)


def compile_intent(root):
    """{'protect': intent} for the committed tree, in the daemon's validated shape; ValueError names a bad entry."""
    device = local_device(root)
    empty = dict(certificates={}, auth_profiles={}, users={}, portals={}, gateways={})
    if device is None:
        return dict(protect=empty)
    portals, gateways = {}, {}
    for vsys in device.findall('vsys/entry'):
        portals.update({e.get('name', ''): e for e in vsys.findall('global-protect/global-protect-portal/entry')})
        gateways.update({e.get('name', ''): e for e in vsys.findall('global-protect/global-protect-gateway/entry')})
    if not portals and not gateways:
        return dict(protect=empty)
    inventory, units, certs = interface_inventory(root), tunnel_units(root), certificates(root)
    profiles = auth_profiles(root)
    intent = dict(certificates={}, auth_profiles={}, users=users(root), portals={}, gateways={})
    referenced_certs, referenced_profiles = set(), set()
    for name, entry in portals.items():
        spec = portal_spec(entry, inventory)
        root_ca = ''
        for ca_name in spec.pop('root_ca_names'):
            if ca_name not in certs:
                raise ValueError('portal %s: root CA certificate %r is not in the store' % (name, ca_name))
            root_ca += certs[ca_name]['certificate']
        spec['root_ca'] = root_ca
        referenced_certs.add(spec['certificate'])
        referenced_profiles.add(spec['auth_profile'])
        intent['portals'][name] = spec
    for name, entry in gateways.items():
        spec = gateway_spec(entry, inventory, units)
        referenced_certs.add(spec['certificate'])
        referenced_profiles.add(spec['auth_profile'])
        intent['gateways'][name] = spec
    for name in referenced_certs:
        if name not in certs:
            raise ValueError('certificate %r is not in the store' % name)
        intent['certificates'][name] = certs[name]
    for name in referenced_profiles:
        if name not in profiles:
            raise ValueError('authentication profile %r is not configured' % name)
        intent['auth_profiles'][name] = profiles[name]
    return dict(protect=daemon.validate_intent(dict(protect=intent)))
