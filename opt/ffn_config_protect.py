# SPDX-License-Identifier: GPL-2.0-or-later
"""Validated, revision-checked candidate FFN Protect configuration (console API).

The XML reading, the device mapping and the dataplane intent live in
ffn_protect_intent, which has no web-framework dependency; the semantic rules
are the dataplane daemon's own (`ffn_protect_gateway.validate_intent`), so a
candidate that saves is an intent that applies.

Secrets never leave through this API: certificate private keys, local user
password hashes, RADIUS shared secrets and directory CA material are written
into the candidate and reported only as present.
"""
import asyncio
import hashlib
import ipaddress
import re
import subprocess
import tempfile
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Literal, Optional
from defusedxml import ElementTree as SafeET
from fastapi import Depends, HTTPException
from pydantic import BaseModel, Field

import ffn_protect_gateway as daemon
from ffn_protect_intent import (auth_profiles, certificates, gateway_spec, interface_inventory, local_device, parse_pool,  # noqa: F401
                                portal_spec, tunnel_units, users, yes)

ENFORCEMENT = ('FFN Protect portals and gateways are stored in the candidate configuration and served by the dataplane after a '
               'commit; the status below is the dataplane daemon\'s own view.')
INTERFACE = re.compile(r'(ethernet1/([1-9][0-9]{0,3})|ae([1-9][0-9]{0,2}))(\.([1-9][0-9]{0,3}))?\Z')
HOST = re.compile(r'[A-Za-z0-9.-]{1,253}\Z')


class GatewayRef(BaseModel):
    name: str = Field(min_length=1, max_length=253)
    priority: int = Field(default=1, ge=1, le=5)
    description: str = Field(default='', max_length=64)
    class Config:
        extra = 'forbid'


class PortalEdit(BaseModel):
    revision: str = Field(pattern=r'^[a-f0-9]{64}$')
    name: str = Field(min_length=1, max_length=63)
    interface: str = Field(min_length=3, max_length=31)
    address: str = Field(default='', max_length=15)
    certificate: str = Field(min_length=1, max_length=63)
    auth_profile: str = Field(min_length=1, max_length=63)
    login_lifetime: int = Field(default=2592000, ge=60, le=31536000)
    connect_method: Literal['user-logon', 'on-demand', 'pre-logon'] = 'user-logon'
    gateways: list[GatewayRef] = Field(min_length=1, max_length=16)
    root_ca: list[str] = Field(default_factory=list, max_length=4)
    class Config:
        extra = 'forbid'


class GatewayEdit(BaseModel):
    revision: str = Field(pattern=r'^[a-f0-9]{64}$')
    name: str = Field(min_length=1, max_length=63)
    interface: str = Field(min_length=3, max_length=31)
    address: str = Field(default='', max_length=15)
    certificate: str = Field(min_length=1, max_length=63)
    auth_profile: str = Field(min_length=1, max_length=63)
    tunnel: str = Field(pattern=r'^tunnel\.[1-9][0-9]{0,3}$')
    tunnel_address: str = Field(min_length=9, max_length=18)
    pools: list[str] = Field(min_length=1, max_length=32)
    dns: list[str] = Field(default_factory=list, max_length=4)
    dns_suffix: list[str] = Field(default_factory=list, max_length=8)
    access_routes: list[str] = Field(default_factory=list, max_length=256)
    exclude_routes: list[str] = Field(default_factory=list, max_length=256)
    ipsec_crypto: Literal['aes-128-cbc', 'aes-256-cbc', 'none'] = 'aes-128-cbc'
    idle_timeout: int = Field(default=3600, ge=60, le=604800)
    login_lifetime: int = Field(default=2592000, ge=60, le=31536000)
    mtu: int = Field(default=1400, ge=576, le=1500)
    hip: bool = False
    class Config:
        extra = 'forbid'


class AuthProfileEdit(BaseModel):
    revision: str = Field(pattern=r'^[a-f0-9]{64}$')
    name: str = Field(min_length=1, max_length=63)
    method: Literal['local', 'ldap', 'radius'] = 'local'
    server_profile: str = Field(default='', max_length=63)
    allow: list[str] = Field(default_factory=list, max_length=1024)
    class Config:
        extra = 'forbid'


class ServerEntry(BaseModel):
    address: str = Field(min_length=1, max_length=253)
    port: int = Field(ge=1, le=65535)
    class Config:
        extra = 'forbid'


class ServerProfileEdit(BaseModel):
    revision: str = Field(pattern=r'^[a-f0-9]{64}$')
    kind: Literal['ldap', 'radius']
    name: str = Field(min_length=1, max_length=63)
    servers: list[ServerEntry] = Field(min_length=1, max_length=4)
    timeout: int = Field(default=5, ge=1, le=60)
    ssl: bool = True
    verify: bool = True
    bind_dn_template: str = Field(default='', max_length=512)
    ca: str = Field(default='', max_length=65536)          # LDAP: PEM; empty keeps the stored one
    secret: str = Field(default='', max_length=128)        # RADIUS: empty keeps the stored one
    class Config:
        extra = 'forbid'


class UserEdit(BaseModel):
    revision: str = Field(pattern=r'^[a-f0-9]{64}$')
    name: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=8, max_length=256)
    class Config:
        extra = 'forbid'


class CertificateEdit(BaseModel):
    revision: str = Field(pattern=r'^[a-f0-9]{64}$')
    name: str = Field(min_length=1, max_length=63)
    mode: Literal['upload', 'self-signed'] = 'upload'
    certificate: str = Field(default='', max_length=65536)
    private_key: str = Field(default='', max_length=65536)
    chain: str = Field(default='', max_length=65536)
    common_name: str = Field(default='', max_length=253)
    alternative_names: list[str] = Field(default_factory=list, max_length=16)
    days: int = Field(default=825, ge=1, le=3650)
    class Config:
        extra = 'forbid'


def as_dict(model):
    return model.model_dump() if hasattr(model, 'model_dump') else model.dict()


def fail(message, code=422):
    raise HTTPException(code, message)


def digest(xml):
    return hashlib.sha256(xml.encode()).hexdigest()


def child(parent, tag, **attributes):
    for node in parent.findall(tag.split('[')[0]) if '[' not in tag else []:
        if all(node.get(k) == v for k, v in attributes.items()):
            return node
    node = parent.find(tag) if not attributes else None
    if node is None:
        node = ET.SubElement(parent, tag, **attributes)
    return node


def scalar(parent, tag, text):
    node = parent.find(tag)
    if text in (None, ''):
        if node is not None:
            parent.remove(node)
        return
    if node is None:
        node = ET.SubElement(parent, tag)
    node.text = str(text)


def set_members(parent, path, values):
    """Replace path/member children with values (the container is removed when empty)."""
    parts = path.split('/')
    node = parent
    for part in parts[:-1]:
        node = child(node, part)
    container = node.find(parts[-1])
    if container is not None:
        node.remove(container)
    if values:
        container = ET.SubElement(node, parts[-1])
        for value in values:
            ET.SubElement(container, 'member').text = value


def xml_safe(*values):
    for text in values:
        if any(not (c in '\t\n\r' or 0x20 <= ord(c) <= 0xD7FF or 0xE000 <= ord(c) <= 0xFFFD or 0x10000 <= ord(c) <= 0x10FFFF) for c in str(text)):
            fail('Invalid XML characters')


def entry_named(container, name):
    return [e for e in container.findall('entry') if e.get('name') == name] if container is not None else []


def openssl(args, cwd, stdin=None):
    try:
        result = subprocess.run(['openssl'] + args, cwd=cwd, input=stdin, capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        fail('openssl is not available on the management plane', 500)
    if result.returncode:
        fail('openssl: ' + result.stderr.strip()[-300:], 422)
    return result.stdout


def certificate_details(pem):
    """subject and not-after of a PEM certificate through openssl; both None when it cannot be parsed."""
    try:
        result = subprocess.run(['openssl', 'x509', '-noout', '-subject', '-enddate'], input=pem, capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return None, None
    if result.returncode:
        return None, None
    subject = not_after = None
    for line in result.stdout.splitlines():
        if line.startswith('subject='):
            subject = line[len('subject='):].strip()
        elif line.startswith('notAfter='):
            not_after = line[len('notAfter='):].strip()
    return subject, not_after


class ProtectStore:
    def __init__(self, manager, candidate):
        self.manager, self.candidate = manager, candidate

    def load(self, source='candidate'):
        xml = self.manager.get_running() if source == 'running' else self.manager.get_candidate()
        root = SafeET.fromstring(xml, forbid_dtd=True)
        device = local_device(root)
        if device is None:
            fail('Local device not found', 404)
        return root, device, digest(xml)

    def shared(self, root):
        node = root.find('shared')
        if node is None:
            node = ET.SubElement(root, 'shared')
        return node

    def vsys(self, device, name='vsys1'):
        matches = [e for e in device.findall('vsys/entry') if e.get('name') == name]
        if matches:
            return matches[0]
        return ET.SubElement(child(device, 'vsys'), 'entry', name=name)

    # ---- reading
    def listing(self, source='candidate'):
        root, device, revision = self.load(source)
        try:
            inventory = interface_inventory(root)
            inventory_problem = None
        except ValueError as error:
            inventory, inventory_problem = {}, str(error)
        units = tunnel_units(root)
        store = root.find('shared')
        certs = certificates(root)
        portals, gateways = [], []
        for vsys in device.findall('vsys/entry'):
            for entry in vsys.findall('global-protect/global-protect-portal/entry'):
                config, client = entry.find('portal-config'), entry.find('client-config')
                row = dict(name=entry.get('name', ''), vsys=vsys.get('name', ''),
                           interface=(config.findtext('local-address/interface') or '') if config is not None else '',
                           address=(config.findtext('local-address/ip/ipv4') or '') if config is not None else '',
                           certificate=(config.findtext('certificate') or '') if config is not None else '',
                           auth_profile=next(((e.findtext('authentication-profile') or '') for e in config.findall('client-auth/entry')), '') if config is not None else '',
                           login_lifetime=int(config.findtext('login-lifetime') or 2592000) if config is not None and (config.findtext('login-lifetime') or '').isdigit() else 2592000,
                           connect_method=(client.findtext('connect-method') or 'user-logon') if client is not None else 'user-logon',
                           gateways=[dict(name=g.get('name', ''), priority=int(g.findtext('priority') or 1) if (g.findtext('priority') or '1').isdigit() else 1,
                                          description=g.findtext('description') or '') for g in (client.findall('gateways/external/list/entry') if client is not None else [])],
                           root_ca=[m.text for m in (client.findall('root-ca/member') if client is not None else [])], problems=[])
                if inventory_problem:
                    row['problems'].append(inventory_problem)
                else:
                    try:
                        portal_spec(entry, inventory)
                    except ValueError as error:
                        row['problems'].append(str(error))
                if row['certificate'] and row['certificate'] not in certs:
                    row['problems'].append('certificate %s is not in the store' % row['certificate'])
                portals.append(row)
            for entry in vsys.findall('global-protect/global-protect-gateway/entry'):
                configs = entry.findall('remote-user-tunnel-configs/entry')
                config = configs[0] if configs else None
                def members(path):
                    node = config.find(path) if config is not None else None
                    return [m.text for m in node.findall('member')] if node is not None else []
                crypto = (entry.findtext('ipsec-crypto') or 'aes-128-cbc').strip()
                row = dict(name=entry.get('name', ''), vsys=vsys.get('name', ''), interface=entry.findtext('local-address/interface') or '',
                           address=entry.findtext('local-address/ip/ipv4') or '', certificate=entry.findtext('certificate') or '',
                           auth_profile=next(((e.findtext('authentication-profile') or '') for e in entry.findall('client-auth/entry')), ''),
                           tunnel=entry.findtext('tunnel-interface') or '', tunnel_address=units.get(entry.findtext('tunnel-interface') or ''),
                           pools=members('ip-pool'), dns=members('dns'), dns_suffix=members('dns-suffix'),
                           access_routes=members('split-tunneling/access-route'), exclude_routes=members('split-tunneling/exclude-access-route'),
                           ipsec_crypto=crypto if crypto in ('aes-128-cbc', 'aes-256-cbc', 'none') else 'aes-128-cbc',
                           idle_timeout=int(entry.findtext('idle-timeout') or 3600) if (entry.findtext('idle-timeout') or '1').isdigit() else 3600,
                           login_lifetime=int(entry.findtext('login-lifetime') or 2592000) if (entry.findtext('login-lifetime') or '1').isdigit() else 2592000,
                           mtu=int(entry.findtext('mtu') or 1400) if (entry.findtext('mtu') or '1').isdigit() else 1400,
                           hip=yes(entry.findtext('hip-collection') or 'no'), problems=[])
                if inventory_problem:
                    row['problems'].append(inventory_problem)
                else:
                    try:
                        gateway_spec(entry, inventory, units)
                    except ValueError as error:
                        row['problems'].append(str(error))
                if row['certificate'] and row['certificate'] not in certs:
                    row['problems'].append('certificate %s is not in the store' % row['certificate'])
                gateways.append(row)
        profiles = []
        for entry in (store.findall('authentication-profile/entry') if store is not None else []):
            method = entry.find('method')
            kind = 'local'
            server_profile = ''
            if method is not None and method.find('ldap') is not None:
                kind, server_profile = 'ldap', method.findtext('ldap/server-profile') or ''
            elif method is not None and method.find('radius') is not None:
                kind, server_profile = 'radius', method.findtext('radius/server-profile') or ''
            profiles.append(dict(name=entry.get('name', ''), method=kind, server_profile=server_profile,
                                 allow=[m.text for m in entry.findall('allow-list/member')]))
        server_profiles = dict(ldap=[], radius=[])
        for entry in (store.findall('server-profile/ldap/entry') if store is not None else []):
            server_profiles['ldap'].append(dict(name=entry.get('name', ''), servers=[dict(address=s.findtext('address') or '', port=int(s.findtext('port') or 636))
                                                                                     for s in entry.findall('server/entry')],
                                                ssl=yes(entry.findtext('ssl') or 'yes'), verify=yes(entry.findtext('verify-server-certificate') or 'yes'),
                                                bind_dn_template=entry.findtext('bind-dn-template') or '', has_ca=bool((entry.findtext('ca') or '').strip()),
                                                timeout=int(entry.findtext('timeout') or 5)))
        for entry in (store.findall('server-profile/radius/entry') if store is not None else []):
            server_profiles['radius'].append(dict(name=entry.get('name', ''), servers=[dict(address=s.findtext('ip-address') or '', port=int(s.findtext('port') or 1812))
                                                                                       for s in entry.findall('server/entry')],
                                                  has_secret=bool(entry.findtext('secret')), timeout=int(entry.findtext('timeout') or 5)))
        certificate_rows = []
        for name, cert in sorted(certs.items()):
            subject, not_after = certificate_details(cert['certificate'])
            certificate_rows.append(dict(name=name, subject=subject, not_after=not_after, has_key='PRIVATE KEY' in cert['private_key'], has_chain=bool(cert['chain'])))
        choices = [dict(name=name, addresses=info['addresses'], dhcp_client=info['dhcp_client']) for name, info in sorted(inventory.items())]
        return dict(source=source, revision=revision, portals=portals, gateways=gateways, auth_profiles=profiles, server_profiles=server_profiles,
                    users=[dict(name=n) for n in sorted(users(root))], certificates=certificate_rows, tunnel_units=units,
                    interface_choices=choices, requires_commit=True, enforcement=ENFORCEMENT)

    # ---- writing
    def authorise(self, user, revision):
        if user.get('role') not in ('admin', 'superuser'):
            fail('Requires admin or superuser role', 403)
        lock = self.manager.lock_status()
        if lock['locked'] and lock.get('holder') != user['username']:
            fail('Configuration locked by another administrator', 423)
        root, device, current = self.load()
        if revision != current:
            fail('Candidate changed. Refresh and review before retrying.', 409)
        if not lock['locked'] and not self.manager.acquire_lock(user['username'], 'editing FFN Protect'):
            fail('Could not acquire configuration lock', 423)
        return root, device

    def save(self, root, status, **extra):
        self.manager._save(root, self.candidate)
        return dict(status=status, requires_commit=True, revision=digest(self.manager.get_candidate()), **extra)

    def check_name(self, name, what):
        if not daemon.NAME.fullmatch(name):
            fail('%s: name may use letters, digits, dot, dash and underscore' % what)
        return name

    def local_address_check(self, root, spec):
        if not INTERFACE.fullmatch(spec.interface):
            fail('Only ethernet1/N, aeN and their subinterfaces can host a portal or gateway')
        try:
            inventory = interface_inventory(root)
        except ValueError as error:
            fail(str(error))
        info = inventory.get(spec.interface)
        if info is None:
            fail('Interface is not configured as layer3 in the candidate: ' + spec.interface)
        if info['dhcp_client']:
            fail('A DHCP client interface cannot host a portal or gateway: ' + spec.interface)
        own = [str(ipaddress.ip_interface(a).ip) for a in info['addresses'] if ipaddress.ip_interface(a).version == 4]
        if not own:
            fail('Interface has no static IPv4 address in the candidate: ' + spec.interface)
        if spec.address and spec.address not in own:
            fail('%s is not an address of %s' % (spec.address, spec.interface))
        return spec.address or own[0]

    def references(self, root, certificate, auth_profile):
        if certificate not in certificates(root):
            fail('Certificate is not in the store: ' + certificate)
        if auth_profile not in [e.get('name') for e in self.shared(root).findall('authentication-profile/entry')]:
            fail('Authentication profile is not configured: ' + auth_profile)

    def write_portal(self, spec, user):
        self.check_name(spec.name, 'Portal')
        xml_safe(spec.name, spec.interface, spec.address, spec.certificate, spec.auth_profile, *spec.root_ca,
                 *[g.name + g.description for g in spec.gateways])
        root, device = self.authorise(user, spec.revision)
        address = self.local_address_check(root, spec)
        self.references(root, spec.certificate, spec.auth_profile)
        certs = certificates(root)
        for name in spec.root_ca:
            if name not in certs:
                fail('Root CA certificate is not in the store: ' + name)
        for g in spec.gateways:
            if not HOST.fullmatch(g.name):
                fail('Gateway entries name a host or address: ' + g.name)
        container = child(child(child(self.vsys(device), 'global-protect'), 'global-protect-portal'))
        matches = entry_named(container, spec.name)
        entry = matches[0] if matches else ET.SubElement(container, 'entry', name=spec.name)
        config = child(entry, 'portal-config')
        local = child(config, 'local-address')
        scalar(local, 'interface', spec.interface)
        scalar(child(local, 'ip'), 'ipv4', address)
        scalar(config, 'certificate', spec.certificate)
        auth = config.find('client-auth')
        if auth is not None:
            config.remove(auth)
        scalar(ET.SubElement(ET.SubElement(config, 'client-auth'), 'entry', name='default'), 'authentication-profile', spec.auth_profile)
        scalar(config, 'login-lifetime', spec.login_lifetime)
        client = child(entry, 'client-config')
        scalar(client, 'connect-method', spec.connect_method)
        gateways = client.find('gateways')
        if gateways is not None:
            client.remove(gateways)
        listing = child(child(child(client, 'gateways'), 'external'), 'list')
        for g in spec.gateways:
            node = ET.SubElement(listing, 'entry', name=g.name)
            scalar(node, 'priority', g.priority)
            scalar(node, 'description', g.description)
        set_members(client, 'root-ca', spec.root_ca)
        return self.save(root, 'updated' if matches else 'created', name=spec.name)

    def write_gateway(self, spec, user):
        self.check_name(spec.name, 'Gateway')
        xml_safe(spec.name, spec.interface, spec.address, spec.certificate, spec.auth_profile, spec.tunnel, spec.tunnel_address, *spec.pools,
                 *spec.dns, *spec.dns_suffix, *spec.access_routes, *spec.exclude_routes)
        root, device = self.authorise(user, spec.revision)
        address = self.local_address_check(root, spec)
        self.references(root, spec.certificate, spec.auth_profile)
        try:
            tunnel_address = ipaddress.IPv4Interface(spec.tunnel_address)
            pools = [parse_pool(p) for p in spec.pools]
            dns = [str(ipaddress.IPv4Address(a)) for a in spec.dns]
            routes = [str(ipaddress.IPv4Network(r)) for r in spec.access_routes]
            excludes = [str(ipaddress.IPv4Network(r)) for r in spec.exclude_routes]
        except ValueError as error:
            fail(str(error))
        for suffix in spec.dns_suffix:
            if not HOST.fullmatch(suffix):
                fail('Invalid DNS suffix: ' + suffix)
        for other in device.iter('entry'):
            pass
        for vsys in device.findall('vsys/entry'):
            for other in vsys.findall('global-protect/global-protect-gateway/entry'):
                if other.get('name') != spec.name and (other.findtext('tunnel-interface') or '') == spec.tunnel:
                    fail('Tunnel interface %s is used by gateway %s' % (spec.tunnel, other.get('name')))
        candidate = dict(interface='p1', address=address, certificate=spec.certificate, auth_profile=spec.auth_profile, tunnel=spec.tunnel,
                         tunnel_address=str(tunnel_address), pools=pools, dns=dns, dns_suffix=spec.dns_suffix, access_routes=routes,
                         exclude_routes=excludes, tunnel_mode='ssl-only' if spec.ipsec_crypto == 'none' else 'esp-ssl',
                         crypto='aes-128-cbc' if spec.ipsec_crypto == 'none' else spec.ipsec_crypto, idle_timeout=spec.idle_timeout,
                         login_lifetime=spec.login_lifetime, mtu=spec.mtu, hip=spec.hip)
        try:
            daemon.validate_intent(dict(protect=dict(certificates={spec.certificate: dict(certificate='-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----',
                                                                                             private_key='-----BEGIN ' + 'PRIVATE KEY-----\n-----END ' + 'PRIVATE KEY-----')},
                                                     auth_profiles={spec.auth_profile: dict(method='local')}, users={}, portals={}, gateways={spec.name: candidate})))
        except ValueError as error:
            fail(str(error))
        # the tunnel unit carries the gateway's address; the zone it belongs to is set on the zones page
        tunnel_container = child(child(child(child(device, 'network'), 'interface'), 'tunnel'))
        parent = entry_named(tunnel_container, 'tunnel')
        parent = parent[0] if parent else ET.SubElement(tunnel_container, 'entry', name='tunnel')
        units = child(parent, 'units')
        unit = entry_named(units, spec.tunnel)
        unit = unit[0] if unit else ET.SubElement(units, 'entry', name=spec.tunnel)
        ip = unit.find('ip')
        if ip is not None:
            unit.remove(ip)
        ET.SubElement(ET.SubElement(unit, 'ip'), 'entry', name=str(tunnel_address))
        container = child(child(child(self.vsys(device), 'global-protect'), 'global-protect-gateway'))
        matches = entry_named(container, spec.name)
        entry = matches[0] if matches else ET.SubElement(container, 'entry', name=spec.name)
        local = child(entry, 'local-address')
        scalar(local, 'interface', spec.interface)
        scalar(child(local, 'ip'), 'ipv4', address)
        scalar(entry, 'certificate', spec.certificate)
        auth = entry.find('client-auth')
        if auth is not None:
            entry.remove(auth)
        scalar(ET.SubElement(ET.SubElement(entry, 'client-auth'), 'entry', name='default'), 'authentication-profile', spec.auth_profile)
        scalar(entry, 'tunnel-mode', 'yes')
        scalar(entry, 'tunnel-interface', spec.tunnel)
        configs = entry.find('remote-user-tunnel-configs')
        if configs is not None:
            entry.remove(configs)
        config = ET.SubElement(ET.SubElement(entry, 'remote-user-tunnel-configs'), 'entry', name='default')
        set_members(config, 'ip-pool', ['-'.join(dict.fromkeys(p)) for p in pools])
        set_members(config, 'dns', dns)
        set_members(config, 'dns-suffix', spec.dns_suffix)
        set_members(config, 'split-tunneling/access-route', routes)
        set_members(config, 'split-tunneling/exclude-access-route', excludes)
        scalar(entry, 'ipsec-crypto', spec.ipsec_crypto)
        scalar(entry, 'idle-timeout', spec.idle_timeout)
        scalar(entry, 'login-lifetime', spec.login_lifetime)
        scalar(entry, 'mtu', spec.mtu)
        scalar(entry, 'hip-collection', 'yes' if spec.hip else 'no')
        return self.save(root, 'updated' if matches else 'created', name=spec.name, tunnel=spec.tunnel)

    def remove_entry(self, kind, name, revision, user):
        root, device = self.authorise(user, revision)
        removed = False
        for vsys in device.findall('vsys/entry'):
            container = vsys.find('global-protect/global-protect-' + kind)
            for entry in entry_named(container, name):
                container.remove(entry)
                removed = True
        if not removed:
            fail(kind.capitalize() + ' not found', 404)
        return self.save(root, 'deleted', name=name)

    def write_auth_profile(self, spec, user):
        self.check_name(spec.name, 'Authentication profile')
        xml_safe(spec.name, spec.server_profile, *spec.allow)
        for name in spec.allow:
            if not daemon.USERNAME.fullmatch(name):
                fail('Invalid user name in the allow list: ' + name)
        root, device = self.authorise(user, spec.revision)
        store = self.shared(root)
        if spec.method != 'local':
            if not entry_named(store.find('server-profile/' + spec.method), spec.server_profile):
                fail('%s server profile is not configured: %s' % (spec.method.upper(), spec.server_profile))
        container = child(store, 'authentication-profile')
        matches = entry_named(container, spec.name)
        entry = matches[0] if matches else ET.SubElement(container, 'entry', name=spec.name)
        method = entry.find('method')
        if method is not None:
            entry.remove(method)
        method = ET.SubElement(entry, 'method')
        if spec.method == 'local':
            ET.SubElement(method, 'local-database')
        else:
            scalar(ET.SubElement(method, spec.method), 'server-profile', spec.server_profile)
        set_members(entry, 'allow-list', spec.allow)
        return self.save(root, 'updated' if matches else 'created', name=spec.name)

    def remove_shared(self, path, name, revision, user, what):
        root, device = self.authorise(user, revision)
        container = self.shared(root).find(path)
        matches = entry_named(container, name)
        if not matches:
            fail(what + ' not found', 404)
        for entry in matches:
            container.remove(entry)
        return self.save(root, 'deleted', name=name)

    def write_server_profile(self, spec, user):
        self.check_name(spec.name, 'Server profile')
        xml_safe(spec.name, spec.bind_dn_template, spec.ca, spec.secret, *[s.address for s in spec.servers])
        for server in spec.servers:
            if not HOST.fullmatch(server.address):
                fail('Invalid server address: ' + server.address)
        if spec.kind == 'ldap' and '{user}' not in spec.bind_dn_template:
            fail('The bind DN template must contain {user}, for example uid={user},ou=people,dc=example,dc=com or {user}@example.com')
        if spec.ca and ('-----BEGIN CERTIFICATE-----' not in spec.ca or '-----END CERTIFICATE-----' not in spec.ca):
            fail('The CA must be a PEM certificate')
        root, device = self.authorise(user, spec.revision)
        container = child(child(self.shared(root), 'server-profile'), spec.kind)
        matches = entry_named(container, spec.name)
        entry = matches[0] if matches else ET.SubElement(container, 'entry', name=spec.name)
        if spec.kind == 'radius' and not spec.secret and not entry.findtext('secret'):
            fail('A shared secret is required')
        servers = entry.find('server')
        if servers is not None:
            entry.remove(servers)
        servers = ET.SubElement(entry, 'server')
        for index, server in enumerate(spec.servers, 1):
            node = ET.SubElement(servers, 'entry', name='server%d' % index)
            scalar(node, 'address' if spec.kind == 'ldap' else 'ip-address', server.address)
            scalar(node, 'port', server.port)
        scalar(entry, 'timeout', spec.timeout)
        if spec.kind == 'ldap':
            scalar(entry, 'ssl', 'yes' if spec.ssl else 'no')
            scalar(entry, 'verify-server-certificate', 'yes' if spec.verify else 'no')
            scalar(entry, 'bind-dn-template', spec.bind_dn_template)
            if spec.ca:
                scalar(entry, 'ca', spec.ca.strip())
        elif spec.secret:
            scalar(entry, 'secret', spec.secret)
        return self.save(root, 'updated' if matches else 'created', name=spec.name, kind=spec.kind)

    def write_user(self, spec, user):
        if not daemon.USERNAME.fullmatch(spec.name):
            fail('User names use letters, digits, dot, dash, underscore, @ and backslash')
        root, device = self.authorise(user, spec.revision)
        container = child(child(self.shared(root), 'local-user-database'), 'user')
        matches = entry_named(container, spec.name)
        entry = matches[0] if matches else ET.SubElement(container, 'entry', name=spec.name)
        scalar(entry, 'phash', daemon.make_phash(spec.password))
        return self.save(root, 'updated' if matches else 'created', name=spec.name)

    def write_certificate(self, spec, user):
        self.check_name(spec.name, 'Certificate')
        root, device = self.authorise(user, spec.revision)
        if spec.mode == 'upload':
            certificate, key, chain = spec.certificate.strip(), spec.private_key.strip(), spec.chain.strip()
            if '-----BEGIN CERTIFICATE-----' not in certificate or 'PRIVATE KEY-----' not in key:
                fail('Upload needs a PEM certificate and its PEM private key')
            with tempfile.TemporaryDirectory(prefix='ffn-protect-cert-') as work:
                Path(work, 'cert.pem').write_text(certificate + '\n')
                Path(work, 'key.pem').write_text(key + '\n')
                cert_key = openssl(['x509', '-noout', '-pubkey', '-in', 'cert.pem'], work)
                own_key = openssl(['pkey', '-pubout', '-in', 'key.pem'], work)
                if cert_key.strip() != own_key.strip():
                    fail('The private key does not match the certificate')
        else:
            if not HOST.fullmatch(spec.common_name):
                fail('A common name (host name or address) is required')
            names = ['DNS:' + n if not re.fullmatch(r'[0-9.]+', n) else 'IP:' + n for n in [spec.common_name] + spec.alternative_names if HOST.fullmatch(n)]
            with tempfile.TemporaryDirectory(prefix='ffn-protect-cert-') as work:
                openssl(['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-sha256', '-days', str(spec.days), '-subj', '/CN=' + spec.common_name,
                         '-addext', 'subjectAltName=' + ','.join(dict.fromkeys(names)), '-addext', 'extendedKeyUsage=serverAuth',
                         '-keyout', 'key.pem', '-out', 'cert.pem'], work)
                certificate, key, chain = Path(work, 'cert.pem').read_text().strip(), Path(work, 'key.pem').read_text().strip(), ''
        xml_safe(certificate, key, chain)
        container = child(self.shared(root), 'certificate')
        matches = entry_named(container, spec.name)
        entry = matches[0] if matches else ET.SubElement(container, 'entry', name=spec.name)
        scalar(entry, 'public-key', certificate)
        scalar(entry, 'private-key', key)
        scalar(entry, 'chain', chain)
        subject, not_after = certificate_details(certificate + '\n')
        return self.save(root, 'updated' if matches else 'created', name=spec.name, subject=subject, not_after=not_after)


def plane_status():
    """The dataplane daemon's view through the MP control daemon; never raises."""
    try:
        from ffn_controld_client import ControldClient
        response = ControldClient(timeout=30).plane_request({'v': 1, 'id': str(uuid.uuid4()), 'resource': 'protect', 'action': 'status', 'payload': {}})
    except Exception as error:
        return dict(available=False, reason='control daemon unavailable (' + type(error).__name__ + ')')
    if not isinstance(response, dict) or not response.get('ok') or not isinstance(response.get('result'), dict):
        return dict(available=False, reason=str((response or {}).get('error') or 'protect resource unavailable')[:200])
    return dict(available=True, **response['result'])


def live_view(listing, status):
    """Committed portals and gateways joined with the daemon's view, for the console."""
    running = status.get('running') if status.get('available') else None
    running = running if isinstance(running, dict) else None
    live_gateways = (running or {}).get('gateways', {})
    listeners = (running or {}).get('listeners', [])
    rows = []
    for row in listing['gateways']:
        view = dict(name=row['name'], tunnel=row['tunnel'], address=row['address'], interface=row['interface'])
        live = live_gateways.get(row['name'])
        if not status.get('available'):
            view.update(state='unavailable', detail=status.get('reason', 'dataplane not reachable'))
        elif running is None:
            view.update(state='pending', detail='the dataplane daemon is not running')
        elif live is None:
            view.update(state='pending', detail='not yet applied on the dataplane')
        else:
            view.update(state=live.get('state'), detail=live.get('detail', ''), sessions=live.get('sessions', 0), pool_size=live.get('pool_size'),
                        pool_used=live.get('pool_used'), totals=live.get('totals', {}))
        rows.append(view)
    portals = []
    for row in listing['portals']:
        served = any(l.get('address') == row['address'] and l.get('owners', {}).get('portal') == row['name'] for l in listeners)
        portals.append(dict(name=row['name'], address=row['address'], interface=row['interface'],
                            state='serving' if served else ('unavailable' if not status.get('available') else 'pending')))
    return dict(available=bool(status.get('available')), reason=status.get('reason'), revision=(status.get('config') or {}).get('revision'),
                configuration=(status.get('config') or {}).get('configuration'), daemon_time=(running or {}).get('time'),
                gateways=rows, portals=portals, sessions=(running or {}).get('sessions', []))


def install(app, current_user, require_admin, audit, manager, candidate, plane=None):
    store = ProtectStore(manager, candidate)
    plane = plane or plane_status

    @app.get('/api/config/protect')
    async def protect_listing(source: str = 'candidate', user=Depends(current_user)):
        if source not in ('candidate', 'running'):
            fail('Source must be candidate or running')
        result = store.listing(source)
        result['can_edit'] = source == 'candidate' and user.get('role') in ('admin', 'superuser')
        return result

    @app.put('/api/config/protect/portal')
    async def protect_portal_save(spec: PortalEdit, user=Depends(current_user)):
        result = store.write_portal(spec, user)
        await audit(user, 'protect_portal_edit', spec.name)
        return result

    @app.delete('/api/config/protect/portal/{name}')
    async def protect_portal_delete(name: str, revision: str, user=Depends(current_user)):
        result = store.remove_entry('portal', name, revision, user)
        await audit(user, 'protect_portal_delete', name)
        return result

    @app.put('/api/config/protect/gateway')
    async def protect_gateway_save(spec: GatewayEdit, user=Depends(current_user)):
        result = store.write_gateway(spec, user)
        await audit(user, 'protect_gateway_edit', spec.name)
        return result

    @app.delete('/api/config/protect/gateway/{name}')
    async def protect_gateway_delete(name: str, revision: str, user=Depends(current_user)):
        result = store.remove_entry('gateway', name, revision, user)
        await audit(user, 'protect_gateway_delete', name)
        return result

    @app.put('/api/config/protect/auth-profile')
    async def protect_auth_profile_save(spec: AuthProfileEdit, user=Depends(current_user)):
        result = store.write_auth_profile(spec, user)
        await audit(user, 'protect_auth_profile_edit', spec.name)
        return result

    @app.delete('/api/config/protect/auth-profile/{name}')
    async def protect_auth_profile_delete(name: str, revision: str, user=Depends(current_user)):
        result = store.remove_shared('authentication-profile', name, revision, user, 'Authentication profile')
        await audit(user, 'protect_auth_profile_delete', name)
        return result

    @app.put('/api/config/protect/server-profile')
    async def protect_server_profile_save(spec: ServerProfileEdit, user=Depends(current_user)):
        result = store.write_server_profile(spec, user)
        await audit(user, 'protect_server_profile_edit', spec.kind + '/' + spec.name)
        return result

    @app.delete('/api/config/protect/server-profile/{kind}/{name}')
    async def protect_server_profile_delete(kind: str, name: str, revision: str, user=Depends(current_user)):
        if kind not in ('ldap', 'radius'):
            fail('Kind must be ldap or radius')
        result = store.remove_shared('server-profile/' + kind, name, revision, user, 'Server profile')
        await audit(user, 'protect_server_profile_delete', kind + '/' + name)
        return result

    @app.put('/api/config/protect/user')
    async def protect_user_save(spec: UserEdit, user=Depends(current_user)):
        result = store.write_user(spec, user)
        await audit(user, 'protect_user_edit', spec.name)
        return result

    @app.delete('/api/config/protect/user/{name}')
    async def protect_user_delete(name: str, revision: str, user=Depends(current_user)):
        result = store.remove_shared('local-user-database/user', name, revision, user, 'User')
        await audit(user, 'protect_user_delete', name)
        return result

    @app.post('/api/config/protect/certificate')
    async def protect_certificate_save(spec: CertificateEdit, user=Depends(current_user)):
        result = await asyncio.to_thread(store.write_certificate, spec, user)
        await audit(user, 'protect_certificate_' + spec.mode, spec.name)
        return result

    @app.delete('/api/config/protect/certificate/{name}')
    async def protect_certificate_delete(name: str, revision: str, user=Depends(current_user)):
        result = store.remove_shared('certificate', name, revision, user, 'Certificate')
        await audit(user, 'protect_certificate_delete', name)
        return result

    @app.get('/api/protect/status')
    async def protect_status(user=Depends(current_user)):
        status = await asyncio.to_thread(plane)
        return live_view(store.listing('running'), status)
