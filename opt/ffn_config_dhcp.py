# SPDX-License-Identifier: GPL-2.0-or-later
"""Validated, revision-checked candidate DHCP server configuration (console API).

The XML reading, the device mapping and the dataplane intent live in
ffn_dhcp_intent, which has no web-framework dependency.

PAN-OS shape, under the local device's network tree:

    network/dhcp/interface/entry[@name='ae1.69']/server/
        mode enabled|disabled, probe-ip yes|no
        ip-pool/member            "10.1.0.100-10.1.0.199" (or one address)
        reserved/entry[@name=IP]  mac, description
        option/lease/{timeout (minutes) | unlimited}, gateway, subnet-mask,
        option/dns/{primary,secondary}, ntp/{primary,secondary}, wins/{primary,secondary}, dns-suffix

The server address is the interface's first IPv4 address in the same
configuration; pools and reservations must lie in its network. The semantic
rules are the dataplane daemon's own (`ffn_dhcp_server.validate_server`), so a
candidate that saves is an intent that applies. `compile_intent()` turns the
committed tree into one entry per dataplane device, which the platform
provider applies through the `dhcp` plane resource on commit and on boot.
"""
import asyncio
import hashlib
import ipaddress
import re
import uuid
import xml.etree.ElementTree as ET
from typing import Literal, Optional
from defusedxml import ElementTree as SafeET
from fastapi import Depends, HTTPException
from pydantic import BaseModel, Field

from ffn_dhcp_intent import (INTERFACE, OPTION_PAIRS, compile_intent, describe, dp_device, interface_inventory,  # noqa: F401
                             local_device, parse_pool, server_spec, yes)

ENFORCEMENT = ('DHCP servers are stored in the candidate configuration and served by the dataplane after a commit; '
               'the status below is the dataplane daemon\'s own view.')


class Reservation(BaseModel):
    ip: str = Field(min_length=7, max_length=15)
    mac: str = Field(min_length=17, max_length=17)
    description: str = Field(default='', max_length=255)
    class Config:
        extra = 'forbid'


class DhcpOptions(BaseModel):
    gateway: str = Field(default='', max_length=15)
    subnet_mask: str = Field(default='', max_length=15)
    dns: list[str] = Field(default_factory=list, max_length=2)
    ntp: list[str] = Field(default_factory=list, max_length=2)
    wins: list[str] = Field(default_factory=list, max_length=2)
    dns_suffix: str = Field(default='', max_length=253)
    class Config:
        extra = 'forbid'


class DhcpServerEdit(BaseModel):
    revision: str = Field(pattern=r'^[a-f0-9]{64}$')
    interface: str = Field(min_length=3, max_length=31)
    mode: Literal['enabled', 'disabled'] = 'enabled'
    probe_ip: bool = False
    lease_minutes: Optional[int] = Field(default=1440, ge=1, le=1000000)   # None: unlimited
    pools: list[str] = Field(default_factory=list, max_length=32)
    reserved: list[Reservation] = Field(default_factory=list, max_length=1024)
    options: DhcpOptions = Field(default_factory=DhcpOptions)
    class Config:
        extra = 'forbid'


def fail(message, code=422):
    raise HTTPException(code, message)


def digest(xml):
    return hashlib.sha256(xml.encode()).hexdigest()


def child(parent, tag):
    node = parent.find(tag)
    if node is None:
        node = ET.SubElement(parent, tag)
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


def xml_safe(*values):
    for text in values:
        if any(not (c in '\t\n\r' or 0x20 <= ord(c) <= 0xD7FF or 0xE000 <= ord(c) <= 0xFFFD or 0x10000 <= ord(c) <= 0x10FFFF) for c in text):
            fail('Invalid XML characters')


class DhcpStore:
    def __init__(self, manager, candidate):
        self.manager, self.candidate = manager, candidate

    def load(self, source='candidate'):
        xml = self.manager.get_running() if source == 'running' else self.manager.get_candidate()
        root = SafeET.fromstring(xml, forbid_dtd=True)
        device = local_device(root)
        if device is None:
            fail('Local device not found', 404)
        return root, device, digest(xml)

    def inventory(self, root):
        try:
            return interface_inventory(root)
        except ValueError as error:
            fail(str(error))

    def listing(self, source='candidate'):
        root, device, revision = self.load(source)
        inventory = self.inventory(root)
        rows = []
        for entry in device.findall('network/dhcp/interface/entry'):
            row = describe(entry)
            addresses = inventory.get(row['interface'], {}).get('addresses', [])
            row['address'] = addresses[0] if addresses else None
            row['problems'] = []
            try:
                row['device'] = dp_device(row['interface'])
            except ValueError as error:
                row['device'] = None
                row['problems'].append(str(error))
            if not addresses:
                row['problems'].append('interface has no static IPv4 address')
            elif row['device']:
                try:
                    server_spec(row, addresses[0])
                except ValueError as error:
                    row['problems'].append(str(error))
            rows.append(row)
        configured = {r['interface'] for r in rows}
        choices = [dict(name=name, addresses=info['addresses'], dhcp_client=info['dhcp_client'], has_server=name in configured)
                   for name, info in sorted(inventory.items())]
        return dict(source=source, revision=revision, entries=rows, interface_choices=choices, requires_commit=True,
                    enforcement=ENFORCEMENT)

    def authorise(self, user, revision):
        if user.get('role') not in ('admin', 'superuser'):
            fail('Requires admin or superuser role', 403)
        lock = self.manager.lock_status()
        if lock['locked'] and lock.get('holder') != user['username']:
            fail('Configuration locked by another administrator', 423)
        root, device, current = self.load()
        if revision != current:
            fail('Candidate changed. Refresh and review before retrying.', 409)
        if not lock['locked'] and not self.manager.acquire_lock(user['username'], 'editing DHCP servers'):
            fail('Could not acquire configuration lock', 423)
        return root, device

    def mutate(self, spec, user):
        if not INTERFACE.fullmatch(spec.interface):
            fail('Only ethernet1/N, aeN and their subinterfaces can serve DHCP')
        xml_safe(spec.options.dns_suffix, *[r.description for r in spec.reserved], *spec.pools, *[r.ip + r.mac for r in spec.reserved],
                 spec.options.gateway, spec.options.subnet_mask, *spec.options.dns, *spec.options.ntp, *spec.options.wins)
        root, device = self.authorise(user, spec.revision)
        inventory = self.inventory(root)
        info = inventory.get(spec.interface)
        if info is None:
            fail('Interface is not configured as layer3 in the candidate: ' + spec.interface)
        if info['dhcp_client']:
            fail('A DHCP client interface cannot serve DHCP: ' + spec.interface)
        if not info['addresses']:
            fail('Interface has no static IPv4 address in the candidate: ' + spec.interface)
        described = dict(interface=spec.interface, mode=spec.mode, probe_ip=spec.probe_ip, lease_minutes=spec.lease_minutes,
                         pools=spec.pools, reserved=[r.model_dump() for r in spec.reserved], options=spec.options.model_dump())
        try:
            server_spec(described, info['addresses'][0])
        except ValueError as error:
            fail(str(error))
        container = child(child(child(device, 'network'), 'dhcp'), 'interface')
        matches = [e for e in container.findall('entry') if e.get('name') == spec.interface]
        if len(matches) > 1:
            fail('Duplicate DHCP entries must be repaired first', 409)
        entry = matches[0] if matches else ET.SubElement(container, 'entry', name=spec.interface)
        server = child(entry, 'server')
        scalar(server, 'mode', spec.mode)
        scalar(server, 'probe-ip', 'yes' if spec.probe_ip else 'no')
        for tag in ('ip-pool', 'reserved'):
            node = server.find(tag)
            if node is not None:
                server.remove(node)
        if spec.pools:
            pool = ET.SubElement(server, 'ip-pool')
            for value in spec.pools:
                ET.SubElement(pool, 'member').text = '-'.join(dict.fromkeys(parse_pool(value)))
        if spec.reserved:
            reserved = ET.SubElement(server, 'reserved')
            for row in spec.reserved:
                node = ET.SubElement(reserved, 'entry', name=str(ipaddress.IPv4Address(row.ip)))
                ET.SubElement(node, 'mac').text = row.mac.lower()
                if row.description:
                    ET.SubElement(node, 'description').text = row.description
        option = child(server, 'option')
        lease = option.find('lease')
        if lease is not None:
            option.remove(lease)
        lease = ET.SubElement(option, 'lease')
        if spec.lease_minutes is None:
            ET.SubElement(lease, 'unlimited')
        else:
            ET.SubElement(lease, 'timeout').text = str(spec.lease_minutes)
        scalar(option, 'gateway', spec.options.gateway)
        scalar(option, 'subnet-mask', spec.options.subnet_mask)
        for tag, key in OPTION_PAIRS:
            values = getattr(spec.options, key)
            node = option.find(tag)
            if node is not None:
                option.remove(node)
            if values:
                node = ET.SubElement(option, tag)
                for label, value in zip(('primary', 'secondary'), values):
                    ET.SubElement(node, label).text = value
        scalar(option, 'dns-suffix', spec.options.dns_suffix)
        self.manager._save(root, self.candidate)
        return dict(status='updated' if matches else 'created', interface=spec.interface, requires_commit=True,
                    revision=digest(self.manager.get_candidate()))

    def remove(self, interface, revision, user):
        root, device = self.authorise(user, revision)
        container = device.find('network/dhcp/interface')
        matches = [e for e in container.findall('entry') if e.get('name') == interface] if container is not None else []
        if not matches:
            fail('DHCP server not found', 404)
        for entry in matches:
            container.remove(entry)
        self.manager._save(root, self.candidate)
        return dict(status='deleted', interface=interface, requires_commit=True, revision=digest(self.manager.get_candidate()))


def plane_status():
    """The dataplane daemon's view through the MP control daemon; never raises."""
    try:
        from ffn_controld_client import ControldClient
        response = ControldClient(timeout=30).plane_request({'v': 1, 'id': str(uuid.uuid4()), 'resource': 'dhcp', 'action': 'status', 'payload': {}})
    except Exception as error:
        return dict(available=False, reason=str(error)[:200])
    if not isinstance(response, dict) or not response.get('ok') or not isinstance(response.get('result'), dict):
        return dict(available=False, reason=str((response or {}).get('error') or 'dhcp resource unavailable')[:200])
    return dict(available=True, **response['result'])


def live_view(root, status):
    """Committed servers joined with the daemon's view, for the console."""
    device = local_device(root)
    running = status.get('running') if status.get('available') else None
    served = (running or {}).get('servers', {}) if isinstance(running, dict) else {}
    applied = status.get('config', {}) if status.get('available') else {}
    rows, leases = [], []
    for entry in (device.findall('network/dhcp/interface/entry') if device is not None else []):
        row = describe(entry)
        try:
            row['device'] = dp_device(row['interface'])
        except ValueError:
            row['device'] = None
        live = served.get(row['device']) if row['device'] else None
        if row['mode'] != 'enabled':
            row['state'], row['detail'] = 'disabled', 'server disabled in the committed configuration'
        elif not status.get('available'):
            row['state'], row['detail'] = 'unavailable', status.get('reason', 'dataplane not reachable')
        elif live is None:
            row['state'], row['detail'] = 'pending', 'not yet applied on the dataplane' if row['device'] not in applied.get('servers', {}) else 'daemon has not started this server'
        else:
            row['state'], row['detail'] = live.get('state'), live.get('detail', '')
            row['address'] = live.get('address')
            row['bound'], row['offered'], row['declined'] = live.get('bound', 0), live.get('offered', 0), live.get('declined', 0)
            row['pool_size'], row['counters'], row['last_event'] = live.get('pool_size'), live.get('counters', {}), live.get('last_event')
            for lease in live.get('leases', []):
                leases.append(dict(lease, interface=row['interface'], device=row['device']))
        rows.append(row)
    return dict(available=bool(status.get('available')), reason=status.get('reason'), revision=applied.get('revision'),
                configuration=applied.get('configuration'), daemon_time=(running or {}).get('time') if isinstance(running, dict) else None,
                servers=rows, leases=leases)


def install(app, current_user, require_admin, audit, manager, candidate, plane=None):
    store = DhcpStore(manager, candidate)
    plane = plane or plane_status

    @app.get('/api/config/dhcp')
    async def dhcp_listing(source: str = 'candidate', user=Depends(current_user)):
        if source not in ('candidate', 'running'):
            fail('Source must be candidate or running')
        result = store.listing(source)
        result['can_edit'] = source == 'candidate' and user.get('role') in ('admin', 'superuser')
        return result

    @app.put('/api/config/dhcp')
    async def dhcp_save(spec: DhcpServerEdit, user=Depends(current_user)):
        result = store.mutate(spec, user)
        await audit(user, 'dhcp_server_edit', spec.interface)
        return result

    @app.delete('/api/config/dhcp/{interface:path}')
    async def dhcp_delete(interface: str, revision: str, user=Depends(current_user)):
        if not re.fullmatch(r'[a-f0-9]{64}', revision):
            fail('Candidate revision required')
        result = store.remove(interface, revision, user)
        await audit(user, 'dhcp_server_delete', interface)
        return result

    @app.get('/api/dhcp/status')
    async def dhcp_status(user=Depends(current_user)):
        status = await asyncio.to_thread(plane)
        root = SafeET.fromstring(manager.get_running(), forbid_dtd=True)
        return live_view(root, status)

    @app.get('/api/dhcp/leases')
    async def dhcp_leases(user=Depends(current_user)):
        """Active leases as the dataplane daemon holds them (kept for the earlier console page)."""
        view = await dhcp_status(user)
        leases = [dict(ip=l['ip'], mac=l.get('mac') or '', hostname=l.get('hostname') or '', state=l['state'],
                       expires=l.get('expires'), interface=l['interface']) for l in view['leases']]
        if not view['available']:
            return dict(available=False, leases=[], message='Dataplane DHCP status unavailable: ' + str(view.get('reason') or ''))
        return dict(available=True, source='dataplane', count=len(leases), leases=leases)
