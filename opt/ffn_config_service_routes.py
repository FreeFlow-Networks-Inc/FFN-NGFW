# SPDX-License-Identifier: GPL-2.0-or-later
"""Validated, revision-checked candidate service routes (console API, Device > Setup > Services).

The tree shape, the service table and the dataplane intent live in
ffn_service_routes, which has no web-framework dependency; the semantic
rules are the dataplane's own, so a candidate that saves is an intent that
applies on commit through the platform's `service-routes` plane resource.
"""
import asyncio
import hashlib
import ipaddress
import re
import uuid
import xml.etree.ElementTree as ET
from defusedxml import ElementTree as SafeET
from fastapi import Depends, HTTPException
from pydantic import BaseModel, Field

import ffn_service_routes as routes
from ffn_dhcp_intent import interface_inventory, local_device

ENFORCEMENT = ('Service routes are stored in the candidate configuration and installed on the dataplane after a commit; '
               'a service without a route leaves through the management interface.')
INTERFACE = re.compile(r'(ethernet1/([1-9][0-9]{0,3})|ae([1-9][0-9]{0,2}))(\.([1-9][0-9]{0,3}))?\Z')


class ServiceRouteEdit(BaseModel):
    revision: str = Field(pattern=r'^[a-f0-9]{64}$')
    service: str = Field(min_length=1, max_length=32)
    interface: str = Field(default='', max_length=31)     # empty: use the management interface
    address: str = Field(default='', max_length=15)       # empty: the interface's first IPv4 address
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


class ServiceRouteStore:
    def __init__(self, manager, candidate):
        self.manager, self.candidate = manager, candidate

    def load(self, source='candidate'):
        xml = self.manager.get_running() if source == 'running' else self.manager.get_candidate()
        root = SafeET.fromstring(xml, forbid_dtd=True)
        device = local_device(root)
        if device is None:
            fail('Local device not found', 404)
        return root, device, digest(xml)

    def listing(self, source='candidate'):
        root, device, revision = self.load(source)
        try:
            inventory = interface_inventory(root)
            problem = None
        except ValueError as error:
            inventory, problem = {}, str(error)
        try:
            configured = routes.configured(root)
            compiled = routes.compile_intent(root)['routes'] if not problem else {}
            compile_problem = None
        except ValueError as error:
            configured, compiled, compile_problem = {}, {}, str(error)
            try:
                configured = routes.configured(root)
            except ValueError:
                pass
        rows = []
        for name, meta in routes.SERVICES.items():
            source = configured.get(name, {})
            row = dict(service=name, label=meta['label'], ports=['%s/%d' % (p, n) for p, n in meta['ports']],
                       interface=source.get('interface', ''), address=source.get('address', ''), device=None, problems=[])
            if row['interface']:
                if compile_problem and name in (compile_problem or ''):
                    row['problems'].append(compile_problem)
                elif problem:
                    row['problems'].append(problem)
                elif name in compiled:
                    row['device'] = compiled[name]['device']
                    row['address'] = compiled[name]['address']
            rows.append(row)
        choices = [dict(name=n, addresses=[str(ipaddress.ip_interface(a).ip) for a in info['addresses'] if ipaddress.ip_interface(a).version == 4])
                   for n, info in sorted(inventory.items()) if not info.get('dhcp_client')]
        return dict(source=source, revision=revision, services=rows, interface_choices=[c for c in choices if c['addresses']],
                    requires_commit=True, enforcement=ENFORCEMENT)

    def authorise(self, user, revision):
        if user.get('role') not in ('admin', 'superuser'):
            fail('Requires admin or superuser role', 403)
        lock = self.manager.lock_status()
        if lock['locked'] and lock.get('holder') != user['username']:
            fail('Configuration locked by another administrator', 423)
        root, device, current = self.load()
        if revision != current:
            fail('Candidate changed. Refresh and review before retrying.', 409)
        if not lock['locked'] and not self.manager.acquire_lock(user['username'], 'editing service routes'):
            fail('Could not acquire configuration lock', 423)
        return root, device

    def save(self, root, status, **extra):
        self.manager._save(root, self.candidate)
        return dict(status=status, requires_commit=True, revision=digest(self.manager.get_candidate()), **extra)

    def write(self, spec, user):
        if spec.service not in routes.SERVICES:
            fail('Unknown service; known services: ' + ', '.join(sorted(routes.SERVICES)))
        root, device = self.authorise(user, spec.revision)
        container = child(child(child(child(device, 'deviceconfig'), 'system'), 'route'), 'service')
        matches = [e for e in container.findall('entry') if e.get('name') == spec.service]
        if not spec.interface:
            for entry in matches:
                container.remove(entry)
            return self.save(root, 'management', service=spec.service)
        if not INTERFACE.fullmatch(spec.interface):
            fail('Only ethernet1/N, aeN and their subinterfaces can carry a service route')
        try:
            inventory = interface_inventory(root)
        except ValueError as error:
            fail(str(error))
        info = inventory.get(spec.interface)
        if info is None:
            fail('Interface is not configured as layer3 in the candidate: ' + spec.interface)
        if info.get('dhcp_client'):
            fail('A DHCP client interface cannot carry a service route: ' + spec.interface)
        own = [str(ipaddress.ip_interface(a).ip) for a in info['addresses'] if ipaddress.ip_interface(a).version == 4]
        if not own:
            fail('Interface has no static IPv4 address in the candidate: ' + spec.interface)
        if spec.address and spec.address not in own:
            fail('%s is not an address of %s' % (spec.address, spec.interface))
        entry = matches[0] if matches else ET.SubElement(container, 'entry', name=spec.service)
        source = child(entry, 'source')
        child(source, 'interface').text = spec.interface
        address = source.find('address')
        if spec.address:
            child(source, 'address').text = spec.address
        elif address is not None:
            source.remove(address)
        return self.save(root, 'updated' if matches else 'created', service=spec.service)


def plane_status():
    """The dataplane's view through the MP control daemon; never raises."""
    try:
        from ffn_controld_client import ControldClient
        response = ControldClient(timeout=30).plane_request({'v': 1, 'id': str(uuid.uuid4()), 'resource': 'service-routes', 'action': 'status', 'payload': {}})
    except Exception as error:
        return dict(available=False, reason='control daemon unavailable (' + type(error).__name__ + ')')
    if not isinstance(response, dict) or not response.get('ok') or not isinstance(response.get('result'), dict):
        return dict(available=False, reason=str((response or {}).get('error') or 'service-routes resource unavailable')[:200])
    return dict(available=True, **response['result'])


def live_view(listing, status):
    """Committed routes joined with the dataplane's view, for the console."""
    applied = (status.get('config') or {}).get('routes', {}) if status.get('available') else {}
    running = status.get('running') if status.get('available') else None
    rows = []
    for row in listing['services']:
        view = dict(service=row['service'], label=row['label'], interface=row['interface'], address=row['address'])
        if not row['interface']:
            view.update(state='management', detail='leaves through the management interface')
        elif not status.get('available'):
            view.update(state='unavailable', detail=status.get('reason', 'dataplane not reachable'))
        elif row['service'] not in applied:
            view.update(state='pending', detail='not yet applied on the dataplane')
        elif not isinstance(running, dict) or not running.get('link', {}).get('index'):
            view.update(state='pending', detail='dataplane link not up')
        else:
            view.update(state='routed', detail='via %s as %s' % (applied[row['service']]['device'], applied[row['service']]['address']))
        rows.append(view)
    return dict(available=bool(status.get('available')), reason=status.get('reason'), revision=(status.get('config') or {}).get('revision'),
                mp=status.get('mp'), services=rows)


def install(app, current_user, require_admin, audit, manager, candidate, plane=None):
    store = ServiceRouteStore(manager, candidate)
    plane = plane or plane_status

    @app.get('/api/system/service-routes')
    async def service_routes_listing(source: str = 'candidate', user=Depends(current_user)):
        if source not in ('candidate', 'running'):
            fail('Source must be candidate or running')
        result = store.listing(source)
        result['can_edit'] = source == 'candidate' and user.get('role') in ('admin', 'superuser')
        return result

    @app.put('/api/system/service-routes')
    async def service_routes_save(spec: ServiceRouteEdit, user=Depends(current_user)):
        result = store.write(spec, user)
        await audit(user, 'service_route_edit', spec.service)
        return result

    @app.get('/api/system/service-routes/status')
    async def service_routes_status(user=Depends(current_user)):
        status = await asyncio.to_thread(plane)
        return live_view(store.listing('running'), status)
