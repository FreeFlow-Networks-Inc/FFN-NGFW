# SPDX-License-Identifier: GPL-2.0-or-later
"""Typed XML object editing. No runtime apply, DNS lookup, or arbitrary XPath."""
import hashlib
import ipaddress
import re
import xml.etree.ElementTree as ET

from defusedxml import ElementTree as SafeET
from fastapi import Depends, HTTPException
from pydantic import BaseModel, Field
from typing import Literal

KINDS = ('address', 'address-group', 'service', 'service-group')
NAME = re.compile(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,62}\Z')


class ObjectEdit(BaseModel):
    revision: str = Field(min_length=64, max_length=64)
    name: str = Field(min_length=1, max_length=63)
    type: str = Field(max_length=32)
    value: str = Field(default='', max_length=4096)
    source_port: str = Field(default='', max_length=4096)
    members: list[str] = Field(default_factory=list, max_length=1024)
    description: str = Field(default='', max_length=1024)

    class Config:
        extra = 'forbid'


def reject(message, status=422):
    raise HTTPException(status, message)


def valid_name(name):
    return bool(NAME.fullmatch(name)) and name not in ('any', 'application-default')


def revision(xml):
    return hashlib.sha256(xml.encode('utf-8')).hexdigest()


def scopes(root):
    out = {}
    shared = root.find('shared')
    if shared is not None:
        out['shared'] = shared
    # Only the local device is editable: never silently select a remote template.
    devices = root.find('devices')
    if devices is not None:
        local = next((e for e in devices.findall('entry') if e.get('name') == 'localhost.localdomain'), None)
        if local is not None:
            for node in local.findall('vsys/entry'):
                name = node.get('name', '')
                if name and name != 'shared':
                    out[name] = node
    return out


def entries(root):
    result = {}
    for scope, node in scopes(root).items():
        for kind in KINDS:
            for entry in node.findall(kind + '/entry'):
                key = (scope, kind, entry.get('name', ''))
                if key in result:
                    reject('Configuration contains duplicate object names; repair before editing', 409)
                result[key] = entry
    return result


def resolve(index, scope, name, family):
    for owner in ([scope, 'shared'] if scope != 'shared' else ['shared']):
        for kind in (family, family + '-group'):
            key = (owner, kind, name)
            if key in index:
                return key
    return None


def group_members(entry, kind):
    container = 'static' if kind == 'address-group' else 'members'
    return [m.text or '' for m in entry.findall(container + '/member')]


def describe(entry, kind):
    value, source_port, members, typ = '', '', [], ''
    supported = valid_name(entry.get('name', ''))
    if kind == 'address':
        options = [tag for tag in ('ip-netmask', 'ip-range', 'fqdn') if entry.find(tag) is not None]
        typ = options[0] if len(options) == 1 else 'unsupported'
        value = entry.findtext(typ, '')
        supported &= len(options) == 1 and all(n.tag in ('description', 'tag', typ) for n in entry)
    elif kind == 'service':
        protocol = entry.find('protocol')
        options = list(protocol) if protocol is not None else []
        typ = options[0].tag if len(options) == 1 else 'unsupported'
        value = entry.findtext('protocol/' + typ + '/port', '')
        source_port = entry.findtext('protocol/' + typ + '/source-port', '')
        supported &= typ in ('tcp', 'udp') and all(n.tag in ('description', 'tag', 'protocol') for n in entry)
        supported &= all(n.tag in ('port', 'source-port') for p in options for n in p)
    else:
        typ = 'static' if entry.find('dynamic') is None else 'dynamic'
        members = group_members(entry, kind)
        supported &= typ == 'static' and all(n.tag in ('description', 'tag', 'static' if kind == 'address-group' else 'members') for n in entry)
    # Never flatten imported nested settings or duplicate scalar fields.
    supported &= len({n.tag for n in entry}) == len(entry)
    for child in entry:
        if child.tag == 'tag':
            continue  # Retained verbatim by the editor.
        for node in child.iter():
            supported &= not node.attrib
            if node.tag in ('description', 'ip-netmask', 'ip-range', 'fqdn', 'port', 'source-port', 'member'):
                supported &= len(node) == 0
        if child.tag in ('static', 'members'):
            supported &= all(n.tag == 'member' for n in child)
        if child.tag == 'protocol':
            supported &= all(len({n.tag for n in proto}) == len(proto) for proto in child)
    return {'name': entry.get('name', ''), 'kind': kind, 'type': typ, 'value': value,
            'source_port': source_port, 'members': members,
            'description': entry.findtext('description', ''), 'editable': bool(supported)}


def ports(value, optional=False):
    if not value and optional:
        return ''
    parts = value.split(',')
    if not 1 <= len(parts) <= 64:
        reject('Use at most 64 port values or ranges')
    result = []
    for part in parts:
        part = part.strip()
        if not re.fullmatch(r'[0-9]{1,5}(-[0-9]{1,5})?', part):
            reject('Ports must be numbers or ranges separated by commas')
        bounds = [int(v) for v in part.split('-')]
        if not all(1 <= v <= 65535 for v in bounds) or bounds[0] > bounds[-1]:
            reject('Port ranges must be ordered and between 1 and 65535')
        result.append('-'.join(str(v) for v in bounds))
    return ','.join(dict.fromkeys(result))


def validate_spec(spec, kind):
    if not valid_name(spec.name):
        reject('Use 1–63 letters, numbers, dots, underscores or hyphens; begin with a letter, number or underscore. Reserved names are not allowed')
    for text in [spec.name, spec.description, spec.value, spec.source_port, *spec.members]:
        if any(not (c in '\n\t\r' or 0x20 <= ord(c) <= 0xD7FF or
                    0xE000 <= ord(c) <= 0xFFFD or 0x10000 <= ord(c) <= 0x10FFFF) for c in text):
            reject('Control characters are not allowed')
    if kind.endswith('-group'):
        if spec.type != 'static' or spec.value or spec.source_port:
            reject('Static groups accept members and a description only')
        if not spec.members or any(not valid_name(m) for m in spec.members):
            reject('Select at least one valid object or group name')
        if len(set(spec.members)) != len(spec.members):
            reject('Group members must be unique')
        return
    if spec.members:
        reject('Only groups accept members')
    if kind == 'service':
        if spec.type not in ('tcp', 'udp'):
            reject('Service protocol must be TCP or UDP')
        spec.value = ports(spec.value)
        spec.source_port = ports(spec.source_port, optional=True)
        return
    if spec.source_port:
        reject('Address objects do not accept source ports')
    try:
        if spec.type == 'ip-netmask':
            spec.value = str(ipaddress.ip_network(spec.value, strict=False))
        elif spec.type == 'ip-range':
            parts = spec.value.split('-')
            if len(parts) != 2:
                raise ValueError()
            start, end = (ipaddress.ip_address(v.strip()) for v in parts)
            if start.version != end.version or int(start) > int(end):
                raise ValueError()
            spec.value = f'{start}-{end}'
        elif spec.type == 'fqdn':
            domain = spec.value.rstrip('.').encode('idna').decode('ascii').lower()
            if len(domain) > 253 or not all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label) for label in domain.split('.')):
                raise ValueError()
            spec.value = domain
        else:
            reject('Address type must be IP/netmask, IP range or FQDN')
    except (ValueError, UnicodeError):
        reject('Invalid address value or range')


def validate_group(root, key):
    index = entries(root)
    active, visited = set(), set()
    def visit(current, depth=0):
        if depth > 64:
            reject('Group nesting exceeds 64 levels')
        if current in active:
            reject('Group membership would create a cycle')
        if current in visited or not current[1].endswith('-group'):
            return
        if index[current].find('dynamic') is not None:
            reject('Dynamic groups cannot be nested through this editor')
        active.add(current)
        for name in group_members(index[current], current[1]):
            target = resolve(index, current[0], name, current[1].split('-')[0])
            if target is None:
                reject('Group member does not exist in this scope: ' + name)
            visit(target, depth + 1)
        active.remove(current)
        visited.add(current)
    visit(key)


def references(root, target):
    """Conservative XML member references, with local/shared name resolution."""
    index = entries(root)
    family = target[1].split('-')[0]
    result = []
    for scope, node in scopes(root).items():
        if resolve(index, scope, target[2], family) != target:
            continue
        def walk(parent, path):
            for child in parent:
                suffix = child.tag + ('[' + child.get('name') + ']' if child.get('name') else '')
                child_path = path + '/' + suffix
                # Ignore tags, descriptions and members belonging to the other family.
                if child.tag in ('description', 'tag', 'service' if family == 'address' else 'address',
                                 'service-group' if family == 'address' else 'address-group'):
                    continue
                if child.tag == 'member' and child.text == target[2]:
                    result.append({'scope': scope, 'path': child_path})
                walk(child, child_path)
        walk(node, scope)
    return result


class ObjectStore:
    def __init__(self, manager, candidate):
        self.manager, self.candidate = manager, candidate

    def load(self, source):
        xml = self.manager.get_running() if source == 'running' else self.manager.get_candidate()
        return SafeET.fromstring(xml, forbid_dtd=True), revision(xml)

    def listing(self, kind, scope, source):
        if kind not in KINDS:
            reject('Unknown object kind', 404)
        root, rev = self.load(source)
        owners = scopes(root)
        if scope not in owners and scope != 'shared':
            reject('Virtual system not found', 404)
        index = entries(root)
        rows = [describe(entry, key[1]) for key, entry in index.items() if key[:2] == (scope, kind)]
        family = kind.split('-')[0]
        choices = {}
        for owner in ['shared', scope]:
            for key in index:
                if key[0] == owner and key[1].split('-')[0] == family:
                    choices[key[2]] = {'name': key[2], 'scope': owner, 'kind': key[1]}
        return {'source': source, 'scope': scope, 'kind': kind, 'revision': rev,
                'scopes': ['shared'] + sorted(k for k in owners if k != 'shared'),
                'entries': sorted(rows, key=lambda r: r['name']),
                'member_choices': sorted(choices.values(), key=lambda r: r['name'])}

    def mutate(self, kind, scope, name, expected, user, spec=None, create=False):
        if kind not in KINDS:
            reject('Unknown object kind', 404)
        lock = self.manager.lock_status()
        if lock['locked'] and lock.get('holder') != user:
            reject('Configuration is locked by another administrator', 423)
        root, rev = self.load('candidate')
        if expected != rev:
            reject('Candidate configuration changed. Refresh and review your edits before retrying', 409)
        owners = scopes(root)
        if scope == 'shared' and scope not in owners:
            owners[scope] = ET.SubElement(root, 'shared')
        if scope not in owners:
            reject('Virtual system not found', 404)
        index = entries(root)
        key = (scope, kind, name)
        entry = index.get(key)
        if create:
            if any((scope, k, name) in index for k in (kind.split('-')[0], kind.split('-')[0] + '-group')):
                reject('An object or group with this name already exists in this scope', 409)
        elif entry is None:
            reject('Object not found', 404)
        elif not describe(entry, kind)['editable']:
            reject('This imported object contains settings that this editor cannot safely modify', 409)
        if spec is None:
            refs = references(root, key)
            if refs:
                reject('Object is referenced. Remove its references before deleting it', 409)
            owners[scope].find(kind).remove(entry)
        else:
            if spec.name != name:
                reject('Renaming is not supported; create a new object and update references')
            validate_spec(spec, kind)
            container = owners[scope].find(kind)
            if container is None:
                container = ET.SubElement(owners[scope], kind)
            if entry is None:
                entry = ET.SubElement(container, 'entry', name=name)
            # Preserve tags; unknown fields are rejected above rather than discarded.
            for child in list(entry):
                if child.tag != 'tag':
                    entry.remove(child)
            if kind.endswith('-group'):
                members = ET.SubElement(entry, 'static' if kind == 'address-group' else 'members')
                for member in spec.members:
                    ET.SubElement(members, 'member').text = member
                validate_group(root, key)
            elif kind == 'address':
                ET.SubElement(entry, spec.type).text = spec.value
            else:
                protocol = ET.SubElement(ET.SubElement(entry, 'protocol'), spec.type)
                ET.SubElement(protocol, 'port').text = spec.value
                if spec.source_port:
                    ET.SubElement(protocol, 'source-port').text = spec.source_port
            if spec.description:
                ET.SubElement(entry, 'description').text = spec.description
        # A newly shadowed name can change other groups' resolution too.
        for group_key, group in entries(root).items():
            if group_key[1].endswith('-group') and group.find('dynamic') is None:
                validate_group(root, group_key)
        if not lock['locked'] and not self.manager.acquire_lock(user, 'editing objects'):
            reject('Configuration lock could not be acquired', 423)
        self.manager._save(root, self.candidate)
        return {'status': 'candidate-updated', 'requires_commit': True,
                'revision': revision(self.manager.get_candidate())}


def install(app, current_user, require_admin, audit, manager, candidate):
    store = ObjectStore(manager, candidate)

    @app.get('/api/config/objects/{kind}')
    async def list_objects(kind: str, scope: str = 'shared', source: Literal['candidate', 'running'] = 'candidate', user=Depends(current_user)):
        result = store.listing(kind, scope, source)
        result['can_edit'] = source == 'candidate' and user.get('role') in ('admin', 'superuser')
        return result

    @app.get('/api/config/objects/{kind}/{name}/references')
    async def object_references(kind: str, name: str, scope: str = 'shared', source: Literal['candidate', 'running'] = 'candidate', user=Depends(current_user)):
        if kind not in KINDS:
            reject('Unknown object kind', 404)
        root, rev = store.load(source)
        key = (scope, kind, name)
        if key not in entries(root):
            reject('Object not found', 404)
        return {'references': references(root, key), 'revision': rev}

    @app.post('/api/config/objects/{kind}')
    async def create_object(kind: str, request: ObjectEdit, scope: str = 'shared', user=Depends(current_user)):
        require_admin(user)
        result = store.mutate(kind, scope, request.name, request.revision, user['username'], request, True)
        await audit(user['username'], 'object_create', kind + ':' + scope + ':' + request.name)
        return result

    @app.put('/api/config/objects/{kind}/{name}')
    async def update_object(kind: str, name: str, request: ObjectEdit, scope: str = 'shared', user=Depends(current_user)):
        require_admin(user)
        result = store.mutate(kind, scope, name, request.revision, user['username'], request)
        await audit(user['username'], 'object_update', kind + ':' + scope + ':' + name)
        return result

    @app.delete('/api/config/objects/{kind}/{name}')
    async def delete_object(kind: str, name: str, revision: str, scope: str = 'shared', user=Depends(current_user)):
        require_admin(user)
        result = store.mutate(kind, scope, name, revision, user['username'])
        await audit(user['username'], 'object_delete', kind + ':' + scope + ':' + name)
        return result
