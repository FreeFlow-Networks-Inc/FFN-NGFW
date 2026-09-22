# SPDX-License-Identifier: GPL-2.0-or-later
"""Virtual router candidate storage. No SQL writes, FRR, or kernel operations."""
import copy
import json
import re
import xml.etree.ElementTree as ET


class RouterError(ValueError):
    def __init__(self, message, code=422):
        super().__init__(message)
        self.code = code


def child(node, path):
    for tag in path.split('/'):
        found = node.find(tag)
        node = ET.SubElement(node, tag) if found is None else found
    return node


def container(root, create=False):
    devices = root.find('devices')
    if devices is None:
        if not create: return None
        devices = ET.SubElement(root, 'devices')
    device = next((e for e in devices.findall('entry') if e.get('name') == 'localhost.localdomain'), None)
    if device is None:
        if not create: return None
        device = ET.SubElement(devices, 'entry', name='localhost.localdomain')
    return child(device, 'network/virtual-router') if create else device.find('network/virtual-router')


def _number(node, path, default):
    try: return int(node.findtext(path, str(default)))
    except (ValueError, TypeError): return default


def describe(node, index):
    name = node.get('name', '')
    try: settings = json.loads(node.findtext('ffn-routing-settings', '{}'))
    except ValueError: settings = {}
    return dict(name=name, id=_number(node, 'ffn-id', index),
                table_id=_number(node, 'ffn-table-id', 254 if name == 'default' else 1000 + index),
                interfaces=[m.text for m in node.findall('interface/member') if m.text],
                admin_up=node.findtext('admin-up', 'yes') != 'no', vsys=node.findtext('ffn-vsys'),
                protocol=node.findtext('ffn-protocol', 'static'), router_id=node.findtext('router-id'),
                asn=_number(node, 'ffn-asn', None), config=settings, frr_fragment=None)


def routes(node, vr):
    result = []
    for index, route in enumerate(node.findall('routing-table/ip/static-route/entry'), 1):
        result.append(dict(id=_number(route, 'ffn-id', index), vr_id=vr['id'],
                           dest_cidr=route.findtext('destination', ''), next_hop=route.findtext('nexthop/ip-address', ''),
                           dev=route.findtext('interface'), metric=_number(route, 'metric', 10), table_id=vr['table_id']))
    return result


def list_routers(root, seed):
    parent = container(root)
    if parent is None or parent.findtext('ffn-candidate-managed') != 'yes':
        parent = migrate(copy.deepcopy(root), seed)
    return [dict(describe(e, i), routes=routes(e, describe(e, i))) for i, e in enumerate(parent.findall('entry'), 1)]


def put_fields(node, fields):
    mapping = dict(id='ffn-id', table_id='ffn-table-id', admin_up='admin-up', vsys='ffn-vsys',
                   protocol='ffn-protocol', router_id='router-id', asn='ffn-asn')
    for key, tag in mapping.items():
        if key not in fields: continue
        value = fields[key]
        if value is None or value == '':
            found = node.find(tag)
            if found is not None: node.remove(found)
        else: child(node, tag).text = ('yes' if value else 'no') if key == 'admin_up' else str(value)
    if fields.get('interfaces') is not None:
        parent = child(node, 'interface'); parent.clear()
        for name in fields['interfaces']: ET.SubElement(parent, 'member').text = name
    if 'config' in fields:
        child(node, 'ffn-routing-settings').text = json.dumps(fields['config'], sort_keys=True, separators=(',', ':'), allow_nan=False)


def put_route(node, data, route_id):
    for path, value in [('ffn-id', route_id), ('destination', data['dest_cidr']),
                        ('nexthop/ip-address', data.get('next_hop')), ('interface', data.get('dev')),
                        ('metric', data.get('metric', 100))]:
        el = child(node, path)
        el.text = '' if value is None else str(value)


def migrate(root, seed):
    # Import legacy definitions once, including into the empty default router
    # supplied by the factory template. Existing XML settings take precedence.
    # This happens in the in-memory candidate edit, never on GET or running.
    existing = container(root)
    if existing is not None and existing.findtext('ffn-candidate-managed') == 'yes': return existing
    parent = container(root, True)
    for vr in seed:
        node = next((e for e in parent.findall('entry') if e.get('name') == vr['name']), None)
        if node is None:
            node = ET.SubElement(parent, 'entry', name=vr['name']); put_fields(node, vr)
        else:
            legacy = ET.Element('entry'); put_fields(legacy, vr)
            for field in legacy:
                if node.find(field.tag) is None: node.append(field)
        destinations = {e.findtext('destination') for e in node.findall('routing-table/ip/static-route/entry')}
        for route in vr.get('routes', []):
            if route['dest_cidr'] in destinations: continue
            el = ET.SubElement(child(node, 'routing-table/ip/static-route'), 'entry', name='route-' + str(route['id']))
            put_route(el, route, route['id'])
    # Persist IDs so deleting or reordering another entry cannot change them.
    route_id = max((int(e.text) for e in parent.findall('.//static-route/entry/ffn-id') if (e.text or '').isdigit()), default=0)
    for index, node in enumerate(parent.findall('entry'), 1):
        if node.find('ffn-id') is None: child(node, 'ffn-id').text = str(index)
        for route in node.findall('routing-table/ip/static-route/entry'):
            if route.find('ffn-id') is None:
                route_id += 1; child(route, 'ffn-id').text = str(route_id)
    child(parent, 'ffn-candidate-managed').text = 'yes'
    return parent


def edit(root, seed, action, name, data=None, route_id=None, management_iface=None):
    """Mutate an isolated tree; caller atomically persists it after validation."""
    data = data or {}
    if not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,63}', name):
        raise RouterError('Use a virtual router name of 1–63 letters, numbers, dots, underscores or hyphens')
    parent = migrate(root, seed)
    node = next((e for e in parent.findall('entry') if e.get('name') == name), None)
    vrs = list_routers(root, [])
    if action == 'create':
        if node is not None: raise RouterError('Virtual router already exists', 409)
        data = dict(data, id=max((v['id'] for v in vrs), default=0) + 1,
                    table_id=max([999] + [v['table_id'] for v in vrs if v['table_id'] != 254]) + 1)
        node = ET.SubElement(parent, 'entry', name=name)
    elif node is None: raise RouterError('Virtual router not found', 404)
    if action in ('create', 'update'):
        if data.get('interfaces') is not None:
            members = data['interfaces']
            if management_iface and management_iface in members: raise RouterError('Management interface cannot be assigned to a virtual router')
            owners = {i: v['name'] for v in vrs if v['name'] not in (name, 'default') for i in v['interfaces']}
            for iface in members:
                if iface in owners: raise RouterError('Interface already belongs to ' + owners[iface], 409)
        if data.get('protocol', 'static') not in ('static', 'bgp', 'ospf'): raise RouterError('Unknown routing protocol')
        put_fields(node, data)
    elif action == 'routing':
        put_fields(node, {'config': data})
    elif action == 'assign-interface':
        iface = data['interface']
        if iface == management_iface: raise RouterError('Management interface cannot be assigned to a virtual router')
        for vr_node in parent.findall('entry'):
            members = child(vr_node, 'interface')
            for member in list(members):
                if member.tag == 'member' and member.text == iface: members.remove(member)
        if name != 'default': ET.SubElement(child(node, 'interface'), 'member').text = iface
    elif action == 'delete':
        if name == 'default': raise RouterError('The default virtual router cannot be deleted')
        parent.remove(node)
    elif action in ('route-add', 'route-update', 'route-delete'):
        owner = describe(node, 1)
        rows = routes(node, owner)
        route_nodes = node.findall('routing-table/ip/static-route/entry')
        target = next((el for el, row in zip(route_nodes, rows) if row['id'] == route_id), None)
        if action == 'route-add':
            route_id = max((r['id'] for v in list_routers(root, []) for r in v['routes']), default=0) + 1
            target = ET.SubElement(child(node, 'routing-table/ip/static-route'), 'entry', name='route-' + str(route_id))
        elif target is None: raise RouterError('Static route not found', 404)
        if action == 'route-delete': node.find('routing-table/ip/static-route').remove(target)
        else: put_route(target, data, route_id)
    else: raise RouterError('Unknown virtual router edit')
    return dict(status='candidate-updated', name=name, id=route_id, runtime='not-applied',
                message='Staged in candidate configuration. Commit is required to request activation.')
