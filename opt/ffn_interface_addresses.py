"""Resolve interface address-object references without changing stored XML."""
import copy
import ipaddress


def object_index(root, owner):
    result = {}
    for node, scope in ((root.find('shared'), 'shared'), (owner, owner.get('name') if owner is not None else None)):
        if node is None:
            continue
        seen = set()
        for entry in node.findall('address/entry'):
            name = entry.get('name', '')
            if name in seen:
                raise ValueError('Duplicate address object: ' + name)
            seen.add(name)
            result[name] = (entry, scope)
    return result


def object_address(entry):
    values = [n for n in entry if n.tag in ('ip-netmask', 'ip-range', 'fqdn', 'ip-wildcard')]
    if len(values) != 1 or values[0].tag != 'ip-netmask' or len(values[0]):
        raise ValueError('Interface addresses require an IP/netmask object')
    value = values[0].text or ''
    if '%' in value:
        raise ValueError('Scoped IPv6 addresses are not supported')
    return ipaddress.ip_interface(value)


def address_choices(root, owner):
    choices = []
    for name, (entry, scope) in sorted(object_index(root, owner).items()):
        try:
            address = object_address(entry)
        except ValueError:
            continue
        choices.append(dict(name=name, scope=scope, value=str(address), family=address.version))
    return choices


def resolve_address(value, root, owner):
    if not isinstance(value, str) or not value or value != value.strip() or '%' in value:
        raise ValueError('Enter an interface address with a prefix or select an IP/netmask object')
    item = object_index(root, owner).get(value)
    if item is not None:
        try:
            return str(object_address(item[0]))
        except ValueError as error:
            raise ValueError('Invalid interface address object ' + value + ': ' + str(error)) from error
    try:
        if '/' not in value:
            raise ValueError()
        return str(ipaddress.ip_interface(value))
    except ValueError as error:
        raise ValueError('Unknown IP/netmask object or invalid interface address: ' + value) from error


def validate_addresses(values, root, owner):
    """Return stored references/literals and their resolved interface addresses."""
    index = object_index(root, owner)
    stored, resolved = [], []
    for value in values:
        address = resolve_address(value, root, owner)
        reference = value if value in index else address
        if reference in stored:
            continue
        if address in resolved:
            raise ValueError('Duplicate interface address after object resolution: ' + address)
        stored.append(reference)
        resolved.append(address)
    return stored, resolved


def interface_nodes(root):
    """Yield address containers and their local/shared object scope."""
    for device in root.findall('devices/entry'):
        owners = device.findall('vsys/entry')
        for kind in ('ethernet', 'aggregate-ethernet', 'loopback', 'tunnel', 'vlan'):
            for parent in device.findall('network/interface/' + kind + '/entry'):
                parent_name = parent.get('name', '')
                rows = [(parent, parent_name, parent.find('layer3'))]
                rows += [(unit, unit.get('name', ''), unit) for path in
                         ('layer3/units/entry', 'units/entry') for unit in parent.findall(path)]
                for entry, name, layer in rows:
                    if layer is None:
                        layer = entry
                    addresses = layer.findall('ip/entry')
                    if not addresses:
                        continue
                    selected = [v for v in owners if name in [m.text for m in v.findall('import/network/interface/member')]]
                    if not selected and name != parent_name:
                        selected = [v for v in owners if parent_name in [m.text for m in v.findall('import/network/interface/member')]]
                    if not selected and len(owners) == 1:
                        selected = owners
                    if len(selected) > 1:
                        raise ValueError('Ambiguous virtual-system ownership for interface ' + name)
                    yield name, selected[0] if selected else None, addresses


def resolved_config(root):
    """Make an execution-only copy; candidate/running retain object references."""
    result = copy.deepcopy(root)
    for name, owner, nodes in interface_nodes(result):
        try:
            values = [resolve_address(n.get('name', ''), result, owner) for n in nodes]
            if len(values) != len(set(values)):
                raise ValueError('Duplicate interface address after object resolution')
        except ValueError as error:
            raise ValueError(name + ': ' + str(error)) from error
        for node, value in zip(nodes, values):
            node.set('name', value)
    return result


def reference_blockers(root):
    try:
        resolved_config(root)
        return []
    except ValueError as error:
        return [dict(scope='network', kind='interface', name='address', reason=str(error))]


def object_references(root, scope, name):
    found = []
    for interface, owner, nodes in interface_nodes(root):
        item = object_index(root, owner).get(name)
        if item and item[1] == scope and any(n.get('name') == name for n in nodes):
            found.append(dict(scope=scope, path='network/interface/' + interface + '/ip/' + name))
    return found
