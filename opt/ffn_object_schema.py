# SPDX-License-Identifier: GPL-2.0-or-later
"""Object field definitions shared by the XML API and its form renderer.

These describe configuration, not a claim of App-ID, Device-ID or feed runtime
support. Only explicit schema paths can be written; imported extensions are
protected by a structural round-trip check.
"""
import ipaddress
import math
import re
import xml.etree.ElementTree as ET
from urllib.parse import urlsplit
from fastapi import HTTPException


def field(key, label, path=None, *, mode='text', required=False, options=None):
    return dict(key=key, label=label, path=path or key, mode=mode,
                required=required, options=options or [])


ATTRIBUTES = ('category', 'subcategory', 'technology', 'risk')
SCHEMAS = {
    'region': dict(label='Regions', type='region', fields=[
        field('addresses', 'Addresses', 'address', mode='lines', required=True),
        field('latitude', 'Latitude', 'geo-location/latitude'),
        field('longitude', 'Longitude', 'geo-location/longitude')]),
    'dynamic-user-group': dict(label='Dynamic User Groups', type='dynamic', fields=[
        field('filter', 'Match criteria', required=True)]),
    'application': dict(label='Applications', type='custom', fields=[
        field('category', 'Category', required=True),
        field('subcategory', 'Subcategory', required=True),
        field('technology', 'Technology', required=True),
        field('risk', 'Risk', mode='select', required=True, options=['1','2','3','4','5']),
        field('ports', 'Default ports (tcp/80, udp/53)', 'default/port', mode='lines')]),
    'application-filter': dict(label='Application Filters', type='filter', fields=[
        field(k, k.title(), mode='lines') for k in ATTRIBUTES]),
    'tag': dict(label='Tags', type='tag', fields=[
        field('color', 'Color', mode='select', options=['none']+['color'+str(i) for i in range(1,43)])]),
    'device': dict(label='Devices', type='device', fields=[
        field(k, label) for k, label in [('category','Category'),('profile','Profile'),
        ('model','Model'),('os-family','OS Family'),('os-version','OS Version'),('vendor','Vendor')]]),
    'external-list': dict(label='External Dynamic Lists', type='ip', types=['ip','domain','url'], fields=[
        field('url', 'Source URL', 'type/{type}/url', required=True),
        field('interval', 'Check for updates', 'type/{type}/recurring', mode='schedule',
              options=['five-minute','hourly','daily']),
        field('time', 'Daily update time (HH:MM)', 'type/{type}/recurring/daily/at'),
        field('exceptions', 'Exceptions', 'type/{type}/exception-list', mode='lines')]),
}
LABELS = {'address':'Addresses','address-group':'Address Groups',
          'service':'Services','service-group':'Service Groups',
          'application-group':'Application Groups', **{k:v['label'] for k,v in SCHEMAS.items()}}
GROUPS = ('address-group', 'service-group', 'application-group')


def fail(message):
    raise HTTPException(422, message)


def expression_tags(value):
    """Bounded, non-evaluating parser for quoted tags joined by and/or."""
    tokens = re.findall(r"'[^'\n]+'|\(|\)|\band\b|\bor\b|\S+", value)
    if len(tokens) > 256:
        fail('Match criteria are too complex')
    expect, depth, names = True, 0, []
    for token in tokens:
        if expect:
            if token == '(':
                depth += 1
                if depth > 32: fail('Match criteria nesting exceeds 32 levels')
            elif re.fullmatch(r"'[^'\n]+'", token):
                names.append(token[1:-1]); expect = False
            else: fail("Use quoted tags with and/or, for example 'trusted' and 'office'")
        elif token == ')' and depth:
            depth -= 1
        elif token in ('and','or'):
            expect = True
        else: fail('Invalid match criteria')
    if expect or depth: fail('Incomplete match criteria')
    return names


def child_at(entry, path):
    node = entry
    for part in path.split('/'):
        found = node.find(part)
        node = found if found is not None else ET.SubElement(node, part)
    return node


def write_extra(entry, kind, spec):
    for f in SCHEMAS[kind]['fields']:
        value = spec.settings.get(f['key'])
        if value in (None, '', []): continue
        path = f['path'].replace('{type}', spec.type)
        node = child_at(entry, path)
        if f['mode'] == 'lines':
            for item in value: ET.SubElement(node, 'member').text = item
        elif f['mode'] == 'schedule':
            ET.SubElement(node, value)
        else: node.text = value


def shape(node):
    # XML element order/formatting is immaterial, attributes/unknown leaves aren't.
    return (node.tag, tuple(sorted(node.attrib.items())), (node.text or '').strip(),
            sorted((shape(c) for c in node), key=repr))


def describe_extra(entry, kind):
    from types import SimpleNamespace
    schema = SCHEMAS[kind]; typ = schema['type']; settings = {}
    if kind == 'external-list':
        types = list(entry.find('type')) if entry.find('type') is not None else []
        typ = types[0].tag if len(types) == 1 and types[0].tag in schema['types'] else 'unsupported'
    for f in schema['fields']:
        node = entry.find(f['path'].replace('{type}', typ))
        if node is None: continue
        if f['mode'] == 'lines': settings[f['key']] = [n.text or '' for n in node.findall('member')]
        elif f['mode'] == 'schedule': settings[f['key']] = next(iter(node)).tag if len(node) == 1 else 'unsupported'
        else: settings[f['key']] = node.text or ''
    expected = ET.Element('entry', name=entry.get('name',''))
    write_extra(expected, kind, SimpleNamespace(type=typ, settings=settings))
    for tag in ('description','tag'):
        for node in entry.findall(tag): expected.append(node)
    common_safe = all(not n.attrib and len(n)==0 for n in entry.findall('description'))
    common_safe &= len(entry.findall('description'))<=1 and len(entry.findall('tag'))<=1
    for node in entry.findall('tag'):
        common_safe &= not node.attrib and all(c.tag=='member' and not c.attrib and len(c)==0 for c in node)
    return dict(name=entry.get('name',''),kind=kind,type=typ,value='',source_port='',members=[],
                settings=settings,description=entry.findtext('description',''),
                editable=common_safe and shape(expected)==shape(entry),tags=[n.text or '' for n in entry.findall('tag/member')])


def validate_extra(spec, kind, ports):
    schema = SCHEMAS[kind]
    if spec.type not in schema.get('types', [schema['type']]) or spec.value or spec.source_port or spec.members:
        fail('Invalid fields or type for '+schema['label'])
    fields = {f['key']:f for f in schema['fields']}
    if set(spec.settings)-set(fields): fail('Unknown object settings')
    for key, f in fields.items():
        value = spec.settings.get(key, [] if f['mode']=='lines' else '')
        if f['mode']=='lines':
            if not isinstance(value,list) or len(value)>1024 or any(not isinstance(x,str) or not x.strip() or len(x)>1024 for x in value):
                fail(f['label']+': expected at most 1024 nonempty values')
            spec.settings[key] = value = list(dict.fromkeys(x.strip() for x in value))
        elif not isinstance(value,str) or len(value)>4096:
            fail(f['label']+': invalid value')
        if f['required'] and not value: fail(f['label']+' is required')
        if f['options'] and value and value not in f['options']: fail(f['label']+': invalid selection')
    s = spec.settings
    if kind=='region':
        for value in s['addresses']:
            try:
                if '-' in value:
                    a,b=map(ipaddress.ip_address,value.split('-'))
                    if a.version!=b.version or int(a)>int(b): raise ValueError()
                else: ipaddress.ip_network(value,strict=False)
            except ValueError: fail('Region addresses must be valid IP addresses, subnets or ordered ranges')
        if bool(s.get('latitude'))!=bool(s.get('longitude')): fail('Set both latitude and longitude')
        for key,limit in [('latitude',90),('longitude',180)]:
            if s.get(key):
                try: number=float(s[key])
                except ValueError: fail('Invalid '+key)
                if not math.isfinite(number) or abs(number)>limit: fail('Invalid '+key)
    elif kind=='dynamic-user-group': expression_tags(s['filter'])
    elif kind=='application':
        for value in s.get('ports',[]):
            parts=value.split('/',1)
            if len(parts)!=2 or parts[0] not in ('tcp','udp'): fail('Default ports use tcp/80 or udp/53 syntax')
            ports(parts[1])
    elif kind=='application-filter':
        if not any(s.values()): fail('Select at least one application attribute')
        if any(v not in ('1','2','3','4','5') for v in s.get('risk',[])): fail('Risk must be between 1 and 5')
    elif kind=='device':
        if not any(s.values()): fail('Specify at least one device attribute')
    elif kind=='external-list':
        try:
            url=urlsplit(s['url']); port=url.port
            valid=url.scheme in ('http','https') and url.hostname and not url.username and not url.password and not url.fragment
        except ValueError: valid=False
        if not valid or re.search(r'\s',s['url']): fail('Use an HTTP(S) source URL without credentials or fragments')
        s['interval']=s.get('interval') or 'hourly'
        if s['interval']=='daily':
            if not re.fullmatch(r'(?:[01][0-9]|2[0-3]):[0-5][0-9]',s.get('time','')): fail('Daily updates require a valid HH:MM time')
        elif s.get('time'): fail('Update time is only valid for a daily schedule')
        for value in s.get('exceptions',[]):
            if spec.type=='ip':
                try: ipaddress.ip_network(value,strict=False)
                except ValueError: fail('IP list exceptions must be addresses or subnets')
