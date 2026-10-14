"""Shared candidate schema for external management-plane interfaces (Device > Setup > Interfaces).

Every external MP port carries address mode, address, gateway, DNS, MTU and a
description. The MGT port additionally carries the permitted services and
permitted source addresses PAN-OS keeps on its management interface; the MP
host firewall renders them (ffn_config_bridge -> ffn_bmfw).
"""
import ipaddress
from xml.etree import ElementTree as ET

FIELDS = {'mode','address','gateway','dns','mtu','description','services','permitted'}
LABELS = ('MGT','HA1-A','HA1-B','AUX-1','AUX-2')
SERVICES = ('https','ssh','ping','snmp')
DEFAULT_SERVICES = ('https','ssh')


def validate(data):
    if not isinstance(data,dict) or not {'mode','address','gateway','dns','mtu','description'}<=set(data) or set(data)-FIELDS:
        raise ValueError('Expected complete management interface settings')
    if data['mode'] not in ('static','dhcp','disabled'): raise ValueError('Select Static, DHCP or Disabled')
    if type(data['mtu']) is not int or not 576 <= data['mtu'] <= 9000: raise ValueError('MTU must be 576–9000')
    if not isinstance(data['description'],str) or len(data['description'])>128 or any(ord(c)<32 for c in data['description']):
        raise ValueError('Description must be at most 128 printable characters')
    result=dict(data)
    if data['mode']=='static':
        addr=ipaddress.IPv4Interface(data['address'])
        if '/' not in data['address'] or addr.ip.is_multicast or addr.ip.is_unspecified or addr.ip.is_loopback:
            raise ValueError('A usable IPv4 address with prefix length is required')
        result['address']=str(addr)
        if data['gateway']:
            gateway=ipaddress.IPv4Address(data['gateway'])
            if gateway not in addr.network or gateway==addr.ip or gateway.is_multicast or gateway.is_unspecified:
                raise ValueError('Gateway must be another address on this subnet')
            result['gateway']=str(gateway)
    else:
        if data['address'] or data['gateway']: raise ValueError('Address and gateway must be empty in DHCP/Disabled mode')
    if not isinstance(data['dns'],list) or len(data['dns'])>3: raise ValueError('At most three DNS servers are supported')
    result['dns']=[str(ipaddress.ip_address(value)) for value in data['dns']]
    services=data.get('services',[])
    if not isinstance(services,list) or any(s not in SERVICES for s in services) or len(set(services))!=len(services):
        raise ValueError('Permitted services are a list of https, ssh, ping and snmp')
    result['services']=[s for s in SERVICES if s in services]
    permitted=data.get('permitted',[])
    if not isinstance(permitted,list) or len(permitted)>64: raise ValueError('At most 64 permitted source networks are supported')
    result['permitted']=[str(ipaddress.IPv4Network(value,strict=False)) for value in permitted]
    return result


def decode(node):
    if node is None: return None
    if set(c.tag for c in node)-(FIELDS|{'permitted-ip'}) or len({c.tag for c in node})!=len(node):raise ValueError('Unsupported or duplicate MP setting')
    for tag in ('dns','services','permitted-ip'):
        container=node.find(tag)
        if container is not None and any(c.tag!='member' or len(c) for c in container):raise ValueError('Invalid %s list'%tag)
    return validate(dict(mode=node.findtext('mode','disabled'),address=node.findtext('address',''),
        gateway=node.findtext('gateway',''),dns=[e.text for e in node.findall('./dns/member')],
        mtu=int(node.findtext('mtu','1500')),description=node.findtext('description',''),
        services=[e.text for e in node.findall('./services/member')],permitted=[e.text for e in node.findall('./permitted-ip/member')]))


def encode(data):
    data=validate(data)
    return {**{k:str(v) for k,v in data.items() if k not in ('dns','services','permitted')},
            'dns':data['dns'],'services':data['services'],'permitted-ip':data['permitted']}


def management_rule(data):
    """The MGT port's input rule as the host firewall renders it: tcp/udp ports, ping, permitted sources."""
    services=data.get('services') or list(DEFAULT_SERVICES)
    ports={'https':('tcp',[443,8443]),'ssh':('tcp',[22]),'snmp':('udp',[161])}
    rule=dict(tcp=[],udp=[],icmp='ping' in services,permitted_ip=list(data.get('permitted') or []))
    for service in services:
        if service in ports:
            proto,values=ports[service]
            rule[proto].extend(values)
    rule['tcp']=sorted(set(rule['tcp']));rule['udp']=sorted(set(rule['udp']))
    return rule
