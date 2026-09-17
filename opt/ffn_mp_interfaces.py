"""Shared candidate schema for external management-plane interfaces."""
import ipaddress
from xml.etree import ElementTree as ET

FIELDS = {'mode','address','gateway','dns','mtu','description'}
LABELS = ('MGT','HA1-A','HA1-B','AUX-1','AUX-2')


def validate(data):
    if not isinstance(data,dict) or set(data) != FIELDS: raise ValueError('Expected complete management interface settings')
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
    return result


def decode(node):
    if node is None: return None
    if set(c.tag for c in node)-FIELDS or len({c.tag for c in node})!=len(node):raise ValueError('Unsupported or duplicate MP setting')
    dns=node.find('dns')
    if dns is not None and any(c.tag!='member' or len(c) for c in dns):raise ValueError('Invalid DNS server list')
    return validate(dict(mode=node.findtext('mode','disabled'),address=node.findtext('address',''),
        gateway=node.findtext('gateway',''),dns=[e.text for e in node.findall('./dns/member')],
        mtu=int(node.findtext('mtu','1500')),description=node.findtext('description','')))


def encode(data):
    data=validate(data)
    return {**{k:str(v) for k,v in data.items() if k!='dns'},'dns':data['dns']}
