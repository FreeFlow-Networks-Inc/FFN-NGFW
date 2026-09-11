"""Validate stored policy fields and reject unsupported fast-path matches."""
import ipaddress
import re
from fastapi import HTTPException

def validate_policy_rule(rule, compilation=False):
    def reject(message): raise HTTPException(422,message)
    for key in ('src_ip','dst_ip'):
        value=(rule.get(key) or '0.0.0.0/0').strip()
        if value.lower() in ('any','*'): value='0.0.0.0/0'
        try: network=ipaddress.ip_network(value,strict=False)
        except ValueError: reject(key+' must be an IP address or CIDR')
        if compilation and network.version!=4: reject('Fast-path policy does not support IPv6 matches')
    for key in ('src_port','dst_port'):
        value=rule.get(key,0)
        if not isinstance(value,int) or not 0<=value<=65535: reject(key+' must be 0–65535; zero means any')
    proto=str(rule.get('proto') or 'any').strip().lower()
    protocols={'any','ip','tcp','udp','icmp','esp','ah','gre','sctp'}
    if proto not in protocols and not(proto.isdigit() and 0<=int(proto)<=255): reject('Unknown IP protocol')
    if any(rule.get(k,0) for k in ('src_port','dst_port')) and proto not in ('tcp','udp','sctp','6','17','132'):
        reject('Port matching requires TCP, UDP or SCTP')
    action=str(rule.get('action') or '').strip().lower()
    if action not in ('permit','deny','drop','reject','inspect','scan','reset'): reject('Unknown policy action')
    if compilation and action=='reset': reject('Fast-path reset action is not implemented')
    for key in ('src_iface','dst_iface'):
        value=rule.get(key)
        if value and (len(value)>63 or not re.fullmatch(r'[A-Za-z0-9_.*?/-]+',value)): reject('Invalid interface match')
        if compilation and value not in (None,'','*'): reject('Fast-path interface-constrained policy is not implemented')
    if not isinstance(rule.get('position',0),int) or rule.get('position',0)<0: reject('Rule position must be nonnegative')
    for key,limit in (('name',127),('description',1024)):
        value=rule.get(key) or ''
        if len(value)>limit or any(ord(c)<32 and c not in '\t\n\r' for c in value): reject('Invalid '+key)
