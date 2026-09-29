"""Bounded IPv4 ICMP probes sent on the selected Ethernet route, even withdrawn.

Run inside the data namespace. Uses ARP and AF_PACKET, never a fallback default
route, a management interface, a temporary route, or customer conntrack entries.
"""
import ipaddress
import json
import os
import select
import socket
import struct
import subprocess
import sys
import time
from ffn_route_monitor import validate


def checksum(data):
    if len(data)%2: data+=b'\0'
    value=sum(struct.unpack('!%dH'%(len(data)//2),data))
    while value>>16: value=(value&65535)+(value>>16)
    return (~value)&65535


def receive(sock, deadline, accept):
    while time.monotonic()<deadline:
        if not select.select([sock],[],[],max(0,deadline-time.monotonic()))[0]: break
        packet=sock.recv(4096)
        answer=accept(packet)
        if answer is not None: return answer
    return None


def arp_reply(packet, source, gateway, mac):
    if len(packet)<42 or packet[12:14]!=b'\x08\x06': return None
    body=packet[14:42]
    if body[:8]!=struct.pack('!HHBBH',1,0x0800,6,4,2): return None
    if body[14:18]!=gateway or body[24:28]!=source or body[18:24]!=mac: return None
    sender=body[8:14]
    if sender!=packet[6:12] or sender==b'\0'*6 or sender[0]&1: return None
    return sender


def echo_reply(packet, source, target, token, mac):
    if len(packet)<42 or packet[:6]!=mac or packet[12:14]!=b'\x08\x00': return None
    ip=packet[14:];length=(ip[0]&15)*4
    if ip[0]>>4!=4 or length<20 or len(ip)<length+8 or ip[9]!=1: return None
    total=struct.unpack('!H',ip[2:4])[0]
    if total>len(ip) or total<length+8 or checksum(ip[:length]) or struct.unpack('!H',ip[6:8])[0]&0x3fff: return None
    if ip[12:16]!=target or ip[16:20]!=source: return None
    icmp=ip[length:total]
    if icmp[:2]!=b'\0\0' or checksum(icmp) or icmp[4:]!=token: return None
    return True


def probe(route):
    settings=validate(route['monitor'],route['dst'])
    if len(settings['targets'])>1:
        from concurrent.futures import ThreadPoolExecutor
        def single(target):
            return probe(dict(route,monitor=dict(settings,targets=[target])))[0]
        with ThreadPoolExecutor(max_workers=4) as pool:
            return list(pool.map(single,settings['targets']))
    dev=route['dev']
    if not isinstance(dev,str) or not dev or len(dev)>15 or any(c not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-' for c in dev):
        raise ValueError('Invalid data interface')
    rows=json.loads(subprocess.check_output(['ip','-j','address','show','dev',dev],timeout=3))
    if len(rows)!=1: raise ValueError('Missing data interface')
    row=rows[0];mac=bytes.fromhex(row['address'].replace(':',''))
    addresses=[ipaddress.ip_interface(a['local']+'/'+str(a['prefixlen'])) for a in row['addr_info'] if a['family']=='inet' and a['scope']=='global']
    if not addresses: raise ValueError('No IPv4 source address')
    via=ipaddress.ip_address(route['via']) if route.get('via') else None
    source=next((a.ip for a in addresses if via and via in a.network),addresses[0].ip).packed
    results=[]
    with socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3)) as sock:
        sock.bind((dev,0));sock.setblocking(False)
        for value in settings['targets']:
            target=ipaddress.ip_address(value).packed;gateway=via.packed if via else target
            deadline=time.monotonic()+settings['timeout']
            request=struct.pack('!HHBBH',1,0x0800,6,4,1)+mac+source+b'\0'*6+gateway
            sock.send(b'\xff'*6+mac+b'\x08\x06'+request)
            peer=receive(sock,deadline,lambda p:arp_reply(p,source,gateway,mac))
            if peer is None: results.append(False);continue
            token=os.urandom(4)+os.urandom(24)
            body=b'\x08\0\0\0'+token;body=body[:2]+struct.pack('!H',checksum(body))+body[4:]
            header=struct.pack('!BBHHHBBH4s4s',0x45,0,20+len(body),0,0x4000,64,1,0,source,target)
            header=header[:10]+struct.pack('!H',checksum(header))+header[12:]
            sock.send(peer+mac+b'\x08\0'+header+body)
            results.append(receive(sock,deadline,lambda p:echo_reply(p,source,target,token,mac)) is True)
    return results


if __name__=='__main__':
    print(json.dumps(probe(json.load(sys.stdin))))
