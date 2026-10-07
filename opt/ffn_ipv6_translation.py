# SPDX-License-Identifier: GPL-2.0-or-later
"""Portable NAT64 address synthesis and NPTv6 mapping, without hardware I/O.

RFC 6052 sections 2.2/2.3 and RFC 6296 section 3. These primitives do not
allocate NAT64 sessions, authorize traffic, or commission a runtime provider.
All prefixes come from configuration. No customer network is a default.
"""
import ipaddress as ip
import struct

NAT64_LENGTHS=(32,40,48,56,64,96)
FIELDS={'nat64-prefix','nat64-pool','nptv6-internal-prefix','nptv6-external-prefix'}
LEGACY_FIELDS={'source-type','translated-source','source-interface','destination-type',
               'translated-destination','translated-port','session-distribution'}


def prefix(value,kind='IPv6'):
    try:
        if not isinstance(value,str) or '/' not in value:raise ValueError()
        network=ip.IPv6Network(value,strict=True)
        if not network.prefixlen or any(network.overlaps(ip.IPv6Network(n)) for n in
                ('ff00::/8','fe80::/10','::/128','::1/128','::ffff:0:0/96')):raise ValueError()
    except (ValueError,TypeError):raise ValueError(kind+' requires a unicast IPv6 network prefix without host bits')
    return network


def nat64_prefix(value):
    network=prefix(value,'NAT64')
    if network.prefixlen not in NAT64_LENGTHS:raise ValueError('NAT64 prefix length must be /32, /40, /48, /56, /64 or /96')
    if network.prefixlen==96 and network.network_address.packed[8]:raise ValueError('NAT64 reserved u octet must be zero')
    return network


def nat64_embed(value,network):
    network=nat64_prefix(network);v4=ip.IPv4Address(value).packed
    raw=bytearray(network.network_address.packed);start=network.prefixlen//8
    positions=list(range(12,16)) if start==12 else [i for i in range(start,16) if i!=8][:4]
    for index,byte in zip(positions,v4):raw[index]=byte
    return str(ip.IPv6Address(bytes(raw)))


def nat64_extract(value,network):
    network=nat64_prefix(network);address=ip.IPv6Address(value);raw=address.packed
    if address not in network:raise ValueError('Address is outside the NAT64 prefix')
    if raw[8]:raise ValueError('NAT64 reserved u octet must be zero')
    start=network.prefixlen//8
    positions=list(range(12,16)) if start==12 else [i for i in range(start,16) if i!=8][:4]
    # RFC 6052 recommends ignoring reserved suffix bits on received addresses.
    return str(ip.IPv4Address(bytes(raw[i] for i in positions)))


def nat64_destination(value,network):
    address=ip.IPv4Address(nat64_extract(value,network))
    if address.is_multicast or address.is_unspecified or address.is_loopback or address.is_link_local:
        raise ValueError('NAT64 destination must be routable unicast')
    if nat64_prefix(network)==ip.IPv6Network('64:ff9b::/96') and not address.is_global:
        raise ValueError('The NAT64 well-known prefix cannot translate non-global IPv4 destinations')
    return str(address)


def checksum(raw):
    data=raw+bytes(len(raw)%2);total=sum(struct.unpack('!%dH'%(len(data)//2),data))
    while total>>16:total=(total&65535)+(total>>16)
    return total^65535


def nat64_packet(packet,source,destination,source_port=None,destination_port=None):
    """Bounded packet rewrite oracle for already allocated TCP/UDP/echo tuples.

    No session lookup, port allocation, fragment assembly, ICMP error mapping
    or forwarding occurs here. Unsupported traffic is rejected. A provider
    must retain the original IPv6 tuple; reverse translation cannot guess it.
    """
    src,dst=ip.ip_address(source),ip.ip_address(destination)
    if src.version!=dst.version or not packet or packet[0]>>4==src.version:raise ValueError('NAT64 must change IP version')
    version=packet[0]>>4
    if version==6:
        if len(packet)<40 or len(packet)!=40+int.from_bytes(packet[4:6],'big'):raise ValueError('Incomplete IPv6 packet')
        protocol=packet[6];ttl=packet[7];traffic=(int.from_bytes(packet[:4],'big')>>20)&255
        oldsrc,olddst=packet[8:24],packet[24:40];payload=bytearray(packet[40:])
        if src.version!=4 or protocol not in (6,17,58):raise ValueError('NAT64 oracle does not support IPv6 extensions or this protocol')
        pseudo=oldsrc+olddst+struct.pack('!I3xB',len(payload),protocol)
    elif version==4:
        if len(packet)<20 or packet[0]!=0x45 or len(packet)!=int.from_bytes(packet[2:4],'big') or checksum(packet[:20]):raise ValueError('Invalid or unsupported IPv4 header')
        if int.from_bytes(packet[6:8],'big')&0xbfff:raise ValueError('NAT64 oracle requires unfragmented IPv4 without options')
        protocol=packet[9];ttl=packet[8];traffic=packet[1]
        oldsrc,olddst=packet[12:16],packet[16:20];payload=bytearray(packet[20:])
        if src.version!=6 or protocol not in (6,17,1):raise ValueError('Unsupported NAT64 input protocol')
        pseudo=oldsrc+olddst+struct.pack('!BBH',0,protocol,len(payload)) if protocol!=1 else b''
    else:raise ValueError('Unsupported input IP version')
    if ttl<=1:raise ValueError('NAT64 hop limit expired; provider must generate ICMP')
    if protocol in (6,17):
        minimum,offset=(20,16) if protocol==6 else (8,6)
        if len(payload)<minimum:raise ValueError('Truncated transport header')
        if protocol==6 and not 20<=((payload[12]>>4)*4)<=len(payload):raise ValueError('Invalid TCP header size')
        if protocol==17 and int.from_bytes(payload[4:6],'big')!=len(payload):raise ValueError('Invalid UDP length')
        zero=payload[offset:offset+2]==b'\0\0'
        if protocol==17 and version==6 and zero:raise ValueError('IPv6 UDP checksum is required')
        if not (protocol==17 and version==4 and zero) and checksum(pseudo+payload):raise ValueError('Invalid transport checksum')
        for port,index in ((source_port,0),(destination_port,2)):
            if port is not None:
                if type(port) is not int or not 1<=port<=65535:raise ValueError('Invalid translated port')
                struct.pack_into('!H',payload,index,port)
        output_protocol=protocol
    else:
        if source_port is not None or destination_port is not None:raise ValueError('ICMP identifiers require a separate binding allocator')
        if len(payload)<8 or payload[1] or checksum(pseudo+payload):raise ValueError('Invalid ICMP echo packet')
        types={128:8,129:0} if version==6 else {8:128,0:129}
        if payload[0] not in types:raise ValueError('NAT64 ICMP error translation is not qualified')
        payload[0]=types[payload[0]];offset=2;output_protocol=1 if version==6 else 58
    payload[offset:offset+2]=b'\0\0'
    if src.version==4:
        if len(payload)>65515:raise ValueError('NAT64 packet requires fragmentation')
        pseudo=src.packed+dst.packed+struct.pack('!BBH',0,output_protocol,len(payload)) if output_protocol!=1 else b''
        header=bytearray(struct.pack('!BBHHHBBH4s4s',0x45,traffic,20+len(payload),0,0x4000,ttl-1,output_protocol,0,src.packed,dst.packed))
        struct.pack_into('!H',header,10,checksum(header))
    else:
        pseudo=src.packed+dst.packed+struct.pack('!I3xB',len(payload),output_protocol)
        header=struct.pack('!IHBB16s16s',0x60000000|(traffic<<20),len(payload),output_protocol,ttl-1,src.packed,dst.packed)
    value=checksum(pseudo+payload)
    struct.pack_into('!H',payload,offset,(value or 65535) if output_protocol==17 else value)
    return bytes(header+payload)


def nptv6_prefixes(internal,external):
    a,b=prefix(internal,'NPTv6'),prefix(external,'NPTv6')
    length=max(a.prefixlen,b.prefixlen)
    if length>64:raise ValueError('NPTv6 prefixes must be /64 or shorter')
    a,b=(ip.IPv6Network((n.network_address,length)) for n in (a,b))
    if a.overlaps(b):raise ValueError('NPTv6 internal and external prefixes must not overlap')
    return a,b


def nptv6_address(value,internal,external,reverse=False):
    a,b=nptv6_prefixes(internal,external)
    if reverse:a,b=b,a
    address=ip.IPv6Address(value)
    if address not in a:raise ValueError('Address is outside the effective NPTv6 prefix')
    words=list(struct.unpack('!8H',address.packed))
    if a.prefixlen<=48:
        index=3
        if words[index]==65535:raise ValueError('NPTv6 subnet 0xffff has no reversible mapping')
    else:
        index=next((i for i in range(4,8) if words[i]!=65535),None)
        if index is None:raise ValueError('NPTv6 all-ones interface identifier has no mapping')
    adjustment=(sum(struct.unpack('!8H',a.network_address.packed))-
                sum(struct.unpack('!8H',b.network_address.packed)))%65535
    # Modulo 65535 implements end-around carry and canonical positive zero.
    words[index]=(words[index]+adjustment)%65535
    mapped=int.from_bytes(struct.pack('!8H',*words),'big')
    hostmask=(1<<(128-a.prefixlen))-1
    return str(ip.IPv6Address(int(b.network_address)|(mapped&hostmask)))


def nptv6_packet(packet,internal,external,direction):
    """IPv6 base-header rewrite oracle, including internal hairpin mapping.

    Payload, transport checksum, flow label and hop limit remain unchanged.
    Routing, TTL expiry, ICMP error embedded headers and forwarding are the
    provider's responsibility. This bounded oracle rejects extension headers
    and ICMP errors rather than misrepresenting complete protocol support.
    """
    if direction not in ('outbound','inbound','hairpin'):raise ValueError('Invalid NPTv6 direction')
    if len(packet)<40 or packet[0]>>4!=6 or len(packet)!=40+int.from_bytes(packet[4:6],'big'):
        raise ValueError('Expected one complete IPv6 packet')
    if packet[6] not in (6,17,58) or packet[6]==58 and (len(packet)<48 or packet[40]<128):
        raise ValueError('NPTv6 packet oracle supports TCP, UDP and informational ICMPv6 without extensions')
    raw=bytearray(packet)
    for offset,reverse in ((8,False),(24,True)):
        if (reverse and direction=='outbound') or (not reverse and direction=='inbound'):continue
        raw[offset:offset+16]=ip.IPv6Address(nptv6_address(str(ip.IPv6Address(bytes(raw[offset:offset+16]))),internal,external,reverse)).packed
    return bytes(raw)


def validate_settings(settings,resolve):
    """Resolve configured prefix/address objects and reject incompatible modes."""
    mode=settings.get('nat-type') or 'ipv4'
    if mode=='ipv4':
        if any(settings.get(k) for k in FIELDS):raise ValueError('IPv6 translation fields require NAT64 or NPTv6')
        return None
    if mode not in ('nat64','nptv6'):raise ValueError('Unknown NAT type')
    for key in LEGACY_FIELDS:
        if settings.get(key) not in (None,'',[], 'none'):raise ValueError(mode.upper()+' cannot include IPv4 translation fields')
    allowed={'nat64-prefix','nat64-pool'} if mode=='nat64' else {'nptv6-internal-prefix','nptv6-external-prefix'}
    if any(settings.get(k) for k in FIELDS-allowed):raise ValueError('Translation fields belong to another NAT type')
    def one(key):
        value=settings.get(key)
        if not value:raise ValueError('Required translation field: '+key)
        values=resolve([value],6)
        if len(values)!=1:raise ValueError(key+' requires exactly one IPv6 prefix')
        return values[0]
    if mode=='nat64':
        network=nat64_prefix(one('nat64-prefix'));pool=resolve(settings.get('nat64-pool') or [],4)
        if not pool or len(pool)>256:raise ValueError('NAT64 requires an explicit IPv4 source pool')
        for item in pool:
            try:address=ip.IPv4Network(item,strict=True)
            except ValueError:raise ValueError('NAT64 source pool must contain explicit IPv4 hosts')
            if address.prefixlen!=32 or address.network_address.is_multicast or address.network_address.is_unspecified or address.network_address.is_loopback or address.network_address.is_link_local:
                raise ValueError('NAT64 source pool must contain unicast IPv4 hosts')
        return dict(type=mode,prefix=str(network),pool=sorted({str(ip.IPv4Network(v).network_address) for v in pool},key=ip.IPv4Address))
    a,b=nptv6_prefixes(one('nptv6-internal-prefix'),one('nptv6-external-prefix'))
    if settings.get('service')!=['any'] or settings.get('destination')!=['any']:
        raise ValueError('NPTv6 is transport-independent; Service and Destination Address must be any')
    source=resolve(settings.get('source') or [],6)
    if source not in (['::/0'],[str(a)]):raise ValueError('NPTv6 Source Address must be any or the effective internal prefix')
    return dict(type=mode,internal=str(a),external=str(b),checksum_neutral=True)


def validate_translation(translation):
    if not isinstance(translation,dict):raise ValueError('Invalid IPv6 translation')
    kind=translation.get('type')
    if kind=='nat64' and set(translation)=={'type','prefix','pool'}:
        nat64_prefix(translation['prefix']);pool=translation['pool']
        if not isinstance(pool,list) or not 1<=len(pool)<=256 or len(set(pool))!=len(pool):raise ValueError('Invalid NAT64 pool')
        for value in pool:
            if not isinstance(value,str):raise ValueError('Invalid NAT64 pool address')
            address=ip.IPv4Address(value)
            if address.is_multicast or address.is_unspecified or address.is_loopback or address.is_link_local:raise ValueError('Invalid NAT64 pool address')
    elif kind=='nptv6' and set(translation)=={'type','internal','external','checksum_neutral'}:
        a,b=nptv6_prefixes(translation['internal'],translation['external'])
        if str(a)!=translation['internal'] or str(b)!=translation['external'] or translation['checksum_neutral'] is not True:raise ValueError('Invalid normalized NPTv6 translation')
    else:raise ValueError('Invalid IPv6 translation fields')
    return kind
