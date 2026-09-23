# SPDX-License-Identifier: GPL-2.0-or-later
"""Compile candidate NAT XML into an ordered, platform-neutral IPv4 plan.

No shell commands, kernel writes, DNS lookups or device-name guesses occur here.
The selected DP adapter resolves logical interfaces to its owned netdevices.
"""
import hashlib
import ipaddress
import json


class NatError(ValueError):
    pass


def digest(plan):
    return hashlib.sha256(json.dumps(plan,sort_keys=True,separators=(',',':')).encode()).hexdigest()


def ipv4(value, host=False):
    try:
        if '-' in value and not host:
            a,b=value.split('-');a=ipaddress.IPv4Address(a);b=ipaddress.IPv4Address(b)
            if a>b:raise ValueError()
            return str(a)+'-'+str(b)
        net=ipaddress.ip_network(value,strict=False)
        if net.version!=4 or host and net.prefixlen!=32:raise ValueError()
        if host and (net.network_address.is_multicast or net.network_address.is_unspecified or net.network_address.is_loopback):raise ValueError()
        return str(net.network_address) if host else str(net)
    except (ValueError,TypeError):raise NatError('Expected an IPv4 '+('host address' if host else 'address, subnet or range')+': '+str(value))


def ports(value):
    out=[]
    for part in value.split(','):
        ends=part.split('-')
        if len(ends)>2 or not all(x.isdigit() and 1<=int(x)<=65535 for x in ends):raise NatError('Invalid service ports: '+value)
        if int(ends[0])>int(ends[-1]):raise NatError('Reversed service port range')
        out.append('-'.join(str(int(x)) for x in ends))
    return out


class Resolver:
    def __init__(self,root,owner,family=4):self.root,self.owner,self.family=root,owner,family

    def find(self,kind,name):
        # Local objects shadow shared objects, without interpolating XML paths.
        for parent in (self.owner,self.root.find('shared')):
            if parent is not None:
                for e in parent.findall(kind+'/entry'):
                    if e.get('name')==name:return e

    def addresses(self,values,stack=()):
        out=[]
        def address(value):
            if self.family==4:return ipv4(value)
            try:
                network=ipaddress.ip_network(value,strict=True)
                if network.version!=6:raise ValueError()
                return str(network)
            except (ValueError,TypeError):raise NatError('Expected an IPv6 address or network prefix: '+str(value))
        for value in values:
            if len(stack)>16 or value in stack:raise NatError('Address group cycle or excessive nesting: '+value)
            if value=='any':out.append('0.0.0.0/0' if self.family==4 else '::/0');continue
            entry=self.find('address',value)
            group=self.find('address-group',value)
            if entry is not None:
                child=entry.find('ip-netmask')
                if child is None:child=entry.find('ip-range')
                if child is None:raise NatError('NAT requires static address objects; unresolved object: '+value)
                out.append(address(child.text or ''))
            elif group is not None:
                members=group.findall('static/member')
                if group.find('dynamic') is not None or not members:raise NatError('NAT requires a nonempty static address group: '+value)
                out.extend(self.addresses([m.text or '' for m in members],stack+(value,)))
            else:out.append(address(value))
            if len(out)>256:raise NatError('Expanded address list exceeds 256 entries')
        return sorted(set(out))

    def services(self,values,stack=()):
        out=[]
        for value in values:
            if len(stack)>16 or value in stack:raise NatError('Service group cycle or excessive nesting: '+value)
            if value=='any':out.append({'protocol':'any','source_ports':[],'destination_ports':[]});continue
            entry=self.find('service',value);group=self.find('service-group',value)
            if entry is not None:
                proto=entry.find('protocol');children=list(proto) if proto is not None else []
                if len(children)!=1 or children[0].tag not in ('tcp','udp'):raise NatError('Only TCP/UDP service objects are supported: '+value)
                child=children[0]
                out.append({'protocol':child.tag,'source_ports':ports(child.findtext('source-port')) if child.findtext('source-port') else [],'destination_ports':ports(child.findtext('port',''))})
            elif group is not None:
                members=group.findall('members/member')
                if not members:raise NatError('Empty service group: '+value)
                out.extend(self.services([m.text or '' for m in members],stack+(value,)))
            else:raise NatError('Unknown service: '+value)
            if len(out)>256:raise NatError('Expanded service list exceeds 256 entries')
        return out

    def interfaces(self,zones):
        # ANY is bounded to the virtual system's Layer 3 zone membership.
        out=[]
        # An unaddressed aggregate can carry addressed VLAN units without being
        # a routed endpoint itself. Do not require NAT on that transport parent.
        containers=set()
        for entry in self.root.findall('./devices/entry/network/interface/aggregate-ethernet/entry'):
            layer=entry.find('layer3')
            if layer is not None and (entry.findtext('aggregate-only')=='yes' or
                (layer.find('units/entry') is not None and not layer.findall('ip/entry') and
                 layer.findtext('dhcp-client/enable','no')!='yes')):
                containers.add(entry.get('name'))
        for zone in self.owner.findall('zone/entry'):
            if zones!=['any'] and zone.get('name') not in zones:continue
            members=zone.findall('network/layer3/member')
            if not members and zones!=['any']:raise NatError('NAT requires a nonempty Layer 3 zone: '+str(zone.get('name')))
            out.extend(m.text or '' for m in members if m.text not in containers)
        if not out:raise NatError('Assign Layer 3 interfaces to the selected zones before activating NAT')
        return sorted(set(out))


def compile_rule(root,owner,spec,position):
    s=spec['settings'];r=Resolver(root,owner)
    if not spec['editable']:raise NatError('Imported NAT rule contains unsupported XML fields')
    from ffn_ipv6_translation import validate_settings
    translation=validate_settings(s,lambda values,family:Resolver(root,owner,family).addresses(values))
    if translation:
        r=Resolver(root,owner,6);source=r.addresses(s['source']);destination=r.addresses(s['destination'])
        if translation['type']=='nat64':
            target=translation['prefix']
            if destination==['::/0']:destination=[target]
            if any(not ipaddress.IPv6Network(n).subnet_of(ipaddress.IPv6Network(target)) for n in destination):
                raise NatError('NAT64 destination matches must be within the translation prefix')
        else:source=[translation['internal']]
        ingress=r.interfaces(s['from']);egress=r.interfaces(s['to'])
        if s.get('to-interface') not in (None,'','any'):
            if s['to-interface'] not in egress:raise NatError('Destination interface is not in the selected destination zone')
            egress=[s['to-interface']]
        return dict(name=spec['name'],scope=owner.get('name'),position=position,ingress=ingress,egress=egress,
                    source=source,destination=destination,services=r.services(s['service']),snat={'type':'none'},dnat=None,translation=translation)
    if s.get('source-type')=='persistent-dynamic-ip-and-port':raise NatError('Persistent Dynamic IP and Port requires a dataplane persistent-binding allocator; activation is not supported by this provider')
    dynamic=s.get('destination-type')=='dynamic-ip'
    if dynamic and s.get('session-distribution') not in ('round-robin','source-ip-hash','ip-hash'):
        raise NatError('This session-distribution method requires a different dataplane allocator')
    if not dynamic and s.get('session-distribution'):
        raise NatError('Session distribution requires dynamic destination translation')
    source=r.addresses(s['source']);destination=r.addresses(s['destination'])
    ingress=r.interfaces(s['from']);egress=r.interfaces(s['to'])
    if s.get('to-interface') and s['to-interface']!='any':
        if s['to-interface'] not in egress:raise NatError('Destination interface is not in the selected destination zone')
        egress=[s['to-interface']]
    services=r.services(s['service']);mode=s.get('source-type','none')
    snat={'type':'none'}
    if mode=='dynamic-ip':raise NatError('Dynamic IP without port translation requires a dedicated address-pool allocator; use Dynamic IP and Port')
    if mode not in ('none','static-ip','dynamic-ip-and-port'):raise NatError('Unsupported source translation')
    if mode!='none':
        if s.get('source-interface'):
            if mode!='dynamic-ip-and-port' or s.get('translated-source'):raise NatError('Interface NAT requires Dynamic IP and Port without an address pool')
            snat={'type':'masquerade','interface':s['source-interface']}
        else:
            translated=r.addresses(s.get('translated-source',[]))
            if len(translated)!=1:raise NatError('This NAT provider requires one translated IPv4 address')
            address=ipv4(translated[0],host=True)
            if mode=='static-ip' and (len(source)!=1 or ipaddress.ip_network(source[0]).prefixlen!=32):raise NatError('Static source NAT requires one original host and one translated host')
            snat={'type':'static' if mode=='static-ip' else 'snat','address':address}
    elif s.get('source-interface') or s.get('translated-source'):raise NatError('Source translation must be selected')
    dnat=None
    if s.get('translated-destination'):
        addresses=r.addresses([s['translated-destination']])
        if dynamic:
            pool=set()
            for value in addresses:
                if '-' in value:
                    first,last=value.split('-');start,end=int(ipaddress.IPv4Address(first)),int(ipaddress.IPv4Address(last))
                else:
                    network=ipaddress.IPv4Network(value);start,end=int(network.network_address),int(network.broadcast_address)
                if end-start+1>256:raise NatError('Dynamic destination pool exceeds 256 hosts')
                for number in range(start,end+1):pool.add(ipv4(str(ipaddress.IPv4Address(number)),host=True))
                if len(pool)>256:raise NatError('Dynamic destination pool exceeds 256 hosts')
            if not pool:raise NatError('Dynamic destination pool is empty')
            dnat={'type':'dynamic','addresses':sorted(pool,key=ipaddress.IPv4Address),'method':s['session-distribution']}
        else:
            if len(addresses)!=1:raise NatError('Destination translation requires one IPv4 host')
            dnat={'address':ipv4(addresses[0],host=True)}
        if s.get('translated-port'):
            if any(x['protocol']=='any' for x in services):raise NatError('Port forwarding requires a TCP or UDP service')
            n=int(s['translated-port'])
            if not 1<=n<=65535:raise NatError('Translated port must be 1–65535')
            dnat['port']=n
    elif s.get('translated-port'):raise NatError('Translated port requires destination translation')
    return dict(name=spec['name'],scope=owner.get('name'),position=position,ingress=ingress,egress=egress,
                source=source,destination=destination,services=services,snat=snat,dnat=dnat)


def compile_policy(xml):
    from ffn_policy_config import parse,owners,describe,revision
    root=parse(xml);rules=[];errors=[];disabled=0
    for scope,owner in owners(root).items():
        for i,entry in enumerate(owner.findall('rulebase/nat/rules/entry')):
            if entry.findtext('disabled')=='yes':disabled+=1;continue
            try:rules.append(compile_rule(root,owner,describe('nat',entry),i+1))
            except (NatError,ValueError,KeyError,TypeError) as error:errors.append({'scope':scope,'kind':'nat','name':entry.get('name',''),'reason':str(error)})
    if len(rules)>1024:errors.append(dict(scope='all',kind='nat',name='',reason='NAT supports at most 1024 enabled rules'))
    plan={'version':2 if any('translation' in r for r in rules) else 1,'rules':rules}
    return {'valid':not errors,'blockers':errors,'disabled_rules':disabled,'plan':plan,'digest':digest(plan),'configuration_revision':revision(xml),'applied':False}
