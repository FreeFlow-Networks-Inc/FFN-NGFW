# SPDX-License-Identifier: GPL-2.0-or-later
"""Lower supported IPv4 Security rules to a namespace-scoped nftables table.

This module does not apply rules or commission a provider. The caller must
coordinate the table with platform transit guards, NAT, logs and persistence.
Every reply is checked against current policy and an original-direction grant.
INPUT/OUTPUT are untouched: interface management is not transit policy.
"""
import json
from ffn_nat_policy import Resolver, NatError, digest
from ffn_policy_config import owners, parse
from ffn_policy_plan import compile_policy

TABLE='ffn_security'
PERMIT=0x80000000


def elements(values):return '{ '+', '.join(str(v) for v in values)+' }'


def render(xml,bindings,session_tokens=None):
    """Bindings are logical interface -> verified current kernel ifindex.

    Use numeric ifindexes so a newly recreated aggregate cannot inherit an old
    permit before its new owner is acknowledged. A separate reconciler is needed
    to install a new generation when the binding changes.
    """
    root=parse(xml);zones={};rules=[];seen=set()
    for scope,owner in owners(root).items():
        resolver=Resolver(root,owner)
        for zone in owner.findall('zone/entry'):
            name=zone.get('name')
            if (scope,name) in zones:raise NatError('Duplicate zone identity')
            if zone.find('network/layer3') is None:continue
            interfaces=resolver.interfaces([name]);indices=[]
            for interface in interfaces:
                index=bindings.get(interface)
                if type(index) is not int or not 1<=index<=0x7fffffff:raise NatError('Uncommissioned Security interface: '+interface)
                if index in seen:raise NatError('An interface belongs to multiple zones or virtual systems')
                seen.add(index);indices.append(index)
            zones[(scope,name)]=sorted(indices)
        report=compile_policy(xml,'security',scope)
        if not report['valid']:raise NatError('; '.join(b['reason'] for b in report['blockers']))
        for row in report['plan']['rules']:
            match=row['match'];action=row['action']
            for field in ('application','source-user','source-device','destination-device'):
                if match[field]!=['any']:raise NatError(row['name']+': '+field+' requires an identity/inspection provider')
            if match['services'] is None:raise NatError(row['name']+': application-default requires App-ID service resolution')
            if action['profiles']['mode']!='none':raise NatError(row['name']+': requested inspection profiles require a commissioned engine')
            if action['type'] not in ('allow','drop') or action['icmp_unreachable']:
                raise NatError(row['name']+': reject/reset action requires a commissioned response provider')
            logging=action['logging']
            if logging['forwarding_profile']:
                raise NatError(row['name']+': log forwarding requires a commissioned forwarding provider')
            if any(logging.values()) and (session_tokens is None or action['type']!='allow'):
                raise NatError(row['name']+': session logging requires a commissioned conntrack event collector')
            pairs=[]
            for (s,source),incoming in zones.items():
                if s!=scope or match['from']!=['any'] and source not in match['from']:continue
                for (d,destination),outgoing in zones.items():
                    if d!=scope or match['to']!=['any'] and destination not in match['to']:continue
                    if match['rule-type']=='intrazone' and source!=destination:continue
                    if match['rule-type']=='interzone' and source==destination:continue
                    pairs.append((incoming,outgoing))
            if not pairs:raise NatError(row['name']+': no applicable routed zone pair')
            rules.append(dict(row,pairs=pairs))
    plan_digest=digest({'rules':rules,'zones':sorted((s,z,v) for (s,z),v in zones.items())})
    lines=['table inet '+TABLE+' {',' comment "ffn-security:'+plan_digest+'"',
           ' chain forward { type filter hook forward priority -260; policy drop;',
           '  meta mark set meta mark & 0x7fffffff',
           '  meta nfproto != ipv4 drop','  ct state invalid drop',
           '  ct direction reply ct state != established drop',
           '  ct direction reply ct label & 0 != 0 drop']
    for i,rule in enumerate(rules):
        m=rule['match']
        for incoming,outgoing in rule['pairs']:
            for direction,src,dst in [('original',incoming,outgoing),('reply',outgoing,incoming)]:
                base='ct direction '+direction+' iif '+elements(src)+' oif '+elements(dst)
                base+=' ct original ip saddr '+elements(m['source'])+' ct original ip daddr '+elements(m['destination'])
                for service in m['services']:
                    condition=base
                    if service['protocol']!='any':
                        condition+=' meta l4proto '+service['protocol']
                        for key,field in (('source_ports','proto-src'),('destination_ports','proto-dst')):
                            if service[key]:condition+=' ct original '+field+' '+elements(service[key])
                    lines.append('  '+condition+' goto r'+str(i))
    for indices in zones.values():
        lines.append('  iif '+elements(indices)+' oif '+elements(indices)+' goto implicit_allow')
    lines+=['  counter drop',' }']
    def label(identity):
        if session_tokens is None:return ''
        token=session_tokens.get(identity)
        if type(token) is not int or not 1<=token<0x40000000:raise NatError('Missing or invalid durable Security session token')
        # ct_label is a symbolic bitmask datatype: each number names a bit,
        # including zero. Hexadecimal does not turn it into a raw integer.
        bits=[0]+[i+1 for i in range(30) if token & (1<<i)]
        return 'ct direction original ct label & 0 != 0 ct label set '+' | '.join(map(str,bits))+'; '
    for i,rule in enumerate(rules):
        decision=(label((rule['scope'],rule['name']))+'goto grant') if rule['action']['type']=='allow' else 'drop'
        lines.append(' chain r'+str(i)+' { counter comment '+json.dumps(rule['scope']+'/'+rule['name'])+'; '+decision+'; }')
    lines+=[' chain implicit_allow { counter; '+label(('implicit','intrazone-default'))+'goto grant; }',
            ' chain grant { ct direction original ct label set ct label | 0; meta mark set meta mark | 0x80000000; accept; }','}']
    script='\n'.join(lines)+'\n'
    if len(script.encode())>65536:raise NatError('Expanded Security policy exceeds 64 KiB')
    return dict(script=script,digest=plan_digest,applied=False,
                requirements=['Dedicated data namespace','Exclusive conntrack label bit 0 and packet mark bit 31 ownership',
                              'Acknowledged platform guard integration','Atomic coordination with NAT and binding changes'])
