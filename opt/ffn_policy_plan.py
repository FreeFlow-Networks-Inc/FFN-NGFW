# SPDX-License-Identifier: GPL-2.0-or-later
"""Portable policy compilation and read-only first-match diagnostics.

Plans describe intended behavior, never an apply acknowledgment. Packet tests
use explicit caller context; they do not infer routing, identity or App-ID.
Unknown predicates stop selection rather than silently selecting a later rule.
"""
import copy
import ipaddress

from ffn_nat_policy import Resolver, NatError, compile_rule as compile_nat, digest
from ffn_policy_config import PolicyError, describe, owners, parse, revision, validate

KINDS=('security','nat','qos','pbf','decryption')
REQUIREMENTS={
    'security':['Security enforcement provider with ordered rules, connection tracking and acknowledged apply',
                'Zone-to-dataplane interface bindings, including aggregate VLAN transit gates',
                'Requested identity, inspection, reset and session logging capabilities'],
    'nat':['Commissioned NAT provider, logical interface bindings and dataplane validation'],
    'qos':['Dataplane classifier and egress scheduler with class-to-queue bindings and rate profiles'],
    'pbf':['Dataplane policy routing provider with next-hop validation and return-path handling',
           'NAT route lookup integration before combining PBF with NAT'],
    'decryption':['TLS/SSH inspection proxy and session steering on the dataplane',
                  'Certificate/key provisioning, trust validation and decryption profile enforcement'],
}


def applications(resolver, values, stack=()):
    result=[]
    for value in values:
        if value=='any':return ['any']
        if value in stack or len(stack)>16:raise NatError('Application group cycle or excessive nesting')
        group=resolver.find('application-group',value)
        if group is not None:
            members=group.findall('members/member')
            if not members:raise NatError('Empty application group: '+value)
            result.extend(applications(resolver,[m.text or '' for m in members],stack+(value,)))
        elif resolver.find('application',value) is not None:result.append(value)
        else:raise NatError('Application filter or unresolved application requires an App-ID provider: '+value)
        if len(result)>256:raise NatError('Expanded application list exceeds 256 entries')
    return sorted(set(result))


def compile_entry(root,owner,kind,spec,position):
    s=spec['settings'];resolver=Resolver(root,owner)
    if not spec['editable']:raise PolicyError('Imported rule contains unsupported XML fields')
    checked={k:copy.deepcopy(spec[k]) for k in ('name','description','enabled','settings')}
    validate(kind,checked,root,owner.get('name'))
    s=checked['settings']
    # Application-default is a semantic constraint, not the same as service any.
    services=None if kind=='security' and s['service']==['application-default'] else resolver.services(s['service'])
    match={'from':s['from'],'to':s['to'],'source':resolver.addresses(s['source']),
           'destination':resolver.addresses(s['destination']),'services':services,
           'source-user':s.get('source-user',['any']),
           'application':applications(resolver,s.get('application',['any']))}
    if kind=='security':
        from ffn_policy_config import SECURITY_PROFILES
        match.update({'rule-type':s['rule-type'],'source-device':s['source-device'],
                      'destination-device':s['destination-device']})
        action={'type':s['action'],'icmp_unreachable':s['icmp-unreachable']=='yes',
                'profiles':{'mode':s['profile-mode'],'group':s['profile-group'] or None,
                            'individual':{k:s[k] for k in SECURITY_PROFILES if s[k]}},
                'logging':{'start':s['log-start']=='yes','end':s['log-end']=='yes',
                           'forwarding_profile':s['log-setting'] or None}}
    elif kind=='nat':
        native=compile_nat(root,owner,dict(spec,settings=s),position)
        match['egress-interface']=s.get('to-interface') or 'any'
        action={'source_translation':native['snat'],'destination_translation':native['dnat']}
    elif kind=='qos':action={'class':int(s['class'])}
    elif kind=='pbf':
        action={'type':s['action']}
        if s['action']=='forward':
            # Interface inventory includes L2 and disabled entries; routing must not.
            name=s['egress-interface']
            parent=root.find("./devices/entry[@name='localhost.localdomain']/network/interface")
            routed=set()
            if parent is not None:
                for group in ('ethernet','aggregate-ethernet'):
                    for entry in parent.findall(group+'/entry'):
                        if entry.find('layer3') is not None:
                            routed.add(entry.get('name'));routed.update(e.get('name') for e in entry.findall('layer3/units/entry'))
                for group in ('vlan','loopback','tunnel'):routed.update(e.get('name') for e in parent.findall(group+'/units/entry'))
            if name not in routed:
                raise PolicyError('PBF egress must be a configured Layer 3 interface')
            if s['next-hop'] and ipaddress.ip_address(s['next-hop']).version!=4:raise PolicyError('IPv4 policy requires an IPv4 next hop')
            action.update(interface=name,next_hop=s['next-hop'] or None)
    else:
        action={'type':s['action'],'inspection':s['type'] if s['action']=='decrypt' else None,
                'certificate':s['certificate'] or None,'profile':s['profile'] or None}
    return {'match':match,'action':action}


def compile_policy(xml,kind,scope='vsys1'):
    if kind not in KINDS:raise PolicyError('Policy planning is available for Security, NAT, QoS, PBF and Decryption',404)
    root=parse(xml);owner=owners(root).get(scope)
    if owner is None:raise PolicyError('Virtual system not found',404)
    rows=[];blockers=[];disabled=0
    entries=owner.findall('rulebase/'+kind+'/rules/entry')
    if len(entries)>1024:raise PolicyError('Policy planning supports at most 1024 rules per rulebase')
    names=set()
    for position,entry in enumerate(entries,1):
        if entry.findtext('disabled')=='yes':disabled+=1;continue
        row={'name':entry.get('name',''),'scope':scope,'position':position}
        try:
            if row['name'] in names:raise PolicyError('Duplicate rule identity')
            names.add(row['name'])
            row.update(compile_entry(root,owner,kind,describe(kind,entry),position))
        except (PolicyError,NatError,ValueError,TypeError,KeyError) as error:
            row.update(match=None,action=None,error=str(error))
            blockers.append(dict(scope=scope,kind=kind,name=row['name'],reason=str(error)))
        rows.append(row)
    plan={'version':1,'kind':kind,'scope':scope,'rules':rows}
    return {'valid':not blockers,'plan':plan,'digest':digest(plan),'configuration_revision':revision(xml),
            'blockers':blockers,'disabled_rules':disabled,'applied':False,'owner':'ffn-controld',
            'runtime_requirements':REQUIREMENTS[kind],
            'enforcement':'Use NAT translation preview for current dataplane acknowledgment' if kind=='nat' else 'No commissioned runtime provider',
            'semantics':'First matching enabled rule; packet context is supplied, not detected. This test does not authorize traffic or apply configuration.'}


def validate_packet(packet,root,scope):
    allowed={'source','destination','from_zone','to_zone','protocol','source_port','destination_port',
           'application','source_user','source_device','destination_device','egress_interface'}
    if not isinstance(packet,dict) or set(packet)-allowed:raise PolicyError('Unknown packet fields')
    p=dict(packet)
    for key in ('source','destination'):
        try:p[key]=str(ipaddress.IPv4Address(p[key]))
        except (ValueError,KeyError,TypeError):raise PolicyError('Packet '+key+' must be an IPv4 address')
    zones={e.get('name') for e in owners(root)[scope].findall('zone/entry')}
    for key in ('from_zone','to_zone'):
        if not isinstance(p.get(key),str) or p[key] not in zones:raise PolicyError('Select a configured '+key)
    if p.get('protocol') not in ('tcp','udp','icmp','other'):raise PolicyError('Packet protocol must be tcp, udp, icmp or other')
    for key in ('source_port','destination_port'):
        if key in p and (type(p[key]) is not int or not 1<=p[key]<=65535 or p['protocol'] not in ('tcp','udp')):raise PolicyError('Packet ports require TCP/UDP and values 1–65535')
    for key in ('application','source_user','source_device','destination_device','egress_interface'):
        if key in p and (not isinstance(p[key],str) or not 1<=len(p[key])<=1024):raise PolicyError('Invalid packet '+key)
    return p


def address_match(value,addresses):
    address=ipaddress.IPv4Address(value)
    for item in addresses:
        if '-' in item:
            lo,hi=item.split('-')
            if ipaddress.IPv4Address(lo)<=address<=ipaddress.IPv4Address(hi):return True
        elif address in ipaddress.ip_network(item):return True
    return False


def port_match(value,ranges):
    if not ranges:return True
    if value is None:return None
    return any(int(part.split('-')[0])<=value<=int(part.split('-')[-1]) for part in ranges)


def all_matches(values):
    return False if False in values else None if None in values else True


def match_packet(match,packet):
    if match is None:return None
    results=[]
    for key,packet_key in (('from','from_zone'),('to','to_zone'),('source-user','source_user'),('application','application'),
                           ('source-device','source_device'),('destination-device','destination_device')):
        if key not in match:continue
        values=match[key]
        results.append(True if values==['any'] else packet[packet_key] in values if packet_key in packet else None)
    if match.get('rule-type') in ('intrazone','interzone'):
        results.append((packet['from_zone']==packet['to_zone'])==(match['rule-type']=='intrazone'))
    for key in ('source','destination'):results.append(address_match(packet[key],match[key]))
    egress=match.get('egress-interface','any')
    results.append(True if egress=='any' else packet['egress_interface']==egress if 'egress_interface' in packet else None)
    services=[]
    if match['services'] is None:services.append(None) # No App-ID default-service resolver.
    for service in match['services'] or []:
        if service['protocol']=='any':services.append(True);continue
        services.append(all_matches([service['protocol']==packet['protocol'],
            port_match(packet.get('source_port'),service['source_ports']),
            port_match(packet.get('destination_port'),service['destination_ports'])]))
    results.append(True if True in services else None if None in services else False)
    return all_matches(results)


def test_policy(xml,kind,scope,packet):
    report=compile_policy(xml,kind,scope);packet=validate_packet(packet,parse(xml),scope)
    trace=[];selected=None;status='no-match'
    for row in report['plan']['rules']:
        matched=match_packet(row['match'],packet)
        trace.append({'name':row['name'],'position':row['position'],'result':'indeterminate' if matched is None else 'match' if matched else 'no-match',
                      'reason':row.get('error') or ('Application-default requires an App-ID default-service resolver' if matched is None and row['match']['services'] is None else 'Supply missing ports, user, device, application or egress interface' if matched is None else '')})
        if matched is None:status='indeterminate';break
        if matched:selected=row;status='matched';break
    if kind=='security' and status=='no-match':
        same=packet['from_zone']==packet['to_zone']
        selected={'name':'intrazone-default' if same else 'interzone-default',
                  'scope':scope,'implicit':True,'action':{'type':'allow' if same else 'deny'}}
        status='matched'
        trace.append({'name':selected['name'],'position':None,'result':'match','reason':'Implicit policy intent; no runtime enforcement acknowledgment'})
    return {'kind':kind,'scope':scope,'configuration_revision':report['configuration_revision'],'digest':report['digest'],
            'status':status,'selected':selected,'trace':trace,'applied':False,'simulation':True,
            'runtime_requirements':report['runtime_requirements'],'enforcement':report['enforcement'],
            'semantics':report['semantics']}
