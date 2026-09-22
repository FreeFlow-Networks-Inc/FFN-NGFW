# SPDX-License-Identifier: GPL-2.0-or-later
"""Candidate egress QoS attachments and deterministic eight-class budgets.

This module never selects a Linux device, changes a queue, or reports an apply
acknowledgment. A commissioned scheduler must consume the resulting plan.
"""
from decimal import Decimal
import math
import re
import xml.etree.ElementTree as ET
from ffn_policy_config import PolicyError, parse, revision, node_at, shape, save_candidate
from ffn_policy_profiles import describe as describe_profile

NETWORK="./devices/entry[@name='localhost.localdomain']/network"
PATH=NETWORK+'/qos/interface'
DEFAULTS={'profile':'','enabled':False,'max-mbps':1000,'default-class':4}
RUNTIME='No commissioned egress scheduler; enabled QoS interfaces cannot be committed'


def interfaces(root):
    names=[]
    for group in ('ethernet','aggregate-ethernet'):
        for entry in root.findall(NETWORK+'/interface/'+group+'/entry'):
            name=entry.get('name','')
            if re.fullmatch(r'(ethernet[0-9]+/[0-9]+|ae[0-9]+)',name) and entry.find('aggregate-group') is None and any(entry.find(mode) is not None for mode in ('layer2','layer3')):
                names.append(name)
    return sorted(set(names))


def profiles(root):
    entries=root.findall(NETWORK+'/profiles/qos-profile/entry')
    if len({e.get('name') for e in entries})!=len(entries):raise PolicyError('Duplicate QoS profile names',409)
    return {e.get('name'):describe_profile('qos',e) for e in entries}


def serialize(spec):
    entry=ET.Element('entry',name=spec['interface'])
    for key in DEFAULTS:
        ET.SubElement(entry,key).text=('yes' if spec[key] else 'no') if key=='enabled' else str(spec[key])
    return entry


def describe(entry):
    spec=dict(DEFAULTS,interface=entry.get('name',''));editable=False
    try:
        spec.update(profile=entry.findtext('profile',''),enabled=entry.findtext('enabled')=='yes',
                    **{'max-mbps':float(entry.findtext('max-mbps','0')),'default-class':int(entry.findtext('default-class','4'))})
        if not math.isfinite(spec['max-mbps']):
            spec['max-mbps']=0
            return dict(spec,editable=False)
        normalized=ET.fromstring(ET.tostring(entry))
        for value in normalized.findall('max-mbps'):value.text=str(float(value.text))
        editable=shape(normalized)==shape(serialize(spec))
    except (ValueError,TypeError):pass
    return dict(spec,editable=editable)


def budget(root,spec):
    if not isinstance(spec,dict) or set(spec)!=set(DEFAULTS)|{'interface'}:raise PolicyError('QoS attachment requires interface, profile, enabled, max-mbps and default-class')
    if not isinstance(spec['interface'],str) or spec['interface'] not in interfaces(root):raise PolicyError('Select a configured Layer 2 or Layer 3 data interface; management ports and aggregate members are not eligible')
    if type(spec['enabled']) is not bool:raise PolicyError('Enabled must be true or false')
    if type(spec['default-class']) is not int or not 1<=spec['default-class']<=8:raise PolicyError('Default class must be 1–8')
    value=spec['max-mbps']
    if type(value) not in (int,float) or not 0<value<=1000000 or not math.isfinite(value):raise PolicyError('Egress maximum must be a finite positive value up to 1000000 Mbps')
    if not isinstance(spec['profile'],str):raise PolicyError('Select a QoS profile')
    profile=profiles(root).get(spec['profile'])
    if not profile:raise PolicyError('QoS profile does not exist')
    if not profile['editable']:raise PolicyError('Imported QoS profile has unsupported settings')
    settings=profile['settings'];cap=min(Decimal(str(value)),Decimal(str(settings['max-mbps'] or value)))
    classes=[]
    if Decimal(str(settings['guaranteed-mbps']))>cap:raise PolicyError('Profile guaranteed bandwidth exceeds interface egress maximum')
    for row in settings['classes']:
        guarantee=Decimal(str(row['guaranteed-mbps']));maximum=Decimal(str(row['max-mbps'] or cap))
        if maximum>cap or guarantee>cap:raise PolicyError('Class '+str(row['id'])+' bandwidth exceeds effective egress maximum')
        classes.append(dict(id=row['id'],priority=row['priority'],**{'max-mbps':float(maximum),'guaranteed-mbps':float(guarantee)}))
    guaranteed=sum(Decimal(str(c['guaranteed-mbps'])) for c in classes)
    if guaranteed>cap:raise PolicyError('Class guarantees exceed effective egress maximum')
    return dict(interface=spec['interface'],profile=spec['profile'],enabled=spec['enabled'],default_class=spec['default-class'],
                max_mbps=float(cap),guaranteed_mbps=float(guaranteed),unreserved_mbps=float(cap-guaranteed),classes=classes)


def plan(root):
    entries=root.findall(PATH+'/entry');rows=[];blockers=[];names=set()
    for entry in entries:
        spec=describe(entry);name=spec['interface']
        try:
            if name in names:raise PolicyError('Duplicate QoS interface attachment')
            names.add(name)
            if not spec.pop('editable'):raise PolicyError('Imported QoS interface fields are protected')
            rows.append(budget(root,spec))
        except PolicyError as error:blockers.append(dict(interface=name,reason=str(error)))
    return dict(valid=not blockers,interfaces=rows,blockers=blockers,applied=False,runtime=RUNTIME)


def activation_blockers(root):
    result=[]
    for entry in root.findall(PATH+'/entry'):
        # Unknown/imported activation values cannot silently bypass the guard.
        if entry.findtext('enabled')=='no':continue
        result.append(dict(scope='device',kind='qos-interface',name=entry.get('name',''),reason=RUNTIME))
    return result


def validate_profile_references(root,name):
    for entry in root.findall(PATH+'/entry'):
        if entry.findtext('profile')!=name:continue
        spec=describe(entry)
        if not spec.pop('editable'):raise PolicyError('Referenced QoS interface has protected imported fields',409)
        try:budget(root,spec)
        except PolicyError as error:raise PolicyError('QoS interface '+spec['interface']+': '+str(error),409)


def request(controller,args):
    action=args['action'];source=args.get('source','candidate')
    if source not in ('candidate','running') or action not in ('qos-interface-list','qos-interface-create','qos-interface-update','qos-interface-delete'):raise PolicyError('Invalid QoS interface operation')
    path=controller.directory/(source+'-config.xml');xml=path.read_bytes();root=parse(xml)
    parent=root.find(PATH);entries=list(parent.findall('entry')) if parent is not None else []
    names=[e.get('name') for e in entries]
    if action=='qos-interface-list':return dict(source=source,revision=revision(xml),entries=[describe(e) for e in entries],defaults=DEFAULTS,
                                               interfaces=interfaces(root),profiles=[n for n,p in profiles(root).items() if p['editable']],plan=plan(root),applied=False)
    if source!='candidate':raise PolicyError('Running configuration is read only',403)
    user=args.get('user')
    if not user:raise PolicyError('Authenticated actor required',403)
    if controller.commit:
        state=controller.commit.lock_status()
        if state['locked'] and state.get('holder')!=user:raise PolicyError('Configuration is locked by another administrator',423)
    if args.get('revision')!=revision(xml):raise PolicyError('Candidate changed. Refresh before retrying',409)
    if len(set(names))!=len(names):raise PolicyError('Duplicate QoS interfaces must be repaired',409)
    name=args.get('name');entry=next((e for e in entries if e.get('name')==name),None)
    if action!='qos-interface-create':
        if entry is None:raise PolicyError('QoS interface not found',404)
        if not describe(entry)['editable']:raise PolicyError('Imported QoS interface fields are protected',409)
    if action=='qos-interface-delete':parent.remove(entry)
    else:
        spec=args.get('attachment');budget(root,spec)
        if action=='qos-interface-create' and spec['interface'] in names:raise PolicyError('Interface already has a QoS attachment',409)
        if action=='qos-interface-update' and spec['interface']!=name:raise PolicyError('Remove and recreate to change the interface')
        if parent is None:
            network=root.find(NETWORK)
            if network is None:raise PolicyError('Configure a data interface first')
            parent=node_at(network,'qos/interface')
        if entry is not None:parent.remove(entry)
        parent.append(serialize(spec))
    return save_candidate(path,xml,root)
