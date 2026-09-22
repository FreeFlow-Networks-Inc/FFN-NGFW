# SPDX-License-Identifier: GPL-2.0-or-later
"""Validated candidate QoS and Decryption profiles owned by controld."""
import copy
import math
from decimal import Decimal
import re
import xml.etree.ElementTree as ET
from ffn_policy_config import PolicyError,parse,owners,revision,node_at,shape,save_candidate

PRIORITIES=['real-time','high','medium','low']
TLS=['tls1-0','tls1-1','tls1-2','tls1-3']
DECRYPT_FIELDS={
 'min-version':('Minimum TLS Version','ssl-protocol-settings/min-version','tls1-2',TLS),
 'max-version':('Maximum TLS Version','ssl-protocol-settings/max-version','tls1-3',TLS),
 'block-expired-certificate':('Block Expired Certificates','ssl-forward-proxy/block-expired-certificate','yes',['yes','no']),
 'block-untrusted-issuer':('Block Untrusted Issuers','ssl-forward-proxy/block-untrusted-issuer','yes',['yes','no']),
 'block-unsupported-version':('Block Unsupported TLS Versions','ssl-forward-proxy/block-unsupported-version','yes',['yes','no']),
 'block-unsupported-cipher':('Block Unsupported Ciphers','ssl-forward-proxy/block-unsupported-cipher','yes',['yes','no']),
 'block-client-auth':('Block Client Authentication','ssl-forward-proxy/block-client-auth','yes',['yes','no']),
 'block-if-no-resource':('Block When Inspection Resources Are Unavailable','ssl-forward-proxy/block-if-no-resource','yes',['yes','no']),
 'no-decrypt-block-expired':('No Decryption: Block Expired Certificates','ssl-no-proxy/block-expired-certificate','yes',['yes','no']),
 'no-decrypt-block-untrusted':('No Decryption: Block Untrusted Issuers','ssl-no-proxy/block-untrusted-issuer','yes',['yes','no']),
}


def defaults(kind):
    return ({'max-mbps':0,'guaranteed-mbps':0,'classes':[
        {'id':i,'priority':'medium','max-mbps':0,'guaranteed-mbps':0} for i in range(1,9)]}
        if kind=='qos' else {key:item[2] for key,item in DECRYPT_FIELDS.items()})


def validate(kind,profile):
    if not isinstance(profile,dict) or set(profile)!={'name','settings'}:raise PolicyError('Profile requires name and settings')
    name=profile['name']
    if not isinstance(name,str) or not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_ .-]{0,62}',name) or name!=name.strip():raise PolicyError('Invalid profile name')
    s=profile['settings']
    if not isinstance(s,dict) or set(s)!=set(defaults(kind)):raise PolicyError('Profile settings must match the schema')
    if kind=='decryption':
        if any(s[key] not in item[3] for key,item in DECRYPT_FIELDS.items()):raise PolicyError('Invalid decryption setting')
        if TLS.index(s['min-version'])>TLS.index(s['max-version']):raise PolicyError('Minimum TLS version exceeds maximum')
        return
    def bandwidth(row):
        for key in ('max-mbps','guaranteed-mbps'):
            v=row[key]
            if type(v) not in (int,float) or not math.isfinite(v) or not 0<=v<=1000000:raise PolicyError('Bandwidth must be a finite number from 0 to 1000000 Mbps')
        if row['max-mbps'] and row['guaranteed-mbps']>row['max-mbps']:raise PolicyError('Guaranteed bandwidth exceeds maximum')
    bandwidth(s)
    if not isinstance(s['classes'],list) or len(s['classes'])!=8:raise PolicyError('QoS requires all eight classes')
    ids=set()
    for row in s['classes']:
        if not isinstance(row,dict) or set(row)!={'id','priority','max-mbps','guaranteed-mbps'}:raise PolicyError('Invalid QoS class fields')
        if type(row['id']) is not int or not 1<=row['id']<=8 or row['id'] in ids:raise PolicyError('QoS class IDs must be unique values 1–8')
        ids.add(row['id'])
        if row['priority'] not in PRIORITIES:raise PolicyError('Invalid QoS priority')
        bandwidth(row)
        if s['max-mbps'] and (row['max-mbps']>s['max-mbps'] or row['guaranteed-mbps']>s['max-mbps']):raise PolicyError('Class bandwidth exceeds profile maximum')
    total=sum(Decimal(str(row['guaranteed-mbps'])) for row in s['classes'])
    if s['max-mbps'] and total>Decimal(str(s['max-mbps'])):raise PolicyError('Class guarantees exceed available profile bandwidth')
    if s['guaranteed-mbps'] and total>Decimal(str(s['guaranteed-mbps'])):raise PolicyError('Class guarantees exceed profile guaranteed bandwidth')


def serialize(kind,profile):
    entry=ET.Element('entry',name=profile['name']);s=profile['settings']
    if kind=='decryption':
        for key,(_,path,_,_) in DECRYPT_FIELDS.items():node_at(entry,path).text=s[key]
    else:
        for key in ('max-mbps','guaranteed-mbps'):node_at(entry,'aggregate-bandwidth/'+key).text=str(s[key])
        parent=node_at(entry,'classes')
        for row in sorted(s['classes'],key=lambda r:r['id']):
            child=ET.SubElement(parent,'entry',name='class'+str(row['id']))
            for key in ('priority','max-mbps','guaranteed-mbps'):ET.SubElement(child,key).text=str(row[key])
    return entry


def describe(kind,entry):
    profile={'name':entry.get('name',''),'settings':defaults(kind)}
    try:
        if kind=='decryption':
            for key,(_,path,default,_) in DECRYPT_FIELDS.items():profile['settings'][key]=entry.findtext(path,default)
        else:
            for key in ('max-mbps','guaranteed-mbps'):
                profile['settings'][key]=float(entry.findtext('aggregate-bandwidth/'+key,'0'))
            for row in profile['settings']['classes']:
                child=entry.find("classes/entry[@name='class"+str(row['id'])+"']")
                if child is None:continue
                row.update(priority=child.findtext('priority','medium'))
                for key in ('max-mbps','guaranteed-mbps'):row[key]=float(child.findtext(key,'0'))
        validate(kind,profile)
        # Number formatting is canonicalized only for comparison, not written.
        normalized=copy.deepcopy(entry)
        if kind=='qos':
            for node in normalized.iter():
                if node.tag in ('max-mbps','guaranteed-mbps'):node.text=str(float(node.text))
        expected=serialize(kind,profile)
        profile['editable']=shape(normalized)==shape(expected)
    except (PolicyError,ValueError,TypeError):profile['editable']=False
    return profile


def request(controller,args):
    kind=args.get('kind');source=args.get('source','candidate');scope=args.get('scope','vsys1');action=args['action']
    if kind not in ('qos','decryption'):raise PolicyError('Unknown policy profile type',404)
    if source not in ('candidate','running') or action not in ('profile-list','profile-create','profile-update','profile-delete'):raise PolicyError('Invalid profile operation')
    path=controller.directory/(source+'-config.xml');xml=path.read_bytes();root=parse(xml)
    local=owners(root).get(scope)
    if local is None:raise PolicyError('Virtual system not found',404)
    parent_path="./devices/entry[@name='localhost.localdomain']/network/profiles/qos-profile" if kind=='qos' else 'profiles/decryption'
    container=root if kind=='qos' else local
    parent=container.find(parent_path);entries=list(parent.findall('entry')) if parent is not None else []
    names=[e.get('name') for e in entries]
    if len(set(names))!=len(names):raise PolicyError('Duplicate profile names must be repaired',409)
    if action=='profile-list':
        return dict(kind=kind,scope=scope,location='Device-wide' if kind=='qos' else scope,source=source,revision=revision(xml),
            entries=[describe(kind,e) for e in entries],defaults=defaults(kind),priorities=PRIORITIES,
            fields=[dict(key=k,label=v[0],options=v[3]) for k,v in DECRYPT_FIELDS.items()] if kind=='decryption' else [],
            applied=False,runtime='Profile definition only; enforcement requires the corresponding dataplane engine')
    if source!='candidate':raise PolicyError('Running configuration is read only',403)
    user=args.get('user')
    if not user:raise PolicyError('Authenticated actor required',403)
    if controller.commit:
        state=controller.commit.lock_status()
        if state['locked'] and state.get('holder')!=user:raise PolicyError('Configuration is locked by another administrator',423)
    if args.get('revision')!=revision(xml):raise PolicyError('Candidate changed. Refresh before retrying',409)
    name=args.get('name');entry=next((e for e in entries if e.get('name')==name),None)
    if action!='profile-create':
        if entry is None:raise PolicyError('Profile not found',404)
        if not describe(kind,entry)['editable']:raise PolicyError('Imported profile fields are protected',409)
    if action=='profile-delete':
        references=(local.findall('rulebase/decryption/rules/entry/profile') if kind=='decryption' else
                    [node for node in root.findall('.//qos//*') if node.tag.endswith('profile')])
        if any((n.text or '')==name for n in references):raise PolicyError('Profile is referenced; update its references before deleting',409)
        parent.remove(entry)
    else:
        profile=args.get('profile');validate(kind,profile)
        if action=='profile-create' and profile['name'] in names:raise PolicyError('Profile already exists',409)
        if action=='profile-update' and profile['name']!=name:raise PolicyError('Profile renaming is not supported')
        if parent is None:
            parent=node_at(root.find("./devices/entry[@name='localhost.localdomain']"),'network/profiles/qos-profile') if kind=='qos' else node_at(local,'profiles/decryption')
        if entry is not None:parent.remove(entry)
        parent.append(serialize(kind,profile))
        if kind=='qos':
            from ffn_qos_config import validate_profile_references
            validate_profile_references(root,profile['name'])
    return save_candidate(path,xml,root)
