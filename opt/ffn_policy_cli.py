# SPDX-License-Identifier: GPL-2.0-or-later
"""FFN-CLI command extension using the same authenticated API as the WebUI."""
import json
import copy
from urllib.parse import urlencode


HELP='''show policies <kind> [vsys] [candidate|running]
request policies <kind> add <name> [field=value ...] [scope=vsys1]
request policies <kind> edit <name> [field=value ...] [scope=vsys1]
request policies <kind> clone <name> <new-name> [field=value ...] [scope=vsys1]
request policies <kind> enable|disable|remove <name> [scope=vsys1]
request policies <kind> before|after <name> <anchor-name> [scope=vsys1]
show policies profiles <qos|decryption> [vsys] [candidate|running]
request policies profiles <qos|decryption> add|edit <name> [field=value ...] [scope=vsys1]
request policies profiles <qos|decryption> remove <name> [scope=vsys1]
Lists use comma-separated values; quote names or values containing spaces.
Rules start disabled. Friendly commands fetch the current candidate revision;
concurrent edits are rejected. enabled=yes|no and description= are supported.
QoS profile fields include max-mbps, guaranteed-mbps and class1.priority,
class1.max-mbps, class1.guaranteed-mbps (class1 through class8).
show policies preview <nat|qos|pbf|decryption> [vsys] [candidate|running]
request policies <nat|qos|pbf|decryption> test <packet-JSON> [vsys] [candidate|running]
show policies nat-preview [candidate|running]
show policies nat-tools
show policies status [candidate|running]
request policies <kind> <create|update|delete|move|toggle> <JSON> [vsys]
Use the displayed revision in mutations. Create/update use a rule object with
name, description, enabled and settings. Rules save to candidate; use commit.
Security settings include source-device, destination-device, source-user,
rule-type, action, icmp-unreachable, profile-mode (none|group|profiles),
profile-group, antivirus, vulnerability, anti-spyware, url-filtering,
file-blocking, data-filtering, crucible-analysis, log-start, log-end and
log-setting. Use the returned schema and choices for exact keys and references.
Rule usage is read only; unavailable statistics are not zero hits.
Kinds: security nat qos pbf decryption tunnel-inspect application-override
authentication dos sdwan. The same runtime blockers apply in CLI and WebUI.'''


def handle(tokens,api,token):
    if len(tokens)<2 or tokens[0] not in ('show','request') or tokens[1]!='policies':return False
    if len(tokens)<3:print(HELP);return True
    kind=tokens[2]
    if kind=='profiles':
        try:profile_command(tokens,api,token)
        except ValueError as error:print(str(error))
        return True
    if tokens[0]=='request' and len(tokens)>3 and tokens[3] in ('add','edit','clone','enable','disable','remove','before','after'):
        try:friendly_rule(tokens,api,token)
        except ValueError as error:print(str(error))
        return True
    if tokens[0]=='show' and kind=='preview':
        if len(tokens)<4 or len(tokens)>6:print(HELP);return True
        source=next((x for x in tokens[4:] if x in ('candidate','running')),'candidate')
        scope=next((x for x in tokens[4:] if x not in ('candidate','running')),'vsys1')
        print(json.dumps(api('/api/config/policies/'+tokens[3]+'/preview?'+urlencode(dict(scope=scope,source=source)),token=token),indent=2));return True
    if tokens[0]=='request' and len(tokens)>3 and tokens[3]=='test':
        if not 5<=len(tokens)<=7:print(HELP);return True
        try:packet=json.loads(tokens[4])
        except ValueError:print('Invalid JSON packet');return True
        if not isinstance(packet,dict):print('Packet must be a JSON object');return True
        source=next((x for x in tokens[5:] if x in ('candidate','running')),'candidate')
        scope=next((x for x in tokens[5:] if x not in ('candidate','running')),'vsys1')
        print(json.dumps(api('/api/config/policies/'+kind+'/test?'+urlencode(dict(scope=scope,source=source)),method='POST',body={'packet':packet},token=token),indent=2));return True
    if tokens[0]=='show' and kind=='nat-tools':
        print(json.dumps(api('/api/system/dataplane-tools',token=token),indent=2));return True
    if tokens[0]=='show' and kind=='nat-preview':
        source='running' if 'running' in tokens[3:] else 'candidate'
        print(json.dumps(api('/api/config/nat/preview?'+urlencode(dict(source=source)),token=token),indent=2));return True
    if tokens[0]=='show':
        source=next((x for x in tokens[3:] if x in ('candidate','running')),'candidate')
        scope=next((x for x in tokens[3:] if x not in ('candidate','running')),'vsys1')
        result=api('/api/config/policies/'+kind+'?'+urlencode(dict(scope=scope,source=source)),token=token)
    else:
        if len(tokens) not in (5,6):print(HELP);return True
        try:payload=json.loads(tokens[4])
        except ValueError:print('Invalid JSON policy request');return True
        if not isinstance(payload,dict):print('Policy request must be a JSON object');return True
        payload['action']=tokens[3]
        result=api('/api/config/policies/'+kind+'?'+urlencode(dict(scope=tokens[5] if len(tokens)==6 else 'vsys1')),method='POST',body=payload,token=token)
    print(json.dumps(result,indent=2));return True


def arguments(tokens):
    positional=[];fields={};scope='vsys1'
    for token in tokens:
        if '=' not in token:positional.append(token);continue
        key,value=token.split('=',1)
        if key=='scope':scope=value;continue
        if key in fields:raise ValueError('Repeated field: '+key)
        fields[key]=value
    return positional,fields,scope


def yesno(value):
    if value not in ('yes','no'):raise ValueError('enabled must be yes or no')
    return value=='yes'


def friendly_rule(tokens,api,token):
    kind,op=tokens[2:4];names,fields,scope=arguments(tokens[4:])
    if len(names)!=(2 if op in ('clone','before','after') else 1):raise ValueError('Specify rule name'+(' and target name' if op in ('clone','before','after') else ''))
    url='/api/config/policies/'+kind+'?'+urlencode(dict(scope=scope))
    snapshot=api(url,token=token)
    if 'entries' not in snapshot or 'schema' not in snapshot:raise ValueError('Cannot read policy schema: '+str(snapshot))
    entry=next((r for r in snapshot['entries'] if r['name']==names[0]),None)
    if op!='add' and entry is None:raise ValueError('Rule not found: '+names[0])
    payload={'revision':snapshot['revision'],'name':names[0]}
    if op in ('enable','disable','remove','before','after'):
        if fields:raise ValueError('This operation does not accept rule fields')
        payload['action']='toggle' if op in ('enable','disable') else 'delete' if op=='remove' else 'move'
        if op in ('enable','disable'):payload['enabled']=op=='enable'
        if op in ('before','after'):
            if names[0]==names[1]:raise ValueError('Rule and anchor must differ')
            others=[r['name'] for r in snapshot['entries'] if r['name']!=names[0]]
            if names[1] not in others:raise ValueError('Anchor rule not found')
            payload['position']=others.index(names[1])+1+(op=='after')
    else:
        schema={f['key']:f for f in snapshot['schema']['fields']}
        rule=({key:copy.deepcopy(entry[key]) for key in ('name','description','enabled','settings')} if entry and op!='add' else
              {'name':names[0],'description':'','enabled':False,'settings':{key:copy.deepcopy(f['default']) if f['default'] is not None else '' for key,f in schema.items()}})
        if op=='clone':rule.update(name=names[1],enabled=False)
        for key,value in fields.items():
            if key=='enabled':rule[key]=yesno(value)
            elif key=='description':rule[key]=value
            elif key in schema:rule['settings'][key]=[v.strip() for v in value.split(',') if v.strip()] if schema[key]['mode']=='list' else value
            else:raise ValueError('Unknown rule field: '+key)
        s=rule['settings']
        if kind=='nat':
            if s['source-type']=='none':s.update({'translated-source':[],'source-interface':''})
            elif 'source-interface' in fields and fields['source-interface']:s['translated-source']=[]
            elif 'translated-source' in fields or s['source-type']!='dynamic-ip-and-port':s['source-interface']=''
        if kind=='pbf' and s['action']!='forward':s.update({'egress-interface':'','next-hop':''})
        if kind=='decryption' and (s['action']!='decrypt' or s['type']!='ssl-inbound-inspection'):s['certificate']=''
        payload.update(action='update' if op=='edit' else 'create',rule=rule)
    print(json.dumps(api(url,method='POST',body=payload,token=token),indent=2))


def profile_command(tokens,api,token):
    if len(tokens)<4:raise ValueError('Specify qos or decryption')
    kind=tokens[3]
    if kind not in ('qos','decryption'):raise ValueError('Profile kind must be qos or decryption')
    if tokens[0]=='show':
        source=next((v for v in tokens[4:] if v in ('candidate','running')),'candidate')
        scope=next((v for v in tokens[4:] if v not in ('candidate','running')),'vsys1')
        print(json.dumps(api('/api/config/policy-profiles/'+kind+'?'+urlencode(dict(scope=scope,source=source)),token=token),indent=2));return
    if len(tokens)<6 or tokens[4] not in ('add','edit','remove'):raise ValueError('Use profiles <kind> add|edit|remove <name> [field=value]')
    op=tokens[4];names,fields,scope=arguments(tokens[5:])
    if len(names)!=1:raise ValueError('Specify one profile name')
    url='/api/config/policy-profiles/'+kind+'?'+urlencode(dict(scope=scope));snapshot=api(url,token=token)
    if 'entries' not in snapshot:raise ValueError('Cannot read profile inventory: '+str(snapshot))
    entry=next((r for r in snapshot['entries'] if r['name']==names[0]),None)
    if op!='add' and entry is None:raise ValueError('Profile not found')
    payload={'action':{'add':'create','edit':'update','remove':'delete'}[op],'name':names[0],'revision':snapshot['revision']}
    if op=='remove':
        if fields:raise ValueError('Remove does not accept profile fields')
    else:
        settings=copy.deepcopy(entry['settings'] if op=='edit' else snapshot['defaults'])
        for key,value in fields.items():
            target=settings;field=key
            if kind=='qos' and key.startswith('class') and '.' in key:
                group,field=key.split('.',1)
                if group not in ['class'+str(i) for i in range(1,9)]:raise ValueError('Use class1 through class8')
                target=next(row for row in settings['classes'] if row['id']==int(group[5:]))
            if field not in target or field in ('classes','id'):raise ValueError('Unknown profile field: '+key)
            target[field]=float(value) if field in ('max-mbps','guaranteed-mbps') else value
        payload['profile']={'name':names[0],'settings':settings}
    print(json.dumps(api(url,method='POST',body=payload,token=token),indent=2))
