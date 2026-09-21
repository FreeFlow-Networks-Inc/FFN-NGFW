# SPDX-License-Identifier: GPL-2.0-or-later
"""Shared policy configuration contract for controld, configd and API clients.

Only controld writes these candidate rules. No SQL shadow copy and no implicit
dataplane apply. Enabled rules without a commissioned runtime provider block
commit and configd apply, including rules imported through the generic CLI.
"""
import hashlib
import ipaddress
import os
from pathlib import Path
import re
import tempfile
import threading
import time
import xml.etree.ElementTree as ET


class PolicyError(ValueError):
    def __init__(self, message, code=422):
        super().__init__(message); self.code=code


def field(key, label, tab, mode='list', default=None, options=(), ref=None, path=None):
    return dict(key=key,label=label,tab=tab,mode=mode,default=default,
                options=list(options),ref=ref,path=path or key)


FROM=field('from','Source Zone','Source',default=['any'],ref='zone')
TO=field('to','Destination Zone','Destination',default=['any'],ref='zone')
SOURCE=field('source','Source Address','Source',default=['any'],ref='address')
DEST=field('destination','Destination Address','Destination',default=['any'],ref='address')
USER=field('source-user','Source User','Source',default=['any'])
APP=field('application','Application','Application / Service',default=['any'],ref='application')
SERVICE=field('service','Service','Application / Service',default=['any'],ref='service')
TAGS=field('tag','Tags','General',default=[],ref='tag')
MATCH=[FROM,SOURCE,TO,DEST]
FULL=MATCH+[USER,APP,SERVICE]


def select(key,label,options,default=None,path=None,tab='Actions'):
    return field(key,label,tab,'select',default or options[0],options,path=path)


SECURITY_PROFILES={
    'antivirus':('Antivirus Profile','virus'),
    'vulnerability':('Vulnerability Protection Profile','vulnerability'),
    'anti-spyware':('Anti-Spyware','spyware'),
    'url-filtering':('URL Filtering','url-filtering'),
    'file-blocking':('File Blocking','file-blocking'),
    'data-filtering':('Data Filtering','data-filtering'),
    'crucible-analysis':('Crucible Analysis','crucible-analysis'),
}


SCHEMAS={
 'security':dict(label='Security',fields=FULL+[
     field('source-device','Source Device','Source',default=['any'],ref='device'),
     field('destination-device','Destination Device','Destination',default=['any'],ref='device'),
     select('rule-type','Rule Type',['universal','intrazone','interzone'],tab='General'),
     select('action','Action',['allow','deny','drop','reset-client','reset-server','reset-both'],'deny'),
     select('icmp-unreachable','Send ICMP Unreachable',['no','yes']),
     dict(select('profile-mode','Profile Type',['none','group','profiles'],tab='Profiles'),virtual=True),
     field('profile-group','Security Profile Group','Profiles',mode='member-text',ref='profile-group',path='profile-setting/group'),
     *[field(key,label,'Profiles',mode='member-text',ref='profiles/'+path,path='profile-setting/profiles/'+path)
       for key,(label,path) in SECURITY_PROFILES.items()],
     select('log-start','Log at Session Start',['no','yes'],tab='Logging'),
     select('log-end','Log at Session End',['yes','no'],tab='Logging'),
     field('log-setting','Log Forwarding Profile','Logging',mode='text',ref='log-settings/profiles')]),
 'nat':dict(label='NAT',fields=MATCH+[SERVICE,
     select('nat-type','NAT Type',['ipv4'],tab='General'),
     field('to-interface','Destination Interface','Original Packet','text','any',ref='layer3-interface'),
     field('source-type','Translation Type','Translated Packet','branch','none',
           ['none','static-ip','dynamic-ip','dynamic-ip-and-port','persistent-dynamic-ip-and-port'],path='source-translation'),
     field('translated-source','Translated Source Addresses','Translated Packet',default=[],ref='address',path='source-translation/{source-type}/translated-address'),
     field('source-interface','Interface','Translated Packet','text',ref='layer3-interface',path='source-translation/{source-type}/interface-address/interface'),
     dict(field('destination-type','Translation Type','Translated Packet','select','none',['none','static-ip','dynamic-ip']),virtual=True),
     field('translated-destination','Translated Destination Address','Translated Packet','text',ref='address',path='destination-translation/translated-address'),
     field('translated-port','Translated Port','Translated Packet','text',path='destination-translation/translated-port'),
     field('session-distribution','Session Distribution Method','Translated Packet','select','',
           ['','round-robin','source-ip-hash','ip-modulo','ip-hash','least-sessions'],path='dynamic-destination-translation/distribution')]),
 'qos':dict(label='QoS',fields=FULL+[
     select('class','Class',[str(i) for i in range(1,9)],path='action/class')]),
 'pbf':dict(label='Policy Based Forwarding',fields=FULL+[
     field('action','Action','Forwarding','branch','no-pbf',['forward','discard','no-pbf'],path='action'),
     field('egress-interface','Egress Interface','Forwarding','text',ref='layer3-interface',path='action/forward/egress-interface'),
     field('next-hop','Next Hop','Forwarding','text',path='action/forward/nexthop/ip-address')]),
 'decryption':dict(label='Decryption',fields=MATCH+[USER,SERVICE,
     select('action','Action',['no-decrypt','decrypt']),
     field('type','Type','Actions','branch','ssl-forward-proxy',['ssl-forward-proxy','ssl-inbound-inspection','ssh-proxy']),
     field('certificate','Server Certificate','Actions','text',ref='certificate',path='type/ssl-inbound-inspection/certificate'),
     field('profile','Decryption Profile','Actions','text',ref='profiles/decryption')]),
 'tunnel-inspect':dict(label='Tunnel Inspection',fields=MATCH+[
     select('action','Action',['inspect','bypass']),
     field('tunnel-protocol','Tunnel Protocols','Inspection',default=['gre'],options=['gre','gtp-u','ipsec','vxlan']),
     select('log-end','Log at Session End',['yes','no'])]),
 'application-override':dict(label='Application Override',fields=MATCH+[
     select('protocol','Protocol',['tcp','udp'],tab='Protocol / Application'),
     field('port','Ports','Protocol / Application','text'),
     field('application','Application','Protocol / Application','text',ref='application')]),
 'authentication':dict(label='Authentication',fields=MATCH+[USER,SERVICE,
     field('authentication-enforcement','Authentication Enforcement','Actions','text',ref='authentication-enforcement'),
     field('timeout','Timeout (minutes)','Actions','text','60')]),
 'dos':dict(label='DoS Protection',fields=MATCH+[USER,SERVICE,
     select('action','Action',['deny','allow','protect']),
     field('aggregate-profile','Aggregate Profile','Actions','text',ref='profiles/dos-protection',path='protection/aggregate/profile'),
     field('classified-profile','Classified Profile','Actions','text',ref='profiles/dos-protection',path='protection/classified/profile')]),
 'sdwan':dict(label='SD-WAN',fields=FULL+[
     field('path-quality-profile','Path Quality Profile','Path Selection','text',ref='profiles/sdwan-path-quality',path='action/traffic-distribution/path-quality-profile'),
     field('traffic-distribution-profile','Traffic Distribution Profile','Path Selection','text',ref='profiles/sdwan-traffic-distribution',path='action/traffic-distribution/traffic-distribution-profile')]),
}
for schema in SCHEMAS.values(): schema['fields']=[TAGS]+schema['fields']
SCHEMAS['nat']['fields']=[dict(f,tab='Original Packet') if f['key'] in ('from','to','source','destination','service') else f for f in SCHEMAS['nat']['fields']]


def parse(xml):
    if len(xml)>16*1024*1024: raise PolicyError('Configuration exceeds policy parser limit')
    # Daemons use the stdlib-only runtime. Decode strictly before checking DTDs
    # so alternate encodings cannot hide declarations from the rejection.
    try:
        text=xml.decode('utf-8') if isinstance(xml,bytes) else xml
        if re.search(r'<!\s*(?:DOCTYPE|ENTITY)\b',text,re.I):raise ValueError('DTD/entity declarations are forbidden')
        return ET.fromstring(text)
    except Exception as error: raise PolicyError('Invalid configuration XML') from error


def revision(xml): return hashlib.sha256(xml if isinstance(xml,bytes) else xml.encode()).hexdigest()


def owners(root):
    return {n.get('name'):n for n in root.findall("./devices/entry[@name='localhost.localdomain']/vsys/entry")}


def node_at(root,path):
    for part in path.split('/'):
        n=root.find(part)
        root=n if n is not None else ET.SubElement(root,part)
    return root


def shape(node):
    return node.tag,tuple(sorted(node.attrib.items())),(node.text or '').strip(),sorted((shape(c) for c in node),key=repr)


def named(node,path): return {e.get('name') for e in node.findall(path+'/entry')} if node is not None else set()


def layer3_interfaces(root):
    parent=root.find("./devices/entry[@name='localhost.localdomain']/network/interface");routed=set()
    if parent is not None:
        for group in ('ethernet','aggregate-ethernet'):
            for entry in parent.findall(group+'/entry'):
                if entry.find('layer3') is not None:
                    if entry.findtext('aggregate-only')!='yes':routed.add(entry.get('name'))
                    routed.update(e.get('name') for e in entry.findall('layer3/units/entry'))
        for group in ('vlan','loopback','tunnel'):routed.update(e.get('name') for e in parent.findall(group+'/units/entry'))
    return {name for name in routed if name}


def inventory(root,scope,ref):
    local=owners(root)[scope];shared=root.find('shared')
    paths={'address':['address','address-group','region','external-list'],
           'application':['application','application-group','application-filter'],
           'service':['service','service-group']}.get(ref,[ref])
    if ref=='zone': return named(local,'zone')
    if ref=='layer3-interface':return layer3_interfaces(root)
    if ref=='interface':
        parent=root.find("./devices/entry[@name='localhost.localdomain']/network/interface")
        if parent is None:return set()
        return {e.get('name') for e in parent.iter('entry') if e.get('name') and re.fullmatch(r'(?:ethernet\d+/\d+|ae\d+|loopback|tunnel|vlan)(?:\.\d+)?',e.get('name'))}
    return set().union(*(named(node,path) for node in (shared,local) for path in paths))


def nat_destination_type(settings):
    return settings.get('destination-type') or ('static-ip' if settings.get('translated-destination') else 'none')


def policy_field_path(kind,field,settings):
    path=field['path']
    if kind=='nat' and field['key'] in ('translated-destination','translated-port') and nat_destination_type(settings)=='dynamic-ip':
        path=path.replace('destination-translation/','dynamic-destination-translation/',1)
    for key,value in settings.items():
        if isinstance(value,str):path=path.replace('{'+key+'}',value)
    return path


def serialize(kind,spec):
    entry=ET.Element('entry',name=spec['name'])
    ET.SubElement(entry,'disabled').text='no' if spec['enabled'] else 'yes'
    if spec.get('description'):ET.SubElement(entry,'description').text=spec['description']
    settings=spec['settings']
    for f in SCHEMAS[kind]['fields']:
        if f.get('virtual'):continue
        value=settings.get(f['key'])
        if value in (None,'',[]):continue
        path=policy_field_path(kind,f,settings)
        if f['mode']=='branch':
            if value!='none':node_at(entry,path+'/'+value)
        elif f['mode']=='list':
            for item in value:ET.SubElement(node_at(entry,path),'member').text=item
        elif f['mode']=='member-text':ET.SubElement(node_at(entry,path),'member').text=value
        else:node_at(entry,path).text=value
    return entry


def describe(kind,entry):
    settings={};fields=SCHEMAS[kind]['fields']
    if kind=='nat':
        settings['destination-type']='dynamic-ip' if entry.find('dynamic-destination-translation') is not None else 'static-ip' if entry.find('destination-translation') is not None else 'none'
    for f in fields:
        if f['mode']=='branch':
            parent=entry.find(f['path']);children=list(parent) if parent is not None else []
            settings[f['key']]=children[0].tag if len(children)==1 else 'none' if not children else 'unsupported'
    for f in fields:
        if f['mode']=='branch' or f.get('virtual'):continue
        path=policy_field_path(kind,f,settings)
        node=entry.find(path)
        if node is not None:
            settings[f['key']]=([n.text or '' for n in node.findall('member')] if f['mode']=='list'
                               else node.findtext('member','') if f['mode']=='member-text' and len(node)
                               else node.text or '')
    if kind=='security':
        settings['profile-mode']='group' if settings.get('profile-group') else 'profiles' if any(settings.get(k) for k in SECURITY_PROFILES) else 'none'
    spec=dict(name=entry.get('name',''),description=entry.findtext('description',''),enabled=entry.findtext('disabled','no')!='yes',settings=settings)
    expected=serialize(kind,spec)
    # Older FFN releases stored the group as scalar text. Read it losslessly;
    # an explicit edit upgrades it to the member representation.
    if kind=='security':
        old=entry.find('profile-setting/group');new=expected.find('profile-setting/group')
        if old is not None and not len(old) and new is not None:
            new.remove(new.find('member'));new.text=old.text
    # Absent disabled means enabled in imported PAN-style configurations.
    if entry.find('disabled') is None:expected.remove(expected.find('disabled'))
    spec['is_implicit']=kind=='security' and spec['name'].lower() in ('intrazone-default','interzone-default')
    spec['editable']=not spec['is_implicit'] and shape(expected)==shape(entry)
    for f in fields:
        default=f['default'] if kind=='security' and f['default'] is not None else [] if f['mode']=='list' else ''
        settings.setdefault(f['key'],default.copy() if isinstance(default,list) else default)
    spec['state']='blocked' if spec['enabled'] else 'disabled'
    if kind=='security':
        spec['usage']=dict(available=False,hit_count=None,first_hit=None,last_hit=None,
                           reason='No commissioned Security provider reports per-rule dataplane usage')
    return spec


def text_ok(value):
    return isinstance(value,str) and all(c in '\n\r\t' or 32<=ord(c)<=0xD7FF or 0xE000<=ord(c)<=0xFFFD or 0x10000<=ord(c)<=0x10FFFF for c in value)


def validate(kind,spec,root,scope):
    if not isinstance(spec,dict) or set(spec)-{'name','description','enabled','settings'}:raise PolicyError('Unknown rule properties')
    name=spec.get('name','')
    if not isinstance(name,str) or not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_ .-]{0,62}',name) or name!=name.strip():raise PolicyError('Invalid rule name (1–63 characters)')
    if type(spec.get('enabled')) is not bool:raise PolicyError('Enabled must be true or false')
    if not text_ok(spec.get('description','')) or len(spec.get('description',''))>1024:raise PolicyError('Invalid description')
    s=spec.get('settings');fields={f['key']:f for f in SCHEMAS[kind]['fields']}
    if not isinstance(s,dict) or set(s)-set(fields):raise PolicyError('Unknown rule settings')
    if kind=='nat':s.setdefault('destination-type',nat_destination_type(s))
    if kind=='security' and 'profile-mode' not in s:
        s['profile-mode']='group' if s.get('profile-group') else 'profiles' if any(s.get(k) for k in SECURITY_PROFILES) else 'none'
    for key,f in fields.items():
        default=f['default'] if f['default'] is not None else ''
        value=s.setdefault(key,default.copy() if isinstance(default,list) else default)
        values=value if f['mode']=='list' else [value]
        if f['mode']=='list' and (not isinstance(value,list) or len(value)>256 or any(not isinstance(v,str) for v in value) or len(set(value))!=len(value)):raise PolicyError(f['label']+': expected unique list values')
        if any(not text_ok(v) or len(v)>1024 or (f['mode']=='list' and not v.strip()) for v in values):raise PolicyError('Invalid '+f['label'])
        if f['options'] and any(v not in f['options'] for v in values):raise PolicyError('Invalid '+f['label'])
        if f['default']==['any'] and not value:raise PolicyError(f['label']+' must include a value or any')
        if isinstance(value,list) and 'any' in value and len(value)!=1:raise PolicyError('Any cannot be combined with other matches')
        if isinstance(value,list) and 'application-default' in value and len(value)!=1:raise PolicyError('Application-default cannot be combined with other services')
        if f['ref']:
            choices=inventory(root,scope,f['ref'])
            for v in values:
                if not v:continue
                if kind=='nat' and key=='to-interface' and v=='any':continue
                if v=='any' and f['default']==['any']:continue
                if v=='application-default' and kind=='security' and key=='service':continue
                if f['ref']=='address':
                    try:ipaddress.ip_network(v,strict=False);continue
                    except ValueError:pass
                if v not in choices:raise PolicyError(f['label']+': unknown reference '+v)
    if kind=='security':
        mode=s['profile-mode'];group=bool(s['profile-group']);profiles=any(s[k] for k in SECURITY_PROFILES)
        if mode=='none' and (group or profiles):raise PolicyError('Profile Type None cannot include a group or individual profiles')
        if mode=='group' and (not group or profiles):raise PolicyError('Select one profile group without individual profiles')
        if mode=='profiles' and (group or not profiles):raise PolicyError('Select at least one individual profile without a profile group')
        if s['icmp-unreachable']=='yes' and s['action']=='allow':raise PolicyError('ICMP Unreachable requires a blocking action')
        if s['rule-type']=='intrazone' and s['to']!=['any']:raise PolicyError('Intrazone rules use the source zone as destination; set Destination Zone to any')
    if kind=='nat':
        mode=s['source-type'];addresses=s['translated-source'];iface=s['source-interface']
        if mode=='none' and (addresses or iface):raise PolicyError('Source translation must be selected')
        if mode!='none' and bool(addresses)==bool(iface):raise PolicyError('Select translated source addresses or an interface address')
        if iface and mode not in ('dynamic-ip-and-port','persistent-dynamic-ip-and-port'):raise PolicyError('Interface address requires Dynamic IP and Port or Persistent Dynamic IP and Port')
        if mode=='static-ip' and len(addresses)!=1:raise PolicyError('Static source NAT needs one address')
        destination_mode=s['destination-type']
        if destination_mode=='none' and (s['translated-destination'] or s['translated-port']):raise PolicyError('Select a destination translation type')
        if destination_mode!='none' and not s['translated-destination']:raise PolicyError('Destination translation requires a translated address')
        if destination_mode=='dynamic-ip' and not s['session-distribution']:raise PolicyError('Select a session distribution method')
        if destination_mode!='dynamic-ip' and s['session-distribution']:raise PolicyError('Session distribution requires Dynamic IP destination translation')
        if s['translated-port']:
            if not s['translated-port'].isdigit() or not 1<=int(s['translated-port'])<=65535 or not s['translated-destination']:raise PolicyError('Destination port requires a destination address and port 1–65535')
    if kind=='pbf':
        if s['action']=='forward':
            if not s['egress-interface']:raise PolicyError('Forward requires an egress interface')
            if s['next-hop']:
                try:ipaddress.ip_address(s['next-hop'])
                except ValueError:raise PolicyError('Invalid next hop')
        elif s['egress-interface'] or s['next-hop']:raise PolicyError('Forwarding fields require Forward')
    if kind=='decryption':
        if s['action']=='no-decrypt' and s['certificate']:raise PolicyError('Server certificate requires Decrypt')
        if s['type']=='ssl-inbound-inspection' and s['action']=='decrypt' and not s['certificate']:raise PolicyError('Inbound TLS inspection requires a certificate')
        if s['certificate'] and s['type']!='ssl-inbound-inspection':raise PolicyError('Server certificate requires inbound TLS inspection')
    if kind=='application-override':
        if not s['application']:raise PolicyError('Select an application')
        for part in s['port'].split(','):
            if not re.fullmatch(r'[0-9]{1,5}(-[0-9]{1,5})?',part):raise PolicyError('Use TCP/UDP port numbers or ranges')
            bounds=list(map(int,part.split('-')))
            if not all(1<=n<=65535 for n in bounds) or bounds[0]>bounds[-1]:raise PolicyError('Invalid port range')
    if kind=='authentication' and (not s['authentication-enforcement'] or not s['timeout'].isdigit() or not 1<=int(s['timeout'])<=1440):raise PolicyError('Select an authentication enforcement profile and timeout 1–1440')
    if kind=='dos' and s['action']=='protect' and not (s['aggregate-profile'] or s['classified-profile']):raise PolicyError('Protect requires a DoS protection profile')
    if kind=='sdwan' and not all(s[k] for k in ('path-quality-profile','traffic-distribution-profile')):raise PolicyError('Select path quality and traffic distribution profiles')


def runtime_report(xml,check_runtime=False):
    """Fail closed until each policy compiler and acknowledged apply are connected."""
    root=parse(xml);blockers=[];disabled=0;nat_enabled=[];plans={}
    from ffn_qos_config import activation_blockers
    blockers.extend(activation_blockers(root))
    for scope,node in owners(root).items():
        for kind in SCHEMAS:
            for rule in node.findall('rulebase/'+kind+'/rules/entry'):
                if rule.findtext('disabled')=='yes':disabled+=1
                elif kind=='nat':nat_enabled.append(dict(scope=scope,kind=kind,name=rule.get('name','')))
                else:
                    reason='No commissioned runtime provider for this XML rulebase'
                    if kind in ('security','qos','pbf','decryption'):
                        from ffn_policy_plan import compile_policy as compile_plan
                        key=(scope,kind)
                        if key not in plans:plans[key]=compile_plan(xml,kind,scope)
                        plan=plans[key]
                        errors=[b['reason'] for b in plan['blockers'] if b['name']==rule.get('name','')]
                        if kind=='security':
                            reason=('Security plan compilation failed: '+ '; '.join(errors) if errors else
                                    'Security plan compiled, but dataplane enforcement is not connected. '+
                                    'Required: ordered stateful rules, zone/interface bindings and requested inspection/logging. '+
                                    'Aggregate transit remains default-deny; no rule has been activated')
                        else:reason+='; '+('; '.join(errors) if errors else '; '.join(plan['runtime_requirements']))
                    blockers.append(dict(scope=scope,kind=kind,name=rule.get('name',''),reason=reason))
    if nat_enabled:
        from ffn_nat_policy import compile_policy
        compiled=compile_policy(xml)
        if compiled['blockers']:blockers.extend(compiled['blockers'])
        else:
            try:
                from ffn_nat_control import preflight,commissioned
                if check_runtime:preflight(xml)
                elif not commissioned():raise ValueError('NAT runtime provider is not commissioned for Commit')
            except Exception as error:blockers.extend(dict(r,reason=str(error)) for r in nat_enabled)
    return dict(valid=not blockers,blockers=blockers,disabled_rules=disabled,
                revision=revision(xml),applied=False,owner='ffn-controld',
                runtime_state='blocked' if blockers else 'validated' if nat_enabled and check_runtime else 'requires-dataplane-validation' if nat_enabled else 'no-enabled-rules')


def require_supported(xml):
    report=runtime_report(xml,check_runtime=True)
    if report['blockers']:
        rows=report['blockers']
        raise PolicyError('Policy activation blocked: '+'; '.join(x['scope']+'/'+x['kind']+'/'+x['name']+': '+x['reason'] for x in rows[:8])+'. Running configuration was not applied.',409)
    return report


def configd_validate(path,status):
    """Called before any platform or local applier can perform side effects."""
    try:require_supported(Path(path).read_bytes())
    except (PolicyError,OSError) as error:
        status.validation(str(error));status.finish();status.write();return False
    return True


def replace_candidate(temp,path,original):
    # Windows scanners may briefly open the target without delete sharing.
    # Keep atomic replacement and the revision fence on every bounded retry.
    for attempt in range(6):
        if path.read_bytes()!=original:raise PolicyError('Candidate changed during this edit',409)
        try:os.replace(temp,path);return
        except PermissionError:
            if os.name!='nt' or attempt==5:raise
            time.sleep(0.02*(attempt+1))


def save_candidate(path,original,root):
    raw=ET.tostring(root,encoding='utf-8',xml_declaration=True)
    fd,temp=tempfile.mkstemp(prefix='.policy-',dir=path.parent)
    try:
        with os.fdopen(fd,'wb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
        os.chmod(temp,path.stat().st_mode & 0o777);replace_candidate(temp,path,original)
    finally:
        if os.path.exists(temp):os.unlink(temp)
    return dict(status='candidate-updated',revision=revision(raw),requires_commit=True,applied=False)


class PolicyController:
    def __init__(self,directory,commit=None):
        self.directory=Path(directory);self.commit=commit;self.lock=threading.RLock()

    def request(self,args):
        try:
            with self.lock:return dict(ok=True,data=self.execute(args))
        except PolicyError as error:return dict(ok=False,error=str(error),code=error.code)

    def execute(self,args):
        if args.get('action','').startswith('qos-interface-'):
            from ffn_qos_config import request
            return request(self,args)
        if args.get('action','').startswith('profile-'):
            from ffn_policy_profiles import request
            return request(self,args)
        action=args.get('action','list');source=args.get('source','candidate')
        if source not in ('candidate','running'):raise PolicyError('Invalid configuration source')
        if action not in ('list','report','preview','test','create','update','delete','move','toggle'):raise PolicyError('Unknown policy operation')
        path=self.directory/(source+'-config.xml');xml=path.read_bytes();root=parse(xml);rev=revision(xml)
        if action=='report':return runtime_report(xml)
        kind=args.get('kind');scope=args.get('scope','vsys1')
        if kind not in SCHEMAS:raise PolicyError('Unknown policy kind',404)
        scopes=owners(root)
        if scope not in scopes:raise PolicyError('Virtual system not found',404)
        if action in ('preview','test'):
            from ffn_policy_plan import compile_policy, test_policy
            return (compile_policy(xml,kind,scope) if action=='preview' else
                    test_policy(xml,kind,scope,args.get('packet')))
        rules=scopes[scope].find('rulebase/'+kind+'/rules');rows=list(rules) if rules is not None else []
        names=[e.get('name') for e in rows]
        if len(names)!=len(set(names)):raise PolicyError('Duplicate rule names must be repaired',409)
        if action=='list':
            schema=SCHEMAS[kind]
            return dict(kind=kind,label=schema['label'],schema=schema,scope=scope,scopes=list(scopes),source=source,revision=rev,
                entries=[dict(describe(kind,e),position=i+1) for i,e in enumerate(rows)],
                choices={f['key']:sorted(inventory(root,scope,f['ref'])) for f in schema['fields'] if f['ref']},
                runtime=runtime_report(xml))
        if source!='candidate':raise PolicyError('Running configuration is read only',403)
        user=args.get('user','')
        if not user:raise PolicyError('Authenticated actor required',403)
        if self.commit:
            state=self.commit.lock_status()
            if state['locked'] and state.get('holder')!=user:raise PolicyError('Configuration is locked by another administrator',423)
        if args.get('revision')!=rev:raise PolicyError('Candidate changed. Refresh and review before retrying',409)
        name=args.get('name');entry=next((r for r in rows if r.get('name')==name),None)
        incoming=args.get('rule');incoming_name=incoming.get('name') if isinstance(incoming,dict) else None
        if kind=='security' and any(str(n or '').lower() in ('intrazone-default','interzone-default') for n in (name,incoming_name)):
            raise PolicyError('Implicit security rules are read only',403)
        if action=='create':
            spec=args.get('rule');validate(kind,spec,root,scope)
            if spec['name'] in names:raise PolicyError('A rule with this name already exists',409)
            if rules is None:rules=node_at(scopes[scope],'rulebase/'+kind+'/rules')
            rules.append(serialize(kind,spec))
        else:
            if entry is None:raise PolicyError('Rule not found',404)
            if not describe(kind,entry)['editable']:raise PolicyError('Imported settings are protected; this rule cannot be edited safely',409)
            if action=='update':
                spec=args.get('rule');validate(kind,spec,root,scope)
                if spec['name']!=name:raise PolicyError('Clone and update references to rename a rule')
                i=list(rules).index(entry);rules.remove(entry);rules.insert(i,serialize(kind,spec))
            elif action=='delete':rules.remove(entry)
            elif action=='toggle':
                enabled=args.get('enabled')
                if type(enabled) is not bool:raise PolicyError('Enabled must be true or false')
                node_at(entry,'disabled').text='no' if enabled else 'yes'
            elif action=='move':
                position=args.get('position')
                if type(position) is not int or not 1<=position<=len(rows):raise PolicyError('Position must be within the rulebase')
                rules.remove(entry);rules.insert(position-1,entry)
        # Candidate writes are optimistic and atomic. Never write running here.
        if path.read_bytes()!=xml:raise PolicyError('Candidate changed during this edit',409)
        return save_candidate(path,xml,root)
