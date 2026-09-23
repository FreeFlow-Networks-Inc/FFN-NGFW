#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""DP-owned IPv4 NAT. Same Python/nftables contract on CPU and MIPS64eb.

Only the ffn-data namespace and ffn_nat table are owned. A root-provisioned
logical-interface map is required. No interface creation or routing changes.
"""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import subprocess as S
import sys

from ffn_nat_policy import digest,ipv4,ports,NatError

NS='ffn-data'
TABLE='ffn_nat'
STATE=Path('/etc/ffn/nat.json')
BINDINGS=Path('/etc/ffn/nat-interfaces.json')
PLATFORM_BINDINGS=Path('/etc/ffn/policy-bindings.json')
COORDINATED=Path('/etc/ffn/policy-runtime.json')
LOCK=Path('/run/ffn-network.lock')
MARK=0xf1000000


def executable(name):
    private=Path('/usr/local/ffn-dp/sbin')/name
    if private.is_file():return str(private)
    private=Path('/usr/local/ffn-dp/bin')/name
    return str(private) if private.is_file() else shutil.which(name)


def run(argv,text=None):
    result=S.run(argv,input=text,text=True,capture_output=True,timeout=15)
    if result.returncode:raise NatError(result.stderr.strip()[:1500] or 'Dataplane command failed')
    return result.stdout


def nft(args,text=None):
    binary=executable('nft')
    if not binary:raise NatError('nftables userspace is missing on the dataplane')
    return run(['ip','netns','exec',NS,binary,*args],text)


def saved():
    if COORDINATED.exists():return json.loads(COORDINATED.read_text())['nat']
    return json.loads(STATE.read_text()) if STATE.exists() else {'revision':0,'plan':{'version':1,'rules':[]},'digest':None,'script':None}


def bindings():
    if not BINDINGS.exists():raise NatError('No commissioned NAT interface map on the dataplane')
    st=BINDINGS.stat()
    if st.st_uid!=0 or st.st_mode & 0o022:raise NatError('NAT interface map must be root-owned and not writable by other users')
    data=json.loads(BINDINGS.read_text())
    if not isinstance(data,dict) or not data or any(not isinstance(k,str) or not isinstance(v,str) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,15}',v) or v=='lo' for k,v in data.items()):raise NatError('Invalid NAT interface map')
    if len(set(data.values()))!=len(data):raise NatError('Ambiguous NAT interface map')
    selection=PLATFORM_BINDINGS
    if selection.exists():
        st=selection.stat()
        if st.st_uid!=0 or st.st_mode & 0o022:raise NatError('Policy binding provider must be root-owned')
        if json.loads(selection.read_text())!={'provider':'platform'}:raise NatError('Unknown policy binding provider')
        try:from ffn_platform_policy_bindings import discover
        except ImportError as error:raise NatError('Selected platform binding provider is not installed') from error
        links={x['ifname']:x for x in json.loads(run(['ip','-n',NS,'-d','-j','link']))}
        for logical,device in discover(links).items():
            if logical in data and data[logical]!=device:raise NatError('Conflicting platform interface binding: '+logical)
            if device in data.values() and data.get(logical)!=device:raise NatError('Ambiguous platform interface binding')
            data[logical]=device
    return data


def validate_plan(plan):
    if not isinstance(plan,dict) or set(plan)!={'version','rules'} or type(plan['version']) is not int or plan['version'] not in (1,2) or not isinstance(plan['rules'],list) or len(plan['rules'])>1024:raise NatError('Invalid NAT plan')
    if len(json.dumps(plan))>65536:raise NatError('NAT plan exceeds 64 KiB')
    identities=set();owners={}
    for rule in plan['rules']:
        fields={'name','scope','position','ingress','egress','source','destination','services','snat','dnat'}
        if isinstance(rule,dict) and 'translation' in rule and plan['version']==2:fields.add('translation')
        if not isinstance(rule,dict) or set(rule)!=fields:raise NatError('Invalid NAT rule fields')
        translation=rule.get('translation')
        if 'translation' in rule:
            from ffn_ipv6_translation import validate_translation
            validate_translation(translation)
        if not all(isinstance(rule[k],str) and 1<=len(rule[k])<=63 for k in ('name','scope')) or type(rule['position']) is not int:raise NatError('Invalid NAT rule identity')
        key=(rule['scope'],rule['name'])
        if key in identities:raise NatError('Duplicate NAT rule')
        identities.add(key)
        for key in ('ingress','egress','source','destination'):
            if not isinstance(rule[key],list) or not 1<=len(rule[key])<=256 or any(not isinstance(v,str) for v in rule[key]):raise NatError('Invalid NAT match')
        for iface in rule['ingress']+rule['egress']:
            if not re.fullmatch(r'(?:ethernet[0-9]+/[0-9]+|ae[0-9]+|vlan|tunnel|loopback)(?:\.[0-9]+)?',iface):raise NatError('Invalid logical interface')
            if iface in owners and owners[iface]!=rule['scope']:raise NatError('Interface belongs to multiple virtual systems')
            owners[iface]=rule['scope']
        for addr in rule['source']+rule['destination']:
            if translation:ipaddress.IPv6Network(addr,strict=True)
            else:ipv4(addr)
        if not isinstance(rule['services'],list) or not 1<=len(rule['services'])<=256:raise NatError('Invalid NAT services')
        for service in rule['services']:
            if not isinstance(service,dict) or set(service)!={'protocol','source_ports','destination_ports'} or service['protocol'] not in ('any','tcp','udp'):raise NatError('Invalid NAT service')
            for key in ('source_ports','destination_ports'):
                if not isinstance(service[key],list) or len(service[key])>256:raise NatError('Invalid NAT service ports')
                for part in service[key]:
                    if not isinstance(part,str):raise NatError('Invalid NAT service port')
                    ports(part)
                if service['protocol']=='any' and service[key]:raise NatError('Port matches require TCP or UDP')
        snat=rule['snat'];dnat=rule['dnat']
        if translation:
            if snat!={'type':'none'} or dnat is not None:raise NatError('IPv6 translation cannot include IPv4 NAT actions')
            if translation['type']=='nat64' and any(not ipaddress.IPv6Network(n).subnet_of(ipaddress.IPv6Network(translation['prefix'])) for n in rule['destination']):raise NatError('NAT64 destination is outside its prefix')
            if translation['type']=='nptv6' and (rule['source']!=[translation['internal']] or rule['destination']!=['::/0'] or rule['services']!=[{'protocol':'any','source_ports':[],'destination_ports':[]}]):raise NatError('NPTv6 requires a complete transport-independent prefix mapping')
        if not isinstance(snat,dict) or snat.get('type') not in ('none','static','snat','masquerade'):raise NatError('Invalid source translation')
        expected={'type'}|({'interface'} if snat['type']=='masquerade' else {'address'} if snat['type'] in ('static','snat') else set())
        if set(snat)!=expected:raise NatError('Invalid source translation fields')
        if 'address' in snat:ipv4(snat['address'],host=True)
        if snat['type']=='static' and (len(rule['source'])!=1 or '/' not in rule['source'][0] or ipaddress.ip_network(rule['source'][0]).prefixlen!=32):raise NatError('Static NAT needs one original host')
        if snat['type']=='masquerade' and (not isinstance(snat['interface'],str) or not re.fullmatch(r'(?:ethernet[0-9]+/[0-9]+|ae[0-9]+|vlan|tunnel|loopback)(?:\.[0-9]+)?',snat['interface'])):raise NatError('Invalid source translation interface')
        if dnat is not None:
            if not isinstance(dnat,dict):raise NatError('Invalid destination translation')
            if dnat.get('type')=='dynamic':
                if set(dnat)-{'type','addresses','method','port'} or not {'addresses','method'}<=set(dnat):raise NatError('Invalid dynamic destination fields')
                pool=dnat['addresses']
                if not isinstance(pool,list) or not 1<=len(pool)<=256 or any(not isinstance(a,str) for a in pool) or len(set(pool))!=len(pool):raise NatError('Invalid dynamic destination pool')
                for addr in pool:ipv4(addr,host=True)
                if dnat['method'] not in ('round-robin','source-ip-hash','ip-hash'):raise NatError('Unsupported session-distribution method')
            else:
                if set(dnat)-{'address','port'} or 'address' not in dnat:raise NatError('Invalid destination translation')
                ipv4(dnat['address'],host=True)
            if 'port' in dnat and (type(dnat['port']) is not int or not 1<=dnat['port']<=65535 or any(s['protocol']=='any' for s in rule['services'])):raise NatError('Port forwarding requires TCP/UDP and a valid port')
    return plan


def elements(values,quoted=False):return '{ '+', '.join(json.dumps(v) if quoted else v for v in values)+' }'


def translation_capabilities(module_root=Path('/sys/module')):
    # Discovery is evidence, never permission to bypass coordinated Security.
    return {
        'ipv4':dict(supported=True,hardware_offload=False,reason='Commit validates current interface bindings and nftables'),
        'nat64':dict(supported=False,hardware_offload=False,
            userspace_installed=bool(executable('jool')),module_loaded=(module_root/'jool').is_dir(),
            reason='NAT64 needs a commissioned stateful translator with IPv6 Security, ICMP/PMTU, fragment handling and acknowledged session lifecycle'),
        'nptv6':dict(supported=False,hardware_offload=False,
            module_loaded=(module_root/'ip6t_NPT').is_dir(),
            reason='NPTv6 needs a commissioned checksum-neutral IPv6 forwarding provider with Security, hairpin and ICMP error translation'),
    }


def require_translation_provider(plan):
    for rule in plan['rules']:
        if 'translation' in rule:
            kind=rule['translation']['type']
            raise NatError(rule['scope']+'/'+rule['name']+': '+translation_capabilities()[kind]['reason']+'; no settings applied')


def render(plan,mapping,links,revision):
    validate_plan(plan)
    require_translation_provider(plan)
    if not 1<=revision<16384:raise NatError('NAT generation space exhausted; reconcile conntrack before reset')
    used={i for r in plan['rules'] for i in r['ingress']+r['egress']}
    used.update(r['snat']['interface'] for r in plan['rules'] if r['snat']['type']=='masquerade')
    for logical in used:
        if logical not in mapping or mapping[logical] not in links:raise NatError('Uncommissioned or missing interface: '+logical)
        link=links[mapping[logical]]
        if link.get('master') or link.get('linkinfo',{}).get('info_kind') in ('bridge','vrf'):raise NatError('NAT provider currently requires routed interfaces in the main routing table')
        if not any(a['family']=='inet' for a in link.get('addr_info',[])):raise NatError('No active IPv4 address on '+logical)
    lines=['table ip '+TABLE+' {',' comment "ffn-nat:'+digest(plan)+'"',' chain prerouting { type nat hook prerouting priority dstnat; policy accept;','  ct direction reply return','  ct mark != 0 return']
    chains=[];post=[]
    for i,r in enumerate(plan['rules']):
        mark=MARK+revision*1024+i;chain='r'+str(i)
        incoming=[mapping[n] for n in r['ingress']];outgoing=[mapping[n] for n in r['egress']]
        conditions=['fib daddr oifname '+elements(outgoing,True)]
        local=sorted({a['local'] for p in outgoing for a in links[p].get('addr_info',[]) if a['family']=='inet'})
        if local:conditions.append('ip daddr '+elements(local))
        for service in r['services']:
            match='iifname '+elements(incoming,True)+' ip saddr '+elements(r['source'])+' ip daddr '+elements(r['destination'])
            if service['protocol']!='any':
                proto=service['protocol'];match+=' meta l4proto '+proto
                for key,token in [('source_ports','sport'),('destination_ports','dport')]:
                    if service[key]:match+=' '+proto+' '+token+' '+elements(service[key])
            for condition in conditions:lines.append('  '+match+' '+condition+' goto '+chain)
        action='accept'
        if r['dnat']:
            dnat=r['dnat']
            if dnat.get('type')=='dynamic':
                count=len(dnat['addresses'])
                selector='numgen inc mod '+str(count)
                if dnat['method']!='round-robin':
                    fields='ip saddr' if dnat['method']=='source-ip-hash' else 'ip saddr . ip daddr'
                    # Stable per-rule seed avoids reshuffling new flows after replay.
                    seed='0x'+digest({'scope':r['scope'],'name':r['name']})[:8]
                    selector='jhash '+fields+' mod '+str(count)+' seed '+seed
                targets=' map { '+', '.join(str(n)+' : '+address for n,address in enumerate(dnat['addresses']))+' }'
                action='dnat ip to '+selector+targets
            else:action='dnat to '+dnat['address']
            if 'port' in r['dnat']:
                action='; '.join('meta l4proto '+proto+' '+action+':'+str(r['dnat']['port']) for proto in sorted({s['protocol'] for s in r['services']}))+'; drop'
        chains.append(' chain '+chain+' { counter comment '+json.dumps('NAT '+r['scope']+'/'+r['name'])+'; ct mark set '+str(mark)+'; '+action+'; }')
        snat=r['snat'];prefix='  ct mark '+str(mark)
        if snat['type']=='masquerade':
            dev=mapping[snat['interface']]
            post.append(prefix+' oifname '+json.dumps(dev)+' masquerade')
            post.append(prefix+' drop') # Never leak an untranslated source after an unexpected route change.
        elif snat['type']=='static':post.append(prefix+' snat ip to ip saddr map { '+str(ipaddress.ip_network(r['source'][0]).network_address)+' : '+snat['address']+' }')
        elif snat['type']=='snat':post.append(prefix+' snat to '+snat['address'])
        else:post.append(prefix+' accept')
    lines+=[' }',*chains,' chain postrouting { type nat hook postrouting priority srcnat; policy accept;',*post,'  ct mark & 0xff000000 == 0xf1000000 drop',' }','}']
    return '\n'.join(lines)+'\n'


def inspect():
    data=json.loads(nft(['-j','list','ruleset']))
    table=None
    for item in data['nftables']:
        t=item.get('table',{})
        if t.get('name')==TABLE and t.get('family')=='ip':table=t
        chain=item.get('chain',{})
        if chain.get('table')!=TABLE and chain.get('type')=='nat':raise NatError('Another NAT owner exists in the data namespace')
        rule=item.get('rule',{})
        def connection_mark(value):
            if isinstance(value,dict):
                return value.get('ct',{}).get('key')=='mark' or any(connection_mark(v) for v in value.values())
            return isinstance(value,list) and any(connection_mark(v) for v in value)
        if rule.get('table')!=TABLE and connection_mark(rule):raise NatError('Another rule owns connection marks in the data namespace')
    return table,data


def kernel_digest(data):
    def clean(value):
        if isinstance(value,dict):return {k:clean(v) for k,v in value.items() if k not in ('handle','packets','bytes','index')}
        if isinstance(value,list):return [clean(v) for v in value]
        return value
    rows=[x for x in data['nftables'] if any(isinstance(v,dict) and (v.get('table')==TABLE or k=='table' and v.get('name')==TABLE) for k,v in x.items())]
    return hashlib.sha256(json.dumps(clean(rows),sort_keys=True,separators=(',',':')).encode()).hexdigest()


def status():
    from ffn_kernel_capabilities import inspect as inspect_kernel
    kernel=inspect_kernel()
    distribution={}
    for method in ('round-robin','source-ip-hash','ip-hash','ip-modulo','least-sessions'):
        feature='nat-round-robin' if method=='round-robin' else 'nat-address-hash'
        supported=method in ('round-robin','source-ip-hash','ip-hash') and kernel['features'][feature]['compiled'] is True
        distribution[method]=dict(supported=supported,reason='Commit validates the current dataplane' if supported else
            'Dataplane allocator is not implemented' if method in ('ip-modulo','least-sessions') else 'Required kernel feature is unavailable or unverified')
    state=saved();result={'revision':state['revision'],'digest':state['digest'],'available':False,'applied':False,'provider':'linux-nftables','byteorder':sys.byteorder,'machine':os.uname().machine,'rules':[],
        'capabilities':{'destination_distribution':distribution,'persistent_source_binding':False,
                        'translation_types':translation_capabilities()},'kernel':kernel}
    try:
        mapping=bindings();table,data=inspect()
        result.update(available=True,interfaces=mapping,applied=bool(table and table.get('comment')=='ffn-nat:'+str(state['digest']) and state.get('kernel_digest')==kernel_digest(data)))
        result['rules']=[x['rule'] for x in data['nftables'] if x.get('rule',{}).get('table')==TABLE and x['rule'].get('chain','').startswith('r')]
        result['usage']=rule_usage(state,data,result['applied'])
    except (NatError,OSError,ValueError) as error:result['error']=str(error)
    return result


def rule_usage(state,data,applied):
    """NAT chain counters count initial connection packets, not session traffic."""
    usage=[]
    for index,rule in enumerate(state.get('plan',{}).get('rules',[])):
        counters=[expr['counter'] for item in data.get('nftables',[]) for row in [item.get('rule',{})]
                  if row.get('family')=='ip' and row.get('table')==TABLE and row.get('chain')=='r'+str(index)
                  for expr in row.get('expr',[]) if isinstance(expr.get('counter'),dict)]
        available=applied and len(counters)==1 and all(type(counters[0].get(k)) is int and counters[0][k]>=0 for k in ('packets','bytes'))
        usage.append(dict(scope=rule['scope'],name=rule['name'],available=available,
                          packets=counters[0]['packets'] if available else None,
                          bytes=counters[0]['bytes'] if available else None,
                          generation=state['revision'],source='nftables NAT initial-packet counters'))
    return usage


def prepare(request,allow_restore=False):
    if not isinstance(request,dict) or set(request)!={'revision','plan'}:raise NatError('NAT request requires revision and plan')
    validate_plan(request['plan'])
    require_translation_provider(request['plan'])
    dynamic=[r['dnat'] for r in request['plan']['rules'] if r['dnat'] and r['dnat'].get('type')=='dynamic']
    if dynamic:
        from ffn_kernel_capabilities import inspect as inspect_kernel
        features=inspect_kernel()['features']
        for translation in dynamic:
            name='nat-round-robin' if translation['method']=='round-robin' else 'nat-address-hash'
            if features[name]['compiled'] is False:
                raise NatError('Running dataplane kernel lacks '+name+' support; a matching kernel/module build and packet validation are required')
    state=saved()
    if type(request['revision']) is not int or request['revision']!=state['revision']:raise NatError('NAT revision changed; refresh before retrying')
    table,data=inspect()
    if table and not state['script']:raise NatError('Unmanaged NAT table; explicit reconciliation required')
    if state['script'] and not (allow_restore and not table) and (not table or table.get('comment')!='ffn-nat:'+state['digest'] or state.get('kernel_digest')!=kernel_digest(data)):raise NatError('NAT table drift; explicit reconciliation required')
    links={x['ifname']:x for x in json.loads(run(['ip','-n',NS,'-j','address']))}
    if request['plan'].get('rules'):
        policies=json.loads(run(['ip','-n',NS,'-4','-j','rule','show']))
        # Linux retains its automatic l3mdev rule after the last VRF is removed.
        # It has no effect without a VRF; do not mistake that residue for PBR.
        if not json.loads(run(['ip','-n',NS,'-d','-j','link','show','type','vrf'])):
            policies=[p for p in policies if not ('l3mdev' in p and p.get('priority')==1000
                       and p.get('src','all')=='all' and not {'iif','fwmark','table'} & set(p))]
        if any(p.get('table') not in ('local','main','default',253,254,255) or p.get('src','all')!='all' or 'iif' in p or 'fwmark' in p for p in policies):raise NatError('NAT destination-zone lookup does not yet support policy routing or VRFs')
        if any(r.get('nexthops') for r in json.loads(run(['ip','-n',NS,'-4','-j','route','show','table','main']))):raise NatError('NAT destination-zone lookup does not yet support ECMP')
    script=render(request['plan'],bindings(),links,state['revision']+1)
    batch=('delete table ip '+TABLE+'\n' if table else '')+script
    nft(['-c','-f','-'],batch)
    return state,script,batch


def write_state(state):
    STATE.parent.mkdir(parents=True,exist_ok=True);temp=STATE.with_suffix('.tmp')
    with temp.open('w') as f:json.dump(state,f);f.flush();os.fsync(f.fileno())
    os.chmod(temp,0o600);temp.replace(STATE)


def apply(request):
    if COORDINATED.exists():raise NatError('Security owns coordinated NAT activation; use the policy Commit path')
    old,script,batch=prepare(request)
    if digest(request['plan'])==old['digest']:return dict(revision=old['revision'],digest=old['digest'],applied=True,unchanged=True)
    nft(['-f','-'],batch)
    try:
        state={'revision':old['revision']+1,'digest':digest(request['plan']),'plan':request['plan'],'script':script}
        table,data=inspect()
        if not table or table.get('comment')!='ffn-nat:'+state['digest']:raise NatError('NAT readback did not confirm application')
        state['kernel_digest']=kernel_digest(data)
        write_state(state)
    except BaseException as error:
        rollback='delete table ip '+TABLE+'\n'+(old['script'] or '')
        try:nft(['-f','-'],rollback)
        except Exception as failed:raise RuntimeError('NAT apply failed and rollback is unconfirmed: '+str(failed)) from error
        raise
    return dict(revision=state['revision'],digest=state['digest'],applied=True)


def restore():
    """Boot replay after the platform restores its isolated network namespace."""
    if COORDINATED.exists():return {'restored':False,'reason':'Security supervisor owns coordinated policy replay'}
    state=saved()
    if not state['script']:return {'restored':False,'reason':'No saved NAT configuration'}
    table,data=inspect()
    if table:
        if state.get('kernel_digest')!=kernel_digest(data):raise NatError('Existing NAT table differs; refusing boot replay')
        return {'restored':True,'unchanged':True}
    links={x['ifname']:x for x in json.loads(run(['ip','-n',NS,'-j','address']))}
    script=render(state['plan'],bindings(),links,state['revision'])
    nft(['-c','-f','-'],script);nft(['-f','-'],script)
    try:
        _,data=inspect();state.update(script=script,kernel_digest=kernel_digest(data));write_state(state)
    except BaseException:
        nft(['delete','table','ip',TABLE]);raise
    return {'restored':True,'revision':state['revision'],'digest':state['digest']}


def main():
    import fcntl
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('action',choices=['status','validate','apply','restore']);args=p.parse_args()
    with LOCK.open('w') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        if args.action=='status':result=status()
        elif args.action=='restore':result=restore()
        else:
            raw=sys.stdin.buffer.read(65537)
            if len(raw)>65536:raise NatError('NAT request exceeds 64 KiB')
            request=json.loads(raw)
            if args.action=='apply':result=apply(request)
            else:
                state,script,_=prepare(request)
                result={'validated':True,'revision':state['revision'],'digest':digest(request['plan']),'script':script,'applied':False}
        print(json.dumps(result))


if __name__=='__main__':
    try:main()
    except (NatError,ValueError,OSError) as error:print(json.dumps({'error':str(error)}));raise SystemExit(2)
