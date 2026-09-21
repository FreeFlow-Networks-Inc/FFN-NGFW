#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Coordinated IPv4 Security/NAT provider for an isolated data namespace.

A short kernel lease gates all transit. The session collector renews it only
while the stored generation, interface owners and nftables readback agree.
Management INPUT/OUTPUT and platform LACP owners are not changed.
"""
import argparse
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import select
import signal
import sys
import time

import ffn_nat_runtime as nat
from ffn_nat_policy import NatError, compile_policy, digest
from ffn_policy_config import owners, parse
from ffn_policy_plan import compile_policy as security_plan
from ffn_security_nft import render
from ffn_session_events import Journal, EventError, subscribe, receive

STATE=Path('/etc/ffn/policy-runtime.json')
HEALTH=Path('/run/ffn-security-health.json')
DATABASE=Path('/var/lib/ffn/security-sessions.db')
GATE='ffn_policy_gate'
LEASE_SECONDS=8


def atomic(path, value):
    path.parent.mkdir(parents=True,exist_ok=True)
    temp=path.with_name(path.name+'.'+str(os.getpid())+'.tmp')
    with temp.open('w') as f:
        os.chmod(temp,0o600);json.dump(value,f);f.flush();os.fsync(f.fileno())
    temp.replace(path)
    fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(fd)
    finally:os.close(fd)


def boot():return Path('/proc/sys/kernel/random/boot_id').read_text().strip()


def saved():
    return json.loads(STATE.read_text()) if STATE.exists() else None


@contextlib.contextmanager
def lock():
    with nat.LOCK.open('a') as f:
        fcntl.flock(f,fcntl.LOCK_EX)
        yield


def gate():
    return ('table inet '+GATE+' {\n'
            ' set live { type nf_proto; flags timeout; timeout '+str(LEASE_SECONDS)+'s; }\n'
            ' chain forward { type filter hook forward priority -270; policy drop;\n'
            '  meta mark set meta mark & 0x7fffffff\n'
            '  meta nfproto @live accept\n }\n}\n')


def close_gate():
    data=json.loads(nat.nft(['-j','list','ruleset']))
    if any(x.get('table',{}).get('name')==GATE and x['table']['family']=='inet' for x in data['nftables']):
        nat.nft(['flush','set','inet',GATE,'live'])
    else:nat.nft(['-f','-'],gate())


def renew():
    nat.nft(['-f','-'],'flush set inet '+GATE+' live\nadd element inet '+GATE+' live { ipv4 timeout '+str(LEASE_SECONDS)+'s }\n')


def health():
    try:
        st=HEALTH.stat()
        if st.st_uid!=0 or st.st_mode&0o022:raise NatError('Untrusted Security collector health')
        data=json.loads(HEALTH.read_text())
        process=Path('/proc/'+str(data['pid'])+'/stat').read_text().rsplit(') ',1)[1].split()
        if (data['boot_id']!=boot() or not 0<=time.monotonic()-data['monotonic']<=5 or
                process[19]!=data['process_start'] or process[0]=='Z' or not data['collector_ready']):
            raise NatError('Security session collector is not healthy')
        return data
    except (OSError,KeyError,ValueError,IndexError) as error:
        raise NatError('Security session collector unavailable: '+str(error)) from error


def bindings():
    mapping=nat.bindings()
    links={r['ifname']:r for r in json.loads(nat.run(['ip','-n',nat.NS,'-d','-j','link']))}
    current={}
    for logical,dev in mapping.items():
        row=links.get(dev)
        if row and not row.get('master'):
            current[logical]=dict(device=dev,index=row['ifindex'],alias=row.get('ifalias',''))
    return current,links


def fingerprint(data, tables):
    def clean(value):
        if isinstance(value,dict):return {k:clean(v) for k,v in value.items() if k not in ('handle','packets','bytes','index','expires')}
        if isinstance(value,list):return [clean(v) for v in value]
        return value
    rows=[]
    for item in data['nftables']:
        for kind,row in item.items():
            if not isinstance(row,dict):continue
            key=(row.get('family'),row.get('name') if kind=='table' else row.get('table'))
            if key not in tables:continue
            # Lease element contents change every heartbeat, never the gate.
            if kind=='element' and key==('inet',GATE):continue
            value=clean(row)
            if kind=='set' and key==('inet',GATE):value.pop('elem',None)
            rows.append({kind:value})
    return digest(rows)


def inventory():return json.loads(nat.nft(['-j','list','ruleset']))


def table_names(data):
    return {(x['table']['family'],x['table']['name']) for x in data['nftables'] if 'table' in x}


def guard_scripts(links):
    if nat.PLATFORM_BINDINGS.exists():
        try:from ffn_platform_policy_bindings import security_guards
        except ImportError as error:raise NatError('Platform has no commissioned Security guard integration') from error
        return security_guards(links)
    return {}


def ownership(data, guards):
    allowed={'ffn_security',GATE,nat.TABLE,*guards}
    for item in data['nftables']:
        if 'flowtable' in item:raise NatError('A flowtable could bypass Security enforcement')
        row=item.get('chain',{})
        if row.get('hook')=='forward' and row.get('table') not in allowed:
            raise NatError('Another forwarding policy owner exists: '+str(row.get('table')))
        row=item.get('rule',{})
        if row.get('table') not in allowed and any('"'+word+'"' in json.dumps(row) for word in ('label','mark','flow')):
            raise NatError('Another rule owns Security marks or acceleration')


def tokens_for(xml, revision):
    metadata={};tokens={};counter=0
    for scope in owners(parse(xml)):
        report=security_plan(xml,'security',scope)
        if not report['valid']:raise NatError(str(report['blockers']))
        for rule in report['plan']['rules']:
            if rule['action']['type']!='allow':continue
            counter+=1;token=revision*2048+counter
            tokens[(scope,rule['name'])]=token
            metadata[token]=dict(scope=scope,name=rule['name'],revision=revision,logging=rule['action']['logging'])
    if counter>=2047 or not 1<=revision<524287:raise NatError('Security generation capacity exhausted')
    token=revision*2048+2047;tokens[('implicit','intrazone-default')]=token
    metadata[token]=dict(scope='implicit',name='intrazone-default',revision=revision,logging=dict(start=False,end=False))
    return tokens,metadata


def prepare(request, replay=False):
    if not isinstance(request,dict) or set(request)!={'revision','xml'} or not isinstance(request['xml'],str):
        raise NatError('Security request requires revision and policy XML')
    old=saved();revision=old['revision'] if old else 0
    if type(request['revision']) is not int or request['revision']!=revision:raise NatError('Security revision changed; refresh before retrying')
    health()
    current,links=bindings();data=inventory();guards=guard_scripts(links);ownership(data,guards)
    compiled=compile_policy(request['xml'])
    if not compiled['valid']:raise NatError(str(compiled['blockers']))
    old_nat,_,_=nat.prepare(dict(revision=nat.saved()['revision'],plan=compiled['plan']),allow_restore=replay)
    same=bool(old and old['xml']==request['xml'])
    generation=revision if same else revision+1
    if same:token_generation=old['token_generation']
    else:
        j=Journal(DATABASE,boot())
        try:token_generation=(j.db.execute('SELECT coalesce(max(token),0) FROM rules').fetchone()[0]//2048)+1
        finally:j.close()
    tokens,metadata=tokens_for(request['xml'],token_generation)
    security=render(request['xml'],{k:v['index'] for k,v in current.items()},tokens)
    nat_revision=old_nat['revision'] if old_nat['digest']==digest(compiled['plan']) else old_nat['revision']+1
    addresses={r['ifname']:r for r in json.loads(nat.run(['ip','-n',nat.NS,'-j','address']))}
    nat_script=nat.render(compiled['plan'],{k:v['device'] for k,v in current.items()},addresses,nat_revision)
    scripts={('inet',GATE):gate(),('inet','ffn_security'):security['script'],('ip',nat.TABLE):nat_script}
    scripts.update({('inet',name):script for name,script in guards.items()})
    names=table_names(data)
    if not old and ('inet','ffn_security') in names:raise NatError('Unmanaged Security table requires reconciliation')
    if old and not replay and fingerprint(data,{tuple(k) for k in old['tables']})!=old['kernel_digest']:
        raise NatError('Security table drift; transit is held closed')
    batch=''.join(('delete table '+family+' '+name+'\n' if (family,name) in names else '')+script
                  for (family,name),script in scripts.items())
    nat.nft(['-c','-f','-'],batch)
    state=dict(version=1,revision=generation,token_generation=token_generation,xml=request['xml'],digest=security['digest'],
               bindings=current,tables=list(scripts),scripts=[(list(key),value) for key,value in scripts.items()],
               boot_id=boot(),nat=dict(revision=nat_revision,plan=compiled['plan'],digest=digest(compiled['plan']),script=nat_script))
    return old,state,batch,metadata


def apply(request,replay=False):
    old,state,batch,metadata=prepare(request,replay)
    if (old and not replay and old['xml']==state['xml'] and old['bindings']==state['bindings'] and
            old['boot_id']==boot()):
        return dict(applied=True,unchanged=True,revision=old['revision'],digest=old['digest'],forwarding='awaiting-supervisor-lease')
    # The durable metadata precedes the kernel generation. A failed attempt may
    # leave unused metadata, which is harmless; token reuse is rejected.
    j=Journal(DATABASE,boot())
    try:
        if j.fault_reason():raise NatError(j.fault_reason())
        j.register(metadata)
    finally:j.close()
    before=inventory();present=table_names(before)
    durable_before=STATE.read_bytes() if STATE.exists() else None
    rollback_scripts={}
    for family,name in (tuple(t) for t in state['tables']):
        if (family,name)==('inet',GATE):rollback_scripts[(family,name)]=gate()
        elif (family,name) in present:rollback_scripts[(family,name)]=nat.nft(['list','table',family,name])
    close_gate()
    try:
        nat.nft(['-f','-'],batch)
        data=inventory()
        required={tuple(t) for t in state['tables']}
        if not required<=table_names(data):raise NatError('Coordinated policy readback is incomplete')
        state['kernel_digest']=fingerprint(data,required)
        state['nat']['kernel_digest']=nat.kernel_digest(data)
        after,_=bindings()
        if after!=state['bindings']:raise NatError('Interface ownership changed during Security apply')
        atomic(STATE,state)
    except BaseException as error:
        close_gate()
        try:
            present=table_names(inventory())
            rollback=''.join('delete table '+family+' '+name+'\n' for family,name in
                (tuple(t) for t in state['tables']) if (family,name) in present)
            rollback+=''.join(rollback_scripts.values())
            nat.nft(['-f','-'],rollback)
            durable_after=STATE.read_bytes() if STATE.exists() else None
            if durable_after!=durable_before:
                if old is not None:atomic(STATE,old)
                elif STATE.exists():STATE.unlink()
            # The previous policy returns with a CLOSED lease. Only the
            # supervisor can admit traffic after revalidating its owners.
        except Exception as failed:
            journal=Journal(DATABASE,boot())
            try:journal.fault('Policy rollback unconfirmed: '+str(failed))
            finally:journal.close()
            raise NatError('Policy apply failed; rollback unconfirmed: '+str(failed)) from error
        raise
    return dict(applied=True,revision=state['revision'],digest=state['digest'],forwarding='awaiting-supervisor-lease')


def status():
    state=saved();result=dict(available=False,applied=False,revision=state['revision'] if state else 0,provider='linux-stateful-nftables')
    try:
        result['collector']=health();result['available']=True
        if state:
            data=inventory();current,_=bindings()
            result.update(digest=state['digest'],applied=state['boot_id']==boot() and current==state['bindings'] and
                fingerprint(data,{tuple(k) for k in state['tables']})==state['kernel_digest'] and
                result['collector'].get('forwarding_revision')==state['revision'])
    except (NatError,OSError,ValueError) as error:result['error']=str(error)
    return result


def serve():
    # Enter via `ip netns exec`: subscription belongs to the data namespace.
    if os.stat('/proc/self/ns/net').st_ino!=os.stat('/run/netns/'+nat.NS).st_ino:
        raise NatError('Security collector must run in the isolated data namespace')
    DATABASE.parent.mkdir(parents=True,exist_ok=True)
    os.umask(0o077)
    stream=subscribe();j=Journal(DATABASE,boot())
    j.recover_boot()
    # A crash with active records cannot be reported as successful session end.
    # Preserve the evidence and hold admission for explicit reconciliation.
    if j.db.execute('SELECT count(*) FROM sessions').fetchone()[0]:
        j.fault('Collector restarted with active sessions; event-gap reconciliation is required')
    start=Path('/proc/self/stat').read_text().rsplit(') ',1)[1].split()[19]
    running=True
    def stop(*_):
        nonlocal running
        running=False
    signal.signal(signal.SIGTERM,stop);signal.signal(signal.SIGINT,stop)
    def publish(ready,revision=None,error=None):
        atomic(HEALTH,dict(pid=os.getpid(),process_start=start,boot_id=boot(),monotonic=time.monotonic(),
            collector_ready=ready,forwarding_revision=revision,error=error))
    next_check=0;last_forwarding=None;last_error=None
    try:
        with lock():close_gate()
        for key in ('nf_conntrack_acct','nf_conntrack_events'):
            nat.run(['sysctl','-qw','net.netfilter.'+key+'=1'])
        while running:
            if select.select([stream],[],[],max(0,min(0.25,next_check-time.monotonic())))[0]:
                for event in receive(stream):j.record(event)
            if time.monotonic()<next_check:continue
            next_check=time.monotonic()+1
            fault=j.fault_reason()
            if fault:
                with lock():close_gate()
                publish(False,error=fault);continue
            publish(True,last_forwarding,last_error)
            try:
                with lock():
                    state=saved()
                    if not state:continue
                    current,_=bindings();data=inventory()
                    if (state['boot_id']!=boot() or current!=state['bindings'] or
                            fingerprint(data,{tuple(k) for k in state['tables']})!=state['kernel_digest']):
                        close_gate()
                        # Replay only after the compiler and platform have
                        # validated every current owner; never reset LACP.
                        apply(dict(revision=state['revision'],xml=state['xml']),replay=True)
                        state=saved()
                    renew();last_forwarding=state['revision'];last_error=None;publish(True,last_forwarding)
            except (NatError,OSError,ValueError) as error:
                with lock():close_gate()
                last_forwarding=None;last_error=str(error);publish(True,error=last_error)
    except BaseException as error:
        j.fault(str(error));publish(False,error=str(error));raise
    finally:
        try:
            with lock():close_gate()
            publish(False,error='Collector stopped')
        finally:stream.close();j.close()


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('action',choices=('status','validate','apply','serve'));a=p.parse_args()
    if a.action=='serve':serve();return
    with lock():
        if a.action=='status':result=status()
        else:
            raw=sys.stdin.buffer.read(262145)
            if len(raw)>262144:raise NatError('Security request exceeds 256 KiB')
            request=json.loads(raw)
            if a.action=='apply':result=apply(request)
            else:
                _,state,_,_=prepare(request)
                result=dict(validated=True,applied=False,digest=state['digest'],revision=request['revision'])
        print(json.dumps(result))


if __name__=='__main__':
    try:main()
    except (NatError,EventError,OSError,ValueError) as error:
        print(json.dumps(dict(error=str(error))));raise SystemExit(2)
