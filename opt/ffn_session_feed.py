#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Read-only bounded session observations for platform offload planning.

An observation is not an admission authorization or an event subscription.
It never changes the forwarding lease, conntracks, hardware or configuration.
"""
import hashlib
import contextlib
import json
import os
from pathlib import Path
import sqlite3
import sys
import time
import uuid

import ffn_security_runtime as runtime
from ffn_nat_policy import Resolver
from ffn_policy_config import owners,parse
from ffn_policy_plan import compile_policy
from ffn_session_events import subscribe,snapshot,EventError

LIMIT=128


def catalog(state):
    root=parse(state['xml']);rules={}
    tokens,metadata=runtime.tokens_for(state['xml'],state['token_generation'])
    for scope,owner in owners(root).items():
        resolver=Resolver(root,owner)
        zones={z.get('name'):resolver.interfaces([z.get('name')]) for z in owner.findall('zone/entry')
               if z.findall('network/layer3/member')}
        compiled=compile_policy(state['xml'],'security',scope)
        if not compiled['valid']:raise ValueError('Current Security plan is not valid')
        for rule in compiled['plan']['rules']:
            token=tokens.get((scope,rule['name']))
            if token is None:continue
            match=rule['match'];pairs=set()
            for source,incoming in zones.items():
                if match['from']!=['any'] and source not in match['from']:continue
                for destination,outgoing in zones.items():
                    if match['to']!=['any'] and destination not in match['to']:continue
                    if match['rule-type']=='intrazone' and source!=destination:continue
                    if match['rule-type']=='interzone' and source==destination:continue
                    pairs.update((a,b) for a in incoming for b in outgoing)
            rules[token]=dict(metadata[token],interface_pairs=[list(pair) for pair in sorted(pairs)],
                             inspection_required=rule['action']['profiles']['mode']!='none')
    return rules,metadata


def assess(row,rules,boot):
    reasons=[];rule=rules.get(row['token']);proto=row['original']['protocol']
    flags=row.get('status');flags=flags if type(flags) is int else 0
    if rule is None:reasons.append('grant-not-in-current-explicit-policy')
    if proto not in (6,17) or row['reply']['protocol']!=proto:reasons.append('unsupported-protocol')
    if flags & 14 != 14:reasons.append('session-not-confirmed-assured-and-replied')
    if flags & (512|2048|4096|16384|32768):reasons.append('dying-template-or-already-offloaded-session')
    if proto==6 and row.get('tcp_state')!=3:reasons.append('tcp-not-established')
    if type(row.get('timeout')) is not int or row['timeout']<=0:reasons.append('session-expiry-unavailable')
    if row.get('zone',0)!=0:reasons.append('nondefault-conntrack-zone')
    pairs=rule['interface_pairs'] if rule else []
    if len(pairs)!=1:reasons.append('interface-pair-ambiguous')
    if rule and rule['inspection_required']:reasons.append('inspection-required')
    fields={'source','destination','source_port','destination_port','protocol'}
    complete=all(set(row[direction])==fields for direction in ('original','reply'))
    if not complete:reasons.append('incomplete-transport-tuple')
    translated=None;nat=None
    if complete:
        original,reply=row['original'],row['reply']
        translated=dict(source=reply['destination'],destination=reply['source'],
                        source_port=reply['destination_port'],destination_port=reply['source_port'],protocol=proto)
        nat=dict(source=any(original[k]!=translated[k] for k in ('source','source_port')),
                 destination=any(original[k]!=translated[k] for k in ('destination','destination_port')))
    identity=hashlib.sha256(json.dumps([boot,row.get('zone',0),row['id'],row['original']],sort_keys=True).encode()).hexdigest()
    return dict(identity=identity,conntrack_id=row['id'],token=row['token'],rule=rule,
                original=row['original'],reply=row['reply'],translated=translated,nat=nat,
                counters=row['counters'],remaining_seconds=row.get('timeout'),tcp_state=row.get('tcp_state'),
                software_candidate=not reasons,blockers=reasons)


def acknowledgement(value,state):
    if (value.get('available') is not True or value.get('applied') is not True or
        value.get('revision')!=state['revision'] or value.get('digest')!=state['digest'] or
        value.get('nat',{}).get('acknowledged') is not True or
        value.get('nat',{}).get('digest')!=state['nat']['digest']):
        raise ValueError('Current Security/NAT acknowledgement is required')
    health=value['collector']
    return {key:health[key] for key in ('boot_id','pid','process_start')} | {
        'reconciliations':health.get('events',{}).get('recoveries')}


def observe(nonce):
    if not isinstance(nonce,str) or str(uuid.UUID(nonce))!=nonce:raise ValueError('Canonical request nonce required')
    if os.stat('/proc/self/ns/net').st_ino!=os.stat('/run/netns/'+runtime.nat.NS).st_ino:
        raise ValueError('Session feed must run inside the data namespace')
    start=time.monotonic();before=runtime.status();state=runtime.saved()
    if not state:raise ValueError('No applied policy generation')
    producer=acknowledgement(before,state)
    rules,expected=catalog(state)
    dbpath=runtime.DATABASE
    st=dbpath.stat()
    if st.st_uid!=0 or st.st_mode&0o022:raise ValueError('Untrusted session journal')
    with contextlib.closing(sqlite3.connect(dbpath.as_uri()+'?mode=ro',uri=True,timeout=1)) as db:
        db.execute('BEGIN')
        fault=db.execute('SELECT fault FROM health WHERE id=1').fetchone()
        if fault and fault[0]:raise ValueError('Session journal fault is active')
        persisted={token:json.loads(raw) for token,raw in db.execute('SELECT token,metadata FROM rules')}
        if any(persisted.get(token)!=metadata for token,metadata in expected.items()):
            raise ValueError('Durable rule generation does not match applied policy')
    with subscribe() as stream:
        rows,changes=snapshot(stream,timeout=2,capacity=8192)
    # Kernel dumps race with multicast updates. Replay removals/admissions;
    # this is a bounded observation, never a promise that a session stays live.
    def key(row):return (row.get('zone',0),row['id'],json.dumps(row['original'],sort_keys=True))
    live={key(row):row for row in rows if row['token'] is not None}
    for row in changes:
        ident=key(row)
        if row['event']=='end':live.pop(ident,None)
        elif row['token'] is not None:live[ident]=row
        else:live.pop(ident,None)
    after=runtime.status()
    if runtime.saved()!=state or acknowledgement(after,state)!=producer:
        raise ValueError('Policy, bindings or session producer changed during observation')
    completed=time.monotonic()
    if completed-start>8:raise ValueError('Session observation exceeded its freshness budget')
    owned=sorted(live.values(),key=lambda row:(row['id'],json.dumps(row['original'],sort_keys=True)))
    return dict(schema=1,nonce=nonce,available=True,source='kernel-conntrack-with-durable-security-grants',
                producer=producer,policy=dict(revision=state['revision'],digest=state['digest'],
                nat_digest=state['nat']['digest'],bindings=state['bindings']),
                observed_monotonic=start,completed_monotonic=completed,owned_sessions=len(owned),
                truncated=len(owned)>LIMIT,hardware_admission=False,
                sessions=[assess(row,rules,producer['boot_id']) for row in owned[:LIMIT]])


if __name__=='__main__':
    try:
        raw=sys.stdin.buffer.read(4097)
        if len(raw)>4096:raise ValueError('Session feed request too large')
        request=json.loads(raw)
        if set(request)!={'nonce'}:raise ValueError('Session feed accepts only a nonce')
        print(json.dumps(observe(request['nonce'])))
    except (ValueError,OSError,RuntimeError,KeyError,sqlite3.Error,EventError) as error:
        print(json.dumps(dict(available=False,hardware_admission=False,error=str(error)[:512])))
        raise SystemExit(2)
