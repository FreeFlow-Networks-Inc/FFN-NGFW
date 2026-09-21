# SPDX-License-Identifier: GPL-2.0-or-later
"""NAT compilation and activation through the MP control daemon and DP worker."""
import json
import os
from pathlib import Path
import uuid
from ffn_nat_policy import compile_policy,NatError

PROVIDER=Path('/etc/ffn/nat-provider.json')


def commissioned():
    if not PROVIDER.exists():return False
    st=PROVIDER.stat()
    if st.st_uid!=0 or st.st_mode & 0o022:raise NatError('NAT provider selection must be root-owned')
    cfg=json.loads(PROVIDER.read_text())
    return cfg=={'provider':'linux-nftables','commit':True}


def control_call(command,**args):
    from ffn_controld_client import ControldClient
    return ControldClient(timeout=60).query(command,**args)


def preflight(xml):
    report=compile_policy(xml)
    if not report['valid']:raise NatError('; '.join(x['name']+': '+x['reason'] for x in report['blockers']))
    if not commissioned():raise NatError('NAT runtime provider is not commissioned for Commit')
    response=control_call('nat/validate',plan=report['plan'])
    if not response.get('validated'):raise NatError(response.get('error','Dataplane did not validate NAT'))
    return response


def reconcile(path,status):
    """Configd hook. Apply only running XML; disabled/removal yields an empty plan."""
    from ffn_security_control import commissioned as security_commissioned, reconcile as reconcile_security
    if security_commissioned():return reconcile_security(path,status)
    if not commissioned():return
    try:
        report=compile_policy(Path(path).read_bytes())
        if not report['valid']:raise NatError(str(report['blockers']))
        result=control_call('nat/apply',plan=report['plan'])
        if not result.get('applied'):raise NatError(result.get('error','NAT application unconfirmed'))
        status.ok('rulebase/nat',None,result['digest'],'nat',json.dumps({'revision':result['revision'],'digest':result['digest']}))
    except Exception as error:status.fail('rulebase/nat','nat',str(error))


class NatGateway:
    def __init__(self,planes,directory):self.planes,self.directory=planes,Path(directory)

    async def worker(self,action,payload,resource='nat'):
        request={'v':1,'id':str(uuid.uuid4()),'resource':resource,'action':action,'payload':payload}
        response=await self.planes.request({'request':request})
        if not response.get('ok'):raise NatError(response.get('error','NAT worker unavailable')+'; request '+request['id'])
        result=response['result'];result['control']={'request_id':request['id'],'trace':response.get('trace',[]),'state':response.get('state')}
        return result

    async def tools(self,args):
        if args:raise NatError('Tool inventory takes no arguments')
        return await self.worker('status',{},'dataplane-tools')

    async def preview(self,args):
        if set(args)-{'source'} or args.get('source','candidate') not in ('candidate','running'):raise NatError('Invalid NAT preview source')
        report=compile_policy((self.directory/(args.get('source','candidate')+'-config.xml')).read_bytes())
        report['commissioned']=commissioned()
        try:report['runtime']=await self.worker('status',{})
        except Exception as error:report['runtime']={'available':False,'applied':False,'error':str(error)}
        return report

    async def validate(self,args):
        if set(args)!={'plan'}:raise NatError('One NAT plan required')
        state=await self.worker('status',{})
        if not state.get('available'):raise NatError(state.get('error','NAT dataplane unavailable'))
        return await self.worker('validate',{'revision':state['revision'],'plan':args['plan']})

    async def apply(self,args):
        if not commissioned():raise NatError('NAT runtime provider is not commissioned for Commit')
        # A caller cannot use this path to bypass candidate/Commit.
        report=compile_policy((self.directory/'running-config.xml').read_bytes())
        if not report['valid'] or args!={'plan':report['plan']}:raise NatError('NAT apply must match committed running configuration')
        state=await self.worker('status',{})
        if not state.get('available'):raise NatError(state.get('error','NAT dataplane unavailable'))
        return await self.worker('apply',{'revision':state['revision'],'plan':report['plan']})
