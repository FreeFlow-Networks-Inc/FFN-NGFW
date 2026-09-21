# SPDX-License-Identifier: GPL-2.0-or-later
"""Shared CLI/WebUI Commit boundary for coordinated Security and NAT."""
import copy
import json
from pathlib import Path
from xml.etree import ElementTree as ET
from ffn_nat_policy import NatError
from ffn_policy_config import parse
from ffn_nat_control import NatGateway, control_call

PROVIDER=Path('/etc/ffn/security-provider.json')


def commissioned():
    if not PROVIDER.exists():return False
    st=PROVIDER.stat()
    if st.st_uid!=0 or st.st_mode&0o022:raise NatError('Security provider selection must be root-owned')
    if json.loads(PROVIDER.read_text())!={'provider':'linux-stateful-nftables','commit':True}:
        raise NatError('Unknown Security provider selection')
    return True


def projection(xml):
    """Send only policy/object/interface definitions; never device credentials."""
    root=parse(xml)
    objects={'address','address-group','service','service-group','application','application-group','application-filter','tag'}
    def retain(node,allowed):
        for child in list(node):
            if child.tag not in allowed:node.remove(child)
    retain(root,{'shared','devices'})
    shared=root.find('shared')
    if shared is not None:retain(shared,objects)
    for device in root.findall('./devices/entry'):
        retain(device,{'network','vsys'})
        network=device.find('network')
        if network is not None:retain(network,{'interface'})
        for vsys in device.findall('./vsys/entry'):
            retain(vsys,objects|{'zone','rulebase'})
            rules=vsys.find('rulebase')
            if rules is not None:retain(rules,{'security','nat'})
    result=ET.tostring(root,encoding='unicode')
    if len(result.encode())>131072:raise NatError('Security policy projection exceeds 128 KiB')
    return result


def preflight(xml):
    if not commissioned():raise NatError('Security runtime provider is not commissioned for Commit')
    result=control_call('security/validate',xml=projection(xml))
    if result.get('validated') is not True:raise NatError(result.get('error','Security dataplane validation is unconfirmed'))
    return result


def reconcile(path,status):
    try:
        result=control_call('security/apply',xml=projection(Path(path).read_bytes()))
        if not result.get('applied'):raise NatError(result.get('error','Coordinated Security/NAT application is unconfirmed'))
        status.ok('rulebase/security-and-nat',None,result['digest'],'security',json.dumps(result))
    except Exception as error:status.fail('rulebase/security-and-nat','security',str(error))


class SecurityGateway(NatGateway):
    async def worker(self,action,payload):
        return await super().worker(action,payload,resource='security')

    async def status(self,args):
        if args:raise NatError('Security status takes no arguments')
        return await self.worker('status',{})

    async def validate(self,args):
        if set(args)!={'xml'} or not isinstance(args['xml'],str):raise NatError('Policy XML required')
        if not commissioned():raise NatError('Security runtime provider is not commissioned for Commit')
        state=await self.worker('status',{})
        if not state.get('available'):raise NatError(state.get('error','Security collector is unavailable'))
        return await self.worker('validate',dict(revision=state['revision'],xml=projection(args['xml'])))

    async def apply(self,args):
        if not commissioned():raise NatError('Security runtime provider is not commissioned for Commit')
        xml=projection((self.directory/'running-config.xml').read_bytes())
        if args!={'xml':xml}:raise NatError('Security apply must match committed running configuration')
        state=await self.worker('status',{})
        if not state.get('available'):raise NatError(state.get('error','Security collector is unavailable'))
        result=await self.worker('apply',dict(revision=state['revision'],xml=xml))
        # An nft transaction is not the complete acknowledgment: wait for the
        # collector to validate it and open its short forwarding lease.
        import asyncio
        for _ in range(6):
            await asyncio.sleep(1)
            observed=await self.worker('status',{})
            if observed.get('applied') and observed.get('digest')==result.get('digest'):
                return dict(result,forwarding='supervised',applied=True)
        raise NatError('Security generation installed, but supervised forwarding acknowledgment is pending')
