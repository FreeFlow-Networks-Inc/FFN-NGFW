# SPDX-License-Identifier: GPL-2.0-or-later
"""Authenticated WebUI/CLI adapter; all policy reads and writes go to controld."""
import asyncio
from fastapi import Depends, HTTPException
from pydantic import BaseModel, Field
from typing import Literal
from ffn_controld_client import ControldClient


class PolicyRequest(BaseModel):
    action: Literal['create','update','delete','move','toggle']
    revision: str = Field(min_length=64,max_length=64)
    name: str | None = Field(default=None,max_length=63)
    rule: dict | None = None
    position: int | None = None
    enabled: bool | None = None

    class Config: extra='forbid'


class PolicyTestRequest(BaseModel):
    packet: dict
    class Config: extra='forbid'


class ProfileRequest(BaseModel):
    action: Literal['create','update','delete']
    revision: str = Field(min_length=64,max_length=64)
    name: str | None = Field(default=None,max_length=63)
    profile: dict | None = None
    class Config: extra='forbid'


def install(app,current_user,require_admin,audit,manager,client=None):
    client=client or ControldClient(timeout=15)

    async def call(payload):
        try:result=await asyncio.to_thread(client.query,'policy/request',**payload)
        except Exception as error:raise HTTPException(503,'Policy controller unavailable; no local fallback was used') from error
        if not result.get('ok'):raise HTTPException(result.get('code',422),result.get('error','Policy request failed'))
        return result['data']

    @app.get('/api/config/policies/status')
    async def policy_status(source:Literal['candidate','running']='candidate',user=Depends(current_user)):
        return await call(dict(action='report',source=source))

    @app.get('/api/config/policy-profiles/{kind}')
    async def profiles_list(kind:str,scope:str='vsys1',source:Literal['candidate','running']='candidate',user=Depends(current_user)):
        result=await call(dict(action='profile-list',kind=kind,scope=scope,source=source))
        result['can_edit']=source=='candidate' and user.get('role') in ('admin','superuser')
        return result

    @app.post('/api/config/policy-profiles/{kind}')
    async def profiles_mutate(kind:str,request:ProfileRequest,scope:str='vsys1',user=Depends(current_user)):
        require_admin(user)
        state=manager.lock_status()
        if state['locked'] and state.get('holder')!=user['username']:raise HTTPException(423,'Configuration is locked by another administrator')
        if not state['locked'] and not manager.acquire_lock(user['username'],'editing policy profiles'):raise HTTPException(423,'Could not acquire configuration lock')
        payload=request.model_dump(exclude_none=True);payload['action']='profile-'+request.action
        try:result=await call(dict(payload,kind=kind,scope=scope,user=user['username']))
        except HTTPException:
            if not state['locked']:manager.release_lock(user['username'])
            raise
        await audit(user['username'],'policy_profile_'+request.action,kind+':'+scope+':'+(request.name or (request.profile or {}).get('name','')))
        return result

    @app.get('/api/config/nat/preview')
    async def nat_preview(source:Literal['candidate','running']='candidate',user=Depends(current_user)):
        try:return await asyncio.to_thread(client.query,'nat/preview',source=source)
        except Exception as error:raise HTTPException(503,'NAT compiler or dataplane status unavailable') from error

    @app.get('/api/system/dataplane-tools')
    async def dataplane_tools(user=Depends(current_user)):
        require_admin(user)
        try:return await asyncio.to_thread(client.query,'nat/tools')
        except Exception as error:raise HTTPException(503,'Dataplane tool audit unavailable') from error

    @app.get('/api/config/policies/{kind}')
    async def policy_list(kind:str,scope:str='vsys1',source:Literal['candidate','running']='candidate',user=Depends(current_user)):
        result=await call(dict(action='list',kind=kind,scope=scope,source=source))
        result['can_edit']=source=='candidate' and user.get('role') in ('admin','superuser')
        return result

    @app.get('/api/config/policies/{kind}/preview')
    async def policy_preview(kind:str,scope:str='vsys1',source:Literal['candidate','running']='candidate',user=Depends(current_user)):
        return await call(dict(action='preview',kind=kind,scope=scope,source=source))

    @app.post('/api/config/policies/{kind}/test')
    async def policy_test(kind:str,request:PolicyTestRequest,scope:str='vsys1',source:Literal['candidate','running']='candidate',user=Depends(current_user)):
        return await call(dict(action='test',kind=kind,scope=scope,source=source,packet=request.packet))

    @app.post('/api/config/policies/{kind}')
    async def policy_mutate(kind:str,request:PolicyRequest,scope:str='vsys1',user=Depends(current_user)):
        require_admin(user)
        state=manager.lock_status()
        if state['locked'] and state.get('holder')!=user['username']:raise HTTPException(423,'Configuration is locked by another administrator')
        if not state['locked'] and not manager.acquire_lock(user['username'],'editing policies'):raise HTTPException(423,'Could not acquire configuration lock')
        try:
            result=await call(dict(request.model_dump(exclude_none=True),kind=kind,scope=scope,user=user['username']))
        except HTTPException:
            if not state['locked']:manager.release_lock(user['username'])
            raise
        await audit(user['username'],'policy_'+request.action,kind+':'+scope+':'+(request.name or (request.rule or {}).get('name','')))
        return result
