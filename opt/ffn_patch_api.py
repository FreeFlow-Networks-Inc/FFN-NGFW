# SPDX-License-Identifier: GPL-2.0-or-later
"""Authenticated API for the independent patch worker."""
import asyncio
from fastapi import Depends, HTTPException
from pydantic import BaseModel
from ffn_patch import PatchError, PatchManager


class PatchRequest(BaseModel):
    sha256: str = ''


def install(app, current_user, require_admin, audit, server_url):
    @app.get('/api/system/patches')
    async def patch_status(user=Depends(current_user)):
        try:
            result = await asyncio.to_thread(PatchManager().status)
            result['server'] = server_url()
            result['can_manage'] = user.get('role') in ('admin', 'superuser')
            return result
        except Exception:
            raise HTTPException(503, 'Patch state unavailable; inspect the worker journal') from None

    @app.post('/api/system/patches/{action}', status_code=202)
    async def patch_action(action: str, request: PatchRequest, user=Depends(current_user)):
        require_admin(user)
        try:
            job = await asyncio.to_thread(PatchManager().submit, action, user['username'], server_url(), request.sha256)
        except PatchError as exc:
            raise HTTPException(409, exc.public_message) from None
        except Exception:
            raise HTTPException(503, 'Patch worker unavailable') from None
        await audit(user['username'], 'patch_' + action, job['id'])
        return {'job': job}
