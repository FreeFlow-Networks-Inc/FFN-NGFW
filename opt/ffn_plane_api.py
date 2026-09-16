# SPDX-License-Identifier: GPL-2.0-or-later
"""Core access to an explicitly selected MP daemon, independent of platform."""
import asyncio
import os
import uuid
from fastapi import Depends, HTTPException, Request
from ffn_planed import LIMIT, check, decode, encode
from ffn_control_plane import plane_rpc as rpc, control_rpc


def install(app, current_user, require_admin, audit):
    @app.get('/api/system/control')
    async def control(user=Depends(current_user)):
        require_admin(user)
        try:
            return await control_rpc('state/control', timeout=5)
        except (OSError, asyncio.TimeoutError, ValueError, ConnectionError):
            raise HTTPException(503, 'Control observations unavailable')

    @app.get('/api/system/control/events')
    async def events(user=Depends(current_user)):
        require_admin(user)
        try:
            return await control_rpc('state/control-events', timeout=5)
        except (OSError, asyncio.TimeoutError, ValueError, ConnectionError):
            raise HTTPException(503, 'Control events unavailable')

    @app.post('/api/system/planes')
    async def command(request: Request, user=Depends(current_user)):
        # All operations require admin: results may contain saved configuration.
        require_admin(user)
        path = os.environ.get('FFN_PLANE_SOCKET', '')
        if not path or not os.path.isabs(path):
            raise HTTPException(503, 'No MP control daemon selected')
        raw = bytearray()
        async for chunk in request.stream():
            raw.extend(chunk)
            if len(raw) > 65536: raise HTTPException(413, 'Request exceeds 64 KiB')
        try:
            data = check(decode(raw))
        except (ValueError, TypeError, AttributeError, UnicodeError):
            raise HTTPException(422, 'Invalid plane request')
        detail = '%s %s id=%s' % (data['resource'], data['action'], data['id'])
        await audit(user['username'], 'plane_request', detail)
        try:
            result = await rpc(path, data)
        except (OSError, asyncio.TimeoutError, ValueError, ConnectionError):
            await audit(user['username'], 'plane_unknown', detail)
            raise HTTPException(502, 'Control outcome unknown; query request ID '+data['id'])
        await audit(user['username'], 'plane_result', detail+' state='+str(result.get('state')))
        return result
