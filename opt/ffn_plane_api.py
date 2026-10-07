# SPDX-License-Identifier: GPL-2.0-or-later
"""Core access to an explicitly selected MP daemon, independent of platform."""
import asyncio
import os
import uuid
from fastapi import Depends, HTTPException, Request
from ffn_planed import INVENTORY, check, decode
from ffn_control_plane import plane_rpc as rpc, control_rpc


def selected():
    """The MP control daemon's socket, or '' when controld is the gateway.

    A console whose control gateway is controld has no plane socket of its
    own; its requests still go through rpc(), so that is not a missing
    daemon. Only a console with neither is refused.
    """
    path = os.environ.get('FFN_PLANE_SOCKET', '')
    if os.environ.get('FFN_CONTROL_GATEWAY') != 'controld' and (not path or not os.path.isabs(path)):
        raise HTTPException(503, 'No MP control daemon selected')
    return path


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

    @app.get('/api/system/planes')
    async def inventory(user=Depends(current_user)):
        """Which resources the selected daemons offer, and what is blocking them.

        The core learns the vocabulary from the daemons rather than carrying a
        list of its own, so an installed platform's resources appear without a
        core change. Admin-only like the command endpoint below: this is the
        administration surface of the same daemon, and a blocked request ID is
        operational state. No saved configuration or controller path is
        returned, and nothing here probes hardware.
        """
        require_admin(user)
        path = selected()
        request = {'v': 1, 'id': str(uuid.uuid4()), 'resource': INVENTORY,
                   'action': 'inventory', 'payload': {}}
        try:
            result = await rpc(path, request)
        except (OSError, asyncio.TimeoutError, ValueError, ConnectionError):
            raise HTTPException(502, 'Control daemon did not answer')
        if not result.get('ok') or not isinstance(result.get('result'), dict):
            raise HTTPException(502, 'Control daemon did not describe itself')
        return result['result']

    @app.post('/api/system/planes')
    async def command(request: Request, user=Depends(current_user)):
        # All operations require admin: results may contain saved configuration.
        require_admin(user)
        path = selected()
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
