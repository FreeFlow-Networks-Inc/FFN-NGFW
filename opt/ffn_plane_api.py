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

    @app.get('/api/system/convergence')
    async def convergence(user=Depends(current_user)):
        """Did the committed configuration reach every subsystem after boot?

        Computed from the lifecycle replay receipt, the running configuration
        and live observations (front ports and aggregates through the selected
        daemon, the dataplane's interface-management enforcement through the
        relay). Admin-only: it names interfaces and their committed state. An
        unreachable daemon or relay makes a subsystem unobservable, never a
        failure of the request.
        """
        require_admin(user)
        import json as _json
        import ffn_convergence as conv
        resources = {}
        try:
            path = selected()
        except HTTPException as error:
            path = None
        for key in (('faceplate', 'status'), ('aggregate', 'status')):
            if path is None:
                resources[key] = {'error': 'No MP control daemon selected'}
                continue
            request = {'v': 1, 'id': str(uuid.uuid4()), 'resource': key[0], 'action': key[1], 'payload': {}}
            try:
                result = await rpc(path, request)
                resources[key] = result.get('result') if result.get('ok') else {'error': str(result.get('error'))[:200]}
            except (OSError, asyncio.TimeoutError, ValueError, ConnectionError) as error:
                resources[key] = {'error': str(error)[:200]}
        views = status = None
        try:
            import ffn_ifmgmt_audit as audit
            if os.path.exists('/etc/ffn-ngfw/ssh-cp.conf'):
                views = lambda: audit.collect(audit.run_dp)
                status = lambda: _json.loads(audit.run_dp('cat ' + conv.DP_SERVICES_STATUS))
        except ImportError:
            views = None
        return await asyncio.to_thread(conv.assess, resources=resources, dp_views=views,
                                       tunnel=conv.unit_active, dp_status=status)

    @app.post('/api/system/convergence/reapply')
    async def convergence_reapply(user=Depends(current_user)):
        """Start the lifecycle's committed-configuration replay for the current boots."""
        require_admin(user)
        import json as _json
        import ffn_convergence as conv
        result = await asyncio.to_thread(conv.reapply)
        await audit(user['username'], 'convergence_reapply', _json.dumps(result, sort_keys=True)[:300])
        return result

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
