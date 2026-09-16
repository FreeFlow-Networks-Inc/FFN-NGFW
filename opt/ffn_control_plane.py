# SPDX-License-Identifier: GPL-2.0-or-later
"""Controld's journaled worker gateway and supervised CP/DP observation pipes."""
import asyncio
from collections import deque
import json
import os
from pathlib import Path
import signal
import time
import uuid

from ffn_agent_protocol import LIMIT as AGENT_LIMIT, frame, parse, validate
from ffn_planed import LIMIT, check, decode, encode

CONTROL_LIMIT = 2 * LIMIT


async def exchange(path, message, timeout=125, limit=CONTROL_LIMIT):
    """Single exchange. Never retry a mutation after an uncertain outcome."""
    raw = encode(message)
    if len(raw) > limit:
        raise ValueError('request exceeds limit')
    async def perform():
        reader, writer = await asyncio.open_unix_connection(path, limit=limit + 1)
        try:
            writer.write(raw)
            await writer.drain()
            reply = await reader.readline()
            if not reply.endswith(b'\n') or len(reply) > limit:
                raise ValueError('incomplete or oversized response')
            result = json.loads(reply, parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite number')))
            if not isinstance(result, dict) or result.get('id') != message['id']:
                raise ValueError('response identity mismatch')
            return result
        finally:
            writer.close()
            await writer.wait_closed()
    return await asyncio.wait_for(perform(), timeout)


async def control_rpc(cmd, args=None, timeout=130):
    path = os.environ.get('FFN_CONTROLD_SOCKET', '/run/ffn-ngfw/controld.sock')
    response = await exchange(path, {'id': str(uuid.uuid4()), 'cmd': cmd, 'args': args or {}}, timeout)
    if response.get('ok') is not True:
        raise ValueError(response.get('error', 'controld rejected request'))
    return response.get('data')


async def plane_rpc(path, request):
    """Frontend entry point; path selects a worker only on legacy installations."""
    check(request)
    if os.environ.get('FFN_CONTROL_GATEWAY') == 'controld':
        # The client cannot select a worker, executable, or transport endpoint.
        result = await control_rpc('plane/request', {'request': request})
    else:
        result = await exchange(path, request, limit=LIMIT)
    if (not isinstance(result, dict) or result.get('id') != request['id']
            or result.get('v') != 1 or type(result.get('ok')) is not bool):
        raise ValueError('invalid plane response')
    return result


def load_config(path):
    path = Path(path)
    if not path.exists():
        return {'worker_socket': None, 'agents': {}}
    stat = path.stat()
    if stat.st_uid != 0 or stat.st_mode & 0o022 or stat.st_size > 65536:
        raise ValueError('control configuration must be root-owned and not writable by others')
    cfg = json.loads(path.read_text())
    if set(cfg) != {'worker_socket', 'agents'} or not os.path.isabs(cfg['worker_socket']):
        raise ValueError('absolute worker socket and agents required')
    if cfg['worker_socket'] == os.environ.get('FFN_CONTROLD_SOCKET', '/run/ffn-ngfw/controld.sock'):
        raise ValueError('control worker cannot be controld itself')
    if not isinstance(cfg['agents'], dict) or len(cfg['agents']) > 4:
        raise ValueError('at most four selected agents required')
    for name, agent in cfg['agents'].items():
        if (not isinstance(name, str) or len(name) > 64 or
                set(agent) != {'argv', 'role', 'platform', 'interval', 'timeout', 'stale_after'}
                or agent['role'] not in ('cp', 'dp') or not isinstance(agent['platform'], str)
                or not isinstance(agent['argv'], list) or not 1 <= len(agent['argv']) <= 40
                or any(not isinstance(arg, str) or not arg or '\x00' in arg for arg in agent['argv'])
                or not os.path.isabs(agent['argv'][0])):
            raise ValueError('invalid selected agent')
        for field in ('interval', 'timeout', 'stale_after'):
            if type(agent[field]) is not int or not 1 <= agent[field] <= 300:
                raise ValueError('invalid agent timing')
        if agent['stale_after'] <= agent['interval'] + agent['timeout']:
            raise ValueError('expiry must exceed interval plus observation timeout')
    return cfg


class ControlPlane:
    def __init__(self, config, clock=time.monotonic):
        self.config = config
        self.clock = clock
        self.agents = {name: {'connected': False, 'received': None, 'sample': None,
                              'error': 'awaiting agent', 'reconnects': 0}
                       for name in config['agents']}
        self.events = deque(maxlen=256)
        self.tasks = []

    def event(self, kind, **fields):
        self.events.append({'time': time.time(), 'kind': kind, **fields})

    def status(self, args=None):
        observed = {}
        for name, state in self.agents.items():
            age = None if state['received'] is None else max(0, self.clock() - state['received'])
            fresh = state['connected'] and age is not None and age < self.config['agents'][name]['stale_after']
            sample = state['sample']
            observed[name] = {'role': self.config['agents'][name]['role'], 'connected': state['connected'],
                'fresh': fresh, 'age_seconds': age, 'ready': bool(fresh and sample['report']['ready']),
                'error': (state['error'] or 'Observation expired') if not fresh else None, 'reconnects': state['reconnects'],
                # Historic reports are retained only as explicitly labelled last observations.
                'last_observation': sample}
        return {'owner': 'ffn-controld', 'worker_configured': bool(self.config['worker_socket']),
                'agents': observed, 'event_count': len(self.events)}

    async def request(self, args):
        if set(args) != {'request'}:
            raise ValueError('one plane request required')
        request = check(args['request'])
        path = self.config['worker_socket']
        if not path:
            raise ValueError('no execution worker configured')
        fields = {k: request[k] for k in ('id', 'resource', 'action')}
        try:
            response = await exchange(path, request, limit=LIMIT)
            if response.get('v') != 1 or type(response.get('ok')) is not bool:
                raise ValueError('invalid worker response')
        except (OSError, ValueError, asyncio.TimeoutError):
            self.event('control-result', **fields, state='unknown')
            # The journal may have completed the operation. The same original ID
            # remains queryable; never manufacture a replacement request.
            return {'v': 1, 'id': request['id'], 'ok': False, 'state': 'unknown',
                    'error': 'Worker outcome unknown; query the original request ID', 'trace': ['controld']}
        self.event('control-result', **fields, state=response.get('state'))
        response['trace'] = ['controld'] + response.get('trace', [])
        return response

    async def supervise(self, name, cfg):
        state = self.agents[name]
        backoff = 1
        while True:
            proc = None
            try:
                proc = await asyncio.create_subprocess_exec(*cfg['argv'], stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
                    limit=AGENT_LIMIT + 1, start_new_session=True)
                previous = None
                while True:
                    nonce = str(uuid.uuid4())
                    proc.stdin.write(frame({'v': 1, 'op': 'observe', 'nonce': nonce}))
                    async def receive():
                        await proc.stdin.drain()
                        return await proc.stdout.readline()
                    raw = await asyncio.wait_for(receive(), cfg['timeout'])
                    reply = validate(parse(raw), nonce, cfg['role'], cfg['platform'], previous)
                    if not state['connected']:
                        self.event('agent-connected', agent=name, boot_id=reply['boot_id'])
                    state.update(connected=True, received=self.clock(), sample=reply, error=None)
                    previous = reply
                    backoff = 1
                    await asyncio.sleep(cfg['interval'])
            except asyncio.CancelledError:
                raise
            except (OSError, ValueError, TypeError, KeyError, asyncio.TimeoutError):
                state['error'] = 'Agent disconnected, timed out, or returned an invalid report'
                self.event('agent-disconnected', agent=name)
            finally:
                state['connected'] = False
                if proc:
                    try:
                        os.killpg(proc.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    await proc.wait()
            state['reconnects'] += 1
            await asyncio.sleep(backoff)
            backoff = min(30, backoff * 2)

    def start(self):
        self.tasks = [asyncio.create_task(self.supervise(name, cfg)) for name, cfg in self.config['agents'].items()]

    async def close(self):
        for task in self.tasks:
            task.cancel()
        await asyncio.gather(*self.tasks, return_exceptions=True)
