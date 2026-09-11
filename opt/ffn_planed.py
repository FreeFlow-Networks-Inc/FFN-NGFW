#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Authenticated-by-transport MP/CP/DP RPC. No TCP listener or shell payloads.

Unix sockets are root-only. Remote hops use locally configured pinned SSH argv.
Only the leaf executes controllers; its durable journal prevents blind replay
after a crash or lost reply. Relays forward the original request unchanged.
"""
import argparse
import asyncio
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import sys
import uuid

LIMIT = 1024 * 1024
ACTIONS = {'status', 'validate', 'apply', 'lookup', 'result', 'resolve'}


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode() + b'\n'


def decode(raw):
    if len(raw) > LIMIT:
        raise ValueError('message exceeds limit')
    return json.loads(raw, parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite number')))


def check(request):
    if not isinstance(request, dict) or set(request) != {'v', 'id', 'resource', 'action', 'payload'}:
        raise ValueError('invalid request fields')
    if type(request['v']) is not int or request['v'] != 1:
        raise ValueError('unsupported protocol version')
    if not isinstance(request['id'], str) or str(uuid.UUID(request['id'])) != request['id']:
        raise ValueError('request ID must be a canonical UUID')
    if not isinstance(request['resource'], str) or not re.fullmatch('[a-z][a-z0-9-]{0,31}', request['resource']):
        raise ValueError('invalid resource')
    if request['action'] not in ACTIONS or not isinstance(request['payload'], dict):
        raise ValueError('invalid action or payload')
    if request['action'] == 'status' and request['payload']:
        raise ValueError('status takes no payload')
    if request['action'] in ('apply', 'validate'):
        revision = request['payload'].get('revision')
        if type(revision) is not int or revision < 0:
            raise ValueError('current revision is required')
    return request


async def process(argv, data, timeout):
    """Bound both output pipes and kill/reap on timeout or cancellation."""
    proc = await asyncio.create_subprocess_exec(*argv, stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, start_new_session=True)
    async def read(stream):
        out = bytearray()
        while True:
            chunk = await stream.read(8192)
            if not chunk: return bytes(out)
            out.extend(chunk)
            if len(out) > LIMIT: raise ValueError('controller output exceeds limit')
    async def exchange():
        proc.stdin.write(data)
        await proc.stdin.drain()
        proc.stdin.close()
        out, err = await asyncio.gather(read(proc.stdout), read(proc.stderr))
        await proc.wait()
        if proc.returncode:
            if proc.returncode == 2:
                try:
                    failure = decode(out)
                    if isinstance(failure, dict) and set(failure) == {'error'} and isinstance(failure['error'], str):
                        raise ValueError(failure['error'][:512])
                except (json.JSONDecodeError, UnicodeError):
                    pass
            raise RuntimeError('controller failed with exit code %d' % proc.returncode)
        return decode(out)
    try:
        return await asyncio.wait_for(exchange(), timeout)
    finally:
        if proc.returncode is None:
            import signal
            try: os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError: pass
            await proc.wait()


class Plane:
    def __init__(self, config, journal, runner=process):
        self.config, self.runner = config, runner
        if config.get('role') not in ('mp', 'cp', 'dp'):
            raise ValueError('role must be mp, cp or dp')
        self.role = config['role']
        self.commands = config.get('commands', {})
        self.peer = config.get('peer')
        if not self.peer and not self.commands:
            raise ValueError('select peer argv or local commands')
        vectors = ([self.peer] if self.peer else []) + [a for resource in self.commands.values() for a in resource.values()]
        for vector in vectors:
            if not isinstance(vector, list) or not vector or any(not isinstance(a, str) or not a or '\0' in a for a in vector):
                raise ValueError('controller argv must be a nonempty string array')
            if not Path(vector[0]).is_absolute():
                raise ValueError('executables must have absolute paths')
        self.db = sqlite3.connect(str(journal))
        self.db.execute('PRAGMA synchronous=FULL')
        self.db.execute('CREATE TABLE IF NOT EXISTS requests (id TEXT PRIMARY KEY, digest TEXT, resource TEXT, response TEXT, state TEXT, intent TEXT)')
        self.db.execute('CREATE INDEX IF NOT EXISTS pending_resource ON requests(resource, state)')
        self.db.commit()
        self.lock = asyncio.Lock()

    def response(self, request, state, result=None, error=None):
        return {'v':1, 'id':request.get('id'), 'ok':error is None, 'state':state,
                'result':result, 'error':error, 'trace':[self.role]}

    async def command(self, resource, action, payload):
        argv = self.commands.get(resource, {}).get(action)
        if not argv: raise ValueError('unsupported resource operation')
        result = await self.runner(argv, encode(payload), 90 if action == 'apply' else 20)
        if not isinstance(result, dict): raise ValueError('controller response must be an object')
        return result

    def stored(self, ident):
        return self.db.execute('SELECT digest, resource, response FROM requests WHERE id=?', (ident,)).fetchone()

    def record(self, ident, response):
        self.db.execute('UPDATE requests SET response=?,state=? WHERE id=?', (encode(response).decode(), response['state'], ident))
        self.db.commit()

    async def dispatch(self, request):
        try: check(request)
        except (ValueError, TypeError, AttributeError):
            return self.response({}, 'rejected', error='Invalid plane request')
        if self.peer and request['resource'] not in self.commands:
            if request['action'] == 'apply':
                digest = hashlib.sha256(encode(request)).hexdigest()
                row = self.stored(request['id'])
                if row:
                    if row[0] != digest:
                        return self.response(request, 'rejected', error='request ID reused with different content')
                    prior = decode(row[2])
                    if prior['state'] in ('applied', 'reconciled'):
                        return prior
                else:
                    pending = self.response(request, 'unknown', error='Awaiting downstream outcome')
                    self.db.execute('INSERT INTO requests VALUES(?,?,?,?,?,?)', (request['id'], digest,
                        request['resource'], encode(pending).decode(), 'unknown', encode(request).decode()))
                    self.db.commit()
            try:
                result = await self.runner(self.peer, encode(request), 120)
                if (not isinstance(result, dict) or result.get('v') != 1 or
                        result.get('id') != request['id'] or not isinstance(result.get('trace'), list) or
                        len(result['trace']) >= 3 or self.role in result['trace']):
                    raise ValueError('invalid peer response')
                result['trace'].insert(0, self.role)
                if request['action'] == 'apply': self.record(request['id'], result)
                return result
            except Exception:
                return self.response(request, 'unknown', error='Downstream outcome unknown; query request ID before retrying')
        async with self.lock:
            return await self.local(request)

    async def local(self, request):
        resource, action, payload = (request[k] for k in ('resource', 'action', 'payload'))
        ident = request['id']
        try:
            if resource not in self.commands:
                raise ValueError('unsupported resource')
            if action in ('result', 'resolve'):
                allowed = {'request_id'} if action == 'result' else {'request_id', 'observed_revision'}
                if set(payload) != allowed or not isinstance(payload['request_id'], str):
                    raise ValueError('invalid result/reconciliation request')
                row = self.stored(payload['request_id'])
                if not row or row[1] != resource: raise ValueError('request not found')
                prior = decode(row[2])
                if action == 'result': return self.response(request, 'observed', prior)
                if prior['state'] != 'unknown': raise ValueError('only unknown requests require reconciliation')
                observed = await self.command(resource, 'status', {})
                revision = observed.get('config', {}).get('revision')
                if type(payload['observed_revision']) is not int or revision != payload['observed_revision']:
                    raise ValueError('observed revision changed; review runtime status again')
                resolved = self.response({'id':payload['request_id']}, 'reconciled', {'observed_revision':revision})
                self.record(payload['request_id'], resolved)
                return self.response(request, 'reconciled', resolved)
            if action != 'apply':
                result = await self.command(resource, action, payload)
                return self.response(request, 'validated' if action == 'validate' else 'observed', result)
            digest = hashlib.sha256(encode(request)).hexdigest()
            row = self.stored(ident)
            if row:
                if row[0] != digest: raise ValueError('request ID reused with different content')
                return decode(row[2])
            if self.db.execute("SELECT 1 FROM requests WHERE resource=? AND state='unknown' LIMIT 1", (resource,)).fetchone():
                raise ValueError('resource has an unknown outcome; reconcile before another apply')
            # Validation is side-effect-free and occurs before creating the durable intent.
            await self.command(resource, 'validate', payload)
            unknown = self.response(request, 'unknown', error='Apply interrupted or incomplete; reconcile runtime state')
            self.db.execute('INSERT INTO requests VALUES(?,?,?,?,?,?)', (ident, digest, resource, encode(unknown).decode(), 'unknown', encode(request).decode()))
            self.db.commit()
            try:
                result = await self.command(resource, 'apply', payload)
            except Exception:
                return unknown
            answer = self.response(request, 'applied', result)
            self.record(ident, answer)
            return answer
        except (ValueError, RuntimeError, OSError, asyncio.TimeoutError) as error:
            # No subprocess diagnostics or configuration contents leave the node.
            detail = str(error) if isinstance(error, ValueError) else 'Controller unavailable or rejected request'
            return self.response(request, 'rejected', error=detail)


async def serve(config, journal, path):
    plane = Plane(config, journal)
    connections = set()
    async def handle(reader, writer):
        # Root-only socket plus bounded concurrency prevents unbounded subprocesses.
        if len(connections) >= 16:
            writer.close(); return
        connections.add(writer)
        try:
            while True:
                raw = await asyncio.wait_for(reader.readline(), 130)
                if not raw: break
                try: result = await plane.dispatch(decode(raw))
                except (ValueError, UnicodeError): result = plane.response({}, 'rejected', error='Invalid JSON')
                writer.write(encode(result))
                await writer.drain()
        except (ValueError, asyncio.TimeoutError, ConnectionError):
            pass
        finally:
            connections.discard(writer)
            writer.close()
            await writer.wait_closed()
    # A second daemon must never unlink a live daemon's endpoint.
    import fcntl
    lock = open(str(path)+'.lock', 'w')
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    path.unlink(missing_ok=True)
    server = await asyncio.start_unix_server(handle, path=str(path), limit=LIMIT+1)
    os.chmod(path, 0o600)
    try:
        async with server: await server.serve_forever()
    finally:
        plane.db.close()
        lock.close()


async def call(path):
    raw = sys.stdin.buffer.readline(LIMIT+1)
    check(decode(raw))
    reader, writer = await asyncio.open_unix_connection(str(path), limit=LIMIT+1)
    try:
        writer.write(raw if raw.endswith(b'\n') else raw+b'\n')
        await writer.drain()
        result = await asyncio.wait_for(reader.readline(), 125)
        if not result: raise RuntimeError('plane daemon disconnected')
        sys.stdout.buffer.write(encode(decode(result)))
        sys.stdout.buffer.flush()
    finally:
        writer.close()
        await writer.wait_closed()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('mode', choices=['serve', 'call'])
    p.add_argument('--socket', type=Path, required=True)
    p.add_argument('--config', type=Path)
    p.add_argument('--journal', type=Path)
    args = p.parse_args()
    os.umask(0o077)
    if args.mode == 'serve':
        if not args.config or not args.journal: p.error('serve requires config and journal')
        asyncio.run(serve(decode(args.config.read_bytes()), args.journal, args.socket))
    else: asyncio.run(call(args.socket))


if __name__ == '__main__': main()
