#!/usr/bin/env python3
"""Profile-scoped TCP/UDP access to MP services over a root-only local transport.

TLS and SSH are passed through unchanged. This is not an authentication service.
The platform owns the authenticated MP/DP transport; this module never routes
transit traffic or accepts an arbitrary destination supplied by a client.
"""
import argparse
import asyncio
import errno
import ipaddress
import importlib
import json
import os
from pathlib import Path
import socket
import stat
import struct
import time

from ffn_interface_management import SERVICES, validate

RUNTIME = Path('/run/ffn-interface-services')
PROFILES = Path('/run/ffn-interface-profiles')
ALLOWED = {f'{proto}/{port}' for proto, ports in SERVICES.values() for port in ports}
# Product listener defaults; installations may override their loopback endpoints.
DEFAULT_PROVIDERS = {key: {'host': '127.0.0.1', 'port': int(key.split('/')[1])}
                     for key in ALLOWED}
DEFAULT_PROVIDERS['tcp/443']['port'] = 8443


def prepare_transport(path):
    """Remove only a dead, owned Unix listener left behind by an SSH restart."""
    path = Path(path)
    parent = path.parent.lstat()
    if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.geteuid() or parent.st_mode & 0o077:
        raise ValueError('Transport directory must be private and owned')
    try:
        before = path.lstat()
    except FileNotFoundError:
        return
    if not stat.S_ISSOCK(before.st_mode) or before.st_uid != os.geteuid():
        raise ValueError('Refusing to replace a non-socket transport path')
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as probe:
        probe.settimeout(1)
        try:
            probe.connect(str(path))
        except OSError as error:
            if error.errno != errno.ECONNREFUSED:
                raise
        else:
            raise ValueError('Transport listener is still active')
    after = path.lstat()
    if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
        raise ValueError('Transport path changed during recovery')
    path.unlink()


def providers(path):
    values = DEFAULT_PROVIDERS.copy()
    if Path(path).exists():
        values.update(json.loads(Path(path).read_text()))
    for key, value in values.items():
        if key not in ALLOWED or (value is not None and (
                set(value) != {'host', 'port'} or not ipaddress.ip_address(value['host']).is_loopback
                or type(value['port']) is not int or not 1 <= value['port'] <= 65535)):
            raise ValueError('Invalid management service provider')
    return {k: v for k, v in values.items() if v is not None}


async def line(reader):
    data = await asyncio.wait_for(reader.readline(), 5)
    if not data.endswith(b'\n') or len(data) > 4096:
        raise ValueError('Invalid service request')
    return json.loads(data)


async def send(writer, value):
    writer.write(json.dumps(value).encode() + b'\n')
    await writer.drain()


async def close(writer):
    writer.close()
    try:
        await asyncio.wait_for(writer.wait_closed(), 2)
    except (OSError, asyncio.TimeoutError):
        pass


async def relay(left, right):
    async def pump(reader, writer):
        while True:
            data = await asyncio.wait_for(reader.read(65536), 900)
            if not data:
                if writer.can_write_eof():
                    writer.write_eof()
                return
            writer.write(data)
            await writer.drain()
    tasks = [asyncio.create_task(pump(left[0], right[1])),
             asyncio.create_task(pump(right[0], left[1]))]
    try:
        await asyncio.gather(*tasks)
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


async def availability(options):
    """A listening socket is readiness evidence, not successful authentication."""
    listeners = {'tcp': set(), 'udp': set()}
    for proto, flag in (('tcp', '-lntH'), ('udp', '-lnuH')):
        process = await asyncio.create_subprocess_exec('ss', flag, stdout=asyncio.subprocess.PIPE)
        output, _ = await asyncio.wait_for(process.communicate(), 3)
        if process.returncode:
            raise OSError('Cannot inspect service listeners')
        for row in output.decode().splitlines():
            fields = row.split()
            if len(fields) >= 4:
                listeners[proto].add(fields[3])
    result = {}
    for key, value in options.items():
        proto = key.split('/')[0]
        port = str(value['port'])
        host = value['host']
        endpoints = {host + ':' + port, '[' + host + ']:' + port, '*:' + port,
                     ('[::]:' if ':' in host else '0.0.0.0:') + port}
        result[key] = bool(endpoints & listeners[proto])
    return result


class Provider:
    def __init__(self, configuration):
        self.configuration = configuration
        self.active = 0

    async def handle(self, reader, writer):
        backend = None
        udp = None
        if self.active >= 256:
            await close(writer)
            return
        self.active += 1
        try:
            request = await line(reader)
            options = providers(self.configuration)
            if request == {'status': True}:
                await send(writer, {'providers': await availability(options)})
                return
            if set(request) != {'service', 'source', 'interface'}:
                raise ValueError('Invalid request')
            ipaddress.ip_address(request['source'])
            endpoint = options[request['service']]
            proto = request['service'].split('/')[0]
            if proto == 'tcp':
                backend = await asyncio.wait_for(asyncio.open_connection(
                    endpoint['host'], endpoint['port']), 5)
                await send(writer, {'ok': True})
                await relay((reader, writer), backend)
            else:
                size = struct.unpack('!H', await asyncio.wait_for(reader.readexactly(2), 5))[0]
                packet = await asyncio.wait_for(reader.readexactly(size), 5)
                family = socket.AF_INET6 if ':' in endpoint['host'] else socket.AF_INET
                udp = socket.socket(family, socket.SOCK_DGRAM)
                udp.setblocking(False)
                udp.connect((endpoint['host'], endpoint['port']))
                loop = asyncio.get_running_loop()
                await loop.sock_sendall(udp, packet)
                answer = await asyncio.wait_for(loop.sock_recv(udp, 65507), 3)
                writer.write(struct.pack('!H', len(answer)) + answer)
                await writer.drain()
        except (OSError, ValueError, KeyError, asyncio.TimeoutError, asyncio.IncompleteReadError):
            pass
        finally:
            if backend:
                await close(backend[1])
            if udp:
                udp.close()
            await close(writer)
            self.active -= 1


def permissions(root=PROFILES):
    boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    result = {}
    records = []
    source = os.environ.get('FFN_INTERFACE_PROFILE_SOURCE')
    if source:
        # A selected platform may expose verified runtime intent. This keeps
        # existing long-lived packet workers upgradeable without a LACP reset.
        try:
            records = importlib.import_module(source).records()
        except (OSError, ValueError, KeyError, ImportError):
            return {}
    else:
        for path in root.glob('*.json'):
            try:
                record = json.loads(path.read_text())
                if path.name == record['interface'] + '.json': records.append(record)
            except (OSError, ValueError, KeyError, TypeError):
                continue
    for record in records:
        try:
            if record['boot_id'] != boot:
                continue
            settings = record['settings']
            policy = validate(settings['management'])
            name = record['interface']
            for address in settings.get('addresses', []):
                address = str(ipaddress.ip_interface(address).ip)
                for proto in ('tcp', 'udp'):
                    for port in policy[proto]:
                        if f'{proto}/{port}' in ALLOWED:
                            result[(name, address, proto, port)] = tuple(policy['sources'])
        except (OSError, ValueError, KeyError, TypeError):
            continue
    return result


def allowed(source, networks):
    address = ipaddress.ip_address(source)
    return not networks or any(address in ipaddress.ip_network(n) for n in networks)


class Datagram(asyncio.DatagramProtocol):
    def __init__(self, owner, key):
        self.owner, self.key = owner, key

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, peer):
        if self.owner.authorized(self.key, peer[0]) and len(self.owner.tasks) < 256:
            self.owner.start(self.owner.datagram(self.key, data, peer, self.transport), self.key)


class Frontend:
    def __init__(self, upstream, root=PROFILES, bind_device=True):
        self.upstream, self.root, self.bind_device = str(upstream), root, bind_device
        self.rules, self.listeners, self.tasks, self.results = {}, {}, {}, {}
        self.providers = {}
        self.channel_ready = False

    def authorized(self, key, source):
        # Re-read the applied manifest on every new request, not only the tick.
        rule = permissions(self.root).get(key)
        return rule is not None and rule == self.rules.get(key) and allowed(source, rule)

    def start(self, coroutine, key):
        task = asyncio.create_task(coroutine)
        self.tasks[task] = key
        task.add_done_callback(self.tasks.pop)

    async def upstream_request(self, key, source):
        stream = await asyncio.wait_for(asyncio.open_unix_connection(self.upstream), 5)
        try:
            await send(stream[1], {'service': f'{key[2]}/{key[3]}',
                                   'source': source, 'interface': key[0]})
            return stream
        except BaseException:
            await close(stream[1])
            raise

    async def client(self, key, reader, writer):
        backend = None
        source = writer.get_extra_info('peername')[0]
        try:
            if not self.authorized(key, source):
                return
            backend = await self.upstream_request(key, source)
            if await line(backend[0]) != {'ok': True}:
                raise ValueError('Provider not ready')
            self.results[key] = {'state': 'connected', 'last_source': source, 'at': time.time()}
            await relay((reader, writer), backend)
        except (OSError, ValueError, asyncio.TimeoutError, asyncio.IncompleteReadError):
            self.results[key] = {'state': 'provider-unavailable', 'at': time.time()}
        finally:
            if backend:
                await close(backend[1])
            await close(writer)

    async def datagram(self, key, data, peer, transport):
        backend = None
        try:
            backend = await self.upstream_request(key, peer[0])
            backend[1].write(struct.pack('!H', len(data)) + data)
            await backend[1].drain()
            size = struct.unpack('!H', await asyncio.wait_for(backend[0].readexactly(2), 5))[0]
            answer = await asyncio.wait_for(backend[0].readexactly(size), 5)
            if self.authorized(key, peer[0]):
                transport.sendto(answer, peer)
            self.results[key] = {'state': 'response-received', 'last_source': peer[0], 'at': time.time()}
        except (OSError, ValueError, asyncio.TimeoutError, asyncio.IncompleteReadError):
            self.results[key] = {'state': 'no-provider-response', 'at': time.time()}
        finally:
            if backend:
                await close(backend[1])

    async def reconcile(self):
        current = permissions(self.root)
        for key in list(self.listeners):
            if key not in current or current[key] != self.rules.get(key):
                self.listeners.pop(key).close()
                for task, task_key in list(self.tasks.items()):
                    if task_key == key:
                        task.cancel()
                self.results.pop(key, None)
        self.rules = current
        for key in current:
            if key in self.listeners:
                continue
            name, address, proto, port = key
            sock = None
            try:
                family = socket.AF_INET6 if ':' in address else socket.AF_INET
                sock = socket.socket(family, socket.SOCK_STREAM if proto == 'tcp' else socket.SOCK_DGRAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                if self.bind_device:
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, name.encode() + b'\0')
                if family == socket.AF_INET6:
                    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                sock.bind((address, port))
                sock.setblocking(False)
                if proto == 'tcp':
                    def accept(reader, writer, target=key):
                        if len(self.tasks) >= 256:
                            writer.close()
                        else:
                            self.start(self.client(target, reader, writer), target)
                    sock.listen(128)
                    listener = await asyncio.start_server(accept, sock=sock)
                else:
                    listener, _ = await asyncio.get_running_loop().create_datagram_endpoint(
                        lambda target=key: Datagram(self, target), sock=sock)
                self.listeners[key] = listener
                self.results[key] = {'state': 'listening-provider-unverified'}
            except OSError as error:
                if sock:
                    sock.close()
                self.results[key] = {'state': 'listener-unavailable', 'reason': str(error)}

    def status(self):
        return {'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                'at': time.time(), 'observed': time.monotonic(), 'channel_ready': self.channel_ready,
                'connections': len(self.tasks),
                'services': [dict(interface=k[0], address=k[1], protocol=k[2], port=k[3],
                                  provider_listening=self.providers.get(f'{k[2]}/{k[3]}', False),
                                  **self.results.get(k, {})) for k in self.rules]}

    async def check_provider(self):
        writer = None
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_unix_connection(self.upstream), 3)
            await send(writer, {'status': True})
            result = await line(reader)
            self.providers = result['providers']
            self.channel_ready = True
        except (OSError, ValueError, KeyError, asyncio.TimeoutError):
            self.providers = {}
            self.channel_ready = False
        finally:
            if writer:
                await close(writer)

    async def stop(self):
        for listener in self.listeners.values():
            listener.close()
        tasks = list(self.tasks)
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


async def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('role', choices=['frontend', 'provider', 'prepare-transport'])
    parser.add_argument('--socket', default=str(RUNTIME / 'upstream.sock'))
    parser.add_argument('--providers', default='/etc/ffn/interface-services.json')
    args = parser.parse_args()
    RUNTIME.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.umask(0o077)
    if args.role == 'prepare-transport':
        prepare_transport(args.socket)
        return
    if args.role == 'provider':
        providers(args.providers)
        Path(args.socket).unlink(missing_ok=True)
        provider = Provider(args.providers)
        server = await asyncio.start_unix_server(provider.handle, args.socket, limit=4096)
        async with server:
            await server.serve_forever()
    else:
        frontend = Frontend(args.socket)
        health = None
        try:
            while True:
                await frontend.reconcile()
                if health is None or health.done():
                    async def refresh():
                        await frontend.check_provider()
                        await asyncio.sleep(5)
                    health = asyncio.create_task(refresh())
                temporary = RUNTIME / 'status.tmp'
                temporary.write_text(json.dumps(frontend.status()))
                temporary.replace(RUNTIME / 'status.json')
                await asyncio.sleep(1)
        finally:
            if health:
                health.cancel()
                await asyncio.gather(health, return_exceptions=True)
            await frontend.stop()


if __name__ == '__main__':
    asyncio.run(main())
