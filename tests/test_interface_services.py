"""Socket integration tests; run in an isolated Linux network namespace as root."""
import asyncio
import json
import os
import socket
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'opt'))
import ffn_interface_services as m


class EchoUDP(asyncio.DatagramProtocol):
    def connection_made(self, transport): self.transport = transport
    def datagram_received(self, data, peer): self.transport.sendto(data, peer)


@unittest.skipUnless('--inside' in sys.argv, 'Run this script directly for an isolated namespace')
class Services(unittest.IsolatedAsyncioTestCase):
    async def test_transport_reconnect_removes_only_a_dead_owned_socket(self):
        path=self.root/'reconnect.sock'
        m.prepare_transport(path)
        listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        try:
            listener.bind(str(path));listener.listen(1)
            with self.assertRaisesRegex(ValueError,'still active'):m.prepare_transport(path)
            self.assertTrue(path.exists())
        finally:listener.close()
        m.prepare_transport(path)
        self.assertFalse(path.exists())
        path.write_text('preserve')
        with self.assertRaises(ValueError):m.prepare_transport(path)
        self.assertEqual(path.read_text(),'preserve')
        path.unlink();path.symlink_to(self.config)
        with self.assertRaises(ValueError):m.prepare_transport(path)
        self.assertTrue(self.config.exists())

    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.profile = self.root / 'lo.json'
        self.settings = {'addresses': ['127.0.0.1/8'], 'management': {
            'profile': 'test', 'ping': True, 'tcp': [443], 'udp': [161], 'sources': ['127.0.0.1/32']}}
        self.publish()
        async def echo(reader, writer):
            try:
                while data := await reader.read(4096):
                    writer.write(data)
                    await writer.drain()
            finally:
                await m.close(writer)
        self.echo = await asyncio.start_server(echo, '127.0.0.1', 0)
        self.udp, _ = await asyncio.get_running_loop().create_datagram_endpoint(
            EchoUDP, local_addr=('127.0.0.1', 0))
        self.config = self.root / 'providers.json'
        self.config.write_text(json.dumps({
            'tcp/443': {'host': '127.0.0.1', 'port': self.echo.sockets[0].getsockname()[1]},
            'udp/161': {'host': '127.0.0.1', 'port': self.udp.get_extra_info('sockname')[1]}}))
        self.provider = m.Provider(self.config)
        self.socket = self.root / 'upstream.sock'
        self.server = await asyncio.start_unix_server(self.provider.handle, str(self.socket), limit=4096)
        self.front = m.Frontend(self.socket, self.root, bind_device=False)
        await self.front.reconcile()
        self.clients = []

    def publish(self):
        self.profile.write_text(json.dumps({'interface': 'lo', 'settings': self.settings,
            'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip()}))

    async def connect(self, source='127.0.0.1'):
        reader, writer = await asyncio.open_connection('127.0.0.1', 443, local_addr=(source, 0))
        self.clients.append(writer)
        return reader, writer

    async def asyncTearDown(self):
        await self.front.stop()
        for writer in self.clients: await m.close(writer)
        self.server.close(); await self.server.wait_closed()
        self.echo.close(); await self.echo.wait_closed()
        self.udp.close()
        await asyncio.sleep(.05)
        self.tmp.cleanup()

    async def test_tcp_transparency_and_provider_readiness(self):
        reader, writer = await self.connect()
        payload = b'\x16\x03\x01\x00\x05\x00\xffTLS'
        writer.write(payload); await writer.drain()
        self.assertEqual(await asyncio.wait_for(reader.readexactly(len(payload)), 3), payload)
        await self.front.check_provider()
        self.assertTrue(self.front.channel_ready)
        self.assertTrue(self.front.providers['tcp/443'])

    async def test_udp_request_reply(self):
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(('127.0.0.1', 0)); sock.setblocking(False)
        try:
            loop = asyncio.get_running_loop()
            await loop.sock_sendto(sock, b'snmp-test', ('127.0.0.1', 161))
            answer, _ = await asyncio.wait_for(loop.sock_recvfrom(sock, 1024), 3)
            self.assertEqual(answer, b'snmp-test')
        finally: sock.close()

    async def test_disallowed_source(self):
        reader, _ = await self.connect('127.0.0.2')
        self.assertEqual(await asyncio.wait_for(reader.read(1), 3), b'')
        self.assertEqual(self.provider.active, 0)

    async def test_revocation_closes_active_session_and_listener(self):
        reader, writer = await self.connect()
        writer.write(b'allowed'); await writer.drain()
        self.assertEqual(await asyncio.wait_for(reader.readexactly(7), 3), b'allowed')
        self.profile.unlink()
        await self.front.reconcile()
        self.assertEqual(await asyncio.wait_for(reader.read(1), 3), b'')
        with self.assertRaises(OSError): await self.connect()

    async def test_source_change_closes_existing_session(self):
        reader, writer = await self.connect()
        writer.write(b'a'); await writer.drain()
        self.assertEqual(await asyncio.wait_for(reader.read(1), 3), b'a')
        self.settings['management']['sources'] = ['127.0.0.2/32']
        self.publish(); await self.front.reconcile()
        self.assertEqual(await asyncio.wait_for(reader.read(1), 3), b'')
        reader2, writer2 = await self.connect('127.0.0.2')
        writer2.write(b'b'); await writer2.drain()
        self.assertEqual(await asyncio.wait_for(reader2.read(1), 3), b'b')

    async def test_missing_transport_fails_closed(self):
        self.front.upstream = str(self.root / 'missing.sock')
        reader, _ = await self.connect()
        self.assertEqual(await asyncio.wait_for(reader.read(1), 3), b'')
        await self.front.check_provider()
        self.assertFalse(self.front.channel_ready)
        self.front.upstream = str(self.socket)
        reader, writer = await self.connect()
        writer.write(b'recovered'); await writer.drain()
        self.assertEqual(await asyncio.wait_for(reader.readexactly(9), 3), b'recovered')

    async def test_stale_boot_and_disabled_profile_remove_listeners(self):
        record = json.loads(self.profile.read_text()); record['boot_id'] = 'old'
        self.profile.write_text(json.dumps(record)); await self.front.reconcile()
        self.assertEqual(self.front.listeners, {})
        self.settings['management']['tcp'] = []; self.settings['management']['udp'] = []
        self.publish(); await self.front.reconcile()
        self.assertEqual(self.front.listeners, {})


if __name__ == '__main__':
    if '--inside' in sys.argv:
        sys.argv.remove('--inside'); unittest.main()
    elif os.name == 'posix' and os.geteuid() == 0:
        name = 'ffn-svc-' + uuid.uuid4().hex[:8]
        subprocess.run(['ip', 'netns', 'add', name], check=True)
        try:
            subprocess.run(['ip', '-n', name, 'link', 'set', 'lo', 'up'], check=True)
            result = subprocess.run(['ip', 'netns', 'exec', name, sys.executable,
                str(Path(__file__).resolve()), '--inside'], timeout=50)
            raise SystemExit(result.returncode)
        finally:
            subprocess.run(['ip', 'netns', 'delete', name], check=True)
    else:
        raise SystemExit('Use root on Linux; tests create an isolated network namespace')
