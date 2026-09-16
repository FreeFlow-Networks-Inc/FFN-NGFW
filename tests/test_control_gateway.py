"""Central ownership, report expiry, replay fences, and real local transport."""
import asyncio
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import AsyncMock, Mock, patch
import uuid
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'opt'))
import ffn_agent_protocol as protocol
import ffn_control_plane as control
from ffn_controld import IPCServer
from ffn_planed import serve


def request(action='status'):
    return {'v':1, 'id':str(uuid.uuid4()), 'resource':'network', 'action':action,
            'payload':{} if action=='status' else {'revision':0}}


def report():
    nonce = str(uuid.uuid4()); sink = io.BytesIO()
    protocol.serve(lambda: {'boot_id':str(uuid.uuid4()), 'ready':True}, 'dp', 'test',
                   io.BytesIO(protocol.frame({'v':1, 'op':'observe', 'nonce':nonce})), sink)
    return nonce, protocol.parse(sink.getvalue())


class ProtocolTests(unittest.TestCase):
    def test_identity_nonce_and_replay(self):
        nonce, sample = report()
        protocol.validate(sample, nonce, 'dp', 'test')
        for fields in ({'nonce':str(uuid.uuid4())}, {'role':'cp'}, {'sequence':True},
                       {'boot_id':str(uuid.uuid4())}, {'instance':'bad'}):
            with self.assertRaises(ValueError):
                protocol.validate(sample | fields, nonce, 'dp', 'test')
        with self.assertRaises(ValueError):
            protocol.validate(sample, nonce, 'dp', 'test', sample)
        protocol.validate(sample | {'sequence':2}, nonce, 'dp', 'test', sample)
        with self.assertRaises(ValueError):
            protocol.validate(sample | {'sequence':2,'instance':str(uuid.uuid4())}, nonce, 'dp', 'test', sample)

    def test_bounded_strict_frames(self):
        for raw in (b'{}', b'[]\n', b'{"n":NaN}\n', b' ' * protocol.LIMIT + b'\n'):
            with self.assertRaises(ValueError): protocol.parse(raw)
        with self.assertRaises(ValueError): protocol.frame({'huge':'x' * protocol.LIMIT})
        with self.assertRaises(ValueError):
            protocol.serve(Mock(), 'cp', 'test', io.BytesIO(b'{"op":"apply"}\n'), io.BytesIO())

    def test_expiry_uses_local_monotonic_time_and_disconnect_revokes_ready(self):
        now = [10]
        owner = control.ControlPlane({'worker_socket':None,'agents':{'dp':{'role':'dp','stale_after':20}}}, lambda:now[0])
        sample = report()[1]
        owner.agents['dp'].update(connected=True, received=10, sample=sample, error=None)
        self.assertTrue(owner.status()['agents']['dp']['ready'])
        now[0] = 31
        self.assertFalse(owner.status()['agents']['dp']['ready'])
        now[0] = 11; owner.agents['dp']['connected'] = False
        state = owner.status()['agents']['dp']
        self.assertFalse(state['fresh']); self.assertFalse(state['ready'])
        self.assertEqual(state['last_observation'], sample)


class GatewayTests(unittest.IsolatedAsyncioTestCase):
    async def test_preserves_identity_trace_and_does_not_log_payload(self):
        owner = control.ControlPlane({'worker_socket':'/worker', 'agents':{}})
        req = request('apply'); req['payload']['private'] = 'do not log'
        reply = {'v':1,'id':req['id'],'ok':True,'state':'applied','trace':['mp','dp'],'result':{}}
        with patch.object(control, 'exchange', AsyncMock(return_value=reply)) as rpc:
            result = await owner.request({'request':req})
        self.assertEqual(rpc.await_args.args, ('/worker', req))
        self.assertEqual(result['trace'], ['controld','mp','dp'])
        self.assertNotIn('private', json.dumps(list(owner.events)))

    async def test_no_retry_when_worker_loses_reply(self):
        owner = control.ControlPlane({'worker_socket':'/worker','agents':{}})
        req = request('apply')
        with patch.object(control, 'exchange', AsyncMock(side_effect=asyncio.TimeoutError)) as rpc:
            result = await owner.request({'request':req})
        self.assertEqual(result['id'], req['id']); self.assertEqual(result['state'],'unknown')
        self.assertEqual(rpc.await_count,1)

    async def test_no_frontend_bypass_when_controld_is_down(self):
        with patch.dict(os.environ, {'FFN_CONTROL_GATEWAY':'controld'}), \
                patch.object(control, 'control_rpc', AsyncMock(side_effect=OSError)) as rpc, \
                patch.object(control, 'exchange', AsyncMock()) as direct:
            with self.assertRaises(OSError): await control.plane_rpc('/untrusted-worker', request())
        direct.assert_not_called(); self.assertEqual(rpc.await_count,1)

    async def test_client_cannot_select_execution_worker(self):
        owner = control.ControlPlane({'worker_socket':'/worker','agents':{}})
        with patch.object(control, 'exchange', AsyncMock()) as rpc:
            with self.assertRaises(ValueError):
                await owner.request({'request':request(), 'worker_socket':'/other'})
        rpc.assert_not_called()

    async def test_bad_ipc_shapes_remain_recoverable(self):
        ipc = IPCServer(Mock(), Mock())
        for value in ([], None, {'cmd':[]}, {'cmd':'state/control','args':[1]}):
            self.assertFalse((await ipc._process(json.dumps(value).encode()))['ok'])
        self.assertTrue((await ipc._process(b'{"cmd":"state/control"}'))['ok'])


@unittest.skipIf(sys.platform=='win32', 'Linux daemon transport')
class TransportTests(unittest.IsolatedAsyncioTestCase):
    async def test_gateway_to_journal_replay_applies_only_once(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); count = root/'count'; script = root/'fixture.py'
            script.write_text("import json,sys,pathlib\np=json.load(sys.stdin)\n"
                "if sys.argv[1]=='apply':\n pth=pathlib.Path(sys.argv[2]);pth.write_text(pth.read_text()+'x' if pth.exists() else 'x')\n"
                "print(json.dumps({'config':{'revision':1}}))\n")
            cfg = {'role':'mp','commands':{'network':{action:[sys.executable,str(script),action,str(count)]
                    for action in ('validate','apply')}}}
            task = asyncio.create_task(serve(cfg, root/'requests.db', root/'worker.sock'))
            server = None
            try:
                for _ in range(100):
                    if (root/'worker.sock').exists(): break
                    if task.done(): await task
                    await asyncio.sleep(.01)
                owner = control.ControlPlane({'worker_socket':str(root/'worker.sock'),'agents':{}})
                ipc = IPCServer(Mock(), Mock(), owner)
                server = await asyncio.start_unix_server(ipc.handle_client, path=str(root/'control.sock'))
                req = request('apply')
                with patch.dict(os.environ, {'FFN_CONTROL_GATEWAY':'controld','FFN_CONTROLD_SOCKET':str(root/'control.sock')}):
                    first = await control.plane_rpc('/must-not-use',req)
                    second = await control.plane_rpc('/must-not-use',req)
                self.assertEqual(first,second); self.assertEqual(first['trace'],['controld','mp'])
                self.assertEqual(count.read_text(),'x')
            finally:
                if server: server.close(); await server.wait_closed()
                task.cancel(); await asyncio.gather(task,return_exceptions=True)

    async def test_persistent_agent_exchange_and_clean_shutdown(self):
        with tempfile.TemporaryDirectory() as directory:
            script = Path(directory)/'agent.py'
            script.write_text('import sys\nsys.path.insert(0,'+repr(str(Path(control.__file__).parent))+')\n'
                'from ffn_agent_protocol import serve\n'
                "serve(lambda: {'ready':True,'boot_id':'"+str(uuid.uuid4())+"'},'dp','test')\n")
            cfg = {'argv':[sys.executable,str(script)],'role':'dp','platform':'test',
                   'interval':.01,'timeout':1,'stale_after':3}
            owner = control.ControlPlane({'worker_socket':None,'agents':{'dp':cfg}})
            owner.start()
            try:
                for _ in range(200):
                    sample = owner.agents['dp']['sample']
                    if sample and sample['sequence']>=2: break
                    await asyncio.sleep(.01)
                self.assertTrue(owner.status()['agents']['dp']['ready'])
                self.assertGreaterEqual(sample['sequence'],2)
                self.assertEqual(owner.agents['dp']['reconnects'],0)
            finally: await owner.close()
            self.assertFalse(owner.status()['agents']['dp']['ready'])


if __name__=='__main__': unittest.main()
