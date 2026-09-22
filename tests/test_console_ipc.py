import asyncio
import base64
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import AsyncMock, Mock, patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'opt'))
import ffn_management_ipc as ipc
import ffn_cli_transport as cli
import ffn_console_identity as identity
from fastapi import Depends, FastAPI, HTTPException, Request


def request(path='/api/auth/me',method='GET',body=None):
    return {'method':method,'path':path,'headers':[],
            'body':base64.b64encode(json.dumps(body).encode()).decode() if body is not None else ''}


class Protocol(unittest.TestCase):
    def test_strict_request_and_bounds(self):
        ipc.validate(request())
        for change in ({'peer_uid':0},{'path':'https://elsewhere/api/auth/me'},
                       {'method':'CONNECT'},{'body':'!!!'},{'headers':[['x','a\nb']]}):
            with self.assertRaises((ValueError,TypeError)):ipc.validate(request()|change)
        for raw in (b'{}',b'[]\n',b'{"x":NaN}\n'):
            with self.assertRaises(ValueError):ipc.decode(raw)

    def test_cli_has_no_network_fallback(self):
        with patch.object(cli.socket,'socket') as sock:
            sock.return_value.__enter__.return_value.connect.side_effect=FileNotFoundError
            with self.assertRaisesRegex(RuntimeError,'no HTTP fallback'):cli.request('/api/auth/me')
            sock.assert_called_once_with(cli.socket.AF_UNIX,cli.socket.SOCK_STREAM)


class Backend(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.app=FastAPI()
        async def auth(request:Request,authorization=None):raise HTTPException(401,'Token required')
        self.manager=types.SimpleNamespace(app=self.app,get_current_user=auth)
        identity.install_identity(self.manager)
        @self.app.get('/api/auth/me')
        async def me(user=Depends(auth)):return user
        @self.app.get('/api/config/lock')
        async def lock(user=Depends(auth)):return {'owner':user['username']}

    async def test_root_console_is_full_access_without_root_database_entry(self):
        response=await ipc.invoke(self.app,request(),peer_uid=0)
        self.assertEqual(response['status'],200)
        self.assertEqual(json.loads(base64.b64decode(response['body']))['role'],'superuser')

    async def test_web_and_spoofed_headers_do_not_inherit_root(self):
        value=request();value['headers']=[['x-ffn-console-uid','0']]
        self.assertEqual((await ipc.invoke(self.app,value))['status'],401)

    async def test_current_database_role_checked_every_request(self):
        with patch.object(identity,'console_user',AsyncMock(return_value={'username':'viewer','role':'readonly'})) as user:
            await ipc.invoke(self.app,request(),peer_uid=200001)
            await ipc.invoke(self.app,request(),peer_uid=200001)
        self.assertEqual(user.await_count,2)
        self.assertEqual(user.await_args.args[:2],(200001,'/api/auth/me'))

    async def test_unknown_uid_is_rejected(self):
        with patch.object(identity.pwd,'getpwuid',side_effect=KeyError):
            self.assertEqual((await ipc.invoke(self.app,request(),peer_uid=234567))['status'],401)

    async def test_database_deletion_role_and_password_change_are_enforced(self):
        import aiosqlite
        with tempfile.TemporaryDirectory() as directory:
            self.manager.aiosqlite=aiosqlite;self.manager.DB_PATH=str(Path(directory)/'users.db')
            self.manager.PW_CHANGE_ALLOWED_PATHS={'/api/auth/me','/api/auth/change-password'}
            async with aiosqlite.connect(self.manager.DB_PATH) as db:
                await db.execute('CREATE TABLE users(username TEXT,role TEXT,must_change_pw INTEGER)')
                await db.execute("INSERT INTO users VALUES ('viewer','read-only',0)");await db.commit()
                with patch.object(identity.pwd,'getpwuid',return_value=types.SimpleNamespace(pw_name='viewer')):
                    value=await identity.console_user(200001,'/api/config/lock',self.manager)
                    self.assertEqual(value['role'],'read-only')
                    await db.execute("UPDATE users SET must_change_pw=1");await db.commit()
                    with self.assertRaises(HTTPException) as raised:
                        await identity.console_user(200001,'/api/config/lock',self.manager)
                    self.assertEqual(raised.exception.status_code,403)
                    self.assertTrue((await identity.console_user(200001,'/api/auth/me',self.manager))['pw_change_required'])
                    await db.execute('DELETE FROM users');await db.commit()
                    with self.assertRaises(HTTPException):await identity.console_user(200001,'/api/auth/me',self.manager)

    async def test_web_gateway_does_not_fallback_to_local_handlers(self):
        downstream=AsyncMock()
        gateway=ipc.WebGateway(downstream);sent=[]
        scope={'type':'http','path':'/api/config/commit','method':'POST','headers':[], 'query_string':b''}
        with patch.object(ipc.asyncio,'open_unix_connection',AsyncMock(side_effect=FileNotFoundError)) as exchange:
            await gateway(scope,AsyncMock(return_value={'type':'http.request','body':b'{}'}),AsyncMock(side_effect=sent.append))
        self.assertEqual(sent[0]['status'],503)
        self.assertEqual(exchange.await_count,1)
        downstream.assert_not_awaited()

    async def test_web_gateway_and_console_share_backend(self):
        response=await ipc.invoke(self.app,request(),peer_uid=0)
        writer=Mock();writer.drain=AsyncMock();writer.wait_closed=AsyncMock()
        events=[{'type':'http.response.start','status':200,'headers':[]},
                {'type':'http.response.body','body':response['body']}]
        async def read():
            head=ipc.decode(writer.write.call_args_list[0].args[0])
            return ipc.frame(dict(events.pop(0),id=head['id']))
        reader=types.SimpleNamespace(readline=read)
        with patch.object(ipc.asyncio,'open_unix_connection',AsyncMock(return_value=(reader,writer))):
            sent=[]
            await ipc.WebGateway(AsyncMock())({'type':'http','path':'/api/auth/me','method':'GET','headers':[]},
                AsyncMock(return_value={'type':'http.request'}),AsyncMock(side_effect=sent.append))
        self.assertEqual(ipc.decode(writer.write.call_args_list[0].args[0])['cmd'],'management/stream')
        self.assertEqual(sent[0]['status'],200)


@unittest.skipIf(sys.platform=='win32','Linux Unix socket transport')
class Transport(unittest.IsolatedAsyncioTestCase):
    @unittest.skipUnless(os.getuid()==0,'Root-only web gateway transport')
    async def test_web_stream_large_body_and_binary_response(self):
        size=17*1024*1024
        async def app(scope,receive,send):
            received=0
            while True:
                event=await receive();received+=len(event.get('body',b''))
                if not event.get('more_body'):break
            self.assertEqual(received,size)
            await send({'type':'http.response.start','status':200,'headers':[]})
            await send({'type':'http.response.body','body':b'\x00\xff'*100000})
        with tempfile.TemporaryDirectory() as directory,patch.dict(os.environ,
                {'FFN_MANAGEMENT_SOCKET':directory+'/backend','FFN_CONSOLE_SOCKET':directory+'/console'}):
            backend=asyncio.create_task(ipc.serve_backend(app));server=None
            try:
                for _ in range(100):
                    if Path(directory+'/backend').exists():break
                    await asyncio.sleep(.01)
                server=await ipc.start_console();left=size;sent=[]
                async def receive():
                    nonlocal left
                    count=min(65536,left);left-=count
                    return {'type':'http.request','body':b'x'*count,'more_body':bool(left)}
                await ipc.WebGateway(Mock())({'type':'http','path':'/api/upload','method':'POST','headers':[]},
                    receive,AsyncMock(side_effect=sent.append))
                self.assertEqual(sent[0]['status'],200)
                self.assertEqual(b''.join(e.get('body',b'') for e in sent),b'\x00\xff'*100000)
            finally:
                if server:server.close();await server.wait_closed()
                backend.cancel();await asyncio.gather(backend,return_exceptions=True)

    async def test_kernel_identity_not_supplied_identity_and_old_commands_denied(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'console.sock'
            server=await asyncio.start_unix_server(ipc.console_connection,path=str(path),limit=ipc.LIMIT+1)
            try:
                with patch.object(ipc,'relay',AsyncMock(return_value={'status':200,'headers':[],
                        'body':base64.b64encode(b'{"ok":true}').decode()})) as relay:
                    with patch.dict(os.environ,{'FFN_CONSOLE_SOCKET':str(path)}):
                        self.assertEqual(await asyncio.to_thread(cli.request,'/api/auth/me'),{'ok':True})
                    self.assertEqual(relay.await_args.args[1],os.getuid())
                    reply=await ipc.exchange(str(path),{'id':'x','cmd':'plane/request','args':{}})
                    self.assertFalse(reply['ok'])
                    self.assertEqual(relay.await_count,1)
            finally:server.close();await server.wait_closed()


if __name__=='__main__':unittest.main()
