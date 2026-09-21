#!/usr/bin/env python3
"""Local management backend RPC. No network listener and no HTTP client.

The shared management handlers own authentication and candidate/commit state.
The browser gateway and console use the same single backend process. Controld
exposes a separate unprivileged socket accepting only management/request;
legacy privileged daemon commands are never accessible through that socket.
"""
import asyncio
import base64
import json
import os
from pathlib import Path
import socket
import struct
import uuid

LIMIT = 32 * 1024 * 1024
TIMEOUT = 180
BACKEND = '/run/ffn-ngfw/management.sock'
CONSOLE = '/run/ffn-ngfw/console.sock'


def frame(value):
    raw = json.dumps(value, allow_nan=False, separators=(',', ':')).encode() + b'\n'
    if len(raw) > LIMIT: raise ValueError('Management message exceeds limit')
    return raw


def decode(raw):
    if len(raw) > LIMIT or not raw.endswith(b'\n'): raise ValueError('Invalid management frame')
    value = json.loads(raw, parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Nonfinite value')))
    if not isinstance(value, dict): raise ValueError('Management object required')
    return value


async def exchange(path, message):
    async def perform():
        reader, writer = await asyncio.open_unix_connection(path, limit=LIMIT + 1)
        try:
            writer.write(frame(message)); await writer.drain()
            reply = decode(await reader.readline())
            if reply.get('id') != message['id']: raise ValueError('Management reply identity mismatch')
            return reply
        finally:
            writer.close(); await writer.wait_closed()
    # A timed-out mutation is uncertain. Never retry automatically.
    return await asyncio.wait_for(perform(), TIMEOUT)


def validate(request):
    if not isinstance(request, dict) or set(request) != {'method','path','headers','body'}:
        raise ValueError('Invalid management request fields')
    if request['method'] not in ('GET','POST','PUT','PATCH','DELETE','HEAD','OPTIONS'):
        raise ValueError('Unsupported method')
    path = request['path']
    if (not isinstance(path,str) or len(path)>16384 or not path.startswith(('/api/','/openapi.json'))
            or '#' in path or any(ord(c)<32 for c in path)):
        raise ValueError('Management API path required')
    headers = request['headers']
    if not isinstance(headers,list) or len(headers)>100: raise ValueError('Invalid headers')
    for pair in headers:
        if (not isinstance(pair,list) or len(pair)!=2 or
                any(not isinstance(s,str) or len(s)>16384 or '\r' in s or '\n' in s for s in pair)):
            raise ValueError('Invalid header')
        for s in pair: s.encode('latin1')
    if not isinstance(request['body'],str): raise ValueError('Invalid body')
    body = base64.b64decode(request['body'], validate=True)
    if len(body)>LIMIT//2: raise ValueError('Management body exceeds limit')
    return body


async def invoke(app, request, client='local', peer_uid=None):
    from urllib.parse import unquote
    body = validate(request)
    path, _, query = request['path'].partition('?')
    scope = {'type':'http','asgi':{'version':'3.0'},'http_version':'1.1',
             'method':request['method'],'scheme':'https','path':unquote(path),
             'raw_path':path.encode('ascii'),'query_string':query.encode('ascii'),
             'root_path':'','headers':[(a.lower().encode('latin1'),b.encode('latin1')) for a,b in request['headers']],
             'client':(client,0),'server':('local-management',0)}
    if peer_uid is not None: scope['ffn.console_uid']=peer_uid
    delivered=False; response={'status':500,'headers':[]}; chunks=[]; size=0
    done=asyncio.Event()
    async def receive():
        nonlocal delivered
        if not delivered:
            delivered=True
            return {'type':'http.request','body':body,'more_body':False}
        await done.wait()
        return {'type':'http.disconnect'}
    async def send(message):
        nonlocal size
        if message['type']=='http.response.start':
            response.update(status=message['status'],headers=[[a.decode('latin1'),b.decode('latin1')] for a,b in message['headers']])
        elif message['type']=='http.response.body':
            chunk=message.get('body',b'');size+=len(chunk)
            if size>LIMIT//2: raise ValueError('Management response exceeds limit')
            chunks.append(chunk)
            if not message.get('more_body',False):done.set()
    await app(scope,receive,send)
    response['body']=base64.b64encode(b''.join(chunks)).decode()
    return response


async def relay(args, peer_uid=None):
    if not isinstance(args,dict) or set(args)!={'request'}:raise ValueError('Invalid management arguments')
    validate(args['request'])
    message={'id':str(uuid.uuid4()),'request':args['request']}
    if peer_uid is not None:message['peer_uid']=peer_uid
    reply=await exchange(os.getenv('FFN_MANAGEMENT_SOCKET',BACKEND),message)
    if not reply.get('ok'):raise RuntimeError(reply.get('error','Management backend failed'))
    return reply['data']


async def console_connection(reader,writer):
    ident=None
    try:
        request=decode(await asyncio.wait_for(reader.readline(),15))
        ident=request.get('id')
        if request.get('cmd')=='management/stream':
            credentials=writer.get_extra_info('socket').getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12)
            if struct.unpack('3i',credentials)[1]!=0:raise PermissionError('Web gateway identity required')
            validate(request['args']['request'] | {'body':''})
            upstream, sink=await asyncio.open_unix_connection(os.getenv('FFN_MANAGEMENT_SOCKET',BACKEND),limit=LIMIT+1)
            async def copy(source,target):
                while True:
                    data=await source.read(65536)
                    if not data:return
                    target.write(data);await target.drain()
            try:
                sink.write(frame({'id':ident,'stream':request['args']['request']}));await sink.drain()
                outgoing=asyncio.create_task(copy(reader,sink));incoming=asyncio.create_task(copy(upstream,writer))
                try:await asyncio.wait_for(incoming,TIMEOUT)
                finally:
                    outgoing.cancel();await asyncio.gather(outgoing,return_exceptions=True)
            finally:
                sink.close();await sink.wait_closed();writer.close();await writer.wait_closed()
            return
        if (set(request)!={'id','cmd','args'} or not isinstance(ident,str) or len(ident)>128
                or request['cmd'] not in ('management/request','console/request')):
            raise ValueError('Console socket accepts only authenticated management requests')
        # Credentials are checked by the shared backend on every protected route.
        # A local OS account alone conveys no FFN role or administrative rights.
        uid=None
        if request['cmd']=='console/request':
            credentials=writer.get_extra_info('socket').getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12)
            uid=struct.unpack('3i',credentials)[1]
        response={'id':ident,'ok':True,'data':await relay(request['args'],uid)}
    except (Exception,) as error:
        response={'id':ident,'ok':False,'error':str(error) or 'Management request failed; outcome may be uncertain'}
    try:
        writer.write(frame(response));await asyncio.wait_for(writer.drain(),10)
    finally:writer.close();await writer.wait_closed()


async def start_console():
    path=Path(os.getenv('FFN_CONSOLE_SOCKET',CONSOLE));path.parent.mkdir(parents=True,exist_ok=True)
    path.unlink(missing_ok=True)
    server=await asyncio.start_unix_server(console_connection,path=str(path),limit=LIMIT+1)
    path.chmod(0o666)
    return server


class WebGateway:
    """Forward web management calls to the same owner as the console, never fallback."""
    def __init__(self,app):self.app=app

    async def __call__(self,scope,receive,send):
        if scope['type']!='http' or not scope['path'].startswith(('/api/','/openapi.json')):
            return await self.app(scope,receive,send)
        started=False;writer=None;upload=None
        try:
            path=scope.get('raw_path',scope['path'].encode()).decode('ascii')
            if scope.get('query_string'):path+='?'+scope['query_string'].decode('ascii')
            request={'method':scope['method'],'path':path,
                     'headers':[[a.decode('latin1'),b.decode('latin1')] for a,b in scope['headers']]}
            validate(request | {'body':''});ident=str(uuid.uuid4())
            reader,writer=await asyncio.open_unix_connection(os.getenv('FFN_CONSOLE_SOCKET',CONSOLE),limit=LIMIT+1)
            writer.write(frame({'id':ident,'cmd':'management/stream','args':{'request':request}}));await writer.drain()
            async def transmit():
                while True:
                    message=await receive()
                    body=message.get('body',b'')
                    chunks=[body[i:i+65536] for i in range(0,len(body),65536)] or [b'']
                    for index,chunk in enumerate(chunks):
                        item={'type':message['type'],'body':base64.b64encode(chunk).decode(),
                              'more_body':index<len(chunks)-1 or message.get('more_body',False)}
                        writer.write(frame(item));await writer.drain()
                    if not message.get('more_body',False):return
            upload=asyncio.create_task(transmit())
            while True:
                response=decode(await asyncio.wait_for(reader.readline(),TIMEOUT))
                if response.pop('id',None)!=ident:raise ValueError('Response identity mismatch')
                if response['type']=='http.response.start':
                    response['headers']=[(a.encode('latin1'),b.encode('latin1')) for a,b in response['headers']]
                    started=True
                elif response['type']=='http.response.body':response['body']=base64.b64decode(response['body'],validate=True)
                else:raise ValueError('Invalid backend response event')
                await send(response)
                if response['type']=='http.response.body' and not response.get('more_body',False):return
        except Exception:
            if started:raise
            payload=b'{"detail":"Control backend unavailable; a submitted change may have an uncertain outcome. Do not retry without checking state."}'
            await send({'type':'http.response.start','status':503,'headers':[(b'content-type',b'application/json')]})
            await send({'type':'http.response.body','body':payload})
        finally:
            if upload:
                upload.cancel();await asyncio.gather(upload,return_exceptions=True)
            if writer:writer.close();await writer.wait_closed()


def sync_accounts(path,method,status):
    if (os.getenv('FFN_CONSOLE_IDENTITIES')=='1' and method in ('POST','PUT','PATCH','DELETE')
            and path.split('?')[0].startswith('/api/users') and status<400):
        import ffn_manager
        from ffn_console_accounts import sync
        sync(ffn_manager.DB_PATH)


async def stream_backend(app,head,ident,reader,writer):
    from urllib.parse import unquote
    validate(head | {'body':''})
    path,_,query=head['path'].partition('?')
    scope={'type':'http','asgi':{'version':'3.0'},'http_version':'1.1','method':head['method'],
           'scheme':'https','path':unquote(path),'raw_path':path.encode('ascii'),
           'query_string':query.encode('ascii'),'root_path':'','client':('web-gateway',0),
           'server':('local-management',0),
           'headers':[(a.lower().encode('latin1'),b.encode('latin1')) for a,b in head['headers']]}
    status=500;finished=asyncio.Event();body_done=False
    async def receive():
        nonlocal body_done
        if body_done:
            await finished.wait();return {'type':'http.disconnect'}
        event=decode(await asyncio.wait_for(reader.readline(),TIMEOUT))
        if event.get('type') not in ('http.request','http.disconnect'):raise ValueError('Invalid request event')
        body=base64.b64decode(event.get('body',''),validate=True)
        if len(body)>65536:raise ValueError('Request chunk exceeds limit')
        body_done=not event.get('more_body',False)
        return {'type':event['type'],'body':body,'more_body':not body_done}
    async def send(event):
        nonlocal status
        value=dict(event,id=ident)
        if event['type']=='http.response.start':
            status=event['status'];value['headers']=[[a.decode('latin1'),b.decode('latin1')] for a,b in event['headers']]
        elif event['type']=='http.response.body':
            if not event.get('more_body',False):
                sync_accounts(head['path'],head['method'],status);finished.set()
            body=event.get('body',b'')
            chunks=[body[i:i+65536] for i in range(0,len(body),65536)] or [b'']
            for index,chunk in enumerate(chunks):
                writer.write(frame(dict(value,body=base64.b64encode(chunk).decode(),
                    more_body=index<len(chunks)-1 or event.get('more_body',False))))
                await writer.drain()
            return
        writer.write(frame(value));await writer.drain()
    await app(scope,receive,send)


async def serve_backend(app):
    path=Path(os.getenv('FFN_MANAGEMENT_SOCKET',BACKEND));path.parent.mkdir(parents=True,exist_ok=True)
    path.unlink(missing_ok=True)
    async def connection(reader,writer):
        ident=None
        try:
            # Only the root control daemon can reach the private backend socket.
            credentials=writer.get_extra_info('socket').getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12)
            if struct.unpack('3i',credentials)[1]!=0:raise PermissionError('Control daemon identity required')
            message=decode(await asyncio.wait_for(reader.readline(),15));ident=message.get('id')
            if set(message)=={'id','stream'} and isinstance(ident,str):
                try:await asyncio.wait_for(stream_backend(app,message['stream'],ident,reader,writer),TIMEOUT)
                finally:writer.close();await writer.wait_closed()
                return
            if set(message) not in ({'id','request'},{'id','request','peer_uid'}) or not isinstance(ident,str):raise ValueError('Invalid backend request')
            uid=message.get('peer_uid')
            if uid is not None and (type(uid) is not int or uid<0):raise ValueError('Invalid peer')
            data=await asyncio.wait_for(invoke(app,message['request'],peer_uid=uid),TIMEOUT)
            sync_accounts(message['request']['path'],message['request']['method'],data['status'])
            result={'id':ident,'ok':True,'data':data}
        except Exception:
            # Never log request contents, passwords or bearer tokens.
            result={'id':ident,'ok':False,'error':'Management backend failed; outcome may be uncertain'}
        try:writer.write(frame(result));await asyncio.wait_for(writer.drain(),10)
        finally:writer.close();await writer.wait_closed()
    server=await asyncio.start_unix_server(connection,path=str(path),limit=LIMIT+1)
    path.chmod(0o600)
    notify=os.getenv('NOTIFY_SOCKET')
    if notify:
        address='\0'+notify[1:] if notify.startswith('@') else notify
        with socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM) as readiness:
            readiness.connect(address);readiness.sendall(b'READY=1')
    async with server:await server.serve_forever()


async def main():
    if os.getenv('FFN_MANAGER_FRONTEND')=='1':raise RuntimeError('Backend cannot run in frontend mode')
    import ffn_manager
    from ffn_console_identity import install_identity
    install_identity(ffn_manager)
    # Startup schema initialization is shared; the console auth HTTP dependency
    # is gone. Do not start the old peer-auth socket owned by the web service.
    await ffn_manager.startup()
    if os.getenv('FFN_CONSOLE_IDENTITIES')=='1':
        from ffn_console_accounts import sync
        sync(ffn_manager.DB_PATH)
    await serve_backend(ffn_manager.app)


if __name__=='__main__':asyncio.run(main())
