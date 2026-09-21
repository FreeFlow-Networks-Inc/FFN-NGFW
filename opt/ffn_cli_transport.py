"""FFN console client: authenticated local controld RPC, with no HTTP fallback."""
import base64
import json
import os
import socket
import uuid

LIMIT=32*1024*1024


def request(path,method='GET',body=None,token=None):
    ident=str(uuid.uuid4())
    headers=[['content-type','application/json']]
    # The kernel-provided UID is the only console identity. Do not send a
    # caller-controlled role, username, bearer token or forwarded identity.
    message={'id':ident,'cmd':'console/request','args':{'request':{
        'method':method,'path':path,'headers':headers,
        'body':base64.b64encode(json.dumps(body,allow_nan=False).encode()).decode() if body is not None else ''}}}
    raw=json.dumps(message,allow_nan=False,separators=(',',':')).encode()+b'\n'
    if len(raw)>LIMIT:raise RuntimeError('Console request exceeds limit')
    path=os.getenv('FFN_CONSOLE_SOCKET','/run/ffn-ngfw/console.sock')
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as connection:
        connection.settimeout(190)
        try:
            connection.connect(path);connection.sendall(raw)
            received=bytearray()
            while not received.endswith(b'\n'):
                chunk=connection.recv(65536)
                if not chunk:raise RuntimeError('Incomplete control-daemon reply')
                received.extend(chunk)
                if len(received)>LIMIT:raise RuntimeError('Console response exceeds limit')
        except OSError as error:
            raise RuntimeError('Control daemon unavailable or request outcome uncertain; no HTTP fallback') from error
    reply=json.loads(received)
    if reply.get('id')!=ident:raise RuntimeError('Control-daemon reply identity mismatch')
    if not reply.get('ok'):raise RuntimeError(reply.get('error','Control-daemon request failed'))
    response=reply['data'];payload=base64.b64decode(response['body'],validate=True)
    value=json.loads(payload) if payload else None
    if response['status']>=400:
        detail=value.get('detail','Request failed') if isinstance(value,dict) else 'Request failed'
        raise RuntimeError('['+str(response['status'])+'] '+str(detail))
    return value
