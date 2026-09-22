"""Exercise every registered mutation through the real identity dependency."""
import asyncio
import base64
import os
from pathlib import Path
import re
import sys
import tempfile
import unittest
from unittest.mock import AsyncMock, patch

_temp = tempfile.TemporaryDirectory()
os.environ['FFN_DB_PATH'] = str(Path(_temp.name)/'config.db')
os.environ['FFN_CONFIG_DIR'] = str(Path(_temp.name)/'config')
os.environ['FFN_JWT_SECRET'] = 'isolated-authorization-test'
sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'opt'))
import ffn_manager as manager
import ffn_console_identity as identity
from ffn_authorization import authorize, READ_POSTS
from ffn_management_ipc import invoke
from starlette.requests import Request
from fastapi import HTTPException


class AuthorizationTests(unittest.TestCase):
    def test_all_registered_mutations_deny_non_admins_before_execution(self):
        async def check():
            identity.install_identity(manager)
            count = 0
            try:
                for route in manager.app.routes:
                    for method in set(getattr(route, 'methods', ())) & {'POST','PUT','PATCH','DELETE'}:
                        path = re.sub(r'\{[^}]+\}', 'test', route.path)
                        if path in {'/api/auth/login','/api/auth/change-password'} or path == '/api/config/policies/test/test':
                            continue
                        for role in ('operator','read-only'):
                            user = {'username':'test-user','role':role}
                            for console in (False,True):
                                req = dict(method=method,path=path,headers=[['authorization','Bearer test']],body='')
                                with patch.object(manager, '_authenticate_token', AsyncMock(return_value=user)), \
                                     patch.object(identity, 'console_user', AsyncMock(return_value=user)):
                                    result = await invoke(manager.app, req, peer_uid=200001 if console else None)
                                self.assertEqual(result['status'], 403, (method,path,role,console,base64.b64decode(result['body'])))
                        count += 1
            finally:
                manager.app.dependency_overrides.pop(manager.get_current_user, None)
            self.assertGreater(count, 90)
        asyncio.run(check())

    def test_reads_password_change_and_policy_simulation(self):
        for path,method in [('/api/config/candidate','GET'),('/api/auth/change-password','POST'),
                            *((path,'POST') for path in READ_POSTS)]:
            request = Request({'type':'http','path':path,'method':method,'headers':[]})
            self.assertEqual(authorize(request, {'role':'read-only'})['role'], 'read-only')
        for role in ('admin','superuser'):
            request = Request({'type':'http','path':'/api/config/commit','method':'POST','headers':[]})
            self.assertEqual(authorize(request, {'role':role})['role'],role)
        for path in ('/api/config/policies/nat/test/other','/api/config/policies/nat', '/api/config/lock'):
            with self.assertRaises(HTTPException):
                authorize(Request({'type':'http','path':path,'method':'POST','headers':[]}), {'role':'read-only'})
