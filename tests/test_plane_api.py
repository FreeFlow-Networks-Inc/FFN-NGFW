import os
from pathlib import Path
import sys
import unittest
from unittest.mock import AsyncMock, patch
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
sys.path[:0]=[str(Path(__file__).resolve().parents[1]/'opt'),str(Path(__file__).resolve().parent)]
import ffn_plane_api
from test_planes import request


class APITests(unittest.TestCase):
    def setUp(self):
        self.role='admin'
        async def user(): return {'username':'tester','role':self.role}
        def admin(user):
            if user['role']!='admin': raise HTTPException(403)
        self.audit=AsyncMock(); app=FastAPI()
        ffn_plane_api.install(app,user,admin,self.audit)
        self.client=TestClient(app)
        self.env=patch.dict(os.environ,{'FFN_PLANE_SOCKET':str(Path.cwd()/'test.sock')})
        self.env.start();self.addCleanup(self.env.stop)
    def test_readonly_cannot_issue_any_command(self):
        self.role='readonly'
        with patch.object(ffn_plane_api,'rpc',new_callable=AsyncMock) as rpc:
            self.assertEqual(self.client.post('/api/system/planes',json=request()).status_code,403)
            rpc.assert_not_called()
    def test_invalid_and_oversized_messages_rejected(self):
        with patch.object(ffn_plane_api,'rpc',new_callable=AsyncMock) as rpc:
            self.assertEqual(self.client.post('/api/system/planes',json={}).status_code,422)
            self.assertEqual(self.client.post('/api/system/planes',content='x'*65537).status_code,413)
            rpc.assert_not_called()
    def test_request_id_survives_failure_without_payload_audit(self):
        req=request();req['payload']['private']='must-not-be-audited'
        with patch.object(ffn_plane_api,'rpc',side_effect=OSError('private diagnostic')):
            result=self.client.post('/api/system/planes',json=req)
        self.assertEqual(result.status_code,502)
        self.assertIn(req['id'],result.json()['detail'])
        self.assertNotIn('private diagnostic',result.text)
        self.assertNotIn('must-not-be-audited',str(self.audit.call_args_list))


if __name__=='__main__': unittest.main()
