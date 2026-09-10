#!/usr/bin/env python3
import sys
from pathlib import Path
import unittest
from unittest.mock import AsyncMock, Mock, patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'opt'))
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
import ffn_patch_api as api


class PatchAPITests(unittest.TestCase):
    def setUp(self):
        self.user = {'username': 'fixture', 'role': 'read-only'}
        app = FastAPI()
        def require_admin(user):
            if user['role'] != 'admin':
                raise HTTPException(403, 'Administrator required')
        self.audit = AsyncMock()
        api.install(app, lambda: self.user, require_admin, self.audit, lambda: 'https://updates.example')
        self.client = TestClient(app)

    def test_read_only_cannot_start_any_action(self):
        with patch.object(api, 'PatchManager') as manager:
            for action in ('check', 'stage', 'install', 'rollback', 'recover'):
                self.assertEqual(self.client.post('/api/system/patches/' + action, json={}).status_code, 403)
            manager.assert_not_called()

    def test_admin_launch_and_audit(self):
        self.user['role'] = 'admin'
        with patch.object(api, 'PatchManager') as manager:
            manager.return_value.submit.return_value = {'id': 'fixture-job', 'status': 'queued'}
            result = self.client.post('/api/system/patches/install', json={'sha256': 'a' * 64})
            self.assertEqual(result.status_code, 202)
            self.assertEqual(result.json()['job']['status'], 'queued')
        self.audit.assert_awaited_once_with('fixture', 'patch_install', 'fixture-job')

    def test_state_permissions_and_safe_unexpected_error(self):
        with patch.object(api, 'PatchManager') as manager:
            manager.return_value.status.return_value = {'history': []}
            self.assertFalse(self.client.get('/api/system/patches').json()['can_manage'])
            manager.return_value.status.side_effect = OSError('private-path')
            result = self.client.get('/api/system/patches')
            self.assertEqual(result.status_code, 503)
            self.assertNotIn('private-path', result.text)


if __name__ == '__main__':
    unittest.main()
