"""An unselected platform must never import code or issue probes."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'opt'))
from ffn_extensions import install


async def user():
    return {'username': 'fixture', 'role': 'admin'}


async def audit(*args):
    pass


class ExtensionTests(unittest.TestCase):
    def test_disabled_never_imports_or_probes(self):
        app = FastAPI()
        with patch('ffn_extensions.importlib.util.spec_from_file_location') as imp:
            install(app, user, lambda u: None, audit, selected='')
            with TestClient(app) as client:
                self.assertEqual(client.get('/api/system/extensions').json(), {'state':'disabled', 'extensions':[]})
                self.assertEqual(client.get('/api/pa5200/network').status_code, 404)
                self.assertEqual(client.get('/static/extensions/pa5200/ui.js').status_code, 404)
            imp.assert_not_called()

    def test_manifest_read_requires_auth(self):
        async def denied():
            raise HTTPException(401, 'Not authenticated')
        app = FastAPI()
        install(app, denied, lambda u: None, audit, selected='')
        with TestClient(app) as client:
            self.assertEqual(client.get('/api/system/extensions').status_code, 401)

    def test_explicit_generic_extension(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'extension.json').write_text(json.dumps({'id':'fixture','label':'Fixture', 'api_version':1}))
            (root / 'static').mkdir()
            (root / 'static/ui.js').write_text('// test')
            (root / 'control.py').write_text('from fastapi import APIRouter\ndef router(*args):\n    return APIRouter()\n')
            app = FastAPI()
            install(app, user, lambda u: None, audit, selected=temp)
            with TestClient(app) as client:
                result = client.get('/api/system/extensions').json()
                self.assertEqual(result['state'], 'enabled')
                self.assertEqual(result['extensions'][0]['id'], 'fixture')
                self.assertEqual(client.get('/static/extensions/fixture/ui.js').text, '// test')

    def test_missing_extension_does_not_break_core(self):
        app = FastAPI()
        with self.assertLogs('ffn_extensions', level='ERROR'):
            install(app, user, lambda u: None, audit, selected='/nonexistent-ffn-extension')
        with TestClient(app) as client:
            self.assertEqual(client.get('/api/system/extensions').json()['state'], 'unavailable')


if __name__ == '__main__':
    unittest.main()
