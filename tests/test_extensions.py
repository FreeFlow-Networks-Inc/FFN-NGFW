"""An unselected platform must never import code or issue probes."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from fastapi.staticfiles import StaticFiles
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
            (root / 'core-static').mkdir()
            (root / 'core-static/core.js').write_text('// core')
            app.mount('/static', StaticFiles(directory=root / 'core-static'))
            install(app, user, lambda u: None, audit, selected=temp)
            with TestClient(app) as client:
                result = client.get('/api/system/extensions').json()
                self.assertEqual(result['state'], 'enabled')
                self.assertEqual(result['extensions'][0]['id'], 'fixture')
                self.assertEqual(client.get('/static/extensions/fixture/ui.js').text, '// test')
                self.assertEqual(client.get('/static/core.js').text, '// core')

    def test_missing_extension_does_not_break_core(self):
        app = FastAPI()
        with self.assertLogs('ffn_extensions', level='ERROR'):
            install(app, user, lambda u: None, audit, selected='/nonexistent-ffn-extension')
        with TestClient(app) as client:
            self.assertEqual(client.get('/api/system/extensions').json()['state'], 'unavailable')

    def test_selected_runtime_and_declared_pages(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            pages = [{'id':'ports', 'label':'Hardware ports', 'tab':'network'}]
            manifest = {'id':'fixture','label':'Fixture','api_version':1,
                        'runtime_api_version':1,'pages':pages}
            (root/'extension.json').write_text(json.dumps(manifest))
            (root/'static').mkdir()
            (root/'control.py').write_text(
                'from fastapi import APIRouter, Depends\n'
                'def router(*args): return APIRouter()\n'
                'def runtime_router(current, *args):\n'
                '    api = APIRouter(prefix="/api/system/runtime")\n'
                '    @api.get("/status")\n'
                '    async def status(user=Depends(current)): return {"provider":"fixture"}\n'
                '    return api\n')
            app = FastAPI()
            install(app, user, lambda u: None, audit, selected=temp)
            with TestClient(app) as client:
                self.assertEqual(client.get('/api/system/runtime/status').json()['provider'],'fixture')
                self.assertEqual(client.get('/api/system/runtime-provider').json()['runtime']['provider'],'fixture')
                self.assertEqual(client.get('/api/system/extensions').json()['extensions'][0]['pages'],pages)
            manifest['pages'][0]['tab']='invalid'
            (root/'extension.json').write_text(json.dumps(manifest))
            app=FastAPI()
            with self.assertLogs('ffn_extensions',level='ERROR'):
                install(app,user,lambda u: None,audit,selected=temp)
            with TestClient(app) as client:
                self.assertEqual(client.get('/api/system/runtime/status').status_code,503)


if __name__ == '__main__':
    unittest.main()
