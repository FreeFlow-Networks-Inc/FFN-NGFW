import ast
import asyncio
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock
from fastapi import FastAPI,HTTPException
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'opt'))
from ffn_extensions import install


class AggregateStatusTests(unittest.TestCase):
    def test_selected_provider_and_outage_never_probe_mp_bond(self):
        root=Path(__file__).resolve().parents[1]
        function=next(n for n in ast.parse((root/'opt/ffn_manager.py').read_text(encoding='utf-8')).body
                      if isinstance(n,ast.AsyncFunctionDef) and n.name=='aggregate_status')
        function.decorator_list=[];function.args.defaults=[]
        provider=Mock(return_value={'aggregates':[{'ae_name':'ae1','backend':'pa5200-bcm'}]})
        manager=Mock();shell=Mock()
        scope=dict(app=SimpleNamespace(state=SimpleNamespace(platform_aggregate_status=provider)),
                   config_mgr=manager,subprocess=shell,asyncio=asyncio,HTTPException=HTTPException)
        exec(compile(ast.Module(body=[function],type_ignores=[]),'<handler>','exec'),scope)
        result=asyncio.run(scope['aggregate_status']({}))
        self.assertEqual(result['aggregates'][0]['backend'],'pa5200-bcm')
        manager.get_xpath.assert_not_called();shell.run.assert_not_called()
        provider.side_effect=RuntimeError('offline')
        with self.assertRaises(HTTPException) as error:asyncio.run(scope['aggregate_status']({}))
        self.assertEqual(error.exception.status_code,503)
        manager.get_xpath.assert_not_called();shell.run.assert_not_called()

    def test_manifest_contract_requires_hook_and_preserves_unavailable_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp);(path/'static').mkdir()
            manifest=dict(id='fixture',label='Fixture',api_version=1,aggregate_status_version=1)
            (path/'extension.json').write_text(json.dumps(manifest),encoding='utf-8')
            body='from fastapi import APIRouter\ndef router(*args):return APIRouter()\n'
            (path/'control.py').write_text(body,encoding='utf-8')
            app=FastAPI()
            with self.assertLogs('ffn_extensions',level='ERROR'):install(app,lambda:None,lambda u:None,lambda *a:None,selected=tmp)
            with self.assertRaises(RuntimeError):app.state.platform_aggregate_status()
            (path/'control.py').write_text(body+'def aggregate_status():return {"provider":"fixture"}\n',encoding='utf-8')
            app=FastAPI();install(app,lambda:None,lambda u:None,lambda *a:None,selected=tmp)
            self.assertEqual(app.state.platform_aggregate_status(),{'provider':'fixture'})


if __name__=='__main__':unittest.main()
