import asyncio
import ast
import logging
from pathlib import Path
import sys
import tempfile
import unittest
from xml.etree import ElementTree as ET
from types import SimpleNamespace
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'opt'))
from ffn_policy_barrier import before_commit


class Barrier(unittest.TestCase):
    def test_actual_commit_handler_drains_before_writing_and_unlocks_on_failure(self):
        # Exercise the real handler without starting the manager or loading
        # appliance services. Stop at its first running-config write.
        from fastapi import HTTPException
        source=Path(__file__).resolve().parents[1]/'opt/ffn_manager.py'
        if not source.exists():
            source=Path(__file__).with_name('ffn_manager.py')
        handler=next(n for n in ast.parse(source.read_text()).body
                     if isinstance(n,ast.AsyncFunctionDef) and n.name=='_config_commit_serial')
        handler.decorator_list=[];handler.returns=None;handler.args.defaults=[]
        for arg in handler.args.args:arg.annotation=None
        calls=[]
        class AtWrite(Exception):pass
        def commit(**kwargs):calls.append('write');raise AtWrite()
        async def prepare(scope):return dict(revision='review',diff={'has_changes':True},effective=ET.fromstring('<config/>'))
        with tempfile.TemporaryDirectory() as tmp:
            candidate=Path(tmp)/'candidate.xml';candidate.write_bytes(b'<config/>')
            config=SimpleNamespace(lock_status=lambda:{'locked':True,'holder':'admin'},
                diff=lambda:{'has_changes':True,'total_changes':1},commit=commit,
                release_lock=lambda u:calls.append('unlock'))
            def guard(data):calls.append('drain');raise RuntimeError('hardware unavailable')
            app=SimpleNamespace(state=SimpleNamespace(platform_policy_guard=guard))
            scope=dict(config_mgr=config,_prepare_commit_review=prepare,app=app,ET=ET,Path=Path,asyncio=asyncio,
                       CANDIDATE_CONFIG=candidate,HTTPException=HTTPException,logger=logging.getLogger('test'))
            exec(compile(ast.Module(body=[handler],type_ignores=[]),str(source),'exec'),scope)
            req=SimpleNamespace(partial_xpath=None,description='',commit_type='full',expected_revision='review')
            with self.assertRaises(HTTPException) as failure:
                asyncio.run(scope['_config_commit_serial'](req,{'username':'admin'}))
            self.assertEqual(failure.exception.status_code,409)
            self.assertEqual(calls,['drain','unlock'])
            calls.clear()
            app.state.platform_policy_guard=lambda data:calls.append('drain')
            with self.assertRaises(AtWrite):asyncio.run(scope['_config_commit_serial'](req,{'username':'admin'}))
            self.assertEqual(calls,['drain','write','unlock'])

    def test_generic_platform_does_not_read_or_call(self):
        self.assertIsNone(asyncio.run(before_commit(SimpleNamespace(state=SimpleNamespace()),'/missing')))

    def test_selected_barrier_receives_candidate_before_commit(self):
        calls=[]
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'candidate.xml';path.write_bytes(b'<config/>')
            def guard(data):calls.append(data);return {'drained':True}
            app=SimpleNamespace(state=SimpleNamespace(platform_policy_guard=guard))
            self.assertEqual(asyncio.run(before_commit(app,path)),{'drained':True})
            self.assertEqual(calls,[b'<config/>'])
            def failed(data):raise RuntimeError('drain failed')
            app.state.platform_policy_guard=failed
            with self.assertRaises(RuntimeError):asyncio.run(before_commit(app,path))


if __name__=='__main__':unittest.main()
