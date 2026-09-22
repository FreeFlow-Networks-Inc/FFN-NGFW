import ast
import copy
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import AsyncMock
import xml.etree.ElementTree as ET
from fastapi import HTTPException

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'opt'))
from ffn_vr_candidate import edit, list_routers, RouterError, container

SEED = [dict(id=1, name='default', table_id=254, interfaces=[], admin_up=True,
             protocol='static', config={}, routes=[dict(id=7, dest_cidr='0.0.0.0/0',
             next_hop='192.0.2.1', dev='ethernet1/1', metric=100)])]
XML = '<config><devices><entry name="localhost.localdomain"><network><interface><ethernet><entry name="ethernet1/1"/></ethernet></interface></network></entry></devices></config>'


class RouterTests(unittest.TestCase):
    def test_candidate_route_appears_in_real_commit_diff(self):
        source=(Path(__file__).resolve().parents[1]/'opt/ffn_manager.py').read_text(encoding='utf-8')
        klass=next(n for n in ast.parse(source).body if isinstance(n,ast.ClassDef) and n.name=='ConfigManager')
        klass.body=[n for n in klass.body if isinstance(n,ast.FunctionDef) and n.name in ('_collect_paths','diff')]
        env=dict(ET=ET,CANDIDATE_CONFIG='candidate',RUNNING_CONFIG='running')
        exec(compile(ast.Module(body=[klass],type_ignores=[]),'diff','exec'),env)
        roots={k:ET.fromstring(XML) for k in ('candidate','running')}
        manager=env['ConfigManager']();manager._load=lambda name:roots[name]
        self.assertFalse(manager.diff()['has_changes'])
        edit(roots['candidate'],SEED,'route-update','default',dict(SEED[0]['routes'][0],metric=20),7)
        diff=manager.diff()
        self.assertTrue(diff['has_changes'])
        self.assertIn('static-route',str(diff))
        self.assertEqual(ET.tostring(roots['running']),ET.tostring(ET.fromstring(XML)))

    def test_read_does_not_migrate_and_candidate_keeps_legacy_route(self):
        root=ET.fromstring(XML); before=ET.tostring(root)
        self.assertEqual(list_routers(root, SEED)[0]['routes'][0]['id'], 7)
        self.assertEqual(ET.tostring(root), before)
        result=edit(root, SEED, 'routing', 'default', {'ecmp': {'max_paths':2}})
        self.assertEqual(result['status'], 'candidate-updated')
        self.assertEqual(result['runtime'], 'not-applied')
        row=list_routers(root, [])[0]
        self.assertEqual(row['config']['ecmp']['max_paths'],2)
        self.assertEqual(row['routes'][0]['id'],7)
        self.assertEqual(row['routes'][0]['next_hop'],'192.0.2.1')
        self.assertIsNotNone(root.find('.//interface/ethernet/entry'))
        self.assertEqual(SEED[0]['config'],{})

    def test_factory_default_keeps_saved_sql_routes(self):
        root=ET.fromstring(XML)
        net=root.find('.//network')
        parent=ET.SubElement(net,'virtual-router')
        default=ET.SubElement(parent,'entry',name='default')
        ET.SubElement(default,'interface')
        before=ET.tostring(root)
        self.assertEqual(list_routers(root,SEED)[0]['routes'][0]['id'],7)
        self.assertEqual(ET.tostring(root),before)
        edit(root,SEED,'routing','default',{'ecmp':{'enable':True}})
        self.assertEqual(list_routers(root,SEED)[0]['routes'][0]['id'],7)
        edit(root,SEED,'route-delete','default',route_id=7)
        self.assertEqual(list_routers(root,SEED)[0]['routes'],[],'Deleted routes cannot reappear from SQL')

    def test_route_crud_and_revert(self):
        root=ET.fromstring(XML)
        new=dict(dest_cidr='198.51.100.0/24', next_hop='192.0.2.5', dev='ethernet1/1',metric=50)
        result=edit(root,SEED,'route-add','default',new)
        self.assertEqual(result['id'],8)
        edit(root,SEED,'route-update','default',dict(new,metric=25),8)
        self.assertEqual(list_routers(root,[])[0]['routes'][1]['metric'],25)
        edit(root,SEED,'route-delete','default',route_id=7)
        self.assertEqual([r['id'] for r in list_routers(root,[])[0]['routes']],[8])
        reverted=ET.fromstring(XML)
        self.assertEqual(list_routers(reverted,SEED)[0]['routes'][0]['id'],7)
        with self.assertRaises(RouterError):edit(root,SEED,'route-delete','default',route_id=7)

    def test_membership_and_unknown_xml_preservation(self):
        root=ET.fromstring(XML)
        edit(root,SEED,'create','tenant',{'interfaces':['ethernet1/2'],'protocol':'static'})
        tenant=container(root).find("entry[@name='tenant']")
        ET.SubElement(tenant,'provider-extension').text='keep'
        edit(root,SEED,'update','tenant',{'admin_up':False})
        self.assertEqual(tenant.findtext('provider-extension'),'keep')
        with self.assertRaises(RouterError):edit(root,SEED,'create','other',{'interfaces':['ethernet1/2']})
        with self.assertRaises(RouterError):edit(root,SEED,'delete','default')
        with self.assertRaises(RouterError):edit(root,SEED,'update','tenant',{'interfaces':['mgmt']},management_iface='mgmt')


class EndpointTests(unittest.IsolatedAsyncioTestCase):
    async def test_actual_candidate_writer_lock_errors_and_running_unchanged(self):
        source=(Path(__file__).resolve().parents[1]/'opt/ffn_manager.py').read_text(encoding='utf-8')
        node=next(n for n in ast.parse(source).body if isinstance(n,ast.AsyncFunctionDef) and n.name=='_vr_candidate_edit')
        with tempfile.TemporaryDirectory() as directory:
            candidate=Path(directory)/'candidate.xml';running=Path(directory)/'running.xml'
            candidate.write_text(XML);running.write_text(XML)
            class Manager:
                holder=None
                def lock_status(self):return dict(locked=bool(self.holder),holder=self.holder)
                def acquire_lock(self,user,reason):self.holder=user;return True
                def release_lock(self,user):self.holder=None
                def _load(self,path):return ET.fromstring(path.read_text())
                def _save(self,root,path):path.write_bytes(ET.tostring(root))
            manager=Manager()
            def require_admin(user):
                if user['role']!='admin':raise HTTPException(403,'Admin required')
            env=dict(HTTPException=HTTPException,config_mgr=manager,CANDIDATE_CONFIG=candidate,
                     _vr_candidate_seed=AsyncMock(return_value=copy.deepcopy(SEED)),_audit=AsyncMock(),
                     _require_admin=require_admin,_mgmt_iface=lambda:'mgmt')
            exec(compile(ast.Module(body=[node],type_ignores=[]),'writer','exec'),env)
            call=env['_vr_candidate_edit'];user=dict(username='admin',role='admin')
            for actor,holder,code in [(dict(username='view',role='readonly'),None,403),(user,'another',423)]:
                manager.holder=holder
                with self.assertRaises(HTTPException) as raised:await call('routing','default',{},actor)
                self.assertEqual(raised.exception.status_code,code)
                self.assertEqual(candidate.read_text(),XML)
            manager.holder=None
            with self.assertRaises(HTTPException):await call('delete','default',{},user)
            self.assertIsNone(manager.holder)
            self.assertEqual(candidate.read_text(),XML)
            result=await call('routing','default',{'ecmp':{'enable':True}},user)
            self.assertEqual(result['status'],'candidate-updated')
            self.assertEqual(running.read_text(),XML)
            self.assertNotEqual(candidate.read_text(),XML)
            env['_audit'].assert_awaited_once()


if __name__=='__main__':unittest.main()
