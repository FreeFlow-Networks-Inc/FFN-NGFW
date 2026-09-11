import ast,asyncio,os,sys,tempfile,types,unittest
from pathlib import Path
from contextlib import closing
from typing import Optional
import aiosqlite
from fastapi import FastAPI,Depends,HTTPException
from fastapi.testclient import TestClient
from pydantic import BaseModel
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'opt'))
from ffn_policy_validation import validate_policy_rule

class PolicyEditorTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.path=str(Path(self.tmp.name)/'db.sqlite');self.role='admin'
        import sqlite3
        with closing(sqlite3.connect(self.path)) as db:
            db.execute('CREATE TABLE policy_rules(id INTEGER PRIMARY KEY,position INTEGER,name TEXT,src_ip TEXT,dst_ip TEXT,src_iface TEXT,dst_iface TEXT,src_port INTEGER,dst_port INTEGER,proto TEXT,action TEXT,vsys INTEGER,description TEXT,enabled INTEGER DEFAULT 1,kind TEXT DEFAULT "user",immutable INTEGER DEFAULT 0,hidden INTEGER DEFAULT 0,hit_count INTEGER DEFAULT 0,updated_at TEXT)')
        async def current():return {'username':'tester','role':self.role}
        def admin(user):
            if user['role']!='admin':raise HTTPException(403)
        async def audit(db,*args):await db.commit()
        self.app=FastAPI()
        self.ns=dict(app=self.app,Depends=Depends,HTTPException=HTTPException,Optional=Optional,BaseModel=BaseModel,aiosqlite=aiosqlite,
                     DB_PATH=self.path,get_current_user=current,_require_admin=admin,ADMIN_ROLES={'admin'},audit=audit,_check_vsys=lambda v:v,
                     IMMUTABLE_RULE_NAMES={'intrazone-default','interzone-default'},validate_policy_rule=validate_policy_rule,os=os)
        tree=ast.parse((Path(__file__).resolve().parents[1]/'opt/ffn_manager.py').read_text(encoding='utf-8'))
        for node in tree.body:
            if isinstance(node,(ast.ClassDef,ast.AsyncFunctionDef)) and node.name in ('PolicyRule','policy_list','policy_add','policy_update','policy_delete','_compile_policy_bin'):
                exec(compile(ast.Module(body=[node],type_ignores=[]),'<policy>','exec'),self.ns)
        self.client=TestClient(self.app)
    def tearDown(self):self.tmp.cleanup()
    def create(self,**changes):
        data=dict(name='test',src_ip='192.0.2.0/24',dst_ip='198.51.100.0/24',proto='tcp',dst_port=443,vsys=0,enabled=False)
        data.update(changes);return self.client.post('/api/policy/rules',json=data)
    def test_roundtrip_name_interfaces_vsys_enabled(self):
        self.assertEqual(self.create(src_iface='ethernet1/1',dst_iface='ethernet1/2',vsys=3).status_code,200)
        result=self.client.get('/api/policy/rules').json();self.assertTrue(result['can_edit'])
        rule=result['rules'][0];self.assertEqual(rule['name'],'test');self.assertEqual(rule['enabled'],0);self.assertEqual(rule['vsys'],3)
        data={k:rule.get(k) for k in self.ns['PolicyRule'].__fields__};data.update(enabled=True,name='updated')
        self.assertEqual(self.client.put('/api/policy/rules/1',json=data).status_code,200)
        self.assertEqual(self.client.get('/api/policy/rules').json()['rules'][0]['enabled'],1)
    def test_bad_matches_and_readonly_rejected(self):
        for data in [dict(src_ip='garbage'),dict(dst_port=65536),dict(proto='tcpp'),dict(proto='icmp',dst_port=443),dict(action='unknown')]:
            self.assertEqual(self.create(**data).status_code,422)
        self.create();self.role='readonly'
        self.assertEqual(self.create().status_code,403)
        self.assertEqual(self.client.delete('/api/policy/rules/1').status_code,403)
        self.assertFalse(self.client.get('/api/policy/rules').json()['can_edit'])
    def test_older_update_without_enabled_keeps_disabled_rule(self):
        self.create(enabled=False)
        self.assertEqual(self.client.put('/api/policy/rules/1',json={'name':'renamed','description':'edit'}).status_code,200)
        self.assertEqual(self.client.get('/api/policy/rules').json()['rules'][0]['enabled'],0)
    def test_default_only_description_changes(self):
        self.create()
        import sqlite3
        with closing(sqlite3.connect(self.path)) as db:
            db.execute('UPDATE policy_rules SET immutable=1,kind="interzone-default"');db.commit()
        self.assertEqual(self.client.put('/api/policy/rules/1',json={'name':'replacement','description':'edited','enabled':True}).status_code,200)
        rule=self.client.get('/api/policy/rules').json()['rules'][0]
        self.assertEqual(rule['description'],'edited');self.assertEqual(rule['name'],'test');self.assertEqual(rule['enabled'],0)
        self.assertEqual(self.client.delete('/api/policy/rules/1').status_code,403)
    def test_compile_rejects_unsupported_without_replacing_binary(self):
        self.create(src_iface='ethernet1/1',enabled=True)
        blob=Path(self.tmp.name)/'policy.bin';blob.write_bytes(b'existing-policy')
        module=types.ModuleType('ffn_fastpath_compile')
        from unittest.mock import patch
        with patch.dict(sys.modules,{'ffn_fastpath_compile':module}):
            with self.assertRaises(HTTPException):asyncio.run(self.ns['_compile_policy_bin'](str(blob)))
        self.assertEqual(blob.read_bytes(),b'existing-policy')
    def test_unsupported_compile_conditions(self):
        base=dict(src_ip='0.0.0.0/0',dst_ip='0.0.0.0/0',src_port=0,dst_port=0,proto='any',action='permit')
        for change in [dict(src_ip='2001:db8::/64'),dict(action='reset'),dict(dst_iface='eth*'),dict(proto='unknown')]:
            with self.assertRaises(HTTPException):validate_policy_rule({**base,**change},compilation=True)
        validate_policy_rule(base,compilation=True)
if __name__=='__main__':unittest.main()
