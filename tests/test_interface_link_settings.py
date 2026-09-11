import ast,unittest
from pathlib import Path
from typing import Optional
from unittest.mock import Mock
from fastapi import FastAPI,Depends,HTTPException
from fastapi.testclient import TestClient
from pydantic import BaseModel
class LinkSettingsTests(unittest.TestCase):
    def setUp(self):
        app=FastAPI();self.manager=Mock()
        self.ns=dict(app=app,Depends=Depends,HTTPException=HTTPException,BaseModel=BaseModel,Optional=Optional,
                     get_current_user=lambda:{'username':'test'},_require_lock=lambda u:None,config_mgr=self.manager,DEV='devices.localhost')
        tree=ast.parse((Path(__file__).parents[1]/'opt/ffn_manager.py').read_text(encoding='utf-8'))
        for node in tree.body:
            if isinstance(node,(ast.ClassDef,ast.FunctionDef,ast.AsyncFunctionDef)) and node.name in ('InterfaceEntry','_build_iface_payload','interface_create') or isinstance(node,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='MODES' for t in node.targets):
                exec(compile(ast.Module(body=[node],type_ignores=[]),'<interface>','exec'),self.ns)
        self.client=TestClient(app)
    def test_invalid_speed_does_not_delete_candidate(self):
        response=self.client.post('/api/interfaces',json={'name':'ethernet1/2','link_speed':'1000; reboot'})
        self.assertEqual(response.status_code,422);self.manager.delete_candidate.assert_not_called()
    def test_dhcp_shape_and_static_conflict(self):
        cls=self.ns['InterfaceEntry'];build=self.ns['_build_iface_payload']
        payload=build(cls(name='ethernet1/2',dhcp_client=True))
        self.assertEqual(payload['layer3']['dhcp-client'],{'enable':'yes','create-default-route':'yes','default-route-metric':'10'})
        for change in [{'mode':'layer2'},{'ip_addresses':['192.0.2.1/24']}]:
            response=self.client.post('/api/interfaces',json={'name':'ethernet1/2','dhcp_client':True,**change})
            self.assertEqual(response.status_code,422)
        self.manager.delete_candidate.assert_not_called()
    def test_fixed_and_auto_payloads(self):
        cls=self.ns['InterfaceEntry'];build=self.ns['_build_iface_payload']
        self.assertEqual(build(cls(name='ethernet1/5',link_speed='1000'))['link-speed'],'1000')
        self.assertNotIn('link-speed',build(cls(name='ethernet1/5',link_speed='auto')))
if __name__=='__main__':unittest.main()
