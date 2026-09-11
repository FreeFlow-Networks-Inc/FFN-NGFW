import ast
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path
from unittest.mock import AsyncMock
from fastapi import Depends, HTTPException, Query
from test_config_zones import ZoneTests
from ffn_config_subinterfaces import SubinterfaceEdit, SubinterfaceStore
from ffn_config_zones import digest

class SubinterfaceTests(unittest.TestCase):
    def setUp(self):
        ZoneTests.setUp(self)
        async def current():
            if self.role is None: raise HTTPException(401)
            return {'username':'tester','role':self.role}
        namespace=dict(app=self.app,Depends=Depends,Query=Query,HTTPException=HTTPException,get_current_user=current,
                       SubInterfaceEntry=SubinterfaceEdit,SubinterfaceStore=SubinterfaceStore,config_mgr=self.manager,CANDIDATE_CONFIG=Path('unused'),
                       ADMIN_ROLES={'admin','superuser'},_audit=AsyncMock())
        source=ast.parse((Path(__file__).resolve().parents[1]/'opt/ffn_manager.py').read_text(encoding='utf-8'))
        methods=('subinterface_list','subinterface_create','subinterface_update','subinterface_delete')
        for node in source.body:
            if isinstance(node,ast.AsyncFunctionDef) and node.name in methods:
                exec(compile(ast.Module(body=[node],type_ignores=[]),'<subinterface-routes>','exec'),namespace)
        self.url='/api/config/subinterfaces'
    def payload(self,**values):
        data=dict(parent='ethernet1/1',unit=1,tag=100,mode='layer3',vsys='vsys1',revision=digest(self.manager.xml),ip_addresses=['192.0.2.1/24'])
        data.update(values);return data
    def create(self,**values):return self.client.post(self.url,json=self.payload(**values))
    def listing(self):return self.client.get(self.url,params={'parent':'ethernet1/1'}).json()
    def delete(self):return self.client.delete(self.url,params={'parent':'ethernet1/1','unit':1,'revision':digest(self.manager.xml)})
    def test_unit_and_tag_are_separate_candidate_only(self):
        running=self.manager.running
        self.assertEqual(self.create().status_code,200)
        row=self.listing()['entries'][0]
        self.assertEqual(row['name'],'ethernet1/1.1');self.assertEqual(row['tag'],'100')
        self.assertEqual(self.manager.running,running)
        self.assertIn('<member>ethernet1/1.1</member>',self.manager.xml)
    def test_edit_replaces_addresses_and_clears_fields(self):
        self.create(mtu=1500,comment='before')
        self.manager.xml=self.manager.xml.replace('<tag>100</tag>','<adjust-tcp-mss><enable>no</enable></adjust-tcp-mss><tag>100</tag>')
        result=self.client.put(self.url,json=self.payload(ip_addresses=['198.51.100.1/24'],mtu=None,comment=''))
        self.assertEqual(result.status_code,200)
        row=self.listing()['entries'][0]
        self.assertEqual(row['ip_addresses'],['198.51.100.1/24']);self.assertEqual(row['mtu'],'');self.assertEqual(row['comment'],'')
        self.assertIn('<adjust-tcp-mss>',self.manager.xml)
    def test_layer2_and_parent_validation(self):
        self.assertEqual(self.create(parent='ethernet1/2',mode='layer2',ip_addresses=[]).status_code,200)
        self.assertIn('<layer2><units>',self.manager.xml)
        self.assertEqual(self.create(parent='ethernet1/2').status_code,409)
        self.assertEqual(self.create(parent='ethernet1/99').status_code,404)
    def test_invalid_values_and_duplicate_vlan(self):
        before=self.manager.xml
        for changes in [dict(tag=4095),dict(tag=0),dict(unit=0),dict(ip_addresses=['invalid']),dict(mtu=100),dict(ip_addresses=['2001:db8::1/64'],mtu=1000),dict(parent='bad]')]:
            self.assertEqual(self.create(**changes).status_code,422);self.assertEqual(self.manager.xml,before)
        self.create()
        self.assertEqual(self.create(unit=2).status_code,409)
    def test_stale_revision_and_auth(self):
        old=self.payload();self.create()
        self.assertEqual(self.client.put(self.url,json=old).status_code,409)
        self.role='readonly';self.assertEqual(self.delete().status_code,403)
        self.assertFalse(self.listing()['can_edit'])
        self.role='admin';self.manager.holder='other';self.assertEqual(self.delete().status_code,423)
    def test_references_block_deletion_then_import_is_removed(self):
        self.create()
        self.manager.xml=self.manager.xml.replace('</vsys>', '<entry name="other"><zone><entry name="trust"><network><layer3><member>ethernet1/1.1</member></layer3></network></entry></zone></entry></vsys>')
        self.assertEqual(self.delete().status_code,409)
        root=ET.fromstring(self.manager.xml);vsys=root.find('devices/entry/vsys');vsys.remove(vsys.findall('entry')[1]);self.manager.xml=ET.tostring(root,encoding='unicode')
        self.assertEqual(self.delete().status_code,200);self.assertNotIn('ethernet1/1.1',self.manager.xml)
    def test_imported_settings_are_not_discarded(self):
        self.create();self.manager.xml=self.manager.xml.replace('<tag>100</tag>','<tag>100</tag><custom>keep</custom>')
        self.assertFalse(self.listing()['entries'][0]['editable'])
        old=self.manager.xml
        self.assertEqual(self.client.put(self.url,json=self.payload()).status_code,409)
        self.assertEqual(self.manager.xml,old)
    def test_legacy_delete_is_registered_before_catchall(self):
        source=(Path(__file__).resolve().parents[1]/'opt/ffn_manager.py').read_text(encoding='utf-8')
        self.assertLess(source.index('@app.delete("/api/interfaces/subinterface")'),source.index('@app.delete("/api/interfaces/{name:path}")'))
        self.create()
        self.assertEqual(self.client.delete('/api/interfaces/subinterface',params={'parent':'ethernet1/1','unit':1,'revision':digest(self.manager.xml)}).status_code,200)
if __name__=='__main__':unittest.main()
