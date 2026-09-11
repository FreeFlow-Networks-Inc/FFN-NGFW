import ast
import sys
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path
from unittest.mock import AsyncMock
from fastapi import FastAPI, Depends, HTTPException
from fastapi.testclient import TestClient
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'opt'))
from ffn_config_zones import ZoneEdit, ZoneStore, digest
from test_config_objects import Manager

class ZoneTests(unittest.TestCase):
    def setUp(self):
        self.manager=Manager()
        root=ET.fromstring(self.manager.xml)
        dev=root.find('devices/entry')
        interface=ET.SubElement(ET.SubElement(dev,'network'),'interface')
        eth=ET.SubElement(interface,'ethernet')
        for name,mode in [('ethernet1/1','layer3'),('ethernet1/2','layer2')]:
            ET.SubElement(ET.SubElement(eth,'entry',name=name),mode)
        self.manager.xml=ET.tostring(root,encoding='unicode')
        self.manager.running=self.manager.xml
        self.role='admin'
        async def current():
            if self.role is None: raise HTTPException(401)
            return {'username':'tester','role':self.role}
        self.app=FastAPI()
        namespace=dict(app=self.app,Depends=Depends,HTTPException=HTTPException,get_current_user=current,
                       ZoneEntry=ZoneEdit,ZoneStore=ZoneStore,config_mgr=self.manager,CANDIDATE_CONFIG=Path('unused'),
                       ADMIN_ROLES={'admin','superuser'},_audit=AsyncMock())
        source=ast.parse((Path(__file__).resolve().parents[1]/'opt/ffn_manager.py').read_text(encoding='utf-8'))
        for node in source.body:
            if isinstance(node,ast.AsyncFunctionDef) and node.name in ('zone_list','zone_create','zone_update','zone_delete'):
                exec(compile(ast.Module(body=[node],type_ignores=[]),'<zone-routes>','exec'),namespace)
        self.client=TestClient(self.app)
        self.url='/api/vsys/vsys1/zones'
    def payload(self,**values):
        data=dict(revision=digest(self.manager.xml),name='trust',zone_type='layer3',interfaces=['ethernet1/1'],log_setting='traffic',comment='Zone')
        data.update(values);return data
    def create(self,**values): return self.client.post(self.url,json=self.payload(**values))
    def test_listing_without_visiting_interfaces_and_source(self):
        data=self.client.get(self.url).json()
        self.assertEqual(len(data['interface_choices']),2)
        self.assertTrue(data['can_edit'])
        self.assertFalse(self.client.get(self.url+'?source=running').json()['can_edit'])
        self.assertEqual(self.client.get(self.url+'?source=bad').status_code,422)
    def test_create_update_clear_mode_and_preserve(self):
        running=self.manager.running
        self.assertEqual(self.create().status_code,200)
        self.assertEqual(self.manager.running,running)
        self.manager.xml=self.manager.xml.replace('<comment>','<custom>retain</custom><comment>')
        self.assertEqual(self.client.put(self.url+'/trust',json=self.payload(log_setting='new')).status_code,200)
        self.assertIn('<log-setting>new</log-setting>',self.manager.xml)
        self.assertIn('<custom>retain</custom>',self.manager.xml)
        self.assertEqual(self.client.put(self.url+'/trust',json=self.payload(zone_type='layer2',interfaces=['ethernet1/2'],log_setting='')).status_code,200)
        zone=ET.fromstring(self.manager.xml).find('.//zone/entry')
        self.assertIsNone(zone.find('network/layer3'))
        self.assertIsNone(zone.find('network/log-setting'))
    def test_revision_duplicate_lock_and_readonly(self):
        old=self.payload();self.create()
        self.assertEqual(self.client.put(self.url+'/trust',json=old).status_code,409)
        self.assertEqual(self.create().status_code,409)
        self.role='readonly'
        self.assertEqual(self.create(name='other').status_code,403)
        self.assertEqual(self.client.delete(self.url+'/trust',params={'revision':digest(self.manager.xml)}).status_code,403)
        self.role='admin';self.manager.holder='other'
        self.assertEqual(self.create(name='other').status_code,423)
        self.role=None;self.assertEqual(self.client.get(self.url).status_code,401)
    def test_bad_membership_and_names_do_not_change_candidate(self):
        old=self.manager.xml
        for values in [dict(interfaces=['missing']),dict(interfaces=['ethernet1/2']),dict(interfaces=['ethernet1/1']*2),dict(name="bad].name"),dict(zone_type='invalid'),dict(comment='\x00')]:
            self.assertEqual(self.create(**values).status_code,422)
            self.assertEqual(self.manager.xml,old)
        self.create()
        self.assertEqual(self.create(name='other').status_code,409)
    def test_policy_reference_blocks_delete(self):
        self.create()
        self.manager.xml=self.manager.xml.replace('</vsys>', '<entry name="other"><rulebase><security><rules><entry name="rule"><from><member>trust</member></from></entry></rules></security></rulebase></entry></vsys>')
        self.assertEqual(self.client.delete(self.url+'/trust',params={'revision':digest(self.manager.xml)}).status_code,409)
    def test_unresolved_member_retained_and_unknown_type_is_readonly(self):
        self.create()
        self.manager.xml=self.manager.xml.replace('<member>ethernet1/1</member>', '<member>retired-port</member>')
        self.assertEqual(self.client.put(self.url+'/trust',json=self.payload(interfaces=['retired-port'])).status_code,200)
        self.manager.xml=self.manager.xml.replace('<member>retired-port</member>', '<member special="yes">retired-port</member>')
        self.assertFalse(self.client.get(self.url).json()['entries'][0]['editable'])
        self.assertEqual(self.client.put(self.url+'/trust',json=self.payload(interfaces=['retired-port'])).status_code,409)
    def test_other_vsys_ownership(self):
        self.manager.xml=self.manager.xml.replace('</vsys>','<entry name="other"><import><network><interface><member>ethernet1/1</member></interface></network></import></entry></vsys>')
        self.assertEqual(self.create().status_code,409)
    def test_delete_candidate_only(self):
        self.create();running=self.manager.running
        self.assertEqual(self.client.delete(self.url+'/trust',params={'revision':digest(self.manager.xml)}).status_code,200)
        self.assertEqual(self.client.get(self.url).json()['entries'],[])
        self.assertEqual(self.manager.running,running)
if __name__=='__main__': unittest.main()
