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
    def test_subinterface_address_object_reference(self):
        root=ET.fromstring(self.manager.xml)
        root.find('devices/entry/vsys/entry').append(ET.fromstring('<address><entry name="LAN"><ip-netmask>192.0.2.9/24</ip-netmask></entry></address>'))
        self.manager.xml=ET.tostring(root,encoding='unicode')
        self.assertEqual(self.listing()['address_choices'][0]['value'],'192.0.2.9/24')
        self.assertEqual(self.create(ip_addresses=['LAN']).status_code,200)
        self.assertEqual(self.listing()['entries'][0]['ip_addresses'],['LAN'])
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
    def add_choices(self):
        root=ET.fromstring(self.manager.xml);dev=root.find('devices/entry')
        dev.find('vsys/entry').append(ET.fromstring('<zone><entry name="trust"><network><layer3/></network></entry><entry name="switch"><network><layer2/></network></entry></zone>'))
        dev.find('network').extend([ET.fromstring('<virtual-router><entry name="default"><interface/><protocol><keep/></protocol></entry><entry name="other"/></virtual-router>'),
            ET.fromstring('<vlan><entry name="users"/></vlan>'),
            ET.fromstring('<profiles><interface-management-profile><entry name="ping"/></interface-management-profile></profiles>')])
        self.manager.xml=ET.tostring(root,encoding='unicode')
    def test_choices_and_atomic_membership_candidate_save(self):
        self.add_choices();running=self.manager.running
        choices=self.listing()
        self.assertEqual(choices['zone_choices'],['trust'])
        self.assertEqual(choices['management_profile_choices'],['ping'])
        self.assertEqual(self.create(zone='trust',virtual_router='default',interface_management_profile='ping').status_code,200)
        row=self.listing()['entries'][0]
        self.assertEqual((row['zone'],row['virtual_router']),('trust','default'))
        self.assertEqual(self.manager.running,running)
        self.assertEqual(self.client.put(self.url,json=self.payload(zone='',virtual_router='other')).status_code,200)
        row=self.listing()['entries'][0]
        self.assertEqual((row['zone'],row['virtual_router']),('','other'))
        root=ET.fromstring(self.manager.xml)
        self.assertIsNotNone(root.find('.//virtual-router/entry/protocol/keep'))
        self.assertIsNone(root.find('.//virtual-router/entry[@name="default"]/interface/member'))
        self.assertEqual(self.client.put(self.url,json=self.payload()).status_code,200)
        self.assertEqual(self.listing()['entries'][0]['virtual_router'],'other')
    def test_bad_references_are_atomic_and_layer_specific(self):
        self.add_choices();before=self.manager.xml
        for changes in [dict(zone='switch'),dict(zone='missing'),dict(zone='trust',virtual_router='missing'),
                        dict(interface_management_profile='missing'),dict(vlan='users'),dict(ip_addresses=['192.0.2.1'])]:
            self.assertEqual(self.create(**changes).status_code,422,changes)
            self.assertEqual(self.manager.xml,before)
        self.assertEqual(self.create(parent='ethernet1/2',mode='layer2',ip_addresses=[],zone='switch',vlan='users').status_code,200)
        data=self.client.get(self.url,params={'parent':'ethernet1/2'}).json()
        self.assertEqual(data['zone_choices'],['switch'])
        self.assertEqual(data['entries'][0]['vlan'],'users')
        self.assertEqual(self.client.put(self.url,json=self.payload(parent='ethernet1/2',mode='layer2',ip_addresses=[],virtual_router='default')).status_code,422)
    def test_unresolved_profile_is_preserved_but_cannot_be_newly_assigned(self):
        self.create()
        self.manager.xml=self.manager.xml.replace('<tag>100</tag>','<tag>100</tag><interface-management-profile>retired</interface-management-profile>')
        self.assertEqual(self.client.put(self.url,json=self.payload(interface_management_profile='retired')).status_code,200)
        self.assertEqual(self.create(unit=2,tag=200,interface_management_profile='retired').status_code,422)
    def test_conflicting_memberships_rejected_without_losing_configuration(self):
        self.add_choices();self.create(virtual_router='default')
        self.manager.xml=self.manager.xml.replace('<entry name="other" />','<entry name="other"><interface><member>ethernet1/1.1</member></interface></entry>')
        self.assertFalse(self.listing()['entries'][0]['editable'])
        before=self.manager.xml
        self.assertEqual(self.client.put(self.url,json=self.payload(virtual_router='default')).status_code,409)
        self.assertEqual(self.manager.xml,before)
if __name__=='__main__':unittest.main()
