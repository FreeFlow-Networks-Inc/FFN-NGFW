import sys
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path
from unittest.mock import AsyncMock
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'opt'))
from ffn_config_interfaces import install
from ffn_config_zones import digest
from test_config_objects import Manager

class InterfaceEditorTests(unittest.TestCase):
    def setUp(self):
        self.manager=Manager();root=ET.fromstring(self.manager.xml);dev=root.find('devices/entry')
        dev.append(ET.fromstring('''<network><interface><ethernet><entry name="ethernet1/1"><layer3><ip><entry name="192.0.2.1/24"/></ip><units><entry name="ethernet1/1.100"><tag>100</tag><custom>keep</custom></entry></units><adjust-tcp-mss><enable>yes</enable></adjust-tcp-mss></layer3><vendor>retain</vendor></entry><entry name="ethernet1/2"/></ethernet><aggregate-ethernet><entry name="ae1"><layer3><bond><mode>802.3ad</mode><miimon>100</miimon></bond><lacp><enable>yes</enable></lacp></layer3></entry></aggregate-ethernet></interface><virtual-router><entry name="default"><interface/></entry></virtual-router><vlan><entry name="users"/></vlan><profiles><interface-management-profile><entry name="ping"/></interface-management-profile><lldp-profile><entry name="discovery"/></lldp-profile></profiles></network>'''))
        dev.find('vsys/entry').append(ET.fromstring('<zone><entry name="trust"><network><layer3/></network></entry><entry name="switch"><network><layer2/></network></entry></zone>'))
        self.manager.xml=ET.tostring(root,encoding='unicode');self.manager.running=self.manager.xml
        self.role='admin'
        async def user():
            if self.role is None: raise HTTPException(401)
            return {'username':'tester','role':self.role}
        app=FastAPI();install(app,user,AsyncMock(),self.manager,Path('unused'),lambda:{'ethernet1/1','ethernet1/2','ethernet1/3'})
        self.client=TestClient(app);self.url='/api/config/interfaces'
    def data(self,**values):
        body=dict(name='ethernet1/1',mode='layer3',vsys='vsys1',revision=digest(self.manager.xml),ip_addresses=['198.51.100.1/24'],zone='trust',virtual_router='default')
        body.update(values);return body
    def save(self,**values): return self.client.put(self.url,json=self.data(**values))
    def listing(self,name='ethernet1/1',**params): return self.client.get(self.url,params={'name':name,**params})
    def test_atomic_save_preserves_children_custom_and_running(self):
        before=self.manager.running
        self.assertEqual(self.save(interface_management_profile='ping',lldp_enabled=True,lldp_profile='discovery').status_code,200)
        root=ET.fromstring(self.manager.xml)
        self.assertEqual(root.findtext('.//units/entry/custom'),'keep')
        self.assertEqual(root.findtext('.//ethernet/entry/vendor'),'retain')
        self.assertEqual(root.findtext('.//adjust-tcp-mss/enable'),'yes')
        row=self.listing().json()['entry'];self.assertEqual((row['zone'],row['virtual_router']),('trust','default'))
        self.assertEqual(row['ip_addresses'],['198.51.100.1/24'])
        self.assertEqual(self.manager.running,before)
    def test_invalid_values_and_refs_do_not_save(self):
        before=self.manager.xml
        for change in [dict(ip_addresses=['invalid']),dict(ip_addresses=['192.0.2.1']),dict(mtu=100),dict(mtu=1000,ip_addresses=['2001:db8::1/64']),dict(zone='switch'),dict(virtual_router='missing'),dict(interface_management_profile='missing'),dict(link_speed='invalid'),dict(dhcp_client=True),dict(name='ethernet1/99'),dict(comment='\x00')]:
            self.assertEqual(self.save(**change).status_code,422,change);self.assertEqual(self.manager.xml,before)
    def test_stale_readonly_lock_and_sources(self):
        stale=self.data();self.save()
        self.assertEqual(self.client.put(self.url,json=stale).status_code,409)
        self.role='readonly';self.assertFalse(self.listing().json()['can_edit']);self.assertEqual(self.save().status_code,403)
        self.role='admin';self.manager.holder='other';self.assertEqual(self.save().status_code,423)
        self.assertFalse(self.listing(source='running').json()['can_edit']);self.assertEqual(self.listing(source='bad').status_code,422)
        self.role=None;self.assertEqual(self.listing().status_code,401)
    def test_mode_change_does_not_delete_subinterfaces(self):
        before=self.manager.xml
        self.assertEqual(self.save(mode='none',ip_addresses=[],zone='',virtual_router='').status_code,409)
        self.assertEqual(self.manager.xml,before)
    def test_none_default_link_disabled_and_new_data_port_validation(self):
        spec=dict(name='ethernet1/3',revision=digest(self.manager.xml),link_state='up')
        self.assertEqual(self.client.put(self.url,json=spec).status_code,200)
        row=self.listing('ethernet1/3').json()['entry'];self.assertEqual((row['mode'],row['link_state']),('none','down'))
        self.assertEqual(self.listing('eth0').status_code,422)
    def test_l2_memberships_then_mode_change_clears_parent_references(self):
        self.assertEqual(self.save(name='ethernet1/2',mode='layer2',ip_addresses=[],zone='switch',virtual_router='',vlan='users').status_code,200)
        self.assertEqual(self.listing('ethernet1/2').json()['entry']['vlan'],'users')
        self.assertEqual(self.save(name='ethernet1/2',mode='layer3').status_code,200)
        root=ET.fromstring(self.manager.xml)
        self.assertIsNone(root.find('.//vlan/entry/interface/member'));self.assertIsNone(root.find('.//zone/entry/network/layer2/member'))
    def test_dhcp_metric_and_lacp_options_roundtrip(self):
        self.assertEqual(self.save(name='ae1',dhcp_client=True,ip_addresses=[],dhcp_route_metric=23,bond_mode='802.3ad').status_code,200)
        row=self.listing('ae1').json()['entry'];self.assertTrue(row['dhcp_client']);self.assertEqual(row['dhcp_route_metric'],'23')
        self.assertEqual(ET.fromstring(self.manager.xml).findtext('.//lacp/enable'),'yes')
    def test_aggregate_member_link_settings_and_bad_target(self):
        args=dict(name='ethernet1/2',mode='aggregate-group',ip_addresses=[],zone='',virtual_router='',aggregate_group='ae1',link_speed='40000')
        self.assertEqual(self.save(**args).status_code,200)
        row=self.listing('ethernet1/2').json()['entry'];self.assertEqual((row['aggregate_group'],row['link_speed']),('ae1','40000'))
        args['aggregate_group']='ae99';before=self.manager.xml;self.assertEqual(self.save(**args).status_code,422);self.assertEqual(self.manager.xml,before)
    def test_actual_vsys_ownership_and_duplicate_membership(self):
        root=ET.fromstring(self.manager.xml);vsys=root.find('.//vsys')
        vsys.append(ET.fromstring('<entry name="vsys2"><import><network><interface><member>ethernet1/1</member></interface></network></import></entry>'))
        self.manager.xml=ET.tostring(root,encoding='unicode')
        self.assertEqual(self.listing().json()['vsys'],'vsys2')
        self.assertEqual(self.save().status_code,409)

if __name__=='__main__':unittest.main()
