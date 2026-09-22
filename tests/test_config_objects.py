import sys
import unittest
from pathlib import Path
from unittest.mock import AsyncMock
import xml.etree.ElementTree as ET
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'opt'))
from ffn_config_objects import install, revision


class Manager:
    def __init__(self):
        self.xml = '<config><shared/><devices><entry name="localhost.localdomain"><vsys><entry name="vsys1"/></vsys></entry></devices></config>'
        self.running = self.xml
        self.holder = None
    def get_candidate(self): return self.xml
    def get_running(self): return self.running
    def lock_status(self): return {'locked': bool(self.holder), 'holder': self.holder}
    def acquire_lock(self, user, reason): self.holder = user; return True
    def _save(self, root, path): self.xml = ET.tostring(root, encoding='unicode')


class ObjectTests(unittest.TestCase):
    def setUp(self):
        self.manager = Manager()
        self.role = 'admin'
        async def current():
            if self.role is None: raise HTTPException(401)
            return {'username': 'tester', 'role': self.role}
        def admin(user):
            if user['role'] not in ('admin', 'superuser'): raise HTTPException(403)
        app = FastAPI()
        self.audit = AsyncMock()
        install(app, current, admin, self.audit, self.manager, Path('unused'))
        self.client = TestClient(app)

    def create(self, kind='address', name='net', **extra):
        payload = dict(revision=revision(self.manager.xml), name=name,
                       type='ip-netmask', value='192.0.2.3/24')
        payload.update(extra)
        return self.client.post('/api/config/objects/'+kind, json=payload)

    def test_candidate_only_normalizes_and_conflicts(self):
        old = self.manager.xml
        self.assertEqual(self.create().status_code, 200)
        self.assertIn('192.0.2.0/24', self.manager.xml)
        self.assertEqual(self.manager.running, old)
        self.assertEqual(self.create(name='other', revision=revision(old)).status_code,409)
        self.assertEqual(self.create().status_code,409)

    def test_groups_references_cycles_and_delete(self):
        self.create()
        self.assertEqual(self.create('address-group','group',type='static',value='',members=['net']).status_code,200)
        url='/api/config/objects/address/net'
        self.assertEqual(len(self.client.get(url+'/references').json()['references']),1)
        self.assertEqual(self.client.delete(url,params={'revision':revision(self.manager.xml)}).status_code,409)
        before=self.manager.xml
        self.assertEqual(self.create('address-group','cycle',type='static',value='',members=['cycle']).status_code,422)
        self.assertEqual(self.manager.xml,before)
        self.assertEqual(self.create('service-group','wrong',type='static',value='',members=['net']).status_code,422)

    def test_invalid_values_and_xml_characters(self):
        for args in ({'type':'ip-range','value':'192.0.2.9-192.0.2.1'},
                     {'type':'fqdn','value':'-invalid.example'}, {'description':'\uffff'},
                     {'members':['unexpected']}):
            self.assertEqual(self.create(**args).status_code,422)
        for value in ('0','65536','443-80','80; reboot'):
            self.assertEqual(self.create('service', type='tcp',value=value).status_code,422)

    def test_scope_inheritance_and_preservation(self):
        self.create()
        data={'revision':revision(self.manager.xml),'name':'group','type':'static','members':['net']}
        self.assertEqual(self.client.post('/api/config/objects/address-group?scope=vsys1',json=data).status_code,200)
        listing=self.client.get('/api/config/objects/address-group?scope=vsys1').json()
        self.assertIn('net',[x['name'] for x in listing['member_choices']])
        self.assertEqual(self.client.get('/api/config/objects/address?scope=missing').status_code,404)
        self.manager.xml=self.manager.xml.replace('<ip-netmask>', '<tag><member>retain</member></tag><ip-netmask>')
        data={'revision':revision(self.manager.xml),'name':'net','type':'fqdn','value':'Example.COM'}
        self.assertEqual(self.client.put('/api/config/objects/address/net',json=data).status_code,200)
        self.assertIn('<member>retain</member>',self.manager.xml)
        self.assertIn('example.com',self.manager.xml)

    def test_auth_and_lock(self):
        self.role=None
        self.assertEqual(self.client.get('/api/config/objects/address').status_code,401)
        self.role='readonly'
        self.assertFalse(self.client.get('/api/config/objects/address').json()['can_edit'])
        self.assertEqual(self.create().status_code,403)
        self.role='admin';self.manager.holder='someone-else'
        self.assertEqual(self.create().status_code,423)
        self.audit.assert_not_called()

    def test_all_categories_round_trip_update_clone_delete(self):
        definitions = {
            'tag': ('tag', {'color':'color1'}),
            'region': ('region', {'addresses':['192.0.2.0/24','2001:db8::/32'], 'latitude':'-12.5','longitude':'45'}),
            'dynamic-user-group': ('dynamic', {'filter':"'tag fixture'"}),
            'application': ('custom', {'category':'business-systems','subcategory':'general','technology':'client-server','risk':'3','ports':['tcp/443','udp/53']}),
            'application-filter': ('filter', {'category':['business-systems'],'risk':['3','4']}),
            'device': ('device', {'vendor':'Example','os-family':'Linux'}),
            'external-list': ('ip', {'url':'https://example.com/list.txt','interval':'daily','time':'12:30','exceptions':['192.0.2.3']}),
        }
        for kind,(typ,settings) in definitions.items():
            with self.subTest(kind=kind):
                name=kind+' fixture'
                response=self.create(kind,name,type=typ,value='',settings=settings)
                self.assertEqual(response.status_code,200,response.text)
                row=self.client.get('/api/config/objects/'+kind).json()['entries'][0]
                self.assertTrue(row['editable'],row)
                for key,value in settings.items():self.assertEqual(row['settings'][key],value)
                row={k:v for k,v in row.items() if k not in ('kind','editable')}
                row['revision']=revision(self.manager.xml);row['description']='updated'
                response=self.client.put('/api/config/objects/'+kind+'/'+name,json=row)
                self.assertEqual(response.status_code,200,response.text)
                row.update(name=name+' clone',revision=revision(self.manager.xml))
                self.assertEqual(self.client.post('/api/config/objects/'+kind,json=row).status_code,200)
                self.assertEqual(self.client.delete('/api/config/objects/'+kind+'/'+row['name'],params={'revision':revision(self.manager.xml)}).status_code,200)
        self.assertEqual(self.create('application-group','apps',type='static',value='',members=['application fixture']).status_code,200)
        self.assertEqual(self.create('application-group','nested',type='static',value='',members=['apps']).status_code,200)
        self.assertEqual(self.client.delete('/api/config/objects/application/application fixture',params={'revision':revision(self.manager.xml)}).status_code,409)
        self.assertNotIn('application fixture',self.manager.running)

    def test_tags_dynamic_groups_references_and_shadowing(self):
        self.assertEqual(self.create('tag','office',type='tag',value='',settings={'color':'color2'}).status_code,200)
        self.assertEqual(self.create(tags=['office']).status_code,200)
        self.assertEqual(self.create('address-group','dynamic',type='dynamic',value="('office' or 'office')").status_code,200)
        refs=self.client.get('/api/config/objects/tag/office/references').json()['references']
        self.assertEqual(len(refs),2,refs)
        self.assertEqual(self.client.delete('/api/config/objects/tag/office',params={'revision':revision(self.manager.xml)}).status_code,409)
        listing=self.client.get('/api/config/objects/address-group').json()
        self.assertTrue(listing['entries'][0]['editable'])
        for value in ("'missing'", "'office' and", "not 'office'", "'office' or ()", "'office');import os"):
            before=self.manager.xml
            self.assertEqual(self.create('dynamic-user-group','bad',type='dynamic',value='',settings={'filter':value}).status_code,422)
            self.assertEqual(self.manager.xml,before)

    def test_invalid_new_settings_and_import_protection(self):
        for kind,typ,settings in [
            ('region','region',{'addresses':['bad']}),
            ('region','region',{'addresses':['192.0.2.1'],'latitude':'NaN','longitude':'0'}),
            ('device','device',{}), ('device','device',{'vendor':['bad-type']}),
            ('tag','tag',{'color':'evil'}), ('tag','tag',{'color':'none','arbitrary/path':'x'}),
            ('application-filter','filter',{'risk':['6']}),
            ('external-list','url',{'url':'file:///etc/passwd'}),
            ('external-list','url',{'url':'https://user:secret@example.com'}),
            ('external-list','url',{'url':'https://example.com','interval':'daily','time':'99:99'}),
            ('external-list','ip',{'url':'https://example.com','exceptions':['bad']}),
            ('application','custom',{'category':'x','subcategory':'x','technology':'x','risk':'1','ports':['tcp/70000']}),
        ]:
            with self.subTest(kind=kind,settings=settings):
                before=self.manager.xml
                self.assertEqual(self.create(kind,'invalid',type=typ,value='',settings=settings).status_code,422)
                self.assertEqual(self.manager.xml,before)
        self.create('device','imported',type='device',value='',settings={'vendor':'Example'})
        self.manager.xml=self.manager.xml.replace('<vendor>Example</vendor>','<vendor>Example</vendor><future><match>retain me</match></future>')
        listing=self.client.get('/api/config/objects/device').json()
        self.assertFalse(listing['entries'][0]['editable'])
        before=self.manager.xml
        response=self.client.put('/api/config/objects/device/imported',json={'revision':revision(before),'name':'imported','type':'device','settings':{'vendor':'Changed'}})
        self.assertEqual(response.status_code,409)
        self.assertEqual(self.manager.xml,before)

    def test_new_kinds_auth_revision_and_running(self):
        for kind in ('region','dynamic-user-group','application','application-group','application-filter','tag','device','external-list'):
            self.role='readonly'
            self.assertFalse(self.client.get('/api/config/objects/'+kind).json()['can_edit'])
            self.assertEqual(self.create(kind,type='tag',value='').status_code,403)
            self.role='admin'
            self.assertFalse(self.client.get('/api/config/objects/'+kind+'?source=running').json()['can_edit'])
        self.assertEqual(self.create('tag','fresh',type='tag',value='',revision='0'*64).status_code,409)

    def test_imported_application_groups_do_not_block_other_families(self):
        self.manager.xml=self.manager.xml.replace('<shared/>','<shared><application-group><entry name="imported"><members><member>vendor-predefined-app</member></members></entry></application-group></shared>')
        self.assertEqual(self.create('tag','independent',type='tag',value='').status_code,200)
        self.assertIn('vendor-predefined-app',self.manager.xml)


if __name__ == '__main__': unittest.main()
