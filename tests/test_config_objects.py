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


if __name__ == '__main__': unittest.main()
