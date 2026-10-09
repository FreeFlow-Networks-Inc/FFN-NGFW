import sys
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path
from unittest.mock import AsyncMock
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'opt'))
import ffn_config_dhcp as cfg
from test_config_objects import Manager

CONFIG = '''<config><shared><address><entry name="lan-ip"><ip-netmask>10.1.0.2/22</ip-netmask></entry></address></shared>
<devices><entry name="localhost.localdomain"><vsys><entry name="vsys1"><import><network><interface>
<member>ethernet1/1</member><member>ethernet1/5</member><member>ae1.69</member></interface></network></import></entry></vsys>
<network><interface>
 <ethernet>
  <entry name="ethernet1/1"><layer3><dhcp-client><enable>yes</enable></dhcp-client></layer3></entry>
  <entry name="ethernet1/5"><layer3><ip><entry name="192.0.2.1/24"/></ip></layer3></entry>
  <entry name="ethernet1/7"><layer2/></entry>
 </ethernet>
 <aggregate-ethernet><entry name="ae1"><layer3><units><entry name="ae1.69"><tag>69</tag><ip><entry name="lan-ip"/></ip></entry></units></layer3></entry></aggregate-ethernet>
</interface></network></entry></devices></config>'''


class ConfigDhcpTests(unittest.TestCase):
    def setUp(self):
        self.manager = Manager()
        self.manager.xml = CONFIG
        self.manager.running = CONFIG
        self.role = 'admin'
        async def current():
            if self.role is None:
                raise HTTPException(401)
            return {'username': 'tester', 'role': self.role}
        def admin(user):
            if user['role'] not in ('admin', 'superuser'):
                raise HTTPException(403)
        self.app = FastAPI()
        self.audit = AsyncMock()
        self.plane = lambda: dict(available=False, reason='no daemon in this test')
        cfg.install(self.app, current, admin, self.audit, self.manager, Path('unused'), plane=lambda: self.plane())
        self.client = TestClient(self.app)

    def revision(self):
        return cfg.digest(self.manager.get_candidate())

    def payload(self, **values):
        data = dict(revision=self.revision(), interface='ae1.69', mode='enabled', probe_ip=False, lease_minutes=1440,
                    pools=['10.1.0.100-10.1.0.199', '10.1.1.10'], reserved=[dict(ip='10.1.0.50', mac='02:11:22:33:44:99', description='printer')],
                    options=dict(gateway='', subnet_mask='', dns=['1.1.1.1', '8.8.8.8'], ntp=[], wins=[], dns_suffix='lan'))
        data.update(values)
        return data

    def test_listing_offers_only_dataplane_layer3_interfaces_with_addresses(self):
        data = self.client.get('/api/config/dhcp').json()
        self.assertTrue(data['can_edit']); self.assertEqual(data['entries'], [])
        choices = {c['name']: c for c in data['interface_choices']}
        self.assertEqual(set(choices), {'ethernet1/1', 'ethernet1/5', 'ae1.69'})
        self.assertEqual(choices['ae1.69']['addresses'], ['10.1.0.2/22'])      # resolved from the address object
        self.assertTrue(choices['ethernet1/1']['dhcp_client']); self.assertEqual(choices['ethernet1/1']['addresses'], [])
        self.assertFalse(self.client.get('/api/config/dhcp?source=running').json()['can_edit'])
        self.assertEqual(self.client.get('/api/config/dhcp?source=bad').status_code, 422)

    def test_create_writes_the_pan_os_shape_and_compiles_to_the_dataplane_intent(self):
        response = self.client.put('/api/config/dhcp', json=self.payload())
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual((response.json()['status'], response.json()['requires_commit']), ('created', True))
        self.assertEqual(self.manager.running, CONFIG)   # candidate only
        root = ET.fromstring(self.manager.xml)
        entry = root.find(".//network/dhcp/interface/entry[@name='ae1.69']/server")
        self.assertEqual(entry.findtext('mode'), 'enabled'); self.assertEqual(entry.findtext('probe-ip'), 'no')
        self.assertEqual([m.text for m in entry.findall('ip-pool/member')], ['10.1.0.100-10.1.0.199', '10.1.1.10'])
        self.assertEqual(entry.find("reserved/entry[@name='10.1.0.50']").findtext('mac'), '02:11:22:33:44:99')
        self.assertEqual(entry.findtext('option/lease/timeout'), '1440')
        self.assertEqual((entry.findtext('option/dns/primary'), entry.findtext('option/dns/secondary'), entry.findtext('option/dns-suffix')), ('1.1.1.1', '8.8.8.8', 'lan'))
        listing = self.client.get('/api/config/dhcp').json()
        row = listing['entries'][0]
        self.assertEqual((row['interface'], row['device'], row['address'], row['problems'], row['options']['dns']), ('ae1.69', 'ae1.69', '10.1.0.2/22', [], ['1.1.1.1', '8.8.8.8']))
        self.assertTrue([c for c in listing['interface_choices'] if c['name'] == 'ae1.69'][0]['has_server'])
        intent = cfg.compile_intent(root)
        spec = intent['servers']['ae1.69']
        self.assertEqual((spec['address'], spec['pools'], spec['reserved'], spec['lease'], spec['options']),
                         ('10.1.0.2/22', [['10.1.0.100', '10.1.0.199'], ['10.1.1.10', '10.1.1.10']], {'02:11:22:33:44:99': '10.1.0.50'}, 86400,
                          dict(dns=['1.1.1.1', '8.8.8.8'], domain='lan')))
        self.audit.assert_awaited()

    def test_physical_port_maps_to_its_dataplane_device_and_disabled_servers_compile_to_nothing(self):
        self.assertEqual(self.client.put('/api/config/dhcp', json=self.payload(interface='ethernet1/5', pools=['192.0.2.100-192.0.2.150'], reserved=[], options={})).status_code, 200)
        self.assertEqual(sorted(cfg.compile_intent(ET.fromstring(self.manager.xml))['servers']), ['p5'])
        self.assertEqual(self.client.put('/api/config/dhcp', json=self.payload(interface='ethernet1/5', mode='disabled', pools=['192.0.2.100-192.0.2.150'], reserved=[], options={}, lease_minutes=None)).status_code, 200)
        self.assertEqual(cfg.compile_intent(ET.fromstring(self.manager.xml))['servers'], {})
        self.assertIsNotNone(ET.fromstring(self.manager.xml).find(".//entry[@name='ethernet1/5']/server/option/lease/unlimited"))

    def test_validation_refuses_bad_servers_with_the_daemon_rules(self):
        cases = [
            (dict(interface='ethernet1/1'), 'DHCP client'),
            (dict(interface='ethernet1/7'), 'not configured as layer3'),
            (dict(interface='loopback.1'), 'ethernet1/N'),
            (dict(pools=['10.2.0.1-10.2.0.9']), 'outside'),
            (dict(pools=['10.1.0.1-10.1.0.9']), 'interface address'),
            (dict(pools=['nope']), 'first-last range'),
            (dict(pools=[], reserved=[]), 'pool or a reservation'),
            (dict(reserved=[dict(ip='10.1.0.50', mac='zz:zz:zz:zz:zz:zz')]), 'MAC'),
            (dict(reserved=[dict(ip='10.1.0.50', mac='02:11:22:33:44:99'), dict(ip='10.1.0.51', mac='02:11:22:33:44:99')]), 'unique'),
            (dict(options=dict(dns=['x'])), 'dns'),
            (dict(options=dict(dns_suffix='-bad')), 'domain'),
        ]
        for changes, text in cases:
            with self.subTest(text=text):
                response = self.client.put('/api/config/dhcp', json=self.payload(**changes))
                self.assertEqual(response.status_code, 422, response.text)
                self.assertIn(text, response.json()['detail'])
        self.assertEqual(self.client.put('/api/config/dhcp', json=self.payload(lease_minutes=0)).status_code, 422)
        self.assertEqual(self.client.put('/api/config/dhcp', json=self.payload(extra=1)).status_code, 422)

    def test_revision_lock_role_and_delete(self):
        self.assertEqual(self.client.put('/api/config/dhcp', json=self.payload(revision='0' * 64)).status_code, 409)
        self.manager.holder = 'someone-else'
        self.assertEqual(self.client.put('/api/config/dhcp', json=self.payload()).status_code, 423)
        self.manager.holder = None
        self.role = 'operator'
        self.assertEqual(self.client.put('/api/config/dhcp', json=self.payload()).status_code, 403)
        self.role = 'admin'
        self.assertEqual(self.client.put('/api/config/dhcp', json=self.payload()).status_code, 200)
        self.manager.xml = self.manager.xml.replace('<server>', '<server><custom>keep</custom>')
        self.assertEqual(self.client.put('/api/config/dhcp', json=self.payload(pools=['10.1.0.100-10.1.0.110'])).json()['status'], 'updated')
        self.assertIn('<custom>keep</custom>', self.manager.xml)
        self.assertEqual(len(ET.fromstring(self.manager.xml).findall('.//ip-pool/member')), 1)
        self.assertEqual(self.client.delete('/api/config/dhcp/ae1.69?revision=' + '0' * 64).status_code, 409)
        self.assertEqual(self.client.delete('/api/config/dhcp/ae1.69?revision=' + self.revision()).json()['status'], 'deleted')
        self.assertIsNone(ET.fromstring(self.manager.xml).find(".//network/dhcp/interface/entry"))
        self.assertEqual(self.client.delete('/api/config/dhcp/ae1.69?revision=' + self.revision()).status_code, 404)

    def test_status_joins_the_committed_servers_with_the_daemon_view(self):
        self.client.put('/api/config/dhcp', json=self.payload())
        self.manager.running = self.manager.xml   # as if committed
        view = self.client.get('/api/dhcp/status').json()
        self.assertEqual((view['available'], view['servers'][0]['state']), (False, 'unavailable'))
        self.assertEqual(self.client.get('/api/dhcp/leases').json()['available'], False)
        self.plane = lambda: dict(available=True, config=dict(revision=3, configuration='c' * 64, servers={'ae1.69': {}}), boot_id='b',
                                  running=dict(revision=3, time=1000.0, servers={'ae1.69': dict(state='serving', detail='', address='10.1.0.2/22', bound=2, offered=0, declined=0, pool_size=101,
                                                                                                counters={'discover': 5}, last_event=999.0,
                                                                                                leases=[dict(ip='10.1.0.100', mac='02:00:00:00:00:01', hostname='laptop', state='bound', since=900.0, expires=4500.0)])}))
        view = self.client.get('/api/dhcp/status').json()
        row = view['servers'][0]
        self.assertEqual((view['available'], view['revision'], row['state'], row['bound'], row['pool_size'], row['device']), (True, 3, 'serving', 2, 101, 'ae1.69'))
        self.assertEqual(view['leases'][0]['interface'], 'ae1.69')
        leases = self.client.get('/api/dhcp/leases').json()
        self.assertEqual((leases['available'], leases['count'], leases['leases'][0]['hostname'], leases['leases'][0]['interface']), (True, 1, 'laptop', 'ae1.69'))
        self.plane = lambda: dict(available=True, config=dict(revision=4, configuration=None, servers={}), boot_id='b', running=None)
        self.assertEqual(self.client.get('/api/dhcp/status').json()['servers'][0]['state'], 'pending')

    def test_device_mapping(self):
        self.assertEqual([cfg.dp_device(n) for n in ('ethernet1/5', 'ethernet1/12.100', 'ae1', 'ae2.69')], ['p5', 'p12.100', 'ae1', 'ae2.69'])
        for bad in ('loopback.1', 'tunnel.5', 'vlan.10', 'ethernet2/1', 'eth0'):
            with self.assertRaises(ValueError):
                cfg.dp_device(bad)


if __name__ == '__main__':
    unittest.main()
