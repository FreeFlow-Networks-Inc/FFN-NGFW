import copy
import io
import json
import unittest
import xml.etree.ElementTree as ET
from contextlib import redirect_stdout
from unittest.mock import Mock
import test_policy_config
from ffn_policy_config import parse, revision, runtime_report, require_supported, PolicyError
from ffn_policy_cli import handle
from ffn_vrrp import DEFAULTS, NETWORK, PATH, plan, validate, inventory


class VrrpTests(unittest.TestCase):
    def setUp(self):
        self.f = test_policy_config.PolicyTests(); self.f.setUp(); self.addCleanup(self.f.tearDown)
        self.path = self.f.directory / 'candidate-config.xml'
        root = parse(self.path.read_bytes()); network = root.find(NETWORK)
        network.find('interface/ethernet/entry/layer3').append(ET.fromstring('<ip><entry name="192.0.2.2/24"/><entry name="2001:db8::2/64"/></ip>'))
        for number in (2, 3, 4):
            network.find('interface/ethernet').append(ET.fromstring(f'<entry name="ethernet1/{number}"><layer2/></entry>'))
        network.append(ET.fromstring('<vlan><entry name="isp-segment"><interface><member>ethernet1/2</member><member>ethernet1/3</member></interface></entry></vlan>'))
        owner = root.find("./devices/entry/vsys/entry[@name='vsys1']")
        owner.append(ET.fromstring('<import><network><interface>' + ''.join(f'<member>ethernet1/{n}</member>' for n in (1, 2, 3)) + '</interface></network></import>'))
        owner.append(ET.fromstring('<address><entry name="shared-gateway"><ip-netmask>192.0.2.1/24</ip-netmask></entry></address>'))
        self.path.write_bytes(ET.tostring(root))
        (self.f.directory / 'running-config.xml').write_bytes(self.path.read_bytes())

    def get(self, source='candidate'):
        return self.f.client.get('/api/config/network/vrrp?source=' + source).json()

    def spec(self, mode='participate', **kwargs):
        base = dict(copy.deepcopy(DEFAULTS[mode]), name='isp', mode=mode)
        base.update(dict(interface='ethernet1/1', virtual_addresses=['shared-gateway']) if mode == 'participate' else dict(domain='isp-segment'))
        base.update(kwargs); return base

    def put(self, spec=None, action='create', **extra):
        spec = self.spec() if spec is None else spec
        payload = dict(action=action, name=spec['name'], revision=revision(self.path.read_bytes()))
        if action != 'delete': payload['entry'] = spec
        payload.update(extra)
        return self.f.client.post('/api/config/network/vrrp', json=payload)

    def test_modes_roundtrip_and_running_unchanged(self):
        before = self.f.manager.get_running()
        for mode in DEFAULTS:
            spec = self.spec(mode)
            r = self.put(spec); self.assertEqual(r.status_code, 200, r.text)
            self.assertEqual(self.get()['entries'][0], spec)
            self.assertEqual(self.get('running')['entries'], [])
            self.assertTrue(runtime_report(self.path.read_bytes())['valid'])
            self.assertEqual(self.put(spec, 'delete').status_code, 200)
        self.assertEqual(self.f.manager.get_running(), before)

    def test_participation_object_resolution_protocol_mac_and_no_routing(self):
        self.put(); row = self.get()['plan']['entries'][0]
        self.assertEqual(row['resolved_addresses'], ['192.0.2.1/24'])
        self.assertEqual(row['virtual_addresses'], ['shared-gateway'])
        self.assertEqual(row['virtual_mac'], '00:00:5e:00:01:01')
        self.assertEqual(row['advertisements'], [dict(family='ipv4', protocol=112, destination='224.0.0.18', hop_limit=255)])
        self.assertEqual(row['initial_state'], 'BACKUP'); self.assertFalse(row['route_advertisements'])

    def test_ipv6_and_vrid_scoped_by_family(self):
        self.assertEqual(self.put(self.spec(enabled=True)).status_code, 200)
        r = self.put(self.spec(name='v6', enabled=True, family='ipv6', virtual_addresses=['2001:db8::1/64']))
        self.assertEqual(r.status_code, 200, r.text)
        row = self.get()['plan']['entries'][1]
        self.assertEqual(row['virtual_mac'], '00:00:5e:00:02:01')
        self.assertEqual(row['advertisements'][0]['destination'], 'ff02::12')

    def test_passthrough_uses_configured_domain_without_foreign_interfaces(self):
        self.put(self.spec('passthrough')); data = self.get(); row = data['plan']['entries'][0]
        self.assertEqual(row['interfaces'], ['ethernet1/2', 'ethernet1/3'])
        self.assertNotIn('ethernet1/4', [i['name'] for i in data['choices']['interfaces']])
        self.assertEqual(row['forwarding_scope'], 'same-bridge-and-vlan-only')
        self.assertEqual(len(row['advertisements']), 2); self.assertFalse(row['route_advertisements'])
        self.assertEqual(self.put(self.spec('passthrough', domain='unknown'), 'update').status_code, 422)

    def test_invalid_fields_leave_candidate_unchanged(self):
        invalid = [dict(vrid=0), dict(vrid=256), dict(priority=255), dict(priority=True), dict(advert_ms=101),
                   dict(advert_ms=50000), dict(preempt='yes'), dict(enabled=1), dict(mode=[]), dict(family={}),
                   dict(interface='mgmt0'), dict(interface='ethernet1/2'), dict(scope='vsys2'),
                   dict(track_interfaces=['ethernet1/1']), dict(track_interfaces=['ethernet1/4']),
                   dict(virtual_addresses=['192.0.2.0/24']), dict(virtual_addresses=['192.0.2.255/24']),
                   dict(virtual_addresses=['192.0.2.2/24']), dict(virtual_addresses=['198.51.100.1/24']),
                   dict(virtual_addresses=['192.0.2.1/32']), dict(virtual_addresses=['224.0.0.18/24']),
                   dict(virtual_addresses=['shared-gateway','192.0.2.1/24']), dict(virtual_addresses=[]),
                   dict(virtual_addresses=['missing-object']), dict(unknown='field')]
        before = self.path.read_bytes()
        for values in invalid:
            with self.subTest(values=values):
                r = self.put(dict(self.spec(), **values)); self.assertEqual(r.status_code, 422, r.text)
                self.assertEqual(self.path.read_bytes(), before)

    def test_duplicate_active_id_and_vip(self):
        self.put(self.spec(enabled=True))
        for spec in (self.spec(name='second', enabled=True), self.spec(name='second', enabled=True, vrid=2)):
            self.assertEqual(self.put(spec).status_code, 422)
        self.assertEqual(self.put(self.spec(name='disabled-copy')).status_code, 200)

    def test_overlapping_passthrough(self):
        self.put(self.spec('passthrough', enabled=True))
        self.assertEqual(self.put(self.spec('passthrough', name='second', enabled=True, family='ipv4')).status_code, 422)

    def test_enabled_modes_block_commit_without_provider(self):
        for mode in DEFAULTS:
            spec = self.spec(mode, enabled=True)
            self.assertEqual(self.put(spec).status_code, 200)
            report = runtime_report(self.path.read_bytes())
            self.assertFalse(report['valid']); self.assertEqual(report['blockers'][0]['kind'], 'vrrp')
            self.assertIn('not commissioned', report['blockers'][0]['reason'])
            with self.assertRaises(PolicyError): require_supported(self.path.read_bytes())
            self.put(spec, 'delete')

    def test_object_and_interface_changes_revalidated_at_commit(self):
        self.put()
        root = parse(self.path.read_bytes()); root.find('.//address/entry/ip-netmask').text = '198.51.100.1/24'
        self.assertFalse(plan(root)['valid'])
        root = parse(self.path.read_bytes()); root.find(NETWORK + '/interface/ethernet').remove(root.find(NETWORK + '/interface/ethernet/entry'))
        self.assertFalse(plan(root)['valid'])

    def test_auth_revision_lock_outage_and_running_write(self):
        self.f.role = None
        self.assertEqual(self.f.client.get('/api/config/network/vrrp').status_code, 401)
        self.f.role = 'viewer'; self.assertFalse(self.get()['can_edit']); self.assertEqual(self.put().status_code, 403)
        self.f.role = 'admin'; self.f.manager.holder = 'other'; self.assertEqual(self.put().status_code, 423)
        self.f.manager.holder = None; self.assertEqual(self.put(revision='0'*64).status_code, 409)
        self.assertEqual(self.f.client.post('/api/config/network/vrrp?source=running', json=dict(action='delete',name='isp',revision=self.get()['revision'])).status_code, 403)
        self.f.gateway.query = Mock(side_effect=RuntimeError('offline'))
        before = self.path.read_bytes(); self.assertEqual(self.put().status_code, 503); self.assertEqual(self.path.read_bytes(), before)

    def test_unknown_import_cannot_bypass_commit(self):
        self.put()
        for transform in ('unknown-field', 'duplicate-json', 'duplicate-container', 'unknown-child'):
            root = parse(self.path.read_bytes()); entry = root.find(PATH + '/entry')
            if transform == 'unknown-field': ET.SubElement(entry, 'future')
            elif transform == 'duplicate-json': entry.find('settings').text = '{"name":"isp","name":"other"}'
            elif transform == 'duplicate-container': root.find(NETWORK).append(copy.deepcopy(root.find(PATH)))
            else: ET.SubElement(root.find(PATH), 'future')
            self.assertFalse(plan(root)['valid'])
            self.assertFalse(runtime_report(ET.tostring(root))['valid'])

    def test_unknown_json_fields_cannot_be_silently_deleted(self):
        self.put(); root = parse(self.path.read_bytes())
        setting = root.find(PATH + '/entry/settings'); value = json.loads(setting.text)
        value['future_setting'] = 'keep'; setting.text = json.dumps(value)
        self.path.write_bytes(ET.tostring(root)); before = self.path.read_bytes()
        self.assertEqual(self.put(action='delete').status_code, 422)
        self.assertEqual(self.put(action='update').status_code, 422)
        self.assertEqual(self.path.read_bytes(), before)

    def test_cli_uses_same_candidate_controller(self):
        calls = []
        def api(path, method='GET', body=None, token=None):
            r = self.f.client.request(method, path, json=body); calls.append(r.status_code); return r.json()
        with redirect_stdout(io.StringIO()):
            self.assertTrue(handle(['request','policies','vrrp','add','isp','interface=ethernet1/1','virtual_addresses=shared-gateway'], api, 'fixture'))
            handle(['request','policies','vrrp','edit','isp','priority=150'], api, 'fixture')
        self.assertTrue(all(c == 200 for c in calls)); self.assertEqual(self.get()['entries'][0]['priority'], 150)
        with redirect_stdout(io.StringIO()): handle(['request','policies','vrrp','remove','isp'], api, 'fixture')
        self.assertEqual(self.get()['entries'], [])

    def test_aggregate_subinterface_ownership_and_object_changes(self):
        root = parse(self.path.read_bytes()); network = root.find(NETWORK)
        network.find('interface').append(ET.fromstring('<aggregate-ethernet><entry name="ae7"><aggregate-only>yes</aggregate-only><layer3><units><entry name="ae7.100"><tag>100</tag><ip><entry name="192.0.2.2/24"/></ip></entry></units></layer3></entry></aggregate-ethernet>'))
        imports = root.find("./devices/entry/vsys/entry[@name='vsys1']/import/network/interface")
        ET.SubElement(imports, 'member').text = 'ae7'
        _, interfaces, _ = inventory(root, 'vsys1')
        self.assertNotIn('ae7', interfaces); self.assertIn('ae7.100', interfaces)
        spec = self.spec(interface='ae7.100')
        self.assertEqual(validate(root, spec)['resolved_addresses'], ['192.0.2.1/24'])
        root.find('.//address/entry/ip-netmask').text = '192.0.2.10/24'
        self.assertEqual(validate(root, spec)['resolved_addresses'], ['192.0.2.10/24'])

    def test_installer_navigation_idempotent(self):
        import importlib.util
        from pathlib import Path
        root = Path(__file__).resolve().parents[1]
        spec = importlib.util.spec_from_file_location('vrrp_installer_fixture', root / 'image/install-policies-ui.py')
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        source = (root / 'static/index.html').read_text(encoding='utf-8')
        merged = module.merge_html(source, source)
        self.assertEqual(module.merge_html(merged, source), merged)
        self.assertEqual(merged.count("{id:'vrrp',label:'VRRP'}"), 1)
        self.assertEqual(merged.count('/static/vrrp.js'), 1)


if __name__ == '__main__': unittest.main()
