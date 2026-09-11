import copy
import unittest
from unittest.mock import patch
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'opt'))
import ffn_linux_network as net


class ConfigTests(unittest.TestCase):
    def test_native_runtime_cannot_adopt_unprovisioned_interfaces(self):
        with patch.object(net,'PORT_BACKEND','native'), patch.object(net,'run') as run:
            with self.assertRaisesRegex(ValueError,'provisioned'):
                net.prepare(self.cfg,{'revision':7,'ports':{'p99':{'mode':'l3'}}})
        run.assert_not_called()

    def test_prepare_has_no_writes(self):
        with patch.object(net,'exists',return_value=True), patch.object(net,'backend',return_value={'ports':[]}), \
             patch.object(net,'configure_port') as ports, patch.object(net,'save') as save:
            proposed, changed=net.prepare(self.cfg,{'revision':7,'ports':{'p1':{'mode':'disabled'}}})
        self.assertEqual(proposed['revision'],8)
        self.assertEqual(changed,['p1'])
        ports.assert_not_called();save.assert_not_called()

    def test_unattached_hardware_port_is_rejected(self):
        with patch.object(net,'REQUIRE_ATTACHMENT',True), patch.object(net,'backend',return_value={'ports':[1]}), \
             patch.object(net,'configure_port') as ports:
            with self.assertRaisesRegex(ValueError,'physical backend'):
                net.prepare(self.cfg,{'revision':7,'ports':{'p3':{'mode':'l3'}}})
        ports.assert_not_called()

    def setUp(self):
        paths=patch.object(net, 'Path')
        paths.start().return_value.exists.return_value=False
        self.addCleanup(paths.stop)
        overlay=patch.object(net, 'OVERLAY_STATE')
        overlay.start().exists.return_value=False
        self.addCleanup(overlay.stop)
        self.cfg = {'revision': 7, 'ports': {
            'p1': {'mode': 'l2', 'vlans': [100], 'pvid': 100},
            'p3': {'mode': 'l3', 'addresses': ['198.18.1.1/24']}}}

    def test_reject_invalid_before_io(self):
        for settings in ({'mode': 'l2', 'vlans': [0]},
                         {'mode': 'l2', 'vlans': [100], 'pvid': 200},
                         {'mode': 'l2', 'vlans': [100], 'addresses': ['198.18.1.1/24']},
                         {'mode': 'l3', 'addresses': ['bad']},
                         {'mode': 'disabled', 'mtu': 12}):
            with self.subTest(settings=settings), self.assertRaises(ValueError), patch.object(net, 'run') as io:
                net.patch(self.cfg, {'revision': 7, 'ports': {'p1': settings}})
            io.assert_not_called()

    def test_revision_conflict(self):
        with patch.object(net, 'run') as io, self.assertRaises(ValueError):
            net.patch(self.cfg, {'revision': 6, 'ports': {'p1': {'mode': 'disabled'}}})
        io.assert_not_called()

    def test_static_route_validation(self):
        self.cfg['routes'] = [{'dst':'0.0.0.0/0','dev':'p3','via':'198.18.1.2'},
                              {'dst':'2001:db8::/32','type':'blackhole'}]
        net.validate(self.cfg)
        for route in ({'dst':'203.0.113.1/24','dev':'p3'},
                      {'dst':'0.0.0.0/0','dev':'p1'},
                      {'dst':'0.0.0.0/0','dev':'p3','via':'198.18.9.2'},
                      {'dst':'0.0.0.0/0','dev':'p3','via':'198.18.1.1'},
                      {'dst':'0.0.0.0/0','dev':'p3','via':'198.18.1.255'},
                      {'dst':'::/0','dev':'p3','via':'198.18.1.2'},
                      {'dst':'::/0','type':'blackhole','dev':'p3'}):
            self.cfg['routes'] = [route]
            with self.subTest(route=route), self.assertRaises(ValueError):
                net.validate(self.cfg)

    def test_route_save_failure_rolls_back(self):
        route = {'dst':'0.0.0.0/0','dev':'p3','via':'198.18.1.2'}
        with patch.object(net,'exists',return_value=True), patch.object(net,'backend',return_value={'ports':[]}), \
             patch.object(net,'configure_route') as change, patch.object(net,'configure_port') as ports, \
             patch.object(net,'save',side_effect=OSError('disk full')):
            with self.assertRaisesRegex(RuntimeError,'rollback errors: \\[\\]'):
                net.patch(self.cfg,{'revision':7,'routes':[route]})
        self.assertEqual([c.args for c in change.call_args_list],[('add',route),('del',route)])
        ports.assert_not_called()

    def test_failed_add_does_not_delete_unmanaged_route(self):
        with patch.object(net,'exists',return_value=True), patch.object(net,'backend',return_value={'ports':[]}), \
             patch.object(net,'configure_route',side_effect=RuntimeError('File exists')) as change:
            with self.assertRaises(RuntimeError):
                net.patch(self.cfg,{'revision':7,'routes':[{'dst':'0.0.0.0/0','dev':'p3'}]})
        self.assertEqual(change.call_count,1)

    def test_route_dependency_protects_port(self):
        self.cfg['routes'] = [{'dst':'0.0.0.0/0','dev':'p3','via':'198.18.1.2'}]
        with patch.object(net,'exists',return_value=True), patch.object(net,'backend',return_value={'ports':[]}), \
             patch.object(net,'configure_port') as change, self.assertRaises(ValueError):
            net.patch(self.cfg,{'revision':7,'ports':{'p3':{'mode':'disabled'}}})
        change.assert_not_called()

    def test_vrf_address_isolation_and_table_validation(self):
        self.cfg['vrfs'] = {'vrf-blue':1001,'vrf-red':1002}
        self.cfg['ports'] = {'p1':{'mode':'l3','vrf':'vrf-blue','addresses':['192.0.2.1/24']},
                             'p3':{'mode':'l3','vrf':'vrf-red','addresses':['192.0.2.1/24']}}
        self.cfg['routes'] = [{'dst':'0.0.0.0/0','dev':'p1','via':'192.0.2.2','table':1001}]
        net.validate(self.cfg)
        self.cfg['routes'][0]['table'] = 1002
        with self.assertRaisesRegex(ValueError,'same virtual router'):
            net.validate(self.cfg)
        self.cfg['routes'] = []
        self.cfg['ports']['p3']['vrf'] = 'vrf-blue'
        with self.assertRaisesRegex(ValueError,'duplicate local'):
            net.validate(self.cfg)

    def test_vrf_failure_does_not_save_configuration(self):
        with patch.object(net,'exists',return_value=True), patch.object(net,'backend',return_value={'ports':[]}), \
             patch.object(net,'create_vrf',side_effect=RuntimeError('not supported')), patch.object(net,'save') as save:
            with self.assertRaises(RuntimeError):
                net.patch(self.cfg,{'revision':7,'vrfs':{'vrf-blue':1001}})
        save.assert_not_called()

    def test_ecmp_next_hop_validation(self):
        route = {'dst':'0.0.0.0/0','nexthops':[{'dev':'p3','via':'198.18.1.2','weight':1},
                                              {'dev':'p3','via':'198.18.1.3','weight':2}]}
        self.cfg['routes'] = [route]
        net.validate(self.cfg)
        route['nexthops'][1]['weight'] = 0
        with self.assertRaises(ValueError): net.validate(self.cfg)
        route['nexthops'][1]['weight'] = 2
        route['nexthops'][1]['via'] = '198.18.2.3'
        with self.assertRaises(ValueError): net.validate(self.cfg)

    def test_policy_validation_and_priority_conflict(self):
        self.cfg['vrfs'] = {'vrf-blue':1001}
        rule = {'from':'198.18.1.0/24','iif':'p3','table':1001,'priority':101}
        self.cfg['rules'] = [rule]
        net.validate(self.cfg)
        self.cfg['rules'] = [rule, dict(rule)]
        with self.assertRaises(ValueError): net.validate(self.cfg)
        with patch.object(net,'ip',return_value='[{"priority":101}]') as io, self.assertRaises(RuntimeError):
            net.configure_rule('add',rule)
        self.assertEqual(io.call_count,1)

    def test_policy_persistence_failure_restores_rule(self):
        self.cfg['vrfs'] = {'vrf-blue':1001}
        rule = {'from':'198.18.1.0/24','iif':'p3','table':1001,'priority':101}
        with patch.object(net,'exists',return_value=True), patch.object(net,'backend',return_value={'ports':[]}), \
             patch.object(net,'configure_rule') as change, patch.object(net,'save',side_effect=OSError('disk full')):
            with self.assertRaises(RuntimeError):
                net.patch(self.cfg,{'revision':7,'rules':[rule]})
        self.assertEqual([c.args for c in change.call_args_list],[('add',rule),('del',rule)])

    def test_only_changed_port(self):
        original = copy.deepcopy(self.cfg)
        with patch.object(net, 'exists', return_value=True), patch.object(net, 'configure_port') as change, patch.object(net, 'save'):
            result = net.patch(self.cfg, {'revision': 7, 'ports': {'p1': {'mode': 'disabled'}}})
        change.assert_called_once_with('p1', {'mode': 'disabled'}, create=False)
        self.assertEqual(result['revision'], 8)
        self.assertEqual(original, self.cfg)

    def test_persistence_failure_restores_port(self):
        with patch.object(net, 'exists', return_value=True), patch.object(net, 'configure_port') as change, patch.object(net, 'save', side_effect=OSError('disk full')):
            with self.assertRaisesRegex(RuntimeError, 'rollback errors: \\[\\]'):
                net.patch(self.cfg, {'revision': 7, 'ports': {'p1': {'mode': 'disabled'}}})
        self.assertEqual(change.call_args_list[-1].args, ('p1', self.cfg['ports']['p1']))

    def test_active_overlay_protects_underlay(self):
        with patch.object(net, 'exists', return_value=True), patch.object(net, 'backend', return_value={'ports':[]}), \
             patch.object(net, 'OVERLAY_STATE') as path, patch.object(net, 'configure_port') as change:
            path.exists.return_value = True
            path.read_text.return_value = '{"links":{"ovtest":{"underlay":"p3"}}}'
            with self.assertRaisesRegex(ValueError, 'dependent overlays'):
                net.patch(self.cfg, {'revision':7,'ports':{'p3':{'mode':'disabled'}}})
        change.assert_not_called()


if __name__ == '__main__':
    unittest.main()
