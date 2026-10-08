import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'opt'))
import ffn_l3_offload as l3


class L3Tests(unittest.TestCase):
    def setUp(self):
        self.bindings = {'lan': dict(device='trunk.80', index=10, alias='owner:unit'),
                         'wan': dict(device='p7', index=12, alias='')}
        def link(name, index, alias):
            return dict(ifname=name, ifindex=index, ifalias=alias, address='02:00:00:00:00:01',
                        flags=['UP', 'LOWER_UP'], mtu=1500)
        self.state = dict(
            links=[dict(link('trunk.80', 10, 'owner:unit'), link_index=11,
                        linkinfo={'info_kind': 'vlan', 'info_data': {'id': 80, 'protocol': '802.1Q'}}),
                   link('trunk', 11, 'owner'), link('p7', 12, '')],
            addresses=[dict(addr_info=[dict(local='192.0.2.1')])],
            rules=[dict(priority=p, src='all', table=t) for p, t in
                   [(0, 'local'), (32766, 'main'), (32767, 'default')]],
            routes=[dict(dst='192.0.2.0/24', dev='trunk.80'),
                    dict(dst='default', dev='p7', gateway='203.0.113.1')],
            neighbors=[dict(dst='192.0.2.5', dev='trunk.80', state=['REACHABLE'], lladdr='02:00:00:00:00:05'),
                       dict(dst='203.0.113.1', dev='p7', state=['PERMANENT'], lladdr='02:00:00:00:00:07')])
        self.row = dict(software_candidate=True, rule={'interface_pairs': [['lan', 'wan']]},
                        original={'source': '192.0.2.5'}, translated={'destination': '198.51.100.5'})

    def test_routes_actual_translation_both_directions_and_retains_vlan_owner(self):
        result = l3.plan(self.row, self.bindings, self.state)
        self.assertTrue(result['available'], result)
        self.assertFalse(result['hardware_admission'])
        forward, reverse = result['directions']
        self.assertEqual(forward['next_hop'], '203.0.113.1')
        self.assertEqual(reverse['next_hop'], '192.0.2.5')
        self.assertEqual(reverse['vlan'], 80)
        self.assertEqual(reverse['parent']['ifalias'], 'owner')
        self.assertTrue(forward['decrement_ttl'])
        self.assertIn('mtu-exceeded', forward['exceptions'])

    def test_destination_nat_uses_translated_destination(self):
        self.state['routes'].append(dict(dst='198.18.0.0/24', dev='p7'))
        self.state['neighbors'].append(dict(dst='198.18.0.5', dev='p7', state=['REACHABLE'], lladdr='02:00:00:00:00:08'))
        self.row['translated']['destination'] = '198.18.0.5'
        result = l3.plan(self.row, self.bindings, self.state)
        self.assertTrue(result['available'])
        self.assertEqual(result['directions'][0]['next_hop'], '198.18.0.5')

    def test_local_destination_never_becomes_transit_offload(self):
        self.row['translated']['destination'] = '192.0.2.1'
        result = l3.plan(self.row, self.bindings, self.state)
        self.assertFalse(result['available'])
        self.assertIn('management-profile', result['blockers'][0])

    def test_rejects_failed_unresolved_or_multicast_neighbor(self):
        for change in ({'state': ['FAILED']}, {'state': ['INCOMPLETE']}, {'state': []}, {'valid': False},
                       {'lladdr': 'ff:ff:ff:ff:ff:ff'}, {'lladdr': '00:00:00:00:00:00'}, {'dst': '203.0.113.99'}):
            state = copy.deepcopy(self.state); state['neighbors'][1].update(change)
            with self.subTest(change=change):
                self.assertFalse(l3.plan(self.row, self.bindings, state)['available'])
        no_lladdr = copy.deepcopy(self.state); del no_lladdr['neighbors'][1]['lladdr']
        self.assertFalse(l3.plan(self.row, self.bindings, no_lladdr)['available'])

    def test_kernel_valid_neighbor_states_keep_the_next_hop(self):
        # STALE/DELAY/PROBE entries still carry the link address the kernel
        # forwards with; the generation must survive the state machine.
        for states in (['STALE'], ['DELAY'], ['PROBE'], ['REACHABLE'], ['NOARP']):
            state = copy.deepcopy(self.state); state['neighbors'][1]['state'] = states
            with self.subTest(states=states):
                self.assertTrue(l3.plan(self.row, self.bindings, state)['available'])
        projected = copy.deepcopy(self.state)
        projected['neighbors'] = [l3.project_neighbor(n) for n in projected['neighbors']]
        self.assertEqual(projected['neighbors'][1], dict(dst='203.0.113.1', dev='p7', lladdr='02:00:00:00:00:07', valid=True))
        self.assertTrue(l3.plan(self.row, self.bindings, projected)['available'])

    def test_snapshot_projection_is_stable_across_neighbor_state_churn(self):
        import json
        from unittest.mock import patch
        raw = {
            'link': [dict(ifindex=1, ifname='p7', flags=['UP'], mtu=1500, stats64={'rx': {'bytes': 1}})],
            'address': [dict(ifindex=1, ifname='p7', addr_info=[dict(family='inet', local='203.0.113.2', prefixlen=24, valid_life_time=100)])],
            'route': [dict(dst='default', dev='p7', gateway='203.0.113.1')],
            'rule': [dict(priority=32766, src='all', table='main')],
            'neigh': [dict(dst='203.0.113.1', dev='p7', lladdr='02:00:00:00:00:07', state=['REACHABLE'])],
        }
        def run(argv, **kw):
            kind = next(k for k in raw if k in argv)
            return type('R', (), {'stdout': json.dumps(raw[kind])})()
        with patch.object(l3.subprocess, 'run', side_effect=run), patch.object(l3.time, 'monotonic', return_value=0):
            first = l3.snapshot(5)
            raw['neigh'][0]['state'] = ['STALE']; raw['link'][0]['stats64']['rx']['bytes'] = 2
            raw['address'][0]['addr_info'][0]['valid_life_time'] = 50
            second = l3.snapshot(5)
            raw['neigh'][0]['state'] = ['FAILED']; del raw['neigh'][0]['lladdr']
            failed = l3.snapshot(5)
            raw['neigh'][0].update(lladdr='02:00:00:00:00:08', state=['REACHABLE'])
            moved = l3.snapshot(5)
        self.assertEqual(first, second); self.assertEqual(l3.fingerprint(first), l3.fingerprint(second))
        self.assertEqual(first['neighbors'], [dict(dst='203.0.113.1', dev='p7', lladdr='02:00:00:00:00:07', valid=True)])
        self.assertNotEqual(first, failed); self.assertFalse(failed['neighbors'][0]['valid'])
        self.assertNotEqual(first, moved); self.assertEqual(moved['neighbors'][0]['lladdr'], '02:00:00:00:00:08')

    def test_ownership_carrier_vlan_and_route_mismatches(self):
        for change in ({'ifindex': 100}, {'ifalias': 'replaced'}, {'flags': ['UP']}, {'master': 'vrf1'}):
            state = copy.deepcopy(self.state); state['links'][0].update(change)
            with self.subTest(change=change):
                self.assertFalse(l3.plan(self.row, self.bindings, state)['available'])
        for change in ({'dev': 'trunk.80'}, {'type': 'blackhole'}, {'nexthops': []},
                       {'encap': {}}, {'nhid': 4}, {'metrics': [{'mtu': 1280}]}):
            state = copy.deepcopy(self.state); state['routes'][1].update(change)
            with self.subTest(change=change):
                self.assertFalse(l3.plan(self.row, self.bindings, state)['available'])

    def test_longest_prefix_precedes_metric_and_ecmp_is_rejected(self):
        self.state['routes'].append(dict(dst='198.51.100.0/24', dev='p7', gateway='203.0.113.1', metric=200))
        result = l3.plan(self.row, self.bindings, self.state)
        self.assertEqual(result['directions'][0]['route']['metric'], 200)
        self.state['routes'].append(dict(self.state['routes'][-1]))
        self.assertFalse(l3.plan(self.row, self.bindings, self.state)['available'])

    def test_policy_routing_and_ungranted_sessions_are_not_guessed(self):
        self.state['rules'].insert(1, dict(priority=100, src='all', table=100))
        self.assertFalse(l3.plan(self.row, self.bindings, self.state)['available'])
        self.row['software_candidate'] = False
        self.assertFalse(l3.plan(self.row, self.bindings, self.state)['available'])


if __name__ == '__main__':
    unittest.main()
