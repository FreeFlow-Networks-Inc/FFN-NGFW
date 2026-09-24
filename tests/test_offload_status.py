import copy
import unittest
from ffn_offload_status import with_dp_acknowledgement


class OffloadStatusTests(unittest.TestCase):
    def setUp(self):
        self.inventory = {'present': True, 'dp': {'present': False},
                          'note': 'CP inventory unavailable'}
        self.agents = {'agents': {'dp': {'connected': True, 'fresh': True, 'ready': True,
            'last_observation': {'role': 'dp', 'platform': 'pa5200', 'boot_id': 'boot-1',
                'report': {'role': 'dataplane', 'boot_id': 'boot-1', 'octeon': True,
                           'ready': True, 'cpu_count': 40, 'forwarding_verified': False}}}}}

    def test_live_ack_establishes_presence_without_claiming_forwarding(self):
        out = with_dp_acknowledgement(self.inventory, self.agents)
        self.assertTrue(out['dp']['present'])
        self.assertTrue(out['dp']['ready'])
        self.assertEqual(out['dp']['cpu_count'], 40)
        self.assertFalse(out['dp']['forwarding_verified'])
        self.assertEqual(out['note'], self.inventory['note'])
        self.assertFalse(self.inventory['dp']['present'])

    def test_stale_disconnected_wrong_role_and_wrong_boot_do_not_establish_presence(self):
        for field in ('fresh', 'connected'):
            agents = copy.deepcopy(self.agents); agents['agents']['dp'][field] = False
            self.assertFalse(with_dp_acknowledgement(self.inventory, agents)['dp']['present'])
        for field, value in [('role', 'cp'), ('platform', 'other'), ('boot_id', 'old')]:
            agents = copy.deepcopy(self.agents)
            agents['agents']['dp']['last_observation'][field] = value
            self.assertFalse(with_dp_acknowledgement(self.inventory, agents)['dp']['present'])

    def test_boot_incomplete_agent_is_present_but_not_ready(self):
        self.agents['agents']['dp']['ready'] = False
        out = with_dp_acknowledgement(self.inventory, self.agents)
        self.assertTrue(out['dp']['present'])
        self.assertFalse(out['dp']['ready'])

    def test_missing_agent_preserves_inventory(self):
        self.assertEqual(with_dp_acknowledgement(self.inventory, {}), self.inventory)
