import copy
import os
import sys
from pathlib import Path
import unittest
from unittest.mock import patch
from xml.etree import ElementTree as ET
sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'opt'))
import ffn_interface_management as m
if os.name != 'nt':
    import ffn_linux_network as network
else:
    network = None


class ManagementTests(unittest.TestCase):
    def device(self, fields):
        return ET.fromstring('<entry><network><profiles><interface-management-profile><entry name="PING-ONLY">'
                             + fields + '</entry></interface-management-profile></profiles></network></entry>')

    def test_profiles_do_not_require_zones_or_security_rules(self):
        for fields in ('<ping>yes</ping>', '<permit_ping>yes</permit_ping>'):
            value = m.profile(self.device(fields), 'PING-ONLY')
            self.assertTrue(value['ping'])
            self.assertEqual(value['tcp'], [])
        self.assertFalse(m.profile(self.device('<ping>yes</ping><enabled>no</enabled>'), 'PING-ONLY')['ping'])
        self.assertFalse(m.profile(self.device(''), '')['ping'])

    def test_source_restrictions_and_unknown_profile_fail_closed(self):
        value = m.profile(self.device('<ping>yes</ping><permitted-ip><entry name="192.0.2.7"/></permitted-ip>'), 'PING-ONLY')
        self.assertEqual(value['sources'], ['192.0.2.7/32'])
        with self.assertRaises(ValueError): m.profile(self.device(''), 'missing')
        with self.assertRaises(ValueError): m.profile(self.device('<ping>yes</ping><permit_ping>no</permit_ping>'), 'PING-ONLY')

    @unittest.skipIf(network is None, 'Linux namespace owner is tested on the dataplane')
    def test_profile_edit_retains_routes_and_does_not_flap_interface(self):
        old = {'mode':'l3','addresses':['192.0.2.1/24'], 'management':m.profile(self.device(''), '')}
        new = copy.deepcopy(old);new['management']['ping'] = True
        cfg = {'revision':1,'ports':{'p1':old}, 'routes':[{'dst':'0.0.0.0/0','dev':'p1','via':'192.0.2.254'}]}
        with patch.object(network,'exists',return_value=True), patch.object(network,'backend',return_value={'ports':[1]}):
            proposed, changed = network.prepare(cfg, {'revision':1,'ports':{'p1':new}})
        self.assertEqual(changed,['p1'])
        self.assertEqual(proposed['routes'],cfg['routes'])
        with patch.object(m,'apply') as apply, patch.object(network,'configure_port') as configure:
            network.update_port('p1',old,new)
            apply.assert_called_once_with(network.NS,'p1',new)
            configure.assert_not_called()

    def test_render_targets_local_input_and_destination_address(self):
        settings={'addresses':['192.0.2.1/24'],'management':m.profile(self.device('<ping>yes</ping>'),'PING-ONLY')}
        _, script=m.render('p1',settings)
        self.assertIn('hook input',script)
        self.assertNotIn('hook forward',script)
        self.assertIn('ip daddr { 192.0.2.1 } icmp type echo-request counter accept',script)
        self.assertIn('ct direction reply',script)
        self.assertNotIn('ct state established,related accept\n  icmp type echo-request',script)
        with self.assertRaises(ValueError):m.render('p1;flush ruleset',settings)


if __name__=='__main__':unittest.main()
