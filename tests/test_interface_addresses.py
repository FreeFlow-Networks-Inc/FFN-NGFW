import sys
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'opt'))
from ffn_interface_addresses import address_choices, resolve_address, resolved_config, reference_blockers, object_references


class AddressResolutionTests(unittest.TestCase):
    def setUp(self):
        self.root = ET.fromstring('''<config><shared><address>
          <entry name="gateway"><ip-netmask>192.0.2.7/24</ip-netmask></entry>
          <entry name="shared6"><ip-netmask>2001:db8::123/64</ip-netmask></entry>
          <entry name="shadow"><ip-netmask>198.51.100.1/24</ip-netmask></entry>
          </address></shared><devices><entry name="localhost.localdomain">
          <network><interface><aggregate-ethernet><entry name="ae1"><layer3><ip><entry name="gateway"/></ip>
          <units><entry name="ae1.7"><tag>7</tag><ip><entry name="shared6"/></ip></entry></units>
          </layer3></entry></aggregate-ethernet></interface></network>
          <vsys><entry name="vsys1"><address>
          <entry name="gateway"><ip-netmask>203.0.113.17/27</ip-netmask></entry>
          <entry name="shadow"><fqdn>example.com</fqdn></entry>
          <entry name="range"><ip-range>192.0.2.1-192.0.2.3</ip-range></entry>
          </address><import><network><interface><member>ae1</member></interface></network></import></entry>
          <entry name="vsys2"><address><entry name="other"><ip-netmask>198.51.100.2/24</ip-netmask></entry></address></entry></vsys>
          </entry></devices></config>''')
        self.owner = self.root.find('devices/entry/vsys/entry')

    def test_choices_are_scoped_shadowed_and_family_aware(self):
        choices = address_choices(self.root, self.owner)
        self.assertEqual([o['name'] for o in choices], ['gateway', 'shared6'])
        self.assertEqual(choices[0]['value'], '203.0.113.17/27')
        self.assertEqual(choices[1]['family'], 6)
        self.assertEqual(choices[1]['scope'], 'shared')
        for value in ('other', 'shadow', 'range', 'missing', '192.0.2.1'):
            with self.assertRaises(ValueError):resolve_address(value, self.root, self.owner)

    def test_runtime_copy_preserves_reference_host_and_subinterface_scope(self):
        before = ET.tostring(self.root)
        result = resolved_config(self.root)
        self.assertEqual(result.find('.//layer3/ip/entry').get('name'), '203.0.113.17/27')
        self.assertEqual(result.find('.//units/entry/ip/entry').get('name'), '2001:db8::123/64')
        self.assertEqual(ET.tostring(self.root), before)
        self.owner.find('address/entry/ip-netmask').text = '203.0.113.18/27'
        self.assertEqual(resolved_config(self.root).find('.//layer3/ip/entry').get('name'), '203.0.113.18/27')

    def test_deleted_or_changed_type_blocks_commit_and_deletion_tracks_scope(self):
        self.assertEqual(len(object_references(self.root, 'vsys1', 'gateway')), 1)
        self.assertEqual(object_references(self.root, 'shared', 'gateway'), [])
        self.assertEqual(len(object_references(self.root, 'shared', 'shared6')), 1)
        entry = self.owner.find('address/entry')
        entry[0].tag = 'fqdn';entry[0].text = 'example.com'
        self.assertTrue(reference_blockers(self.root))
        with self.assertRaises(ValueError):resolved_config(self.root)

    def test_duplicate_resolved_addresses_fail_before_runtime_changes(self):
        ET.SubElement(self.root.find('.//layer3/ip'), 'entry', name='203.0.113.17/27')
        self.assertTrue(reference_blockers(self.root))
    def test_policy_uses_network_while_interface_keeps_ipv6_host(self):
        from ffn_nat_policy import Resolver
        self.assertEqual(Resolver(self.root,self.owner,6).addresses(['shared6']),['2001:db8::/64'])
        self.assertEqual(resolve_address('shared6',self.root,self.owner),'2001:db8::123/64')


if __name__ == '__main__':unittest.main()
