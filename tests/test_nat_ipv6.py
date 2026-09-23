import copy
import ipaddress as ip
from pathlib import Path
import struct
import sys
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'opt'))
import ffn_ipv6_translation as v6
import ffn_nat_runtime as runtime
from ffn_nat_policy import compile_policy
from test_nat_policy import configuration


def config(kind='nat64',**changes):
    fields={'nat-type':kind,'source-type':'none','source-interface':'','source':['2001:db8:1::/64']}
    if kind=='nat64':fields.update({'nat64-prefix':'2001:db8:64::/96','nat64-pool':['192.0.2.10']})
    else:fields.update({'source':['any'],'nptv6-internal-prefix':'fd01:203:405::/48','nptv6-external-prefix':'2001:db8:1::/48'})
    fields.update(changes);return configuration(**fields)


def sum16(raw):return sum(struct.unpack('!%dH'%(len(raw)//2),raw))%65535


class PrefixTests(unittest.TestCase):
    def test_nat64_packet_tcp_udp_and_echo_both_directions(self):
        source,destination=ip.IPv6Address('2001:db8:1::10'),ip.IPv6Address('2001:db8:64::c000:221')
        for protocol in (6,17,58):
            if protocol==6:payload=struct.pack('!HHIIHHHH',1234,443,123,456,0x5018,4096,0,0)+b'odd'
            elif protocol==17:payload=struct.pack('!HHHH',1234,53,11,0)+b'odd'
            else:payload=struct.pack('!BBHHH',128,0,0,1234,1)+b'odd'
            offset={6:16,17:6,58:2}[protocol]
            value=v6.checksum(source.packed+destination.packed+struct.pack('!I3xB',len(payload),protocol)+payload)
            payload=payload[:offset]+struct.pack('!H',value)+payload[offset+2:]
            packet=struct.pack('!IHBB',0x62e00000,len(payload),protocol,64)+source.packed+destination.packed+payload
            translated=v6.nat64_packet(packet,'192.0.2.10','192.0.2.33',**({'source_port':50000} if protocol!=58 else {}))
            self.assertEqual(translated[0],0x45);self.assertEqual(translated[1],0x2e);self.assertEqual(translated[8],63)
            self.assertEqual(v6.checksum(translated[:20]),0)
            restored=v6.nat64_packet(translated,str(source),str(destination),**({'source_port':1234} if protocol!=58 else {}))
            self.assertEqual(restored[8:],packet[8:]);self.assertEqual(restored[7],62)
            corrupt=bytearray(packet);corrupt[-1]^=1
            with self.assertRaises(ValueError):v6.nat64_packet(bytes(corrupt),'192.0.2.10','192.0.2.33')

    def test_nat64_rejects_fragments_extensions_and_expired_hops(self):
        for next_header in (0,43,44,60):
            packet=struct.pack('!IHBB16s16s',0x60000000,8,next_header,64,bytes(16),bytes(16))+bytes(8)
            with self.assertRaisesRegex(ValueError,'extensions'):v6.nat64_packet(packet,'192.0.2.10','192.0.2.33')
        packet=struct.pack('!IHBB16s16s',0x60000000,8,17,1,bytes(16),bytes(16))+bytes(8)
        with self.assertRaisesRegex(ValueError,'hop limit'):v6.nat64_packet(packet,'192.0.2.10','192.0.2.33')

    def test_rfc6052_vectors_all_lengths(self):
        vectors=[('2001:db8::/32','2001:db8:c000:221::'),('2001:db8:100::/40','2001:db8:1c0:2:21::'),
                 ('2001:db8:122::/48','2001:db8:122:c000:2:2100::'),('2001:db8:122:300::/56','2001:db8:122:3c0:0:221::'),
                 ('2001:db8:122:344::/64','2001:db8:122:344:c0:2:2100::'),('2001:db8:122:344::/96','2001:db8:122:344::c000:221')]
        for prefix,expected in vectors:
            self.assertEqual(v6.nat64_embed('192.0.2.33',prefix),str(ip.IPv6Address(expected)))
            self.assertEqual(v6.nat64_extract(expected,prefix),'192.0.2.33')
        self.assertEqual(v6.nat64_destination('64:ff9b::808:808','64:ff9b::/96'),'8.8.8.8')
        with self.assertRaisesRegex(ValueError,'non-global'):v6.nat64_destination('64:ff9b::a00:1','64:ff9b::/96')
        with self.assertRaisesRegex(ValueError,'u octet'):v6.nat64_extract('2001:db8::100:0:0:1','2001:db8::/32')
        self.assertEqual(v6.nat64_extract('2001:db8:c000:221::abcd','2001:db8::/32'),'192.0.2.33')

    def test_prefix_validation_rejects_host_bits_and_wrong_family(self):
        for bad in ('2001:db8::1/96','2001:db8::/80','fe80::/64','ff00::/32','::/96','192.0.2.0/24','2001:db8::100:0:0:0/96'):
            with self.assertRaises(ValueError):v6.nat64_prefix(bad)

    def test_rfc6296_example_and_zero_normalization(self):
        a,b='fd01:203:405::/48','2001:db8:1::/48'
        self.assertEqual(v6.nptv6_address('fd01:203:405:1::1234',a,b),'2001:db8:1:d550::1234')
        self.assertEqual(v6.nptv6_address('2001:db8:1:d550::1234',a,b,True),'fd01:203:405:1::1234')
        # Exercise every usable subnet: mapping is one-to-one, neutral, reversible.
        seen=set()
        for subnet in range(65535):
            original=ip.IPv6Address(int(ip.IPv6Address('fd01:203:405::1234'))|(subnet<<64))
            translated=v6.nptv6_address(str(original),a,b)
            self.assertNotIn(translated,seen);seen.add(translated)
            self.assertEqual(sum16(original.packed),sum16(ip.IPv6Address(translated).packed))
            self.assertEqual(v6.nptv6_address(translated,a,b,True),str(original))
        with self.assertRaisesRegex(ValueError,'subnet'):v6.nptv6_address('fd01:203:405:ffff::1',a,b)

    def test_long_unequal_prefix_mapping_and_reserved_iid(self):
        a,b='fd01:203:405::/48','2001:db8:1:ab00::/56'
        for original in ('fd01:203:405:1::1234','fd01:203:405:1:ffff:ffff:ffff:1234','fd01:203:405::'):
            translated=v6.nptv6_address(original,a,b)
            self.assertEqual(v6.nptv6_address(translated,a,b,True),original)
            self.assertEqual(sum16(ip.IPv6Address(original).packed),sum16(ip.IPv6Address(translated).packed))
        with self.assertRaisesRegex(ValueError,'effective'):v6.nptv6_address('fd01:203:405:100::1',a,b)
        with self.assertRaisesRegex(ValueError,'all-ones'):v6.nptv6_address('fd01:203:405:1:ffff:ffff:ffff:ffff',a,b)

    def test_packet_hairpin_preserves_transport_checksum(self):
        a,b='fd01:203:405::/48','2001:db8:1::/48'
        src=ip.IPv6Address('fd01:203:405:1::1').packed
        dst=ip.IPv6Address(v6.nptv6_address('fd01:203:405:2::2',a,b)).packed
        udp=struct.pack('!4H',1234,5678,12,0)+b'test'
        pseudo=src+dst+struct.pack('!I3xB',len(udp),17)
        check=65535-sum16(pseudo+udp);udp=udp[:6]+struct.pack('!H',check)+udp[8:]
        packet=struct.pack('!IHBB',0x60000000,len(udp),17,64)+src+dst+udp
        result=v6.nptv6_packet(packet,a,b,'hairpin')
        self.assertEqual(packet[40:],result[40:]);self.assertEqual(sum16(result[8:40]+pseudo[32:]+result[40:]),0)
        self.assertEqual(str(ip.IPv6Address(result[24:40])),'fd01:203:405:2::2')
        with self.assertRaises(ValueError):v6.nptv6_packet(packet[:-1],a,b,'outbound')


class TranslationPlanTests(unittest.TestCase):
    def test_compile_modes_and_no_dataplane_mutation(self):
        for kind in ('nat64','nptv6'):
            report=compile_policy(config(kind));self.assertTrue(report['valid'],report)
            self.assertEqual(report['plan']['version'],2);runtime.validate_plan(report['plan'])
            with patch.object(runtime,'nft') as nft,patch.object(runtime,'run') as run:
                with self.assertRaisesRegex(ValueError,'commissioned'):runtime.prepare({'revision':0,'plan':report['plan']})
                with self.assertRaisesRegex(ValueError,'commissioned'):runtime.render(report['plan'],{}, {},1)
                nft.assert_not_called();run.assert_not_called()

    def test_wrong_families_and_mixed_actions_rejected(self):
        for changes in ({'source':['192.0.2.0/24']},{'nat64-prefix':'2001:db8::/72'},
                        {'nat64-pool':['192.0.2.0/24']},{'nat64-pool':[]},
                        {'destination':['2001:db8:2::/64']},{'source-type':'dynamic-ip-and-port','source-interface':'ethernet1/2'}):
            self.assertFalse(compile_policy(config(**changes))['valid'],changes)
        for changes in ({'service':['web']},{'nptv6-external-prefix':'fd01:203:405::/48'},
                        {'destination':['2001:db8::/32']},{'nptv6-internal-prefix':'fd01:203:405::/80'}):
            self.assertFalse(compile_policy(config('nptv6',**changes))['valid'],changes)

    def test_raw_plans_cannot_smuggle_ipv4_actions(self):
        plan=compile_policy(config())['plan']
        for mutate in (lambda p:p.update(version=1),lambda p:p['rules'][0].update(translation=None),
                       lambda p:p['rules'][0].update(dnat={'address':'192.0.2.1'}),
                       lambda p:p['rules'][0]['translation'].update(prefix='2001:db8::/72')):
            bad=copy.deepcopy(plan);mutate(bad)
            with self.assertRaises(ValueError):runtime.validate_plan(bad)

    def test_nat64_first_match_simulation_accepts_ipv6_only_for_nat(self):
        from ffn_policy_plan import test_policy,validate_packet
        packet=dict(source='2001:db8:1::10',destination='2001:db8:64::c000:221',from_zone='trust',to_zone='untrust',protocol='tcp')
        result=test_policy(config(),'nat','vsys1',packet)
        self.assertEqual(result['status'],'matched');self.assertEqual(result['selected']['action']['translation']['type'],'nat64')
        self.assertFalse(result['applied'])


if __name__=='__main__':unittest.main()
