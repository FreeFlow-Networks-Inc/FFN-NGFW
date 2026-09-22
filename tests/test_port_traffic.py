import sys
from pathlib import Path
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'opt'))
from ffn_port_traffic import PortTraffic
from ffn_mp_interfaces import validate,decode,encode
from xml.etree import ElementTree as ET


class TrafficTests(unittest.TestCase):
    def observation(self,t=1,n=100,boot='one'):
        return dict(sample_monotonic=t,boot_id=boot,unit='pps',ports=[dict(name='ethernet1/1',rx_packets_total=n,tx_packets_total=n//2)])
    def test_warmup_rates_reset_gap_and_boot(self):
        sampler=PortTraffic()
        self.assertIsNone(sampler.sample(self.observation())['ports'][0]['rx_pps'])
        port=sampler.sample(self.observation(3,300))['ports'][0]
        self.assertEqual(port['rx_pps'],100);self.assertEqual(port['tx_pps'],50)
        self.assertIsNone(port['rx_gbps'])
        for sample in [self.observation(5,10),self.observation(50,100),self.observation(52,200,'two')]:
            self.assertIsNone(sampler.sample(sample)['ports'][0]['rx_pps'])
    def test_removed_ports_do_not_reappear(self):
        sampler=PortTraffic();sampler.sample(self.observation())
        self.assertEqual(sampler.sample(dict(sample_monotonic=3,boot_id='one',ports=[]))['ports'],[])


class MPSettingsTests(unittest.TestCase):
    def config(self):return dict(mode='static',address='192.0.2.10/24',gateway='192.0.2.1',dns=['192.0.2.53'],mtu=1500,description='Management')
    def test_ipv4_and_schema_validation(self):
        self.assertEqual(validate(self.config())['address'],'192.0.2.10/24')
        for changes in [dict(address='127.0.0.1/8'),dict(gateway='198.51.100.1'),dict(mtu=True),dict(mode='dhcp'),dict(description='x\n[Match]')]:
            with self.assertRaises(ValueError):validate(dict(self.config(),**changes))
        with self.assertRaises(ValueError):validate(dict(self.config(),netdev='internal0'))
    def test_decode_encode_dns(self):
        node=ET.fromstring('<entry><mode>dhcp</mode><dns><member>192.0.2.53</member></dns></entry>')
        data=decode(node);self.assertEqual(encode(data)['dns'],['192.0.2.53'])
        self.assertEqual(data['address'],'')


if __name__=='__main__':unittest.main()
