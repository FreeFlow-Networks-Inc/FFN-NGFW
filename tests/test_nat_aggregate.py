import sys
from pathlib import Path
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'opt'))
from ffn_nat_policy import compile_policy
from test_nat_policy import configuration


class AggregateNatTests(unittest.TestCase):
    def config(self,layer=''):
        xml=configuration().replace(b'ethernet1/1',b'ae7')
        xml=xml.replace(b'<member>ae7</member>',b'<member>ae7</member><member>ae7.123</member>')
        return xml.replace(b'<vsys>',('<network><interface><aggregate-ethernet><entry name="ae7"><layer3>'+layer+
           '<units><entry name="ae7.123"><tag>123</tag><ip><entry name="192.0.2.1/24"/></ip></entry></units>'+
           '</layer3></entry></aggregate-ethernet></interface></network><vsys>').encode())
    def test_unaddressed_parent_excluded_child_retained(self):
        plan=compile_policy(self.config())
        self.assertTrue(plan['valid'],plan)
        self.assertEqual(plan['plan']['rules'][0]['ingress'],['ae7.123'])
    def test_addressed_or_dhcp_parent_retained(self):
        for layer in ('<ip><entry name="203.0.113.1/24"/></ip>','<dhcp-client><enable>yes</enable></dhcp-client>'):
            self.assertEqual(compile_policy(self.config(layer))['plan']['rules'][0]['ingress'],['ae7','ae7.123'])


if __name__=='__main__':unittest.main()
