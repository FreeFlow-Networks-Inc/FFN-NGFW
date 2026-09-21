import sys
from pathlib import Path
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'opt'))
from ffn_security_nft import render
from ffn_nat_policy import NatError
from test_policy_plan import configuration


class SecurityNftTests(unittest.TestCase):
    def test_binding_generation_and_stateful_reply(self):
        xml=configuration('security',{'action':'allow','log-end':'no'})
        report=render(xml,{'ethernet1/1':10,'ethernet1/2':11})
        self.assertFalse(report['applied'])
        self.assertIn('ct direction reply ct label & 0x1 == 0 drop',report['script'])
        self.assertIn('iif { 10 } oif { 11 }',report['script'])
        self.assertIn('iif { 11 } oif { 10 }',report['script'])
        self.assertNotIn('hook input',report['script']);self.assertNotIn('hook output',report['script'])
        self.assertNotEqual(report['digest'],render(xml,{'ethernet1/1':12,'ethernet1/2':11})['digest'])
    def test_required_capabilities_never_silently_ignored(self):
        for fields in ({'log-end':'yes'},{'service':['application-default']},{'action':'reset-both'},
                       {'source-user':['alice']},{'icmp-unreachable':'yes','action':'drop'}):
            settings={'action':'allow','log-end':'no'};settings.update(fields)
            with self.assertRaises(NatError):render(configuration('security',settings),{'ethernet1/1':10,'ethernet1/2':11})
    def test_missing_ambiguous_or_invalid_binding_rejected(self):
        xml=configuration('security',{'action':'allow','log-end':'no'})
        for bindings in ({},{'ethernet1/1':10,'ethernet1/2':10},{'ethernet1/1':'10; accept','ethernet1/2':11}):
            with self.assertRaises(NatError):render(xml,bindings)


if __name__=='__main__':unittest.main()
