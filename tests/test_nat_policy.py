import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'opt'))
from ffn_nat_policy import compile_policy
import ffn_nat_runtime as runtime
from ffn_policy_config import SCHEMAS,serialize,parse,node_at,runtime_report,require_supported,PolicyError

XML='''<config><shared><address><entry name="lan"><ip-netmask>192.0.2.0/24</ip-netmask></entry></address><service><entry name="web"><protocol><tcp><port>8080</port></tcp></protocol></entry></service></shared><devices><entry name="localhost.localdomain"><vsys><entry name="vsys1"><zone><entry name="trust"><network><layer3><member>ethernet1/1</member></layer3></network></entry><entry name="untrust"><network><layer3><member>ethernet1/2</member></layer3></network></entry></zone></entry></vsys></entry></devices></config>'''


def configuration(**settings):
    import xml.etree.ElementTree as ET
    fields={f['key']:copy.deepcopy(f['default']) if f['default'] is not None else '' for f in SCHEMAS['nat']['fields']}
    fields.update({'from':['trust'],'to':['untrust'],'source':['lan'],'source-type':'dynamic-ip-and-port','source-interface':'ethernet1/2'})
    fields.update(settings);root=parse(XML)
    rules=node_at(root.find('./devices/entry/vsys/entry'),'rulebase/nat/rules')
    rules.append(serialize('nat',dict(name='internet',enabled=True,settings=fields)))
    return ET.tostring(root)


class NatPolicyTests(unittest.TestCase):
    def test_readback_digest_ignores_counters_but_detects_changed_actions(self):
        first={'nftables':[{'rule':{'table':'ffn_nat','handle':1,'expr':[{'counter':{'packets':1,'bytes':80}},{'accept':None}]}}]}
        second=copy.deepcopy(first);second['nftables'][0]['rule']['expr'][0]['counter']['packets']=50
        self.assertEqual(runtime.kernel_digest(first),runtime.kernel_digest(second))
        second['nftables'][0]['rule']['expr'][1]={'drop':None}
        self.assertNotEqual(runtime.kernel_digest(first),runtime.kernel_digest(second))
    def test_object_and_service_resolution(self):
        report=compile_policy(configuration(service=['web'],**{'translated-destination':'198.51.100.9','translated-port':'80'}))
        self.assertTrue(report['valid'],report)
        r=report['plan']['rules'][0]
        self.assertEqual(r['source'],['192.0.2.0/24']);self.assertEqual(r['services'][0]['destination_ports'],['8080'])
        self.assertEqual(r['snat'],{'type':'masquerade','interface':'ethernet1/2'})
        self.assertEqual(r['dnat'],{'address':'198.51.100.9','port':80})

    def test_unsupported_rules_block_whole_activation(self):
        for change in [{'source-type':'dynamic-ip','source-interface':'','translated-source':['198.51.100.1']},
                       {'translated-destination':'198.51.100.9','translated-port':'80'},
                       {'source':['2001:db8::/64']},{'to-interface':'ethernet1/1'}]:
            report=compile_policy(configuration(**change));self.assertFalse(report['valid'],change)
            with self.assertRaises(PolicyError):require_supported(configuration(**change))

    def test_uncommissioned_provider_cannot_commit(self):
        with patch('ffn_nat_control.commissioned',return_value=False):
            with self.assertRaisesRegex(PolicyError,'not commissioned'):require_supported(configuration())

    def test_commit_requires_dp_acknowledgment(self):
        with patch('ffn_nat_control.commissioned',return_value=True),patch('ffn_nat_control.control_call',return_value={'validated':False}):
            with self.assertRaisesRegex(PolicyError,'did not validate'):require_supported(configuration())
        with patch('ffn_nat_control.commissioned',return_value=True),patch('ffn_nat_control.control_call',return_value={'validated':True}):
            self.assertTrue(require_supported(configuration())['valid'])

    def test_disabled_rule_does_not_translate(self):
        xml=configuration().replace(b'<disabled>no</disabled>',b'<disabled>yes</disabled>')
        self.assertEqual(compile_policy(xml)['plan']['rules'],[])

    def test_renderer_is_bounded_to_owned_devices(self):
        plan=compile_policy(configuration())['plan'];links={p:{'addr_info':[{'family':'inet','local':a}]} for p,a in [('p1','192.0.2.1'),('p2','198.51.100.1')]}
        script=runtime.render(plan,{'ethernet1/1':'p1','ethernet1/2':'p2'},links,1)
        self.assertIn('goto r0',script);self.assertIn('masquerade',script);self.assertNotIn('flush ruleset',script)
        with self.assertRaisesRegex(ValueError,'Uncommissioned'):runtime.render(plan,{},links,1)
        links['p1']['master']='vrf1'
        with self.assertRaisesRegex(ValueError,'main routing table'):runtime.render(plan,{'ethernet1/1':'p1','ethernet1/2':'p2'},links,1)

    def test_plan_rejects_command_injection_and_unknown_fields(self):
        plan=compile_policy(configuration())['plan'];plan['rules'][0]['source']=['0.0.0.0/0; flush ruleset']
        with self.assertRaises(ValueError):runtime.validate_plan(plan)
        plan=compile_policy(configuration())['plan'];plan['command']='anything'
        with self.assertRaises(ValueError):runtime.validate_plan(plan)

    def test_persistence_failure_restores_prior_rules(self):
        old={'revision':1,'digest':'old','script':'old table'};plan=compile_policy(configuration())['plan']
        with patch.object(runtime,'COORDINATED',Path('/nonexistent/ffn-test-policy-runtime.json')),patch.object(runtime,'prepare',return_value=(old,'new table','replace table')),patch.object(runtime,'nft') as nft,patch.object(runtime,'inspect',return_value=({'comment':'ffn-nat:'+runtime.digest(plan)},{'nftables':[]})),patch.object(runtime,'write_state',side_effect=OSError('full')):
            with self.assertRaises(OSError):runtime.apply({'revision':1,'plan':plan})
            self.assertEqual(nft.call_args_list[-1].args,(['-f','-'],'delete table ip ffn_nat\nold table'))


if __name__=='__main__':unittest.main()
