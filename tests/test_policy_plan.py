import copy
from pathlib import Path
import sys
import unittest
import xml.etree.ElementTree as ET

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'opt'))
from ffn_policy_config import SCHEMAS, PolicyError, parse, node_at, serialize
from ffn_policy_plan import compile_policy, test_policy
from ffn_nat_runtime import rule_usage

XML='''<config><shared><address><entry name="lan"><ip-netmask>192.0.2.0/24</ip-netmask></entry></address>
<application><entry name="custom-web"/></application>
<service><entry name="web"><protocol><tcp><port>443,8000-8080</port></tcp></protocol></entry></service>
<certificate><entry name="server"><private-key>DO-NOT-EXPOSE</private-key></entry></certificate>
</shared><devices><entry name="localhost.localdomain"><network><interface><ethernet>
<entry name="ethernet1/1"><layer3/></entry><entry name="ethernet1/2"><layer3/></entry><entry name="ethernet1/3"><layer2/></entry>
</ethernet></interface></network><vsys><entry name="vsys1"><zone>
<entry name="trust"><network><layer3><member>ethernet1/1</member></layer3></network></entry>
<entry name="untrust"><network><layer3><member>ethernet1/2</member></layer3></network></entry>
</zone></entry><entry name="vsys2"/></vsys></entry></devices></config>'''
PACKET=dict(source='192.0.2.10',destination='198.51.100.10',from_zone='trust',to_zone='untrust',protocol='tcp',destination_port=443)


def configuration(kind,*rules):
    root=parse(XML);target=node_at(root.find('./devices/entry/vsys/entry'),'rulebase/'+kind+'/rules')
    for i,settings in enumerate(rules):
        fields={f['key']:copy.deepcopy(f['default']) if f['default'] is not None else '' for f in SCHEMAS[kind]['fields']}
        fields.update({'from':['trust'],'to':['untrust'],'source':['lan']});fields.update(settings)
        enabled=fields.pop('enabled',True)
        target.append(serialize(kind,dict(name='rule-'+str(i),description='',enabled=enabled,settings=fields)))
    return ET.tostring(root)


class PlanTests(unittest.TestCase):
    def test_actions_and_order_all_four_kinds(self):
        examples=[('nat',{'source-type':'dynamic-ip-and-port','source-interface':'ethernet1/2'},'source_translation',{'type':'masquerade','interface':'ethernet1/2'}),
                  ('qos',{'class':'3'},'class',3),
                  ('pbf',{'action':'forward','egress-interface':'ethernet1/2','next-hop':'198.51.100.1'},'interface','ethernet1/2'),
                  ('decryption',{'action':'decrypt','type':'ssl-inbound-inspection','certificate':'server'},'certificate','server')]
        for kind,settings,key,value in examples:
            with self.subTest(kind=kind):
                xml=configuration(kind,dict(settings,source=['203.0.113.0/24']),settings,settings)
                plan=compile_policy(xml,kind);self.assertTrue(plan['valid'],plan)
                result=test_policy(xml,kind,'vsys1',PACKET)
                self.assertEqual(result['selected']['name'],'rule-1');self.assertEqual(len(result['trace']),2)
                self.assertEqual(result['selected']['action'][key],value);self.assertFalse(result['applied'])
                self.assertNotIn('DO-NOT-EXPOSE',str(result));self.assertNotIn('DO-NOT-EXPOSE',str(plan))

    def test_disabled_and_scope_isolation(self):
        xml=configuration('qos',{'enabled':False,'class':'1'},{'class':'7'})
        self.assertEqual(compile_policy(xml,'qos')['disabled_rules'],1)
        self.assertEqual(test_policy(xml,'qos','vsys1',PACKET)['selected']['action']['class'],7)
        self.assertEqual(compile_policy(xml,'qos','vsys2')['plan']['rules'],[])
        with self.assertRaises(PolicyError):compile_policy(xml,'qos','missing')

    def test_ports_groups_and_indeterminate_first_match(self):
        xml=configuration('qos',{'service':['web'],'application':['custom-web'],'class':'1'},{'class':'8'})
        result=test_policy(xml,'qos','vsys1',PACKET)
        self.assertEqual(result['status'],'indeterminate');self.assertIsNone(result['selected'])
        self.assertEqual(test_policy(xml,'qos','vsys1',dict(PACKET,application='custom-web'))['selected']['action']['class'],1)
        # Known nonmatch takes precedence over a missing application identity.
        self.assertEqual(test_policy(xml,'qos','vsys1',dict(PACKET,destination_port=22))['selected']['action']['class'],8)
        self.assertEqual(test_policy(xml,'qos','vsys1',dict(PACKET,application='custom-web',destination_port=8050))['selected']['action']['class'],1)
        missing=dict(PACKET,application='custom-web');missing.pop('destination_port')
        self.assertEqual(test_policy(xml,'qos','vsys1',missing)['status'],'indeterminate')

    def test_unhandled_rule_cannot_fall_through(self):
        xml=configuration('pbf',{'action':'discard'},{'action':'no-pbf'}).replace(b'<action><discard',b'<unsupported/><action><discard',1)
        result=test_policy(xml,'pbf','vsys1',PACKET)
        self.assertEqual(result['status'],'indeterminate');self.assertEqual(len(result['trace']),1)
        self.assertFalse(compile_policy(xml,'pbf')['valid'])

    def test_nat_specific_egress_and_no_nat_exception(self):
        xml=configuration('nat',{'to-interface':'ethernet1/2'},{'source-type':'dynamic-ip-and-port','source-interface':'ethernet1/2'})
        self.assertEqual(test_policy(xml,'nat','vsys1',PACKET)['status'],'indeterminate')
        result=test_policy(xml,'nat','vsys1',dict(PACKET,egress_interface='ethernet1/2'))
        self.assertEqual(result['selected']['action']['source_translation'],{'type':'none'})

    def test_pbf_and_decryption_prerequisites(self):
        for kind,settings in [('pbf',{'action':'forward','egress-interface':'ethernet1/3'}),
                              ('pbf',{'action':'forward','egress-interface':'ethernet1/2','next-hop':'2001:db8::1'}),
                              ('decryption',{'action':'decrypt','type':'ssl-inbound-inspection'})]:
            self.assertFalse(compile_policy(configuration(kind,settings),kind)['valid'],settings)

    def test_packet_validation(self):
        for update in [{'source':'2001:db8::1'},{'from_zone':'missing'},{'destination_port':True},
                       {'protocol':'icmp'},{'destination_port':0},{'command':'apply'}]:
            with self.assertRaises(PolicyError):test_policy(configuration('qos',{}),'qos','vsys1',dict(PACKET,**update))

    def test_nat_counters_only_trusted_for_matching_generation(self):
        state={'revision':3,'plan':{'rules':[{'name':'internet','scope':'vsys1'}]}}
        data={'nftables':[{'rule':{'family':'ip','table':'ffn_nat','chain':'r0','expr':[{'counter':{'packets':9,'bytes':450}}]}}]}
        self.assertEqual(rule_usage(state,data,True)[0]['packets'],9)
        self.assertIsNone(rule_usage(state,data,False)[0]['packets'])
        self.assertFalse(rule_usage(state,{'nftables':[]},True)[0]['available'])
        data['nftables']*=2
        self.assertFalse(rule_usage(state,data,True)[0]['available'])

    def test_api_and_cli_share_read_only_controller(self):
        from test_policy_config import PolicyTests
        from ffn_policy_cli import handle
        from contextlib import redirect_stdout
        from unittest.mock import Mock
        import io,json
        fixture=PolicyTests();fixture.setUp()
        try:
            candidate=configuration('qos',{'class':'2'})
            (fixture.directory/'candidate-config.xml').write_bytes(candidate)
            running=(fixture.directory/'running-config.xml').read_bytes()
            fixture.role='viewer'
            response=fixture.client.post('/api/config/policies/qos/test',json={'packet':PACKET})
            self.assertEqual(response.status_code,200,response.text);self.assertEqual(response.json()['status'],'matched')
            self.assertTrue(fixture.client.get('/api/config/policies/qos/preview').json()['valid'])
            self.assertEqual(fixture.client.post('/api/config/policies/qos/test',json={'packet':dict(PACKET,protocol='invalid')}).status_code,422)
            fixture.role=None
            self.assertEqual(fixture.client.get('/api/config/policies/qos/preview').status_code,401)
            self.assertEqual(fixture.client.post('/api/config/policies/qos/test',json={'packet':PACKET}).status_code,401)
            self.assertEqual((fixture.directory/'candidate-config.xml').read_bytes(),candidate)
            self.assertEqual((fixture.directory/'running-config.xml').read_bytes(),running)
            self.assertIsNone(fixture.manager.holder);fixture.audit.assert_not_called()
            api=Mock(return_value={})
            with redirect_stdout(io.StringIO()):
                handle(['request','policies','qos','test',json.dumps(PACKET),'vsys1','running'],api,'token')
            self.assertIn('source=running',api.call_args.args[0]);self.assertEqual(api.call_args.kwargs['body'],{'packet':PACKET})
        finally:fixture.tearDown()


if __name__=='__main__':unittest.main()
