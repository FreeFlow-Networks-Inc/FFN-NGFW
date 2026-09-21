import unittest
from xml.etree import ElementTree as ET
import test_policy_config
import test_policy_workflows
from ffn_policy_config import describe,require_supported,PolicyError
from ffn_nat_policy import compile_policy


class TranslationModes(unittest.TestCase):
    def setUp(self):self.fixture=test_policy_config.PolicyTests();self.fixture.setUp()
    def tearDown(self):self.fixture.tearDown()
    def save(self,name,**settings):
        f=self.fixture;spec=f.spec('nat',name,**settings)
        response=f.mutate('nat',rule=spec);self.assertEqual(response.status_code,200,response.text)
        result=f.client.get('/api/config/policies/nat').json()
        row=next(r for r in result['entries'] if r['name']==name)
        self.assertTrue(row['editable']);self.assertEqual(row['settings'],spec['settings'])
        return row
    def test_persistent_pool_and_interface_roundtrip(self):
        for name,fields in [('pool',{'translated-source':['198.51.100.1']}),('interface',{'source-interface':'ethernet1/1'})]:
            self.save(name,**{'source-type':'persistent-dynamic-ip-and-port',**fields})
        self.assertIn('persistent-dynamic-ip-and-port',self.fixture.manager.get_candidate())
    def test_all_distribution_methods_roundtrip_and_none_runtime(self):
        for method in ['round-robin','source-ip-hash','ip-modulo','ip-hash','least-sessions']:
            self.save(method,**{'destination-type':'dynamic-ip','translated-destination':'192.0.2.10','session-distribution':method})
        self.assertIn('<dynamic-destination-translation>',self.fixture.manager.get_candidate())
        self.assertEqual(compile_policy(self.fixture.manager.get_candidate())['plan']['rules'],[])
        self.assertNotIn('dynamic-destination-translation',self.fixture.manager.get_running())
    def test_modes_fail_closed_when_enabled(self):
        for name,settings,reason in [('persistent',{'source-type':'persistent-dynamic-ip-and-port','source-interface':'ethernet1/1'},'persistent-binding'),
                                     ('distributed',{'destination-type':'dynamic-ip','translated-destination':'192.0.2.1','session-distribution':'least-sessions'},'session-distribution')]:
            self.save(name,**settings)
            self.assertEqual(self.fixture.mutate('nat','toggle',name=name,enabled=True).status_code,200)
            report=compile_policy(self.fixture.manager.get_candidate())
            self.assertFalse(report['valid']);self.assertTrue(any(reason in b['reason'] for b in report['blockers']),report)
            with self.assertRaises(PolicyError):require_supported(self.fixture.manager.get_candidate())
    def test_invalid_combinations_leave_candidate_unchanged(self):
        invalid=[{'destination-type':'none','translated-destination':'192.0.2.1'},
                 {'destination-type':'dynamic-ip','translated-destination':'192.0.2.1'},
                 {'destination-type':'dynamic-ip','translated-destination':'192.0.2.1','session-distribution':'random'},
                 {'destination-type':'static-ip','translated-destination':'192.0.2.1','session-distribution':'round-robin'},
                 {'source-type':'persistent-dynamic-ip-and-port'},
                 {'source-type':'static-ip','source-interface':'ethernet1/1'}]
        for settings in invalid:
            before=self.fixture.manager.get_candidate()
            response=self.fixture.mutate('nat',rule=self.fixture.spec('nat',**settings))
            self.assertEqual(response.status_code,422,response.text);self.assertEqual(self.fixture.manager.get_candidate(),before)
    def test_legacy_static_destination_and_unknown_xml_preserved(self):
        old=ET.fromstring('<entry name="old"><disabled>yes</disabled><destination-translation><translated-address>192.0.2.1</translated-address></destination-translation></entry>')
        row=describe('nat',old);self.assertTrue(row['editable']);self.assertEqual(row['settings']['destination-type'],'static-ip')
        # Old API clients omit the newly introduced type field.
        spec=self.fixture.spec('nat',**{'translated-destination':'192.0.2.1'});del spec['settings']['destination-type']
        self.assertEqual(self.fixture.mutate('nat',rule=spec).status_code,200)
        ET.SubElement(old,'dynamic-destination-translation')
        self.assertFalse(describe('nat',old)['editable'],'Conflicting imported translations must not be editable')


class TranslationCLI(unittest.TestCase):
    def test_cli_persistent_dynamic_edit_and_cleanup(self):
        f=test_policy_workflows.WorkflowTests();f.setUp()
        try:
            calls,_=f.cli('request','policies','nat','add','advanced','source-type=persistent-dynamic-ip-and-port','source-interface=ethernet1/1','destination-type=dynamic-ip','translated-destination=192.0.2.1','session-distribution=ip-hash')
            self.assertEqual(calls[-1][-1],200,calls)
            calls,_=f.cli('request','policies','nat','edit','advanced','translated-destination=192.0.2.2')
            self.assertEqual(calls[-1][-1],200,calls)
            row=f.f.client.get('/api/config/policies/nat').json()['entries'][0]['settings']
            self.assertEqual(row['destination-type'],'dynamic-ip');self.assertEqual(row['session-distribution'],'ip-hash');self.assertEqual(row['source-interface'],'ethernet1/1')
            calls,_=f.cli('request','policies','nat','edit','advanced','destination-type=none','source-type=none')
            self.assertEqual(calls[-1][-1],200,calls)
            row=f.f.client.get('/api/config/policies/nat').json()['entries'][0]['settings']
            for key in ['translated-destination','translated-port','session-distribution','source-interface']:self.assertEqual(row[key],'')
        finally:f.tearDown()
