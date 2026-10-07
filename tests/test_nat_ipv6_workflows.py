import unittest
import test_policy_config
import test_policy_workflows


class IPv6NatWorkflows(unittest.TestCase):
    def setUp(self):self.f=test_policy_config.PolicyTests();self.f.setUp()
    def tearDown(self):self.f.tearDown()

    def test_candidate_roundtrip_disabled_modes_and_running_isolation(self):
        before=self.f.manager.get_running()
        for kind,values in [('nat64',{'nat64-prefix':'2001:db8:64::/96','nat64-pool':['192.0.2.10']}),
                            ('nptv6',{'nptv6-internal-prefix':'fd01:203:405::/48','nptv6-external-prefix':'2001:db8:1::/48'})]:
            spec=self.f.spec('nat',kind,**{'nat-type':kind,**values})
            result=self.f.mutate('nat',rule=spec);self.assertEqual(result.status_code,200,result.text)
            row=next(r for r in self.f.client.get('/api/config/policies/nat').json()['entries'] if r['name']==kind)
            self.assertTrue(row['editable']);self.assertEqual(row['settings'],spec['settings'])
        self.assertEqual(self.f.manager.get_running(),before)

    def test_invalid_mode_mixtures_and_prefixes_do_not_write_candidate(self):
        before=self.f.manager.get_candidate()
        for values in ({'nat-type':'nat64'}, {'nat-type':'ipv4','nat64-prefix':'2001:db8::/96'},
                       {'nat-type':'nptv6','nptv6-internal-prefix':'fd01:203:405::1/48','nptv6-external-prefix':'2001:db8:1::/48'}):
            result=self.f.mutate('nat',rule=self.f.spec('nat',**values))
            self.assertEqual(result.status_code,422,result.text);self.assertEqual(self.f.manager.get_candidate(),before)

    def test_live_address_objects_are_resolved_for_prefixes_and_pools(self):
        path=self.f.directory/'candidate-config.xml'
        xml=path.read_text().replace('<shared>','<shared><address><entry name="translation-prefix"><ip-netmask>2001:db8:64::/96</ip-netmask></entry><entry name="pool-host"><ip-netmask>192.0.2.10/32</ip-netmask></entry></address>')
        path.write_text(xml,newline='\n')
        spec=self.f.spec('nat',**{'nat-type':'nat64','nat64-prefix':'translation-prefix','nat64-pool':['pool-host']})
        result=self.f.mutate('nat',rule=spec);self.assertEqual(result.status_code,200,result.text)
        row=self.f.client.get('/api/config/policies/nat').json()['entries'][0]
        self.assertEqual(row['settings']['nat64-prefix'],'translation-prefix')

    def test_cli_mode_change_cleans_only_prior_mode_fields(self):
        f=test_policy_workflows.WorkflowTests();f.setUp()
        try:
            calls,_=f.cli('request','policies','nat','add','v6','nat-type=nat64','nat64-prefix=2001:db8:64::/96','nat64-pool=192.0.2.10')
            self.assertEqual(calls[-1][-1],200,calls)
            calls,_=f.cli('request','policies','nat','edit','v6','nat-type=nptv6','nptv6-internal-prefix=fd01:203:405::/48','nptv6-external-prefix=2001:db8:1::/48')
            self.assertEqual(calls[-1][-1],200,calls)
            row=f.f.client.get('/api/config/policies/nat').json()['entries'][0]['settings']
            self.assertEqual(row['nat64-prefix'],'');self.assertEqual(row['nat64-pool'],[])
            self.assertEqual(row['nat-type'],'nptv6')
            calls,_=f.cli('request','policies','nat','edit','v6','nat-type=ipv4','source-type=dynamic-ip-and-port','source-interface=ethernet1/1')
            self.assertEqual(calls[-1][-1],200,calls)
            row=f.f.client.get('/api/config/policies/nat').json()['entries'][0]['settings']
            self.assertEqual(row['nptv6-internal-prefix'],'');self.assertEqual(row['source-interface'],'ethernet1/1')
        finally:f.tearDown()


if __name__=='__main__':unittest.main()
