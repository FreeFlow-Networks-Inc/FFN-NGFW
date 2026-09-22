import copy
import unittest
import test_policy_plan as fixture
from ffn_nat_policy import compile_policy
from ffn_nat_runtime import validate_plan, NatError


class Distribution(unittest.TestCase):
    def test_compile_object_pool_and_three_selectors(self):
        for method in ('round-robin','source-ip-hash','ip-hash'):
            xml=fixture.configuration('nat',{'destination-type':'dynamic-ip',
                'translated-destination':'198.51.100.10-198.51.100.12','session-distribution':method})
            result=compile_policy(xml)
            self.assertTrue(result['valid'],result)
            translation=result['plan']['rules'][0]['dnat']
            self.assertEqual(translation,dict(type='dynamic',addresses=['198.51.100.10','198.51.100.11','198.51.100.12'],method=method))
            validate_plan(result['plan'])
            for update in ({'method':'least-sessions'},{'addresses':[]},{'addresses':['127.0.0.1']},
                           {'addresses':['198.51.100.1']*2},{'command':'write'}):
                bad=copy.deepcopy(result['plan']);bad['rules'][0]['dnat'].update(update)
                with self.assertRaises(NatError):validate_plan(bad)

    def test_large_unresolved_and_unsupported_pools_fail_closed(self):
        for target in ('198.51.0.0/16','unresolved.example'):
            result=compile_policy(fixture.configuration('nat',{'destination-type':'dynamic-ip',
                'translated-destination':target,'session-distribution':'round-robin'}))
            self.assertFalse(result['valid'])
