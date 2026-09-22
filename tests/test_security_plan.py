"""Security diagnostics must never report simulation as enforcement."""
import io
import json
from contextlib import redirect_stdout
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'opt'))
from ffn_policy_plan import compile_policy, test_policy
from ffn_policy_config import runtime_report, require_supported, PolicyError
from test_policy_plan import configuration, PACKET


class SecurityPlanTests(unittest.TestCase):
    def test_user_rule_compiles_but_activation_stays_blocked(self):
        xml=configuration('security',{'action':'allow','source':['any']})
        plan=compile_policy(xml,'security')
        self.assertTrue(plan['valid'],plan)
        action=plan['plan']['rules'][0]['action']
        self.assertEqual(action['type'],'allow')
        self.assertEqual(action['logging'],{'start':False,'end':True,'forwarding_profile':None})
        self.assertEqual(action['profiles'],{'mode':'none','group':None,'individual':{}})
        self.assertFalse(plan['applied'])
        report=runtime_report(xml,check_runtime=True)
        self.assertFalse(report['valid'])
        self.assertIn('plan compiled',report['blockers'][0]['reason'])
        self.assertIn('enforcement is not connected',report['blockers'][0]['reason'])
        with self.assertRaises(PolicyError):require_supported(xml)

    def test_order_and_disabled_rules(self):
        xml=configuration('security',{'action':'deny','service':['web']},
                          {'action':'deny','enabled':False},{'action':'allow'})
        self.assertEqual(test_policy(xml,'security','vsys1',PACKET)['selected']['action']['type'],'deny')
        result=test_policy(xml,'security','vsys1',dict(PACKET,destination_port=22))
        self.assertEqual(result['selected']['action']['type'],'allow')
        self.assertFalse(result['applied']);self.assertTrue(result['simulation'])

    def test_zone_types_and_implicit_policy_intent(self):
        xml=configuration('security',{'rule-type':'intrazone','to':['any'],'action':'drop'},
                          {'rule-type':'interzone','action':'allow'})
        self.assertEqual(test_policy(xml,'security','vsys1',PACKET)['selected']['name'],'rule-1')
        same=dict(PACKET,to_zone='trust')
        self.assertEqual(test_policy(xml,'security','vsys1',same)['selected']['action']['type'],'drop')
        empty=configuration('security')
        for packet,name in ((PACKET,'interzone-default'),(same,'intrazone-default')):
            result=test_policy(empty,'security','vsys1',packet)
            self.assertEqual(result['selected']['name'],name)
            self.assertTrue(result['selected']['implicit']);self.assertFalse(result['applied'])

    def test_application_default_is_not_any(self):
        xml=configuration('security',{'service':['application-default'],'action':'allow'},{'action':'deny'})
        result=test_policy(xml,'security','vsys1',PACKET)
        self.assertEqual(result['status'],'indeterminate');self.assertIsNone(result['selected'])
        self.assertIn('default-service resolver',result['trace'][0]['reason'])
        # A known source mismatch still allows evaluation of the next rule.
        result=test_policy(xml,'security','vsys1',dict(PACKET,source='203.0.113.1'))
        self.assertEqual(result['selected']['name'],'interzone-default')

    def test_device_and_user_identity_must_be_supplied(self):
        xml=configuration('security',{'source-device':['workstation'],'source-user':['alice'],'action':'allow'})
        xml=xml.replace(b'<shared>',b'<shared><device><entry name="workstation"/></device>')
        result=test_policy(xml,'security','vsys1',PACKET)
        self.assertEqual(result['status'],'indeterminate')
        self.assertEqual(test_policy(xml,'security','vsys1',dict(PACKET,source_device='workstation',source_user='alice'))['selected']['name'],'rule-0')
        self.assertEqual(test_policy(xml,'security','vsys1',dict(PACKET,source_device='another',source_user='alice'))['selected']['name'],'interzone-default')

    def test_imported_unknown_fields_stop_first_match(self):
        xml=configuration('security',{'action':'allow'},{'action':'allow'})
        xml=xml.replace(b'<action>allow</action>',b'<unsupported/><action>allow</action>',1)
        report=runtime_report(xml)
        self.assertIn('compilation failed',report['blockers'][0]['reason'])
        result=test_policy(xml,'security','vsys1',PACKET)
        self.assertEqual(result['status'],'indeterminate');self.assertIsNone(result['selected'])

    def test_cli_uses_existing_control_route(self):
        from ffn_policy_cli import handle
        api=Mock(return_value={})
        with redirect_stdout(io.StringIO()):
            handle(['show','policies','preview','security','vsys1','candidate'],api,None)
            self.assertIn('/api/config/policies/security/preview?',api.call_args.args[0])
            handle(['request','policies','security','test',json.dumps(PACKET),'vsys1','running'],api,None)
            self.assertEqual(api.call_args.kwargs['body'],{'packet':PACKET})


if __name__=='__main__':unittest.main()
