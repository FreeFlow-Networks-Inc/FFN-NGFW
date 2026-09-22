import copy
import io
import unittest
from contextlib import redirect_stdout
from unittest.mock import Mock
import test_policy_workflows
from ffn_policy_config import revision,runtime_report,require_supported,PolicyError
from ffn_policy_cli import handle
from ffn_qos_config import budget,interfaces


class QosInterfaces(unittest.TestCase):
    def setUp(self):
        self.w=test_policy_workflows.WorkflowTests();self.w.setUp();self.f=self.w.f
        self.addCleanup(self.w.tearDown)
        self.assertEqual(self.w.profile('qos').status_code,200)
    def get(self,source='candidate'):return self.f.client.get('/api/config/qos/interfaces?source='+source).json()
    def put(self,action='create',spec=None,**extra):
        spec=spec or dict(self.get()['defaults'],interface='ethernet1/1',profile='profile')
        payload=dict(action=action,name=spec['interface'],revision=revision(self.f.manager.get_candidate()),**({} if action=='delete' else {'attachment':spec}));payload.update(extra)
        return self.f.client.post('/api/config/qos/interfaces',json=payload)

    def test_candidate_roundtrip_and_effective_eight_class_budget(self):
        before=self.f.manager.get_running();self.assertEqual(self.put().status_code,200)
        data=self.get();self.assertEqual(len(data['entries']),1);self.assertEqual(self.get('running')['entries'],[])
        p=data['plan']['interfaces'][0];self.assertEqual(len(p['classes']),8);self.assertEqual(p['max_mbps'],1000)
        self.assertTrue(all(c['max-mbps']==1000 for c in p['classes']));self.assertEqual(p['default_class'],4)
        self.assertFalse(data['applied']);self.assertEqual(self.f.manager.get_running(),before)
        spec={k:v for k,v in data['entries'][0].items() if k!='editable'};spec['max-mbps']=200
        self.assertEqual(self.put('update',spec).status_code,200)
        self.assertEqual(self.get()['plan']['interfaces'][0]['max_mbps'],200)
        self.assertEqual(self.put('delete').status_code,200);self.assertEqual(self.get()['entries'],[])

    def test_invalid_rates_references_and_interfaces_never_write(self):
        original=self.f.manager.get_candidate();base=dict(self.get()['defaults'],interface='ethernet1/1',profile='profile')
        for fields in ({'max-mbps':0},{'max-mbps':True},{'max-mbps':-1},{'max-mbps':1000001},{'default-class':9},{'default-class':True},{'enabled':'yes'},{'profile':'missing'},{'interface':'MGT'},{'interface':'ethernet1/99'},{'interface':'loopback.1'}):
            with self.subTest(fields=fields):
                self.assertEqual(self.put(spec=dict(base,**fields)).status_code,422)
                self.assertEqual(self.f.manager.get_candidate(),original)

    def test_budget_and_referenced_profile_updates_are_validated(self):
        settings=self.w.profiles('qos')['defaults'];settings['max-mbps']=200
        settings['classes'][0]['guaranteed-mbps']=60;settings['classes'][1]['guaranteed-mbps']=60
        self.assertEqual(self.w.profile('qos',action='update',settings=settings).status_code,200)
        spec=dict(self.get()['defaults'],interface='ethernet1/1',profile='profile',**{'max-mbps':100})
        self.assertEqual(self.put(spec=spec).status_code,422)
        settings['classes'][1]['guaranteed-mbps']=20;self.w.profile('qos',action='update',settings=settings)
        self.assertEqual(self.put(spec=spec).status_code,200)
        self.assertEqual(self.get()['plan']['interfaces'][0]['unreserved_mbps'],20)
        before=self.f.manager.get_candidate();settings['classes'][0]['max-mbps']=150
        self.assertEqual(self.w.profile('qos',action='update',settings=settings).status_code,409)
        self.assertEqual(self.w.profile('qos',action='delete').status_code,409)
        self.assertEqual(self.f.manager.get_candidate(),before)

    def test_enabled_attachment_cannot_bypass_activation_guard(self):
        spec=dict(self.get()['defaults'],interface='ethernet1/1',profile='profile',enabled=True)
        self.assertEqual(self.put(spec=spec).status_code,200)
        report=runtime_report(self.f.manager.get_candidate());self.assertFalse(report['valid'])
        self.assertEqual(report['blockers'][0]['kind'],'qos-interface')
        with self.assertRaises(PolicyError):require_supported(self.f.manager.get_candidate())
        spec['enabled']=False;self.assertEqual(self.put('update',spec).status_code,200)
        self.assertTrue(runtime_report(self.f.manager.get_candidate())['valid'])

    def test_auth_lock_revision_and_controller_outage(self):
        self.f.role=None;self.assertEqual(self.f.client.get('/api/config/qos/interfaces').status_code,401)
        self.f.role='read-only';self.assertFalse(self.get()['can_edit']);self.assertEqual(self.put().status_code,403)
        self.f.role='admin';self.f.manager.holder='other';self.assertEqual(self.put().status_code,423)
        self.f.manager.holder=None;rev=self.get()['revision'];self.w.profile('qos',name='second')
        self.assertEqual(self.put(revision=rev).status_code,409)
        self.f.gateway.query=Mock(side_effect=RuntimeError('offline'))
        self.assertEqual(self.f.client.get('/api/config/qos/interfaces').status_code,503)
        self.assertEqual(self.f.client.post('/api/config/qos/interfaces?source=running',json={'action':'delete','name':'ethernet1/1','revision':rev}).status_code,403)

    def test_imported_fields_protected_and_plan_not_fabricated(self):
        self.put();path=self.f.directory/'candidate-config.xml'
        path.write_text(path.read_text().replace('<qos><interface>','<qos><interface>').replace('<default-class>4</default-class>','<default-class>4</default-class><tunnel-profile>legacy</tunnel-profile>'))
        before=path.read_bytes();data=self.get()
        self.assertFalse(data['entries'][0]['editable']);self.assertFalse(data['plan']['valid']);self.assertEqual(data['plan']['interfaces'],[])
        self.assertEqual(self.put('delete').status_code,409);self.assertEqual(path.read_bytes(),before)

    def test_nonfinite_import_is_reported_without_invalid_json(self):
        self.put();path=self.f.directory/'candidate-config.xml'
        from ffn_policy_config import parse
        import xml.etree.ElementTree as ET
        root=parse(path.read_bytes());root.find('.//qos/interface/entry/max-mbps').text='NaN'
        path.write_bytes(ET.tostring(root));response=self.f.client.get('/api/config/qos/interfaces')
        self.assertEqual(response.status_code,200)
        self.assertFalse(response.json()['entries'][0]['editable']);self.assertFalse(response.json()['plan']['valid'])

    def test_cli_friendly_commands_share_controller(self):
        calls,out=self.w.cli('request','policies','qos-interface','add','ethernet1/1','profile=profile','max-mbps=100','default-class=3')
        self.assertEqual(calls[-1][-1],200,out)
        calls,_=self.w.cli('request','policies','qos-interface','edit','ethernet1/1','max-mbps=200')
        self.assertEqual(calls[-1][-1],200);self.assertEqual(self.get()['entries'][0]['default-class'],3)
        self.w.cli('show','policies','qos-interfaces','running')
        calls,_=self.w.cli('request','policies','qos-interface','remove','ethernet1/1')
        self.assertEqual(calls[-1][-1],200);self.assertEqual(self.get()['entries'],[])


if __name__=='__main__':unittest.main()
