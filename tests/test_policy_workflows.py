import ast
import copy
import io
import json
from pathlib import Path
import unittest
from contextlib import redirect_stdout
import test_policy_config
from ffn_policy_cli import handle
from ffn_policy_config import revision,parse


class WorkflowTests(unittest.TestCase):
    def setUp(self):self.f=test_policy_config.PolicyTests();self.f.setUp()
    def tearDown(self):self.f.tearDown()
    def profiles(self,kind):return self.f.client.get('/api/config/policy-profiles/'+kind).json()
    def profile(self,kind,name='profile',settings=None,action='create',**extra):
        s=settings if settings is not None else self.profiles(kind)['defaults']
        return self.f.client.post('/api/config/policy-profiles/'+kind,json=dict(action=action,revision=revision(self.f.manager.get_candidate()),name=name,**({'profile':{'name':name,'settings':s}} if action!='delete' else {}),**extra))
    def cli(self,*tokens):
        calls=[]
        def api(path,method='GET',body=None,token=None):
            response=self.f.client.request(method,path,json=body);calls.append((path,method,body,response.status_code));return response.json()
        with redirect_stdout(io.StringIO()) as stream:handle(list(tokens),api,'fixture')
        return calls,stream.getvalue()

    def test_profile_roundtrip_and_running_isolation(self):
        before=self.f.manager.get_running()
        for kind in ('qos','decryption'):
            response=self.profile(kind);self.assertEqual(response.status_code,200,response.text)
            row=self.profiles(kind)['entries'][0];self.assertTrue(row['editable'],row)
            self.assertEqual(row['settings'],self.profiles(kind)['defaults'])
            self.assertEqual(self.f.client.get('/api/config/policy-profiles/'+kind+'?source=running').json()['entries'],[])
            settings=row['settings'];settings.update({'max-mbps':100,'guaranteed-mbps':50} if kind=='qos' else {'min-version':'tls1-3'})
            self.assertEqual(self.profile(kind,settings=settings,action='update').status_code,200)
            self.assertEqual(self.profiles(kind)['entries'][0]['settings'],settings)
            self.assertEqual(self.profile(kind,action='delete').status_code,200)
        self.assertEqual(self.f.manager.get_running(),before)

    def test_bandwidth_validation_no_candidate_write(self):
        base=self.profiles('qos')['defaults']
        bad=[]
        for changes in ({'max-mbps':-1},{'max-mbps':True},{'max-mbps':10,'guaranteed-mbps':11},{'classes':base['classes'][:-1]}):bad.append(dict(copy.deepcopy(base),**changes))
        x=copy.deepcopy(base);x['classes'][1]['id']=1;bad.append(x)
        x=copy.deepcopy(base);x['max-mbps']=100
        for row in x['classes']:row['guaranteed-mbps']=20
        bad.append(x)
        x=copy.deepcopy(base);x['classes'][0]['priority']='urgent';bad.append(x)
        for settings in bad:
            before=self.f.manager.get_candidate();response=self.profile('qos',settings=settings)
            self.assertEqual(response.status_code,422,response.text);self.assertEqual(self.f.manager.get_candidate(),before)

    def test_decryption_versions_and_references(self):
        s=self.profiles('decryption')['defaults'];s.update({'min-version':'tls1-3','max-version':'tls1-2'})
        self.assertEqual(self.profile('decryption',settings=s).status_code,422)
        self.assertEqual(self.profile('decryption').status_code,200)
        self.assertEqual(self.f.mutate('decryption',rule=self.f.spec('decryption',profile='profile')).status_code,200)
        self.assertIn('profile',self.f.client.get('/api/config/policies/decryption').json()['choices']['profile'])
        self.assertEqual(self.profile('decryption',action='delete').status_code,409)

    def test_fractional_bandwidth_guarantees(self):
        s=self.profiles('qos')['defaults'];s.update({'max-mbps':0.3,'guaranteed-mbps':0.3})
        s['classes'][0]['guaranteed-mbps']=0.1;s['classes'][1]['guaranteed-mbps']=0.2
        response=self.profile('qos',settings=s);self.assertEqual(response.status_code,200,response.text)

    def test_profile_locks_auth_revision_and_import_protection(self):
        self.f.role='viewer';self.assertFalse(self.profiles('qos')['can_edit']);self.assertEqual(self.profile('qos').status_code,403)
        self.f.role=None;self.assertEqual(self.f.client.get('/api/config/policy-profiles/qos').status_code,401)
        self.f.role='admin';self.f.manager.holder='another-admin';self.assertEqual(self.profile('qos').status_code,423)
        self.f.manager.holder=None;self.assertEqual(self.profile('qos').status_code,200)
        data=self.profiles('qos');self.assertEqual(self.f.client.post('/api/config/policy-profiles/qos',json={'action':'delete','name':'profile','revision':'0'*64}).status_code,409)
        path=self.f.directory/'candidate-config.xml';text=path.read_text();path.write_text(text.replace('<aggregate-bandwidth>','<future-field/><aggregate-bandwidth>'))
        self.assertFalse(self.profiles('qos')['entries'][0]['editable']);self.assertEqual(self.profile('qos',action='delete').status_code,409)

    def test_friendly_rule_lifecycle_and_mode_cleanup(self):
        calls,_=self.cli('request','policies','pbf','add','route web','action=forward','egress-interface=ethernet1/1','next-hop=192.0.2.1')
        self.assertEqual(calls[-1][-1],200,calls)
        calls,_=self.cli('request','policies','pbf','edit','route web','action=discard')
        self.assertEqual(calls[-1][-1],200,calls)
        s=self.f.client.get('/api/config/policies/pbf').json()['entries'][0]['settings'];self.assertEqual(s['egress-interface'],'');self.assertEqual(s['next-hop'],'')
        self.cli('request','policies','pbf','clone','route web','copy')
        self.cli('request','policies','pbf','before','copy','route web')
        entries=self.f.client.get('/api/config/policies/pbf').json()['entries'];self.assertEqual([r['name'] for r in entries],['copy','route web'])
        self.cli('request','policies','pbf','enable','copy');self.assertTrue(self.f.client.get('/api/config/policies/pbf').json()['entries'][0]['enabled'])
        self.cli('request','policies','pbf','disable','copy');self.cli('request','policies','pbf','remove','copy')
        before=self.f.manager.get_candidate();calls,message=self.cli('request','policies','pbf','edit','route web','unknown=1')
        self.assertIn('Unknown rule field',message);self.assertEqual(self.f.manager.get_candidate(),before);self.assertEqual(len(calls),1)

    def test_friendly_nat_and_profile_fields(self):
        calls,_=self.cli('request','policies','nat','add','outbound','source-type=dynamic-ip-and-port','source-interface=ethernet1/1','source=192.0.2.0/24,198.51.100.0/24')
        self.assertEqual(calls[-1][-1],200,calls)
        self.cli('request','policies','nat','edit','outbound','source-type=none')
        self.assertEqual(self.f.client.get('/api/config/policies/nat').json()['entries'][0]['settings']['source-interface'],'')
        calls,_=self.cli('request','policies','profiles','qos','add','wan','max-mbps=100','class1.priority=real-time','class1.guaranteed-mbps=20')
        self.assertEqual(calls[-1][-1],200,calls)
        row=self.profiles('qos')['entries'][0];self.assertEqual(row['settings']['classes'][0]['priority'],'real-time')
        calls,_=self.cli('request','policies','profiles','decryption','add','strict','min-version=tls1-3')
        self.assertEqual(calls[-1][-1],200,calls)

    def test_sql_sync_cannot_own_xml_qos_profiles(self):
        tree=ast.parse((Path(__file__).resolve().parents[1]/'opt/ffn_manager.py').read_text(encoding='utf-8'))
        function=next(n for n in tree.body if isinstance(n,ast.AsyncFunctionDef) and n.name=='_sync_netresources_to_xml')
        dictionaries=[n for n in ast.walk(function) if isinstance(n,ast.Dict)]
        self.assertFalse(any(isinstance(k,ast.Constant) and k.value in ('qos-profiles','qos-policies') for d in dictionaries for k in d.keys))


if __name__=='__main__':unittest.main()
