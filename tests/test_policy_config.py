import ast
import copy
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest.mock import AsyncMock,Mock
from fastapi import FastAPI,HTTPException
from fastapi.testclient import TestClient
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'opt'))
from ffn_policy_config import PolicyController,SCHEMAS,SECURITY_PROFILES,revision,require_supported,PolicyError,configd_validate,parse
from ffn_policy_api import install
from ffn_policy_cli import handle
from ffn_config_objects import install as install_objects

XML='''<config><shared><application><entry name="custom-app"><category>business</category></entry></application>
<authentication-enforcement><entry name="auth-profile"/></authentication-enforcement>
<device><entry name="workstation"/></device><tag><entry name="reviewed"/></tag>
<profile-group><entry name="inspection"/></profile-group>
<log-settings><profiles><entry name="central-logs"/></profiles></log-settings>
<profiles><sdwan-path-quality><entry name="quality"/></sdwan-path-quality><sdwan-traffic-distribution><entry name="distribution"/></sdwan-traffic-distribution></profiles>
</shared><devices><entry name="localhost.localdomain"><network><interface><ethernet><entry name="ethernet1/1"><layer3/></entry></ethernet></interface></network>
<vsys><entry name="vsys1"><zone><entry name="trust"/><entry name="untrust"/></zone></entry><entry name="vsys2"/></vsys></entry></devices></config>'''
XML=XML.replace('<profiles><sdwan','<profiles>'+''.join('<'+path+'><entry name="inspect-'+key+'"/></'+path+'>' for key,(_,path) in SECURITY_PROFILES.items())+'<sdwan',1)


class Manager:
    def __init__(self,directory):self.directory=Path(directory);self.holder=None
    def lock_status(self):return dict(locked=self.holder is not None,holder=self.holder)
    def acquire_lock(self,user,reason):self.holder=user;return True
    def release_lock(self,user):self.holder=None
    def get_candidate(self):return (self.directory/'candidate-config.xml').read_text()
    def get_running(self):return (self.directory/'running-config.xml').read_text()
    def _save(self,root,path):
        import xml.etree.ElementTree as ET
        Path(path).write_bytes(ET.tostring(root))


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.directory=Path(self.temp.name);self.role='admin'
        for name in ('candidate','running'):(self.directory/(name+'-config.xml')).write_text(XML,newline='\n')
        self.controller=PolicyController(self.directory);self.manager=Manager(self.directory)
        class Client:
            def query(client,command,**payload):
                if command=='nat/preview':
                    from ffn_nat_policy import compile_policy
                    return dict(compile_policy(self.manager.get_candidate() if payload.get('source')!='running' else self.manager.get_running()),commissioned=False,runtime={'available':False,'applied':False,'error':'No fixture dataplane'})
                assert command=='policy/request'
                return self.controller.request(payload)
        self.gateway=Client();app=FastAPI();self.audit=AsyncMock()
        async def current():
            if self.role is None:raise HTTPException(401)
            return dict(username='tester',role=self.role)
        def admin(user):
            if user['role']!='admin':raise HTTPException(403)
        install(app,current,admin,self.audit,self.manager,self.gateway)
        install_objects(app,current,admin,self.audit,self.manager,self.directory/'candidate-config.xml')
        self.client=TestClient(app)

    def tearDown(self):self.temp.cleanup()

    def test_reserved_security_defaults_cannot_be_created(self):
        for name in ('intrazone-default','interzone-default'):
            before=(self.directory/'candidate-config.xml').read_bytes()
            result=self.mutate('security',rule=self.spec('security',name))
            self.assertEqual(result.status_code,403)
            self.assertEqual((self.directory/'candidate-config.xml').read_bytes(),before)

    def test_imported_security_defaults_are_read_only(self):
        self.assertEqual(self.mutate('security',rule=self.spec('security','import-me')).status_code,200)
        path=self.directory/'candidate-config.xml'
        path.write_text(path.read_text().replace('name="import-me"','name="intrazone-default"'),newline='\n')
        before=path.read_bytes()
        row=self.client.get('/api/config/policies/security').json()['entries'][0]
        self.assertTrue(row['is_implicit']);self.assertFalse(row['editable'])
        for action,payload in [('update',{'rule':self.spec('security','renamed')}),
                               ('toggle',{'enabled':True}),('move',{'position':1}),('delete',{})]:
            with self.subTest(action=action):
                self.assertEqual(self.mutate('security',action,name='intrazone-default',**payload).status_code,403)
                self.assertEqual(path.read_bytes(),before)

    def spec(self,kind,name='rule',**settings):
        fields={f['key']:copy.deepcopy(f['default']) if f['default'] is not None else '' for f in SCHEMAS[kind]['fields']}
        fields.update({'application-override':dict(application='custom-app',port='443'),
                       'authentication':{'authentication-enforcement':'auth-profile'},
                       'sdwan':{'path-quality-profile':'quality','traffic-distribution-profile':'distribution'}}.get(kind,{}))
        fields.update(settings)
        return dict(name=name,description='fixture',enabled=False,settings=fields)

    def mutate(self,kind,action='create',**payload):
        return self.client.post('/api/config/policies/'+kind,json=dict(action=action,revision=revision(self.manager.get_candidate()),**payload))

    def test_all_ten_roundtrip_order_toggle_and_delete(self):
        for kind in SCHEMAS:
            with self.subTest(kind=kind):
                first=self.spec(kind,'first');second=self.spec(kind,'second')
                result=self.mutate(kind,rule=first);self.assertEqual(result.status_code,200,result.text)
                self.assertEqual(self.mutate(kind,rule=second).status_code,200)
                result=self.client.get('/api/config/policies/'+kind).json()
                self.assertTrue(all(r['editable'] for r in result['entries']),result)
                self.assertEqual(result['entries'][0]['settings'],first['settings'])
                first['description']='updated'
                self.assertEqual(self.mutate(kind,'update',name='first',rule=first).status_code,200)
                self.assertEqual(self.mutate(kind,'move',name='second',position=1).status_code,200)
                self.assertEqual(self.client.get('/api/config/policies/'+kind).json()['entries'][0]['name'],'second')
                self.assertEqual(self.mutate(kind,'toggle',name='first',enabled=True).status_code,200)
                report=self.client.get('/api/config/policies/status').json();self.assertFalse(report['valid']);self.assertFalse(report['applied'])
                with self.assertRaises(PolicyError):require_supported(self.manager.get_candidate())
                self.assertEqual(self.mutate(kind,'toggle',name='first',enabled=False).status_code,200)
                self.assertEqual(self.mutate(kind,'delete',name='second').status_code,200)
        self.assertEqual(self.manager.get_running(),XML)
        self.assertTrue(require_supported(self.manager.get_candidate())['valid'])

    def test_shared_objects_are_discovered_and_deletion_protected(self):
        payload=dict(name='office',type='ip-netmask',value='192.0.2.0/24',revision=revision(self.manager.get_candidate()))
        self.assertEqual(self.client.post('/api/config/objects/address',json=payload).status_code,200)
        listed=self.client.get('/api/config/policies/security').json()
        self.assertIn('office',listed['choices']['source'])
        self.assertEqual(self.mutate('security',rule=self.spec('security',source=['office'])).status_code,200)
        self.assertEqual(self.client.delete('/api/config/objects/address/office',params={'revision':revision(self.manager.get_candidate())}).status_code,409)

    def test_rejections_do_not_mutate_candidate(self):
        for kind,settings in [('qos',{'class':'9'}),('security',{'from':['missing']}),('security',{'source':['any','192.0.2.1']}),
            ('security',{'source':[['bad']]}),('security',{'future':'ignored?'}),('pbf',{'action':'forward'}),
            ('nat',{'source-type':'static-ip','translated-source':[]}),('nat',{'translated-port':'65536'}),
            ('application-override',{'port':'80-1'}),('authentication',{'timeout':'0'}),('sdwan',{'path-quality-profile':'missing'})]:
            before=self.manager.get_candidate();result=self.mutate(kind,rule=self.spec(kind,**settings))
            self.assertEqual(result.status_code,422,result.text);self.assertEqual(self.manager.get_candidate(),before)
        before=self.manager.get_candidate()
        self.assertEqual(self.client.post('/api/config/policies/security',json={'action':'create','revision':'0'*64,'rule':self.spec('security')}).status_code,409)
        self.assertEqual(self.manager.get_candidate(),before)

    def test_nat_and_pbf_roundtrip(self):
        for kind,settings in [('nat',{'source-type':'dynamic-ip-and-port','source-interface':'ethernet1/1','translated-destination':'192.0.2.10','translated-port':'443'}),
                              ('pbf',{'action':'forward','egress-interface':'ethernet1/1','next-hop':'192.0.2.1'})]:
            result=self.mutate(kind,rule=self.spec(kind,**settings));self.assertEqual(result.status_code,200,result.text)
            rule=self.client.get('/api/config/policies/'+kind).json()['entries'][0]
            self.assertTrue(rule['editable'],rule)
            for key,value in settings.items():self.assertEqual(rule['settings'][key],value)

    def test_complete_security_rule_roundtrip_and_read_only_usage(self):
        settings={'rule-type':'interzone','from':['trust'],'to':['untrust'],
            'source':['192.0.2.0/24'],'source-user':['EXAMPLE\\alice'],'source-device':['workstation'],
            'destination':['198.51.100.1'],'destination-device':['workstation'],
            'application':['custom-app'],'service':['application-default'],'tag':['reviewed'],
            'action':'reset-both','icmp-unreachable':'yes','profile-mode':'profiles',
            'log-start':'yes','log-end':'yes','log-setting':'central-logs',
            **{key:'inspect-'+key for key in SECURITY_PROFILES}}
        spec=self.spec('security',**settings)
        response=self.mutate('security',rule=spec);self.assertEqual(response.status_code,200,response.text)
        row=self.client.get('/api/config/policies/security').json()['entries'][0]
        self.assertTrue(row['editable']);self.assertEqual(row['settings'],spec['settings'])
        self.assertFalse(row['usage']['available'])
        self.assertTrue(all(row['usage'][k] is None for k in ('hit_count','first_hit','last_hit')))
        root=parse(self.manager.get_candidate());entry=root.find('.//rulebase/security/rules/entry')
        self.assertIsNone(entry.find('profile-mode'))
        for key,(_,path) in SECURITY_PROFILES.items():self.assertEqual(entry.findtext('profile-setting/profiles/'+path+'/member'),'inspect-'+key)
        before=self.manager.get_candidate()
        spec['usage']={'hit_count':42}
        self.assertEqual(self.mutate('security','update',name='rule',rule=spec).status_code,422)
        self.assertEqual(self.manager.get_candidate(),before)

    def test_security_profile_modes_and_invalid_combinations(self):
        for settings in [
            {'profile-mode':'group'},
            {'profile-mode':'none','profile-group':'inspection'},
            {'profile-mode':'group','profile-group':'inspection','antivirus':'inspect-antivirus'},
            {'profile-mode':'profiles'},
            {'profile-mode':'profiles','antivirus':'missing'},
            {'action':'allow','icmp-unreachable':'yes'},
            {'source-device':['missing']},{'destination-device':['missing']},
            {'log-setting':'missing'},{'rule-type':'intrazone','to':['untrust']},
        ]:
            with self.subTest(settings=settings):
                before=self.manager.get_candidate()
                result=self.mutate('security',rule=self.spec('security',**settings))
                self.assertEqual(result.status_code,422,result.text);self.assertEqual(self.manager.get_candidate(),before)
        self.assertEqual(self.mutate('security',rule=self.spec('security',**{'profile-mode':'group','profile-group':'inspection'})).status_code,200)
        self.assertIn('<group><member>inspection</member></group>',self.manager.get_candidate())
        self.assertEqual(self.mutate('security','update',name='rule',rule=self.spec('security')).status_code,200)
        self.assertNotIn('<profile-setting>',self.manager.get_candidate())

    def test_older_security_rules_and_profile_groups_stay_editable(self):
        path=self.directory/'candidate-config.xml'
        for group in ('inspection','<member>inspection</member>'):
            path.write_text(XML.replace('<zone>','<rulebase><security><rules><entry name="old"><disabled>yes</disabled><profile-setting><group>'+group+'</group></profile-setting></entry></rules></security></rulebase><zone>',1),encoding='utf-8',newline='\n')
            row=self.client.get('/api/config/policies/security').json()['entries'][0]
            self.assertTrue(row['editable']);self.assertEqual(row['settings']['profile-mode'],'group')
            self.assertEqual(row['settings']['source-device'],['any'])
            spec={k:row[k] for k in ('name','description','enabled','settings')}
            del spec['settings']['profile-mode'] # older CLI client
            result=self.mutate('security','update',name='old',rule=spec)
            self.assertEqual(result.status_code,200,result.text)
            self.assertIn('<group><member>inspection</member></group>',self.manager.get_candidate())
        path.write_text(path.read_text(encoding='utf-8').replace('<member>inspection</member>','<member>inspection</member><member>other</member>'),encoding='utf-8',newline='\n')
        row=self.client.get('/api/config/policies/security').json()['entries'][0]
        self.assertFalse(row['editable'],'Multiple profile group members cannot be silently discarded')

    def test_permissions_running_and_outage(self):
        self.role=None;self.assertEqual(self.client.get('/api/config/policies/security').status_code,401)
        self.role='readonly';self.assertEqual(self.mutate('security',rule=self.spec('security')).status_code,403)
        self.assertFalse(self.client.get('/api/config/policies/security').json()['can_edit'])
        self.role='admin';self.manager.holder='other';self.assertEqual(self.mutate('security',rule=self.spec('security')).status_code,423)
        self.manager.holder=None
        self.assertFalse(self.client.get('/api/config/policies/security?source=running').json()['can_edit'])
        self.gateway.query=Mock(side_effect=RuntimeError('offline'))
        self.assertEqual(self.mutate('security',rule=self.spec('security')).status_code,503)
        self.assertIsNone(self.manager.holder,'A failed mutation must release the lock it acquired')
        self.assertEqual(self.manager.get_candidate(),XML)

    def test_cli_uses_same_authenticated_api(self):
        calls=[]
        def api(path,method='GET',body=None,token=None):
            calls.append((path,method,token));return self.client.request(method,path,json=body).json()
        payload=dict(revision=revision(self.manager.get_candidate()),rule=self.spec('security','cli-rule'))
        with redirect_stdout(io.StringIO()):
            self.assertTrue(handle(['request','policies','security','create',json.dumps(payload)],api,'fixture-token'))
            self.assertTrue(handle(['show','policies','security'],api,'fixture-token'))
        self.assertEqual(self.client.get('/api/config/policies/security').json()['entries'][0]['name'],'cli-rule')
        self.assertTrue(all(c[2]=='fixture-token' for c in calls))
        self.assertEqual(calls[0][1],'POST')

    def test_configd_blocks_before_apply_and_imported_data_is_preserved(self):
        self.mutate('security',rule=self.spec('security'))
        self.mutate('security','toggle',name='rule',enabled=True)
        status=Mock();self.assertFalse(configd_validate(self.directory/'candidate-config.xml',status))
        status.validation.assert_called_once();status.write.assert_called_once()
        self.mutate('security','toggle',name='rule',enabled=False)
        xml=self.manager.get_candidate().replace('<disabled>yes</disabled>','<disabled>yes</disabled><future-field>retain</future-field>')
        (self.directory/'candidate-config.xml').write_text(xml,newline='\n')
        self.assertFalse(self.client.get('/api/config/policies/security').json()['entries'][0]['editable'])
        self.assertEqual(self.mutate('security','delete',name='rule').status_code,409)
        self.assertEqual(self.manager.get_candidate(),xml)

    def test_actual_commit_rejects_before_history_or_running_write(self):
        self.mutate('security',rule=self.spec('security'))
        self.mutate('security','toggle',name='rule',enabled=True)
        tree=ast.parse((Path(__file__).resolve().parents[1]/'opt/ffn_manager.py').read_text(encoding='utf-8'))
        cls=next(n for n in tree.body if isinstance(n,ast.ClassDef) and n.name=='ConfigManager')
        cls.body=[n for n in cls.body if isinstance(n,ast.FunctionDef) and n.name=='commit']
        from typing import Optional
        import xml.etree.ElementTree as ET
        namespace=dict(Optional=Optional,ET=ET,CANDIDATE_CONFIG=self.directory/'candidate-config.xml')
        exec(compile(ast.Module(body=[cls],type_ignores=[]),'<commit>','exec'),namespace)
        manager=namespace['ConfigManager']();manager.history=Mock();manager.snapshot_save=Mock()
        manager.prepare_commit=lambda scope:ET.fromstring(self.manager.get_candidate())
        result=manager.commit('tester')
        self.assertEqual(result['status'],'error');self.assertIn('activation blocked',result['message'])
        manager.history.latest_version.assert_not_called();manager.snapshot_save.assert_not_called()
        self.assertEqual(self.manager.get_running(),XML)

    def test_daemon_parser_rejects_entities_and_alternate_encodings(self):
        document='<!DOCTYPE config [<!ENTITY x "expanded">]><config>&x;</config>'
        for value in (document,document.encode('utf-16'),document.encode('utf-8')):
            with self.assertRaises(PolicyError):parse(value)

    def test_pure_rule_move_is_a_configuration_diff(self):
        for name in ('first','second'):self.mutate('security',rule=self.spec('security',name))
        (self.directory/'running-config.xml').write_bytes((self.directory/'candidate-config.xml').read_bytes())
        tree=ast.parse((Path(__file__).resolve().parents[1]/'opt/ffn_manager.py').read_text(encoding='utf-8'))
        cls=next(n for n in tree.body if isinstance(n,ast.ClassDef) and n.name=='ConfigManager')
        cls.body=[n for n in cls.body if isinstance(n,ast.FunctionDef) and n.name in ('diff','_collect_paths')]
        import xml.etree.ElementTree as ET
        namespace=dict(ET=ET,json=json,CANDIDATE_CONFIG=self.directory/'candidate-config.xml',RUNNING_CONFIG=self.directory/'running-config.xml')
        exec(compile(ast.Module(body=[cls],type_ignores=[]),'<diff>','exec'),namespace)
        manager=namespace['ConfigManager']();manager._load=lambda path:ET.parse(path).getroot()
        self.assertFalse(manager.diff()['has_changes'])
        self.mutate('security','move',name='second',position=1)
        diff=manager.diff();self.assertTrue(diff['has_changes'])
        self.assertTrue(any(r['path'].endswith('.@order') for r in diff['modified']))


if __name__=='__main__':unittest.main()
