import ast,unittest,re
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock
from typing import Optional
from datetime import datetime
from xml.etree import ElementTree as ET
class PartialCommitTests(unittest.TestCase):
    def test_named_interface_scope_preserves_other_candidate_changes(self):
        tree=ast.parse((Path(__file__).parents[1]/'opt/ffn_manager.py').read_text(encoding='utf-8'))
        klass=next(n for n in tree.body if isinstance(n,ast.ClassDef) and n.name=='ConfigManager')
        names={'commit','_normalize_xpath','_split_xpath','_parse_step','_find_child','_find_or_create_child'}
        klass.body=[n for n in klass.body if isinstance(n,ast.FunctionDef) and n.name in names or isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='_ENTRY_PRED_RE' for t in n.targets)]
        ns=dict(re=re,Optional=Optional,ET=ET,datetime=datetime,CANDIDATE_CONFIG='candidate',RUNNING_CONFIG='running')
        exec(compile(ast.Module(body=[klass],type_ignores=[]),'<config>','exec'),ns)
        manager=ns['ConfigManager']()
        roots={name:ET.fromstring('<config><devices><entry name="localhost.localdomain"><network><interface><ethernet><entry name="ethernet1/2"><layer2/></entry><entry name="ethernet1/3"><comment>'+name+'</comment></entry></ethernet></interface></network></entry></devices></config>') for name in ('candidate','running')}
        p2=roots['candidate'].find('.//ethernet/entry');p2.remove(p2.find('layer2'));ET.SubElement(ET.SubElement(p2,'layer3'),'dhcp-client')
        manager._load=lambda name:roots[name];manager._save=Mock();manager.snapshot_save=Mock()
        manager.diff=lambda:dict(added=[],modified=[],removed=[],total_changes=2)
        manager.history=Mock();manager.history.record.return_value={'version':2}
        result=manager.commit('admin',partial_xpath='devices.entry[@name=localhost.localdomain].network.interface.ethernet.entry[@name=ethernet1/2]')
        self.assertEqual(result['status'],'committed')
        parent=roots['running'].find('.//ethernet')
        self.assertEqual([p.get('name') for p in parent],['ethernet1/2','ethernet1/3'])
        self.assertIsNotNone(parent[0].find('./layer3/dhcp-client'))
        self.assertEqual(parent[1].findtext('comment'),'running')
        self.assertEqual(manager.commit('admin',partial_xpath='config')['status'],'error')
if __name__=='__main__':unittest.main()
