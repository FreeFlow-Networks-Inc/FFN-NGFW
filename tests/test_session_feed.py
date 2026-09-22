import copy
import contextlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import uuid
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'opt'))
import ffn_session_feed as feed
from ffn_session_events import Journal
from test_policy_plan import configuration


class FeedTests(unittest.TestCase):
    def setUp(self):
        self.state=dict(xml=configuration('security',{'action':'allow','log-end':'yes'}),
                        token_generation=3,revision=2,digest='a'*64,nat={'digest':'b'*64},bindings={})
        self.rules,self.metadata=feed.catalog(self.state)
        self.token=next(iter(self.rules))
        self.row=dict(id=42,token=self.token,event='update',status=14,timeout=120,zone=0,tcp_state=3,
            original=dict(source='192.0.2.5',destination='198.51.100.2',source_port=2000,destination_port=443,protocol=6),
            reply=dict(source='198.51.100.2',destination='203.0.113.2',source_port=443,destination_port=3000,protocol=6),
            counters={'original':{'packets':4,'bytes':240},'reply':{'packets':3,'bytes':180}})
        self.status=dict(available=True,applied=True,revision=2,digest='a'*64,
            nat={'acknowledged':True,'digest':'b'*64},collector=dict(boot_id=str(uuid.uuid4()),pid=5,process_start='10',events={'recoveries':1}))

    def test_current_explicit_grant_and_actual_nat(self):
        result=feed.assess(self.row,self.rules,'boot')
        self.assertTrue(result['software_candidate'])
        self.assertEqual(result['nat'],{'source':True,'destination':False})
        self.assertEqual(result['translated']['source_port'],3000)
        self.assertEqual(result['rule']['interface_pairs'],[['ethernet1/1','ethernet1/2']])
        self.assertNotEqual(result['identity'],feed.assess(self.row,self.rules,'another-boot')['identity'])

    def test_unowned_implicit_unassured_expired_and_nondefault_zone_blocked(self):
        for change in ({'token':0},{'token':3*2048+2047},{'status':10},{'status':14|16384},
                       {'timeout':0},{'timeout':None},{'zone':7},{'tcp_state':4}):
            with self.subTest(change=change):
                result=feed.assess(dict(self.row,**change),self.rules,'boot')
                self.assertFalse(result['software_candidate']);self.assertTrue(result['blockers'])
        rules=copy.deepcopy(self.rules);rules[self.token]['interface_pairs'].append(['ethernet1/3','ethernet1/2'])
        self.assertIn('interface-pair-ambiguous',feed.assess(self.row,rules,'boot')['blockers'])
        rules=copy.deepcopy(self.rules);rules[self.token]['inspection_required']=True
        self.assertIn('inspection-required',feed.assess(self.row,rules,'boot')['blockers'])

    @contextlib.contextmanager
    def environment(self):
        with tempfile.TemporaryDirectory() as directory,contextlib.ExitStack() as stack:
            db=Path(directory)/'sessions.db';journal=Journal(db,self.status['collector']['boot_id'])
            journal.register(self.metadata);journal.close();db.chmod(0o600)
            stack.enter_context(patch.object(feed.runtime,'DATABASE',db))
            stack.enter_context(patch.object(feed.runtime,'saved',return_value=self.state))
            status=stack.enter_context(patch.object(feed.runtime,'status',return_value=self.status))
            # Model the root-owned namespace/journal on unprivileged CI runners;
            # journal content inspection remains real, read-only SQLite.
            stat=feed.os.stat
            def trusted_stat(p,*args,**kwargs):
                result=stat('/proc/self/ns/net' if str(p).startswith('/run/netns/') else p,*args,**kwargs)
                if str(p)==str(db):
                    fields=list(result);fields[4]=0;return feed.os.stat_result(fields)
                return result
            stack.enter_context(patch.object(feed.os,'stat',side_effect=trusted_stat))
            stack.enter_context(patch.object(feed,'subscribe',return_value=contextlib.nullcontext(object())))
            snapshot=stack.enter_context(patch.object(feed,'snapshot',return_value=([self.row],[])))
            yield db,status,snapshot

    def test_complete_observation_is_read_only_and_replays_removal(self):
        with self.environment() as (db,status,snapshot):
            before=db.read_bytes();nonce=str(uuid.uuid4())
            result=feed.observe(nonce)
            self.assertEqual(result['nonce'],nonce);self.assertFalse(result['hardware_admission'])
            self.assertEqual(result['owned_sessions'],1);self.assertEqual(db.read_bytes(),before)
            for change in (dict(self.row,event='end',token=None),dict(self.row,token=None)):
                snapshot.return_value=([self.row],[change])
                self.assertEqual(feed.observe(nonce)['owned_sessions'],0)

    def test_generation_restart_fault_and_stale_ack_rejected(self):
        for field in ('pid','boot_id','process_start','events'):
            with self.environment() as (_,status,_):
                changed=copy.deepcopy(self.status)
                changed['collector'][field]={'recoveries':2} if field=='events' else 'changed'
                status.side_effect=[self.status,changed]
                with self.assertRaises(ValueError):feed.observe(str(uuid.uuid4()))

    def test_fault_and_policy_change_rejected(self):
        with self.environment() as (db,status,_):
            status.return_value=dict(self.status,applied=False)
            with self.assertRaises(ValueError):feed.observe(str(uuid.uuid4()))
            status.return_value=self.status
            journal=Journal(db,self.status['collector']['boot_id']);journal.fault('lost stream');journal.close()
            with self.assertRaises(ValueError):feed.observe(str(uuid.uuid4()))
        with self.environment():
            changed=dict(self.state,token_generation=4)
            with patch.object(feed.runtime,'saved',side_effect=[self.state,changed]):
                with self.assertRaises(ValueError):feed.observe(str(uuid.uuid4()))

    def test_large_observation_is_explicitly_truncated(self):
        with self.environment() as (_,_,snapshot):
            snapshot.return_value=([dict(self.row,id=i) for i in range(130)],[])
            result=feed.observe(str(uuid.uuid4()))
            self.assertTrue(result['truncated']);self.assertEqual(result['owned_sessions'],130)
            self.assertEqual(len(result['sessions']),128)


if __name__=='__main__':unittest.main()
