import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'opt'))
from ffn_session_events import decode, EventError, Journal, Collector, snapshot, EventGap
from unittest.mock import patch


def message(order, end=False, label=0x123456789, state=False):
    endian='<' if order=='little' else '>'
    def attr(kind, data):
        raw=struct.pack(endian+'HH',len(data)+4,kind)+data
        return raw+b'\0'*((-len(raw))%4)
    def tup(source,destination):
        return attr(1,attr(1,bytes(source))+attr(2,bytes(destination)))+attr(2,
            attr(1,b'\x11')+attr(2,(1234).to_bytes(2,'big'))+attr(3,(53).to_bytes(2,'big')))
    def counter(packets,octets):return attr(1,packets.to_bytes(8,'big'))+attr(2,octets.to_bytes(8,'big'))
    payload=(b'\x02\0\0\0'+attr(1,tup([192,0,2,2],[198,51,100,2]))+
        attr(2,tup([198,51,100,2],[192,0,2,2]))+attr(12,(123).to_bytes(4,'big'))+
        attr(22,label.to_bytes(16,order))+
        attr(9,counter(2,120))+attr(10,counter(1,60)))
    if state:
        payload+=attr(3,(14).to_bytes(4,'big'))+attr(7,(300).to_bytes(4,'big'))+attr(18,(7).to_bytes(2,'big'))
        payload+=attr(4,attr(1,attr(1,b'\x03')))
    return struct.pack(endian+'IHHII',len(payload)+16,0x102 if end else 0x100,0 if end else 0x600,0,0)+payload


class EventsTests(unittest.TestCase):
    def test_session_state_is_network_order_on_both_architectures(self):
        for order in ('little','big'):
            row=decode(message(order,state=True),order)[0]
            self.assertEqual([row[k] for k in ('status','timeout','zone','tcp_state')],[14,300,7,3])
            row=decode(message(order),order)[0]
            self.assertEqual([row[k] for k in ('status','timeout','zone','tcp_state')],[None,None,0,None])

    def test_batch_failure_rolls_back_every_record(self):
        with tempfile.TemporaryDirectory() as directory:
            j=Journal(Path(directory)/'sessions.db','boot')
            j.register({1:dict(logging=dict(start=True,end=True))})
            row=decode(message('little',label=3),'little')[0]
            with self.assertRaises(EventError):j.record_batch([row,dict(row,id=124,token=999)])
            self.assertEqual(j.recent(),[])
            self.assertEqual(j.db.execute('SELECT count(*) FROM sessions').fetchone()[0],0)
            j.close()

    def test_gap_reconciles_live_sessions_without_fabricating_end_or_start(self):
        with tempfile.TemporaryDirectory() as directory:
            j=Journal(Path(directory)/'sessions.db','boot')
            j.register({1:dict(logging=dict(start=True,end=True))})
            row=decode(message('little',label=3),'little')[0]
            j.record(row,10);j.record(dict(row,id=124),11);j.fault('Session event gap: test')
            # Surviving CT retains its actual start. Lost end is incomplete.
            # Admission observed only in snapshot has an unknown start time.
            j.reconcile([row,dict(row,id=125)],[],'test gap')
            self.assertIsNone(j.fault_reason())
            records=[json.loads(r[0]) for r in j.db.execute('SELECT data FROM sessions')]
            self.assertEqual({r['id']:r['started'] for r in records},{123:10,125:None})
            interrupted=[r for r in j.recent() if r['event']=='interrupted'][0]
            self.assertIsNone(interrupted['ended']);self.assertFalse(interrupted['counters_complete'])
            j.record(dict(row,event='end'),20)
            self.assertTrue(j.recent()[0]['event_gap'])
            self.assertEqual(j.recent()[0]['duration_seconds'],10)
            j.close()

    def test_reconciliation_unknown_token_preserves_fault_and_journal(self):
        with tempfile.TemporaryDirectory() as directory:
            j=Journal(Path(directory)/'sessions.db','boot')
            j.register({1:dict(logging=dict(start=True,end=True))})
            row=decode(message('little',label=3),'little')[0]
            j.record(row,10);j.fault('Session event gap: test')
            before=list(j.db.execute('SELECT * FROM sessions'));events=j.recent()
            with self.assertRaises(EventError):j.reconcile([dict(row,id=999,token=999)],[],'test')
            self.assertEqual(list(j.db.execute('SELECT * FROM sessions')),before)
            self.assertEqual(j.recent(),events);self.assertTrue(j.fault_reason());j.close()
        self.assertFalse(Collector.recoverable('Policy rollback unconfirmed: test'))

    def test_snapshot_replays_destroy_and_rejects_interrupted_dump(self):
        class Stream:
            def sendto(self,request,address):
                sequence=struct.unpack_from('=I',request,8)[0]
                row=bytearray(message(sys.byteorder,label=3))
                struct.pack_into('=I',row,8,sequence)
                self.queue=[bytes(row),message(sys.byteorder,True,label=0),
                            struct.pack('=IHHIIi',20,3,self.flags,sequence,0,0)]
            def recvmsg(self,size):return self.queue.pop(0),[],0,(0,0)
        stream=Stream();stream.flags=0
        with patch('ffn_session_events.select.select',side_effect=lambda *a:([stream] if stream.queue else [],[],[])):
            rows,changes=snapshot(stream)
            self.assertEqual(len(rows),1);self.assertEqual(changes[0]['event'],'end')
            stream.flags=0x10
            with self.assertRaises(EventGap):snapshot(stream)

    def test_native_nft_labels_and_network_order_tuples_both_architectures(self):
        rows=[decode(message(order),order)[0] for order in ('little','big')]
        self.assertEqual(rows[0],rows[1]);self.assertEqual(rows[0]['token'],0x91a2b3c4)
        self.assertEqual(rows[0]['original']['source_port'],1234)
        self.assertEqual(rows[0]['counters']['original'],{'packets':2,'bytes':120})
        self.assertEqual(len(decode(message('big')+message('big',True),'big')),2)

    def test_malformed_and_overrun_fail_closed(self):
        for raw in (b'\0',message('little')[:-1],struct.pack('<IHHII',16,4,0,0,0)):
            with self.assertRaises(EventError):decode(raw,'little')
        self.assertIsNone(decode(message('little',label=0),'little')[0]['token'])

    def test_rule_generation_survives_reopen_and_end_uses_actual_counters(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'sessions.db';j=Journal(path,'boot-a')
            token=51;rule=dict(scope='vsys1',name='outbound',revision=7,logging=dict(start=False,end=True))
            j.register({token:rule})
            row=decode(message('little',label=(token<<1)|1),'little')[0]
            j.record(row,10);self.assertEqual(j.recent(),[]);j.close()
            j=Journal(path,'boot-a')
            with self.assertRaises(EventError):j.register({token:dict(rule,name='reused')})
            end=decode(message('big',True,label=0),'big')[0];j.record(end,15)
            event=j.recent()[0];self.assertEqual(event['duration_seconds'],5)
            self.assertEqual(event['rule']['revision'],7);self.assertEqual(event['counters']['reply']['bytes'],60)
            self.assertEqual(j.db.execute('SELECT count(*) FROM sessions').fetchone()[0],0)
            j.fault('stream loss');j.close();j=Journal(path,'boot-a')
            self.assertEqual(j.fault_reason(),'stream loss');j.close()

    def test_no_fabricated_start_or_missing_accounting(self):
        with tempfile.TemporaryDirectory() as directory:
            j=Journal(Path(directory)/'sessions.db','boot-a');j.register({1:dict(logging=dict(start=False,end=True))})
            end=decode(message('little',True,label=3),'little')[0]
            with self.assertRaises(EventError):j.record(dict(end,counters={}),15)
            j.record(end,15);self.assertIsNone(j.recent()[0]['started']);j.close()

    def test_update_can_report_first_admission_and_boot_loss_is_explicit(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'sessions.db';j=Journal(path,'old-boot')
            j.register({1:dict(logging=dict(start=True,end=True))})
            row=decode(message('little',label=3),'little')[0];row['event']='update'
            j.record(row,10);j.record(row,11)
            self.assertEqual(len(j.recent()),1);self.assertEqual(j.recent()[0]['event'],'start');j.close()
            j=Journal(path,'new-boot');j.recover_boot()
            event=j.recent()[0];self.assertEqual(event['event'],'interrupted')
            self.assertFalse(event['counters_complete']);self.assertIsNone(event['ended'])
            self.assertEqual(j.db.execute('SELECT count(*) FROM sessions').fetchone()[0],0);j.close()


if __name__=='__main__':unittest.main()
