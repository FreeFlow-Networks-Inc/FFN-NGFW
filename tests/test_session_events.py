import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'opt'))
from ffn_session_events import decode, EventError, Journal


def message(order, end=False, label=0x123456789):
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
    return struct.pack(endian+'IHHII',len(payload)+16,0x102 if end else 0x100,0 if end else 0x600,0,0)+payload


class EventsTests(unittest.TestCase):
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
