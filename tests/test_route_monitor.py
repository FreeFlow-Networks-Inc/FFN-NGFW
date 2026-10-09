import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'opt'))
from ffn_route_monitor import validate,advance
from ffn_route_probe import checksum,echo_reply


class MonitorTests(unittest.TestCase):
    def test_hysteresis(self):
        cfg=validate(dict(enabled=True,targets=['192.0.2.1'],failure_count=2,recovery_count=2),'0.0.0.0/0')
        state=advance({},[True],cfg);self.assertFalse(state['healthy'])
        state=advance(state,[True],cfg);self.assertTrue(state['healthy'])
        state=advance(state,[False],cfg);self.assertTrue(state['healthy'])
        state=advance(state,[False],cfg);self.assertFalse(state['healthy'])
        state=advance(state,[True],cfg);self.assertFalse(state['healthy'])

    def test_multiple_target_conditions(self):
        for condition,expected in [('any',False),('all',True)]:
            cfg=validate(dict(failure_condition=condition,failure_count=1,recovery_count=1))
            self.assertEqual(advance({'healthy':True},[True,False],cfg)['healthy'],expected)

    def test_reject_invalid_monitor(self):
        for config in [dict(enabled=True),dict(targets=['::1']),dict(targets=['224.0.0.1']),
                       dict(timeout=6,interval=5),dict(failure_count=True),dict(unknown=1)]:
            with self.subTest(config=config),self.assertRaises(ValueError):validate(config,'0.0.0.0/0')
        with self.assertRaises(ValueError):validate(dict(targets=['198.51.100.1']),'192.0.2.0/24')

    def test_echo_requires_nonce_and_valid_checksum(self):
        import struct,socket
        source=socket.inet_aton('192.0.2.1');target=socket.inet_aton('192.0.2.2');mac=b'\x02\0\0\0\0\x01';token=b'a'*28
        body=b'\0'*4+token;body=body[:2]+struct.pack('!H',checksum(body))+body[4:]
        header=struct.pack('!BBHHHBBH4s4s',0x45,0,20+len(body),0,0,64,1,0,target,source)
        header=header[:10]+struct.pack('!H',checksum(header))+header[12:]
        packet=mac+b'\x02\0\0\0\0\x02'+b'\x08\0'+header+body
        self.assertTrue(echo_reply(packet,source,target,token,mac))
        self.assertIsNone(echo_reply(packet,source,target,b'b'*28,mac))
        self.assertIsNone(echo_reply(packet[:-1]+b'x',source,target,token,mac))


if __name__=='__main__':unittest.main()
