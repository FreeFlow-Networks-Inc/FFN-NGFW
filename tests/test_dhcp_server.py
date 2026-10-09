import ipaddress
import json
import os
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'opt'))
import ffn_dhcp_server as dhcp

SERVER_MAC = bytes.fromhex('02aabbccdd01')
CLIENT_MAC = bytes.fromhex('02112233440a')
SPEC = dict(interface='ae1.69', address='10.1.0.2/22', pools=[['10.1.0.100', '10.1.0.103']],
            reserved={'02:11:22:33:44:99': '10.1.0.50'}, lease=3600, probe=False,
            options=dict(dns=['1.1.1.1', '8.8.8.8'], domain='lan'))


def client_frame(kind, mac=CLIENT_MAC, xid=0x1234, flags=0, ciaddr='0.0.0.0', src_ip='0.0.0.0', options=(), unicast_to=None, giaddr='0.0.0.0'):
    body = struct.pack('!BBBBIHH', 1, 1, 6, 0, xid, 0, flags)
    body += ipaddress.IPv4Address(ciaddr).packed + bytes(4) + bytes(4) + ipaddress.IPv4Address(giaddr).packed
    body += mac + bytes(10) + bytes(64) + bytes(128) + dhcp.MAGIC + dhcp.option(53, bytes([kind]))
    for tag, value in options:
        body += dhcp.option(tag, value)
    body += b'\xff'
    udp = struct.pack('!HHHH', 68, 67, 8 + len(body), 0) + body
    dst_ip = ipaddress.IPv4Address(unicast_to or '255.255.255.255').packed
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0, ipaddress.IPv4Address(src_ip).packed, dst_ip)
    dst_mac = SERVER_MAC if unicast_to else dhcp.BROADCAST_MAC
    return dst_mac + mac + b'\x08\x00' + ip + udp


def decode(frame):
    """A reply frame -> (dst_mac, dst_ip, type, yiaddr, options)."""
    ihl = (frame[14] & 0x0F) * 4
    data = frame[14 + ihl + 8:]
    options, i = {}, 240
    while i < len(data) and data[i] != 255:
        if data[i] == 0:
            i += 1
            continue
        options[data[i]] = data[i + 2:i + 2 + data[i + 1]]
        i += 2 + data[i + 1]
    return dict(dst_mac=frame[:6], src_mac=frame[6:12], dst_ip=str(ipaddress.IPv4Address(frame[30:34])),
                src_ip=str(ipaddress.IPv4Address(frame[26:30])), type=options[53][0],
                yiaddr=str(ipaddress.IPv4Address(data[16:20])), options=options, xid=struct.unpack('!I', data[4:8])[0])


class ServerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'ae1.69.json'
        self.now = 1_000_000.0
        self.probed = []
        self.server = self.make()

    def make(self, spec=SPEC, probe=None):
        server = dhcp.Server('ae1.69', dhcp.validate_server('ae1.69', spec), dhcp.Leases(self.path, 'ae1.69'),
                             clock=lambda: self.now, probe=probe)
        server.mac = SERVER_MAC
        return server

    def test_discover_offers_the_first_free_pool_address_with_the_options(self):
        replies = self.server.handle(client_frame(dhcp.DISCOVER, options=[(12, b'laptop'), (61, b'\x01' + CLIENT_MAC)]))
        self.assertEqual(len(replies), 1)
        offer = decode(replies[0])
        self.assertEqual((offer['type'], offer['yiaddr'], offer['dst_mac'], offer['dst_ip'], offer['src_ip'], offer['xid']),
                         (dhcp.OFFER, '10.1.0.100', CLIENT_MAC, '10.1.0.100', '10.1.0.2', 0x1234))
        opts = offer['options']
        self.assertEqual(opts[54], ipaddress.IPv4Address('10.1.0.2').packed)
        self.assertEqual(struct.unpack('!I', opts[51])[0], 3600)
        self.assertEqual((struct.unpack('!I', opts[58])[0], struct.unpack('!I', opts[59])[0]), (1800, 3150))
        self.assertEqual(opts[1], ipaddress.IPv4Address('255.255.252.0').packed)
        self.assertEqual(opts[3], ipaddress.IPv4Address('10.1.0.2').packed)
        self.assertEqual(opts[28], ipaddress.IPv4Address('10.1.3.255').packed)
        self.assertEqual(opts[6], ipaddress.IPv4Address('1.1.1.1').packed + ipaddress.IPv4Address('8.8.8.8').packed)
        self.assertEqual(opts[15], b'lan')
        self.assertEqual(opts[61], b'\x01' + CLIENT_MAC)
        self.assertEqual(self.server.leases.rows['10.1.0.100']['state'], 'offered')
        self.assertEqual(self.server.leases.rows['10.1.0.100']['hostname'], 'laptop')
        self.assertGreaterEqual(len(replies[0]), 14 + 20 + 8 + 300)

    def test_selecting_request_binds_and_persists_the_lease(self):
        self.server.handle(client_frame(dhcp.DISCOVER))
        replies = self.server.handle(client_frame(dhcp.REQUEST, options=[(50, ipaddress.IPv4Address('10.1.0.100').packed),
                                                                        (54, ipaddress.IPv4Address('10.1.0.2').packed)]))
        ack = decode(replies[0])
        self.assertEqual((ack['type'], ack['yiaddr']), (dhcp.ACK, '10.1.0.100'))
        row = json.loads(self.path.read_text())['rows']['10.1.0.100']
        self.assertEqual((row['state'], row['mac'], row['expires']), ('bound', '02:11:22:33:44:0a', self.now + 3600))
        again = self.make()   # a restart re-reads the file
        self.assertEqual(again.leases.rows['10.1.0.100']['state'], 'bound')
        self.assertEqual(self.server.counters['ack'], 1)

    def test_request_for_another_server_drops_our_offer_silently(self):
        self.server.handle(client_frame(dhcp.DISCOVER))
        replies = self.server.handle(client_frame(dhcp.REQUEST, options=[(50, ipaddress.IPv4Address('10.1.0.100').packed),
                                                                        (54, ipaddress.IPv4Address('10.1.0.1').packed)]))
        self.assertEqual(replies, [])
        self.assertNotIn('10.1.0.100', self.server.leases.rows)
        self.assertEqual(self.server.counters['other_server'], 1)

    def test_broadcast_flag_and_renewals_address_replies_as_rfc_2131_requires(self):
        offer = decode(self.server.handle(client_frame(dhcp.DISCOVER, flags=0x8000))[0])
        self.assertEqual((offer['dst_mac'], offer['dst_ip']), (dhcp.BROADCAST_MAC, '255.255.255.255'))
        self.server.handle(client_frame(dhcp.REQUEST, options=[(50, ipaddress.IPv4Address('10.1.0.100').packed), (54, ipaddress.IPv4Address('10.1.0.2').packed)]))
        self.now += 1800
        renew = self.server.handle(client_frame(dhcp.REQUEST, ciaddr='10.1.0.100', src_ip='10.1.0.100', unicast_to='10.1.0.2'))
        ack = decode(renew[0])
        self.assertEqual((ack['type'], ack['dst_mac'], ack['dst_ip']), (dhcp.ACK, CLIENT_MAC, '10.1.0.100'))
        self.assertEqual(self.server.leases.rows['10.1.0.100']['expires'], self.now + 3600)

    def test_init_reboot_is_acknowledged_for_a_known_lease_and_refused_otherwise(self):
        self.server.handle(client_frame(dhcp.DISCOVER))
        self.server.handle(client_frame(dhcp.REQUEST, options=[(50, ipaddress.IPv4Address('10.1.0.100').packed), (54, ipaddress.IPv4Address('10.1.0.2').packed)]))
        ok = decode(self.server.handle(client_frame(dhcp.REQUEST, options=[(50, ipaddress.IPv4Address('10.1.0.100').packed)]))[0])
        self.assertEqual(ok['type'], dhcp.ACK)
        wrong = decode(self.server.handle(client_frame(dhcp.REQUEST, options=[(50, ipaddress.IPv4Address('192.168.9.9').packed)]))[0])
        self.assertEqual((wrong['type'], wrong['dst_mac'], wrong['dst_ip']), (dhcp.NAK, dhcp.BROADCAST_MAC, '255.255.255.255'))
        self.assertIn(b'wrong network', wrong['options'][56])
        other = decode(self.server.handle(client_frame(dhcp.REQUEST, mac=bytes.fromhex('021122334477'),
                                                       options=[(50, ipaddress.IPv4Address('10.1.0.100').packed)]))[0])
        self.assertEqual(other['type'], dhcp.NAK)
        self.assertEqual(self.server.counters['nak'], 2)

    def test_reservation_wins_and_the_pool_hands_out_distinct_addresses_until_exhausted(self):
        reserved = decode(self.server.handle(client_frame(dhcp.DISCOVER, mac=bytes.fromhex('021122334499')))[0])
        self.assertEqual(reserved['yiaddr'], '10.1.0.50')
        given = []
        for n in range(4):
            given.append(decode(self.server.handle(client_frame(dhcp.DISCOVER, mac=bytes([2, 0, 0, 0, 0, n])))[0])['yiaddr'])
        self.assertEqual(given, ['10.1.0.100', '10.1.0.101', '10.1.0.102', '10.1.0.103'])
        self.assertEqual(self.server.handle(client_frame(dhcp.DISCOVER, mac=bytes([2, 0, 0, 0, 0, 9]))), [])
        self.assertEqual(self.server.counters['exhausted'], 1)
        # the same client asking again keeps its offer; an offer nobody requested expires
        self.assertEqual(decode(self.server.handle(client_frame(dhcp.DISCOVER, mac=bytes([2, 0, 0, 0, 0, 1])))[0])['yiaddr'], '10.1.0.101')
        self.now += dhcp.OFFER_SECONDS + 1
        self.assertEqual(decode(self.server.handle(client_frame(dhcp.DISCOVER, mac=bytes([2, 0, 0, 0, 0, 9])))[0])['yiaddr'], '10.1.0.100')

    def test_release_decline_inform_and_relayed_requests(self):
        self.server.handle(client_frame(dhcp.DISCOVER))
        self.server.handle(client_frame(dhcp.REQUEST, options=[(50, ipaddress.IPv4Address('10.1.0.100').packed), (54, ipaddress.IPv4Address('10.1.0.2').packed)]))
        self.assertEqual(self.server.handle(client_frame(dhcp.RELEASE, ciaddr='10.1.0.100', src_ip='10.1.0.100', unicast_to='10.1.0.2')), [])
        self.assertNotIn('10.1.0.100', self.server.leases.rows)
        self.assertEqual(self.server.handle(client_frame(dhcp.DECLINE, options=[(50, ipaddress.IPv4Address('10.1.0.100').packed)])), [])
        self.assertEqual(self.server.leases.rows['10.1.0.100']['state'], 'declined')
        self.assertEqual(decode(self.server.handle(client_frame(dhcp.DISCOVER))[0])['yiaddr'], '10.1.0.101')
        inform = decode(self.server.handle(client_frame(dhcp.INFORM, ciaddr='10.1.0.77', src_ip='10.1.0.77', unicast_to='10.1.0.2'))[0])
        self.assertEqual((inform['type'], inform['yiaddr'], inform['dst_ip']), (dhcp.ACK, '0.0.0.0', '10.1.0.77'))
        self.assertNotIn(51, inform['options']); self.assertIn(6, inform['options'])
        self.assertEqual(self.server.handle(client_frame(dhcp.DISCOVER, giaddr='10.9.9.1')), [])
        self.assertEqual(self.server.counters['relayed'], 1)

    def test_probe_skips_addresses_that_answer_and_records_the_conflict(self):
        server = self.make(dict(SPEC, probe=True), probe=lambda ip: self.probed.append(ip) or ip == '10.1.0.100')
        offer = decode(server.handle(client_frame(dhcp.DISCOVER))[0])
        self.assertEqual((offer['yiaddr'], self.probed), ('10.1.0.101', ['10.1.0.100', '10.1.0.101']))
        self.assertEqual((server.leases.rows['10.1.0.100']['state'], server.counters['conflict']), ('declined', 1))

    def test_unlimited_lease_and_non_dhcp_frames(self):
        server = self.make(dict(SPEC, lease=None))
        offer = decode(server.handle(client_frame(dhcp.DISCOVER))[0])
        self.assertEqual(struct.unpack('!I', offer['options'][51])[0], dhcp.INFINITE)
        self.assertNotIn(58, offer['options'])
        self.assertEqual(server.handle(b'\x00' * 60), [])
        self.assertEqual(server.handle(client_frame(dhcp.DISCOVER)[:100]), [])
        self.assertIsNone(dhcp.parse(client_frame(dhcp.OFFER)))

    def test_summary_counts_states_and_lists_leases(self):
        self.server.handle(client_frame(dhcp.DISCOVER))
        summary = self.server.summary(self.now)
        self.assertEqual((summary['offered'], summary['bound'], summary['pool_size'], summary['reserved'], summary['interface']),
                         (1, 0, 4, 1, 'ae1.69'))
        self.assertEqual(summary['leases'][0]['ip'], '10.1.0.100')
        self.assertEqual(summary['counters']['discover'], 1)


class IntentTests(unittest.TestCase):
    def test_validation_normalises_and_rejects(self):
        good = dhcp.validate_intent(dict(servers={'ae1.69': SPEC}, configuration='a' * 64))
        self.assertEqual(good['servers']['ae1.69']['reserved'], {'02:11:22:33:44:99': '10.1.0.50'})
        self.assertEqual(good['servers']['ae1.69']['options'], dict(dns=['1.1.1.1', '8.8.8.8'], domain='lan'))
        cases = [
            ({'eth0': SPEC}, 'device name'),
            ({'ae1.69': dict(SPEC, pools=[['10.1.0.100', '10.1.0.90']])}, 'exceeds'),
            ({'ae1.69': dict(SPEC, pools=[['10.1.0.1', '10.1.0.5']])}, 'interface address'),
            ({'ae1.69': dict(SPEC, pools=[['10.2.0.1', '10.2.0.5']])}, 'outside'),
            ({'ae1.69': dict(SPEC, pools=[['10.1.0.100', '10.1.0.110'], ['10.1.0.105', '10.1.0.120']])}, 'overlap'),
            ({'ae1.69': dict(SPEC, pools=[], reserved={})}, 'pool or a reservation'),
            ({'ae1.69': dict(SPEC, reserved={'zz': '10.1.0.50'})}, 'MAC'),
            ({'ae1.69': dict(SPEC, reserved={'02:11:22:33:44:99': '10.1.0.2'})}, 'client address'),
            ({'ae1.69': dict(SPEC, lease=5)}, 'lease'),
            ({'ae1.69': dict(SPEC, options={'dns': ['nope']})}, 'dns'),
            ({'ae1.69': dict(SPEC, options={'domain': '-bad'})}, 'domain'),
            ({'ae1.69': dict(SPEC, address='10.1.0.2/31')}, 'room'),
            ({'ae1.69': dict(SPEC, extra=1)}, 'unknown server field'),
        ]
        for servers, text in cases:
            with self.subTest(text=text), self.assertRaisesRegex(ValueError, text):
                dhcp.validate_intent(dict(servers=servers))
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            dhcp.validate_intent(dict(servers={}, configuration='x'))
        big = {'p%d' % n: SPEC for n in range(1, dhcp.MAX_SERVERS + 2)}
        with self.assertRaisesRegex(ValueError, 'at most'):
            dhcp.validate_intent(dict(servers=big))

    def test_apply_requires_the_current_revision_and_bumps_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch.object(dhcp, 'INTENT', root / 'intent.json'), patch.object(dhcp, 'RUN', root / 'run'), \
                 patch.object(dhcp, 'boot_id', return_value='boot'):
                self.assertEqual(dhcp.status()['config'], dict(revision=0, configuration=None, servers={}))
                with self.assertRaisesRegex(ValueError, 'revision conflict'):
                    dhcp.apply(dict(revision=3, servers={}, configuration=None))
                result = dhcp.apply(dict(revision=0, servers={'ae1.69': SPEC}, configuration='b' * 64), clock=lambda: 5.0)
                self.assertEqual((result['config']['revision'], result['config']['configuration'], sorted(result['config']['servers'])),
                                 (1, 'b' * 64, ['ae1.69']))
                self.assertIsNone(result['running'])
                saved = json.loads((root / 'intent.json').read_text())
                self.assertEqual((saved['revision'], saved['applied_at']), (1, 5.0))
                if os.name != 'nt':
                    self.assertEqual(oct((root / 'intent.json').stat().st_mode & 0o777), '0o600')
                with self.assertRaisesRegex(ValueError, 'revision conflict'):
                    dhcp.apply(dict(revision=0, servers={}, configuration=None))
                self.assertEqual(dhcp.apply(dict(revision=1, servers={}, configuration=None))['config']['servers'], {})

    def test_bpf_program_shape(self):
        program, count = dhcp.bpf_program(False)
        self.assertEqual((count, len(program)), (14, 14 * 8))
        self.assertNotEqual(dhcp.bpf_program(True)[0], program)

    def test_device_addresses_parse_ip_json(self):
        rows = json.dumps([{'addr_info': [{'family': 'inet', 'local': '10.1.0.2', 'prefixlen': 22}, {'family': 'inet6', 'local': 'fe80::1', 'prefixlen': 64}]}])
        self.assertEqual(dhcp.device_addresses('ae1.69', run=lambda argv: rows), ['10.1.0.2/22'])
        self.assertIsNone(dhcp.device_addresses('ae1.69', run=lambda argv: '[]'))


if __name__ == '__main__':
    unittest.main()
