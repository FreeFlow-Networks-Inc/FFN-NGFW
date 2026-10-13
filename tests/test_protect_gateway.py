"""The FFN Protect daemon's protocol pieces, checked without a dataplane: credentials, the directory and
RADIUS exchanges against fakes on the loopback, the address pool, the tunnel framing, the XML the clients
index into, and the intent rules the commit path relies on."""
import hashlib
import hmac
import ipaddress
import json
import socket
import struct
import sys
import threading
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'opt'))
import ffn_protect_gateway as protect

CERT = '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n'
KEY = '-----BEGIN ' + 'PRIVATE KEY-----\nMIIB\n-----END ' + 'PRIVATE KEY-----\n'


def intent(**changes):
    gateway = dict(interface='p5', address='203.0.113.10', certificate='gw', auth_profile='users', tunnel='tunnel.1',
                   tunnel_address='10.200.0.1/24', pools=[['10.200.0.10', '10.200.0.20']], dns=['10.1.0.3'], dns_suffix=['corp.example'],
                   access_routes=['10.0.0.0/8'], crypto='aes-256-cbc', idle_timeout=600, login_lifetime=86400)
    gateway.update(changes)
    return dict(protect=dict(certificates=dict(gw=dict(certificate=CERT, private_key=KEY)),
                             users=dict(alice=dict(phash=protect.make_phash('secret', 1000))),
                             auth_profiles=dict(users=dict(method='local')),
                             portals=dict(main=dict(interface='p5', address='203.0.113.10', certificate='gw', auth_profile='users',
                                                    gateways=[dict(name='vpn.example.com', priority=1)])),
                             gateways=dict(main=gateway)))


class Credentials(unittest.TestCase):
    def test_phash_round_trip(self):
        phash = protect.make_phash('correct horse', 1000)
        self.assertTrue(phash.startswith('pbkdf2-sha256$1000$'))
        self.assertTrue(protect.verify_phash(phash, 'correct horse'))
        self.assertFalse(protect.verify_phash(phash, 'correct horse '))
        self.assertFalse(protect.verify_phash('md5$x$y', 'correct horse'))
        self.assertFalse(protect.verify_phash('garbage', 'correct horse'))

    def test_ber_encoding_and_decoding(self):
        self.assertEqual(protect.ber(0x04, b'abc'), b'\x04\x03abc')
        self.assertEqual(protect.ber(0x04, bytes(200))[:3], b'\x04\x81\xc8')
        self.assertEqual(protect.ber(0x04, bytes(300))[:4], b'\x04\x82\x01\x2c')
        for payload in (b'', b'x', bytes(130), bytes(1000)):
            tag, value, end = protect.ber_read(protect.ber(0x30, payload))
            self.assertEqual((tag, value, end), (0x30, payload, len(protect.ber(0x30, payload))))
        with self.assertRaises(ValueError):
            protect.ber_read(b'\x30\x05ab')

    def test_dn_escaping(self):
        self.assertEqual(protect.ldap_escape('a,b=c'), 'a\\,b\\=c')
        self.assertEqual(protect.ldap_escape(' lead'), '\\ lead')
        self.assertEqual(protect.ldap_escape('plain.user'), 'plain.user')


class FakeDirectory:
    """Answers one simple bind: result 0 for the expected dn and password, 49 otherwise."""
    def __init__(self, dn, password):
        self.dn, self.password, self.seen = dn, password, []
        self.sock = socket.socket()
        self.sock.bind(('127.0.0.1', 0))
        self.sock.listen(1)
        self.port = self.sock.getsockname()[1]
        threading.Thread(target=self.serve, daemon=True).start()

    def serve(self):
        conn, _ = self.sock.accept()
        with conn:
            data = conn.recv(4096)
            _, message, _ = protect.ber_read(data)
            _, msgid, offset = protect.ber_read(message)
            _, bind, _ = protect.ber_read(message, offset)
            _, version, offset = protect.ber_read(bind)
            _, dn, offset = protect.ber_read(bind, offset)
            tag, password, _ = protect.ber_read(bind, offset)
            self.seen.append((version, dn.decode(), tag, password.decode()))
            code = 0 if (dn.decode(), password.decode()) == (self.dn, self.password) else 49
            response = protect.ber(0x61, protect.ber(0x0a, bytes([code])) + protect.ber(0x04, b'') + protect.ber(0x04, b''))
            conn.sendall(protect.ber(0x30, protect.ber(0x02, msgid) + response))


class Directory(unittest.TestCase):
    def test_simple_bind_is_version_3_with_the_password_in_the_simple_choice(self):
        server = FakeDirectory('uid=alice,ou=people,dc=example', 'pw')
        self.assertTrue(protect.ldap_bind('127.0.0.1', server.port, False, 'uid=alice,ou=people,dc=example', 'pw'))
        self.assertEqual(server.seen, [(b'\x03', 'uid=alice,ou=people,dc=example', 0x80, 'pw')])

    def test_refused_credentials_are_false_not_an_error(self):
        server = FakeDirectory('uid=alice,ou=people,dc=example', 'pw')
        self.assertFalse(protect.ldap_bind('127.0.0.1', server.port, False, 'uid=alice,ou=people,dc=example', 'wrong'))

    def test_an_empty_password_never_reaches_the_directory(self):
        server = FakeDirectory('uid=alice,ou=people,dc=example', '')
        self.assertFalse(protect.ldap_bind('127.0.0.1', server.port, False, 'uid=alice,ou=people,dc=example', ''))
        self.assertEqual(server.seen, [])


class FakeRadius:
    def __init__(self, secret, password):
        self.secret, self.password, self.seen = secret.encode(), password, []
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(('127.0.0.1', 0))
        self.port = self.sock.getsockname()[1]
        threading.Thread(target=self.serve, daemon=True).start()

    def serve(self):
        data, peer = self.sock.recvfrom(4096)
        code, identifier, length = struct.unpack('!BBH', data[:4])
        authenticator, attributes, offset = data[4:20], {}, 20
        while offset < length:
            kind, size = data[offset], data[offset + 1]
            attributes[kind] = data[offset + 2:offset + size]
            offset += size
        cipher, previous, plain = attributes[2], authenticator, b''
        for i in range(0, len(cipher), 16):   # RFC 2865 PAP hiding, as a RADIUS server undoes it
            block = hashlib.md5(self.secret + previous).digest()
            plain += bytes(a ^ b for a, b in zip(cipher[i:i + 16], block))
            previous = cipher[i:i + 16]
        self.seen.append(dict(code=code, user=attributes[1].decode(), password=plain.rstrip(b'\0').decode(), nas=socket.inet_ntoa(attributes[4])))
        reply_code = 2 if self.seen[-1]['password'] == self.password else 3
        head = struct.pack('!BBH', reply_code, identifier, 20)
        self.sock.sendto(head + hashlib.md5(head + authenticator + self.secret).digest(), peer)


class Radius(unittest.TestCase):
    def test_pap_request_encrypts_the_password_and_the_reply_is_verified(self):
        server = FakeRadius('s3cret', 'pw')
        self.assertTrue(protect.radius_pap('127.0.0.1', server.port, 's3cret', 'alice', 'pw', '203.0.113.10', timeout=2, retries=0))
        self.assertEqual(server.seen, [dict(code=1, user='alice', password='pw', nas='203.0.113.10')])

    def test_reject_is_false(self):
        server = FakeRadius('s3cret', 'pw')
        self.assertFalse(protect.radius_pap('127.0.0.1', server.port, 's3cret', 'alice', 'nope', '203.0.113.10', timeout=2, retries=0))

    def test_no_reply_is_an_error(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as silent:
            silent.bind(('127.0.0.1', 0))
            with self.assertRaises(OSError):
                protect.radius_pap('127.0.0.1', silent.getsockname()[1], 's3cret', 'alice', 'pw', '203.0.113.10', timeout=0.2, retries=0)


class Authentication(unittest.TestCase):
    def profiles(self):
        return dict(local=dict(method='local'), listed=dict(method='local', allow=['bob']),
                    ldap=dict(method='ldap', servers=[dict(host='ldap.example', port=636)], bind_template='uid={user},dc=x', ssl=True, verify=True),
                    radius=dict(method='radius', servers=[dict(host='r.example', port=1812)], secret='s'))

    def test_local_users(self):
        auth = protect.Authenticator(self.profiles(), dict(alice=dict(phash=protect.make_phash('pw', 1000))))
        self.assertEqual(auth.check('local', 'alice', 'pw', '198.51.100.1', '10.0.0.1'), (True, ''))
        self.assertEqual(auth.check('local', 'alice', 'xx', '198.51.100.1', '10.0.0.1'), (False, 'invalid username or password'))
        self.assertEqual(auth.check('local', 'mallory', 'pw', '198.51.100.1', '10.0.0.1'), (False, 'invalid username or password'))
        self.assertEqual(auth.check('missing', 'alice', 'pw', '198.51.100.1', '10.0.0.1'), (False, 'authentication profile missing'))
        self.assertEqual(auth.check('listed', 'alice', 'pw', '198.51.100.1', '10.0.0.1'), (False, 'invalid username or password'))
        self.assertEqual(auth.check('local', 'bad user!', 'pw', '198.51.100.1', '10.0.0.1'), (False, 'invalid username or password'))

    def test_failures_are_limited_per_source_and_user(self):
        clock = [0.0]
        auth = protect.Authenticator(self.profiles(), {}, clock=lambda: clock[0])
        for _ in range(protect.FAILURE_LIMIT):
            auth.check('local', 'alice', 'x', '198.51.100.1', '10.0.0.1')
        self.assertEqual(auth.check('local', 'alice', 'x', '198.51.100.2', '10.0.0.1'), (False, 'too many failed attempts'))
        self.assertEqual(auth.check('local', 'bob', 'x', '198.51.100.1', '10.0.0.1'), (False, 'too many failed attempts'))
        clock[0] = protect.FAILURE_WINDOW + 1
        self.assertEqual(auth.check('local', 'bob', 'x', '198.51.100.1', '10.0.0.1'), (False, 'invalid username or password'))

    def test_ldap_binds_as_the_templated_dn_and_radius_asks_the_server(self):
        calls = []
        def ldap(host, port, use_tls, dn, password, timeout=5, ca=None, verify=True):
            calls.append(('ldap', host, port, use_tls, dn, password, verify)); return dn == 'uid=corp\\\\alice,dc=x' and password == 'pw'
        def radius(host, port, secret, username, password, nas_ip, timeout=5):
            calls.append(('radius', host, port, secret, username, password, nas_ip)); return password == 'pw'
        auth = protect.Authenticator(self.profiles(), {}, ldap=ldap, radius=radius)
        self.assertEqual(auth.check('ldap', 'corp\\alice', 'pw', '198.51.100.1', '10.0.0.1'), (True, ''))
        self.assertEqual(auth.check('radius', 'alice', 'pw', '198.51.100.1', '10.0.0.1'), (True, ''))
        self.assertEqual(auth.check('radius', 'alice', 'no', '198.51.100.1', '10.0.0.1'), (False, 'invalid username or password'))
        self.assertEqual(calls[0], ('ldap', 'ldap.example', 636, True, 'uid=corp\\\\alice,dc=x', 'pw', True))
        self.assertEqual(calls[1], ('radius', 'r.example', 1812, 's', 'alice', 'pw', '10.0.0.1'))

    def test_an_unreachable_directory_is_reported_not_treated_as_a_bad_password(self):
        def ldap(*a, **k):
            raise OSError('refused')
        auth = protect.Authenticator(self.profiles(), {}, ldap=ldap)
        self.assertEqual(auth.check('ldap', 'alice', 'pw', '198.51.100.1', '10.0.0.1'), (False, 'directory unreachable'))


class Addresses(unittest.TestCase):
    def test_pool_allocates_in_order_honours_a_free_preference_and_reuses_last(self):
        pool = protect.Pool([['10.200.0.10', '10.200.0.12'], ['10.200.0.20', '10.200.0.20']])
        self.assertEqual(pool.size, 4)
        self.assertEqual(pool.allocate(), '10.200.0.10')
        self.assertEqual(pool.allocate('10.200.0.20'), '10.200.0.20')
        self.assertEqual(pool.allocate('10.200.0.20'), '10.200.0.11')
        self.assertEqual(pool.allocate(), '10.200.0.12')
        self.assertIsNone(pool.allocate())
        pool.release('10.200.0.10')
        pool.release('10.200.0.11')
        self.assertEqual(pool.allocate(), '10.200.0.10')
        pool.release('10.200.0.99')
        self.assertEqual(len(pool.used), 3)


class Framing(unittest.TestCase):
    def test_frames_are_parsed_whole_with_the_rest_kept(self):
        packet = b'\x45' + bytes(19)
        data = protect.gpst_frame(0x0800, packet) + protect.gpst_frame(0, b'') + protect.gpst_frame(0x0800, packet)[:10]
        frames, rest = protect.gpst_frames(data)
        self.assertEqual(frames, [(0x0800, packet), (0, b'')])
        self.assertEqual(rest, protect.gpst_frame(0x0800, packet)[:10])
        self.assertEqual(protect.gpst_frame(0x0800, packet)[:16], b'\x1a\x2b\x3c\x4d\x08\x00\x00\x14\x01\x00\x00\x00\x00\x00\x00\x00')
        with self.assertRaises(ValueError):
            protect.gpst_frames(b'\x00' * 16)


class ClientXml(unittest.TestCase):
    def test_prelogin_and_login_argument_positions(self):
        self.assertIn('<status>Success</status>', protect.prelogin_xml('main'))
        xml = protect.login_xml('c0ffee', 'main', 'alice', '10.200.0.10', 'portalcookie')
        arguments = xml.split('<argument>')[1:]
        arguments = [a.split('</argument>')[0] for a in arguments]
        self.assertEqual(len(arguments), 21)
        self.assertEqual((arguments[1], arguments[3], arguments[4], arguments[12], arguments[14], arguments[15], arguments[16]),
                         ('c0ffee', 'main', 'alice', 'tunnel', '4100', '10.200.0.10', 'portalcookie'))

    def test_tunnel_configuration_carries_the_keys_as_bits_and_hex(self):
        gateway = protect.validate_intent(intent())['gateways']['main']
        esp = dict(crypto='aes-256-cbc', c2s_spi=0x1234, s2c_spi=0xabcd, c2s_enc=bytes(32), s2c_enc=bytes(range(32)), c2s_auth=bytes(20), s2c_auth=bytes(20))
        xml = protect.tunnel_config_xml('main', gateway, dict(portal='main', user='alice', client_ip='10.200.0.10', esp=esp))
        for text in ('<ip-address>10.200.0.10</ip-address>', '<gw-address>10.200.0.1</gw-address>', '<c2s-spi>0x00001234</c2s-spi>',
                     '<ekey-s2c><bits>256</bits><val>' + bytes(range(32)).hex() + '</val></ekey-s2c>', '<akey-c2s><bits>160</bits>',
                     '<access-routes><member>10.0.0.0/8</member></access-routes>', '<dns><member>10.1.0.3</member></dns>',
                     '<disconnect-on-idle>600</disconnect-on-idle>', '<ipsec-mode>esp-tunnel</ipsec-mode>', '<udp-port>4501</udp-port>'):
            self.assertIn(text, xml)
        self.assertNotIn('<ipsec>', protect.tunnel_config_xml('main', gateway, dict(portal='', user='alice', client_ip='10.200.0.10', esp=None)))

    def test_portal_configuration_lists_gateways_and_the_cookie(self):
        portal = protect.validate_intent(intent())['portals']['main']
        xml = protect.portal_config_xml('main', portal, 'cookie1')
        self.assertIn('<entry name="vpn.example.com"><priority-rule><entry name="Any"><priority>1</priority>', xml)
        self.assertIn('<portal-userauthcookie>cookie1</portal-userauthcookie>', xml)
        self.assertIn('<connect-method>user-logon</connect-method>', xml)
        self.assertNotIn('<root-ca>', xml)
        self.assertIn('<error>Invalid username or password</error>', protect.error_xml('Invalid username or password'))


class Intent(unittest.TestCase):
    def test_a_valid_intent_normalises(self):
        out = protect.validate_intent(intent())
        gateway = out['gateways']['main']
        self.assertEqual((gateway['tunnel_mode'], gateway['mtu'], gateway['hip'], gateway['exclude_routes']), ('esp-ssl', 1400, False, []))
        self.assertEqual(out['portals']['main']['gateways'], [dict(name='vpn.example.com', priority=1, description='')])
        self.assertEqual(out['auth_profiles']['users'], dict(method='local', timeout=5))
        same = intent()
        self.assertEqual(protect.intent_digest(protect.validate_intent(same)), protect.intent_digest(protect.validate_intent(same)))
        self.assertNotEqual(protect.intent_digest(out), protect.intent_digest(protect.validate_intent(intent(mtu=1300))))
        self.assertEqual(protect.redacted(out)['certificates']['gw']['private_key'], '(private)')
        self.assertEqual(protect.redacted(out)['users']['alice']['phash'], '(hashed)')

    def test_rejections_name_the_fault(self):
        cases = [(intent(certificate='missing'), 'certificate'), (intent(tunnel='tun0'), 'tunnel.N'),
                 (intent(pools=[['10.200.0.1', '10.200.0.5']]), 'tunnel address itself'), (intent(crypto='3des'), 'crypto'),
                 (intent(tunnel_address='10.200.0.1/31'), 'prefix'), (intent(access_routes=['10.0.0.1/8']), 'IPv4 networks'),
                 (intent(pools=[]), 'pool'), (intent(idle_timeout=5), 'idle_timeout')]
        for data, needle in cases:
            with self.assertRaises(ValueError) as caught:
                protect.validate_intent(data)
            self.assertIn(needle, str(caught.exception))
        two = intent()
        two['protect']['gateways']['second'] = dict(two['protect']['gateways']['main'], address='203.0.113.11')
        with self.assertRaises(ValueError) as caught:
            protect.validate_intent(two)
        self.assertIn('used by another gateway', str(caught.exception))
        ldap = intent()
        ldap['protect']['auth_profiles']['users'] = dict(method='ldap', servers=[dict(host='ldap.example')], bind_template='uid={user},dc=x')
        self.assertEqual(protect.validate_intent(ldap)['auth_profiles']['users']['servers'], [dict(host='ldap.example', port=636)])
        ldap['protect']['auth_profiles']['users']['bind_template'] = 'no placeholder'
        with self.assertRaises(ValueError):
            protect.validate_intent(ldap)


if __name__ == '__main__':
    unittest.main()
