"""The committed FFN Protect tree compiles to the daemon's intent, and every fault names its entry."""
import sys
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'opt'))
import ffn_protect_gateway as daemon
import ffn_protect_intent as intent

CERT = '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----'
KEY = '-----BEGIN ' + 'PRIVATE KEY-----\nMIIB\n-----END ' + 'PRIVATE KEY-----'
PHASH = daemon.make_phash('secret', 1000)

CONFIG = '''<config>
<shared>
  <certificate><entry name="gw"><public-key>%s</public-key><private-key>%s</private-key></entry>
               <entry name="root"><public-key>%s</public-key><private-key>%s</private-key></entry></certificate>
  <authentication-profile>
    <entry name="users"><method><local-database/></method><allow-list><member>alice</member></allow-list></entry>
    <entry name="corp"><method><ldap><server-profile>corp-ldap</server-profile></ldap></method></entry>
    <entry name="rad"><method><radius><server-profile>corp-radius</server-profile></radius></method></entry>
  </authentication-profile>
  <server-profile>
    <ldap><entry name="corp-ldap"><server><entry name="dc1"><address>ldap.corp.example</address><port>636</port></entry></server>
          <ssl>yes</ssl><verify-server-certificate>no</verify-server-certificate><bind-dn-template>{user}@corp.example</bind-dn-template></entry></ldap>
    <radius><entry name="corp-radius"><server><entry name="r1"><ip-address>10.1.0.5</ip-address></entry></server><secret>s3</secret><timeout>3</timeout></entry></radius>
  </server-profile>
  <local-user-database><user><entry name="alice"><phash>%s</phash></entry></user></local-user-database>
</shared>
<devices><entry name="localhost.localdomain">
  <network><interface>
    <ethernet><entry name="ethernet1/5"><layer3><ip><entry name="203.0.113.10/32"/></ip></layer3></entry></ethernet>
    <tunnel><entry name="tunnel"><units><entry name="tunnel.1"><ip><entry name="10.200.0.1/24"/></ip></entry></units></entry></tunnel>
  </interface></network>
  <vsys><entry name="vsys1">
    <import><network><interface><member>ethernet1/5</member><member>tunnel.1</member></interface></network></import>
    <global-protect>
      <global-protect-portal><entry name="main">
        <portal-config><local-address><interface>ethernet1/5</interface><ip><ipv4>203.0.113.10</ipv4></ip></local-address>
          <certificate>gw</certificate><client-auth><entry name="default"><authentication-profile>users</authentication-profile></entry></client-auth>
          <login-lifetime>86400</login-lifetime></portal-config>
        <client-config><connect-method>on-demand</connect-method>
          <gateways><external><list><entry name="vpn.example.com"><priority>2</priority><description>Main</description></entry></list></external></gateways>
          <root-ca><member>root</member></root-ca></client-config>
      </entry></global-protect-portal>
      <global-protect-gateway><entry name="main">
        <local-address><interface>ethernet1/5</interface><ip><ipv4>203.0.113.10</ipv4></ip></local-address>
        <certificate>gw</certificate><client-auth><entry name="default"><authentication-profile>%s</authentication-profile></entry></client-auth>
        <tunnel-mode>yes</tunnel-mode><tunnel-interface>tunnel.1</tunnel-interface>
        <remote-user-tunnel-configs><entry name="default">
          <ip-pool><member>10.200.0.10-10.200.0.250</member></ip-pool><dns><member>10.1.0.3</member></dns><dns-suffix><member>corp.example</member></dns-suffix>
          <split-tunneling><access-route><member>10.0.0.0/8</member></access-route></split-tunneling>
        </entry></remote-user-tunnel-configs>
        <ipsec-crypto>%s</ipsec-crypto><idle-timeout>900</idle-timeout><hip-collection>yes</hip-collection>
      </entry></global-protect-gateway>
    </global-protect>
  </entry></vsys>
</entry></devices>
</config>'''


def config(profile='users', crypto='aes-256-cbc'):
    return ET.fromstring(CONFIG % (CERT, KEY, CERT, KEY, PHASH, profile, crypto))


class Compile(unittest.TestCase):
    def test_the_tree_compiles_to_the_daemon_shape(self):
        out = intent.compile_intent(config())['protect']
        gateway, portal = out['gateways']['main'], out['portals']['main']
        self.assertEqual((gateway['interface'], gateway['address'], gateway['tunnel'], gateway['tunnel_address']), ('p5', '203.0.113.10', 'tunnel.1', '10.200.0.1/24'))
        self.assertEqual(gateway['pools'], [['10.200.0.10', '10.200.0.250']])
        self.assertEqual((gateway['crypto'], gateway['tunnel_mode'], gateway['idle_timeout'], gateway['hip'], gateway['mtu']), ('aes-256-cbc', 'esp-ssl', 900, True, 1400))
        self.assertEqual((gateway['dns'], gateway['dns_suffix'], gateway['access_routes']), (['10.1.0.3'], ['corp.example'], ['10.0.0.0/8']))
        self.assertEqual((portal['connect_method'], portal['login_lifetime']), ('on-demand', 86400))
        self.assertEqual(portal['gateways'], [dict(name='vpn.example.com', priority=2, description='Main')])
        self.assertTrue(portal['root_ca'].startswith('-----BEGIN CERTIFICATE-----'))
        self.assertEqual(out['auth_profiles'], dict(users=dict(method='local', timeout=5, allow=['alice'])))
        self.assertEqual(sorted(out['certificates']), ['gw'])
        self.assertEqual(out['users']['alice']['phash'], PHASH)

    def test_directory_and_radius_profiles_carry_their_servers(self):
        out = intent.compile_intent(config(profile='corp'))['protect']
        self.assertEqual(out['auth_profiles']['corp'], dict(method='ldap', timeout=5, bind_template='{user}@corp.example', ssl=True, verify=False, ca='',
                                                            servers=[dict(host='ldap.corp.example', port=636)]))
        out = intent.compile_intent(config(profile='rad'))['protect']
        self.assertEqual(out['auth_profiles']['rad'], dict(method='radius', timeout=3, secret='s3', servers=[dict(host='10.1.0.5', port=1812)]))

    def test_ssl_only_gateways_keep_a_cipher_for_the_fallback_but_no_esp(self):
        gateway = intent.compile_intent(config(crypto='none'))['protect']['gateways']['main']
        self.assertEqual((gateway['tunnel_mode'], gateway['crypto']), ('ssl-only', 'aes-128-cbc'))

    def test_faults_name_their_entry(self):
        root = config()
        root.find('.//global-protect-gateway/entry/tunnel-interface').text = 'tunnel.2'
        with self.assertRaises(ValueError) as caught:
            intent.compile_intent(root)
        self.assertIn('gateway main: tunnel interface', str(caught.exception))
        root = config()
        root.find('.//global-protect-portal/entry/portal-config/local-address/ip/ipv4').text = '203.0.113.11'
        with self.assertRaises(ValueError) as caught:
            intent.compile_intent(root)
        self.assertIn('portal main: 203.0.113.11 is not an address of ethernet1/5', str(caught.exception))
        root = config(profile='nobody')
        with self.assertRaises(ValueError) as caught:
            intent.compile_intent(root)
        self.assertIn("authentication profile 'nobody' is not configured", str(caught.exception))
        root = config()
        root.find('.//global-protect-gateway/entry/certificate').text = 'absent'
        with self.assertRaises(ValueError) as caught:
            intent.compile_intent(root)
        self.assertIn("certificate 'absent'", str(caught.exception))

    def test_a_tree_without_protect_is_an_empty_intent(self):
        root = config()
        vsys = root.find('.//vsys/entry')
        vsys.remove(vsys.find('global-protect'))
        self.assertEqual(intent.compile_intent(root), dict(protect=dict(certificates={}, auth_profiles={}, users={}, portals={}, gateways={})))

    def test_describe_reports_problems_per_entry(self):
        root = config()
        root.find('.//global-protect-gateway/entry/tunnel-interface').text = 'tunnel.9'
        view = intent.describe(root)
        self.assertEqual(view['portals'][0]['problems'], [])
        self.assertIn('tunnel interface', view['gateways'][0]['problems'][0])
        self.assertEqual(view['tunnel_units'], {'tunnel.1': '10.200.0.1/24'})


class Convergence(unittest.TestCase):
    def test_protect_gateway_states_follow_the_committed_tree_and_the_daemon(self):
        import ffn_convergence as conv
        root = config()
        digest = daemon.intent_digest(intent.compile_intent(root)['protect'])
        empty = config()
        vsys = empty.find('.//vsys/entry')
        vsys.remove(vsys.find('global-protect'))
        self.assertEqual(conv.protect_gateway(empty, None)['state'], 'converged')
        self.assertEqual(conv.protect_gateway(root, {'error': 'ssh failed'})['state'], 'unavailable')
        applied = dict(config=dict(revision=2, configuration=None, digest=digest), boot_id='b', running=None)
        self.assertEqual(conv.protect_gateway(root, applied)['state'], 'pending')
        self.assertEqual(conv.protect_gateway(root, dict(applied, config=dict(revision=2, digest='other')))['state'], 'drift')
        listeners = [dict(interface='p5', address='203.0.113.10', port=443, owners=dict(portal='main', gateway='main'))]
        running = dict(revision=2, listeners=listeners, gateways=dict(main=dict(state='up', detail='')), sessions=[{}])
        ok = conv.protect_gateway(root, dict(applied, running=running))
        self.assertEqual((ok['state'], ok['plane'], ok['details']), ('converged', 'dp', ['gateway main: tunnel.1 on 203.0.113.10']))
        self.assertIn('1 session(s)', ok['summary'])
        down = conv.protect_gateway(root, dict(applied, running=dict(running, gateways=dict(main=dict(state='error', detail='worker exited')))))
        self.assertEqual((down['state'], down['details']), ('failed', ['gateway main: error (worker exited)']))
        self.assertEqual(conv.protect_gateway(root, dict(applied, running=dict(running, listeners=[])))['state'], 'pending')
        self.assertEqual(conv.protect_gateway(root, dict(applied, running=dict(running, revision=1)))['state'], 'pending')


if __name__ == '__main__':
    unittest.main()
