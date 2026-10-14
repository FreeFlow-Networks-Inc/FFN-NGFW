"""Service routes: the committed tree compiles to the dataplane intent, the installer issues the right kernel
operations, the security renderer grants the management plane's link, a link change replays at once, the MP
host firewall renders the MGT port's permitted services, and the console's schema round-trips."""
import json
import sys
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'opt'))
import ffn_service_routes as routes
import ffn_mp_interfaces as mp
from ffn_security_nft import render
from ffn_nat_policy import NatError
from test_policy_plan import configuration

CONFIG = '''<config><devices><entry name="localhost.localdomain">
  <deviceconfig><system><route><service>
    <entry name="dns"><source><interface>ethernet1/5</interface><address>203.0.113.10</address></source></entry>
    <entry name="updates"><source><interface>ethernet1/5</interface></source></entry>
    <entry name="ntp"><source><interface>ae1.69</interface></source></entry>
    <entry name="email"/>
  </service></route></system></deviceconfig>
  <network><interface>
    <ethernet><entry name="ethernet1/5"><layer3><ip><entry name="203.0.113.10/32"/><entry name="203.0.113.11/32"/></ip></layer3></entry></ethernet>
    <aggregate-ethernet><entry name="ae1"><layer3><units><entry name="ae1.69"><ip><entry name="192.0.2.1/24"/></ip></entry></units></layer3></entry></aggregate-ethernet>
  </interface></network>
  <vsys><entry name="vsys1"><import><network><interface><member>ethernet1/5</member><member>ae1.69</member></interface></network></import></entry></vsys>
</entry></devices></config>'''


class Compile(unittest.TestCase):
    def test_tree_to_intent(self):
        out = routes.compile_intent(ET.fromstring(CONFIG))['routes']
        self.assertEqual(sorted(out), ['dns', 'ntp', 'updates'])          # email has no source: management interface
        self.assertEqual(out['dns'], dict(interface='ethernet1/5', device='p5', address='203.0.113.10', ports=[['udp', 53], ['tcp', 53]]))
        self.assertEqual((out['updates']['address'], out['updates']['ports']), ('203.0.113.10', [['tcp', 443]]))
        self.assertEqual((out['ntp']['device'], out['ntp']['address']), ('ae1.69', '192.0.2.1'))
        self.assertEqual(routes.validate_intent(dict(routes=out)), out)
        self.assertEqual(routes.intent_digest(out), routes.intent_digest(routes.compile_intent(ET.fromstring(CONFIG))['routes']))

    def test_faults_name_the_service(self):
        root = ET.fromstring(CONFIG)
        root.find(".//service/entry[@name='dns']/source/address").text = '203.0.113.99'
        with self.assertRaises(ValueError) as caught:
            routes.compile_intent(root)
        self.assertIn('service route dns: 203.0.113.99 is not an address of ethernet1/5', str(caught.exception))
        root = ET.fromstring(CONFIG)
        root.find(".//service/entry[@name='ntp']/source/interface").text = 'ethernet1/7'
        with self.assertRaises(ValueError) as caught:
            routes.compile_intent(root)
        self.assertIn('service route ntp: ethernet1/7 is not a layer3', str(caught.exception))
        root = ET.fromstring(CONFIG)
        root.find(".//service/entry[@name='email']").set('name', 'gopher')
        with self.assertRaises(ValueError):
            routes.configured(root)
        for bad in (dict(routes={'dns': dict(device='eth0', address='203.0.113.10', ports=[['udp', 53]])}),
                    dict(routes={'dns': dict(device='p5', address='x', ports=[['udp', 53]])}),
                    dict(routes={'dns': dict(device='p5', address='203.0.113.10', ports=[['sctp', 53]])}),
                    dict(routes={'gopher': dict(device='p5', address='203.0.113.10', ports=[['tcp', 70]])})):
            with self.assertRaises(ValueError):
                routes.validate_intent(bad)

    def test_every_service_has_ports(self):
        for name, meta in routes.SERVICES.items():
            self.assertTrue(meta['ports'] and all(p[0] in ('tcp', 'udp') and 1 <= p[1] <= 65535 for p in meta['ports']), name)


class Installer(unittest.TestCase):
    """install() against a fake kernel: the operations it issues are the specification."""
    def fake(self, routes_main):
        calls = []
        def run(argv, check=True, ns=None, input_text=None):
            argv = list(argv)
            calls.append((ns, argv, input_text))
            if argv[:2] == ['ip', '-j'] or (argv[0] == 'ip' and '-j' in argv[:2]):
                rest = argv[argv.index('-j') + 1:]
                if '-n' in rest:
                    rest = rest[rest.index('-n') + 2:]
                if rest[:2] == ['rule', 'show']:
                    return '[]'
                if rest[:2] == ['link', 'show']:
                    name = rest[2] if len(rest) > 2 else None
                    if name == 'svcrt1':
                        return json.dumps([dict(ifname='svcrt1', ifindex=44)])
                    return json.dumps([dict(ifname='ffndp0'), dict(ifname='lo')] if '-n' not in argv else [dict(ifname='p5'), dict(ifname='ae1.69')])
                if rest[:3] == ['route', 'show', 'dev']:
                    return json.dumps(routes_main.get(rest[3], []))
                return '[]'
            if argv[0] == 'nft' and argv[1:3] == ['list', 'table']:
                return ''
            return ''
        return calls, run

    def test_policy_routing_tables_rules_and_snat(self):
        intent = dict(dns=dict(interface='ethernet1/5', device='p5', address='203.0.113.10', ports=[['udp', 53], ['tcp', 53]]),
                      ntp=dict(interface='ae1.69', device='ae1.69', address='192.0.2.1', ports=[['udp', 123]]),
                      updates=dict(interface='ethernet1/5', device='p5', address='203.0.113.10', ports=[['tcp', 443]]))
        calls, run = self.fake({'p5': [dict(dst='default', gateway='203.0.113.9', flags=['onlink'])], 'ae1.69': [dict(dst='192.0.2.0/24')]})
        original = routes.run
        routes.run = run
        try:
            result = routes.install(intent)
        finally:
            routes.run = original
        self.assertEqual(result['tables'], {'ae1.69': 200, 'p5': 201})
        self.assertEqual(result['problems'], [])
        data = [' '.join(argv) for ns, argv, _ in calls if ns == routes.NAMESPACE or (argv[:3] == ['ip', '-n', routes.NAMESPACE]) or ('-n' in argv and routes.NAMESPACE in argv)]
        joined = '\n'.join(' '.join(argv) for _, argv, _ in calls)
        self.assertIn('ip link add svcrt0 type veth peer name svcrt1 netns ' + routes.NAMESPACE, joined)
        self.assertIn('ip -n %s route replace default via 203.0.113.9 dev p5 table 201 onlink' % routes.NAMESPACE, joined)
        self.assertIn('ip -n %s route replace default dev ae1.69 table 200' % routes.NAMESPACE, joined)
        self.assertIn('ip -n %s rule add pref 2000 from 127.1.1.1 ipproto udp dport 53 lookup 201' % routes.NAMESPACE, joined)
        self.assertIn('ip -n %s rule add pref 2002 from 127.1.1.1 ipproto udp dport 123 lookup 200' % routes.NAMESPACE, joined)
        self.assertIn('ip -n %s rule add pref 2003 from 127.1.1.1 ipproto tcp dport 443 lookup 201' % routes.NAMESPACE, joined)
        self.assertIn('ip rule add pref 100 from 127.1.1.1 iif ffndp0 lookup 100', joined)
        self.assertIn('ip route replace default via 127.1.3.2 dev svcrt0 table 100', joined)
        self.assertIn('ip route replace 127.1.1.0/24 via 127.1.2.1 dev ffndp0', joined)
        self.assertIn('ip -n %s route replace 127.1.1.0/24 via 127.1.3.1 dev svcrt1' % routes.NAMESPACE, joined)
        scripts = [text for ns, argv, text in calls if argv[:1] == ['nft'] and text]
        self.assertEqual(len(scripts), 1)
        self.assertIn('ip saddr 127.1.1.1 oifname "p5" snat to 203.0.113.10', scripts[0])
        self.assertIn('ip saddr 127.1.1.1 oifname "ae1.69" snat to 192.0.2.1', scripts[0])
        self.assertEqual(scripts[0].count('snat to'), 2)
        self.assertIn('priority srcnat - 10', scripts[0])
        self.assertTrue(data)

    def test_no_routes_installs_only_the_link_and_clears_the_rest(self):
        calls, run = self.fake({})
        original = routes.run
        routes.run = run
        try:
            result = routes.install({})
        finally:
            routes.run = original
        self.assertEqual(result['tables'], {})
        self.assertFalse([text for _, argv, text in calls if argv[:1] == ['nft'] and text])
        self.assertFalse([argv for _, argv, _ in calls if 'rule' in argv and 'add' in argv and 'pref' in argv and '2000' in argv])


class Policy(unittest.TestCase):
    def test_renderer_grants_the_service_route_link_both_ways_and_digests_it(self):
        xml = configuration('security', {'action': 'allow', 'log-end': 'no'})
        plain = render(xml, {'ethernet1/1': 10, 'ethernet1/2': 11})
        linked = render(xml, {'ethernet1/1': 10, 'ethernet1/2': 11}, host_links=[dict(index=44, address='127.1.1.1')])
        self.assertIn('ct direction original iif 44 ip saddr 127.1.1.1 goto grant', linked['script'])
        self.assertIn('ct direction reply oif 44 ct original ip saddr 127.1.1.1 goto grant', linked['script'])
        self.assertNotIn('iif 44', plain['script'])
        self.assertNotEqual(plain['digest'], linked['digest'])
        self.assertLess(linked['script'].index('iif 44'), linked['script'].index('goto r0') if 'goto r0' in linked['script'] else len(linked['script']))
        with self.assertRaises(NatError):
            render(xml, {'ethernet1/1': 10, 'ethernet1/2': 11}, host_links=[dict(index='44', address='127.1.1.1')])

    def test_drift_replays_at_once_when_the_link_changes(self):
        try:
            import ffn_security_runtime as runtime
        except ImportError as error:   # fcntl: Linux only
            self.skipTest(str(error))
        state = dict(boot_id='b', bindings={}, tables=[], kernel_digest='d', host_links=[dict(index=44, address='127.1.1.1')])
        reason = runtime.drift(state, read_bindings=lambda: {}, read_inventory=lambda: {'nftables': []}, read_boot=lambda: 'b', sleep=lambda s: None,
                               read_host_links=lambda: [])
        self.assertEqual(reason, 'service route link changed')


class ManagementPort(unittest.TestCase):
    def test_schema_round_trip_and_rule(self):
        data = dict(mode='dhcp', address='', gateway='', dns=[], mtu=1500, description='OOBM', services=['ssh', 'https', 'ping'], permitted=['10.0.0.0/8', '192.0.2.5/32'])
        encoded = mp.encode(data)
        self.assertEqual(encoded['services'], ['https', 'ssh', 'ping'])
        self.assertEqual(encoded['permitted-ip'], ['10.0.0.0/8', '192.0.2.5/32'])
        node = ET.fromstring('<entry name="MGT"><mode>dhcp</mode><mtu>1500</mtu><services><member>ssh</member><member>snmp</member></services>'
                             '<permitted-ip><member>10.1.0.0/22</member></permitted-ip></entry>')
        decoded = mp.decode(node)
        self.assertEqual((decoded['services'], decoded['permitted']), (['ssh', 'snmp'], ['10.1.0.0/22']))
        self.assertEqual(mp.management_rule(decoded), dict(tcp=[22], udp=[161], icmp=False, permitted_ip=['10.1.0.0/22']))
        self.assertEqual(mp.management_rule(dict(services=[], permitted=[])), dict(tcp=[22, 443, 8443], udp=[], icmp=False, permitted_ip=[]))
        old = mp.decode(ET.fromstring('<entry name="MGT"><mode>static</mode><address>192.0.2.10/24</address><gateway>192.0.2.1</gateway><mtu>1500</mtu></entry>'))
        self.assertEqual((old['services'], old['permitted']), ([], []))
        with self.assertRaises(ValueError):
            mp.validate(dict(data, services=['telnet']))
        with self.assertRaises(ValueError):
            mp.validate(dict(data, permitted=['not-a-network']))

    def test_host_firewall_renders_the_mgt_port_services_in_place_of_the_blanket_accept(self):
        import ffn_bmfw as bmfw
        base = dict(mgmt_ifaces=['mgt0', 'ztx'], mgmt_tcp_ports=[22, 443, 8443], trusted_ifaces=[], vsys=[dict(name='vsys1', vsys_id=1, zones=[], rules=[])])
        plain = bmfw.NftGenerator(bmfw.DataplaneConfig.from_dict(base)).render()
        self.assertIn('iifname { "mgt0", "ztx" } tcp dport { 22, 443, 8443 } accept comment "mgmt"', plain)
        restricted = bmfw.NftGenerator(bmfw.DataplaneConfig.from_dict(dict(base, mgmt_services=[dict(iface='mgt0', tcp=[22, 443, 8443], udp=[161], icmp=True, permitted_ip=['10.0.0.0/8'])]))).render()
        self.assertIn('iifname { "ztx" } tcp dport { 22, 443, 8443 } accept comment "mgmt"', restricted)
        self.assertIn('iifname "mgt0" ip saddr { 10.0.0.0/8 } tcp dport { 22, 443, 8443 } accept comment "mgt services"', restricted)
        self.assertIn('iifname "mgt0" ip saddr { 10.0.0.0/8 } udp dport { 161 } accept comment "mgt services"', restricted)
        self.assertIn('iifname "mgt0" ip saddr { 10.0.0.0/8 } icmp type echo-request accept comment "mgt services"', restricted)
        self.assertNotIn('iifname { "mgt0", "ztx" }', restricted)


class Convergence(unittest.TestCase):
    def test_states(self):
        import ffn_convergence as conv
        root = ET.fromstring(CONFIG)
        expected = routes.compile_intent(root)['routes']
        empty = ET.fromstring(CONFIG)
        for entry in list(empty.find('.//route/service')):
            empty.find('.//route/service').remove(entry)
        self.assertEqual(conv.service_routes(empty, None)['state'], 'converged')
        self.assertEqual(conv.service_routes(root, {'error': 'ssh failed'})['state'], 'unavailable')
        applied = dict(config=dict(revision=1, routes=expected), boot_id='b', running=None)
        self.assertEqual(conv.service_routes(root, applied)['state'], 'pending')
        self.assertEqual(conv.service_routes(root, dict(applied, config=dict(revision=1, routes={})))['state'], 'drift')
        up = dict(applied, running=dict(link=dict(index=44), problems=[]))
        ok = conv.service_routes(root, up)
        self.assertEqual((ok['state'], ok['plane']), ('converged', 'dp'))
        self.assertIn('dns via p5 as 203.0.113.10', ok['details'])
        self.assertEqual(conv.service_routes(root, dict(applied, running=dict(link=dict(index=None), problems=[])))['state'], 'failed')
        self.assertEqual(conv.service_routes(root, dict(applied, running=dict(link=dict(index=44), problems=['p5: no route'])))['state'], 'failed')


if __name__ == '__main__':
    unittest.main()
