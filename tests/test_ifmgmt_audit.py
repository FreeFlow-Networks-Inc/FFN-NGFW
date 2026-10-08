import copy
import json
from pathlib import Path
import sys
import unittest
from xml.etree import ElementTree as ET

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'opt'))
import ffn_ifmgmt_audit as audit

BOOT = '9fed3cf5-c2ce-4b38-8d52-01e9d370229d'
CONFIG = '''<config><shared><address>
 <entry name="Verizon Enterprise CPE"><ip-netmask>152.193.185.10/32</ip-netmask></entry>
 <entry name="A range"><ip-range>10.0.0.1-10.0.0.9</ip-range></entry>
</address></shared><devices><entry name="localhost.localdomain">
<vsys><entry name="vsys1"><address>
 <entry name="Internal LAN GW"><ip-netmask>10.1.0.2/22</ip-netmask></entry>
</address></entry></vsys>
<network>
 <profiles><interface-management-profile>
  <entry name="Management"><permit_ping>yes</permit_ping><permit_ssh>yes</permit_ssh><permit_http>no</permit_http><permit_https>yes</permit_https><permit_snmp>yes</permit_snmp><permit_response_pages>yes</permit_response_pages><permit_user_id>yes</permit_user_id><permitted_ips/><enabled>yes</enabled></entry>
  <entry name="PING-ONLY"><permit_ping>yes</permit_ping><permit_ssh>no</permit_ssh><permit_https>no</permit_https><permitted_ips><member>0.0.0.0/0</member></permitted_ips><enabled>yes</enabled></entry>
 </interface-management-profile></profiles>
 <interface>
  <ethernet>
   <entry name="ethernet1/1"><layer3><ip><entry name="184.187.55.66/28"/></ip><interface-management-profile>PING-ONLY</interface-management-profile></layer3></entry>
   <entry name="ethernet1/5"><layer3><ip><entry name="Verizon Enterprise CPE"/></ip><interface-management-profile>PING-ONLY</interface-management-profile></layer3><link-speed>1000</link-speed></entry>
   <entry name="ethernet1/9"><aggregate-group>ae1</aggregate-group></entry>
  </ethernet>
  <aggregate-ethernet>
   <entry name="ae1"><layer3><units><entry name="ae1.69"><tag>69</tag><ip><entry name="Internal LAN GW"/></ip><interface-management-profile>Management</interface-management-profile></entry></units></layer3></entry>
  </aggregate-ethernet>
 </interface>
</network>
</entry></devices></config>'''


def rule(table, exprs):
    return {'rule': {'family': 'inet', 'table': table, 'chain': 'input', 'expr': exprs}}


def match(left, right, op='=='):
    return {'match': {'op': op, 'left': left, 'right': right}}


def payload(protocol, field):
    return {'payload': {'protocol': protocol, 'field': field}}


def table_rules(device, addresses=(), sources=(), ping=False, tcp=(), udp=(), final_drop=True, baseline=True):
    name = 'ffn_ifmgmt_' + device.replace('.', '_')
    items = [{'table': {'family': 'inet', 'name': name, 'handle': 1}},
             {'chain': {'family': 'inet', 'table': name, 'name': 'input', 'type': 'filter', 'hook': 'input', 'prio': -10, 'policy': 'accept'}}]
    if baseline:
        items += [rule(name, [match({'meta': {'key': 'iifname'}}, device, '!='), {'return': None}]),
                  rule(name, [match({'ct': {'key': 'state'}}, 'invalid', 'in'), {'counter': {'packets': 0, 'bytes': 0}}, {'drop': None}]),
                  rule(name, [match({'ct': {'key': 'direction'}}, 'reply'), match({'ct': {'key': 'state'}}, ['established', 'related'], 'in'), {'accept': None}]),
                  rule(name, [match(payload('icmp', 'type'), {'set': ['destination-unreachable', 'time-exceeded', 'parameter-problem']}), {'accept': None}]),
                  rule(name, [match(payload('icmpv6', 'type'), {'set': ['destination-unreachable', 'packet-too-big', 'time-exceeded', 'parameter-problem']}), {'accept': None}]),
                  rule(name, [match(payload('ip6', 'hoplimit'), 255), match(payload('icmpv6', 'type'), {'set': ['nd-router-advert', 'nd-neighbor-solicit', 'nd-neighbor-advert']}), {'accept': None}]),
                  rule(name, [match(payload('udp', 'sport'), 67), match(payload('udp', 'dport'), 68), {'accept': None}]),
                  rule(name, [match(payload('ip6', 'saddr'), {'prefix': {'addr': 'fe80::', 'len': 10}}), match(payload('udp', 'sport'), 547), match(payload('udp', 'dport'), 546), {'accept': None}])]
    for address in addresses:
        head = [match(payload('ip', 'daddr'), address)]
        if sources:
            head.append(match(payload('ip', 'saddr'), {'set': [{'prefix': {'addr': s.split('/')[0], 'len': int(s.split('/')[1])}} for s in sources]}
                              if len(sources) > 1 else {'prefix': {'addr': sources[0].split('/')[0], 'len': int(sources[0].split('/')[1])}}))
        if ping:
            items.append(rule(name, head + [match(payload('icmp', 'type'), 'echo-request'), {'counter': {'packets': 1, 'bytes': 84}}, {'accept': None}]))
        if tcp:
            items.append(rule(name, head + [match(payload('tcp', 'dport'), {'set': list(tcp)} if len(tcp) > 1 else tcp[0]), {'counter': {'packets': 0, 'bytes': 0}}, {'accept': None}]))
        if udp:
            items.append(rule(name, head + [match(payload('udp', 'dport'), {'set': list(udp)} if len(udp) > 1 else udp[0]), {'counter': {'packets': 0, 'bytes': 0}}, {'accept': None}]))
    if final_drop:
        items.append(rule(name, [{'counter': {'packets': 3, 'bytes': 300}}, {'drop': None}]))
    return items


def published(device, addresses, ping, tcp, udp, sources, boot=BOOT):
    return {'interface': device, 'boot_id': boot,
            'settings': {'mode': 'l3', 'addresses': list(addresses),
                         'management': {'profile': 'x', 'ping': ping, 'tcp': list(tcp), 'udp': list(udp), 'sources': list(sources)}}}


MGMT_TCP = [22, 443, 5007, 6080, 6081, 6082, 8443]


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.root = ET.fromstring(CONFIG)
        self.ruleset = {'nftables': [{'metainfo': {'version': '1.1.7'}}]
                        + table_rules('p1', ['184.187.55.66'], ['0.0.0.0/0'], ping=True)
                        + table_rules('p5', ['152.193.185.10'], ['0.0.0.0/0'], ping=True)
                        + table_rules('ae1')
                        + table_rules('ae1.69', ['10.1.0.2'], ping=True, tcp=MGMT_TCP, udp=[161])
                        + [{'table': {'family': 'inet', 'name': 'ffn_security', 'handle': 9}}]}
        self.published = {
            'p1': published('p1', ['184.187.55.66/28'], True, [], [], ['0.0.0.0/0']),
            'p5': published('p5', ['152.193.185.10/32'], True, [], [], ['0.0.0.0/0']),
            'ae1': published('ae1', [], False, [], [], []),
            'ae1.69': published('ae1.69', ['10.1.0.2/22'], True, MGMT_TCP, [161], [])}

    def run_audit(self):
        return audit.audit(self.root, self.ruleset, copy.deepcopy(self.published), BOOT)

    def test_expected_view_uses_the_dataplane_profile_reader_and_address_objects(self):
        view, findings = audit.expected(self.root)
        self.assertEqual(findings, [])
        self.assertEqual(sorted(view), ['ae1', 'ae1.69', 'p1', 'p5'])
        self.assertEqual(view['p5'], dict(interface='ethernet1/5', kind='physical', profile='PING-ONLY', ping=True, tcp=[], udp=[],
                                          sources=['0.0.0.0/0'], addresses=['152.193.185.10/32']))
        self.assertEqual((view['ae1.69']['tcp'], view['ae1.69']['udp'], view['ae1.69']['addresses']), (MGMT_TCP, [161], ['10.1.0.2/22']))
        self.assertEqual((view['ae1']['addresses'], view['ae1']['ping']), ([], False))
        self.assertEqual(audit.device_name('ethernet1/12.80'), 'p12.80');self.assertIsNone(audit.device_name('loopback.1'))

    def test_consistent_views_produce_no_findings(self):
        report = self.run_audit()
        self.assertTrue(report['consistent'], report['findings'])
        self.assertEqual(report['tables'], ['ffn_ifmgmt_ae1', 'ffn_ifmgmt_ae1_69', 'ffn_ifmgmt_p1', 'ffn_ifmgmt_p5'])
        self.assertEqual(report['interfaces']['ae1.69']['findings'], [])

    def test_missing_snmp_rule_is_a_service_finding_and_a_stale_record_when_the_owner_agrees(self):
        # The live table lacks udp 161 and the owner recorded no udp: the apply predates the profile edit.
        def service_udp(item):
            exprs = item.get('rule', {}).get('expr', []) if item.get('rule', {}).get('table') == 'ffn_ifmgmt_ae1_69' else []
            fields = {(e['match']['left'].get('payload', {}).get('protocol'), e['match']['left'].get('payload', {}).get('field')) for e in exprs if 'match' in e}
            return ('udp', 'dport') in fields and ('ip', 'daddr') in fields
        self.ruleset['nftables'] = [i for i in self.ruleset['nftables'] if not service_udp(i)]
        self.published['ae1.69']['settings']['management']['udp'] = []
        report = self.run_audit()
        codes = {(f['code'], f['device']) for f in report['findings']}
        self.assertEqual(codes, {('service-missing', 'ae1.69'), ('published-differs', 'ae1.69')})
        self.assertIn('udp 161 to 10.1.0.2', next(f['detail'] for f in report['findings'] if f['code'] == 'service-missing'))
        self.assertIn('udp', next(f['detail'] for f in report['findings'] if f['code'] == 'published-differs'))
        self.assertEqual(sorted(report['interfaces']['ae1.69']['findings']), ['published-differs', 'service-missing'])

    def test_rule_drift_without_owner_agreement_is_only_a_live_finding(self):
        extra = rule('ffn_ifmgmt_p5', [match(audit_payload('ip', 'daddr'), '152.193.185.10'), match(audit_payload('tcp', 'dport'), 22), {'accept': None}])
        self.ruleset['nftables'].insert(-1, extra)
        report = self.run_audit()
        self.assertEqual([(f['code'], f['detail']) for f in report['findings']], [('service-extra', 'tcp 22 to 152.193.185.10')])

    def test_structural_findings(self):
        self.ruleset['nftables'] = [i for i in self.ruleset['nftables'] if 'ffn_ifmgmt_p1' not in json.dumps(i)]
        self.ruleset['nftables'] += table_rules('p7', ['198.51.100.1'], ping=True)
        self.ruleset['nftables'] = [i for i in self.ruleset['nftables'] if not (
            i.get('rule', {}).get('table') == 'ffn_ifmgmt_ae1' and i['rule']['expr'][-1] == {'drop': None} and len(i['rule']['expr']) == 2)]
        self.published['p5']['boot_id'] = 'older-boot'
        del self.published['ae1']
        self.published['p9'] = published('p9', [], False, [], [], [])
        self.ruleset['nftables'].append(rule('ffn_ifmgmt_p5', [match({'meta': {'key': 'l4proto'}}, 'sctp'), {'accept': None}]))
        report = self.run_audit()
        codes = sorted((f['code'], f.get('device')) for f in report['findings'])
        self.assertEqual(codes, sorted([('table-missing', 'p1'), ('table-unexpected', 'p7'), ('baseline-missing', 'ae1'),
                                        ('published-stale', 'p5'), ('published-missing', 'ae1'), ('published-unexpected', 'p9'),
                                        ('accept-unexpected', 'p5')]))

    def test_configuration_errors_are_findings_not_crashes(self):
        root = ET.fromstring(CONFIG.replace('<interface-management-profile>PING-ONLY</interface-management-profile></layer3><link-speed>',
                                            '<interface-management-profile>GONE</interface-management-profile></layer3><link-speed>')
                             .replace('<entry name="Verizon Enterprise CPE"/></ip>', '<entry name="A range"/></ip>'))
        view, findings = audit.expected(root)
        self.assertNotIn('p5', view)
        self.assertEqual([f['code'] for f in findings], ['profile-missing'])
        root = ET.fromstring(CONFIG.replace('<entry name="Internal LAN GW"/></ip>', '<entry name="A range"/></ip>'))
        view, findings = audit.expected(root)
        self.assertEqual([(f['code'], f['device']) for f in findings], [('address-unresolved', 'ae1.69')])
        self.assertEqual(view['ae1.69']['addresses'], [])

    def test_collection_split_and_record_parsing(self):
        text = (json.dumps(self.ruleset) + audit.SPLIT + '\n/run/ffn-interface-profiles/p5.json\n' + json.dumps(self.published['p5'])
                + '\n\n/run/ffn-interface-profiles/bad.json\nnot json\n' + audit.SPLIT + '\n' + BOOT + '\n')
        ruleset, records, boot = audit.collect(lambda script: text)
        self.assertEqual(boot, BOOT);self.assertEqual(sorted(records), ['p5']);self.assertEqual(len(ruleset['nftables']), len(self.ruleset['nftables']))
        with self.assertRaises(RuntimeError):audit.collect(lambda script: 'garbage')

    def test_cli_exit_status_and_text(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp) / 'running-config.xml';config.write_text(CONFIG)
            ruleset = Path(tmp) / 'ruleset.json';ruleset.write_text(json.dumps(self.ruleset))
            profiles = Path(tmp) / 'profiles.txt'
            profiles.write_text(''.join('/run/x/%s.json\n%s\n\n' % (d, json.dumps(r)) for d, r in self.published.items()))
            import io, contextlib
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                status = audit.main(['--config', str(config), '--ruleset', str(ruleset), '--profiles', str(profiles), '--boot-id', BOOT])
            self.assertEqual(status, 0);self.assertIn('consistent', out.getvalue());self.assertIn('ethernet1/5', out.getvalue())
            self.published['ae1.69']['boot_id'] = 'old'
            profiles.write_text(''.join('/run/x/%s.json\n%s\n\n' % (d, json.dumps(r)) for d, r in self.published.items()))
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                status = audit.main(['--config', str(config), '--ruleset', str(ruleset), '--profiles', str(profiles), '--boot-id', BOOT, '--json'])
            self.assertEqual(status, 1);self.assertEqual(json.loads(out.getvalue())['findings'][0]['code'], 'published-stale')
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                status = audit.main(['--config', str(config / 'missing'), '--ruleset', str(ruleset), '--json'])
            self.assertEqual(status, 2);self.assertIn('error', json.loads(out.getvalue()))


def audit_payload(protocol, field):
    return payload(protocol, field)


if __name__ == '__main__':
    unittest.main()
