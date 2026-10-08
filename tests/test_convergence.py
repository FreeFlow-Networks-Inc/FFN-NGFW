import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'opt'))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import ffn_convergence as conv

MP_BOOT = '783e20f6-188f-4b93-aebd-7bb954586da6'
BOOTS = {'cp': '877ebc14-cp', 'dp': '9fed3cf5-dp'}
CONFIG = '''<config><devices><entry name="localhost.localdomain">
<network><interface>
 <ethernet>
  <entry name="ethernet1/1"><layer3><ip><entry name="184.187.55.66/28"/></ip></layer3></entry>
  <entry name="ethernet1/5"><layer3><ip><entry name="152.193.185.10/32"/></ip></layer3><link-speed>1000</link-speed></entry>
  <entry name="ethernet1/9"><aggregate-group>ae1</aggregate-group></entry>
  <entry name="ethernet1/10"><aggregate-group>ae1</aggregate-group><link-state>down</link-state></entry>
  <entry name="ethernet1/12"><layer3/><link-state>down</link-state></entry>
  <entry name="ethernet1/13"/>
 </ethernet>
 <aggregate-ethernet><entry name="ae1"><layer3><units><entry name="ae1.69"><tag>69</tag></entry></units></layer3></entry></aggregate-ethernet>
</interface></network></entry></devices></config>'''


def port(number, enabled=True, speed='auto', media='sfp', link=True, module=None, available=True, speed_configuration=True):
    return dict(port=number, name='ethernet1/%d' % number, available=available, enabled=enabled, configured_speed=speed,
                media=media, link=link, module=module, speed_configuration=speed_configuration,
                optics=dict(present=True, tx_enabled=bool(enabled)) if media == 'sfp' else None)


HEALTHY = {'pid': 769, 'process_start': '3230', 'boot_id': 'dp-boot', 'monotonic': 500.0, 'collector_ready': True,
           'forwarding_revision': 9, 'error': None, 'events': {'ready': True, 'error': None, 'recoveries': 1}}


class ConvergenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.config = self.root / 'running-config.xml'; self.config.write_text(CONFIG)
        self.generation = hashlib.sha256(self.config.read_bytes()).hexdigest()
        self.boot = self.root / 'boot_id'; self.boot.write_text(MP_BOOT + '\n')
        self.journal = self.root / 'mp.json'; self.journal.write_text(json.dumps({'processor_boots': BOOTS}))
        self.receipt = self.root / 'reconcile-result.json'
        self.receipt.write_text(json.dumps(dict(version=1, mp_boot_id=MP_BOOT, processor_boots=BOOTS, state='applied',
                                                config_sha256=self.generation, apply={'overall': 'applied', 'errors': []})))
        self.health = lambda: (dict(HEALTHY), 505.0, 'dp-boot')
        self.faceplate = {'revision': 1, 'ports': [
            port(1, media='copper', speed='auto'), port(5, speed='1000', module=dict(optical=True, speeds=[1000])),
            port(9, speed='10000'), port(10, enabled=False, speed='10000'), port(12, enabled=False), port(13, enabled=False)]}
        self.aggregates = {'aggregates': [dict(ae_name='ae1', applied=True, state='active', committed=True, blockers=[])]}

    def run_assess(self, **kw):
        kw.setdefault('resources', {('faceplate', 'status'): self.faceplate, ('aggregates', 'status'): self.aggregates})
        kw.setdefault('dp_views', None)
        return conv.assess(self.config, self.receipt, (self.journal,), self.boot, kw.pop('dp_health', self.health), clock=lambda: 1010.0, **kw)

    def states(self, report):
        return {s['id']: s['state'] for s in report['subsystems']}

    def dataplane_views(self):
        from test_ifmgmt_audit import table_rules, published
        ruleset = {'nftables': table_rules('p1') + table_rules('p5') + table_rules('p12') + table_rules('ae1') + table_rules('ae1.69')}
        records = {'p1': published('p1', ['184.187.55.66/28'], False, [], [], [], boot='dp-boot'),
                   'p5': published('p5', ['152.193.185.10/32'], False, [], [], [], boot='dp-boot'),
                   'p12': published('p12', [], False, [], [], [], boot='dp-boot'),
                   'ae1': published('ae1', [], False, [], [], [], boot='dp-boot'),
                   'ae1.69': published('ae1.69', [], False, [], [], [], boot='dp-boot')}
        return ruleset, records, 'dp-boot'

    def test_everything_converged(self):
        # Without a dataplane relay the audit is unobservable, and that is the overall state.
        report = self.run_assess()
        self.assertEqual(self.states(report), {'committed-replay': 'converged', 'faceplate': 'converged', 'aggregates': 'converged',
                                               'interface-management': 'unavailable', 'security-runtime': 'converged'})
        self.assertEqual(report['overall'], 'unavailable'); self.assertEqual(report['actions'], [])
        self.assertEqual(report['generation'], self.generation)
        self.assertEqual({s['id']: s for s in report['subsystems']}['faceplate']['summary'], '5 configured front port(s) match')
        report = self.run_assess(dp_views=self.dataplane_views)
        self.assertEqual(report['overall'], 'converged', report['subsystems'])
        self.assertEqual({s['id']: s for s in report['subsystems']}['interface-management']['summary'], '5 managed interface(s) enforced as committed')

    def test_replay_receipt_states(self):
        cases = [
            (None, 'pending', 'No replay receipt'),
            (dict(mp_boot_id='other', processor_boots=BOOTS, state='applied'), 'pending', 'previous MP boot'),
            (dict(mp_boot_id=MP_BOOT, processor_boots={'cp': 'new', 'dp': BOOTS['dp']}, state='applied'), 'pending', 'booted after'),
            (dict(mp_boot_id=MP_BOOT, processor_boots=BOOTS, state='applying'), 'pending', 'in progress'),
            (dict(mp_boot_id=MP_BOOT, processor_boots=BOOTS, state='failed', reason='board not ready', apply={'errors': ['x']}), 'failed', 'board not ready'),
            (dict(mp_boot_id=MP_BOOT, processor_boots=BOOTS, state='applied', config_sha256='0' * 64), 'drift', 'changed since the replay'),
            (dict(mp_boot_id=MP_BOOT, processor_boots=BOOTS, state='applied', config_sha256=self.generation, apply={'errors': ['nat: failed']}), 'failed', 'with errors'),
        ]
        for receipt, state, text in cases:
            with self.subTest(text=text):
                result = conv.replay(receipt, MP_BOOT, BOOTS, self.generation)
                self.assertEqual(result['state'], state); self.assertIn(text, result['summary'])
        self.assertEqual(conv.replay(dict(mp_boot_id=MP_BOOT, processor_boots=BOOTS, state='applied', config_sha256=self.generation,
                                          apply={'errors': []}), MP_BOOT, None, self.generation)['state'], 'converged')

    def test_faceplate_expectations_follow_layer3_members_and_link_state(self):
        from xml.etree import ElementTree as ET
        expected = conv.faceplate_expectations(ET.fromstring(CONFIG))
        self.assertEqual({p: (w['enabled'], w['speed'], w['member']) for p, w in expected.items() if w['configured']},
                         {1: (True, 'auto', False), 5: (True, '1000', False), 9: (True, 'auto', True), 10: (False, 'auto', True), 12: (False, 'auto', False)})
        self.assertFalse(expected[13]['configured'])

    def test_faceplate_drift_pending_and_the_clause37_readback_allowance(self):
        from xml.etree import ElementTree as ET
        root = ET.fromstring(CONFIG)
        self.faceplate['ports'][1]['configured_speed'] = 'auto'   # 1000BASE-X with Clause 37 on the pre-restart daemon
        self.assertEqual(conv.faceplate(root, self.faceplate)['state'], 'converged')
        self.faceplate['ports'][1]['module'] = dict(optical=True, speeds=[1000, 10000])
        result = conv.faceplate(root, self.faceplate)
        self.assertEqual(result['state'], 'drift'); self.assertIn('ethernet1/5: speed auto, committed 1000', result['details'])
        self.faceplate['ports'][1].update(configured_speed='1000', module=None, enabled=False)
        result = conv.faceplate(root, self.faceplate)
        self.assertEqual(result['state'], 'drift'); self.assertEqual(result['details'], ['ethernet1/5: disabled, committed enabled'])
        self.faceplate['ports'][1].update(enabled=True, link=False)
        result = conv.faceplate(root, self.faceplate)
        self.assertEqual((result['state'], result['details']), ('converged', ['ethernet1/5: enabled, link down']))
        self.faceplate['ports'][0]['available'] = False
        self.assertEqual(conv.faceplate(root, self.faceplate)['state'], 'pending')
        # An SFP cage whose I2C read failed this time carries no optics: no judgement, pending.
        self.faceplate['ports'][0]['available'] = True
        self.faceplate['ports'][1].update(optics=None, module=None, enabled=None, configured_speed='auto')
        result = conv.faceplate(root, self.faceplate)
        self.assertEqual(result['state'], 'pending'); self.assertIn('ethernet1/5: SFP cage state not observable', result['details'])
        self.assertEqual(conv.faceplate(root, {'error': 'controld down'})['state'], 'unavailable')
        self.assertEqual(conv.faceplate(root, None)['state'], 'unavailable')

    def test_aggregates_states(self):
        from xml.etree import ElementTree as ET
        root = ET.fromstring(CONFIG)
        self.assertEqual(conv.aggregates(root, self.aggregates)['state'], 'converged')
        self.aggregates['aggregates'][0].update(applied=False, state='negotiating', blockers=[dict(code='negotiating', message='No members are distributing')])
        result = conv.aggregates(root, self.aggregates)
        self.assertEqual(result['state'], 'pending'); self.assertIn('ae1: negotiating; No members are distributing', result['details'])
        self.aggregates['aggregates'][0].update(state='active', blockers=[dict(code='network-apply', message='address failed')])
        self.assertEqual(conv.aggregates(root, self.aggregates)['state'], 'drift')
        self.assertEqual(conv.aggregates(root, {'aggregates': []})['state'], 'pending')
        self.assertEqual(conv.aggregates(root, None)['state'], 'unavailable')
        self.assertEqual(conv.aggregates(ET.fromstring(CONFIG.replace('<aggregate-ethernet>', '<x>').replace('</aggregate-ethernet>', '</x>')), None)['state'], 'converged')

    def test_interface_management_uses_the_audit(self):
        from xml.etree import ElementTree as ET
        root = ET.fromstring(CONFIG)
        self.assertEqual(conv.interface_management(root, None)['state'], 'unavailable')
        ruleset = {'nftables': []}
        result = conv.interface_management(root, (ruleset, {}, 'boot'))
        self.assertEqual(result['state'], 'pending', result)   # tables missing, records missing: not yet applied
        self.assertIn('table-missing', result['summary'])
        report = self.run_assess(dp_views=lambda: (ruleset, {}, 'boot'))
        self.assertEqual(self.states(report)['interface-management'], 'pending'); self.assertEqual(report['overall'], 'pending')
        report = self.run_assess(dp_views=lambda: (_ for _ in ()).throw(RuntimeError('relay down')))
        self.assertEqual(self.states(report)['interface-management'], 'unavailable')

    def test_security_runtime_states(self):
        self.assertEqual(conv.security_runtime(None, 505.0, 'dp-boot')['state'], 'unavailable')
        healthy = conv.security_runtime(dict(HEALTHY), 505.0, 'dp-boot')
        self.assertEqual((healthy['state'], healthy['plane'], healthy['details']), ('converged', 'dp', ['forwarding revision 9']))
        self.assertEqual(conv.security_runtime(dict(HEALTHY), 505.0, 'other-boot')['state'], 'pending')
        self.assertEqual(conv.security_runtime(dict(HEALTHY), 500.0 + conv.HEALTH_FRESH_SECONDS + 1, 'dp-boot')['state'], 'pending')
        self.assertEqual(conv.security_runtime(dict(HEALTHY, collector_ready=False), 505.0, 'dp-boot')['state'], 'pending')
        self.assertEqual(conv.security_runtime(dict(HEALTHY, error='collector died'), 505.0, 'dp-boot')['state'], 'failed')
        self.assertEqual(conv.security_runtime(dict(HEALTHY, events=dict(ready=True, error='socket lost')), 505.0, 'dp-boot')['state'], 'failed')
        self.assertEqual(conv.security_runtime(dict(HEALTHY, monotonic=None), 505.0, 'dp-boot')['state'], 'pending')

    def test_health_collection_is_parsed_from_one_dataplane_round_trip(self):
        output = json.dumps(HEALTHY) + '\n' + conv.HEALTH_SPLIT + '\n20489.47 799386.79\ndp-boot\n'
        self.assertEqual(conv.parse_health(output), (HEALTHY, 20489.47, 'dp-boot'))
        self.assertEqual(conv.parse_health(conv.HEALTH_SPLIT + '\n20489.47 799386.79\ndp-boot\n'), (None, 20489.47, 'dp-boot'))
        with self.assertRaises(ValueError):
            conv.parse_health('no marker at all')
        with self.assertRaises(ValueError):
            conv.parse_health(conv.HEALTH_SPLIT + '\n')
        failing = self.run_assess(dp_health=lambda: (_ for _ in ()).throw(OSError('ssh: connect failed')))
        state = {s['id']: s['state'] for s in failing['subsystems']}
        self.assertEqual(state['security-runtime'], 'unavailable')

    def test_management_access_states(self):
        ready = dict(channel_ready=True, services=[dict(interface='ae1.69', protocol='tcp', port=443, provider_listening=True, state='ready')])
        self.assertEqual(conv.management_access('active', ready, 1)['state'], 'converged')
        self.assertEqual(conv.management_access(None, ready, 1)['state'], 'unavailable')
        result = conv.management_access('inactive', ready, 1)
        self.assertEqual(result['state'], 'drift'); self.assertIn('start ' + conv.TUNNEL_UNIT, result['details'][1])
        self.assertEqual(conv.management_access('active', None, 1)['state'], 'unavailable')
        self.assertEqual(conv.management_access('active', dict(ready, channel_ready=False), 1)['state'], 'pending')
        waiting = dict(channel_ready=True, services=[dict(interface='ae1.69', protocol='tcp', port=443, provider_listening=False, state='listening-provider-unverified')])
        result = conv.management_access('active', waiting, 1)
        self.assertEqual(result['state'], 'pending'); self.assertEqual(result['details'], ['ae1.69 tcp/443: listening-provider-unverified'])
        # Services the appliance does not provide (user-id, SNMP) are notes, not a pending convergence.
        extras = dict(channel_ready=True, services=ready['services'] + [
            dict(interface='ae1.69', protocol='tcp', port=5007, provider_listening=False, state='listening-provider-unverified'),
            dict(interface='ae1.69', protocol='udp', port=161, provider_listening=False, state='listening-provider-unverified')])
        result = conv.management_access('active', extras, 1)
        self.assertEqual((result['state'], result['summary']), ('converged', '1 profile listener(s) reach the manager'))
        self.assertEqual(result['details'], ['ae1.69 tcp/5007: no provider on this appliance', 'ae1.69 udp/161: no provider on this appliance'])
        report = self.run_assess(dp_views=self.dataplane_views, tunnel=lambda: 'inactive', dp_status=lambda: ready)
        self.assertEqual(report['overall'], 'drift'); self.assertIn('reapply', report['actions'])
        def broken():
            raise OSError('ssh')
        report = self.run_assess(dp_views=self.dataplane_views, tunnel=lambda: 'active', dp_status=broken)
        self.assertEqual(self.states(report)['management-access'], 'unavailable')
        report = self.run_assess(dp_views=self.dataplane_views, tunnel=lambda: 'active', dp_status=lambda: ready)
        self.assertEqual(report['overall'], 'converged')
        calls = []
        def run(argv, **kw):
            calls.append(argv); return type('R', (), {'returncode': 0, 'stdout': 'active' + chr(10), 'stderr': ''})()
        self.assertEqual(conv.unit_active(run=run), 'active'); self.assertEqual(calls[0], ['systemctl', 'is-active', conv.TUNNEL_UNIT])
        def missing(*a, **k):
            raise OSError('no systemctl')
        self.assertIsNone(conv.unit_active(run=missing))

    def test_overall_rank_and_actions(self):
        self.receipt.write_text(json.dumps(dict(mp_boot_id=MP_BOOT, processor_boots=BOOTS, state='applied', config_sha256='1' * 64)))
        report = self.run_assess()
        self.assertEqual(report['overall'], 'drift'); self.assertEqual(report['actions'], ['reapply'])
        self.config.write_text('not xml')
        report = self.run_assess()
        self.assertEqual(report['overall'], 'unavailable'); self.assertIsNone(report['generation'])

    def test_reapply_starts_the_replay_unit_only_for_matching_boots(self):
        request = self.root / 'reconcile-request.json'
        calls = []
        def run(argv, **kw):
            calls.append(argv); return type('R', (), {'returncode': 0, 'stdout': '', 'stderr': ''})()
        self.assertFalse(conv.reapply(request, (self.journal,), self.boot, run=run)['started'])
        request.write_text(json.dumps(dict(version=1, mp_boot_id='other', processor_boots=BOOTS)))
        self.assertFalse(conv.reapply(request, (self.journal,), self.boot, run=run)['started'])
        request.write_text(json.dumps(dict(version=1, mp_boot_id=MP_BOOT, processor_boots={'cp': 'x', 'dp': 'y'})))
        self.assertIn('other CP/DP boots', conv.reapply(request, (self.journal,), self.boot, run=run)['reason'])
        request.write_text(json.dumps(dict(version=1, mp_boot_id=MP_BOOT, processor_boots=BOOTS)))
        result = conv.reapply(request, (self.journal,), self.boot, run=run)
        self.assertTrue(result['started']); self.assertEqual(calls[-1], ['systemctl', 'start', '--no-block', conv.REPLAY_UNIT])
        self.assertEqual(calls.count(calls[-1]), 1)
        def failing(argv, **kw): return type('R', (), {'returncode': 1, 'stdout': '', 'stderr': 'Unit not found'})()
        self.assertEqual(conv.reapply(request, (self.journal,), self.boot, run=failing)['reason'], 'Unit not found')


if __name__ == '__main__':
    unittest.main()
