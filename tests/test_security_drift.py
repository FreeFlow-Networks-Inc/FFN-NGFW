"""The security runtime replays the policy only on confirmed drift, never on one transient read."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'opt'))
import ffn_security_runtime as runtime


STATE = dict(boot_id='boot-1', bindings={'ethernet1/5': {'device': 'p5', 'index': 8, 'alias': ''},
                                        'ae1.69': {'device': 'ae1.69', 'index': 37, 'alias': 'ffn-aggregate:t:ae1.69'}},
             tables=[['inet', 'ffn_security'], ['ip', 'ffn_nat']], kernel_digest='digest-1')


class Drift(unittest.TestCase):
    def helper(self, bindings_reads, digests=None, boots=None):
        calls = dict(bindings=0, inventory=0, sleeps=[])
        digests = digests or ['digest-1'] * 10
        def read_bindings():
            value = bindings_reads[min(calls['bindings'], len(bindings_reads) - 1)]; calls['bindings'] += 1; return value
        def read_inventory():
            calls['inventory'] += 1; return {'nftables': []}
        fingerprint = runtime.fingerprint
        runtime.fingerprint = lambda data, tables: digests[min(calls['inventory'] - 1, len(digests) - 1)]
        self.addCleanup(setattr, runtime, 'fingerprint', fingerprint)
        reason = runtime.drift(STATE, reads=3, delay=0.5, read_bindings=read_bindings, read_inventory=read_inventory,
                               read_boot=lambda: (boots or ['boot-1'])[0], sleep=calls['sleeps'].append)
        return reason, calls

    def test_a_stable_dataplane_is_not_drift_and_costs_one_read(self):
        reason, calls = self.helper([STATE['bindings']])
        self.assertIsNone(reason)
        self.assertEqual((calls['bindings'], calls['inventory'], calls['sleeps']), (1, 1, []))

    def test_an_interface_missing_for_one_read_is_not_drift(self):
        transient = {k: v for k, v in STATE['bindings'].items() if k != 'ethernet1/5'}
        reason, calls = self.helper([transient, STATE['bindings']])
        self.assertIsNone(reason)
        self.assertEqual(calls['sleeps'], [0.5])

    def test_a_persistent_binding_change_is_drift_with_the_names_in_the_reason(self):
        changed = dict(STATE['bindings'], **{'ae1.69': dict(STATE['bindings']['ae1.69'], index=41)})
        changed.pop('ethernet1/5')
        reason, calls = self.helper([changed])
        self.assertEqual(reason, "interface bindings differ (missing ['ethernet1/5'], new [], changed ['ae1.69'])")
        self.assertEqual((calls['bindings'], calls['sleeps']), (3, [0.5, 0.5]))

    def test_a_ruleset_change_must_also_persist(self):
        reason, _ = self.helper([STATE['bindings']], digests=['other', 'digest-1'])
        self.assertIsNone(reason)
        reason, calls = self.helper([STATE['bindings']], digests=['other'])
        self.assertEqual(reason, 'kernel ruleset differs from the applied generation')
        self.assertEqual(calls['inventory'], 3)

    def test_a_boot_change_is_immediate(self):
        reason, calls = self.helper([STATE['bindings']], boots=['boot-2'])
        self.assertEqual(reason, 'dataplane boot identity changed')
        self.assertEqual(calls['bindings'], 0)


if __name__ == '__main__':
    unittest.main()
