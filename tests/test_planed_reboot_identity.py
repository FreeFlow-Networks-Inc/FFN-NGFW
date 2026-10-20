"""A plane rebooted on purpose supersedes the writes bound to its old boot identity.

The restart owner leaves a reboot flag naming the identity it replaced; the plane
daemon then reconciles an unknown row bound to that identity against the live
status instead of blocking every later write on the resource.
"""
import asyncio
import json
from pathlib import Path
import sys
import tempfile
import unittest
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'opt'))
import ffn_planed as planed  # noqa: E402


def request(action, payload):
    return {'v': 1, 'id': str(uuid.uuid4()), 'resource': 'wan-path', 'action': action, 'payload': payload}


class RebootIdentity(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.identity = 'boot-b'
        self.applied = []

        async def runner(argv, payload, timeout):
            action = argv[-1]
            if action == 'status':
                return {'state': {'dp_boot_id': self.identity, 'enabled': True}, 'config': {'revision': 7},
                        'attachment': {'attachment': {'boot_id': self.identity}}}
            if action == 'validate':
                return {}
            if action == 'apply':
                self.applied.append(json.loads(payload))
                return {'applied': True}
            raise AssertionError(action)
        config = {'role': 'mp', 'commands': {'wan-path': {a: [sys.executable, a] for a in ('status', 'validate', 'apply')}}}
        self.plane = planed.Plane(config, self.root / 'requests.db', runner=runner)

    def unknown_row(self, payload):
        intent = request('apply', payload)
        pending = self.plane.response(intent, 'unknown', error='Apply interrupted or incomplete; reconcile runtime state')
        self.plane.db.execute('INSERT INTO requests VALUES(?,?,?,?,?,?)',
                              (intent['id'], 'digest', 'wan-path', planed.encode(pending).decode(), 'unknown', planed.encode(intent).decode()))
        self.plane.db.commit()
        return intent['id']

    def flag(self, before, name='dp.json'):
        flags = self.root / 'reboots'
        flags.mkdir(exist_ok=True)
        (flags / name).write_text(json.dumps({'plane': 'dp', 'boot_id_before': before, 'requested_at': 1, 'by': 'test'}))

    def apply(self):
        return asyncio.run(self.plane.dispatch(request('apply', {'revision': 7, 'operation': 'attach', 'expected_boot_id': self.identity})))

    def row(self, ident):
        state, response = self.plane.db.execute('SELECT state, response FROM requests WHERE id=?', (ident,)).fetchone()
        return state, json.loads(response)

    def test_without_a_reboot_flag_the_row_keeps_blocking(self):
        ident = self.unknown_row({'revision': 6, 'operation': 'attach', 'expected_boot_id': 'boot-a'})
        answer = self.apply()
        self.assertEqual(answer['state'], 'rejected')
        self.assertIn('unknown outcome', answer['error'])
        self.assertEqual(self.row(ident)[0], 'unknown')
        self.assertEqual(self.applied, [])

    def test_a_flagged_reboot_supersedes_rows_bound_to_the_old_identity(self):
        ident = self.unknown_row({'revision': 6, 'operation': 'attach', 'expected_boot_id': 'boot-a'})
        self.flag('boot-a')
        answer = self.apply()
        self.assertTrue(answer['ok'], answer)
        self.assertEqual(len(self.applied), 1)
        state, response = self.row(ident)
        self.assertEqual(state, 'reconciled')
        self.assertEqual((response['state'], response['result']['observed_revision'], response['result']['superseded_by'],
                          response['result']['reboot_flag']), ('reconciled', 7, 'boot-b', 'dp.json'))

    def test_the_flag_must_name_the_identity_the_row_was_bound_to(self):
        ident = self.unknown_row({'revision': 6, 'operation': 'attach', 'expected_boot_id': 'boot-a'})
        self.flag('boot-x')
        self.assertEqual(self.apply()['state'], 'rejected')
        self.assertEqual(self.row(ident)[0], 'unknown')

    def test_no_identity_change_means_no_supersession(self):
        ident = self.unknown_row({'revision': 6, 'operation': 'attach', 'expected_boot_id': 'boot-b'})
        self.flag('boot-b')
        self.assertEqual(self.apply()['state'], 'rejected')
        self.assertEqual(self.row(ident)[0], 'unknown')

    def test_a_row_bound_to_no_identity_still_needs_a_hand(self):
        ident = self.unknown_row({'revision': 6, 'operation': 'attach'})
        self.flag('boot-a')
        self.assertEqual(self.apply()['state'], 'rejected')
        self.assertEqual(self.row(ident)[0], 'unknown')

    def test_only_the_superseded_rows_are_reconciled(self):
        old = self.unknown_row({'revision': 5, 'operation': 'attach', 'expected_boot_id': 'boot-a'})
        bare = self.unknown_row({'revision': 6, 'operation': 'attach'})
        self.flag('boot-a')
        self.assertEqual(self.apply()['state'], 'rejected')
        self.assertEqual((self.row(old)[0], self.row(bare)[0]), ('reconciled', 'unknown'))

    def test_observed_identity_is_found_where_controllers_keep_it(self):
        find = planed.Plane.observed_identity
        self.assertEqual(find({'state': {'dp_boot_id': 'x'}}), 'x')
        self.assertEqual(find({'attachment': {'attachment': {'boot_id': 'y'}}}), 'y')
        self.assertEqual(find({'boot_id': 'z'}), 'z')
        self.assertIsNone(find({'config': {'revision': 1}}))

    def test_the_description_still_lists_a_blocked_row(self):
        self.unknown_row({'revision': 6, 'operation': 'attach', 'expected_boot_id': 'boot-a'})
        self.assertEqual(self.plane.describe()['resources']['wan-path']['blocked_total'], 1)


if __name__ == '__main__':
    unittest.main()
