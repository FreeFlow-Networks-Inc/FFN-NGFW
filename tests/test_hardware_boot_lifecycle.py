"""hardware-boot status falls back to the lifecycle supervisor's view."""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'opt'))
import ffn_hardware_boot as hb  # noqa: E402


class LifecycleFallback(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        base = Path(self.dir.name)
        self.boot = base / 'boot_id'; self.boot.write_text('11111111-1111-4111-8111-111111111111\n')
        self.state = base / 'state.json'          # the manifest worker's file: absent
        self.life = base / 'mp.json'

    def tearDown(self):
        self.dir.cleanup()

    def snapshot(self, **over):
        d = {'version': 1, 'role': 'mp', 'running': True, 'boot_id': '11111111-1111-4111-8111-111111111111',
             'boot_profile': 'native', 'ready': False, 'board_ready': False,
             'processor_boots': {'cp': 'c', 'dp': 'd'},
             'stages': {'processors': {'ready': True, 'state': 'ready'},
                        'board': {'ready': False, 'state': 'waiting', 'reason': 'CP board-agent readiness'},
                        'configuration': {'ready': False, 'state': 'blocked', 'reason': 'earlier startup stage is not ready'}}}
        d.update(over); self.life.write_text(json.dumps(d)); return d

    def test_no_state_no_supervisor_is_unavailable(self):
        self.assertEqual(hb.status(path=self.state, boot_path=self.boot, lifecycle=self.life)['phase'], 'unavailable')

    def test_supervisor_starting(self):
        self.snapshot()
        s = hb.status(path=self.state, boot_path=self.boot, lifecycle=self.life)
        self.assertEqual((s['phase'], s['hardware_ready'], s['source'], s['current_step']), ('starting', False, 'lifecycle', 'board'))
        self.assertIn('board: CP board-agent readiness', s['waiting_for'])

    def test_supervisor_ready(self):
        self.snapshot(ready=True, board_ready=True, stages={'processors': {'ready': True}, 'board': {'ready': True}, 'configuration': {'ready': True}})
        s = hb.status(path=self.state, boot_path=self.boot, lifecycle=self.life)
        self.assertEqual((s['phase'], s['hardware_ready']), ('ready', True))
        self.assertNotIn('waiting_for', s)

    def test_supervisor_failed_stage(self):
        self.snapshot(board_ready=True, stages={'processors': {'ready': True}, 'board': {'ready': True},
                                                'configuration': {'ready': False, 'state': 'failed', 'reason': 'replay failed'}})
        s = hb.status(path=self.state, boot_path=self.boot, lifecycle=self.life)
        self.assertEqual((s['phase'], s['hardware_ready']), ('failed', True))
        self.assertIn('configuration', s['error'])

    def test_other_boot_or_stopped_supervisor_is_ignored(self):
        self.snapshot(boot_id='22222222-2222-4222-8222-222222222222')
        self.assertEqual(hb.status(path=self.state, boot_path=self.boot, lifecycle=self.life)['phase'], 'unavailable')
        self.snapshot(running=False)
        self.assertEqual(hb.status(path=self.state, boot_path=self.boot, lifecycle=self.life)['phase'], 'unavailable')

    def test_manifest_worker_state_wins(self):
        self.snapshot(ready=True, board_ready=True)
        self.state.write_text(json.dumps({'mp_boot_id': '11111111-1111-4111-8111-111111111111', 'phase': 'starting', 'owner': 'mp'}))
        self.assertEqual(hb.status(path=self.state, boot_path=self.boot, lifecycle=self.life)['phase'], 'starting')


if __name__ == '__main__':
    unittest.main()
