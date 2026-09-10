#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Patch lifecycle tests use temporary installations and mocked services only."""
import io
import json
from pathlib import Path
import shutil
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'opt'))
import ffn_patch as p


class PatchTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        self.base, self.source, self.root = [self.dir / n for n in ('base', 'source', 'root')]
        self.base.mkdir()
        (self.base / 'app.py').write_text('VALUE = 1\n')
        (self.base / 'remove.py').write_text('OLD = True\n')
        shutil.copytree(self.base, self.source)
        shutil.copytree(self.base, self.root)
        (self.source / 'app.py').write_text('VALUE = 2\n')
        (self.source / 'remove.py').unlink()
        (self.source / 'new.py').write_text('NEW = True\n')
        self.archive = self.dir / 'update.tgz'
        p.build(self.base, self.source, '2.0-test', self.archive, {})
        self.seed = bytes(range(32))
        self.pub = self.dir / 'update.pub'
        self.pub.write_text(p.payload.ffn_ed25519.publickey(self.seed).hex())
        self.data = self.archive.read_bytes()
        self.meta = {'file': 'patch.tgz', 'version': '2.0-test', 'size': len(self.data),
                     'sha256': p.digest(self.data), 'published': 100, 'notes': 'Test release'}
        self.manifest = {'payloads': {'patch': self.meta}}
        sig, alg = p.payload.sign_manifest(self.manifest, seed=self.seed)
        self.manifest.update(signature=sig, sig_alg=alg)
        self.run = Mock(return_value=Mock(returncode=0))
        self.manager = p.PatchManager(self.root, self.dir / 'state', self.pub, self.run)
        self.sleep = patch.object(p.time, 'sleep')
        self.sleep.start()
        self.addCleanup(self.sleep.stop)

    def stage(self):
        with patch.object(p, 'download', side_effect=[json.dumps(self.manifest).encode(), self.data]):
            self.manager.stage('https://updates.example/ffn', self.meta['sha256'])

    def test_complete_stage_install_rollback(self):
        self.stage()
        self.assertEqual((self.root / 'app.py').read_text(), 'VALUE = 1\n')
        self.manager.install(self.meta['sha256'])
        self.assertEqual((self.root / 'app.py').read_text(), 'VALUE = 2\n')
        self.assertTrue((self.root / 'new.py').exists())
        self.assertFalse((self.root / 'remove.py').exists())
        self.assertTrue(self.manager.status()['rollback_available'])
        self.manager.restore()
        self.assertEqual((self.root / 'app.py').read_text(), 'VALUE = 1\n')
        self.assertFalse((self.root / 'new.py').exists())
        self.assertTrue((self.root / 'remove.py').exists())
        self.assertIsNone(self.manager.status()['installed'])

    def test_signature_failure_and_downgrade_fail_closed(self):
        for manifest in ({}, {**self.manifest, 'signature': '00' * 64}, {**self.manifest, 'sig_alg': 'hmac'}):
            with self.subTest(manifest=manifest), self.assertRaises(p.PatchError):
                self.manager.verify(manifest)
        self.run.assert_not_called()

    def test_package_tamper_and_release_change_rejected(self):
        with self.assertRaises(p.PatchError):
            self.manager.preflight(self.data + b'bad', self.meta)
        with patch.object(p, 'download', return_value=json.dumps(self.manifest).encode()), self.assertRaises(p.PatchError):
            self.manager.stage('https://updates.example', '0' * 64)
        self.run.assert_not_called()

    def test_recheck_baseline_after_stage(self):
        self.stage()
        (self.root / 'app.py').write_text('LOCAL = True\n')
        with self.assertRaisesRegex(p.PatchError, 'baseline'):
            self.manager.install(self.meta['sha256'])
        self.run.assert_not_called()
        self.assertEqual((self.root / 'app.py').read_text(), 'LOCAL = True\n')

    def test_dependency_gate_and_older_release(self):
        p.build(self.base, self.source, '2.0-test', self.archive, {'missing-fixture-package': '1.0'})
        data = self.archive.read_bytes()
        meta = {**self.meta, 'sha256': p.digest(data), 'size': len(data)}
        with self.assertRaisesRegex(p.PatchError, 'dependency'):
            self.manager.preflight(data, meta)
        self.manager._state(installed={'version': 'later', 'published': 101})
        with self.assertRaisesRegex(p.PatchError, 'not newer'):
            self.manager.preflight(self.data, self.meta)

    def test_service_failure_restores_files(self):
        self.stage()
        failed = False
        def service(args, **kwargs):
            nonlocal failed
            if args[1] == 'start' and not failed:
                failed = True
                return Mock(returncode=1)
            return Mock(returncode=0)
        self.run.side_effect = service
        with self.assertRaisesRegex(p.PatchError, 'previous files and services restored'):
            self.manager.install(self.meta['sha256'])
        self.assertEqual((self.root / 'app.py').read_text(), 'VALUE = 1\n')
        self.assertFalse((self.root / 'new.py').exists())
        self.assertFalse(self.manager.status()['recovery_required'])

    def test_power_loss_retains_journal_and_recovers(self):
        self.stage()
        real_atomic = p.atomic
        def interrupted(path, data, mode=0o600):
            if Path(path) == self.manager.root / 'new.py':
                raise KeyboardInterrupt('simulated power loss')
            real_atomic(path, data, mode)
        with patch.object(p, 'atomic', side_effect=interrupted), self.assertRaises(KeyboardInterrupt):
            self.manager.install(self.meta['sha256'])
        self.assertTrue(self.manager.status()['recovery_required'])
        self.manager.restore(check_current=False)
        self.assertEqual((self.root / 'app.py').read_text(), 'VALUE = 1\n')
        self.assertFalse(self.manager.status()['recovery_required'])

    def test_rollback_refuses_local_changes_and_damaged_backup(self):
        self.stage()
        self.manager.install(self.meta['sha256'])
        (self.root / 'app.py').write_text('LOCAL = True\n')
        self.run.reset_mock()
        with self.assertRaisesRegex(p.PatchError, 'Local changes'):
            self.manager.restore()
        self.run.assert_not_called()
        (self.root / 'app.py').write_text('VALUE = 2\n')
        journal = p.read(self.manager.state / 'journal.json')
        (self.manager.state / journal['backup'] / 'app.py').write_text('tampered')
        with self.assertRaisesRegex(p.PatchError, 'damaged'):
            self.manager.restore()
        self.run.assert_not_called()

    def test_archive_rejects_links_paths_duplicates_and_expansion(self):
        for name, kind in [('../escape.py', tarfile.REGTYPE), ('files/app.py', tarfile.SYMTYPE),
                           ('files/app.py', tarfile.LNKTYPE), ('files/venv/site.py', tarfile.REGTYPE)]:
            out = io.BytesIO()
            with tarfile.open(fileobj=out, mode='w:gz') as archive:
                info = tarfile.TarInfo(name)
                info.type = kind
                info.linkname = '/etc/passwd'
                archive.addfile(info)
            with self.subTest(name=name, kind=kind), self.assertRaises(p.PatchError):
                p.unpack(out.getvalue())
        with patch.object(p, 'MAX_BYTES', 1), self.assertRaises(p.PatchError):
            p.unpack(self.data)

    def test_symlink_install_target_rejected(self):
        with patch.object(p.os.path, 'islink', return_value=True), self.assertRaises(p.PatchError):
            self.manager.preflight(self.data, self.meta)

    def test_https_only(self):
        for url in ('http://example.com', 'file:///tmp/patch', 'https://user:pass@example.com', 'https://example.com\nurl=x'):
            with self.subTest(url=url), self.assertRaises(p.PatchError):
                p.server_url(url)

    def test_repository_layout_maps_python_to_flat_installation(self):
        repo = self.dir / 'repo'
        (repo / 'opt').mkdir(parents=True)
        for file in self.source.glob('*.py'):
            shutil.copy2(file, repo / 'opt' / file.name)
        p.build(self.base, repo, '2.0-test', self.archive, {})
        package = p.unpack(self.archive.read_bytes())
        self.assertEqual({e['path'] for e in package['files']}, {'app.py', 'new.py', 'remove.py'})

    def test_full_software_update_cannot_race_a_patch_job(self):
        with patch.object(p, 'PatchManager', return_value=self.manager), \
             patch.object(p.payload, '_apply_payload') as install:
            self.manager.submit('check', 'admin', 'https://updates.example')
            self.assertEqual(p.payload.apply_payload('software', 'unused', {}), 1)
            install.assert_not_called()

    def test_state_inside_installation_rejected(self):
        with self.assertRaises(p.PatchError):
            p.PatchManager(self.root, self.root / 'patch-state', self.pub)

    def test_job_launch_lock_and_history(self):
        job = self.manager.submit('check', 'admin', 'https://updates.example')
        command = self.run.call_args.args[0]
        self.assertEqual(command[0], 'systemd-run')
        self.assertIn('--unit=ffn-patch-' + job['id'], command)
        with self.assertRaises(p.PatchError):
            self.manager.submit('check', 'admin', 'https://updates.example')
        with patch.object(p, 'download', return_value=json.dumps(self.manifest).encode()):
            self.assertEqual(self.manager.worker(job['id']), 0)
        self.assertEqual(self.manager.status()['history'][0]['actor'], 'admin')
        self.assertEqual(self.manager.status()['job']['status'], 'succeeded')

    def test_failed_launch_is_not_left_pending(self):
        self.run.return_value.returncode = 1
        with self.assertRaises(p.PatchError):
            self.manager.submit('check', 'admin', 'https://updates.example')
        self.assertEqual(self.manager.status()['job']['status'], 'failed')

    def test_independent_process_lock(self):
        with p.lock(self.manager.state), self.assertRaises(p.PatchError):
            with p.lock(self.manager.state):
                self.fail('acquired lock twice')


if __name__ == '__main__':
    unittest.main()
