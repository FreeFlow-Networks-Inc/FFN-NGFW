#!/usr/bin/env python3
"""Regression tests for the management API's untrusted input boundaries."""
import asyncio
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

_tmp = tempfile.TemporaryDirectory(prefix="ffn-security-")
os.environ["FFN_DB_PATH"] = str(Path(_tmp.name) / "config.db")
os.environ["FFN_CONFIG_DIR"] = str(Path(_tmp.name) / "config")
os.environ["FFN_JWT_SECRET"] = "security-test-only-signing-secret"
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "opt"))
import ffn_manager as m


class ManagerSecurityTests(unittest.TestCase):
    def test_nft_output_contains_interface_names_not_relay_credentials(self):
        from ffn_bmfw import DataplaneConfig, NftGenerator
        cfg = DataplaneConfig.from_dict({'trusted_ifaces': ['backplane0'],
            'crucible_relay_token': 'test-credential-must-not-appear'})
        rendered = NftGenerator(cfg).render()
        self.assertIn('backplane0', rendered)
        self.assertNotIn('test-credential-must-not-appear', rendered)

    def test_xml_entities_and_dtd_rejected_without_changing_candidate(self):
        original = m.CANDIDATE_CONFIG.read_bytes()
        for xml in (
            '<!DOCTYPE x [<!ENTITY a "expanded">]><x>&a;</x>',
            '<!DOCTYPE x [<!ENTITY a SYSTEM "file:///etc/passwd">]><x>&a;</x>',
            '<!DOCTYPE x SYSTEM "https://example.invalid/schema.dtd"><x/>',
            '<x>', '<x>' + 'a' * (1024 * 1024) + '</x>',
        ):
            with self.subTest(xml=xml[:60]):
                result = m.config_mgr.update_candidate('config.security-test', xml, 'test')
                self.assertEqual(result['status'], 'error')
                self.assertEqual(m.CANDIDATE_CONFIG.read_bytes(), original)

    def test_regular_xml_and_snapshot_round_trip(self):
        result = m.config_mgr.update_candidate('config.security-test', '<security-test>safe &amp; sound</security-test>', 'test')
        self.assertEqual(result['status'], 'ok')
        self.assertEqual(m.config_mgr.snapshot_save('security_test-1')['status'], 'saved')
        self.assertEqual(m.config_mgr.snapshot_restore('security_test-1', 'test')['status'], 'restored-to-candidate')
        self.assertEqual(m.config_mgr.snapshot_delete('security_test-1')['status'], 'deleted')

    def test_invalid_snapshot_and_license_names_rejected(self):
        for name in ('', '../outside', '..\\outside', '/tmp/outside', 'C:\\outside', 'name\n', 'a' * 201):
            for validate in (m._snapshot_name, m._lic_safe_filename):
                with self.subTest(name=name, validator=validate.__name__), self.assertRaises(m.HTTPException):
                    validate(name)
        for operation in (m.config_mgr.snapshot_save, m.config_mgr.snapshot_delete):
            with self.assertRaises(m.HTTPException):
                operation('../outside')

    def test_store_rejects_traversal_and_symlinks(self):
        store = Path(_tmp.name) / 'store'
        store.mkdir(exist_ok=True)
        outside = Path(_tmp.name) / 'outside.lic'
        outside.write_text('untouched')
        with self.assertRaises(m.HTTPException):
            m._store_path(store, '../outside.lic')
        link = store / 'link.lic'
        try:
            link.symlink_to(outside)
        except OSError:
            # Windows without symlink privilege: exercise the same rejection.
            with patch.object(Path, 'is_symlink', return_value=True), self.assertRaises(m.HTTPException):
                m._store_path(store, 'link.lic')
        else:
            with self.assertRaises(m.HTTPException):
                m._store_path(store, 'link.lic')
        self.assertEqual(outside.read_text(), 'untouched')

    def test_network_command_injection_rejected_before_spawn(self):
        cases = [
            ['sh', '-c', 'id'], ['ip', 'link', 'set', '-batch', 'up'],
            ['ip', 'link', 'set', 'eth0\nup', 'up'],
            ['vtysh', '-c', 'vrf test\nend\nshell'],
            ['vtysh', '-c', 'show ip route | cat /etc/passwd'],
            ['vtysh', '-c', 'vrf test; shell'], ['vtysh', '-f', '/tmp/config'],
            ['sysctl', '-w', 'kernel.core_pattern=evil'],
        ]
        with patch.object(m.subprocess, 'run') as spawn:
            for args in cases:
                with self.subTest(args=args), self.assertRaises(m.HTTPException):
                    m._run_net_cmd(args, 'test')
            spawn.assert_not_called()

    def test_valid_network_commands_keep_argument_boundaries(self):
        with patch.object(m.subprocess, 'run', return_value=Mock(returncode=0, stdout='', stderr='')) as spawn:
            for args in (
                ['ip', 'link', 'add', 'vrf-blue', 'type', 'vrf', 'table', '1001'],
                ['ip', '-j', 'route', 'show', 'table', '1001'],
                ['sysctl', '-w', 'net.ipv4.tcp_l3mdev_accept=1'],
                ['vtysh', '-c', 'vrf blue', '-c', 'ip route 192.0.2.0/24 192.0.2.1'],
            ):
                self.assertEqual(m._run_net_cmd(args, 'test'), (0, ''))
                self.assertEqual(spawn.call_args.args[0], args)
                self.assertNotIn('shell', spawn.call_args.kwargs)

    def test_journal_filters_are_validated_and_count_bounded(self):
        with patch.object(m.subprocess, 'check_output', return_value='') as spawn:
            self.assertEqual(m._journal_entries(unit='--file=/etc/passwd'), [])
            self.assertEqual(m._journal_entries(priority='4\n--directory=/tmp'), [])
            spawn.assert_not_called()
            m._journal_entries(unit='ffn-manager.service', priority='4', limit=1000000)
            self.assertEqual(spawn.call_args.args[0][2], '10000')
            with self.assertRaises(ValueError):
                m._journal_entries(limit='1 --file=/etc/passwd')

    def test_exception_details_do_not_reach_api_or_error_log(self):
        secret = 'private-path-and-test-credential'
        with patch.object(m.logger, 'error') as log:
            result = m._bcm_unavailable(ImportError(secret))
            self.assertNotIn(secret, json.dumps(result))
            self.assertNotIn(secret, str(log.call_args))
            self.assertIn('incident', result['detail'])
        with patch.object(m.subprocess, 'run', side_effect=OSError(secret)):
            result = m._payload_cli(['check'])
            self.assertNotIn(secret, json.dumps(result))
        with patch.object(m.shutil, 'which', return_value='/usr/bin/tailscale'), \
             patch.object(m.subprocess, 'check_output', side_effect=subprocess.CalledProcessError(1, ['tailscale'], output=secret)):
            result = asyncio.run(m.tailscale_status(user={'username': 'test'}))
            self.assertNotIn(secret, json.dumps(result))
            self.assertFalse(result['running'])


if __name__ == '__main__':
    unittest.main()
