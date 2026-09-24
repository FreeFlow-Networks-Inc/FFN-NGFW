"""Repository publication and read-only HTTP boundary tests; no live installs."""
import http.client
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch as mockpatch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'opt'))
import ffn_patch as patch
import ffn_update_server as server
spec = importlib.util.spec_from_file_location('repository', ROOT / 'tools/build-server/patch_repository.py')
repo = importlib.util.module_from_spec(spec)
spec.loader.exec_module(repo)


class RepositoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.seed = self.root / 'sign.key'
        self.seed.write_text(bytes(range(32)).hex())
        self.seed.chmod(0o600)
        self.pub = self.root / 'sign.pub'
        self.pub.write_text(patch.payload.ffn_ed25519.publickey(bytes(range(32))).hex())
        self.directory = self.root / 'published'
        self.base, self.source = self.root / 'base', self.root / 'source'
        self.base.mkdir()
        self.source.mkdir()
        (self.base / 'app.py').write_text('VALUE = 1\n')
        (self.source / 'app.py').write_text('VALUE = 2\n')
        self.archive = self.root / 'candidate.tgz'
        patch.build(self.base, self.source, '2', self.archive, {})

    def publish(self, **kwargs):
        return repo.publish(self.directory, self.seed, self.pub, self.archive, **kwargs)

    def test_publish_and_real_client_verification(self):
        meta = self.publish()
        self.assertTrue(repo.verify(self.directory, self.pub)['verified'])
        manager = patch.PatchManager(self.base, self.root / 'state', self.pub)
        manifest = json.loads((self.directory / 'manifest.json').read_text())
        self.assertEqual(manager.verify(manifest), meta)
        manager.preflight((self.directory / meta['file']).read_bytes(), meta)
        self.assertEqual(self.publish(), meta)  # Idempotent, no timestamp reset.

    def test_failed_publication_keeps_previous_catalog(self):
        self.publish()
        before = (self.directory / 'manifest.json').read_bytes()
        patch.build(self.base, self.source, '3', self.archive, {})
        atomic = patch.atomic
        def fail_manifest(path, *args, **kwargs):
            if path.name == 'manifest.json':
                raise OSError('simulated interrupted publication')
            return atomic(path, *args, **kwargs)
        with mockpatch.object(patch, 'atomic', side_effect=fail_manifest), self.assertRaises(OSError):
            self.publish()
        self.assertEqual((self.directory / 'manifest.json').read_bytes(), before)
        self.assertTrue(repo.verify(self.directory, self.pub)['verified'])

    def test_code_patch_preserves_independent_processor_releases(self):
        self.publish()
        manifest = json.loads((self.directory / 'manifest.json').read_text())
        planes = {role: {'version': role + '-release', 'sha256': role * 32}
                  for role in ('cp', 'dp')}
        for role, metadata in planes.items():
            manifest['payloads']['pa5200-' + role] = metadata
        sig, alg = patch.payload.sign_manifest(manifest, seed=bytes(range(32)))
        manifest.update(signature=sig, sig_alg=alg)
        (self.directory / 'manifest.json').write_text(json.dumps(manifest))
        patch.build(self.base, self.source, '3', self.archive, {})
        self.publish()
        current = json.loads((self.directory / 'manifest.json').read_text())
        for role, metadata in planes.items():
            self.assertEqual(current['payloads']['pa5200-' + role], metadata)
        self.assertTrue(repo.verify(self.directory, self.pub)['verified'])

    def test_tampering_and_version_reuse_rejected(self):
        meta = self.publish()
        (self.source / 'app.py').write_text('VALUE = 3\n')
        patch.build(self.base, self.source, '2', self.archive, {})
        with self.assertRaisesRegex(ValueError, 'version cannot'):
            self.publish()
        (self.directory / meta['file']).write_bytes(b'invalid')
        with self.assertRaises(Exception):
            repo.verify(self.directory, self.pub)

    def test_import_preserves_timestamp_and_checks_hash(self):
        self.publish()
        manifest = json.loads((self.directory / 'manifest.json').read_text())
        manifest['payloads']['patch']['published'] = 100
        sig, alg = patch.payload.sign_manifest(manifest, seed=bytes(range(32)))
        manifest.update(signature=sig, sig_alg=alg)
        self.directory = self.root / 'imported'
        self.assertEqual(self.publish(imported=manifest)['published'], 100)
        manifest['payloads']['patch']['size'] += 1
        with self.assertRaisesRegex(ValueError, 'signature'):
            self.publish(imported=manifest)

    def test_signing_seed_in_served_tree_rejected(self):
        self.directory = self.root
        with self.assertRaisesRegex(ValueError, 'outside'):
            self.publish()

    def test_server_page_lists_platform_image_kinds_safely(self):
        self.publish()
        with mockpatch.object(server, 'DIR', str(self.directory)), mockpatch.object(server, 'PUBKEY', str(self.pub)), \
                mockpatch.object(server, 'api_clients', return_value={'clients': []}), \
                mockpatch.object(server, 'api_payloads', return_value={'payloads': [
                    dict(kind='pa5200-cp',version='cp-release',size=10,sha256='a'*64,url='/cp.tar.xz',available=True),
                    dict(kind='<script>',version='dp-release',size=10,sha256='b'*64,url='/dp.tar.xz',available=True)]}):
            page=server.page()
        if isinstance(page,bytes): page=page.decode()
        self.assertIn('pa5200-cp',page)
        self.assertIn('&lt;script&gt;',page)
        self.assertNotIn('<b><script>',page)

    def test_http_only_exposes_exact_manifest_payloads(self):
        meta = self.publish()
        (self.directory / 'private.key').write_text('not a real key')
        with mockpatch.object(server, 'DIR', str(self.directory)), mockpatch.object(server, 'PUBKEY', str(self.pub)):
            httpd = server.http.server.ThreadingHTTPServer(('127.0.0.1', 0), server.Handler)
            thread = threading.Thread(target=httpd.serve_forever, daemon=True)
            thread.start()
            try:
                for path, want in [('/', 200), ('/api/status', 200), ('/manifest.json', 200),
                                   ('/' + meta['file'], 200), ('/private.key', 404),
                                   ('/../' + meta['file'], 404), ('/.history', 404),
                                   ('/%2e%2e/private.key', 404)]:
                    conn = http.client.HTTPConnection(*httpd.server_address, timeout=5)
                    conn.request('GET', path)
                    response = conn.getresponse()
                    data = response.read()
                    conn.close()
                    self.assertEqual(response.status, want, path)
                    if path == '/api/status':
                        self.assertTrue(json.loads(data)['signature_verified'])
                self.assertTrue(server.api_status()['signature_verified'])
            finally:
                httpd.shutdown()
                httpd.server_close()
                thread.join()

    @unittest.skipIf(sys.platform == 'win32', 'Symlink creation requires Windows privilege')
    def test_manifest_cannot_expose_symlink(self):
        meta = self.publish()
        target = self.directory / meta['file']
        target.unlink()
        target.symlink_to(self.seed)
        with mockpatch.object(server, 'DIR', str(self.directory)):
            with self.assertRaises(ValueError):
                server.open_payload(meta['file'])
            self.assertFalse(server.api_payloads()['payloads'][0]['available'])


if __name__ == '__main__':
    unittest.main()
