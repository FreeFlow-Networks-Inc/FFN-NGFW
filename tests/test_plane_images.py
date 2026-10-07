import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'opt'))
import ffn_plane_images as images
import ffn_platform as platforms


class ImageStagingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.cache = Path(self.temp.name)
        self.lock = dict(schema=1, enabled=True, platform='pa5200', architecture='mips64eb',
                         runtime_abi=1, platform_commit='a'*40, core_commit='b'*40,
                         repository='example/platform', tag='octeon-test')
        self.data = {'ffn-pa5200-cp.tar.xz': b'CP', 'ffn-pa5200-dp.tar.xz': b'DP'}
        self.manifest = {k: self.lock[k] for k in ('schema', 'platform', 'architecture',
                         'runtime_abi', 'platform_commit', 'core_commit')}
        self.manifest['assets'] = [dict(role=role, name=name, sha256=hashlib.sha256(self.data[name]).hexdigest(),
                                        size=2, kernel_release='6.18-ffn-'+role)
                                  for role, name in zip(('cp', 'dp'), self.data)]
        self.refresh()
        self.calls = []

    def refresh(self):
        self.data['manifest.json'] = json.dumps(self.manifest).encode()
        self.lock['manifest_sha256'] = hashlib.sha256(self.data['manifest.json']).hexdigest()

    def fetch(self, url, target, limit):
        self.calls.append(url)
        target.write_bytes(self.data[url.rsplit('/', 1)[-1]])

    def stage(self, **kw):
        return images.stage(self.lock, self.cache, fetch=self.fetch, **kw)

    def test_pair_atomic_and_offline_reuse(self):
        result = self.stage()
        self.assertEqual(result['state'], 'staged')
        self.assertFalse(result['activated'])
        self.assertFalse(result['reboot_required'])
        self.assertEqual(len(self.calls), 3)
        self.assertEqual(self.stage(offline=True), result)
        self.assertEqual(len(self.calls), 3)

    def test_missing_offline_pair(self):
        with self.assertRaisesRegex(ValueError, 'not cached'):
            self.stage(offline=True)
        self.assertEqual(self.calls, [])

    def test_unpublished_has_no_network_or_cache(self):
        self.lock['enabled'] = False
        self.assertEqual(self.stage()['state'], 'not-published')
        self.assertEqual(list(self.cache.iterdir()), [])

    def test_tampered_manifest_stops_before_image_download(self):
        self.data['manifest.json'] += b' '
        with self.assertRaisesRegex(ValueError, 'Untrusted'):
            self.stage()
        self.assertEqual(len(self.calls), 1)

    def test_bad_second_asset_leaves_no_partial_pair(self):
        self.data['ffn-pa5200-dp.tar.xz'] = b'XX'
        with self.assertRaisesRegex(ValueError, 'digest mismatch'):
            self.stage()
        self.assertEqual(list((self.cache / 'pa5200').iterdir()), [])

    def test_interrupted_download_cleans_stage(self):
        def interrupted(url, path, limit):
            path.write_bytes(b'partial')
            raise OSError('network lost')
        with self.assertRaises(OSError):
            images.stage(self.lock, self.cache, fetch=interrupted)
        self.assertEqual(list((self.cache / 'pa5200').iterdir()), [])

    def test_failed_new_release_preserves_previous_pair(self):
        previous = Path(self.stage()['path'])
        self.manifest['core_commit'] = 'd'*40
        self.lock['core_commit'] = 'd'*40
        self.refresh()
        self.data['ffn-pa5200-dp.tar.xz'] = b'broken'
        with self.assertRaises(ValueError):
            self.stage()
        self.assertEqual((previous / 'ffn-pa5200-dp.tar.xz').read_bytes(), b'DP')
        self.assertEqual(list((self.cache / 'pa5200').iterdir()), [previous])

    def test_corrupt_cache_refused_offline(self):
        target = Path(self.stage()['path'])
        (target / 'ffn-pa5200-cp.tar.xz').write_bytes(b'xx')
        with self.assertRaisesRegex(ValueError, 'digest mismatch'):
            self.stage(offline=True)

    def test_compatibility_mismatch(self):
        for field, bad in [('architecture', 'mips64el'), ('runtime_abi', 2),
                           ('platform_commit', 'c'*40), ('core_commit', 'c'*40), ('platform', 'other')]:
            original = self.manifest[field]
            self.manifest[field] = bad
            self.refresh()
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'mismatch'):
                self.stage()
            self.manifest[field] = original

    def test_roles_paths_and_sizes(self):
        for field, bad in [('role', 'cp'), ('name', '../../escape'), ('size', 0),
                           ('size', images.MAX_ASSET+1), ('sha256', 'bad')]:
            original = self.manifest['assets'][1][field]
            self.manifest['assets'][1][field] = bad
            self.refresh()
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.stage()
            self.manifest['assets'][1][field] = original

    def test_redirect_host_and_transport_checks(self):
        for url in ('http://github.com/x', 'https://evil.example/x',
                    'https://github.com.evil.example/x', 'https://user@github.com/x',
                    'https://github.com:444/x'):
            with self.subTest(url=url), self.assertRaises(ValueError):
                images.check_url(url)
        images.check_url('https://release-assets.githubusercontent.com/x')

    def test_select_staging_reads_only_selected_platform_lock(self):
        p = self.cache / 'platform/demo'
        p.mkdir(parents=True)
        (p / 'plane-images.json').write_text(json.dumps(self.lock))
        with patch.object(images, 'stage') as stage:
            self.assertEqual(platforms.stage_images(str(self.cache), dict(name='demo', path='platform/demo')), 1)
            stage.assert_not_called()

    def test_no_images_declaration_is_compatible(self):
        self.assertEqual(platforms.stage_images(str(self.cache), dict(name='demo', path='platform/demo')), 0)


if __name__ == '__main__':
    unittest.main()
