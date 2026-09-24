"""Exercise the deployment hook's dispatch and checkpoint boundaries."""
import os
from pathlib import Path
import runpy
import tempfile
import unittest
from unittest.mock import patch

INSTALLER = Path(__file__).resolve().parents[1] / 'image/install-configd-platform.py'
ENGINE = '''class Engine:
    def apply(self, status, new_paths, old_paths):
        changes = diff_configs(old_paths, new_paths)
        if not changes:
            status.finish(); status.write()
            return status
        for path in changes:
            dispatched.append(path)
        try:
            import shutil
            shutil.copy2(RUNNING_CONFIG, LAST_APPLIED)
        except OSError:
            pass
        status.finish(); status.write()
        return status
'''


class Status:
    def __init__(self):
        self.errors = []
        self.validation_errors = []
        self.finished = self.written = False

    def fail(self, *args):
        self.errors.append(args)

    def finish(self):
        self.finished = True

    def write(self):
        self.written = True


class PlatformHookTests(unittest.TestCase):
    def run_hook(self, body, changes):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            engine = root / 'configd.py'
            engine.write_text(ENGINE)
            with patch('sys.argv', [str(INSTALLER), str(engine)]):
                runpy.run_path(str(INSTALLER), run_name='__main__')
            provider = root / 'provider.py'
            provider.write_text('class PlatformApplier:\n'
                                '    def __init__(self, config): pass\n'
                                '    def claims(self, path): return path == "interface"\n'
                                '    def reconcile(self, status):\n        ' + body + '\n')
            running, applied = root / 'running.xml', root / 'applied.xml'
            running.write_text('new'); applied.write_text('old')
            env = dict(os=os, Path=Path, RUNNING_CONFIG=running, LAST_APPLIED=applied,
                       diff_configs=lambda old, new: changes, dispatched=[])
            exec(compile(engine.read_text(), str(engine), 'exec'), env)
            status = Status()
            with patch.dict(os.environ, {'FFN_CONFIG_PLATFORM': str(provider)}):
                env['Engine']().apply(status, {}, {})
            self.assertTrue(status.finished and status.written)
            return status, env['dispatched'], applied.read_text()

    def test_reported_failure_stops_generic_dispatch_and_checkpoint(self):
        status, dispatched, checkpoint = self.run_hook("status.fail('interface', 'platform', 'DP unavailable')", {'interface': {}, 'route': {}})
        self.assertTrue(status.errors)
        self.assertEqual(dispatched, [])
        self.assertEqual(checkpoint, 'old')

    def test_exception_stops_generic_dispatch_and_checkpoint(self):
        status, dispatched, checkpoint = self.run_hook("raise ValueError('DP unavailable')", {'route': {}})
        self.assertTrue(status.errors)
        self.assertEqual(dispatched, [])
        self.assertEqual(checkpoint, 'old')

    def test_reconciles_even_when_saved_snapshot_already_matches(self):
        status, _, _ = self.run_hook("status.fail('interface', 'platform', 'DP unavailable')", {})
        self.assertTrue(status.errors)

    def test_success_filters_platform_paths_and_preserves_generic_dispatch(self):
        status, dispatched, checkpoint = self.run_hook('pass', {'interface': {}, 'hostname': {}})
        self.assertFalse(status.errors)
        self.assertEqual(dispatched, ['hostname'])
        self.assertEqual(checkpoint, 'new')


if __name__ == '__main__':
    unittest.main()
