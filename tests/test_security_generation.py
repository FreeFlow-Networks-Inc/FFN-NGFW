"""Installed provider updates must not leave old code renewing policy leases."""
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'opt'))
import ffn_security_runtime as runtime


class GenerationTests(unittest.TestCase):
    def test_changed_provider_with_same_size_and_timestamp_requires_reload(self):
        import os
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'ffn_platform_policy_bindings.py'
            path.write_text('value=1\n');before=path.stat()
            expected=runtime.code_generation([str(path)])
            runtime.check_generation(expected)
            path.write_text('value=2\n');os.utime(path,ns=(before.st_atime_ns,before.st_mtime_ns))
            with self.assertRaises(runtime.RuntimeUpdated):runtime.check_generation(expected)

    def test_removed_dependency_requires_reload(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'provider.py';path.write_text('value=1\n')
            expected=runtime.code_generation([str(path)]);path.unlink()
            with self.assertRaises(runtime.RuntimeUpdated):runtime.check_generation(expected)

    def test_unchanged_provider_is_stable(self):
        expected=runtime.code_generation()
        self.assertIn(str(Path(runtime.__file__).resolve()),expected)
        runtime.check_generation(expected)


if __name__=='__main__':unittest.main()
