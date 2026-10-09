"""serve()'s gate closes report a stalled nft instead of journaling it as a fault."""
import subprocess
import sys
from pathlib import Path
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'opt'))
import ffn_security_runtime as runtime


class GateCloseTests(unittest.TestCase):
    def test_stalled_or_failed_close_is_a_reported_problem_not_an_exception(self):
        for error in (subprocess.TimeoutExpired(['nft','flush'],15), subprocess.CalledProcessError(1,['nft']),
                      OSError(2,'no nft'), runtime.NatError('nftables userspace is missing on the dataplane')):
            with self.subTest(error=type(error).__name__), patch.object(runtime,'close_gate',side_effect=error):
                problem=runtime.gate_close_problem()
        self.assertTrue(problem.startswith('Policy gate close failed: '))
        self.assertIn('nftables userspace', problem)

    def test_successful_close_reports_nothing(self):
        with patch.object(runtime,'close_gate') as close:
            self.assertIsNone(runtime.gate_close_problem())
        close.assert_called_once()

    def test_main_loop_never_journals_a_gate_close_timeout(self):
        """The three closes in serve() go through the helper; a raw TimeoutExpired
        would reach the catch-all and poison the collector's journal."""
        source=Path(runtime.__file__).read_text()
        body=source[source.index('def serve():'):]
        # stop_transit (the collector thread's own close, which has its own retry) and the final cleanup
        self.assertEqual(body.count('with lock():close_gate()'),2)
        self.assertGreaterEqual(body.count('gate_close_problem()'),3)


if __name__=='__main__':unittest.main()
