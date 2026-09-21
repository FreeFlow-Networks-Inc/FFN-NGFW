import sys
from pathlib import Path
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'opt'))
import ffn_security_runtime as runtime


class AckTests(unittest.TestCase):
    def test_ack_requires_matching_kernel_bindings_boot_and_live_collector(self):
        state=dict(revision=2,boot_id='boot',bindings={'lan':{}},tables=[],kernel_digest='kernel',digest='policy',nat={'revision':3,'digest':'nat','plan':{'rules':[]}})
        for case in ('ready','boot','bindings','kernel','collector','unavailable'):
            with self.subTest(case=case),patch.object(runtime,'saved',return_value=state),patch.object(runtime,'boot',return_value='other' if case=='boot' else 'boot'),patch.object(runtime,'bindings',return_value=({},[]) if case=='bindings' else ({'lan':{}},[])),patch.object(runtime,'inventory',return_value={'nftables':[]}),patch.object(runtime,'fingerprint',return_value='other' if case=='kernel' else 'kernel'),patch.object(runtime,'health',side_effect=runtime.NatError('stale') if case=='unavailable' else None,return_value={'forwarding_revision':1 if case=='collector' else 2}):
                value=runtime.status()
                self.assertEqual(value['processing']['acknowledged'],case=='ready')
                self.assertEqual(value['nat']['acknowledged'],case=='ready')
                self.assertFalse(value['processing']['hardware_offload'])
                self.assertEqual(value['nat']['revision'],3)


if __name__=='__main__':unittest.main()
