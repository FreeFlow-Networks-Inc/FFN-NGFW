from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'opt'))
from ffn_kernel_capabilities import inspect


class Capabilities(unittest.TestCase):
    def test_missing_built_in_and_modular_evidence(self):
        features=inspect('# CONFIG_NFT_NUMGEN is not set\nCONFIG_NFT_HASH=m\nCONFIG_NET_SCH_HTB=y\nCONFIG_NET_CLS_FW=y\n')['features']
        self.assertIs(features['nat-round-robin']['compiled'],False)
        self.assertIs(features['nat-address-hash']['compiled'],True)
        self.assertIs(features['qos-htb']['compiled'],True)
        self.assertFalse(features['nat-address-hash']['runtime_verified'])
        self.assertIsNone(features['transparent-proxy']['compiled'])

    def test_missing_config_does_not_invent_support(self):
        self.assertTrue(all(v['compiled'] is None for v in inspect('')['features'].values()))
