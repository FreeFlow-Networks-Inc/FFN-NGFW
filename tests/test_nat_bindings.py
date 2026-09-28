import json
from types import SimpleNamespace
import sys
from pathlib import Path
import unittest
from unittest.mock import Mock, patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'opt'))
import ffn_nat_runtime as runtime


class DynamicBindingsTests(unittest.TestCase):
    def test_selected_platform_needs_no_static_customer_map(self):
        absent=Mock();absent.exists.return_value=False
        selection=Mock();selection.exists.return_value=True
        selection.stat.return_value=SimpleNamespace(st_uid=0,st_mode=0o600)
        selection.read_text.return_value='{"provider":"platform"}'
        provider=SimpleNamespace(discover=Mock(return_value={'ethernet1/1':'p1'}))
        with patch.object(runtime,'BINDINGS',absent), patch.object(runtime,'PLATFORM_BINDINGS',selection), \
             patch.object(runtime,'run',return_value=json.dumps([{'ifname':'p1'}])), \
             patch.dict(sys.modules,{'ffn_platform_policy_bindings':provider}):
            self.assertEqual(runtime.bindings(),{'ethernet1/1':'p1'})
            provider.discover.return_value={}
            self.assertEqual(runtime.bindings(),{})
            selection.stat.return_value.st_mode=0o666
            with self.assertRaisesRegex(runtime.NatError,'root-owned'):runtime.bindings()
        absent.write_text.assert_not_called()

    def test_unselected_platform_still_requires_commissioning(self):
        absent=Mock();absent.exists.return_value=False
        with patch.object(runtime,'BINDINGS',absent),patch.object(runtime,'PLATFORM_BINDINGS',absent):
            with self.assertRaisesRegex(runtime.NatError,'No commissioned'):runtime.bindings()


if __name__=='__main__':unittest.main()
