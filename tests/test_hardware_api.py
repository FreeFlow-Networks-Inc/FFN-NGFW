#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Manager integration using synthetic PCI and control-plane inventories."""
import copy
import os
import tempfile
import threading
import unittest
from unittest.mock import AsyncMock, patch

from test_hwdetect import Fixture, hw

_temp = tempfile.TemporaryDirectory(prefix="ffn-hardware-api-")
os.environ["FFN_DB_PATH"] = os.path.join(_temp.name, "config.db")
os.environ["FFN_CONFIG_DIR"] = os.path.join(_temp.name, "config")
os.environ["FFN_JWT_SECRET"] = "hardware-test-only-signing-secret"
import ffn_manager as manager


class HardwareAPITests(unittest.IsolatedAsyncioTestCase):
    async def test_blocking_probe_runs_off_event_loop_and_cache_is_not_mutated(self):
        fixture = Fixture()
        fixture.pci("0000:01:00.0", "10ee", "903f", "120000")
        inventory = hw.detect(probe=fixture)
        original = copy.deepcopy(inventory)
        threads = []

        def cached_inventory(refresh=False):
            threads.append(threading.get_ident())
            return inventory

        far = {"cp_devices": [{"kind": "switch", "pci": "0000:03:00.0",
                                "description": "Fixture fabric", "vendor": "14e4", "device": "8375"}]}
        with patch.object(manager, "_hw_inventory", side_effect=cached_inventory), \
             patch.object(manager, "_detect_offload_dp", new=AsyncMock(return_value=far)):
            first = await manager.system_hardware(refresh=1, user={"username": "fixture"})
            second = await manager.system_hardware(refresh=0, user={"username": "fixture"})
        self.assertTrue(all(t != threading.get_ident() for t in threads))
        self.assertEqual(inventory, original)
        self.assertEqual(len(first["accelerators"]), 2)
        self.assertEqual(len(second["accelerators"]), 2)
        self.assertEqual(second["accelerators"][1]["bus"], "control-plane")
        self.assertEqual(second["cpu_role"]["role"], "management")

    async def test_host_octeon_is_discovered_without_lspci_and_bridges_are_not_counted(self):
        fixture = Fixture()
        fixture.pci("0000:01:00.0", "177d", "9700", "0b4000")
        fixture.pci("0000:01:00.1", "177d", "9700", "060400")
        fixture.pci("0000:01:00.2", "177d", "9703", "010802")
        with patch.object(hw, "detect_pci_summary", return_value=hw.detect_pci_summary(fixture)), \
             patch.object(manager, "_sw_forwarder", return_value={}), \
             patch.object(manager, "_cp_reachable", return_value=(False, "fixture offline")):
            result = manager._probe_host_octeon()
        self.assertTrue(result["present"])
        self.assertEqual(result["generation"], "OCTEON III CN73XX")
        self.assertEqual(result["cp"]["chips"], 1)
        self.assertEqual(len(result["pci"]), 1)
        self.assertFalse(result["cp"]["reachable"])
        self.assertFalse(result["dp"]["present"])

    async def test_bridge_or_thunderx_alone_does_not_trigger_cp_probe(self):
        fixture = Fixture()
        fixture.pci("0000:01:00.0", "177d", "9700", "060400")
        fixture.pci("0000:02:00.0", "177d", "a034", "020000")
        with patch.object(hw, "detect_pci_summary", return_value=hw.detect_pci_summary(fixture)), \
             patch.object(manager, "_sw_forwarder", return_value={}), \
             patch.object(manager, "_cp_reachable") as reach:
            result = manager._probe_host_octeon()
        self.assertFalse(result["present"])
        reach.assert_not_called()


if __name__ == "__main__":
    try:
        unittest.main(verbosity=2)
    finally:
        _temp.cleanup()
