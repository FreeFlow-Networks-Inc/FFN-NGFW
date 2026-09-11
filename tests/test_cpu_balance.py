#!/usr/bin/env python3
"""CPU-only default balancing: hermetic topology and boot/runtime agreement."""
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'opt'))
import ffn_cpu_planes as planes
import ffn_cpuisol as isolation


def inventory(count, smt=1, offset=0):
    groups = [[offset + core + thread * count for thread in range(smt)]
              for core in range(count)]
    ids = sorted(c for group in groups for c in group)
    return {'cpu': {'online_cpus': ids, 'available_cpus': ids,
                    'cores_logical': len(ids),
                    'topology': [{'cpu': c, 'siblings': group} for group in groups for c in group]}}


class BalanceTests(unittest.TestCase):
    def test_balanced_sizes_and_boot_agreement(self):
        for count in (4, 8, 16, 32, 64, 128):
            for smt in (1, 2):
                with self.subTest(count=count, smt=smt):
                    inv = inventory(count, smt)
                    auto = planes.CpuPlanes.auto(inventory=inv)
                    boot = isolation.decide(inv)
                    mp, cp, dp = (auto.cores(p) for p in planes.PLANES)
                    self.assertEqual(len(mp), max(1, count // 8) * smt)
                    self.assertEqual(len(mp), len(cp))
                    self.assertGreater(len(dp), len(mp))
                    self.assertEqual(sorted(mp + cp + dp), inv['cpu']['online_cpus'])
                    self.assertEqual(boot.cores, dp)
                    self.assertEqual(boot.planes, auto.planes)
                    for row in inv['cpu']['topology']:
                        self.assertEqual(len({auto.plane_of(c) for c in row['siblings']}), 1)
                    with patch.object(planes, 'read_cmdline', return_value=auto.grub_isolcpus()):
                        active = planes.CpuPlanes.from_system('missing.conf', inventory=inv)
                    self.assertEqual(active.planes, auto.planes)

    def test_small_physical_systems_share_without_isolation(self):
        for count in (1, 2, 3):
            inv = inventory(count, 2)
            auto = planes.CpuPlanes.auto(inventory=inv)
            self.assertEqual(auto.grub_isolcpus(), '')
            self.assertFalse(isolation.decide(inv).isolate)
            self.assertTrue(all(c == inv['cpu']['online_cpus'] for c in auto.planes.values()))

    def test_sparse_ids_and_asymmetric_siblings(self):
        inv = inventory(8, 2, 20)
        for row in inv['cpu']['topology'][1::2]:
            row['siblings'] = [row['cpu']]
        auto = planes.CpuPlanes.auto(inventory=inv)
        self.assertEqual(auto.data_cores, isolation.decide(inv).cores)
        self.assertEqual(auto.cores('mgmt'), [20, 28])
        self.assertEqual(auto.cores('ctrl'), [21, 29])
        self.assertEqual(len(auto.data_cores), 12)

    def test_saved_map_remains_active(self):
        inv = inventory(16)
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, 'cpu-planes.conf')
            with open(path, 'w') as stream:
                stream.write('FFN_MGMT_CORES="0-3"\nFFN_CTRL_CORES="4-7"\nFFN_DPDK_CORES="8-15"\n')
            with patch.object(planes, 'read_cmdline', return_value='isolcpus=8-15'):
                active = planes.CpuPlanes.from_system(path, inventory=inv)
            self.assertEqual(active.cores('mgmt'), [0, 1, 2, 3])
            self.assertEqual(active.data_cores, list(range(8, 16)))
            self.assertEqual(planes.CpuPlanes.auto(inventory=inv).data_cores, list(range(4, 16)))

    def test_specialized_host_stays_management(self):
        inv = inventory(16, 2)
        inv['accelerators'] = [{'kind': 'fpga', 'role': 'packet processing'}]
        auto = planes.CpuPlanes.auto(inventory=inv)
        self.assertEqual(auto.cores('mgmt'), inv['cpu']['online_cpus'])
        self.assertEqual(auto.data_cores, [])
        self.assertFalse(isolation.decide(inv).isolate)


if __name__ == '__main__':
    unittest.main()
