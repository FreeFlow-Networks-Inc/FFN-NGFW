#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Hermetic inventories: no root, hardware, third-party packages or host probes."""
import fnmatch
import io
import json
import os
import subprocess
import sys
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "opt"))
import ffn_hwdetect as hw
import ffn_cpuisol as tuning
import ffn_cpu_planes as planes
from ffn_hwprobe import Probe


class Fixture(Probe):
    def __init__(self):
        super().__init__()
        self.files = {
            "/proc/cpuinfo": "processor : 0\nmodel name : Fixture CPU\nphysical id : 0\ncore id : 0\nflags : aes avx2\n\n"
                             "processor : 1\nmodel name : Fixture CPU\nphysical id : 0\ncore id : 1\nflags : aes avx2\n",
            "/proc/meminfo": "MemTotal: 16777216 kB\n",
            "/proc/uptime": "100.50 20.00",
            "/sys/devices/system/cpu/online": "0-1",
        }
        self.links = {}
        self.directories = {"/sys/bus/pci/devices", "/sys/class/net", "/sys/block"}
        self.commands = {}
        self.calls = []
        self.arch = "x86_64"
        self.os = "Linux"
        self.allowed = []

    def read(self, path, default="", required=False):
        value = self.files.get(path)
        if isinstance(value, Exception):
            self.note(path, type(value).__name__)
            return default
        if value is None:
            if required:
                self.note(path, "FileNotFoundError")
            return default
        return str(value).strip().strip("\0")

    def paths(self):
        paths = set(self.files) | set(self.links) | self.directories
        for path in list(paths):
            while "/" in path:
                path = path.rsplit("/", 1)[0]
                paths.add(path)
        return paths

    def entries(self, path):
        if not self.exists(path):
            self.note(path, "FileNotFoundError", "unavailable")
        return sorted(p for p in self.paths() if p.rsplit("/", 1)[0] == path)

    def glob(self, pattern):
        parts = pattern.split("/")
        return sorted(p for p in self.paths() if len(p.split("/")) == len(parts)
                      and all(fnmatch.fnmatchcase(a, b) for a, b in zip(p.split("/"), parts)))

    def link(self, path):
        return self.links.get(path, "")

    def exists(self, path):
        return path in self.paths()

    def have(self, tool):
        return tool in self.commands

    def run(self, command, timeout=6):
        self.calls.append(command)
        result = self.commands[command[0]]
        if isinstance(result, Exception):
            self.note(command[0], type(result).__name__)
            return ""
        return result

    def host(self):
        return {"hostname": "fixture", "kernel": "test", "arch": self.arch, "os": self.os}

    def cpu_count(self):
        return 2

    def affinity(self):
        return self.allowed

    def pci(self, address, vendor="8086", device="1234", cls="020000", driver="", node=-1):
        path = "/sys/bus/pci/devices/" + address
        self.files.update({path + "/vendor": "0x" + vendor, path + "/device": "0x" + device,
                           path + "/class": "0x" + cls, path + "/numa_node": str(node)})
        if driver:
            self.links[path + "/driver"] = "../../drivers/" + driver
        return path

    def net(self, name, address="", speed="1000", driver=""):
        path = "/sys/class/net/" + name
        self.files.update({path + "/speed": speed, path + "/mtu": "1500",
                           path + "/operstate": "up"})
        if address:
            self.links[path + "/device"] = "../../../" + address
        if driver:
            self.links[path + "/device/driver"] = "../../drivers/" + driver
        return path


class InventoryTests(unittest.TestCase):
    def test_plain_host_without_optional_tools(self):
        p = Fixture()
        inv = hw.detect(probe=p)
        self.assertEqual(inv["status"], "ok")
        self.assertEqual(inv["cpu"]["cores_physical"], 2)
        self.assertFalse(inv["dpu"]["present"])
        self.assertEqual(p.calls, [])
        json.dumps(inv)

    def test_numeric_pci_detects_fpga_octeon_and_display_without_lspci(self):
        p = Fixture()
        p.pci("0000:01:00.0", "10ee", "903f", "120000")
        p.pci("0000:02:00.0", "1172", "0001", "120000")
        p.pci("0000:03:00.0", "177d", "9700", "0b4000")
        p.pci("0000:03:00.1", "177d", "9700", "060400")
        p.pci("0000:03:00.2", "177d", "9703", "010802")
        p.pci("0000:04:00.0", "1a03", "2000", "030000")
        p.pci("0000:05:00.0", "10de", "0001", "030200")
        inv = hw.detect(probe=p)
        self.assertEqual(inv["pci"]["device_count"], 7)
        self.assertEqual([a["kind"] for a in inv["accelerators"]],
                         ["fpga", "fpga", "npu", "bridge", "npu-function", "bmc", "gpu"])
        self.assertTrue(inv["specialized"]["fpga"]["present"])
        self.assertEqual(inv["specialized"]["octeon"]["pci_slots"], ["0000:03:00"])
        self.assertIsNone(inv["specialized"]["offload_ready"])

    def test_octeon_cpu_without_pci_or_dmi(self):
        p = Fixture()
        p.arch = "mips64"
        p.files["/proc/cpuinfo"] = "processor : 0\ncpu model : Cavium Octeon III V0.2\n\nprocessor : 1\ncpu model : Cavium Octeon III V0.2\n"
        inv = hw.detect(probe=p)
        self.assertTrue(inv["specialized"]["octeon"]["host_cpu"])
        self.assertEqual(inv["specialized"]["octeon"]["pci_functions"], [])

    def test_octeon_device_tree_identifies_arm_soc(self):
        p = Fixture()
        p.arch = "aarch64"
        p.files["/sys/firmware/devicetree/base/compatible"] = "vendor,board\0marvell,octeon-tx2\0"
        p.files["/sys/firmware/devicetree/base/model"] = "Test board\0"
        inv = hw.detect(probe=p)
        self.assertTrue(inv["specialized"]["octeon"]["host_cpu"])
        self.assertEqual(inv["system"]["product"], "Test board")
        self.assertFalse(inv["cpu"]["aes_ni"])

    def test_thunderx_is_not_octeon(self):
        p = Fixture()
        p.pci("0000:01:00.0", "177d", "a034", "020000")
        inv = hw.detect(probe=p)
        self.assertFalse(inv["specialized"]["octeon"]["present"])
        self.assertNotEqual(inv["accelerators"][0]["kind"], "npu")

    def test_fpga_manager_without_pci(self):
        p = Fixture()
        p.files["/sys/class/fpga_manager/fpga0/name"] = "SoC FPGA Manager"
        p.files["/sys/class/fpga_manager/fpga0/state"] = "operating"
        inv = hw.detect(probe=p)
        fpga = inv["specialized"]["fpga"]["devices"][0]
        self.assertEqual(fpga["bus"], "platform")
        self.assertEqual(fpga["managers"][0]["state"], "operating")
        self.assertIsNone(inv["specialized"]["offload_ready"])

    def test_fpga_manager_merges_with_known_pci_device(self):
        p = Fixture()
        p.pci("0000:01:00.0", "10ee", "903f", "120000")
        p.files["/sys/class/fpga_manager/fpga0/name"] = "PCI FPGA"
        p.links["/sys/class/fpga_manager/fpga0/device"] = "../../../0000:01:00.0"
        inv = hw.detect(probe=p)
        self.assertEqual(len(inv["specialized"]["fpga"]["devices"]), 1)
        self.assertEqual(inv["accelerators"][0]["managers"][0]["name"], "PCI FPGA")

    def test_mellanox_nic_and_mst_are_not_dpu(self):
        p = Fixture()
        p.pci("0000:01:00.0", "15b3", "1017", driver="mlx5_core")
        p.net("eth0", "0000:01:00.0")
        p.files["/dev/mst/mt4119_pciconf0"] = ""
        inv = hw.detect(probe=p)
        self.assertFalse(inv["dpu"]["present"])
        self.assertEqual(inv["nics"][0]["kind"], "nic/rdma")

    def test_two_bluefields_group_functions_but_not_control_channels(self):
        p = Fixture()
        for address, device in (("0000:01:00.0", "a2d6"), ("0000:01:00.1", "a2d6"), ("0000:02:00.0", "a2dc")):
            p.pci(address, "15b3", device)
        p.files["/dev/rshim0"] = ""
        inv = hw.detect(probe=p)
        self.assertEqual(len(inv["dpu"]["devices"]), 2)
        self.assertEqual(len(inv["dpu"]["devices"][0]["pci_addresses"]), 2)
        self.assertEqual(inv["dpu"]["devices"][1]["rshim"], [])
        self.assertEqual(inv["dpu"]["control_channels"]["rshim"], ["/dev/rshim0"])

    def test_control_only_dpu_does_not_invent_model(self):
        p = Fixture()
        p.net("tmfifo_net0")
        dpu = hw.detect(probe=p)["dpu"]
        self.assertTrue(dpu["present"])
        self.assertIn("unknown", dpu["devices"][0]["type"])

    def test_userspace_and_unbound_nics_retain_numa_and_iommu(self):
        p = Fixture()
        path = p.pci("0000:01:00.0", driver="vfio-pci", node=3)
        p.links[path + "/iommu_group"] = "../../kernel/iommu_groups/17"
        p.files[path + "/sriov_totalvfs"] = "32"
        p.files[path + "/sriov_numvfs"] = "4"
        p.pci("0000:02:00.0", node=1)
        nics = hw.detect(probe=p)["nics"]
        self.assertEqual(nics[0]["numa_node"], 3)
        self.assertEqual(nics[0]["iommu_group"], 17)
        self.assertEqual(nics[0]["sriov_totalvfs"], 32)
        self.assertEqual(nics[1]["binding"], "unbound")

    def test_virtual_usb_virtio_and_sriov_interfaces(self):
        p = Fixture()
        p.net("veth0", speed="-1")
        p.net("wg0")
        p.net("usb0", "0000:00:14.0/usb1/1-1/1-1:1.0", driver="r8152")
        p.pci("0000:01:00.0", driver="virtio-pci")
        p.net("eth0", "0000:01:00.0/virtio0", driver="virtio_net")
        path = p.pci("0000:02:00.1")
        p.links[path + "/physfn"] = "../0000:02:00.0"
        p.net("vf0", "0000:02:00.1")
        nics = {n["name"]: n for n in hw.detect(probe=p)["nics"]}
        self.assertEqual(len(nics), 5)
        self.assertEqual(nics["veth0"]["kind"], "virtual")
        self.assertEqual(nics["veth0"]["speed_mbps"], 0)
        self.assertEqual(nics["wg0"]["kind"], "overlay/virtual")
        self.assertEqual(nics["usb0"]["pci"], "")
        self.assertEqual(nics["usb0"]["driver"], "r8152")
        self.assertEqual(nics["eth0"]["pci"], "0000:01:00.0")
        self.assertEqual(nics["vf0"]["kind"], "sriov-vf")

    def test_many_netdevs_on_one_pci_function_are_preserved(self):
        p = Fixture()
        p.pci("0000:01:00.0", driver="mlx5_core")
        p.net("port0", "0000:01:00.0")
        p.net("representor0", "0000:01:00.0")
        self.assertEqual(len(hw.detect(probe=p)["nics"]), 2)

    def test_one_lspci_snapshot_and_locale_independent_classification(self):
        p = Fixture()
        p.pci("0000:01:00.0", "10ee", "903f", "120000")
        p.commands["lspci"] = "0000:01:00.0 Unknown device [1200]: Unknown [10ee:903f]\n"
        inv = hw.detect(probe=p)
        self.assertEqual(p.calls, [["lspci", "-Dnn"]])
        self.assertEqual(inv["accelerators"][0]["kind"], "fpga")

    def test_lspci_fallback_without_sysfs(self):
        p = Fixture()
        p.directories.remove("/sys/bus/pci/devices")
        p.commands["lspci"] = "0000:01:00.0 Processing accelerators [1200]: Unknown [10ee:903f]\n"
        inv = hw.detect(probe=p)
        self.assertEqual(inv["pci"]["source"], "lspci")
        self.assertEqual(inv["accelerators"][0]["kind"], "fpga")
        self.assertEqual(inv["status"], "partial")

    def test_stale_lspci_row_not_resurrected(self):
        p = Fixture()
        p.commands["lspci"] = "0000:01:00.0 Processing accelerators [1200]: Unknown [10ee:903f]\n"
        self.assertEqual(hw.detect(probe=p)["pci"]["device_count"], 0)

    def test_disappearing_or_restricted_pci_keeps_other_devices(self):
        p = Fixture()
        path = p.pci("0000:01:00.0", "10ee", "903f", "120000")
        p.files[path + "/vendor"] = PermissionError()
        p.pci("0000:02:00.0", "177d", "9700", "0b4000")
        inv = hw.detect(probe=p)
        self.assertEqual(inv["pci"]["device_count"], 2)
        self.assertFalse(inv["pci"]["devices"][0]["identity_complete"])
        self.assertTrue(inv["specialized"]["octeon"]["present"])
        self.assertEqual(inv["probe_status"]["accelerators"], "partial")

    def test_bad_memory_does_not_erase_hardware(self):
        p = Fixture()
        p.files["/proc/meminfo"] = "MemTotal: broken kB"
        p.pci("0000:01:00.0", "10ee", "903f", "120000")
        inv = hw.detect(probe=p)
        self.assertEqual(inv["memory"]["total_gb"], 0)
        self.assertTrue(inv["specialized"]["fpga"]["present"])
        self.assertEqual(inv["probe_status"]["memory"], "partial")

    def test_probe_exception_is_reported_and_brief_still_works(self):
        with patch.object(hw, "detect_cpu", side_effect=RuntimeError("test failure")):
            inv = hw.detect(probe=Fixture())
        self.assertEqual(inv["probe_status"]["cpu"], "error")
        self.assertGreater(inv["memory"]["total_gb"], 0)
        with redirect_stdout(io.StringIO()) as out:
            hw._brief(inv)
        self.assertIn("test failure", out.getvalue())

    def test_optional_tool_failure_preserves_sysfs(self):
        p = Fixture()
        p.commands["lspci"] = subprocess.TimeoutExpired("lspci", 6)
        p.pci("0000:01:00.0", "10ee", "903f", "120000")
        inv = hw.detect(probe=p)
        self.assertTrue(inv["specialized"]["fpga"]["present"])
        self.assertIn("TimeoutExpired", str(inv["diagnostics"]))

    def test_cpu_sparse_ids_smt_numa_and_affinity(self):
        p = Fixture()
        p.files["/sys/devices/system/cpu/online"] = "0,2,8,10"
        p.files["/sys/devices/system/cpu/present"] = "0-15"
        p.files["/sys/devices/system/node/node3/cpulist"] = "8,10"
        p.allowed = [8, 10]
        for cpu, core, sibs in ((0, 0, "0,8"), (8, 0, "0,8"), (2, 1, "2,10"), (10, 1, "2,10")):
            base = "/sys/devices/system/cpu/cpu%d/topology/" % cpu
            p.files.update({base + "core_id": str(core), base + "physical_package_id": "0",
                            base + "thread_siblings_list": sibs})
        cpu = hw.detect_cpu(p)
        self.assertEqual(cpu["cores_logical"], 4)
        self.assertEqual(cpu["cores_physical"], 2)
        self.assertEqual(cpu["available_cpus"], [8, 10])
        self.assertEqual(cpu["numa_topology"], [{"id": 3, "cpus": [8, 10]}])

    def test_cpu_features_are_intersection_not_first_cpu(self):
        p = Fixture()
        p.files["/proc/cpuinfo"] = "processor : 0\nflags : aes avx2\n\nprocessor : 1\nflags : aes\n"
        cpu = hw.detect_cpu(p)
        self.assertEqual(cpu["crypto_ext"], ["aes"])

    def test_malformed_cpu_ranges_are_bounded(self):
        for spec in ("3-1", "0-999999999999", "cat", "-1"):
            with self.subTest(spec=spec), self.assertRaises(ValueError):
                hw._cpulist(spec)

    def test_generic_coprocessor_is_not_qat(self):
        p = Fixture()
        p.pci("0000:01:00.0", "1234", "0001", "0b4000")
        self.assertEqual(hw.detect(probe=p)["accelerators"][0]["role"], "Co-processor")

    def test_known_qat_driver(self):
        p = Fixture()
        p.pci("0000:01:00.0", "8086", "4940", "0b4000", "qat_4xxx")
        self.assertEqual(hw.detect(probe=p)["accelerators"][0]["role"], "Crypto (QAT)")

    def test_non_linux_is_explicitly_unsupported(self):
        p = Fixture(); p.os = "Windows"
        self.assertEqual(hw.detect(probe=p)["status"], "unsupported")

    def test_redetection_has_fresh_diagnostics_and_does_not_mutate_prior_snapshot(self):
        p = Fixture()
        p.files["/proc/meminfo"] = "MemTotal: invalid"
        first = hw.detect(probe=p)
        p.files["/proc/meminfo"] = "MemTotal: 1024000 kB"
        second = hw.detect(probe=p)
        self.assertEqual(first["status"], "partial")
        self.assertTrue(first["diagnostics"])
        self.assertEqual(second["status"], "ok")

    def test_storage_and_hugepages_survive_bad_neighbor(self):
        p = Fixture()
        p.files.update({"/sys/block/nvme0n1/size": "1953125", "/sys/block/sda/size": "bad",
                        "/sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages": "512",
                        "/sys/kernel/mm/hugepages/hugepages-2048kB/free_hugepages": "10",
                        "/proc/mounts": "none /huge hugetlbfs rw 0 0"})
        inv = hw.detect(probe=p)
        self.assertEqual(inv["storage"][0]["size_bytes"], 1000000000)
        self.assertEqual(inv["storage"][1]["size_gb"], 0)
        self.assertEqual(inv["hugepages"]["pools"][0]["total_gb"], 1)
        self.assertTrue(inv["hugepages"]["mounted"])

    def test_cpu_dies_with_repeated_core_id_are_distinct(self):
        p = Fixture()
        for cpu in (0, 1):
            base = "/sys/devices/system/cpu/cpu%d/topology/" % cpu
            p.files.update({base + "physical_package_id": "0", base + "core_id": "0", base + "die_id": str(cpu)})
        self.assertEqual(hw.detect_cpu(p)["cores_physical"], 2)


class TuningTests(unittest.TestCase):
    def test_management_role_for_specialized_processors_before_topology_selection(self):
        for kind in ("fpga", "npu", "coprocessor", "crypto", "accelerator", "gpu", "switch", "asic"):
            with self.subTest(kind=kind):
                inv = {"cpu": {"online_cpus": [0, 2, 8, 10], "cores_logical": 4},
                       "accelerators": [{"kind": kind}]}
                with patch.object(tuning, "smt_siblings", side_effect=AssertionError("premature CPU partitioning")):
                    plan = tuning.decide(inv=inv, decl={"cpu_isolation": "explicit", "isolate_cores": "8,10"})
                self.assertEqual(plan.cpu_role, "management")
                self.assertEqual(plan.housekeeping, [0, 2, 8, 10])
                self.assertEqual(plan.cores, [])
                self.assertEqual(plan.iommu, [])
                self.assertIsNone(plan.hugepages)
                self.assertEqual(tuning.render_cmdline(plan), "")

    def test_bmc_bridges_and_nic_functions_do_not_make_management_only_host(self):
        inv = {"accelerators": [{"kind": k} for k in ("bmc", "bridge", "npu-function", "unknown")]}
        self.assertEqual(hw.classify_cpu_role(inv)["role"], "shared")
        fixture = Fixture()
        fixture.pci("0000:01:00.0", "177d", "9700", "060400")
        self.assertEqual(hw.detect(probe=fixture)["cpu_role"]["role"], "shared")

    def test_incomplete_discovery_defers_cpu_partitioning(self):
        inv = {"cpu": {"cores_logical": 8}, "probe_status": {"pci": "error"}}
        self.assertEqual(tuning.decide(inv=inv).cpu_role, "unknown")
        self.assertEqual(tuning.decide(inv=inv).cores, [])

    def test_runtime_ignores_old_isolcpus_and_saved_dataplane_config(self):
        inv = {"cpu": {"online_cpus": [0, 2, 8, 10]}, "specialized": {"fpga": {"present": True}}}
        with patch.object(planes, "read_cmdline", return_value="isolcpus=8,10 nohz_full=8,10"), \
             patch("builtins.open", side_effect=AssertionError("saved core map read before hardware role")):
            cp = planes.CpuPlanes.from_system(ncpu=4, inventory=inv)
        self.assertEqual(cp.cores(planes.PLANE_MGMT), [0, 2, 8, 10])
        self.assertEqual(cp.data_cores, [])
        self.assertEqual(cp.assign_data_cores(4), [])
        self.assertEqual(cp.eal_lcore_args(cores=[8, 10]), [])
        self.assertEqual(cp.grub_isolcpus(), "")
        self.assertTrue(any("Running kernel still isolates" in w for w in cp.verify()))
        with self.assertRaises(ValueError):
            cp.spawn_worker(8, lambda: None)

    def test_runtime_auto_classifies_after_hardware_detection(self):
        inv = {"cpu": {"online_cpus": [0, 1, 2, 3]}, "dpu": {"present": True}}
        with patch.object(hw, "detect", return_value=inv) as detect:
            cp = planes.CpuPlanes.auto()
        detect.assert_called_once()
        self.assertEqual(cp.assignment["role"], "management")
        self.assertEqual(cp.data_cores, [])

    def test_fastest_nic_uses_numeric_speed_and_inventory_numa(self):
        inv = {"nics": [{"pci": "0000:01:00.0", "speed_mbps": 1000, "numa_node": 0},
                        {"pci": "0000:02:00.0", "speed_mbps": 100000, "numa_node": 3}]}
        with patch.object(tuning.ffn_hwdetect, "detect", return_value=inv), \
             patch.object(tuning, "find_platform_decl", return_value=({}, None)), \
             patch.object(tuning, "decide") as decide:
            tuning.build_plan("unused")
        self.assertEqual(decide.call_args.kwargs["nic_node"], 3)

    def test_sparse_cpu_plan_never_invents_offline_ids(self):
        ids = [0, 2, 8, 10, 12, 14]
        inv = {"cpu": {"online_cpus": ids, "cores_logical": 6}}
        plan = tuning.decide(inv=inv, sibs={i: [i] for i in ids}, mem_gb=16)
        self.assertTrue(plan.isolate)
        self.assertTrue(set(plan.cores).issubset(ids))
        self.assertEqual(sorted(plan.cores + plan.housekeeping), ids)
        self.assertNotIn(0, plan.cores)

    def test_affinity_restricted_host_refuses_kernel_tuning(self):
        inv = {"cpu": {"online_cpus": list(range(8)), "available_cpus": [6, 7], "cores_logical": 8}}
        self.assertFalse(tuning.decide(inv=inv, sibs={}).isolate)

    def test_specialized_presence_reserves_main_cpu_for_management(self):
        inv = {"cpu": {"cores_logical": 8}, "specialized": {"fpga": {"present": True}}}
        plan = tuning.decide(inv=inv, sibs={}, mem_gb=16)
        self.assertEqual(plan.datapath, "offload")
        self.assertEqual(plan.cpu_role, "management")
        self.assertFalse(plan.isolate)
        self.assertEqual(plan.housekeeping, list(range(8)))
        self.assertEqual(tuning.render_cmdline(plan), "")

    def test_arm_tuning_does_not_emit_intel_iommu_argument(self):
        inv = {"system": {"arch": "aarch64"}, "cpu": {"cores_logical": 8}}
        plan = tuning.decide(inv=inv, sibs={}, mem_gb=16)
        self.assertNotIn("intel_iommu=on", tuning.render_cmdline(plan))


class ProbeBoundaryTests(unittest.TestCase):
    def test_optional_command_timeout_is_bounded_and_reported(self):
        p = Probe()
        with patch("ffn_hwprobe.subprocess.run", side_effect=subprocess.TimeoutExpired("lspci", 6)) as run:
            self.assertEqual(p.run(["lspci", "-Dnn"]), "")
        self.assertEqual(run.call_args.kwargs["timeout"], 6)
        self.assertEqual(run.call_args.kwargs["env"]["LC_ALL"], "C")
        self.assertIn("TimeoutExpired", str(p.diagnostics))

    def test_permission_denial_is_distinguishable_from_empty(self):
        p = Probe()
        with patch("builtins.open", side_effect=PermissionError()):
            self.assertEqual(p.read("/sys/example", required=True), "")
        self.assertEqual(p.diagnostics[0]["message"], "PermissionError")


if __name__ == "__main__":
    unittest.main(verbosity=2)
