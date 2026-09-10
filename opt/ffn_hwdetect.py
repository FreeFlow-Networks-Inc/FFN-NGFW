#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Read-only hardware inventory using numeric PCI identities and probe diagnostics.

Import: from ffn_hwdetect import detect; inventory = detect()
CLI: python opt/ffn_hwdetect.py --json | --brief
Detection is not proof of working offload. Existing field names remain available.
"""
import argparse
import json
import re
from datetime import datetime, timezone

from ffn_hwprobe import Probe

V_MELLANOX = "15b3"
V_XILINX = "10ee"
V_ALTERA = "1172"
V_INTEL = "8086"
V_CAVIUM = "177d"
V_BROADCOM = "14e4"
V_PAN = "feed"
USERSPACE_DRIVERS = ("vfio-pci", "igb_uio", "uio_pci_generic")
DPDK_DRIVERS = USERSPACE_DRIVERS + ("mlx5_core",)
# Linux mlx5 PCI table; see docs/hardware-detection.md for sources.
# A Mellanox vendor ID or a generic mlx5 VF is not sufficient DPU evidence.
BLUEFIELD_IDS = {"a2d2": "BlueField", "a2d3": "BlueField VF",
                 "a2d6": "BlueField-2", "a2dc": "BlueField-3", "a2df": "BlueField-4"}
OCTEON_IDS = {
    "0005": "OCTEON CN38XX", "0020": "OCTEON CN31XX", "0030": "OCTEON CN30XX",
    "0040": "OCTEON CN58XX", "0050": "OCTEON CN57XX", "0070": "OCTEON CN50XX",
    "0080": "OCTEON CN52XX", "0090": "OCTEON II CN63XX", "0091": "OCTEON II CN68XX",
    "0092": "OCTEON II CN65XX/CN66XX", "0093": "OCTEON II CN61XX",
    "0094": "OCTEON Fusion CNF71XX", "0095": "OCTEON III CN78XX",
    "0096": "OCTEON III CN70XX", "9700": "OCTEON III CN73XX",
    "9702": "OCTEON CN23XX", "9703": "OCTEON CN23XX NVMe function",
    "9712": "OCTEON CN23XX VF", "9713": "OCTEON CN23XX NVMe VF",
    "9800": "OCTEON Fusion CNF75XX", "a200": "OCTEON TX CN80XX/CN81XX",
    "a300": "OCTEON TX CN83XX", "a059": "OCTEON TX2 MAC",
    "a060": "OCTEON 10 MAC", "a063": "OCTEON TX2 RVU PF",
    "a064": "OCTEON TX2 RVU VF", "a065": "OCTEON TX2 RVU AF",
}
BDF = re.compile(r"^[0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-7]$", re.I)
TOOLS = ("lspci", "ethtool", "dmidecode", "lsblk", "mlxfwmanager")


def _basename(path):
    return path.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]


def _cpulist(value):
    """Strict and bounded: malformed topology must not invent CPU IDs."""
    cpus = set()
    for part in value.split(","):
        if not part.strip():
            continue
        match = re.fullmatch(r"(\d+)(?:-(\d+))?", part.strip())
        if not match:
            raise ValueError("Invalid CPU list")
        lo = int(match[1]); hi = int(match[2] or match[1])
        if hi < lo or hi > 1048575 or hi - lo > 65535:
            raise ValueError("Invalid CPU range")
        cpus.update(range(lo, hi + 1))
    return sorted(cpus)


def _cpu_ids(p, path):
    try:
        return _cpulist(p.read(path))
    except ValueError as exc:
        p.note(path, str(exc))
        return []


def _hex(p, path, digits):
    value = p.read(path, required=True).lower()
    if value.startswith("0x"):
        value = value[2:]
    if re.fullmatch("[0-9a-f]{%d}" % digits, value):
        return value
    if value:
        p.note(path, "Invalid PCI identifier")
    return ""


def detect_system(probe=None):
    p = probe or Probe()
    base = "/sys/class/dmi/id/"
    data = {key: p.read(base + file) for key, file in (
        ("vendor", "sys_vendor"), ("product", "product_name"),
        ("serial", "product_serial"), ("board", "board_name"),
        ("bios_vendor", "bios_vendor"), ("bios_version", "bios_version"),
        ("bios_date", "bios_date"))}
    data["serial"] = data["serial"] or "(restricted)"
    data["device_tree_model"] = p.read("/sys/firmware/devicetree/base/model")
    data["device_tree_compatible"] = [s for s in p.read("/sys/firmware/devicetree/base/compatible").split("\0") if s]
    data["product"] = data["product"] or data["device_tree_model"]
    data.update(p.host())
    try:
        data["uptime_s"] = max(0, int(float(p.read("/proc/uptime").split()[0])))
    except (ValueError, IndexError, OverflowError):
        data["uptime_s"] = 0
    return data


def detect_cpu(probe=None):
    p = probe or Probe()
    records = []
    for block in re.split(r"\n\s*\n", p.read("/proc/cpuinfo", required=True)):
        record = {}
        for line in block.splitlines():
            if ":" in line:
                key, value = line.split(":", 1)
                record[key.strip().lower()] = value.strip()
        if record:
            records.append(record)
    online = _cpu_ids(p, "/sys/devices/system/cpu/online")
    proc_ids = sorted({int(r["processor"]) for r in records if r.get("processor", "").isdigit()})
    online = online or proc_ids or list(range(p.cpu_count()))
    online_set = set(online)
    present = _cpu_ids(p, "/sys/devices/system/cpu/present") or online
    allowed = p.affinity()
    node_rows = []
    nodes = {}
    for path in p.glob("/sys/devices/system/node/node[0-9]*"):
        if not re.fullmatch(r"node\d+", _basename(path)):
            continue
        node = int(_basename(path)[4:])
        cpus = _cpu_ids(p, path + "/cpulist")
        node_rows.append({"id": node, "cpus": cpus})
        nodes.update({cpu: node for cpu in cpus})
    proc_by_id = {int(r["processor"]): r for r in records if r.get("processor", "").isdigit()}
    topology = []
    groups = set()
    sockets = set()
    for cpu in online:
        path = "/sys/devices/system/cpu/cpu%d/topology/" % cpu
        record = proc_by_id.get(cpu, {})
        package = p.number(path + "physical_package_id", default=-1)
        core = p.number(path + "core_id", default=-1)
        die = p.number(path + "die_id", default=-1)
        if package < 0 and record.get("physical id", "").isdigit():
            package = int(record["physical id"])
        if core < 0 and record.get("core id", "").isdigit():
            core = int(record["core id"])
        siblings = sorted(set(_cpu_ids(p, path + "thread_siblings_list")) & online_set)
        if package >= 0:
            sockets.add(package)
        if siblings:
            groups.add(("siblings", tuple(siblings)))
        elif package >= 0 and core >= 0:
            groups.add((package, die, core))
        else:
            groups.add(("unknown", cpu))
        topology.append({"cpu": cpu, "socket": package, "die": die, "core": core,
                         "siblings": siblings, "numa_node": nodes.get(cpu, -1)})
    feature_sets = [set(proc_by_id.get(cpu, {}).get("flags", proc_by_id.get(cpu, {}).get("features", "")).split())
                    for cpu in online]
    flags = set.intersection(*feature_sets) if feature_sets else set()
    model = next((r.get("model name") or r.get("cpu model") or r.get("hardware")
                  for r in records if r.get("model name") or r.get("cpu model") or r.get("hardware")), "")
    khz = max([p.number("/sys/devices/system/cpu/cpu%d/cpufreq/cpuinfo_max_freq" % c) for c in online] or [0])
    known = bool(topology) and all(t["siblings"] or (t["socket"] >= 0 and t["core"] >= 0) for t in topology)
    if not known:
        p.note("cpu/topology", "Physical core topology incomplete; count is an estimate")
    return {"model": model, "sockets": len(sockets) or (1 if online else 0),
            "cores_physical": len(groups), "cores_logical": len(online),
            "max_freq": "%d MHz" % (khz // 1000) if khz > 0 else "",
            "numa_nodes": len(node_rows) or (1 if online else 0),
            "aes_ni": "aes" in flags and p.host()["arch"].lower() in ("x86_64", "amd64", "i686"),
            "crypto_ext": [f for f in ("aes", "vaes", "sha_ni", "pclmulqdq", "avx512f", "avx2",
                                       "sha1", "sha2", "sha3", "pmull") if f in flags],
            "virtualization": "VT-x" if "vmx" in flags else ("AMD-V" if "svm" in flags else ""),
            "isolated_cpus": p.read("/sys/devices/system/cpu/isolated"),
            "online_cpus": online, "present_cpus": present,
            "available_cpus": sorted(online_set & set(allowed)) if allowed else online,
            "topology": topology, "topology_complete": known, "numa_topology": node_rows,
            "flags": sorted(flags)}


def detect_memory(probe=None):
    p = probe or Probe()
    total_kb = 0
    found = False
    for line in p.read("/proc/meminfo", required=True).splitlines():
        if line.startswith("MemTotal:"):
            found = True
            try:
                total_kb = max(0, int(line.split()[1]))
            except (ValueError, IndexError):
                p.note("/proc/meminfo", "Invalid MemTotal")
    if not found:
        p.note("/proc/meminfo", "MemTotal unavailable")
    dimms = []
    if p.have("dmidecode"):
        current = {}
        for line in (p.run(["dmidecode", "-t", "memory"]) + "\nMemory Device").splitlines():
            line = line.strip()
            if line == "Memory Device":
                if current.get("size") and "No Module" not in current["size"]:
                    dimms.append(current)
                current = {}
            elif ":" in line:
                key, value = line.split(":", 1)
                if key in ("Size", "Speed", "Locator", "Manufacturer"):
                    current.setdefault(key.lower(), value.strip())
    return {"total_gb": round(total_kb / 1e6, 1), "total_bytes": total_kb * 1024,
            "dimms": dimms, "dimm_count": len(dimms)}


def detect_pci_summary(probe=None):
    p = probe or Probe()
    labels = {}
    if p.have("lspci"):
        for line in p.run(["lspci", "-Dnn"]).splitlines():
            address = line.split(" ", 1)[0].lower()
            if BDF.fullmatch(address):
                labels[address] = line.strip()
    devices = []
    before_enumeration = len(p.diagnostics)
    paths = p.entries("/sys/bus/pci/devices")
    available = p.exists("/sys/bus/pci/devices") and not any(
        n["status"] == "unavailable" for n in p.diagnostics[before_enumeration:])
    for path in paths:
        address = _basename(path).lower()
        if not BDF.fullmatch(address):
            continue
        vendor = _hex(p, path + "/vendor", 4)
        device = _hex(p, path + "/device", 4)
        cls = _hex(p, path + "/class", 6)
        driver = _basename(p.link(path + "/driver"))
        pf = _basename(p.link(path + "/physfn"))
        group = _basename(p.link(path + "/iommu_group"))
        devices.append({"address": address, "vendor_id": vendor, "device_id": device,
                        "class_id": cls, "driver": driver, "numa_node": p.number(path + "/numa_node", -1),
                        "iommu_group": int(group) if group.isdigit() else None,
                        "physical_function": pf if BDF.fullmatch(pf) else "",
                        "sriov_totalvfs": max(0, p.number(path + "/sriov_totalvfs")),
                        "sriov_numvfs": max(0, p.number(path + "/sriov_numvfs")),
                        "local_cpus": _cpu_ids(p, path + "/local_cpulist"),
                        "description": labels.get(address, "%s [%s:%s] class %s" % (address, vendor, device, cls)),
                        "source": "sysfs", "identity_complete": bool(vendor and device and cls)})
    # Do not resurrect removed devices from stale lspci output when sysfs exists.
    if not available:
        for address, label in sorted(labels.items()):
            ids = re.search(r"\[([0-9a-f]{4})\].*\[([0-9a-f]{4}):([0-9a-f]{4})\]", label, re.I)
            if ids:
                devices.append({"address": address, "class_id": ids[1].lower() + "00",
                                "vendor_id": ids[2].lower(), "device_id": ids[3].lower(),
                                "driver": "", "numa_node": -1, "iommu_group": None,
                                "physical_function": "", "sriov_totalvfs": 0, "sriov_numvfs": 0,
                                "local_cpus": [], "description": label, "source": "lspci",
                                "identity_complete": True})
    return {"device_count": len(devices), "devices": devices, "available": available or bool(devices),
            "source": "sysfs" if available else "lspci" if devices else "unavailable"}


def _bluefield(device):
    return BLUEFIELD_IDS.get(device.get("device_id"), "") if device.get("vendor_id") == V_MELLANOX else ""


def _octeon(device):
    if device.get("vendor_id") != V_CAVIUM:
        return ""
    model = OCTEON_IDS.get(device.get("device_id"), "")
    if model:
        return model
    # New IDs remain discoverable when local pci.ids knows them, with that
    # evidence labelled. ThunderX and Nitrox must not become OCTEON by vendor.
    if "octeon" in device.get("description", "").lower():
        return "OCTEON (generation unknown)"
    if device.get("driver", "").startswith(("octeon", "liquidio")):
        return "OCTEON (driver identified)"
    return ""


def detect_nics(probe=None, pci=None):
    p = probe or Probe()
    pci = pci if pci is not None else detect_pci_summary(p)
    by_address = {d["address"]: d for d in pci["devices"]}
    nics = []
    seen = set()
    for path in p.entries("/sys/class/net"):
        name = _basename(path)
        if name == "lo":
            continue
        backing = p.link(path + "/device")
        address = _basename(backing).lower()
        # USB links are not PCI BDFs. Only virtio may inherit a PCI ancestor;
        # otherwise a USB NIC would be mistaken for its host USB controller.
        if not BDF.fullmatch(address):
            matches = [part.lower() for part in backing.split("/") if BDF.fullmatch(part)]
            address = matches[-1] if "virtio" in backing and matches else ""
        device = by_address.get(address, {})
        driver = _basename(p.link(path + "/device/driver")) or device.get("driver", "")
        virtual = not backing
        kind = "virtual" if virtual else "physical"
        if name.startswith(("tmfifo", "rshim")):
            kind = "dpu-control"
        elif virtual and name.startswith(("zt", "tun", "tap", "wg")):
            kind = "overlay/virtual"
        elif _bluefield(device):
            kind = "dpu-data"
        elif device.get("physical_function"):
            kind = "sriov-vf"
        elif driver.startswith("virtio"):
            kind = "virtual"
        elif device.get("vendor_id") == V_MELLANOX:
            kind = "nic/rdma"
        speed = max(0, p.number(path + "/speed"))
        nics.append({"name": name, "kind": kind, "mac": p.read(path + "/address"),
                     "state": p.read(path + "/operstate"), "speed_mbps": speed,
                     "mtu": max(0, p.number(path + "/mtu")), "driver": driver, "pci": address,
                     "vendor_id": device.get("vendor_id", ""), "device_id": device.get("device_id", ""),
                     "numa_node": device.get("numa_node", p.number(path + "/device/numa_node", -1)),
                     "iommu_group": device.get("iommu_group"),
                     "physical_function": device.get("physical_function", ""),
                     "sriov_totalvfs": device.get("sriov_totalvfs", 0),
                     "sriov_numvfs": device.get("sriov_numvfs", 0),
                     "phys_port_name": p.read(path + "/phys_port_name"),
                     "phys_switch_id": p.read(path + "/phys_switch_id"),
                     "binding": "kernel", "source": "sysfs"})
        seen.add(address)
    for address, device in sorted(by_address.items()):
        if address in seen or not device["class_id"].startswith("02"):
            continue
        driver = device["driver"]
        userspace = driver in USERSPACE_DRIVERS
        # Unbound NICs count too: absence of a netdev is not absence of hardware.
        nics.append({"name": "(%s)%s" % ("dpdk" if userspace else "pci", address),
                     "kind": "dpdk-bound" if userspace else "pci-network",
                     "mac": "", "state": "dpdk" if userspace else "no-netdev",
                     "speed_mbps": 0, "mtu": 0, "pci": address, "driver": driver,
                     "vendor_id": device["vendor_id"], "device_id": device["device_id"],
                     "numa_node": device["numa_node"], "iommu_group": device["iommu_group"],
                     "physical_function": device["physical_function"],
                     "sriov_totalvfs": device["sriov_totalvfs"], "sriov_numvfs": device["sriov_numvfs"],
                     "phys_port_name": "", "phys_switch_id": "",
                     "binding": "userspace" if userspace else "kernel" if driver else "unbound",
                     "source": device["source"]})
    return sorted(nics, key=lambda n: (n["pci"], n["name"]))


def detect_dpu(probe=None, pci=None):
    p = probe or Probe()
    pci = pci if pci is not None else detect_pci_summary(p)
    rshim = p.glob("/dev/rshim*")
    mst = p.glob("/dev/mst/*")
    tmfifo = [_basename(path) for path in p.glob("/sys/class/net/tmfifo_net*")]
    devices = []
    # Group multi-function endpoints by slot. Keep control channels host-level:
    # never attach one card's rshim or firmware to a different card.
    slots = {}
    for device in pci["devices"]:
        if _bluefield(device):
            slots.setdefault(device["address"].rsplit(".", 1)[0], []).append(device)
    for slot, rows in sorted(slots.items()):
        devices.append({"present": True, "type": _bluefield(rows[0]), "slot": slot,
                        "pci_devices": [row["description"] for row in rows],
                        "pci_addresses": [row["address"] for row in rows],
                        "evidence": ["pci-id:%s:%s" % (row["vendor_id"], row["device_id"]) for row in rows],
                        "rshim": [], "mst": [], "tmfifo_ifaces": [], "firmware": {},
                        "control_channels": {"rshim": False, "mst": False, "tmfifo": False}})
    if (rshim or tmfifo) and not devices:
        devices.append({"present": True, "type": "DPU control (model unknown)",
                        "pci_devices": [], "pci_addresses": [], "evidence": rshim + tmfifo,
                        "rshim": rshim, "mst": [], "tmfifo_ifaces": tmfifo, "firmware": {},
                        "control_channels": {"rshim": bool(rshim), "mst": False, "tmfifo": bool(tmfifo)}})
    return {"present": bool(devices), "devices": devices,
            "control_channels": {"rshim": rshim, "mst": mst, "tmfifo_ifaces": tmfifo},
            "note": "MST or a Mellanox vendor ID alone does not establish DPU presence; operating mode and offload readiness are not probed."}


def detect_accelerators(probe=None, pci=None):
    p = probe or Probe()
    pci = pci if pci is not None else detect_pci_summary(p)
    result = []
    for device in pci["devices"]:
        if not device["identity_complete"]:
            continue
        vendor, cls = device["vendor_id"], device["class_id"]
        role = kind = ""
        if vendor in (V_XILINX, V_ALTERA) and not cls.startswith("06"):
            role, kind = "FPGA", "fpga"
        elif device["driver"].startswith("qat_") or (vendor == V_INTEL and "quickassist" in device["description"].lower()):
            role, kind = "Crypto (QAT)", "crypto"
        elif cls.startswith("10"):
            role, kind = "Encryption controller", "crypto"
        elif _octeon(device):
            if cls.startswith("06"):
                role, kind = "NPU (root complex)", "bridge"
            elif cls.startswith("0108"):
                role, kind = "NPU (NVMe function)", "npu-function"
            else:
                role, kind = "NPU", "npu"
        elif vendor == V_CAVIUM:
            # Preserve unknown Cavium functions without claiming they are a
            # processor. This vendor also supplies ThunderX, Nitrox and bridges.
            role, kind = ("Cavium bridge", "bridge") if cls.startswith("06") else ("Cavium device (unclassified)", "unknown")
        elif vendor == V_BROADCOM and device["device_id"] == "8375":
            role, kind = "Packet processor", "switch"
        elif vendor == V_PAN:
            role, kind = "Front-end ASIC", "asic"
        elif cls.startswith("03"):
            role, kind = ("BMC/VGA", "bmc") if vendor in ("1a03", "102b") else ("GPU", "gpu")
        elif cls.startswith("0b40"):
            role, kind = "Co-processor", "coprocessor"
        elif cls.startswith("12"):
            role, kind = "Processing accelerator", "accelerator"
        if role:
            result.append({"role": role, "kind": kind, "bus": "host", "pci": device["description"],
                           "address": device["address"], "vendor_id": vendor,
                           "device_id": device["device_id"], "class_id": cls,
                           "model": _octeon(device),
                           "driver": device["driver"], "numa_node": device["numa_node"],
                           "source": device["source"], "evidence": "PCI identity/class and bound driver"})
    # SoC/platform FPGAs do not have to appear on PCI. FPGA Manager is the
    # standard kernel interface; reading its state never loads a bitstream.
    for path in p.glob("/sys/class/fpga_manager/*"):
        name = p.read(path + "/name", required=True)
        state = p.read(path + "/state")
        backing = p.link(path + "/device")
        addresses = [part.lower() for part in backing.split("/") if BDF.fullmatch(part)]
        match = next((row for row in result if row["kind"] == "fpga" and row["address"] in addresses), None)
        manager = {"path": path, "name": name, "state": state}
        if match is not None:
            match.setdefault("managers", []).append(manager)
        else:
            result.append({"role": "FPGA", "kind": "fpga", "bus": "platform",
                           "pci": name or _basename(path), "address": "", "model": name,
                           "driver": _basename(p.link(path + "/device/driver")),
                           "numa_node": p.number(path + "/device/numa_node", -1),
                           "source": "fpga_manager", "evidence": path,
                           "managers": [manager]})
    return result


def detect_specialized(system, cpu, pci, accelerators):
    evidence = []
    if "octeon" in cpu.get("model", "").lower():
        evidence.append({"source": "/proc/cpuinfo", "value": cpu["model"]})
    for compatible in system.get("device_tree_compatible", []):
        if re.match(r"^(cavium|marvell),octeon", compatible, re.I):
            evidence.append({"source": "device-tree/compatible", "value": compatible})
    functions = [dict(device, model=_octeon(device)) for device in pci["devices"] if _octeon(device)]
    # These are PCI slots/functions, not a physical chip count. On-SoC PCI
    # functions can occupy multiple slots, and SR-IOV VFs are not extra chips.
    return {"octeon": {"present": bool(evidence or functions), "host_cpu": bool(evidence),
                       "evidence": evidence, "pci_functions": functions,
                       "pci_slots": sorted({d["address"].rsplit(".", 1)[0] for d in functions})},
            "fpga": {"present": any(a["kind"] == "fpga" for a in accelerators),
                     "devices": [a for a in accelerators if a["kind"] == "fpga"]},
            "offload_ready": None,
            "note": "Presence does not establish loaded firmware, platform compatibility, remote-bus inventory, or forwarding readiness."}


def detect_storage(probe=None):
    p = probe or Probe()
    disks = []
    for path in p.entries("/sys/block"):
        name = _basename(path)
        if name.startswith(("loop", "ram", "dm-", "sr", "zram")):
            continue
        sectors = max(0, p.number(path + "/size"))
        disks.append({"name": name, "size_gb": round(sectors * 512 / 1e9, 1),
                      "size_bytes": sectors * 512, "model": p.read(path + "/device/model"),
                      "rotational": p.read(path + "/queue/rotational") == "1",
                      "removable": p.read(path + "/removable") == "1", "read_only": p.read(path + "/ro") == "1"})
    return disks


def detect_hugepages(probe=None):
    p = probe or Probe()
    pages = []
    for path in p.glob("/sys/kernel/mm/hugepages/hugepages-*"):
        match = re.fullmatch(r"hugepages-(\d+)kB", _basename(path))
        if not match:
            p.note(path, "Invalid hugepage pool name")
            continue
        kb = int(match[1]); nr = max(0, p.number(path + "/nr_hugepages"))
        if nr:
            pages.append({"size_mb": kb // 1024, "size_kb": kb, "nr": nr,
                          "free": max(0, p.number(path + "/free_hugepages")),
                          "total_gb": round(kb * nr / 1048576, 2)})
    return {"pools": pages, "mounted": any(len(line.split()) > 2 and line.split()[2] == "hugetlbfs"
                                            for line in p.read("/proc/mounts").splitlines())}


def classify_cpu_role(inventory, declaration=None):
    """Assign host responsibility AFTER hardware discovery, before CPU tuning.

    This is allocation policy, not a claim that the detected devices are ready
    to forward. Bridges, storage functions and BMC displays are not dataplanes.
    """
    inv = inventory or {}
    specialized = inv.get("specialized") or {}
    evidence = []
    if (specialized.get("fpga") or {}).get("present"):
        evidence.append("fpga")
    octeon = specialized.get("octeon") or {}
    if octeon.get("host_cpu") or (octeon.get("present") and "pci_functions" not in octeon):
        evidence.append("octeon")
    elif any(not d.get("class_id", "").startswith(("06", "0108"))
             and not d.get("physical_function") and " VF" not in d.get("model", "")
             for d in octeon.get("pci_functions", [])):
        evidence.append("octeon")
    if (inv.get("dpu") or {}).get("present"):
        evidence.append("dpu")
    for device in inv.get("accelerators") or []:
        if device.get("kind") in ("fpga", "npu", "coprocessor", "crypto", "accelerator", "gpu", "switch", "asic"):
            evidence.append(device["kind"])
    if (declaration or {}).get("datapath") == "offload":
        evidence.append("platform-offload")
    evidence = sorted(set(evidence))
    if evidence:
        return {"role": "management", "cpu_isolation": "none", "evidence": evidence,
                "reason": "Specialized hardware detected (%s); the main CPU is the management plane. No host dataplane cores are reserved." % ", ".join(evidence),
                "offload_ready": None}
    statuses = inv.get("probe_status") or {}
    if inv.get("status") == "unsupported" or any(statuses.get(k) in ("partial", "error") for k in ("pci", "accelerators", "dpu", "specialized")):
        return {"role": "unknown", "cpu_isolation": "none", "evidence": [],
                "reason": "Hardware discovery is incomplete; defer CPU partitioning until hardware roles are known.",
                "offload_ready": None}
    return {"role": "shared", "cpu_isolation": "auto", "evidence": [],
            "reason": "No specialized processing hardware detected; host CPUs serve management, control and software dataplane workloads.",
            "offload_ready": None}


def detect(refresh=True, probe=None):
    """Fresh inventory; refresh is retained for compatibility. The manager owns
    caching. Inject a Probe for deterministic tests without touching hardware."""
    p = probe or Probe()
    p.diagnostics = []
    inventory = {"schema_version": 2, "collected_at": datetime.now(timezone.utc).isoformat()}
    sections = {}

    def collect(name, function, fallback):
        p.section = name
        start = len(p.diagnostics)
        try:
            value = function()
        except Exception as exc:
            p.note(name, type(exc).__name__ + ": " + str(exc)[:160], "error")
            value = fallback
        notes = p.diagnostics[start:]
        sections[name] = "error" if any(n["status"] == "error" for n in notes) else "partial" if notes else "ok"
        inventory[name] = value
        return value

    collect("system", lambda: detect_system(p), {})
    collect("cpu", lambda: detect_cpu(p), {})
    collect("memory", lambda: detect_memory(p), {"total_gb": 0, "dimms": [], "dimm_count": 0})
    pci = collect("pci", lambda: detect_pci_summary(p), {"device_count": 0, "devices": [], "available": False, "source": "unavailable"})
    collect("nics", lambda: detect_nics(p, pci), [])
    collect("dpu", lambda: detect_dpu(p, pci), {"present": False, "devices": []})
    collect("accelerators", lambda: detect_accelerators(p, pci), [])
    collect("specialized", lambda: detect_specialized(inventory["system"], inventory["cpu"], pci, inventory["accelerators"]), {})
    collect("storage", lambda: detect_storage(p), [])
    collect("hugepages", lambda: detect_hugepages(p), {"pools": [], "mounted": False})
    inventory["tools"] = {name: p.have(name) for name in TOOLS}
    if any(sections[name] != "ok" for name in ("cpu", "system", "accelerators")) and sections["specialized"] == "ok":
        sections["specialized"] = "partial"
    if sections["pci"] != "ok":
        for name in ("nics", "dpu", "accelerators", "specialized"):
            if sections[name] == "ok":
                sections[name] = "partial"
    inventory["diagnostics"] = p.diagnostics
    inventory["probe_status"] = sections
    inventory["status"] = "partial" if p.diagnostics else "ok"
    if inventory["system"].get("os") and inventory["system"]["os"] != "Linux":
        inventory["status"] = "unsupported"
    inventory["cpu_role"] = classify_cpu_role(inventory)
    inventory["cpu"]["role"] = inventory["cpu_role"]["role"]
    return inventory


def _brief(inv):
    system = inv.get("system", {}); cpu = inv.get("cpu", {}); memory = inv.get("memory", {})
    print("Status : %s" % inv.get("status", "unknown"))
    print("System : %s %s" % (system.get("vendor", ""), system.get("product", "")))
    print("CPU    : %s -- %s cores / %s threads, %s NUMA" %
          (cpu.get("model", ""), cpu.get("cores_physical", "?"), cpu.get("cores_logical", "?"), cpu.get("numa_nodes", "?")))
    print("Memory : %.1f GB" % memory.get("total_gb", 0))
    print("CPU role: %s" % inv.get("cpu_role", {}).get("role", "unknown"))
    print("PCI    : %s devices (%s)" % (inv["pci"]["device_count"], inv["pci"].get("source", "unknown")))
    for nic in inv["nics"]:
        print("NIC    : %-16s %-16s %sMb NUMA=%s %s" %
              (nic["name"], nic["kind"], nic["speed_mbps"], nic["numa_node"], nic["driver"]))
    print("DPU    : %s" % (", ".join(d["type"] for d in inv["dpu"]["devices"]) or "none observed"))
    print("Accel  : %s" % (", ".join(a["role"] for a in inv["accelerators"]) or "none observed"))
    octeon = inv.get("specialized", {}).get("octeon", {})
    print("OCTEON : %s" % ("host CPU" if octeon.get("host_cpu") else "PCI functions present" if octeon.get("present") else "none observed"))
    print("Storage: %s" % ", ".join("%s %.0fGB" % (d["name"], d["size_gb"]) for d in inv["storage"]))
    print("Huge   : %s" % (", ".join("%dx%dMB" % (d["nr"], d["size_mb"]) for d in inv["hugepages"]["pools"]) or "none"))
    for note in inv.get("diagnostics", []):
        print("Probe  : %s: %s (%s)" % (note["section"], note["message"], note["source"]))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    output = parser.add_mutually_exclusive_group()
    output.add_argument("--json", action="store_true")
    output.add_argument("--brief", action="store_true")
    args = parser.parse_args()
    inventory = detect()
    if args.json:
        print(json.dumps(inventory, indent=2))
    else:
        _brief(inventory)
