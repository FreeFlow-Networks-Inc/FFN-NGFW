#!/usr/bin/env python3
"""ffn_hwdetect.py -- FFN NGFW unified hardware autodetection.

Importable  : `from ffn_hwdetect import detect; inv = detect()`
CLI         : `ffn_hwdetect.py --json` | `--brief`

Every probe is best-effort and degrades gracefully: it reads sysfs/procfs
directly where possible and only shells out to optional tools (lspci, ethtool,
lsblk, dpdk-devbind) when present. Never raises -- missing data becomes "" / [].
Detects the full FFN chassis: system/DMI, CPU+NUMA+crypto, memory, every NIC
(driver/speed/PCI/DPDK-bind/role), the BlueField DPU / SmartNIC, accelerators
(FPGA/GPU/QAT), storage and hugepages.
"""
import os
import re
import glob
import json
import shutil
import subprocess

# PCI vendor ids of interest
V_MELLANOX = "15b3"   # NVIDIA/Mellanox ConnectX / BlueField DPU
V_XILINX   = "10ee"   # Xilinx FPGA (VU9P etc.)
V_ALTERA   = "1172"   # Intel/Altera FPGA
V_INTEL    = "8086"
# The forwarding silicon a reclaimed appliance actually carries. Without
# these three the detector matched only Xilinx and Altera, so a chassis with
# a packet processor, a front-end ASIC and a 40-core NPU reported
# "None detected" -- and that report was believed.
V_CAVIUM   = "177d"   # Cavium/Marvell OCTEON network processor
V_BROADCOM = "14e4"   # Broadcom -- the BCM88375 packet processor
V_PAN      = "feed"   # Palo Alto Networks -- the FE100 front-end ASIC
DPDK_DRIVERS = ("vfio-pci", "igb_uio", "uio_pci_generic", "mlx5_core")


def _run(cmd, timeout=6):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout if r.returncode == 0 else ""
    except Exception:
        return ""


def _read(path, default=""):
    try:
        with open(path) as f:
            return f.read().strip()
    except Exception:
        return default


def _have(tool):
    return shutil.which(tool) is not None


# --------------------------------------------------------------------------
def detect_system():
    d = "/sys/class/dmi/id"
    up = _read("/proc/uptime").split()
    try:
        uptime_s = int(float(up[0])) if up else 0
    except Exception:
        uptime_s = 0
    return {
        "vendor":       _read(f"{d}/sys_vendor"),
        "product":      _read(f"{d}/product_name"),
        "serial":       _read(f"{d}/product_serial") or "(restricted)",
        "board":        _read(f"{d}/board_name"),
        "bios_vendor":  _read(f"{d}/bios_vendor"),
        "bios_version": _read(f"{d}/bios_version"),
        "bios_date":    _read(f"{d}/bios_date"),
        "hostname":     os.uname().nodename,
        "kernel":       os.uname().release,
        "arch":         os.uname().machine,
        "uptime_s":     uptime_s,
    }


def detect_cpu():
    model = ""
    flags = set()
    sockets = set()
    try:
        for line in _read("/proc/cpuinfo").splitlines():
            if line.startswith("model name") and not model:
                model = line.split(":", 1)[1].strip()
            elif line.startswith("flags") and not flags:
                flags = set(line.split(":", 1)[1].split())
            elif line.startswith("physical id"):
                sockets.add(line.split(":", 1)[1].strip())
    except Exception:
        pass
    numa = len(glob.glob("/sys/devices/system/node/node[0-9]*"))
    crypto = [f for f in ("aes", "vaes", "sha_ni", "pclmulqdq",
                          "avx512f", "avx2") if f in flags]
    virt = "VT-x" if "vmx" in flags else ("AMD-V" if "svm" in flags else "")
    freq = ""
    try:
        khz = _read("/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq")
        if khz:
            freq = "%d MHz" % (int(khz) // 1000)
    except Exception:
        pass
    return {
        "model": model,
        "sockets": max(1, len(sockets)),
        "cores_physical": _cpu_count(logical=False),
        "cores_logical": os.cpu_count() or 0,
        "max_freq": freq,
        "numa_nodes": max(1, numa),
        "aes_ni": ("aes" in flags),
        "crypto_ext": crypto,
        "virtualization": virt,
        "isolated_cpus": _read("/sys/devices/system/cpu/isolated"),
    }


def _cpu_count(logical=True):
    # physical cores = distinct (physical id, core id) pairs
    if logical:
        return os.cpu_count() or 0
    seen = set()
    phys = None
    try:
        for line in _read("/proc/cpuinfo").splitlines():
            if line.startswith("physical id"):
                phys = line.split(":", 1)[1].strip()
            elif line.startswith("core id"):
                seen.add((phys, line.split(":", 1)[1].strip()))
    except Exception:
        pass
    return len(seen) or (os.cpu_count() or 0)


def detect_memory():
    total_kb = 0
    for line in _read("/proc/meminfo").splitlines():
        if line.startswith("MemTotal:"):
            total_kb = int(line.split()[1])
            break
    dimms = []
    if _have("dmidecode"):
        out = _run(["dmidecode", "-t", "memory"])
        cur = {}
        for ln in out.splitlines():
            ln = ln.strip()
            if ln.startswith("Memory Device"):
                if cur.get("size") and "No Module" not in cur.get("size", ""):
                    dimms.append(cur)
                cur = {}
            elif ln.startswith("Size:"):
                cur["size"] = ln.split(":", 1)[1].strip()
            elif ln.startswith("Speed:") and "speed" not in cur:
                cur["speed"] = ln.split(":", 1)[1].strip()
            elif ln.startswith("Locator:") and "locator" not in cur:
                cur["locator"] = ln.split(":", 1)[1].strip()
            elif ln.startswith("Manufacturer:"):
                cur["manufacturer"] = ln.split(":", 1)[1].strip()
        if cur.get("size") and "No Module" not in cur.get("size", ""):
            dimms.append(cur)
    return {
        "total_gb": round(total_kb / 1e6, 1),
        "dimms": dimms,
        "dimm_count": len(dimms),
    }


def _pci_of_netdev(name):
    link = "/sys/class/net/%s/device" % name
    try:
        return os.path.basename(os.readlink(link))
    except Exception:
        return ""


def _driver_of_pci(pci):
    if not pci:
        return ""
    try:
        return os.path.basename(os.readlink("/sys/bus/pci/devices/%s/driver" % pci))
    except Exception:
        return ""


def _pci_vendor_device(pci):
    if not pci:
        return ("", "")
    v = _read("/sys/bus/pci/devices/%s/vendor" % pci).replace("0x", "")
    d = _read("/sys/bus/pci/devices/%s/device" % pci).replace("0x", "")
    return (v, d)


def detect_nics():
    nics = []
    for path in sorted(glob.glob("/sys/class/net/*")):
        name = os.path.basename(path)
        if name == "lo":
            continue
        # skip purely virtual devices with no backing PCI/phys device unless
        # they are meaningful overlays (keep tun/zt/tmfifo, note as virtual)
        pci = _pci_of_netdev(name)
        driver = _driver_of_pci(pci) if pci else _read("%s/device/driver" % path)
        speed = _read("%s/speed" % path)
        _spd = int(speed) if speed.lstrip("-").isdigit() else 0
        _spd = max(0, _spd)                       # down links report -1
        oper = _read("%s/operstate" % path)
        mac = _read("%s/address" % path)
        mtu = _read("%s/mtu" % path)
        numa = _read("%s/device/numa_node" % path)
        ven, dev = _pci_vendor_device(pci)
        kind = "physical"
        low = name.lower()
        if not pci and (low.startswith("zt") or "tun" in low or low.startswith("wg")):
            kind = "overlay/virtual"
        elif low.startswith("tmfifo") or low.startswith("rshim"):
            kind = "dpu-control"
        elif ven == V_MELLANOX:
            kind = "smartnic/dpu-data"
        nics.append({
            "name": name, "kind": kind, "mac": mac, "state": oper,
            "speed_mbps": _spd,
            "mtu": (int(mtu) if mtu.isdigit() else 0),
            "driver": driver, "pci": pci,
            "vendor_id": ven, "device_id": dev,
            "numa_node": (int(numa) if numa.lstrip("-").isdigit() else -1),
        })
    # DPDK-bound NICs won't appear under /sys/class/net -- surface them from PCI
    for pci in glob.glob("/sys/bus/pci/devices/*"):
        addr = os.path.basename(pci)
        cls = _read("%s/class" % pci)
        if not cls.startswith("0x0200"):    # Ethernet controller class
            continue
        drv = _driver_of_pci(addr)
        if drv in ("vfio-pci", "igb_uio", "uio_pci_generic"):
            ven, dev = _pci_vendor_device(addr)
            nics.append({
                "name": "(dpdk)%s" % addr, "kind": "dpdk-bound",
                "mac": "", "state": "dpdk", "speed_mbps": 0, "mtu": 0,
                "driver": drv, "pci": addr, "vendor_id": ven, "device_id": dev,
                "numa_node": -1,
            })
    return nics


def detect_dpu():
    """BlueField / SmartNIC autodetect: PCI Mellanox devices + rshim + mst."""
    dpus = []
    # PCI Mellanox devices (ConnectX / BlueField)
    lspci = _run(["lspci", "-Dnn"]) if _have("lspci") else ""
    mlx_lines = [ln for ln in lspci.splitlines()
                 if ("15b3" in ln.lower() and
                     ("bluefield" in ln.lower() or "connectx" in ln.lower()
                      or "mellanox" in ln.lower() or "nvidia" in ln.lower()))]
    rshim = sorted(glob.glob("/dev/rshim*"))
    mst = sorted(glob.glob("/dev/mst/*"))
    tmfifo = [os.path.basename(p) for p in glob.glob("/sys/class/net/tmfifo_net*")]

    fw = {}
    if mst and _have("mlxfwmanager"):
        out = _run(["mlxfwmanager", "-d", mst[0], "--query"], timeout=10)
        for ln in out.splitlines():
            s = ln.strip()
            if s.startswith("FW ") or s.startswith("PSID"):
                parts = s.split()
                if s.startswith("PSID"):
                    fw["psid"] = parts[-1] if len(parts) > 1 else ""
                elif "Version" in s:
                    fw["fw_version"] = parts[-1]

    present = bool(mlx_lines or rshim or mst or tmfifo)
    if present:
        dpus.append({
            "present": True,
            "type": "BlueField / SmartNIC" if mlx_lines else "SmartNIC control",
            "pci_devices": [ln.strip() for ln in mlx_lines],
            "rshim": rshim,
            "mst": mst,
            "tmfifo_ifaces": tmfifo,
            "firmware": fw,
            "control_channels": {
                "rshim": bool(rshim), "mst": bool(mst), "tmfifo": bool(tmfifo),
            },
        })
    return {"present": present, "devices": dpus}


def detect_accelerators():
    """Accelerators and forwarding silicon on THIS HOST's PCI bus.

    "This host" is the limit worth stating. On a reclaimed PA-5200 the packet
    processor, the front-end ASIC and the dataplane NPU all hang off the
    control plane's own root complexes, so none of them appears here however
    many vendor ids this function learns -- the host sees the control-plane
    OCTEON and stops there. The manager merges the far side in from the CP's
    own inventory; what this returns is labelled bus="host" so the two are
    never confused.

    The vendor list previously stopped at Xilinx and Altera, which meant an
    appliance carrying three pieces of forwarding silicon reported
    "None detected".
    """
    accel = []
    lspci = _run(["lspci", "-Dnn"]) if _have("lspci") else ""
    for ln in lspci.splitlines():
        low = ln.lower()
        role = kind = None
        if ("[%s:" % V_XILINX) in low or "xilinx" in low or \
           ("[%s:" % V_ALTERA) in low or "altera" in low:
            role, kind = "FPGA", "fpga"
        elif "quickassist" in low or " qat" in low or "co-processor [0b40]" in low:
            role, kind = "Crypto (QAT)", "crypto"
        elif ("[%s:" % V_CAVIUM) in low or "cavium" in low or "octeon" in low:
            # A PCI bridge here is the OCTEON's own root complex, not a second
            # processor: one chip presents several functions, and counting them
            # as separate parts is how a single CN73XX became "3 instances".
            # One OCTEON presents several PCI functions -- the processor
            # itself, its root-complex bridges, and an NVMe-class function --
            # and counting them as separate parts is how a single CN73XX came
            # to be reported as "3 instances" of a dataplane.
            if "pci bridge" in low:
                role, kind = "NPU (root complex)", "bridge"
            elif "non-volatile memory" in low or "[0108]" in low:
                role, kind = "NPU (NVMe function)", "npu-function"
            else:
                role, kind = "NPU", "npu"
        elif ("[%s:8375]" % V_BROADCOM) in low:
            role, kind = "Packet processor", "switch"
        elif ("[%s:" % V_PAN) in low:
            role, kind = "Front-end ASIC", "asic"
        elif "3d controller" in low:
            role, kind = "GPU", "gpu"
        elif "vga compatible controller" in low:
            # ASPEED / Matrox onboard VGA is the BMC display, not an accelerator
            is_bmc = ("aspeed" in low or "[1a03:" in low or
                      "matrox" in low or "[102b:" in low)
            role, kind = ("BMC/VGA", "bmc") if is_bmc else ("GPU", "gpu")
        if role:
            accel.append({"role": role, "kind": kind, "bus": "host",
                          "pci": ln.strip()})
    return accel


def detect_storage():
    disks = []
    for path in sorted(glob.glob("/sys/block/*")):
        name = os.path.basename(path)
        if name.startswith(("loop", "ram", "dm-", "sr", "zram")):
            continue
        sect = _read("%s/size" % path)
        size_gb = round(int(sect) * 512 / 1e9, 1) if sect.isdigit() else 0
        disks.append({
            "name": name,
            "size_gb": size_gb,
            "model": _read("%s/device/model" % path),
            "rotational": _read("%s/queue/rotational" % path) == "1",
        })
    return disks


def detect_hugepages():
    pages = []
    for path in sorted(glob.glob("/sys/kernel/mm/hugepages/hugepages-*")):
        kb = os.path.basename(path).replace("hugepages-", "").replace("kB", "")
        nr = _read("%s/nr_hugepages" % path)
        free = _read("%s/free_hugepages" % path)
        try:
            size_mb = int(kb) // 1024
            nrn = int(nr or 0)
            if nrn:
                pages.append({
                    "size_mb": size_mb, "nr": nrn,
                    "free": int(free or 0),
                    "total_gb": round(size_mb * nrn / 1024, 2),
                })
        except Exception:
            pass
    mounted = "hugetlbfs" in _read("/proc/mounts")
    return {"pools": pages, "mounted": mounted}


def detect_pci_summary():
    lspci = _run(["lspci"]) if _have("lspci") else ""
    lines = [ln for ln in lspci.splitlines() if ln.strip()]
    return {"device_count": len(lines)}


def detect(refresh=True):
    return {
        "system":       detect_system(),
        "cpu":          detect_cpu(),
        "memory":       detect_memory(),
        "nics":         detect_nics(),
        "dpu":          detect_dpu(),
        "accelerators": detect_accelerators(),
        "storage":      detect_storage(),
        "hugepages":    detect_hugepages(),
        "pci":          detect_pci_summary(),
        "tools": {
            "lspci": _have("lspci"), "ethtool": _have("ethtool"),
            "dmidecode": _have("dmidecode"), "lsblk": _have("lsblk"),
            "mlxfwmanager": _have("mlxfwmanager"),
        },
    }


def _brief(inv):
    s = inv["system"]; c = inv["cpu"]; m = inv["memory"]
    print("System : %s %s (BIOS %s)" % (s["vendor"], s["product"], s["bios_version"]))
    print("CPU    : %s -- %d socket(s), %d cores / %d threads, %d NUMA%s" % (
        c["model"], c["sockets"], c["cores_physical"], c["cores_logical"],
        c["numa_nodes"], ", AES-NI" if c["aes_ni"] else ""))
    print("Memory : %.1f GB (%d DIMMs)" % (m["total_gb"], m["dimm_count"]))
    print("NICs   : %d" % len(inv["nics"]))
    for n in inv["nics"]:
        print("   %-16s %-16s %-8s %s %s" % (
            n["name"], n["kind"], n["state"],
            (str(n["speed_mbps"]) + "Mb") if n["speed_mbps"] else "",
            n["pci"]))
    print("DPU    : %s" % ("present" if inv["dpu"]["present"] else "none"))
    for d in inv["dpu"]["devices"]:
        for p in d["pci_devices"]:
            print("   %s" % p)
        print("   rshim=%s mst=%s tmfifo=%s" % (
            d["control_channels"]["rshim"], d["control_channels"]["mst"],
            d["control_channels"]["tmfifo"]))
    print("Accel  : %s" % (", ".join(a["role"] for a in inv["accelerators"]) or "none"))
    print("Storage: %s" % ", ".join("%s %.0fGB" % (d["name"], d["size_gb"])
                                     for d in inv["storage"]))
    hp = inv["hugepages"]
    print("Huge   : %s" % (", ".join("%dx%dMB" % (p["nr"], p["size_mb"])
                                      for p in hp["pools"]) or "none"))


if __name__ == "__main__":
    import sys
    inv = detect()
    if "--json" in sys.argv:
        print(json.dumps(inv, indent=2))
    else:
        _brief(inv)
