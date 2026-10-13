#!/usr/bin/env python3
"""
cpu_nic_manager.py -- Manage regular Ethernet NICs on the NGFW host.

Discovers non-FPGA network interfaces (Intel i350, X710, Mellanox, etc.),
configures IP addresses, VLANs, MTU, bonding, and bridging to FPGA ports.

Import the router in ffn_manager.py:

    from cpu_nic_manager import cpu_nic_router
    app.include_router(cpu_nic_router)
"""

import ipaddress
import json
import logging
import os
import re
import subprocess
from typing import Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

logger = logging.getLogger("ffn-cpu-nic")

cpu_nic_router = APIRouter(prefix="/api/cpu-nics", tags=["cpu-nics"])

# FPGA interface names to exclude from CPU NIC management
FPGA_IF_NAMES = {"ffn0", "ffn1", "ffn2", "ffn3",
                 "eth0_fpga", "eth1_fpga", "eth2_fpga", "eth3_fpga"}

# Path to persist the management interface designation
MGMT_CONF_PATH = os.getenv("FFN_MGMT_CONF", "/var/lib/ffn-ngfw/mgmt_nic.conf")

# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class NicConfig(BaseModel):
    ip_address: Optional[str] = None
    netmask: Optional[str] = None
    gateway: Optional[str] = None
    mtu: Optional[int] = None
    vlan_id: Optional[int] = None

class BridgeRequest(BaseModel):
    fpga_port: int   # 0-3

class BondRequest(BaseModel):
    bond_name: str = "bond0"
    mode: int = 1       # 0=balance-rr, 1=active-backup, 4=802.3ad
    members: list = []  # NIC names to bond

# ---------------------------------------------------------------------------
# System helpers (Linux netlink / ip commands)
# ---------------------------------------------------------------------------

def _run(cmd, check=True):
    """Run a shell command, return stdout. Silently no-op on non-Linux."""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=10, check=check
        )
        return result.stdout.strip()
    except FileNotFoundError:
        return ""
    except subprocess.CalledProcessError as exc:
        logger.warning("Command failed: %s -> %s", cmd, exc.stderr)
        raise


def _get_all_interfaces():
    """Return a list of dicts describing every network interface."""
    try:
        raw = _run(["ip", "-j", "addr", "show"], check=False)
        if not raw:
            return _sim_interfaces()
        return json.loads(raw)
    except Exception:
        return _sim_interfaces()


def _sim_interfaces():
    """Simulated interface list for development on non-Linux hosts."""
    return [
        {
            "ifname": "eno1",
            "operstate": "UP",
            "mtu": 1500,
            "link_type": "ether",
            "address": "aa:bb:cc:dd:00:01",
            "addr_info": [
                {"local": "192.168.1.10", "prefixlen": 24, "family": "inet"}
            ],
        },
        {
            "ifname": "eno2",
            "operstate": "UP",
            "mtu": 1500,
            "link_type": "ether",
            "address": "aa:bb:cc:dd:00:02",
            "addr_info": [],
        },
        {
            "ifname": "enp5s0f0",
            "operstate": "UP",
            "mtu": 9000,
            "link_type": "ether",
            "address": "aa:bb:cc:dd:10:01",
            "addr_info": [
                {"local": "10.99.0.1", "prefixlen": 24, "family": "inet"}
            ],
        },
        {
            "ifname": "enp5s0f1",
            "operstate": "DOWN",
            "mtu": 1500,
            "link_type": "ether",
            "address": "aa:bb:cc:dd:10:02",
            "addr_info": [],
        },
    ]


IFNAME = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.:-]{0,14}\Z")
BOND_NAMES = {"bond%d" % i: "bond%d" % i for i in range(8)}


def _known_nic(requested):
    """The inventory's own name for a manageable CPU NIC; the request only selects it.

    Only that string ever reaches a command line or a sysfs path, never the request's."""
    if not isinstance(requested, str) or not IFNAME.fullmatch(requested):
        raise HTTPException(status_code=400, detail="Invalid interface name")
    for nic in discover_cpu_nics():
        if nic["name"] == requested:
            return nic["name"]
    raise HTTPException(status_code=404, detail="NIC not found")


def _ipv4(value, what):
    try:
        return str(ipaddress.IPv4Address(value))
    except (ValueError, TypeError):
        raise HTTPException(status_code=400, detail="Invalid " + what)


def _bounded(value, what, low, high):
    try:
        number = int(value)
    except (ValueError, TypeError):
        raise HTTPException(status_code=400, detail="Invalid " + what)
    if not low <= number <= high:
        raise HTTPException(status_code=400, detail="%s must be %d to %d" % (what, low, high))
    return number


def _get_nic_stats(ifname):
    """Read interface stats from /sys/class/net or simulate."""
    stats_path = f"/sys/class/net/{ifname}/statistics"
    result = {}
    for counter in ["rx_bytes", "tx_bytes", "rx_packets", "tx_packets",
                    "rx_errors", "tx_errors", "rx_dropped", "tx_dropped"]:
        fpath = os.path.join(stats_path, counter)
        try:
            with open(fpath, "r") as f:
                result[counter] = int(f.read().strip())
        except (FileNotFoundError, ValueError):
            result[counter] = 0
    return result


def _get_driver_name(ifname):
    """Determine the kernel driver bound to this NIC."""
    try:
        link = os.readlink(f"/sys/class/net/{ifname}/device/driver")
        return os.path.basename(link)
    except (FileNotFoundError, OSError):
        return "unknown"


def _get_pci_address(ifname):
    """Determine PCI BDF for a NIC."""
    try:
        link = os.readlink(f"/sys/class/net/{ifname}/device")
        return os.path.basename(link)
    except (FileNotFoundError, OSError):
        return ""


def _is_fpga_nic(ifname):
    """Return True if this interface belongs to the FPGA."""
    if ifname in FPGA_IF_NAMES:
        return True
    drv = _get_driver_name(ifname)
    if drv in ("qdma", "xdma", "ffn_ngfw"):
        return True
    return False


def _get_mgmt_iface():
    """Return the name of the designated management interface."""
    try:
        with open(MGMT_CONF_PATH, "r") as f:
            return f.read().strip()
    except FileNotFoundError:
        return ""


def _set_mgmt_iface(ifname):
    os.makedirs(os.path.dirname(MGMT_CONF_PATH), exist_ok=True)
    with open(MGMT_CONF_PATH, "w") as f:
        f.write(ifname + "\n")


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------

def discover_cpu_nics():
    """Return list of non-FPGA NIC info dicts."""
    all_ifs = _get_all_interfaces()
    mgmt = _get_mgmt_iface()
    nics = []

    for iface in all_ifs:
        name = iface.get("ifname", "")
        if not name or name == "lo":
            continue
        if _is_fpga_nic(name):
            continue
        # Skip virtual / bridge / veth interfaces
        link_type = iface.get("link_type", "")
        if link_type not in ("ether", ""):
            continue

        addrs = iface.get("addr_info", [])
        ipv4 = ""
        prefix = 0
        for a in addrs:
            if a.get("family") == "inet":
                ipv4 = a.get("local", "")
                prefix = a.get("prefixlen", 0)
                break

        nics.append({
            "name": name,
            "mac": iface.get("address", ""),
            "ip_address": ipv4,
            "prefix_len": prefix,
            "mtu": iface.get("mtu", 1500),
            "state": iface.get("operstate", "UNKNOWN"),
            "driver": _get_driver_name(name),
            "pci": _get_pci_address(name),
            "is_management": name == mgmt,
        })

    return nics

# ---------------------------------------------------------------------------
# REST endpoints
# ---------------------------------------------------------------------------

@cpu_nic_router.get("")
async def list_cpu_nics():
    """List all non-FPGA Ethernet interfaces on the host."""
    nics = discover_cpu_nics()
    return {"cpu_nics": nics, "count": len(nics)}


@cpu_nic_router.put("/{name}/config")
async def configure_nic(name: str, cfg: NicConfig):
    """Set IP/mask/gateway/VLAN/MTU on a CPU NIC."""
    name = _known_nic(name)

    actions = []

    # Flush existing addresses if setting a new IP
    if cfg.ip_address and cfg.netmask:
        address = _ipv4(cfg.ip_address, "address")
        prefix = _bounded(_mask_to_prefix(_ipv4(cfg.netmask, "netmask")), "prefix length", 0, 32)
        try:
            _run(["ip", "addr", "flush", "dev", name])
            _run(["ip", "addr", "add", f"{address}/{prefix}",
                  "dev", name])
            actions.append(f"ip={address}/{prefix}")
        except Exception as exc:
            raise HTTPException(status_code=500, detail=str(exc))

    if cfg.gateway:
        gateway = _ipv4(cfg.gateway, "gateway")
        try:
            _run(["ip", "route", "replace", "default", "via", gateway,
                  "dev", name], check=False)
            actions.append(f"gw={gateway}")
        except Exception as exc:
            raise HTTPException(status_code=500, detail=str(exc))

    if cfg.mtu:
        mtu = _bounded(cfg.mtu, "mtu", 68, 9216)
        try:
            _run(["ip", "link", "set", name, "mtu", str(mtu)])
            actions.append(f"mtu={mtu}")
        except Exception as exc:
            raise HTTPException(status_code=500, detail=str(exc))

    if cfg.vlan_id is not None and cfg.vlan_id > 0:
        vlan = _bounded(cfg.vlan_id, "vlan id", 1, 4094)
        vlan_if = f"{name}.{vlan}"
        try:
            _run(["ip", "link", "add", "link", name, "name", vlan_if,
                  "type", "vlan", "id", str(vlan)])
            _run(["ip", "link", "set", vlan_if, "up"])
            actions.append(f"vlan={vlan}")
        except Exception as exc:
            raise HTTPException(status_code=500, detail=str(exc))

    return {"status": "configured", "nic": name, "actions": actions}


@cpu_nic_router.post("/{name}/bridge")
async def bridge_to_fpga(name: str, req: BridgeRequest):
    """Bridge a CPU NIC to an FPGA port."""
    if req.fpga_port < 0 or req.fpga_port > 3:
        raise HTTPException(status_code=400, detail="fpga_port must be 0-3")
    name = _known_nic(name)

    bridge_name = f"br_ffn{req.fpga_port}"
    fpga_if = f"ffn{req.fpga_port}"

    try:
        # Create bridge if it does not exist
        _run(["ip", "link", "add", bridge_name, "type", "bridge"],
             check=False)
        _run(["ip", "link", "set", bridge_name, "up"])

        # Add FPGA interface and CPU NIC to the bridge
        _run(["ip", "link", "set", fpga_if, "master", bridge_name],
             check=False)
        _run(["ip", "link", "set", name, "master", bridge_name],
             check=False)

        return {
            "status": "bridged",
            "bridge": bridge_name,
            "members": [fpga_if, name],
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@cpu_nic_router.get("/{name}/stats")
async def nic_stats(name: str):
    """Return interface statistics for a CPU NIC."""
    name = _known_nic(name)

    counters = _get_nic_stats(name)
    return {"nic": name, "stats": counters}


@cpu_nic_router.post("/{name}/set-management")
async def set_management(name: str):
    """Designate a NIC as the management interface."""
    name = _known_nic(name)

    _set_mgmt_iface(name)
    return {"status": "ok", "management_nic": name}


@cpu_nic_router.post("/{name}/dhcp/start")
async def dhcp_start(name: str):
    """Start DHCP client on a NIC."""
    name = _known_nic(name)

    try:
        # Kill any existing dhclient on this interface
        _run(["pkill", "-f", f"dhclient.*{name}"], check=False)
        _run(["dhclient", "-v", name])
        return {"status": "dhcp_started", "nic": name}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@cpu_nic_router.post("/{name}/dhcp/stop")
async def dhcp_stop(name: str):
    """Stop DHCP client on a NIC."""
    name = _known_nic(name)
    try:
        _run(["dhclient", "-r", name], check=False)
        _run(["pkill", "-f", f"dhclient.*{name}"], check=False)
        return {"status": "dhcp_stopped", "nic": name}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@cpu_nic_router.post("/bond")
async def create_bond(req: BondRequest):
    """Create a bonded interface from multiple CPU NICs."""
    mode_map = {0: "balance-rr", 1: "active-backup", 4: "802.3ad"}
    mode_str = mode_map.get(req.mode, "active-backup")
    bond_name = BOND_NAMES.get(req.bond_name)
    if bond_name is None:
        raise HTTPException(status_code=400, detail="bond_name must be bond0 to bond7")
    members = [_known_nic(member) for member in req.members]

    try:
        # Create bond master
        _run(["ip", "link", "add", bond_name, "type", "bond",
              "mode", mode_str])
        _run(["ip", "link", "set", bond_name, "up"])

        # Enslave members
        for member in members:
            _run(["ip", "link", "set", member, "down"])
            _run(["ip", "link", "set", member, "master", bond_name])
            _run(["ip", "link", "set", member, "up"])

        return {
            "status": "created",
            "bond": bond_name,
            "mode": mode_str,
            "members": members,
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _mask_to_prefix(mask):
    """Convert dotted netmask to CIDR prefix length."""
    try:
        parts = [int(x) for x in mask.split(".")]
        bits = 0
        for p in parts:
            bits += bin(p).count("1")
        return bits
    except Exception:
        return 24
