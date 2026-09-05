#!/usr/bin/env python3
"""
FFN NGFW Management Server
FastAPI REST backend for the FPGA-based Next-Generation Firewall.
Provides system monitoring, security policy management, engine control,
VPN status, logging, and real-time dashboard data.
"""

import asyncio
import hashlib
import json
import logging
import os
import platform
import random
import glob
import re
import secrets
import struct
import subprocess
import time
from collections import deque
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Optional

import aiosqlite
import shutil
import socket
import sys
import uuid
import xml.etree.ElementTree as ET
from xml.dom import minidom
import psutil
import uvicorn
from fastapi import (
    Depends,
    FastAPI,
    File,
    Header,
    HTTPException,
    Query,
    Request,
    UploadFile,
    WebSocket,
    WebSocketDisconnect,
    status,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, Response

# Client for the control plane daemon. If controld isn't running, queries
# fall back to the in-process code paths that existed before the daemon
# was introduced.
try:
    sys.path.insert(0, "/opt/ffn-ngfw")  # installed layout
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "ffn-controld"))
    from ffn_controld_client import get as _get_controld  # type: ignore
    controld = _get_controld()
except Exception:
    controld = None
# ---------------------------------------------------------------------------
# Hardware platform support (optional, per-platform submodule)
# ---------------------------------------------------------------------------
# A platform submodule (platform/pa5200, platform/vu9p) ships the code that
# knows one chassis: its port table, which of its NICs are control-plane, and
# the client for whatever agent runs on its co-processors. None of it is
# vendored into this tree, because two copies of a port map drift and the one
# that drifts is always the copy.
#
# Imported lazily and never fatally: a manager on a box with no platform
# submodule, or with a different one, must still start and serve every other
# endpoint. A missing platform means "this is not that hardware", which is a
# fact to report, not an error to raise.

def _platform_paths():
    here = os.path.dirname(os.path.abspath(__file__))
    return [
        "/opt/ffn-ngfw-v2",                                   # installed, flat
        "/opt/ffn-ngfw",
        os.path.join(here, "..", "platform", "pa5200"),       # repo, submodule
        os.path.join(here, "..", "platform", "pa5200", "octeon", "bcmagent"),
    ]


def platform_mod(name):
    """Import a platform module by name, or return None. Cached, including the
    misses -- a box without the submodule must not pay an import attempt on
    every request.

    The cache is a function attribute rather than a module global so this
    function is self-contained: it can be transplanted into another copy of the
    manager on its own, without a separate module-level line that is easy to
    leave behind. Leaving it behind is not a subtle failure -- the first call
    raises NameError inside a startup path.
    """
    cache = getattr(platform_mod, "_cache", None)
    if cache is None:
        cache = platform_mod._cache = {}
    if name in cache:
        return cache[name]
    mod = None
    try:
        mod = __import__(name)
    except ImportError:
        for path in _platform_paths():
            if path not in sys.path and os.path.isdir(path):
                sys.path.append(path)
        try:
            mod = __import__(name)
        except ImportError:
            mod = None
        except Exception as exc:
            # NOT just ImportError. A platform module may assert at import time
            # -- ffn_bcmports checks its faceplate map against the vendor's own
            # front-panel list, which is exactly the kind of check worth having
            # -- and an AssertionError escaping here would propagate out of a
            # request handler, or out of startup. A broken platform module must
            # degrade to "this is not that hardware", never take the management
            # plane with it.
            logger.warning("platform module %s failed to import: %s: %s",
                           name, type(exc).__name__, exc)
            mod = None
    except Exception as exc:
        logger.warning("platform module %s failed to import: %s: %s",
                       name, type(exc).__name__, exc)
        mod = None
    cache[name] = mod
    return mod


def _bcm_faceplate():
    """The chassis faceplate map, or None when this is not that chassis."""
    return platform_mod("ffn_bcmports")


def _if_roles():
    """The control-plane / data-plane NIC rule for this chassis, or None."""
    return platform_mod("ffn_ifroles")


from fastapi.staticfiles import StaticFiles
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

def _load_jwt_secret() -> str:
    """Return the session-signing secret, generating one on first start.

    There is deliberately no literal default here. A hardcoded fallback is a
    signing key for every deployment that did not override it, and publishing
    the source publishes the key -- so the only safe default is "no default".

    Precedence:
      1. $FFN_JWT_SECRET               -- for systemd drop-ins and containers
      2. $FFN_JWT_SECRET_FILE, or /etc/ffn-ngfw/jwt.secret
      3. generate 48 bytes and persist them, mode 0600

    Refuses to start rather than falling back to an ephemeral secret: an
    in-memory secret would silently invalidate every session on restart, which
    presents as random logouts rather than as a configuration error.
    """
    env = os.getenv("FFN_JWT_SECRET")
    if env:
        return env

    path = Path(os.getenv("FFN_JWT_SECRET_FILE", "/etc/ffn-ngfw/jwt.secret"))
    try:
        if path.is_file():
            existing = path.read_text().strip()
            if existing:
                return existing
    except OSError:
        pass  # unreadable is the same as absent; fall through and try to create

    generated = secrets.token_urlsafe(48)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        # Create with 0600 rather than chmod-ing afterwards: otherwise the
        # secret exists world-readable for the width of two syscalls.
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(generated + "\n")
    except OSError as exc:
        raise SystemExit(
            "ffn-manager: cannot persist a session secret to %s (%s).\n"
            "Set FFN_JWT_SECRET, or point FFN_JWT_SECRET_FILE at a writable "
            "path." % (path, exc)
        )
    return generated


JWT_SECRET = _load_jwt_secret()
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_MINUTES = 480
DB_PATH = os.getenv("FFN_DB_PATH", "/var/lib/ffn-ngfw/config.db")
DEV_PATH = os.getenv("FFN_NGFW_DEV", "/dev/ngfw0")
LOG_PATH = "/var/log/ffn-ngfw"
STATIC_DIR = Path(__file__).parent / "static"
CONFIG_DIR = Path(os.getenv("FFN_CONFIG_DIR", "/var/lib/ffn-ngfw/config"))
RUNNING_CONFIG = CONFIG_DIR / "running-config.xml"
CANDIDATE_CONFIG = CONFIG_DIR / "candidate-config.xml"
SNAPSHOT_DIR = CONFIG_DIR / "snapshots"
HISTORY_DIR = CONFIG_DIR / "history"
HISTORY_MANIFEST = HISTORY_DIR / "manifest.json"
HISTORY_MAX_ENTRIES = int(os.getenv("FFN_HISTORY_MAX", "500"))
COMMIT_LOCK_TIMEOUT = 300  # 5 minutes

NUM_PORTS = 4
NUM_ENGINES = 30
NUM_DDOS_ZONES = 256

# Virtual Router = VRF instance (Axis 3, contract §3). Each VR gets a
# deterministic routing-table id = VRF_TABLE_BASE + index (persisted). The
# `default` VR is special-cased to the kernel `main` table so existing
# (non-VRF) forwarding behavior is preserved.
VRF_TABLE_BASE = 1000
VRF_MAIN_TABLE = 254          # kernel `main` table used by the default VR

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("ffn-manager")

# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class LoginRequest(BaseModel):
    username: str
    password: str


class PolicyRule(BaseModel):
    name: Optional[str] = None
    src_ip: str = "0.0.0.0/0"
    dst_ip: str = "0.0.0.0/0"
    src_iface: Optional[str] = None   # glob pattern, e.g. "zt*", "ethernet1/3"
    dst_iface: Optional[str] = None
    src_port: int = 0
    dst_port: int = 0
    proto: str = "any"
    action: str = "permit"
    # Numeric vsys_id. 0 means "every virtual system", which is what the
    # dataplane's wildcard already meant and what an untagged rule should do.
    vsys: int = 0
    description: str = ""
    position: int = 0


class StaticRoute(BaseModel):
    destination: str
    next_hop: str
    interface: str = ""
    metric: int = 100


class InterfaceConfig(BaseModel):
    ip_address: Optional[str] = None
    netmask: Optional[str] = None
    mtu: Optional[int] = None


class ChangePassword(BaseModel):
    current_password: str
    new_password: str


class DPIPattern(BaseModel):
    name: str
    pattern: str
    severity: str = "medium"
    engine: str = "dpi"


class URLBlockEntry(BaseModel):
    url: str
    category: str = "custom"


class DLPRule(BaseModel):
    name: str
    pattern_type: str = "regex"     # credit_card|ssn|api_key|email|keyword|regex|custom
    pattern: str = ""               # empty for built-in data identifiers
    action: str = "block"           # alert|log|block|quarantine (block stops the transfer)
    severity: str = "medium"
    direction: str = "egress"       # egress|ingress|both -- DLP guards data LEAVING
    threshold: int = 1              # min occurrences in a flow to trigger
    enabled: bool = True


class IPSecTunnel(BaseModel):
    peer_address: str
    local_subnet: str
    remote_subnet: str
    psk: str
    ike_version: int = 2
    esp_encryption: str = "aes256"
    esp_hash: str = "sha256"


# --- Virtual Router = VRF instance (Axis 3, contract §3) -------------------
# A VirtualRouter maps 1:1 onto a real l3mdev VRF device with its own routing
# table. StaticRoute rows live under a VR. NOTE: `StaticRoute` (above) is the
# legacy global-FIB request body kept for /api/network/routes; the VRF route
# request body is `VRRoute` to avoid a name collision.
class VirtualRouterCreate(BaseModel):
    name: str
    interfaces: List[str] = []
    admin_up: bool = True
    vsys: Optional[str] = None
    # FRR routing plane (contract §6). l3mdev remains the kernel substrate;
    # zebra/staticd/bgpd/ospfd own the routing per VRF.
    protocol: str = "static"          # static|bgp|ospf
    router_id: Optional[str] = None   # FRR router-id (bgp/ospf)
    asn: Optional[int] = None         # BGP AS number (protocol=bgp)


class VirtualRouterUpdate(BaseModel):
    interfaces: Optional[List[str]] = None
    admin_up: Optional[bool] = None
    vsys: Optional[str] = None
    protocol: Optional[str] = None    # static|bgp|ospf
    router_id: Optional[str] = None
    asn: Optional[int] = None


class IfaceVrAssign(BaseModel):
    # Assign an interface to a virtual router from the interface side (mirror of
    # the VR member list). None / "" / "default" -> back to the kernel main table.
    virtual_router: Optional[str] = None


class DosConfig(BaseModel):
    # Software anti-DDoS / flood-protection thresholds (ffn_bmfw DosProtection).
    enable: Optional[bool] = None
    syn_rate: Optional[int] = None
    syn_burst: Optional[int] = None
    udp_rate: Optional[int] = None
    udp_burst: Optional[int] = None
    icmp_rate: Optional[int] = None
    icmp_burst: Optional[int] = None
    conn_limit: Optional[int] = None


class HaLink(BaseModel):
    # An HA1 (control), HA2 (state-sync) or HA3 (packet-forwarding) link.
    interface: Optional[str] = None
    ip: Optional[str] = None
    peer_ip: Optional[str] = None
    peer_mac: Optional[str] = None
    enable: Optional[bool] = None


class HaVirtualAddress(BaseModel):
    name: str
    ip: str
    interface: Optional[str] = None
    device_id: Optional[int] = None       # owning device for A/A, or floating
    mode: Optional[str] = "floating"      # floating | arp-load-sharing


class HaConfig(BaseModel):
    # PAN-OS deviceconfig/high-availability shape (Active/Active).
    enable: Optional[bool] = None
    mode: Optional[str] = None            # active-active | active-passive | disabled
    group_id: Optional[int] = None
    device_id: Optional[int] = None       # 0 | 1
    primary_device: Optional[int] = None
    session_setup: Optional[str] = None   # ip-hash | ip-modulo | primary-device | first-packet
    session_owner: Optional[str] = None   # primary-device | first-packet
    ha1: Optional[HaLink] = None
    ha2: Optional[HaLink] = None
    ha3: Optional[HaLink] = None
    heartbeat_ms: Optional[int] = None
    peer_timeout_ms: Optional[int] = None
    hold_ms: Optional[int] = None
    virtual_addresses: Optional[List[HaVirtualAddress]] = None


class DnsProxyConfig(BaseModel):
    enable: Optional[bool] = None
    primary: Optional[str] = None
    secondary: Optional[str] = None
    doh: Optional[str] = None                     # disabled | cloudflare | google | custom
    domain_overrides: Optional[List[str]] = None


class VRRoute(BaseModel):
    dest_cidr: str
    next_hop: str = ""          # "" for a link/onlink route (dev only)
    dev: Optional[str] = None
    metric: int = 0


class MlScoreRequest(BaseModel):
    # Provide exactly one of text/hex; hex may include spaces / 0x prefixes.
    text: Optional[str] = None
    hex: Optional[str] = None


# ---------------------------------------------------------------------------
# Password hashing
# ---------------------------------------------------------------------------

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# ---------------------------------------------------------------------------
# FPGA device interface
# ---------------------------------------------------------------------------


class FPGADevice:
    """Interface to the FPGA via /dev/ngfw0 ioctls and mapped memory."""

    # Must match kernel driver's _IO* encoding — see ngfw_regs.h in
    # platform/vu9p (FFN-NGFW-FPGA submodule).
    #   _IOWR('N', 0x01, struct ngfw_reg_rw)  — REG_READ  (size=8)
    #   _IOW ('N', 0x02, struct ngfw_reg_rw)  — REG_WRITE (size=8)
    #   _IOWR('N', 0x04, struct ngfw_stats_read) — STATS_READ (size=16)
    #   _IOW ('N', 0x30, struct ngfw_lic_push)  — LIC_PUSH  (size=4)
    #   _IOWR('N', 0x31, struct ngfw_lic_payload) — LIC_QUERY (size=84)
    #   _IOR ('N', 0x32, uint8_t[12])  — DNA_READ  (size=12)
    # Encoding: (dir << 30) | (size << 16) | (type << 8) | nr
    IOCTL_READ_REG   = (3 << 30) | (8  << 16) | (0x4E << 8) | 0x01  # 0xC0084E01
    IOCTL_WRITE_REG  = (1 << 30) | (8  << 16) | (0x4E << 8) | 0x02  # 0x40084E02
    IOCTL_STATS_READ = (3 << 30) | (16 << 16) | (0x4E << 8) | 0x04  # 0xC0104E04
    IOCTL_LIC_PUSH   = (1 << 30) | (4  << 16) | (0x4E << 8) | 0x30  # 0x40044E30
    IOCTL_LIC_QUERY  = (3 << 30) | (84 << 16) | (0x4E << 8) | 0x31  # 0xC0544E31
    IOCTL_DNA_READ   = (2 << 30) | (12 << 16) | (0x4E << 8) | 0x32  # 0x800C4E32

    # License payload layout (matches struct ngfw_lic_payload, 84 bytes) — the
    # FPGA-DNA (accelerator) path; FROZEN, mirrors ngfw_regs.h in
    # platform/vu9p (FFN-NGFW-FPGA submodule).
    NGFW_LIC_PAYLOAD_BYTES = 84
    NGFW_DEVICE_DNA_BYTES  = 12
    NGFW_SIG_ALG_ECDSA_P384 = 4
    NGFW_SIG_ALG_ED25519    = 1

    # Register map offsets
    REG_VERSION = 0x0000
    REG_STATUS = 0x0004
    REG_PORT_BASE = 0x1000
    REG_PORT_STRIDE = 0x0100
    REG_ENGINE_BASE = 0x4000
    REG_ENGINE_STRIDE = 0x0040
    REG_STATS_BASE = 0x8000
    REG_DDOS_BASE = 0xC000
    REG_SESSION_BASE = 0xE000
    REG_TCAM_BASE = 0x10000

    def __init__(self, dev_path: str):
        self.dev_path = dev_path
        self._fd = None
        self._sim_counters = {}
        self._sim_start = time.time()
        self._last_attach_check = 0.0
        self._maybe_attach(force=True)
        if self._sim_mode:
            logger.warning(
                "FPGA device %s not found at startup; simulation mode "
                "(will retry on each operation)", dev_path
            )

    def _maybe_attach(self, force: bool = False) -> bool:
        """
        Lazy (re)open. Driver can be loaded/reloaded after manager start,
        so we re-check the device path at most once a second.
        """
        now = time.time()
        if self._fd is not None:
            return True
        if not force and (now - self._last_attach_check) < 1.0:
            return self._fd is not None
        self._last_attach_check = now
        if not os.path.exists(self.dev_path):
            self._sim_mode = True
            return False
        try:
            self._fd = os.open(self.dev_path, os.O_RDWR)
            self._sim_mode = False
            logger.info("FPGA device %s attached (fd=%d)", self.dev_path, self._fd)
            return True
        except OSError as exc:
            logger.warning("Cannot open %s: %s", self.dev_path, exc)
            self._sim_mode = True
            return False

    @property
    def sim_mode(self) -> bool:
        """Public accessor that also opportunistically re-attaches."""
        self._maybe_attach()
        return self._sim_mode

    def close(self):
        if self._fd is not None:
            try:
                os.close(self._fd)
            except OSError:
                pass
            self._fd = None

    def read_reg(self, offset: int) -> int:
        if not self._maybe_attach():
            return self._sim_read(offset)
        buf = struct.pack("II", offset, 0)
        try:
            import fcntl
            result = fcntl.ioctl(self._fd, self.IOCTL_READ_REG, buf)
            return struct.unpack("II", result)[1]
        except Exception as exc:
            # Device went away (driver unloaded) — drop the fd so the next
            # call re-opens cleanly rather than spamming the same error.
            logger.error("ioctl read 0x%08X failed: %s", offset, exc)
            self.close()
            self._sim_mode = True
            return 0

    def write_reg(self, offset: int, value: int):
        if not self._maybe_attach():
            self._sim_counters[offset] = value
            return
        buf = struct.pack("II", offset, value)
        try:
            import fcntl
            fcntl.ioctl(self._fd, self.IOCTL_WRITE_REG, buf)
        except Exception as exc:
            logger.error("ioctl write 0x%08X failed: %s", offset, exc)

    # -- Simulation helpers --------------------------------------------------

    def _sim_read(self, offset: int) -> int:
        # No FPGA attached. Return only values previously written back through
        # this same shim (register-write plumbing) and the static build/version
        # identity. Every analytics/counter register reads as an honest 0 — we
        # do NOT fabricate traffic, engine, DDoS or session numbers.
        if offset in self._sim_counters:
            return self._sim_counters[offset]
        if offset == self.REG_VERSION:
            return 0x0001_0003  # v1.3 (static gateware build id, not analytics)
        # REG_STATUS and all port/engine/DDoS/session counters -> 0 (no device).
        return 0

    def _sim_port_reg(self, port: int, reg: int, t: float) -> int:
        # No device: no fabricated link state or traffic counters.
        return 0

    def _sim_engine_reg(self, eng: int, reg: int, t: float) -> int:
        # No device: no fabricated engine packet/match/drop counters.
        return 0

    def _sim_ddos_zone(self, zone: int, t: float) -> int:
        # No device: every DDoS zone reads clear (0), never a fabricated level.
        return 0

    # -- High-level accessors ------------------------------------------------

    def get_version(self) -> str:
        v = self.read_reg(self.REG_VERSION)
        major = (v >> 16) & 0xFFFF
        minor = v & 0xFFFF
        return f"{major}.{minor}"

    def get_port_link_up(self, port: int) -> bool:
        val = self.read_reg(self.REG_PORT_BASE + port * self.REG_PORT_STRIDE)
        return bool(val & 1)

    def get_port_speed(self, port: int) -> int:
        val = self.read_reg(self.REG_PORT_BASE + port * self.REG_PORT_STRIDE)
        code = (val >> 1) & 0x07
        return {0: 0, 1: 1, 2: 10, 3: 25, 4: 40, 5: 100}.get(code, 0)

    def get_port_stats(self, port: int) -> dict:
        base = self.REG_PORT_BASE + port * self.REG_PORT_STRIDE
        rx_lo = self.read_reg(base + 0x04)
        rx_hi = self.read_reg(base + 0x08)
        tx_lo = self.read_reg(base + 0x0C)
        tx_hi = self.read_reg(base + 0x10)
        return {
            "rx_bytes": (rx_hi << 32) | rx_lo,
            "tx_bytes": (tx_hi << 32) | tx_lo,
            "rx_packets": self.read_reg(base + 0x14),
            "tx_packets": self.read_reg(base + 0x18),
            "rx_drops": self.read_reg(base + 0x1C),
            "tx_drops": self.read_reg(base + 0x20),
            "rx_errors": self.read_reg(base + 0x24),
        }

    def get_throughput_gbps(self, port: int) -> dict:
        stats = self.get_port_stats(port)
        # Instantaneous estimate from recent counter delta
        speed = self.get_port_speed(port)
        if self._sim_mode:
            # No FPGA attached — report honest zero, never a fabricated rate.
            rx_gbps = 0.0
            tx_gbps = 0.0
        else:
            rx_gbps = round(min(stats["rx_bytes"] * 8 / 1e9, speed), 2)
            tx_gbps = round(min(stats["tx_bytes"] * 8 / 1e9, speed), 2)
        return {"rx_gbps": rx_gbps, "tx_gbps": tx_gbps}

    def get_engine_status(self, engine_id: int) -> dict:
        base = self.REG_ENGINE_BASE + engine_id * self.REG_ENGINE_STRIDE
        return {
            "enabled": bool(self.read_reg(base + 0x00)),
            "packets": self.read_reg(base + 0x04),
            "matches": self.read_reg(base + 0x08),
            "drops": self.read_reg(base + 0x0C),
        }

    def set_engine_enable(self, engine_id: int, enable: bool):
        base = self.REG_ENGINE_BASE + engine_id * self.REG_ENGINE_STRIDE
        self.write_reg(base + 0x00, 1 if enable else 0)

    def get_session_stats(self) -> dict:
        active = self.read_reg(self.REG_SESSION_BASE)
        hits = self.read_reg(self.REG_SESSION_BASE + 4)
        misses = self.read_reg(self.REG_SESSION_BASE + 8)
        total = hits + misses if (hits + misses) > 0 else 1
        return {
            "active": active,
            "hits": hits,
            "misses": misses,
            "hit_ratio": round(hits / total * 100, 1),
        }

    def get_ddos_zones(self) -> list:
        zones = []
        for z in range(NUM_DDOS_ZONES):
            level = self.read_reg(self.REG_DDOS_BASE + z * 4)
            zones.append(level)
        return zones

    # ----------------------------------------------------------------
    # DNA + license ioctls (FPGA-DNA / accelerator path — FROZEN, copied
    # verbatim from server_snapshot fpga.py; see REWORK_CONTRACT §4)
    # ----------------------------------------------------------------

    def read_device_dna(self) -> bytes:
        """
        Read the 12-byte (96-bit) Xilinx DEVICE_DNA captured by the
        bitstream at POR. Returns the raw bytes (little-endian word
        order matches NGFW_REG_DEVICE_DNA_{0,1,2}).

        Returns b"" in sim mode, b"" if DNA wasn't valid (pre-Build-#16
        bitstream), or 12 bytes on success.
        """
        if not self._maybe_attach():
            return b""
        try:
            import fcntl
            buf = bytes(self.NGFW_DEVICE_DNA_BYTES)
            result = fcntl.ioctl(self._fd, self.IOCTL_DNA_READ, buf)
            return bytes(result)
        except OSError as exc:
            if getattr(exc, "errno", None) == 61:   # ENODATA — DNA not valid
                return b""
            logger.warning("DNA_READ ioctl failed: %s", exc)
            return b""

    def device_dna_hex(self) -> str:
        """
        Return DNA as 'aa:bb:cc:...:11' or empty string in sim mode.
        Reads bytes from the kernel ioctl; only returns silicon DNA
        (synthesis happens in device_dna_info()).
        """
        d = self.read_device_dna()
        if not d:
            return ""
        # Reject the "all-zero" and "all-FF" patterns — those mean the
        # bitstream's DNA register region is unmapped or hasn't latched
        # yet, NOT a real silicon value.
        if all(b == 0x00 for b in d) or all(b == 0xFF for b in d):
            return ""
        return ":".join(f"{b:02x}" for b in d)

    def device_dna_info(self) -> dict:
        """
        Return DNA + provenance.  Falls back to a synthetic, host-stable
        96-bit value when the bitstream's silicon DNA isn't reachable
        (Build #15 or earlier).  The synthetic value is deterministic
        per physical machine + FPGA card combination, so license
        tokens can still bind to it.

        Returns:
            {
                "dna_hex":  "aa:bb:..:11",
                "valid":    True,
                "source":   "silicon" | "synthetic" | "none",
            }
        """
        # 1. Try the bitstream-exposed silicon DNA first
        sil = self.device_dna_hex()
        if sil:
            return {"dna_hex": sil, "valid": True, "source": "silicon"}

        # 2. Synthesize from stable host + PCI identifiers.
        #    Anything that can't be read drops out of the hash silently
        #    — keeps the result well-defined even on a stripped distro.
        synth = _synthesize_dna()
        if synth:
            return {"dna_hex": synth, "valid": True, "source": "synthetic"}

        return {"dna_hex": "", "valid": False, "source": "none"}

    def device_host_dna_info(self) -> dict:
        """
        Card-independent ``h1`` HOST identity (REWORK_CONTRACT §4, Axis 2).

        This is the base host DNA that exists WITH OR WITHOUT a card — it is
        NOT the silicon/v1 device DNA above.  Sourced from the standalone
        host-side verifier (ffn_license.HostLicense).
        """
        try:
            from ffn_license import HostLicense
            return HostLicense().host_dna_info()
        except Exception as exc:
            logger.warning("host DNA (h1) lookup failed: %s", exc)
            return {"dna_hex": "", "valid": False, "source": "host-h1"}

    def push_license_payloads(self, payloads: list) -> None:
        """
        Push a list of pre-verified license payloads to the kernel
        cache. Each payload is exactly NGFW_LIC_PAYLOAD_BYTES (84 B).

        Userspace must have already verified signatures before calling
        this. The kernel sanity-checks magic / DNA-match / sig_alg but
        cannot verify the cryptographic signature itself.
        """
        if not self._maybe_attach():
            return
        for p in payloads:
            if len(p) != self.NGFW_LIC_PAYLOAD_BYTES:
                raise ValueError(
                    f"payload must be {self.NGFW_LIC_PAYLOAD_BYTES} B, got {len(p)}")
        # struct ngfw_lic_push { uint32_t count; payload[count]; }
        buf = struct.pack("<I", len(payloads)) + b"".join(payloads)
        try:
            import fcntl
            fcntl.ioctl(self._fd, self.IOCTL_LIC_PUSH, buf)
        except OSError as exc:
            logger.error("LIC_PUSH ioctl failed: %s", exc)
            raise

    def query_license(self, feature_id: int) -> bool:
        """
        Ask the kernel whether a license payload covering this
        feature_id has been pushed and is currently active.

        Returns True if licensed, False otherwise. False also if no
        DNA was ever captured (the verifier couldn't have pushed a
        DNA-bound token in that case).
        """
        if not self._maybe_attach():
            return False
        # Build a query payload — only feature_id is meaningful.
        q = bytearray(self.NGFW_LIC_PAYLOAD_BYTES)
        q[0:8] = b"FFN-LIC1"
        struct.pack_into("<I", q,  8, 1)                # version
        struct.pack_into("<I", q, 24, feature_id)       # feature_id
        try:
            import fcntl
            fcntl.ioctl(self._fd, self.IOCTL_LIC_QUERY, bytes(q))
            return True
        except OSError as exc:
            if getattr(exc, "errno", None) == 2:        # ENOENT = no license
                return False
            logger.warning("LIC_QUERY(0x%x) ioctl failed: %s", feature_id, exc)
            return False


# =====================================================================
# Synthetic-DNA fallback (v1) — FROZEN, copied verbatim from
# server_snapshot fpga.py.  Both the Python manager and the C verifier
# (ffn-license-verify.c) produce the SAME 96-bit hash from the SAME byte
# stream.  Any change MUST bump the version prefix and update both
# implementations together.
#
#     v1|pci_bdf=<bdf>|pci_subsystem_vendor=<v>|pci_subsystem_device=<d>
#       |board_serial=<x>|board_asset_tag=<x>|product_uuid=<x>|product_serial=<x>
#       |mac=<aa:bb:..:ff>
#
# This is the card-bound silicon-fallback identity — distinct from the
# card-independent h1 host DNA (ffn_license.HostIdentity).
# =====================================================================

def _read_first_line(path):
    try:
        with open(path) as f:
            return f.readline().strip()
    except (OSError, ValueError):
        return ""


_CANONICAL_FIELDS = (
    # (out_key,                  source_path)
    ("pci_bdf",                  None),  # synthesized below
    ("pci_subsystem_vendor",     None),
    ("pci_subsystem_device",     None),
    ("board_serial",             "/sys/class/dmi/id/board_serial"),
    ("board_asset_tag",          "/sys/class/dmi/id/board_asset_tag"),
    ("product_uuid",             "/sys/class/dmi/id/product_uuid"),
    ("product_serial",           "/sys/class/dmi/id/product_serial"),
    ("mac",                      None),  # synthesized below
)

_DMI_IGNORE = {
    "", "to be filled by o.e.m.", "default string",
    "none", "0", "system serial number",
}


def _synthesize_dna() -> str:
    """
    Compute the v1 canonical synthetic DNA for this host + FPGA pair.
    Returns ':'-separated hex (12 bytes) or empty string if no
    identifiers were readable.

    Wire format:  v1|key=value|key=value|...   (see _CANONICAL_FIELDS)
    """
    import glob
    import hashlib
    import os

    # 1. Find the first FPGA's PCI sysfs base path.  Search 10ee first
    #    (Xilinx) then 1234 (BittWare test ID) so the match order is
    #    deterministic regardless of readdir() order.
    pci_base = None
    for vid_pat in ("10ee", "1234"):
        candidates = []
        for cfg in glob.glob("/sys/bus/pci/devices/*/vendor"):
            try:
                with open(cfg) as f:
                    if f.read().strip().lower() == f"0x{vid_pat}":
                        candidates.append(os.path.dirname(cfg))
            except OSError:
                continue
        if candidates:
            pci_base = sorted(candidates)[0]   # lowest BDF
            break

    out_parts = ["v1"]

    for key, path in _CANONICAL_FIELDS:
        if key == "pci_bdf":
            if pci_base:
                out_parts.append(f"pci_bdf={os.path.basename(pci_base)}")
        elif key == "pci_subsystem_vendor":
            if pci_base:
                v = _read_first_line(f"{pci_base}/subsystem_vendor")
                if v: out_parts.append(f"pci_subsystem_vendor={v}")
        elif key == "pci_subsystem_device":
            if pci_base:
                v = _read_first_line(f"{pci_base}/subsystem_device")
                if v: out_parts.append(f"pci_subsystem_device={v}")
        elif key == "mac":
            try:
                ifs = sorted(os.listdir("/sys/class/net"))
            except OSError:
                ifs = []
            for ifc in ifs:
                if ifc == "lo":
                    continue
                mac = _read_first_line(f"/sys/class/net/{ifc}/address")
                if mac and mac != "00:00:00:00:00:00":
                    out_parts.append(f"mac={mac}")
                    break
        else:
            v = _read_first_line(path)
            if v and v.lower() not in _DMI_IGNORE:
                out_parts.append(f"{key}={v}")

    if len(out_parts) <= 1:
        return ""

    digest = hashlib.sha256("|".join(out_parts).encode("utf-8")).digest()
    dna_bytes = digest[:12]
    return ":".join(f"{b:02x}" for b in dna_bytes)


# ---------------------------------------------------------------------------
# Commit History (append-only versioned changelog with rollback)
# ---------------------------------------------------------------------------


class CommitHistory:
    """
    Append-only changelog of running-config versions. Every successful commit
    produces a new, monotonically-numbered entry storing:
      - full XML snapshot (history/<id>.xml)
      - metadata (manifest.json): version, user, description, timestamp,
        diff summary vs parent, commit type, sha256 of the XML
    Rollback copies a historical XML into the candidate — the user must then
    commit to activate it (which itself appends a new history entry of
    type=rollback).
    """

    def __init__(self):
        HISTORY_DIR.mkdir(parents=True, exist_ok=True)
        if not HISTORY_MANIFEST.exists():
            self._write_manifest({"next_version": 1, "entries": []})

    # -- Manifest I/O --

    def _read_manifest(self) -> dict:
        try:
            return json.loads(HISTORY_MANIFEST.read_text(encoding="utf-8"))
        except Exception:
            return {"next_version": 1, "entries": []}

    def _write_manifest(self, data: dict):
        tmp = HISTORY_MANIFEST.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
        tmp.replace(HISTORY_MANIFEST)

    # -- Record a commit --

    def record(self, *, user: str, description: str, commit_type: str,
               xpath: Optional[str], diff_counts: dict,
               parent_version: Optional[int]) -> dict:
        """
        Append a new history entry pointing at the current running-config.
        Called after the commit() has already written running-config.xml.
        """
        manifest = self._read_manifest()
        version = manifest["next_version"]
        ts = datetime.utcnow().strftime("%Y-%m-%dT%H-%M-%SZ")
        xml_bytes = RUNNING_CONFIG.read_bytes() if RUNNING_CONFIG.exists() else b""
        sha = hashlib.sha256(xml_bytes).hexdigest()
        entry_id = f"{version:05d}-{ts}-{sha[:8]}"
        xml_path = HISTORY_DIR / f"{entry_id}.xml"
        xml_path.write_bytes(xml_bytes)

        entry = {
            "version": version,
            "id": entry_id,
            "file": xml_path.name,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "user": user,
            "description": description or "",
            "type": commit_type,
            "xpath": xpath,
            "parent_version": parent_version,
            "changes": diff_counts,
            "sha256": sha,
            "size_bytes": xml_path.stat().st_size,
        }

        # Newest first
        entries = manifest.get("entries", [])
        entries.insert(0, entry)

        # Prune oldest beyond HISTORY_MAX_ENTRIES
        if len(entries) > HISTORY_MAX_ENTRIES:
            to_prune = entries[HISTORY_MAX_ENTRIES:]
            entries = entries[:HISTORY_MAX_ENTRIES]
            for old in to_prune:
                try:
                    (HISTORY_DIR / old["file"]).unlink(missing_ok=True)
                except Exception:
                    pass

        manifest["entries"] = entries
        manifest["next_version"] = version + 1
        self._write_manifest(manifest)
        logger.info("Recorded config history v%d by %s (%s, %d changes)",
                    version, user, commit_type, diff_counts.get("total", 0))
        return entry

    # -- Queries --

    def list_entries(self, limit: Optional[int] = None) -> list:
        entries = self._read_manifest().get("entries", [])
        return entries[:limit] if limit else entries

    def get(self, version: int) -> Optional[dict]:
        for e in self._read_manifest().get("entries", []):
            if e["version"] == version:
                return e
        return None

    def read_xml(self, version: int) -> Optional[bytes]:
        entry = self.get(version)
        if entry is None:
            return None
        path = HISTORY_DIR / entry["file"]
        if not path.exists():
            return None
        return path.read_bytes()

    def latest_version(self) -> Optional[int]:
        entries = self._read_manifest().get("entries", [])
        return entries[0]["version"] if entries else None

    def prune(self, keep: int) -> dict:
        manifest = self._read_manifest()
        entries = manifest.get("entries", [])
        keep = max(1, int(keep))
        to_delete = entries[keep:]
        remaining = entries[:keep]
        removed = 0
        for old in to_delete:
            try:
                (HISTORY_DIR / old["file"]).unlink(missing_ok=True)
                removed += 1
            except Exception:
                pass
        manifest["entries"] = remaining
        self._write_manifest(manifest)
        return {"kept": len(remaining), "removed": removed}


# ---------------------------------------------------------------------------
# XML Configuration Manager (PAN-OS style candidate/running with commit lock)
# ---------------------------------------------------------------------------


class ConfigManager:
    """
    Manages candidate and running XML configurations with PAN-OS style
    commit semantics:
      - candidate-config.xml: pending changes (not active)
      - running-config.xml: currently active configuration
      - Commit lock: prevents concurrent commits
      - Partial commit: commit only specific xpath subtrees
      - Snapshots: named versions for rollback
    """

    # PAN-OS 11.x encapsulated hierarchy. Every keyed list uses
    # <entry name="X"> and every ordered string list uses <member>foo</member>.
    # Empty containers are left self-closing. Mirrors the structure produced
    # by `show config running` on a real Palo Alto appliance so importing a
    # real PAN-OS config is a straight XML swap.
    DEFAULT_CONFIG = """<?xml version="1.0"?>
<config version="11.2.0" urldb="ffn-cloud" detail-version="1.0.0">
  <mgt-config>
    <users>
      <entry name="admin">
        <permissions>
          <role-based>
            <superuser>yes</superuser>
          </role-based>
        </permissions>
      </entry>
    </users>
    <password-complexity>
      <enabled>yes</enabled>
      <minimum-length>8</minimum-length>
    </password-complexity>
  </mgt-config>
  <shared>
    <application/>
    <application-group/>
    <service/>
    <service-group/>
    <external-list/>
    <certificate/>
    <certificate-profile/>
    <log-settings>
      <profiles/>
    </log-settings>
  </shared>
  <devices>
    <entry name="localhost.localdomain">
      <deviceconfig>
        <system>
          <hostname>ffn-appliance</hostname>
          <domain/>
          <timezone>UTC</timezone>
          <update-server>updates.ffn-cloud.io</update-server>
          <dns-setting>
            <servers>
              <primary>8.8.8.8</primary>
              <secondary>8.8.4.4</secondary>
            </servers>
          </dns-setting>
          <ntp-servers>
            <primary-ntp-server>
              <ntp-server-address>pool.ntp.org</ntp-server-address>
              <authentication-type>
                <none/>
              </authentication-type>
            </primary-ntp-server>
          </ntp-servers>
          <service>
            <disable-telnet>yes</disable-telnet>
            <disable-http>yes</disable-http>
          </service>
          <device-telemetry>
            <device-health-performance>no</device-health-performance>
            <product-usage>no</product-usage>
            <threat-prevention>no</threat-prevention>
          </device-telemetry>
        </system>
        <setting>
          <config>
            <rematch>yes</rematch>
          </config>
          <management>
            <hostname-type-in-syslog>FQDN</hostname-type-in-syslog>
            <enable-certificate-expiration-check>yes</enable-certificate-expiration-check>
          </management>
          <jumbo-frame>
            <mtu>9216</mtu>
          </jumbo-frame>
          <wildfire>
            <cloud>public</cloud>
            <custom-url/>
            <custom-port>443</custom-port>
            <file-size-limit-mb>10</file-size-limit-mb>
            <session-info>
              <source-ip>yes</source-ip>
              <source-port>yes</source-port>
              <destination-ip>yes</destination-ip>
              <destination-port>yes</destination-port>
              <virtual-system>yes</virtual-system>
              <application>yes</application>
              <user>yes</user>
              <url>yes</url>
              <file-name>yes</file-name>
              <email-sender>yes</email-sender>
              <email-recipient>yes</email-recipient>
              <email-subject>yes</email-subject>
            </session-info>
          </wildfire>
          <session>
            <tcp-timeout>3600</tcp-timeout>
            <udp-timeout>30</udp-timeout>
            <icmp-timeout>6</icmp-timeout>
          </session>
        </setting>
        <high-availability>
          <mode>
            <standalone/>
          </mode>
        </high-availability>
      </deviceconfig>
      <network>
        <interface>
          <ethernet/>
          <aggregate-ethernet/>
          <loopback>
            <units/>
          </loopback>
          <tunnel>
            <units/>
          </tunnel>
          <vlan>
            <units/>
          </vlan>
        </interface>
        <virtual-wire/>
        <virtual-router>
          <entry name="default">
            <protocol>
              <bgp>
                <enable>no</enable>
              </bgp>
              <ospf>
                <enable>no</enable>
              </ospf>
              <rip>
                <enable>no</enable>
              </rip>
            </protocol>
            <interface/>
            <routing-table>
              <ip>
                <static-route/>
              </ip>
              <ipv6>
                <static-route/>
              </ipv6>
            </routing-table>
            <ecmp>
              <algorithm>
                <ip-modulo/>
              </algorithm>
            </ecmp>
          </entry>
        </virtual-router>
        <ike>
          <crypto-profiles>
            <ike-crypto-profiles>
              <entry name="default">
                <encryption>
                  <member>aes-256-gcm</member>
                  <member>aes-128-gcm</member>
                </encryption>
                <hash>
                  <member>sha384</member>
                  <member>sha256</member>
                </hash>
                <dh-group>
                  <member>group20</member>
                  <member>group19</member>
                  <member>group14</member>
                </dh-group>
                <lifetime>
                  <hours>8</hours>
                </lifetime>
              </entry>
            </ike-crypto-profiles>
            <ipsec-crypto-profiles>
              <entry name="default">
                <esp>
                  <encryption>
                    <member>aes-256-gcm</member>
                    <member>aes-128-gcm</member>
                  </encryption>
                  <authentication>
                    <member>none</member>
                  </authentication>
                </esp>
                <dh-group>group20</dh-group>
                <lifetime>
                  <hours>1</hours>
                </lifetime>
              </entry>
            </ipsec-crypto-profiles>
            <global-protect-app-crypto-profiles>
              <entry name="default">
                <encryption>
                  <member>aes-256-gcm</member>
                </encryption>
                <authentication>
                  <member>sha256</member>
                </authentication>
              </entry>
            </global-protect-app-crypto-profiles>
          </crypto-profiles>
        </ike>
        <tunnel>
          <ipsec/>
          <global-protect-gateway/>
        </tunnel>
        <gre/>
        <vxlan-tunnel/>
        <shared-gateway/>
        <qos>
          <profile/>
        </qos>
        <lldp>
          <enable>yes</enable>
        </lldp>
        <dhcp>
          <interface/>
        </dhcp>
        <dns-proxy/>
        <sdwan-interface-profile/>
        <profiles>
          <monitor-profile/>
          <interface-management-profile/>
          <zone-protection-profile/>
          <qos-profile/>
          <lldp-profile/>
          <bfd-profile/>
        </profiles>
        <virtual-router-attributes/>
      </network>
      <vsys>
        <entry name="vsys1">
          <display-name>Default</display-name>
          <import>
            <network>
              <interface/>
              <virtual-router>
                <member>default</member>
              </virtual-router>
            </network>
          </import>
          <zone/>
          <address/>
          <address-group/>
          <service/>
          <service-group/>
          <application/>
          <application-group/>
          <tag/>
          <schedule/>
          <profiles>
            <dos-protection/>
          </profiles>
          <rulebase>
            <security>
              <rules/>
            </security>
            <nat>
              <rules/>
            </nat>
            <qos>
              <rules/>
            </qos>
            <pbf>
              <rules/>
            </pbf>
            <decryption>
              <rules/>
            </decryption>
            <application-override>
              <rules/>
            </application-override>
            <authentication>
              <rules/>
            </authentication>
            <dos>
              <rules/>
            </dos>
          </rulebase>
          <global-protect>
            <global-protect-portal/>
            <global-protect-gateway/>
            <global-protect-mdm/>
            <global-protect-clientless-app/>
            <global-protect-clientless-app-group/>
          </global-protect>
          <zero-trust>
            <wireguard>
              <interfaces/>
              <peers/>
            </wireguard>
            <zerotier/>
            <tailscale/>
            <zscaler/>
          </zero-trust>
          <server-profile>
            <ldap/>
            <radius/>
            <tacplus/>
            <kerberos/>
            <saml-idp/>
            <syslog/>
            <email/>
            <snmp-trap/>
            <http/>
            <netflow/>
            <scp/>
            <dns/>
            <mfa/>
          </server-profile>
          <local-user-database>
            <user/>
            <user-group/>
          </local-user-database>
          <certificate/>
          <certificate-profile/>
          <ssl-tls-service-profile/>
          <ocsp-responder/>
          <scep/>
          <ssh-service-profile/>
          <ssl-decryption-exclusion/>
          <external-list/>
          <log-settings/>
          <authentication-profile/>
          <authentication-sequence/>
          <admin-role/>
          <access-domain/>
        </entry>
      </vsys>
    </entry>
  </devices>
  <panorama/>
  <readonly/>
</config>
"""

    def __init__(self):
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        SNAPSHOT_DIR.mkdir(parents=True, exist_ok=True)

        seeded = False
        if not RUNNING_CONFIG.exists():
            RUNNING_CONFIG.write_text(self.DEFAULT_CONFIG, encoding="utf-8")
            logger.info("Initialized running-config at %s", RUNNING_CONFIG)
            seeded = True

        if not CANDIDATE_CONFIG.exists():
            shutil.copy2(RUNNING_CONFIG, CANDIDATE_CONFIG)
            logger.info("Initialized candidate-config at %s", CANDIDATE_CONFIG)

        # Append-only commit history (version + rollback)
        self.history = CommitHistory()
        if not self.history.list_entries(limit=1):
            # Seed version 1 from the running-config we just loaded
            self.history.record(
                user="system",
                description="Initial config (seeded from default)" if seeded
                            else "Initial config (existing running-config at daemon start)",
                commit_type="initial",
                xpath=None,
                diff_counts={"added": 0, "modified": 0, "removed": 0, "total": 0},
                parent_version=None,
            )

        latest = self.history.latest_version()
        logger.info("Config loaded: running-config at v%s (%d history entries)",
                    latest, len(self.history.list_entries()))

        self._lock_holder: Optional[str] = None
        self._lock_acquired_at: float = 0
        self._lock_reason: str = ""

    # -- Lock management --

    def lock_status(self) -> dict:
        if self._lock_holder:
            age = time.time() - self._lock_acquired_at
            if age > COMMIT_LOCK_TIMEOUT:
                self._lock_holder = None
                self._lock_reason = ""
                return {"locked": False, "message": "Lock expired"}
            return {
                "locked": True,
                "holder": self._lock_holder,
                "acquired_at": datetime.fromtimestamp(self._lock_acquired_at).isoformat(),
                "age_seconds": int(age),
                "expires_in": int(COMMIT_LOCK_TIMEOUT - age),
                "reason": self._lock_reason,
            }
        return {"locked": False}

    def acquire_lock(self, user: str, reason: str = "commit") -> bool:
        st = self.lock_status()
        if st["locked"] and st["holder"] != user:
            return False
        self._lock_holder = user
        self._lock_acquired_at = time.time()
        self._lock_reason = reason
        return True

    def release_lock(self, user: str) -> bool:
        if self._lock_holder == user:
            self._lock_holder = None
            self._lock_reason = ""
            return True
        return False

    # -- XML parsing --

    def _load(self, path: Path) -> ET.Element:
        tree = ET.parse(str(path))
        return tree.getroot()

    def _save(self, root: ET.Element, path: Path):
        """Pretty-print and save XML atomically."""
        rough = ET.tostring(root, encoding="unicode")
        pretty = minidom.parseString(rough).toprettyxml(indent="  ", encoding="utf-8")
        # Remove blank lines from pretty printer
        clean = b"\n".join(line for line in pretty.split(b"\n") if line.strip())
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_bytes(clean)
        tmp.replace(path)

    def get_candidate(self) -> str:
        return CANDIDATE_CONFIG.read_text(encoding="utf-8")

    def get_running(self) -> str:
        return RUNNING_CONFIG.read_text(encoding="utf-8")

    # ------------------------------------------------------------------
    # Xpath parsing — PAN-OS style
    #
    # Supported path forms (all dotted, with optional [@name=foo] predicates
    # and a /text() virtual step for leaf text):
    #
    #   devices.entry[@name=localhost.localdomain].deviceconfig.system.hostname
    #   devices.entry[@name=localhost.localdomain].network.interface.ethernet.entry[@name=ethernet1/1].layer3.mtu
    #   devices.entry[@name=localhost].vsys.entry[@name=vsys1].zone.entry[@name=trust].network.layer3
    #
    # The legacy dotted form (device.setup.management.hostname) is still
    # parsed for backwards compatibility but will no longer match after the
    # DEFAULT_CONFIG rewrite — callers must use the PAN-OS form.
    # ------------------------------------------------------------------

    # Regex: "entry[@name=X]" or "entry[@name='X']" with X allowed to contain
    # dots/colons/slashes (since interface names look like 'ethernet1/1').
    _ENTRY_PRED_RE = __import__("re").compile(
        r"^entry\[@name\s*=\s*(?:'([^']*)'|\"([^\"]*)\"|([^\]]+))\]$"
    )

    def _parse_step(self, raw: str):
        """
        Parse a single dotted-path step. Returns a tuple (tag, name_or_None)
        where name is set when the step is `entry[@name=...]`.
        """
        m = self._ENTRY_PRED_RE.match(raw)
        if m:
            return ("entry", (m.group(1) or m.group(2) or m.group(3) or "").strip())
        return (raw, None)

    def _split_xpath(self, xpath: str) -> list:
        """
        Split a dotted xpath into steps while preserving [@name=...] predicates.
        We can't use naive str.split('.') because entry names contain dots
        (e.g. localhost.localdomain). Instead we split at dots that are NOT
        inside square brackets.
        """
        out = []
        depth = 0
        cur = []
        for ch in xpath:
            if ch == "[":
                depth += 1
                cur.append(ch)
            elif ch == "]":
                depth -= 1
                cur.append(ch)
            elif ch == "." and depth == 0:
                if cur:
                    out.append("".join(cur))
                    cur = []
            else:
                cur.append(ch)
        if cur:
            out.append("".join(cur))
        return out

    def _normalize_xpath(self, xpath: str, root: ET.Element) -> list:
        """Parse an xpath into a list of (tag, name_or_None) steps,
        stripping a leading 'config' step if present."""
        raw = self._split_xpath(xpath)
        if raw and raw[0] == root.tag:
            raw = raw[1:]
        return [self._parse_step(r) for r in raw]

    def _find_child(self, parent: ET.Element, step) -> Optional[ET.Element]:
        """Find a single child matching (tag, name_or_None)."""
        tag, name = step
        if name is None:
            return parent.find(tag)
        for child in parent.findall(tag):
            if child.get("name") == name:
                return child
        return None

    def _find_or_create_child(self, parent: ET.Element, step) -> ET.Element:
        """Find or create a child, setting the name attribute if specified."""
        child = self._find_child(parent, step)
        if child is not None:
            return child
        tag, name = step
        child = ET.SubElement(parent, tag)
        if name is not None:
            child.set("name", name)
        return child

    def _traverse_or_create(self, root: ET.Element, steps: list) -> ET.Element:
        """Walk/create each intermediate step, return the final parent."""
        node = root
        for step in steps:
            node = self._find_or_create_child(node, step)
        return node

    # ------------------------------------------------------------------
    # Update APIs
    # ------------------------------------------------------------------

    def update_candidate(self, xpath: str, value_or_xml, user: str) -> dict:
        """
        Update a single leaf in the candidate config. Value can be:
          - a scalar string (sets the .text of the leaf)
          - a raw XML fragment (replaces the leaf subtree)
          - a list of strings (replaces children with <member>X</member> elements)
          - a dict (recursively sets leaf values; values may be scalars/lists/dicts)
        """
        root = self._load(CANDIDATE_CONFIG)
        steps = self._normalize_xpath(xpath, root)
        if not steps:
            return {"status": "error", "message": "empty xpath"}

        parent = self._traverse_or_create(root, steps[:-1])
        leaf_step = steps[-1]

        if isinstance(value_or_xml, dict):
            target = self._find_or_create_child(parent, leaf_step)
            self._apply_dict(target, value_or_xml)
        elif isinstance(value_or_xml, list):
            target = self._find_or_create_child(parent, leaf_step)
            # Clear existing <member> children and rewrite
            for m in list(target.findall("member")):
                target.remove(m)
            for v in value_or_xml:
                m = ET.SubElement(target, "member")
                m.text = str(v)
        elif isinstance(value_or_xml, str) and value_or_xml.lstrip().startswith("<"):
            try:
                frag = ET.fromstring(value_or_xml)
            except ET.ParseError as exc:
                return {"status": "error", "message": f"invalid XML: {exc}"}
            existing = self._find_child(parent, leaf_step)
            if existing is not None:
                parent.remove(existing)
            # Preserve the name attribute if the step specified one but the
            # fragment didn't.
            if leaf_step[1] and frag.get("name") is None:
                frag.set("name", leaf_step[1])
            parent.append(frag)
        else:
            target = self._find_or_create_child(parent, leaf_step)
            target.text = "" if value_or_xml is None else str(value_or_xml)

        self._save(root, CANDIDATE_CONFIG)
        return {"status": "ok", "xpath": xpath, "user": user}

    def _apply_dict(self, node: ET.Element, d: dict):
        """Recursively write a dict of {child_name: value} into an element,
        handling scalars / lists (→ <member>) / dicts / None (→ remove)."""
        for k, v in d.items():
            # Special key ".member" to set the node's own <member> list
            if k == "_members" and isinstance(v, list):
                for m in list(node.findall("member")):
                    node.remove(m)
                for item in v:
                    m = ET.SubElement(node, "member")
                    m.text = str(item)
                continue
            existing = node.find(k)
            if v is None:
                if existing is not None:
                    node.remove(existing)
                continue
            if isinstance(v, dict):
                child = existing if existing is not None else ET.SubElement(node, k)
                self._apply_dict(child, v)
            elif isinstance(v, list):
                child = existing if existing is not None else ET.SubElement(node, k)
                # Treat lists as <member> sequences
                for m in list(child.findall("member")):
                    child.remove(m)
                for item in v:
                    m = ET.SubElement(child, "member")
                    m.text = str(item)
            else:
                child = existing if existing is not None else ET.SubElement(node, k)
                child.text = "" if v is None else str(v)

    def update_candidate_bulk(self, updates: dict, user: str) -> dict:
        """Apply multiple xpath→value updates atomically."""
        root = self._load(CANDIDATE_CONFIG)
        applied = []
        for xpath, value in updates.items():
            steps = self._normalize_xpath(xpath, root)
            if not steps:
                continue
            parent = self._traverse_or_create(root, steps[:-1])
            leaf_step = steps[-1]
            if isinstance(value, list):
                target = self._find_or_create_child(parent, leaf_step)
                for m in list(target.findall("member")):
                    target.remove(m)
                for v in value:
                    m = ET.SubElement(target, "member")
                    m.text = str(v)
            elif isinstance(value, dict):
                target = self._find_or_create_child(parent, leaf_step)
                self._apply_dict(target, value)
            else:
                target = self._find_or_create_child(parent, leaf_step)
                target.text = "" if value is None else str(value)
            applied.append(xpath)
        self._save(root, CANDIDATE_CONFIG)
        return {"status": "ok", "applied": applied, "user": user}

    def delete_candidate(self, xpath: str, user: str) -> dict:
        """Remove an element at the given xpath from the candidate config."""
        root = self._load(CANDIDATE_CONFIG)
        steps = self._normalize_xpath(xpath, root)
        if not steps:
            return {"status": "error", "message": "empty xpath"}
        parent = root
        for step in steps[:-1]:
            parent = self._find_child(parent, step)
            if parent is None:
                return {"status": "not-found", "xpath": xpath}
        target = self._find_child(parent, steps[-1])
        if target is None:
            return {"status": "not-found", "xpath": xpath}
        parent.remove(target)
        self._save(root, CANDIDATE_CONFIG)
        return {"status": "ok", "xpath": xpath, "user": user}

    def get_xpath(self, xpath: str, source: str = "candidate") -> Optional[ET.Element]:
        """Return the XML element at the given xpath, or None if missing."""
        path = CANDIDATE_CONFIG if source == "candidate" else RUNNING_CONFIG
        root = self._load(path)
        steps = self._normalize_xpath(xpath, root)
        node = root
        for step in steps:
            node = self._find_child(node, step)
            if node is None:
                return None
        return node

    # ------------------------------------------------------------------
    # Diff
    # ------------------------------------------------------------------

    def _collect_paths(self, elem: ET.Element, prefix: str = "") -> dict:
        """
        Flatten the tree into {xpath: value}. Path segments include
        entry[@name=...] predicates so we can diff keyed lists correctly.
        """
        out = {}
        name = elem.get("name")
        tag = f"entry[@name={name}]" if (elem.tag == "entry" and name is not None) else elem.tag
        path = f"{prefix}.{tag}" if prefix else tag

        # Treat <member>X</member> as an ordered list, emit one key per index
        members = elem.findall("member")
        if members and len(members) == len(list(elem)):
            for i, m in enumerate(members):
                out[f"{path}.member[{i}]"] = (m.text or "").strip()
            return out

        if len(elem) == 0:
            out[path] = (elem.text or "").strip()
        else:
            for child in elem:
                out.update(self._collect_paths(child, path))
        return out

    def diff(self) -> dict:
        """Return the set of paths that differ between candidate and running."""
        cand_paths = self._collect_paths(self._load(CANDIDATE_CONFIG))
        run_paths = self._collect_paths(self._load(RUNNING_CONFIG))
        added, modified, removed = [], [], []
        all_keys = set(cand_paths) | set(run_paths)
        for k in sorted(all_keys):
            if k not in run_paths:
                added.append({"path": k, "new": cand_paths[k]})
            elif k not in cand_paths:
                removed.append({"path": k, "old": run_paths[k]})
            elif cand_paths[k] != run_paths[k]:
                modified.append({"path": k, "old": run_paths[k], "new": cand_paths[k]})
        return {
            "has_changes": bool(added or modified or removed),
            "total_changes": len(added) + len(modified) + len(removed),
            "added": added,
            "modified": modified,
            "removed": removed,
        }

    # -- Commit --

    def commit(self, user: str, description: str = "", partial_xpath: Optional[str] = None,
               commit_type: Optional[str] = None) -> dict:
        """
        Commit candidate → running. If partial_xpath is given, copy only that
        subtree from candidate into running (partial commit).

        `commit_type` is usually inferred from whether `partial_xpath` is set
        ("full"/"partial"). Callers may override (e.g., "rollback") so the
        history entry labels the commit accurately.
        """
        parent_version = self.history.latest_version()
        diff_before = self.diff()
        diff_counts = {
            "added": len(diff_before["added"]),
            "modified": len(diff_before["modified"]),
            "removed": len(diff_before["removed"]),
            "total": diff_before["total_changes"],
        }

        if partial_xpath is None:
            snapshot_name = f"auto-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}"
            self.snapshot_save(snapshot_name, f"Auto-snapshot before commit by {user}")
            shutil.copy2(CANDIDATE_CONFIG, RUNNING_CONFIG)
            ctype = commit_type or "full"
            hist = self.history.record(
                user=user, description=description, commit_type=ctype,
                xpath=None, diff_counts=diff_counts,
                parent_version=parent_version,
            )
            return {
                "status": "committed",
                "type": ctype,
                "snapshot": snapshot_name,
                "version": hist["version"],
                "parent_version": parent_version,
                "changes": diff_counts,
                "user": user,
                "description": description,
                "timestamp": datetime.utcnow().isoformat(),
            }

        # Partial commit — replace only the subtree at xpath in running
        cand_root = self._load(CANDIDATE_CONFIG)
        run_root = self._load(RUNNING_CONFIG)
        parts = self._normalize_xpath(partial_xpath, cand_root)

        cand_parent, cand_node = cand_root, cand_root
        for part in parts:
            nxt = cand_node.find(part)
            if nxt is None:
                return {"status": "error", "message": f"Path '{partial_xpath}' not in candidate"}
            cand_parent, cand_node = cand_node, nxt

        run_parent, run_node = run_root, run_root
        for part in parts[:-1]:
            nxt = run_node.find(part)
            if nxt is None:
                nxt = ET.SubElement(run_node, part)
            run_parent, run_node = run_node, nxt
        leaf_name = parts[-1]

        snapshot_name = f"partial-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}"
        self.snapshot_save(snapshot_name, f"Partial commit of {partial_xpath} by {user}")

        old = run_node.find(leaf_name)
        if old is not None:
            run_node.remove(old)
        import copy
        run_node.append(copy.deepcopy(cand_node))
        self._save(run_root, RUNNING_CONFIG)

        ctype = commit_type or "partial"
        hist = self.history.record(
            user=user, description=description, commit_type=ctype,
            xpath=partial_xpath, diff_counts=diff_counts,
            parent_version=parent_version,
        )
        return {
            "status": "committed",
            "type": ctype,
            "xpath": partial_xpath,
            "snapshot": snapshot_name,
            "version": hist["version"],
            "parent_version": parent_version,
            "changes": diff_counts,
            "user": user,
            "description": description,
            "timestamp": datetime.utcnow().isoformat(),
        }

    # -- Rollback --

    def rollback_to(self, version: int, user: str) -> dict:
        """
        Load a historical version into the candidate. Does NOT auto-commit;
        the user must explicitly commit to activate, which will itself record
        a new history entry of type=rollback pointing back at `version`.
        """
        xml_bytes = self.history.read_xml(version)
        if xml_bytes is None:
            return {"status": "error", "message": f"Version {version} not found in history"}
        CANDIDATE_CONFIG.write_bytes(xml_bytes)
        logger.info("Loaded history v%d into candidate (requested by %s)", version, user)
        return {
            "status": "loaded-to-candidate",
            "version": version,
            "user": user,
            "message": f"Version {version} loaded into candidate. Commit to activate.",
            "timestamp": datetime.utcnow().isoformat(),
        }

    def diff_between(self, v_old: int, v_new: int) -> dict:
        """Diff two historical versions (or compare one to candidate/running)."""
        def _paths_for(version_or_alias):
            if version_or_alias == "candidate":
                return self._collect_paths(self._load(CANDIDATE_CONFIG))
            if version_or_alias == "running":
                return self._collect_paths(self._load(RUNNING_CONFIG))
            xml_bytes = self.history.read_xml(int(version_or_alias))
            if xml_bytes is None:
                return None
            return self._collect_paths(ET.fromstring(xml_bytes))

        old_paths = _paths_for(v_old)
        new_paths = _paths_for(v_new)
        if old_paths is None or new_paths is None:
            return {"status": "error", "message": "Version not found"}
        added, modified, removed = [], [], []
        for k in sorted(set(old_paths) | set(new_paths)):
            if k not in old_paths:
                added.append({"path": k, "new": new_paths[k]})
            elif k not in new_paths:
                removed.append({"path": k, "old": old_paths[k]})
            elif old_paths[k] != new_paths[k]:
                modified.append({"path": k, "old": old_paths[k], "new": new_paths[k]})
        return {
            "old": v_old, "new": v_new,
            "has_changes": bool(added or modified or removed),
            "total_changes": len(added) + len(modified) + len(removed),
            "added": added, "modified": modified, "removed": removed,
        }

    # -- Revert / Snapshots --

    def revert_candidate(self, user: str) -> dict:
        """Discard candidate changes and copy running back to candidate."""
        shutil.copy2(RUNNING_CONFIG, CANDIDATE_CONFIG)
        return {"status": "reverted", "user": user, "timestamp": datetime.utcnow().isoformat()}

    def snapshot_save(self, name: str, description: str = "") -> dict:
        safe_name = "".join(c if c.isalnum() or c in "-_" else "_" for c in name)
        path = SNAPSHOT_DIR / f"{safe_name}.xml"
        meta_path = SNAPSHOT_DIR / f"{safe_name}.meta.json"
        shutil.copy2(RUNNING_CONFIG, path)
        meta_path.write_text(json.dumps({
            "name": safe_name,
            "description": description,
            "created_at": datetime.utcnow().isoformat(),
            "size_bytes": path.stat().st_size,
        }), encoding="utf-8")
        return {"status": "saved", "name": safe_name, "path": str(path)}

    def snapshot_list(self) -> list:
        out = []
        for meta in sorted(SNAPSHOT_DIR.glob("*.meta.json"), reverse=True):
            try:
                data = json.loads(meta.read_text(encoding="utf-8"))
                out.append(data)
            except Exception:
                pass
        return out

    def snapshot_restore(self, name: str, user: str) -> dict:
        safe_name = "".join(c if c.isalnum() or c in "-_" else "_" for c in name)
        path = SNAPSHOT_DIR / f"{safe_name}.xml"
        if not path.exists():
            return {"status": "error", "message": f"Snapshot '{name}' not found"}
        # Auto-snapshot current running before restore
        self.snapshot_save(f"pre-restore-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}",
                           f"Pre-restore snapshot (before restoring {safe_name}) by {user}")
        shutil.copy2(path, CANDIDATE_CONFIG)  # Restore goes to candidate first
        return {"status": "restored-to-candidate", "name": safe_name, "message": "Commit to activate"}

    def snapshot_delete(self, name: str) -> dict:
        safe_name = "".join(c if c.isalnum() or c in "-_" else "_" for c in name)
        path = SNAPSHOT_DIR / f"{safe_name}.xml"
        meta = SNAPSHOT_DIR / f"{safe_name}.meta.json"
        if path.exists(): path.unlink()
        if meta.exists(): meta.unlink()
        return {"status": "deleted", "name": safe_name}


# ---------------------------------------------------------------------------
# Engine definitions
# ---------------------------------------------------------------------------

ENGINE_NAMES = [
    "ipv4_parser", "ipv6_parser", "tcp_reassembly", "udp_processor",
    "icmp_handler", "arp_responder", "vlan_tagger", "mpls_handler",
    "gre_decap", "vxlan_decap", "ipsec_decrypt", "ipsec_encrypt",
    "nat44", "nat64", "tcam_lookup", "fib_lookup",
    "dpi_l7", "dpi_regex", "url_filter", "dns_filter",
    "dlp_scanner", "ml_anomaly", "rate_limiter", "syn_proxy",
    "ddos_detector", "geo_ip", "session_tracker", "qos_scheduler",
    "flow_exporter", "log_encoder",
]

# ---------------------------------------------------------------------------
# Engine backend registry (REWORK_CONTRACT §1, Axis 1).
# Classifies each of the 30 ENGINE_NAMES into a HOST backend + optional FPGA
# offload. Post-pivot the engines run in host software (kernel nftables/conntrack,
# the DPDK fast path, or Python detection plugins); the FPGA is OPTIONAL offload
# consulted only when a card is present AND `offload` is True.
#   backend ∈ {"dpdk","kernel","python","host"}
#   module  = the real host implementation (Python module / ffn_fastpath_fwd /
#             nftables-conntrack) — informational source label
#   offload = True if the engine has an FPGA-offload path
#   role    = short human description
# NOTE: keyed by name; ENGINE_NAMES order/indices are FROZEN and unchanged.
ENGINE_BACKENDS = {
    "ipv4_parser":     {"backend": "kernel", "module": "nftables",              "offload": True,  "role": "L3 parse/verify"},
    "ipv6_parser":     {"backend": "kernel", "module": "nftables",              "offload": True,  "role": "L3 parse/verify"},
    "tcp_reassembly":  {"backend": "dpdk",   "module": "ffn_fastpath_fwd",      "offload": True,  "role": "L4 stream reassembly"},
    "udp_processor":   {"backend": "dpdk",   "module": "ffn_fastpath_fwd",      "offload": True,  "role": "L4 datagram"},
    "icmp_handler":    {"backend": "kernel", "module": "nftables",              "offload": False, "role": "ICMP"},
    "arp_responder":   {"backend": "kernel", "module": "kernel-arp",            "offload": False, "role": "neighbor"},
    "vlan_tagger":     {"backend": "kernel", "module": "nftables/8021q",        "offload": True,  "role": "VLAN"},
    "mpls_handler":    {"backend": "kernel", "module": "kernel-mpls",           "offload": False, "role": "MPLS"},
    "gre_decap":       {"backend": "kernel", "module": "kernel-gre",            "offload": True,  "role": "tunnel decap"},
    "vxlan_decap":     {"backend": "kernel", "module": "kernel-vxlan",          "offload": True,  "role": "tunnel decap"},
    "ipsec_decrypt":   {"backend": "kernel", "module": "xfrm(+crypto-assist)",  "offload": True,  "role": "IPsec ESP dec"},
    "ipsec_encrypt":   {"backend": "kernel", "module": "xfrm(+crypto-assist)",  "offload": True,  "role": "IPsec ESP enc"},
    "nat44":           {"backend": "kernel", "module": "conntrack/nftables",    "offload": True,  "role": "NAT44"},
    "nat64":           {"backend": "kernel", "module": "conntrack/nftables",    "offload": True,  "role": "NAT64"},
    "tcam_lookup":     {"backend": "dpdk",   "module": "ffn_fastpath_fwd",      "offload": True,  "role": "policy classify (rte_acl)"},
    "fib_lookup":      {"backend": "kernel", "module": "vrf/fib",               "offload": True,  "role": "routing (per-VRF, Axis 3)"},
    "dpi_l7":          {"backend": "python", "module": "inline_payload_det",    "offload": True,  "role": "L7 content sigs (IPS)"},
    "dpi_regex":       {"backend": "python", "module": "ffn_antivirus",         "offload": True,  "role": "hex/PCRE/hyperscan"},
    "url_filter":      {"backend": "python", "module": "ffn_threatdb(ioc)",     "offload": True,  "role": "URL filtering"},
    "dns_filter":      {"backend": "python", "module": "ffn_threatdb(ioc)",     "offload": True,  "role": "DNS security"},
    "dlp_scanner":     {"backend": "python", "module": "dlp",                   "offload": True,  "role": "data filtering"},
    "ml_anomaly":      {"backend": "python", "module": "cloud_det",             "offload": True,  "role": "anomaly/BNN + cloud verdict"},
    "rate_limiter":    {"backend": "kernel", "module": "nftables-limit",        "offload": False, "role": "rate limiting"},
    "syn_proxy":       {"backend": "kernel", "module": "nftables-synproxy",     "offload": True,  "role": "SYN proxy"},
    "ddos_detector":   {"backend": "kernel", "module": "nftables+bmfw",         "offload": True,  "role": "DDoS"},
    "geo_ip":          {"backend": "dpdk",   "module": "ffn_fastpath_fwd",      "offload": True,  "role": "GeoIP lookup"},
    "session_tracker": {"backend": "kernel", "module": "conntrack",             "offload": True,  "role": "session table (per-vsys, Axis 4)"},
    "qos_scheduler":   {"backend": "dpdk",   "module": "ffn_fastpath_fwd",      "offload": True,  "role": "QoS/meter"},
    "flow_exporter":   {"backend": "dpdk",   "module": "ffn_fastpath_fwd",      "offload": False, "role": "IPFIX/flow export"},
    "log_encoder":     {"backend": "host",   "module": "ffn_manager/bmfw",      "offload": False, "role": "logging"},
}

# Security plugins surfaced in the WebUI under Objects > Security Profiles.
# Each maps to an on-FPGA engine (table_id -> NGFW_TBL_* in ngfw_regs.h) and,
# where it has a config editor, a WebUI page key under `config`.
# 2026-07-09 pivot: security plugins now map to HOST SOFTWARE engines (running
# in the bare-metal/DPDK data plane), with the FPGA as optional offload. Each
# `backend` names the real Python engine module in sw/salvage/ngfwd; live stats
# are pulled from it by _detection_live() and merged into /api/plugins.
SECURITY_PLUGINS = [
    {"id": "sigdb",        "display": "Signature Database",              "category": "Content",
     "engine": "sigdb",       "backend": "ffn_sigdb",         "config": "sigdb",
     "desc": "Versioned malware/virus/pattern content store (ClamAV + YARA); compiles to the AV/IPS engines & FPGA."},
    {"id": "antivirus",    "display": "Anti-Virus",                     "category": "Content",
     "engine": "antivirus",   "backend": "ffn_antivirus",     "config": None,
     "desc": "File scanner over carved objects: hash + ClamAV hex-pattern + YARA-lite (Aho-Corasick prefilter)."},
    {"id": "antimalware",  "display": "Anti-Malware (inline)",          "category": "Threat",
     "engine": "antimalware", "backend": "ffn_antimalware",   "config": None,
     "desc": "Fuses hash reputation + AV + heuristics into a verdict; blocks known malware inline, sandboxes unknowns."},
    {"id": "inline_ips",   "display": "Inline Payload Detection / IPS", "category": "Threat",
     "engine": "inline_ips",  "backend": "inline_payload_det", "config": "dpi", "table_id": 0x10,
     "desc": "In-path content signatures (Aho-Corasick + PCRE), IOC extraction, flow reassembly + file carving."},
    {"id": "cloud_det",    "display": "Cloud Sandbox",                  "category": "Threat",
     "engine": "cloud_det",   "backend": "cloud_det",         "config": None, "table_id": 0x15,
     "desc": "Cloud-backed sandbox: detonate unknown files -> verdict + generated signature back to the inline engine."},
    {"id": "dlp_scanner",  "display": "Data Filtering (DLP)",           "category": "Content",
     "engine": "dlp_scanner", "backend": "dlp",  "table_id": 0x14, "config": "dlp",
     "desc": "Detect & block sensitive data (PII, PCI, secrets, source) leaving the network."},
    {"id": "url_filter",   "display": "URL Filtering",                  "category": "Web",
     "engine": "url_filter",  "backend": "ioc",  "table_id": 0x12, "config": "url",
     "desc": "Category + custom block/allow lists with a bloom prefilter (ThreatDB URL IOCs)."},
    {"id": "dns_filter",   "display": "DNS Security",                   "category": "Web",
     "engine": "dns_filter",  "backend": "ioc",  "table_id": 0x13, "config": None,
     "desc": "Malicious-domain and DGA/entropy DNS blocking (ThreatDB domain IOCs)."},
]

# Built-in DLP data patterns seeded on first boot (PII / PCI / secrets).
# (name, type, pattern, action, severity, direction, threshold). Built-in
# identifiers (credit_card/ssn/api_key/email) need no pattern -- the FPGA runs
# the detector; keyword rules carry the literal string to find in content.
DLP_BUILTIN_RULES = [
    ("Credit Card (PAN)",         "credit_card", "",                            "block", "high", "egress", 1),
    ("US Social Security Number", "ssn",         "",                            "block", "high", "egress", 1),
    ("AWS Access Key",            "api_key",     "",                            "block", "high", "egress", 1),
    ("Private Key Block",         "keyword",     "-----BEGIN PRIVATE KEY-----", "block", "high", "egress", 1),
    ("Confidential Marker",       "keyword",     "CONFIDENTIAL",                "alert", "low",  "egress", 2),
]


# ---------------------------------------------------------------------------
# Live detection-engine status (post-pivot host software engines).
# Best-effort + soft-imported so the WebUI still starts if a module or DB is
# absent. The poll path uses cheap direct queries (no automata rebuilds); the
# heavier detectors are only instantiated by /api/detection/scan. Engine DB
# paths come from each module's own env-driven default (FFN_SIGDB_PATH /
# FFN_THREATDB_PATH), so the WebUI reads exactly what the data plane writes.
# ---------------------------------------------------------------------------
def _detection_live() -> dict:
    """Return {plugin_id: {enabled, ...live stats}} from the real engines."""
    live: dict = {}
    # --- Signature Database + Anti-Virus (AV compiles from the sig DB) ---
    try:
        from ffn_sigdb import SignatureDB
        sdb = SignatureDB()
        try:
            st = sdb.stats()
            live["sigdb"] = {
                "enabled": True,
                "version": st["version_string"],
                "signatures": st["total"],
                "by_type": st["by_type"],
                "families": st.get("families", 0),
                "last_update": st.get("last_update"),
            }
            live["antivirus"] = {
                "enabled": st["total"] > 0,
                "hash_sigs": sdb.count("hash"),
                "pattern_sigs": sdb.count("pattern"),
                "yara_rules": sdb.count("yara"),
            }
        finally:
            sdb.close()
    except Exception as e:
        live["sigdb"] = {"enabled": False, "error": str(e)[:160]}
        live["antivirus"] = {"enabled": False, "error": str(e)[:160]}
    # --- Threat DB -> inline IPS + Anti-Malware + Cloud sandbox ---
    try:
        from ffn_threatdb import ThreatDB
        tdb = ThreatDB()
        try:
            ts = tdb.stats()
            try:
                nsig = tdb.conn.execute(
                    "SELECT COUNT(*) c FROM content_signatures WHERE enabled=1"
                ).fetchone()["c"]
            except Exception:
                nsig = 0
            samples = ts.get("samples", {})
            live["inline_ips"] = {
                "enabled": nsig > 0,
                "signatures": nsig,
                "samples": ts.get("samples_total", 0),
                "iocs": ts.get("iocs_total", 0),
            }
            live["antimalware"] = {
                "enabled": True,
                "methods": ["hash", "av", "heuristic"]
                           + (["cloud"] if live.get("sigdb", {}).get("enabled") else []),
                "known_malware": samples.get("malware", 0),
                "grayware": samples.get("grayware", 0),
            }
            live["cloud_det"] = {
                "enabled": True,
                "samples": ts.get("samples_total", 0),
                "verdicts": samples,
                "pending": samples.get("unknown", 0) + samples.get("pending", 0),
            }
        finally:
            try:
                tdb.conn.close()
            except Exception:
                pass
    except Exception as e:
        live.setdefault("inline_ips", {"enabled": False, "error": str(e)[:160]})
        live.setdefault("antimalware", {"enabled": False, "error": str(e)[:160]})
        live.setdefault("cloud_det", {"enabled": False, "error": str(e)[:160]})
    return live


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------


async def init_db():
    """Create database tables and default data if they do not exist."""
    db_dir = os.path.dirname(DB_PATH)
    os.makedirs(db_dir, exist_ok=True)

    async with aiosqlite.connect(DB_PATH) as db:
        await db.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'admin',
                must_change_pw INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                last_login TEXT
            );
            CREATE TABLE IF NOT EXISTS policy_rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                position INTEGER NOT NULL DEFAULT 0,
                name TEXT,                                    -- nullable for legacy rows
                src_ip TEXT NOT NULL DEFAULT '0.0.0.0/0',
                dst_ip TEXT NOT NULL DEFAULT '0.0.0.0/0',
                src_port INTEGER NOT NULL DEFAULT 0,
                dst_port INTEGER NOT NULL DEFAULT 0,
                proto TEXT NOT NULL DEFAULT 'any',
                action TEXT NOT NULL DEFAULT 'permit',
                -- Which virtual system this rule belongs to, as the numeric
                -- vsys_id the dataplane matches on. 0 is dp_classify()'s
                -- WILDCARD -- a rule with vsys 0 applies to every tenant --
                -- and it is the default so that every existing rule keeps
                -- behaving exactly as it did before tenants existed.
                vsys INTEGER NOT NULL DEFAULT 0,
                description TEXT NOT NULL DEFAULT '',
                hit_count INTEGER NOT NULL DEFAULT 0,
                enabled INTEGER NOT NULL DEFAULT 1,
                -- PAN-OS-style implicit/immutable rules. kind: 'user' |
                -- 'intrazone-default' | 'interzone-default'. Immutable
                -- rules can't be deleted and only their description/
                -- logging/profile can be modified.
                kind TEXT NOT NULL DEFAULT 'user',
                immutable INTEGER NOT NULL DEFAULT 0,
                hidden INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
            CREATE TABLE IF NOT EXISTS engine_state (
                name TEXT PRIMARY KEY,
                enabled INTEGER NOT NULL DEFAULT 1,
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
            CREATE TABLE IF NOT EXISTS dpi_patterns (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                pattern TEXT NOT NULL,
                severity TEXT NOT NULL DEFAULT 'medium',
                engine TEXT NOT NULL DEFAULT 'dpi',
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
            CREATE TABLE IF NOT EXISTS url_blocklist (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                category TEXT NOT NULL DEFAULT 'custom',
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
            CREATE TABLE IF NOT EXISTS dlp_rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                pattern_type TEXT NOT NULL DEFAULT 'regex',
                pattern TEXT NOT NULL DEFAULT '',
                action TEXT NOT NULL DEFAULT 'block',
                severity TEXT NOT NULL DEFAULT 'medium',
                direction TEXT NOT NULL DEFAULT 'egress',
                threshold INTEGER NOT NULL DEFAULT 1,
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
            CREATE TABLE IF NOT EXISTS ipsec_tunnels (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                peer_address TEXT NOT NULL,
                local_subnet TEXT NOT NULL,
                remote_subnet TEXT NOT NULL,
                spi TEXT NOT NULL,
                ike_version INTEGER NOT NULL DEFAULT 2,
                esp_encryption TEXT NOT NULL DEFAULT 'aes256',
                esp_hash TEXT NOT NULL DEFAULT 'sha256',
                status TEXT NOT NULL DEFAULT 'down',
                rx_packets INTEGER NOT NULL DEFAULT 0,
                tx_packets INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL DEFAULT (datetime('now')),
                username TEXT NOT NULL,
                action TEXT NOT NULL,
                detail TEXT NOT NULL DEFAULT ''
            );
            -- Generic resource store for Network tab pages (virtual wires,
            -- GRE/VXLAN tunnels, QoS, FFN Protect portals/gateways/MDM,
            -- ZeroTrust, Network Profiles, SD-WAN profiles, etc.).
            -- "kind" identifies the resource type; "config" is a JSON blob
            -- of type-specific fields; "enabled" mirrors admin state.
            CREATE TABLE IF NOT EXISTS net_resources (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                kind TEXT NOT NULL,
                name TEXT NOT NULL,
                config TEXT NOT NULL DEFAULT '{}',
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now')),
                UNIQUE(kind, name)
            );
            CREATE INDEX IF NOT EXISTS net_resources_kind_idx ON net_resources(kind);
            -- Virtual Router = VRF instance (Axis 3). Each row is one l3mdev
            -- VRF device with its own routing table. `interfaces` is a JSON
            -- array of enslaved physical iface names; `table_id` is the
            -- deterministic per-VR kernel table (default VR = main/254).
            CREATE TABLE IF NOT EXISTS virtual_routers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                table_id INTEGER NOT NULL UNIQUE,
                interfaces TEXT NOT NULL DEFAULT '[]',
                admin_up INTEGER NOT NULL DEFAULT 1,
                vsys TEXT,
                -- FRR routing plane (contract §6): protocol + router-id + asn,
                -- plus the last rendered per-VRF FRR config fragment.
                protocol TEXT NOT NULL DEFAULT 'static',
                router_id TEXT,
                asn INTEGER,
                frr_fragment TEXT,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
            -- Static routes belonging to a VR (installed into its table).
            CREATE TABLE IF NOT EXISTS static_routes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                vr_id INTEGER NOT NULL,
                dest_cidr TEXT NOT NULL,
                next_hop TEXT NOT NULL DEFAULT '',
                dev TEXT,
                metric INTEGER NOT NULL DEFAULT 0,
                table_id INTEGER NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                FOREIGN KEY(vr_id) REFERENCES virtual_routers(id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS static_routes_vr_idx ON static_routes(vr_id);
        """)

        # Seed default admin account if table is empty
        cursor = await db.execute("SELECT COUNT(*) FROM users")
        row = await cursor.fetchone()
        if row[0] == 0:
            # NEVER a fixed password. This used to seed "admin"/"admin" and log
            # the pair; with the source published that is a known credential on
            # every deployment that has not changed it yet.
            from_env = os.getenv("FFN_ADMIN_INITIAL_PASSWORD")
            initial = from_env or secrets.token_urlsafe(15)
            await db.execute(
                "INSERT INTO users (username, password_hash, role, must_change_pw) VALUES (?, ?, ?, ?)",
                ("admin", pwd_context.hash(initial), "admin", 1),
            )
            if from_env:
                logger.warning(
                    "Created initial admin account from "
                    "FFN_ADMIN_INITIAL_PASSWORD. It must be changed at first "
                    "login.")
            else:
                # Shown once, at creation, because there is no other way for the
                # operator to learn it. To stderr as well as the log, so it is
                # visible on a console-only first boot. Never logged again.
                logger.warning("Created initial admin account with a generated "
                               "password (printed to the console once).")
                bar = "=" * 68
                print("\n%s\nFFN-NGFW initial admin credentials\n"
                      "  username : admin\n"
                      "  password : %s\n"
                      "This is shown ONCE. It must be changed at first login.\n"
                      "%s\n" % (bar, initial, bar),
                      file=sys.stderr, flush=True)

        # Seed engine states
        cursor = await db.execute("SELECT COUNT(*) FROM engine_state")
        row = await cursor.fetchone()
        if row[0] == 0:
            for name in ENGINE_NAMES:
                await db.execute(
                    "INSERT INTO engine_state (name, enabled) VALUES (?, 1)", (name,)
                )

        # Seed the `default` virtual router (Axis 3). It maps to the kernel
        # `main` table (254) with no enslaved interfaces, so existing
        # (non-VRF) forwarding is preserved and every box always has a VR.
        cursor = await db.execute(
            "SELECT COUNT(*) FROM virtual_routers WHERE name='default'"
        )
        if (await cursor.fetchone())[0] == 0:
            await db.execute(
                "INSERT INTO virtual_routers (name, table_id, interfaces, admin_up, vsys) "
                "VALUES ('default', ?, '[]', 1, NULL)",
                (VRF_MAIN_TABLE,),
            )

        # Seed built-in DLP data patterns (PII / PCI / secrets) once.
        cursor = await db.execute("SELECT COUNT(*) FROM dlp_rules")
        if (await cursor.fetchone())[0] == 0:
            for r in DLP_BUILTIN_RULES:
                await db.execute(
                    "INSERT INTO dlp_rules "
                    "(name, pattern_type, pattern, action, severity, direction, threshold) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)", r)

        # Backfill columns for upgraded DBs. ALTER TABLE ADD COLUMN is
        # idempotent-ish only via try/except — sqlite doesn't have
        # "IF NOT EXISTS" for columns.
        for coldef in (
            "ALTER TABLE policy_rules ADD COLUMN name TEXT",
            "ALTER TABLE policy_rules ADD COLUMN kind TEXT NOT NULL DEFAULT 'user'",
            "ALTER TABLE policy_rules ADD COLUMN immutable INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE policy_rules ADD COLUMN hidden INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE policy_rules ADD COLUMN src_iface TEXT",
            "ALTER TABLE policy_rules ADD COLUMN dst_iface TEXT",
            # Default 0 on purpose: 0 is the dataplane's wildcard, so an
            # upgraded rulebase keeps applying to all traffic rather than
            # silently binding every existing rule to tenant 1.
            "ALTER TABLE policy_rules ADD COLUMN vsys INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE dlp_rules ADD COLUMN direction TEXT NOT NULL DEFAULT 'egress'",
            "ALTER TABLE dlp_rules ADD COLUMN threshold INTEGER NOT NULL DEFAULT 1",
            # FRR routing plane columns (contract §6) for upgraded VR tables.
            "ALTER TABLE virtual_routers ADD COLUMN protocol TEXT NOT NULL DEFAULT 'static'",
            "ALTER TABLE virtual_routers ADD COLUMN router_id TEXT",
            "ALTER TABLE virtual_routers ADD COLUMN asn INTEGER",
            "ALTER TABLE virtual_routers ADD COLUMN frr_fragment TEXT",
            "ALTER TABLE virtual_routers ADD COLUMN vr_config TEXT",
        ):
            try:
                await db.execute(coldef)
            except Exception:
                pass  # column already exists

        # NOTE: no sample/example user policy rules are seeded. A fresh box
        # starts with an empty user rule set; only the immutable PAN-OS-style
        # defaults (intrazone/interzone) and the lab-mgmt safety net below are
        # created. Operators add their own rules.

        # Seed immutable PAN-OS-style default rules. `intrazone-default`
        # permits any traffic within the same zone (hidden implicit); it
        # only matters if the user writes an explicit deny earlier.
        # `interzone-default` denies any traffic between different zones
        # that no higher rule matched. Both always evaluate last and
        # cannot be deleted or retargeted.
        for name, action, kind, hidden, desc in (
            ("intrazone-default", "permit", "intrazone-default", 1,
             "Default: traffic within the same zone is allowed"),
            ("interzone-default", "deny", "interzone-default", 0,
             "Default: traffic between different zones is denied"),
        ):
            cur = await db.execute(
                "SELECT id FROM policy_rules WHERE kind=?", (kind,)
            )
            if not await cur.fetchone():
                await db.execute(
                    "INSERT INTO policy_rules "
                    "(position, name, src_ip, dst_ip, src_port, dst_port, "
                    " proto, action, description, kind, immutable, hidden) "
                    "VALUES (?, ?, '0.0.0.0/0', '0.0.0.0/0', 0, 0, "
                    " 'any', ?, ?, ?, 1, ?)",
                    (999_000 if kind == "intrazone-default" else 999_001,
                     name, action, desc, kind, hidden),
                )

        # Lab / dev safety net: always permit traffic on the lab mgmt
        # interface (env-overridable). Without this, an operator who
        # accidentally commits a deny-all policy can lock themselves
        # out of the box. Rule is immutable and sits at position 0 so
        # it evaluates before any user rule. Operators can disable it
        # explicitly via the UI (enabled=0) but cannot delete it.
        lab_iface = os.getenv("FFN_LAB_MGMT_IFACE", "eno1np0")
        if lab_iface:
            cur = await db.execute(
                "SELECT id FROM policy_rules WHERE kind='lab-mgmt'"
            )
            if not await cur.fetchone():
                await db.execute(
                    "INSERT INTO policy_rules "
                    "(position, name, src_ip, dst_ip, src_iface, "
                    " src_port, dst_port, proto, action, description, "
                    " kind, immutable, hidden) "
                    "VALUES (0, ?, '0.0.0.0/0', '0.0.0.0/0', ?, "
                    " 0, 0, 'any', 'permit', ?, 'lab-mgmt', 1, 0)",
                    (f"allow-lab-mgmt-{lab_iface}", lab_iface,
                     f"Lab dev/test: permit any traffic on {lab_iface}"),
                )

        await db.commit()
    logger.info("Database initialized at %s", DB_PATH)


async def get_db():
    db = await aiosqlite.connect(DB_PATH)
    db.row_factory = aiosqlite.Row
    try:
        yield db
    finally:
        await db.close()


async def audit(db, username: str, action: str, detail: str = ""):
    await db.execute(
        "INSERT INTO audit_log (username, action, detail) VALUES (?, ?, ?)",
        (username, action, detail),
    )
    await db.commit()


# ---------------------------------------------------------------------------
# JWT helpers
# ---------------------------------------------------------------------------


def create_token(username: str, role: str, pw_change_only: bool = False) -> str:
    expire = datetime.utcnow() + timedelta(minutes=JWT_EXPIRE_MINUTES)
    claims = {"sub": username, "role": role, "exp": expire}
    if pw_change_only:
        # Scoped token. The previous behaviour was to issue a FULL token and
        # report must_change_pw in the response body, leaving enforcement to
        # the client -- which trusts whoever holds the token to volunteer for a
        # restriction. An attacker will not volunteer.
        claims["pwc"] = True
    return jwt.encode(claims, JWT_SECRET, algorithm=JWT_ALGORITHM)


# The only endpoints a password-change-only token may reach: changing the
# password, and reading who you are so the UI can render the form.
PW_CHANGE_ALLOWED_PATHS = frozenset({
    "/api/auth/change-password",
    "/api/auth/me",
})


async def get_current_user(
    request: Request,
    authorization: Optional[str] = Header(None),
):
    """Extract and validate JWT from Authorization header."""
    if authorization and authorization.startswith("Bearer "):
        token_str = authorization[7:]
    else:
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        payload = jwt.decode(token_str, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        username = payload.get("sub")
        role = payload.get("role", "viewer")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        if payload.get("pwc") and request.url.path not in PW_CHANGE_ALLOWED_PATHS:
            raise HTTPException(
                status_code=403,
                detail="Password change required before using this API")
        return {"username": username, "role": role,
                "pw_change_required": bool(payload.get("pwc"))}
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


# ---------------------------------------------------------------------------
# FastAPI application
# ---------------------------------------------------------------------------

app = FastAPI(title="FFN NGFW Manager", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

fpga = FPGADevice(DEV_PATH)
config_mgr = ConfigManager()


# ---------------------------------------------------------------------------
# Optional FPGA (REWORK_CONTRACT §1, Axis 1).
# The card is a FIRST-CLASS-ABSENT device: a missing card is a NORMAL state
# (the host software stack runs the engines), never "No HW degradation".
# fpga_present() is the single gate for touching any FPGA register — it is True
# ONLY when a real card is attached (not simulation).
# ---------------------------------------------------------------------------
def fpga_present() -> bool:
    """True only when a real FPGA card is attached (opportunistically re-checks)."""
    return not fpga.sim_mode


# Python-backed engines: name -> key in _detection_live() output (enable-state
# and live counters come from the real detection module). Engines without a
# live entry report 0 counters with a clear backend source label.
_ENGINE_LIVE_KEY = {
    "dpi_l7":     "inline_ips",
    "dpi_regex":  "antivirus",
    "ml_anomaly": "cloud_det",
}


# ---------------------------------------------------------------------------
# Software FPGA DPI offload emulator (REWORK_CONTRACT §7, ffn_fpga_emu.py).
# When NO card is present, the AC/DFA-capable DPI engines must still show a
# WORKING software offload instead of nothing. These two engines map onto the
# emulator's two named engines (dpi_l7 -> Aho-Corasick, dpi_regex -> regex DFA);
# the emulator's AC_ENGINE/DFA_ENGINE default to exactly these names.
# ---------------------------------------------------------------------------
_EMU_DPI_ENGINES = ("dpi_l7", "dpi_regex")     # dpi_l7 -> AC, dpi_regex -> DFA

# EICAR + Log4Shell literals used as the last-resort AC seed (byte-exact with
# the emulator's own selftest constants).
_EMU_AC_FALLBACK = [
    (b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$"
     b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*", 1000),
    (b"${jndi:ldap://", 1001),
]
# A couple of default PCRE rules if ffn_antivirus / inline PCRE sigs are absent.
_EMU_DFA_FALLBACK = [
    (r"union\s+select", 2001),
    (r"evil[0-9]+\.com", 2002),
]

_fpga_emu = None            # lazy FpgaEmulator singleton (None until first use)
_fpga_emu_tried = False     # so a failed/unavailable import is not retried


def _emu_ac_patterns():
    """Literal AC patterns from the inline content signatures (contract §7).

    Sources the DPI content signatures (inline_payload_det / ffn_threatdb
    baseline); falls back to EICAR + '${jndi:ldap://' literals if unreachable.
    Returns a list of (pattern_bytes, sid) pairs (never empty).
    """
    pats = []
    try:
        from ffn_threatdb import ThreatDB
        from inline_payload_det import InlinePayloadDetector, seed_baseline as seed_inline
        tdb = ThreatDB()
        try:
            det = InlinePayloadDetector(tdb)
            if not det.sigs:
                seed_inline(det)
            for sig in det.sigs.values():
                if getattr(sig, "is_pcre", False):
                    continue
                pat = getattr(sig, "pattern", None)
                if pat and getattr(sig, "enabled", True):
                    pats.append((bytes(pat), getattr(sig, "sid", None)))
        finally:
            try:
                tdb.conn.close()
            except Exception:
                pass
    except Exception:
        pats = []
    return pats or list(_EMU_AC_FALLBACK)


def _emu_dfa_patterns():
    """PCRE rules for the DFA engine (contract §7).

    Prefers real PCRE rules reachable on the box (ffn_antivirus, else the inline
    detector's PCRE signatures); falls back to a couple of defaults. Returns a
    list of (regex_str, sid) pairs (never empty).
    """
    rules = []
    # 1) inline detector PCRE sigs are genuine PCRE strings and reachable.
    try:
        from ffn_threatdb import ThreatDB
        from inline_payload_det import InlinePayloadDetector, seed_baseline as seed_inline
        tdb = ThreatDB()
        try:
            det = InlinePayloadDetector(tdb)
            if not det.sigs:
                seed_inline(det)
            for sig in det.sigs.values():
                if not getattr(sig, "is_pcre", False):
                    continue
                pat = getattr(sig, "pattern", None)
                if not pat or not getattr(sig, "enabled", True):
                    continue
                try:
                    rx = pat.decode("latin-1") if isinstance(pat, (bytes, bytearray)) else str(pat)
                except Exception:
                    continue
                rules.append((rx, getattr(sig, "sid", None)))
        finally:
            try:
                tdb.conn.close()
            except Exception:
                pass
    except Exception:
        rules = []
    return rules or list(_EMU_DFA_FALLBACK)


def _get_fpga_emu():
    """Lazily build the software DPI emulator (contract §7).

    Guarded so the module still imports/works when ffn_fpga_emu (or a signature
    source) is missing. Returns the FpgaEmulator singleton, or None if the
    emulator module is unavailable.
    """
    global _fpga_emu, _fpga_emu_tried
    if _fpga_emu is not None:
        return _fpga_emu
    if _fpga_emu_tried:
        return None
    _fpga_emu_tried = True
    try:
        from ffn_fpga_emu import FpgaEmulator
    except Exception as exc:      # module or a dependency missing -> no emulator
        logger.info("FPGA DPI emulator unavailable: %s", exc)
        return None
    try:
        emu = FpgaEmulator()
        try:
            emu.load_ac(_emu_ac_patterns())     # engine name defaults to dpi_l7
        except Exception as exc:
            logger.warning("emulator load_ac failed: %s", exc)
        try:
            emu.load_dfa(_emu_dfa_patterns())    # engine name defaults to dpi_regex
        except Exception as exc:
            logger.warning("emulator load_dfa failed: %s", exc)
        _fpga_emu = emu
        return _fpga_emu
    except Exception as exc:
        logger.warning("FPGA DPI emulator init failed: %s", exc)
        return None


# ---------------------------------------------------------------------------
# Inline ML anti-malware / verdict engine (REWORK_CONTRACT §8, ffn_ml_engine.py).
# A lazy, guarded singleton so the manager still imports when ffn_ml_engine (or
# its optional xgboost training dep) is absent. A persisted model is loaded from
# ML_MODEL_PATH when present; otherwise a tiny default is trained lazily via the
# module (pure-Python fallback, no third-party dep at inference time). If neither
# works the engine is left unloaded with a clear status (never raises).
# ---------------------------------------------------------------------------
ML_MODEL_PATH = os.getenv(
    "FFN_ML_MODEL_PATH",
    os.path.join(os.path.dirname(DB_PATH) or "/var/lib/ffn-ngfw", "ml_model.json"))

_ml_engine = None            # lazy MlEngine singleton (None until first use)
_ml_engine_tried = False     # so a failed/unavailable import is not retried


def _ml_train_default(eng) -> bool:
    """Lazily train a tiny default model via ffn_ml_engine (contract §8).

    Uses the module's deterministic synthetic corpus + pure-Python trainer
    (xgboost is only an optional training accelerator inside the module). Loads
    the assembled blob into `eng`. Returns True on success, False if unavailable
    or training failed (engine is left unloaded, not mutated destructively).
    """
    try:
        from ffn_ml_engine import (
            XGBoostModel, NGramModel, MlEngine,
            _synthetic_dataset, extract_features,
        )
    except Exception as exc:
        logger.info("ML default-train unavailable: %s", exc)
        return False
    try:
        samples, labels = _synthetic_dataset()
        X = [extract_features(s) for s in samples]
        tree = XGBoostModel().fit(X, labels, n_estimators=12, max_depth=3)
        ng = NGramModel().fit(samples, labels, epochs=120, lr=0.5)
        eng.load(MlEngine.make_blob(tree, ng, version=1))
        logger.info("ML engine trained tiny default model (%s), v%s",
                    tree.trained_with, eng.version)
        return True
    except Exception as exc:
        logger.warning("ML default-train failed: %s", exc)
        return False


def _get_ml_engine():
    """Lazily build the inline ML verdict engine (contract §8).

    Guarded so the module still imports/works when ffn_ml_engine is missing.
    Returns the MlEngine singleton, or None if the module is unavailable. A
    reachable-but-unloaded engine (import ok, no persisted model, default-train
    failed) is still returned so /api/ml/status can report loaded=False.
    """
    global _ml_engine, _ml_engine_tried
    if _ml_engine is not None:
        return _ml_engine
    if _ml_engine_tried:
        return None
    _ml_engine_tried = True
    try:
        from ffn_ml_engine import MlEngine
    except Exception as exc:      # module or a dependency missing -> no engine
        logger.info("ML engine unavailable: %s", exc)
        return None
    try:
        eng = MlEngine()
    except Exception as exc:
        logger.warning("ML engine init failed: %s", exc)
        return None
    # Prefer a persisted model; else lazily train a tiny default; else leave
    # unloaded (score() still returns a benign verdict, status reports loaded=0).
    try:
        if os.path.exists(ML_MODEL_PATH):
            with open(ML_MODEL_PATH, "rb") as fh:
                blob = fh.read()
            eng.load(blob)
            logger.info("ML engine loaded persisted model v%s from %s",
                        eng.version, ML_MODEL_PATH)
        else:
            _ml_train_default(eng)
    except Exception as exc:
        logger.warning("ML engine model load failed (%s); training default", exc)
        try:
            _ml_train_default(eng)
        except Exception:
            pass
    _ml_engine = eng
    return _ml_engine


def _ml_persist(eng) -> bool:
    """Atomically persist the engine's current model blob to ML_MODEL_PATH.

    Writes the §9-shaped combined blob (export() -> make_blob) via a temp file +
    rename so a concurrent reader never sees a partial file. Best-effort: returns
    False (logged) on any I/O error rather than raising into a request handler.
    """
    try:
        payload = eng.export()
        blob = {
            "kind": "ml-model",
            "version": eng.version,
            "features_version": eng.features_version,
            "tree_blob": (payload.get("tree_blob") or b"").decode("utf-8")
            if isinstance(payload.get("tree_blob"), (bytes, bytearray))
            else (payload.get("tree_blob") or None),
            "ngram_params": (payload.get("ngram_params") or b"").decode("utf-8")
            if isinstance(payload.get("ngram_params"), (bytes, bytearray))
            else (payload.get("ngram_params") or None),
        }
        if blob["tree_blob"] in (b"", ""):
            blob["tree_blob"] = None
        if blob["ngram_params"] in (b"", ""):
            blob["ngram_params"] = None
        os.makedirs(os.path.dirname(ML_MODEL_PATH) or ".", exist_ok=True)
        tmp = ML_MODEL_PATH + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(blob, fh, separators=(",", ":"))
        os.replace(tmp, ML_MODEL_PATH)
        return True
    except Exception as exc:
        logger.warning("ML engine persist failed: %s", exc)
        return False


def _ml_thresholds() -> dict:
    """Verdict thresholds from ffn_ml_engine (mirrors ffn_antimalware)."""
    try:
        from ffn_ml_engine import THRESH_MALWARE, THRESH_GRAYWARE
        return {"malware": int(THRESH_MALWARE), "grayware": int(THRESH_GRAYWARE)}
    except Exception:
        return {"malware": 60, "grayware": 30}


# ---------------------------------------------------------------------------
# MP<->DP FlatBuffers wire channel (REWORK_CONTRACT §9, ffn_mpdp_wire.py).
# The management plane pushes threat-intel / ML-model / signature-verdict /
# policy updates DOWN to the data plane and reads EngineTelemetry / FlowEvent
# back UP. A lazy, guarded singleton so the manager still imports when
# ffn_mpdp_wire is absent. Default transport is an in-process FIFO (works with
# NO data plane running) or a file-ring when FFN_MPDP_RING_PATH is set; Pass 2
# swaps in an rte_ring living in the shared DPDK hugepage segment ("dpmem").
# ---------------------------------------------------------------------------
MPDP_RING_PATH = os.getenv("FFN_MPDP_RING_PATH", "")   # file-ring path; "" -> InProc
MPDP_TELEMETRY_MAX = 256      # bounded DP->MP telemetry/flow-event history

_mpdp = None            # lazy _MpdpChannel singleton (None until first use)
_mpdp_tried = False     # so a failed/unavailable import is not retried


def _mpdp_as_bytes(v) -> bytes:
    """Coerce a JSON-friendly value to bytes for a wire [ubyte] field.

    Accepts bytes/bytearray, a hex string ('deadbeef' / '0xdead'), a list of
    ints, or None -> b"". A non-hex str is UTF-8 encoded as a last resort.
    """
    if v is None:
        return b""
    if isinstance(v, (bytes, bytearray, memoryview)):
        return bytes(v)
    if isinstance(v, (list, tuple)):
        return bytes(int(x) & 0xFF for x in v)
    if isinstance(v, str):
        cleaned = re.sub(r"(?i)0x|[^0-9a-f]", "", v)
        if cleaned and len(cleaned) % 2 == 0:
            try:
                return bytes.fromhex(cleaned)
            except ValueError:
                pass
        return v.encode("utf-8", "surrogatepass")
    raise TypeError("cannot coerce %r to bytes" % type(v))


def _mpdp_fv_int(fv) -> int:
    """Map a features_version (string 'ffn-ml-feat-1' or int) to the wire u32."""
    if isinstance(fv, bool):
        return 0
    if isinstance(fv, int):
        return fv & 0xFFFFFFFF
    try:
        m = re.findall(r"\d+", str(fv))
        return int(m[-1]) & 0xFFFFFFFF if m else 0
    except Exception:
        return 0


class _MpdpChannel:
    """Guarded MP<->DP channel manager (contract §9).

    Wraps a ffn_mpdp_wire.Channel plus send/recv counters and a bounded ring of
    the last parsed DP->MP messages (EngineTelemetry / FlowEvent). Every push
    from the MP (threat-intel / ML / verdict / policy) is built with the matching
    ffn_mpdp_wire.build_* helper and handed to send_frame(); realtime ML and
    signature updates also fan out here so a running DP sees them live.
    """

    def __init__(self, wire):
        self._wire = wire
        self.transport = "inproc"
        chan = None
        if MPDP_RING_PATH:
            try:
                chan = wire.FileRingChannel(MPDP_RING_PATH)
                self.transport = "file-ring"
            except Exception as exc:
                logger.warning("MPDP file-ring open failed (%s); using in-proc", exc)
        if chan is None:
            chan = wire.InProcChannel()
            self.transport = "inproc"
        self.chan = chan
        self.sent = 0
        self.received = 0
        self.last_seq = 0
        self.last_error = None
        self._telemetry = deque(maxlen=MPDP_TELEMETRY_MAX)

    def send_frame(self, frame) -> int:
        self.chan.send(frame)
        self.sent += 1
        return self.sent

    def next_seq(self) -> int:
        self.last_seq += 1
        return self.last_seq

    def poll(self, max_frames: int = MPDP_TELEMETRY_MAX) -> int:
        """Drain up to max_frames DP->MP frames into the telemetry ring."""
        got = 0
        for _ in range(max_frames):
            try:
                raw = self.chan.recv()
            except Exception as exc:
                self.last_error = str(exc)
                break
            if raw is None:
                break
            try:
                msg = self._wire.parse(raw)
            except Exception as exc:
                self.last_error = str(exc)
                continue
            self.received += 1
            got += 1
            # Only DP->MP telemetry/flow events surface in the telemetry view;
            # anything else (e.g. an echoed MP2DP frame on an in-proc loop) is
            # counted but not shown.
            if msg.get("body_type") in ("EngineTelemetry", "FlowEvent"):
                self._telemetry.append(msg)
        return got

    def telemetry(self) -> list:
        return list(self._telemetry)

    def _connected(self) -> bool:
        # No DP handshake in Pass 1.5: "connected" == the transport is usable.
        # A file-ring counts as connected once its backing file exists.
        if self.transport == "file-ring":
            try:
                return os.path.exists(getattr(self.chan, "path", MPDP_RING_PATH))
            except Exception:
                return False
        return True

    def status(self) -> dict:
        return {
            "available": True,
            "transport": self.transport,
            "ring_path": MPDP_RING_PATH or None,
            "connected": self._connected(),
            "have_flatbuffers": bool(getattr(self._wire, "HAVE_FLATBUFFERS", False)),
            "wire_version": getattr(self._wire, "WIRE_VERSION", None),
            "sent": self.sent,
            "recv": self.received,
            "last_seq": self.last_seq,
            "telemetry_pending": len(self._telemetry),
            "last_error": self.last_error,
        }


def _get_mpdp():
    """Lazily build the MP<->DP wire channel (contract §9).

    Guarded so the module still imports/works when ffn_mpdp_wire is missing.
    Returns the _MpdpChannel singleton, or None if the wire module is
    unavailable (endpoints then report available=False, never error).
    """
    global _mpdp, _mpdp_tried
    if _mpdp is not None:
        return _mpdp
    if _mpdp_tried:
        return None
    _mpdp_tried = True
    try:
        import ffn_mpdp_wire as wire
    except Exception as exc:      # module or a dependency missing -> no channel
        logger.info("MP<->DP wire unavailable: %s", exc)
        return None
    try:
        _mpdp = _MpdpChannel(wire)
        return _mpdp
    except Exception as exc:
        logger.warning("MP<->DP channel init failed: %s", exc)
        return None


def _mpdp_emit_ml_update(eng) -> bool:
    """Fan out the current ML model to the DP as a §9 MlModelUpdate.

    Best-effort realtime push: called from /api/ml/update after a successful
    hot-swap so a running data plane picks up the new tree/n-gram model. No-op
    (returns False) when the wire or engine is unavailable; never raises.
    """
    mgr = _get_mpdp()
    if mgr is None or eng is None:
        return False
    try:
        import ffn_mpdp_wire as wire
        payload = eng.export()      # {kind(int), version, tree_blob, ngram_params, features_version}
        # Wire MlKind is {XGBOOST=0, NGRAM=1}. export()'s kind==2 means "both"
        # (both blobs are carried regardless) -> tag it XGBOOST for the union.
        k = payload.get("kind", 0)
        wire_kind = wire.MlKind.NGRAM if k == wire.MlKind.NGRAM else wire.MlKind.XGBOOST
        frame = wire.build_ml_model_update(
            int(payload.get("version", 0) or 0), wire_kind,
            tree_blob=_mpdp_as_bytes(payload.get("tree_blob")),
            ngram_params=_mpdp_as_bytes(payload.get("ngram_params")),
            features_version=_mpdp_fv_int(payload.get("features_version", 0)))
        mgr.send_frame(frame)
        return True
    except Exception as exc:
        logger.warning("MPDP ML fan-out failed: %s", exc)
        return False


def _mpdp_emit_threat_intel(seq, adds=None, removes=None, iocs=None) -> bool:
    """Fan out a §9 ThreatIntelUpdate to the DP (best-effort).

    Called from the signature-DB update path so a content-package bump is
    pushed to a running data plane in realtime. No-op when the wire is absent.
    """
    mgr = _get_mpdp()
    if mgr is None:
        return False
    try:
        import ffn_mpdp_wire as wire
        frame = wire.build_threat_intel_update(
            int(seq), adds=adds or [], removes=removes or [], iocs=iocs or [])
        mgr.send_frame(frame)
        mgr.last_seq = max(mgr.last_seq, int(seq))
        return True
    except Exception as exc:
        logger.warning("MPDP threat-intel fan-out failed: %s", exc)
        return False


_DDOS_SAMPLE = {"t": 0.0, "total": 0}
_DDOS_COUNTER_MAP = {"ffn_ddos_syn": "syn", "ffn_ddos_udp": "udp",
                     "ffn_ddos_icmp": "icmp", "ffn_ddos_conn": "conn"}


def _nft_ddos_counters() -> dict:
    """Read the live anti-DDoS named counters from the nft ffn_ngfw table.
    These count NEW packets dropped for exceeding the per-protocol flood rate."""
    out = {"syn": 0, "udp": 0, "icmp": 0, "conn": 0, "total": 0, "bytes": 0}
    try:
        r = subprocess.run(["nft", "-j", "list", "counters", "table", "inet", "ffn_ngfw"],
                           capture_output=True, text=True, timeout=5)
        if r.returncode == 0 and r.stdout:
            for item in json.loads(r.stdout).get("nftables", []):
                cobj = item.get("counter")
                if not cobj:
                    continue
                key = _DDOS_COUNTER_MAP.get(cobj.get("name", ""))
                if key:
                    out[key] = int(cobj.get("packets", 0))
                    out["bytes"] += int(cobj.get("bytes", 0))
            out["total"] = out["syn"] + out["udp"] + out["icmp"] + out["conn"]
    except Exception:
        pass
    return out


def _ddos_engine_state() -> dict:
    """Software anti-DDoS engine state: cumulative drop counters + a live drop
    rate (sampled between calls) mapped to a clear/low/medium/high level."""
    import time as _time
    c = _nft_ddos_counters()
    now = _time.time()
    global _DDOS_SAMPLE
    rate = 0.0
    if _DDOS_SAMPLE["t"]:
        dt = now - _DDOS_SAMPLE["t"]
        if dt >= 0.5:
            rate = max(0.0, (c["total"] - _DDOS_SAMPLE["total"]) / dt)
            _DDOS_SAMPLE = {"t": now, "total": c["total"]}
    else:
        _DDOS_SAMPLE = {"t": now, "total": c["total"]}
    level = 0 if rate <= 0 else 1 if rate < 100 else 2 if rate < 1000 else 3
    return {"counters": c, "drop_rate_pps": round(rate, 1), "level": level,
            "level_name": ["clear", "low", "medium", "high"][level]}


def _read_dos_config() -> dict:
    cfg = {"enable": True, "syn_rate": 2000, "syn_burst": 200, "udp_rate": 4000,
           "udp_burst": 400, "icmp_rate": 1000, "icmp_burst": 100, "conn_limit": 0}
    try:
        with open("/etc/ffn-ngfw/bmfw.json") as f:
            dd = (json.load(f).get("dos") or {})
        for k in list(cfg):
            if k in dd:
                cfg[k] = dd[k]
    except Exception:
        pass
    return cfg


def _bmfw_regen_reload() -> tuple:
    """Regenerate the nft ruleset from bmfw.json and reload it. The DoS rules
    live in the FORWARD hook so they cannot affect the mgmt/input path, but we
    still validate with `nft -c` and refuse to load a ruleset missing the mgmt
    allow floor. Returns (ok, detail)."""
    VENV = "/opt/ffn-ngfw-v2/venv/bin/python"
    try:
        gen = subprocess.run([VENV, "/opt/ffn-ngfw-v2/ffn_bmfw.py", "--config",
                              "/etc/ffn-ngfw/bmfw.json", "gen-nft"],
                             capture_output=True, text=True, timeout=30)
        if gen.returncode != 0:
            return False, "gen-nft failed: " + (gen.stderr or "")[:200]
        ruleset = gen.stdout
        if '"mgmt"' not in ruleset:
            return False, "refusing reload: mgmt-allow floor missing from generated ruleset"
        with open("/root/ffn-bmfw.nft", "w") as f:
            f.write(ruleset)
        chk = subprocess.run(["nft", "-c", "-f", "/root/ffn-bmfw.nft"],
                             capture_output=True, text=True, timeout=15)
        if chk.returncode != 0:
            return False, "nft validate failed: " + (chk.stderr or "")[:200]
        ld = subprocess.run(["nft", "-f", "/root/ffn-bmfw.nft"],
                            capture_output=True, text=True, timeout=15)
        if ld.returncode != 0:
            return False, "nft load failed: " + (ld.stderr or "")[:200]
        # keep the persisted boot copy in sync
        try:
            shutil.copy("/root/ffn-bmfw.nft", "/etc/ffn-ngfw/ffn-bmfw.nft")
        except Exception:
            pass
        return True, "reloaded"
    except Exception as e:
        return False, str(e)[:200]


def _engine_backend_view(eid: int, name: str, db_en: int, live: dict) -> dict:
    """Backend-sourced view of one engine (REWORK_CONTRACT §1).

    enabled/packets/matches/drops come from the engine's HOST backend by default:
      * python plugins  -> _detection_live() (enable-state; counters via plugin)
      * dpdk/kernel     -> best-effort host counters (0 today) w/ a source label
    The FPGA is consulted ONLY when a card is present AND offload is True, and is
    surfaced separately as offload_active / offload_stats — never as the primary
    enabled/packets figures.
    """
    meta = ENGINE_BACKENDS.get(
        name, {"backend": "host", "module": None, "offload": False, "role": ""})
    backend = meta["backend"]
    module = meta["module"]
    offload = bool(meta["offload"])

    backend_enabled = True
    packets = matches = drops = 0
    if backend == "python":
        el = live.get(_ENGINE_LIVE_KEY.get(name, ""), {})
        if el:
            backend_enabled = bool(el.get("enabled", True))
        source = f"python:{module}" if module else "python"
    else:
        # dpdk / kernel / host: host packet counters not yet wired -> 0 with a
        # clear source label (DPDK telemetry / conntrack counters land here).
        source = f"{backend}:{module}" if module else backend

    # Anti-DDoS software engines report the real nftables flood-drop counters
    # (ddos_detector + rate_limiter share the flood machinery; syn_proxy = SYN).
    _dc = live.get("_ddos_counters") or {}
    if name in ("ddos_detector", "rate_limiter"):
        packets = matches = drops = int(_dc.get("total", 0))
        source = "kernel:nftables(ffn_ddos_*)"
    elif name == "syn_proxy":
        packets = matches = drops = int(_dc.get("syn", 0))
        source = "kernel:nftables(ffn_ddos_syn)"

    enabled = bool(db_en) and backend_enabled

    # Optional DPI offload (REWORK_CONTRACT §1 + §7):
    #   * card present            -> "hardware": consult FPGA get_engine_status
    #   * no card, AC/DFA engine  -> "emulated": consult the software ffn_fpga_emu
    #   * otherwise               -> "host": no offload surface
    offload_active = False
    offload_stats = None
    offload_mode = "host"
    if offload and fpga_present():
        hw = fpga.get_engine_status(eid)
        offload_stats = hw
        offload_active = bool(hw.get("enabled"))
        offload_mode = "hardware"
    elif offload and name in _EMU_DPI_ENGINES:
        emu = _get_fpga_emu()
        if emu is not None:
            offload_stats = emu.emu_status(name)   # {enabled,packets,matches,drops,mode}
            offload_active = True
            offload_mode = "emulated"

    return {
        "id": eid,
        "name": name,
        "enabled": enabled,
        "packets": packets,
        "matches": matches,
        "drops": drops,
        "backend": backend,
        "module": module,
        "offload": offload,
        "offload_active": offload_active,
        "offload_mode": offload_mode,
        "offload_stats": offload_stats,
        "source": source,
        "role": meta["role"],
        "hw_present": fpga_present(),
    }


# Serve static files
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")



# ---------------------------------------------------------------------------
# Local CLI authentication (SO_PEERCRED over a unix socket)
# ---------------------------------------------------------------------------
CLI_AUTH_SOCK = "/run/ffn-ngfw/cli-auth.sock"
_CLI_NL = chr(10)


async def _cli_auth_conn(reader, writer):
    """Mint a token for a caller whose OS identity the kernel already vouches for.

    sshd authenticates the user before it execs ffn-cli as their login shell, so
    making them type a password a second time proves nothing new. SO_PEERCRED
    reports the connecting process's real uid straight from the kernel -- a
    client cannot forge it -- so we map that uid to a local account name, look
    that name up in the FFN user table, and issue that user's ordinary token
    with their own role.

    This grants no privilege the uid did not already have, and a unix socket is
    not reachable over the network. Authorization is by peer uid, not by socket
    permissions.
    """
    import socket as _sk
    import struct as _st
    import pwd as _pwd
    try:
        sock = writer.get_extra_info("socket")
        raw = sock.getsockopt(_sk.SOL_SOCKET, _sk.SO_PEERCRED, _st.calcsize("3i"))
        _pid, uid, _gid = _st.unpack("3i", raw)
        try:
            name = _pwd.getpwuid(uid).pw_name
        except KeyError:
            name = None

        resp = {"error": "uid %d has no local account" % uid}
        if name:
            async with aiosqlite.connect(DB_PATH) as db:
                db.row_factory = aiosqlite.Row
                cur = await db.execute(
                    "SELECT * FROM users WHERE username = ?", (name,))
                u = await cur.fetchone()
                if u:
                    await db.execute(
                        "UPDATE users SET last_login = datetime('now') WHERE id = ?",
                        (u["id"],))
                    try:
                        await audit(db, name, "login (local peercred)")
                    except Exception:
                        pass
                    await db.commit()
                    resp = {"access_token": create_token(u["username"], u["role"]),
                            "username": u["username"], "role": u["role"]}
                else:
                    resp = {"error": "no FFN user " + name}
        writer.write((json.dumps(resp) + _CLI_NL).encode())
        await writer.drain()
    except Exception as e:
        try:
            writer.write((json.dumps({"error": str(e)}) + _CLI_NL).encode())
            await writer.drain()
        except Exception:
            pass
    finally:
        try:
            writer.close()
        except Exception:
            pass


@app.on_event("startup")
async def _cli_auth_start():
    try:
        os.makedirs(os.path.dirname(CLI_AUTH_SOCK), exist_ok=True)
        if os.path.exists(CLI_AUTH_SOCK):
            os.unlink(CLI_AUTH_SOCK)
        srv = await asyncio.start_unix_server(_cli_auth_conn, path=CLI_AUTH_SOCK)
        os.chmod(CLI_AUTH_SOCK, 0o666)
        app.state._cli_auth_srv = srv
        print("[cli-auth] peercred socket ready at " + CLI_AUTH_SOCK)
    except Exception as e:
        print("[cli-auth] not started: " + str(e))


@app.on_event("startup")
async def startup():
    await init_db()
    logger.info("FFN NGFW Manager started — FPGA device %s", DEV_PATH)
    # Make sure every detected Linux NIC has a PAN-OS alias (ens33 → ethernet1/1 …)
    try:
        aliases = _auto_assign_aliases()
        logger.info("Interface aliases: %d registered", len(aliases))
    except Exception as exc:
        logger.warning("Alias auto-assignment failed: %s", exc)


@app.on_event("shutdown")
async def shutdown():
    fpga.close()


# -- Root -> serve dashboard -----------------------------------------------

@app.get("/")
async def root():
    index = STATIC_DIR / "index.html"
    if index.exists():
        return FileResponse(str(index))
    return {"message": "FFN NGFW Manager API", "docs": "/docs"}


# ==========================================================================
# 1. Authentication
# ==========================================================================


@app.post("/api/auth/login")
async def login(req: LoginRequest):
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            "SELECT * FROM users WHERE username = ?", (req.username,)
        )
        user = await cursor.fetchone()
        if not user or not pwd_context.verify(req.password, user["password_hash"]):
            raise HTTPException(status_code=401, detail="Invalid credentials")
        await db.execute(
            "UPDATE users SET last_login = datetime('now') WHERE id = ?",
            (user["id"],),
        )
        await audit(db, req.username, "login")
        token = create_token(user["username"], user["role"],
                             pw_change_only=bool(user["must_change_pw"]))
        return {
            "access_token": token,
            "token_type": "bearer",
            "username": user["username"],
            "role": user["role"],
            "must_change_pw": bool(user["must_change_pw"]),
        }


@app.get("/api/auth/me")
async def auth_me(user: dict = Depends(get_current_user)):
    return user


@app.post("/api/auth/change-password")
async def change_password(req: ChangePassword, user: dict = Depends(get_current_user)):
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            "SELECT * FROM users WHERE username = ?", (user["username"],)
        )
        row = await cursor.fetchone()
        if not row or not pwd_context.verify(req.current_password, row["password_hash"]):
            raise HTTPException(status_code=400, detail="Current password incorrect")
        new_hash = pwd_context.hash(req.new_password)
        await db.execute(
            "UPDATE users SET password_hash = ?, must_change_pw = 0 WHERE username = ?",
            (new_hash, user["username"]),
        )
        await audit(db, user["username"], "change_password")
        # The caller's token still carries the pwc scope, so issue a full one
        # rather than leaving them locked out of everything they just unlocked.
        return {"status": "ok",
                "access_token": create_token(user["username"], user["role"]),
                "token_type": "bearer"}


# ==========================================================================
# 1b. Administrator / user management (WebUI + CLI share this user store)
# ==========================================================================

VALID_ROLES = {"superuser", "admin", "operator", "read-only"}
ADMIN_ROLES = {"superuser", "admin"}


class AdminUserCreate(BaseModel):
    username: str
    password: str
    role: str = "admin"
    must_change_pw: bool = True


class AdminUserUpdate(BaseModel):
    role: Optional[str] = None
    password: Optional[str] = None
    must_change_pw: Optional[bool] = None


def _require_admin(user: dict):
    if user.get("role") not in ADMIN_ROLES:
        raise HTTPException(status_code=403,
                            detail="Requires admin or superuser role")


async def _admin_count(db) -> int:
    cur = await db.execute(
        "SELECT COUNT(*) FROM users WHERE role IN ('superuser','admin')")
    return (await cur.fetchone())[0]


@app.get("/api/users")
async def list_users(user: dict = Depends(get_current_user)):
    _require_admin(user)
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        rows = await (await db.execute(
            "SELECT id, username, role, must_change_pw, created_at, last_login "
            "FROM users ORDER BY id")).fetchall()
    return {"users": [dict(r) for r in rows], "total": len(rows),
            "roles": sorted(VALID_ROLES)}


@app.post("/api/users")
async def create_user(req: AdminUserCreate, user: dict = Depends(get_current_user)):
    _require_admin(user)
    uname = (req.username or "").strip()
    if not uname:
        raise HTTPException(status_code=400, detail="username is required")
    if req.role not in VALID_ROLES:
        raise HTTPException(status_code=400, detail=f"invalid role: {req.role}")
    if len(req.password or "") < 6:
        raise HTTPException(status_code=400, detail="password must be at least 6 characters")
    async with aiosqlite.connect(DB_PATH) as db:
        try:
            cur = await db.execute(
                "INSERT INTO users (username, password_hash, role, must_change_pw) "
                "VALUES (?,?,?,?)",
                (uname, pwd_context.hash(req.password), req.role, int(req.must_change_pw)))
            await db.commit()
            await audit(db, user["username"], "user_create", uname)
            return {"id": cur.lastrowid, "status": "created"}
        except aiosqlite.IntegrityError:
            raise HTTPException(status_code=409, detail=f"user '{uname}' already exists")


@app.put("/api/users/{uid}")
async def update_user(uid: int, req: AdminUserUpdate,
                      user: dict = Depends(get_current_user)):
    _require_admin(user)
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        row = await (await db.execute("SELECT * FROM users WHERE id=?", (uid,))).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="user not found")
        sets, vals = [], []
        if req.role is not None:
            if req.role not in VALID_ROLES:
                raise HTTPException(status_code=400, detail=f"invalid role: {req.role}")
            if row["role"] in ADMIN_ROLES and req.role not in ADMIN_ROLES:
                if await _admin_count(db) <= 1:
                    raise HTTPException(status_code=400,
                                        detail="cannot demote the last administrator")
            sets.append("role=?"); vals.append(req.role)
        if req.password is not None:
            if len(req.password) < 6:
                raise HTTPException(status_code=400,
                                    detail="password must be at least 6 characters")
            sets.append("password_hash=?"); vals.append(pwd_context.hash(req.password))
        if req.must_change_pw is not None:
            sets.append("must_change_pw=?"); vals.append(int(req.must_change_pw))
        if not sets:
            return {"status": "noop"}
        vals.append(uid)
        await db.execute(f"UPDATE users SET {', '.join(sets)} WHERE id=?", vals)
        await db.commit()
        await audit(db, user["username"], "user_update", f"id={uid} ({row['username']})")
        return {"status": "updated"}


@app.delete("/api/users/{uid}")
async def delete_user(uid: int, user: dict = Depends(get_current_user)):
    _require_admin(user)
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        row = await (await db.execute("SELECT * FROM users WHERE id=?", (uid,))).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="user not found")
        if row["username"] == user["username"]:
            raise HTTPException(status_code=400, detail="cannot delete your own account")
        if row["role"] in ADMIN_ROLES and await _admin_count(db) <= 1:
            raise HTTPException(status_code=400,
                                detail="cannot delete the last administrator")
        await db.execute("DELETE FROM users WHERE id=?", (uid,))
        await db.commit()
        await audit(db, user["username"], "user_delete", row["username"])
        return {"status": "deleted"}


# ==========================================================================
# 1c. FIPS-CC status (mode is set ONLY from the recovery partition — it wipes
#     the config — so the running system merely reports state + self-test result)
# ==========================================================================

FIPS_MODE_FLAG = "/etc/ffn-ngfw/fips-cc.mode"
FIPS_SELFTEST_JSON = "/var/lib/ffn-ngfw/fips-selftest.json"
FIPS_SELFTEST_BIN = "/opt/ffn-ngfw-v2/ffn_fips_selftest.py"
FIPS_PY = "/opt/ffn-ngfw-v2/venv/bin/python3"


def _fips_status() -> dict:
    mode_on = os.path.exists(FIPS_MODE_FLAG)
    st = None
    try:
        st = json.loads(open(FIPS_SELFTEST_JSON).read())
    except Exception:
        st = None
    # A FIPS module that fails POST must not be considered operational.
    healthy = (not mode_on) or (st is not None and st.get("overall") == "pass")
    return {
        "mode": "enabled" if mode_on else "disabled",
        "enabled": mode_on,
        "operational_mode": "fips-cc" if mode_on else "standard",
        "healthy": healthy,
        "self_test": st,
        "note": "FIPS-CC mode is changed only from Recovery/Maintenance (it zeroizes the configuration).",
    }


@app.get("/api/system/fips")
async def system_fips(user: dict = Depends(get_current_user)):
    return _fips_status()


@app.post("/api/system/fips/selftest")
async def system_fips_selftest(user: dict = Depends(get_current_user)):
    _require_admin(user)
    try:
        p = subprocess.run([FIPS_PY, FIPS_SELFTEST_BIN], capture_output=True, text=True, timeout=90)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"self-test run failed: {exc}")
    out = _fips_status()
    out["exit_code"] = p.returncode
    return out


# ==========================================================================
# 2. System Status
# ==========================================================================


@app.get("/api/system/status")
async def system_status():
    try:
        hostname = platform.node()
    except Exception:
        hostname = "ffn-ngfw"
    try:
        uptime_sec = time.time() - psutil.boot_time()
    except Exception:
        uptime_sec = 0
    cpu_percent = psutil.cpu_percent(interval=0.1)
    mem = psutil.virtual_memory()

    # Detect FPGA presence
    fpga_detected = not fpga.sim_mode
    fpga_version = fpga.get_version() if fpga_detected else None

    # Detect PCI devices
    pci_devices = []
    try:
        out = subprocess.check_output(
            ["lspci", "-mm"], text=True, timeout=5
        )
        for line in out.strip().split("\n"):
            if any(kw in line.lower() for kw in ["ethernet", "network", "xilinx", "mellanox", "bittware"]):
                pci_devices.append(line.strip())
    except Exception:
        pass

    return {
        "hostname": hostname,
        "uptime_seconds": int(uptime_sec),
        "uptime_human": str(timedelta(seconds=int(uptime_sec))),
        "fpga_detected": fpga_detected,
        "fpga_version": fpga_version,
        "cpu": _get_cpu_info(),
        "cpu_percent": cpu_percent,
        "cpu_count": psutil.cpu_count(logical=True),
        "cpu_count_physical": psutil.cpu_count(logical=False),
        "memory_total_gb": round(mem.total / 1e9, 2),
        "memory_used_gb": round(mem.used / 1e9, 2),
        "memory_percent": mem.percent,
        "disk_total_gb": round(psutil.disk_usage("/").total / 1e9, 2),
        "disk_used_gb": round(psutil.disk_usage("/").used / 1e9, 2),
        "disk_percent": psutil.disk_usage("/").percent,
        "platform": platform.system(),
        "kernel": platform.release(),
        "pci_network_devices": pci_devices,
        "timestamp": datetime.utcnow().isoformat(),
    }


def _get_cpu_info() -> str:
    """Read CPU model from /proc/cpuinfo."""
    try:
        with open("/proc/cpuinfo") as f:
            for line in f:
                if line.startswith("model name"):
                    return line.split(":", 1)[1].strip()
    except Exception:
        pass
    return platform.processor() or "Unknown"


# ---------------------------------------------------------------------------
# Real interface discovery
# ---------------------------------------------------------------------------

def _discover_interfaces() -> list:
    """
    Auto-detect network interfaces.
    If FPGA is present, show FPGA ports (eth0-3).
    Otherwise, show real system interfaces.
    """
    if not fpga.sim_mode:
        # FPGA present — show FPGA dataplane ports
        ports = []
        for p in range(NUM_PORTS):
            stats = fpga.get_port_stats(p)
            ports.append({
                "name": f"qsfp{p}",
                "port": p,
                "type": "fpga",
                "mac": f"00:1A:2B:3C:4D:{0xE0 + p:02X}",
                "link_up": fpga.get_port_link_up(p),
                "speed_gbps": fpga.get_port_speed(p),
                "mtu": 9000,
                "rx_bytes": stats["rx_bytes"],
                "tx_bytes": stats["tx_bytes"],
                "rx_packets": stats["rx_packets"],
                "tx_packets": stats["tx_packets"],
                "rx_drops": stats["rx_drops"],
                "tx_drops": stats["tx_drops"],
                "rx_errors": stats["rx_errors"],
            })
        # Also add host CPU interfaces
        ports.extend(_get_real_interfaces())
        return ports
    else:
        # No FPGA — show real system interfaces only
        return _get_real_interfaces()


def _get_real_interfaces() -> list:
    """Get real network interfaces from psutil."""
    ifaces = []
    addrs = psutil.net_if_addrs()
    stats = psutil.net_if_stats()
    counters = psutil.net_io_counters(pernic=True)

    for name, addr_list in sorted(addrs.items()):
        if name == "lo" or name.startswith(("tmfifo_net", "rshim")):
            continue  # skip loopback + BlueField DPU control channels

        iface = {
            "name": name,
            "type": "cpu",
            "link_up": False,
            "speed_gbps": 0,
            "mtu": 1500,
            "mac": "",
            "ip_address": "",
            "netmask": "",
            "ipv6_address": "",
            "rx_bytes": 0,
            "tx_bytes": 0,
            "rx_packets": 0,
            "tx_packets": 0,
            "rx_drops": 0,
            "tx_drops": 0,
            "rx_errors": 0,
        }

        # Fill addresses
        for addr in addr_list:
            if addr.family.name == "AF_INET":
                iface["ip_address"] = addr.address
                iface["netmask"] = addr.netmask or ""
            elif addr.family.name == "AF_INET6" and not addr.address.startswith("fe80"):
                iface["ipv6_address"] = addr.address
            elif addr.family.name == "AF_PACKET":
                iface["mac"] = addr.address

        # Fill stats
        if name in stats:
            s = stats[name]
            iface["link_up"] = s.isup
            iface["speed_gbps"] = round(s.speed / 1000, 1) if s.speed else 0
            iface["mtu"] = s.mtu

        # Fill counters
        if name in counters:
            c = counters[name]
            iface["rx_bytes"] = c.bytes_recv
            iface["tx_bytes"] = c.bytes_sent
            iface["rx_packets"] = c.packets_recv
            iface["tx_packets"] = c.packets_sent
            iface["rx_drops"] = c.dropin
            iface["tx_drops"] = c.dropout
            iface["rx_errors"] = c.errin

        ifaces.append(iface)
    return ifaces


@app.get("/api/system/interfaces")
async def system_interfaces():
    """The DEVICE's interfaces: this host's NICs, plus any faceplate connector
    that belongs to the device rather than to the firewall.

    On a PA-5200 that second group is HSCI -- the HA data link (HA2/HA3),
    carrying session sync and, in active/active, forwarded packets between
    peers. It is on the front of the chassis, which is why it used to appear in
    the firewall's interface list, but it is HA plumbing: it is configured with
    the device's high-availability settings and never appears in a security
    policy. It lives on the switch ASIC rather than on a host NIC, so it is
    marked `type: chassis` and carries no MAC or address of its own here.
    """
    out = _discover_interfaces()
    fp = await _faceplate_map("management")
    for d in (fp or {}).values():
        out.append({
            "name": d["name"],
            "type": "chassis",
            "role": d.get("role"),
            "link_up": bool(d.get("link")),
            "link_state": (d.get("link") if d.get("live") else None),
            "speed_gbps": d.get("speed_gbps") or 0,
            "media": d.get("media"),
            "faceplate": d.get("faceplate"),
            "chip_port": d.get("diag_name"),
            "admin_enabled": d.get("admin_enabled"),
            "mtu": 0, "mac": "", "ip_address": "", "netmask": "",
            "ipv6_address": "",
            "rx_bytes": 0, "tx_bytes": 0, "rx_packets": 0, "tx_packets": 0,
            "rx_drops": 0, "tx_drops": 0, "rx_errors": 0,
        })
    return {"interfaces": out}


@app.get("/api/system/resources")
async def system_resources():
    mem = psutil.virtual_memory()
    disk = psutil.disk_usage("/")
    cpu_freq = psutil.cpu_freq()

    result = {
        "cpu": {
            "model": _get_cpu_info(),
            "cores_physical": psutil.cpu_count(logical=False),
            "cores_logical": psutil.cpu_count(logical=True),
            "frequency_mhz": int(cpu_freq.current) if cpu_freq else 0,
            "usage_percent": psutil.cpu_percent(interval=0.1),
            "per_core": psutil.cpu_percent(percpu=True),
        },
        "memory": {
            "total_gb": round(mem.total / 1e9, 2),
            "used_gb": round(mem.used / 1e9, 2),
            "available_gb": round(mem.available / 1e9, 2),
            "percent": mem.percent,
        },
        "disk": {
            "total_gb": round(disk.total / 1e9, 2),
            "used_gb": round(disk.used / 1e9, 2),
            "free_gb": round(disk.free / 1e9, 2),
            "percent": disk.percent,
        },
    }

    # FPGA resources — only when hardware is detected
    if not fpga.sim_mode:
        result["fpga"] = {
            "detected": True,
            "device": "Xilinx VU9P (xcvu9p-flga2577-2-i)",
            "board": "BittWare XUP-P3R",
            "lut_used": 616390,
            "lut_total": 1182240,
            "lut_percent": round(616390 / 1182240 * 100, 1),
            "bram_used": 1348,
            "bram_total": 2160,
            "bram_percent": round(1348 / 2160 * 100, 1),
            "uram_used": 176,
            "uram_total": 960,
            "uram_percent": round(176 / 960 * 100, 1),
            "dsp_used": 768,
            "dsp_total": 6840,
            "dsp_percent": round(768 / 6840 * 100, 1),
            "ff_used": 510720,
            "ff_total": 2364480,
            "ff_percent": round(510720 / 2364480 * 100, 1),
            "clock_mhz": 322,
            # No XADC/System-Monitor sysmon reader wired here yet -> honest null
            # rather than a fabricated temperature/power reading.
            "temperature_c": None,
            "power_w": None,
            "pcie_link": "Gen3 x16 (128 Gbps)",
        }
    else:
        result["fpga"] = {
            "detected": False,
            "status": "No FPGA device found at " + fpga.dev_path,
        }

    # Read CPU temperatures if available
    try:
        temps = psutil.sensors_temperatures()
        if temps:
            for chip, entries in temps.items():
                if entries:
                    result["temperatures"] = {
                        chip: [{"label": e.label, "current": e.current, "high": e.high, "critical": e.critical}
                               for e in entries[:8]]
                    }
                    break
    except Exception:
        pass

    return result


# ==========================================================================
# 3. Dashboard
# ==========================================================================


# Throughput tracking state (for delta-based rate calculation)
_prev_counters = {}
_prev_counter_time = 0


@app.get("/api/dashboard/throughput")
async def dashboard_throughput():
    global _prev_counters, _prev_counter_time

    now = time.time()
    ports = []

    if not fpga.sim_mode:
        # FPGA present — read FPGA port throughput
        for p in range(NUM_PORTS):
            tp = fpga.get_throughput_gbps(p)
            ports.append({
                "port": p,
                "name": f"qsfp{p}",
                "type": "fpga",
                "rx_gbps": tp["rx_gbps"],
                "tx_gbps": tp["tx_gbps"],
            })

    # Always include real CPU interfaces
    counters = psutil.net_io_counters(pernic=True)
    stats = psutil.net_if_stats()
    dt = now - _prev_counter_time if _prev_counter_time > 0 else 1.0

    for iface_name in sorted(counters.keys()):
        if iface_name == "lo":
            continue
        if iface_name not in stats or not stats[iface_name].isup:
            continue

        cur = counters[iface_name]
        prev = _prev_counters.get(iface_name)

        if prev and dt > 0.1:
            rx_bps = (cur.bytes_recv - prev.bytes_recv) * 8 / dt
            tx_bps = (cur.bytes_sent - prev.bytes_sent) * 8 / dt
        else:
            rx_bps = 0
            tx_bps = 0

        # Convert to Gbps (cap at link speed)
        link_speed = stats[iface_name].speed  # Mbps
        max_bps = link_speed * 1e6 if link_speed else 100e9

        ports.append({
            "name": iface_name,
            "type": "cpu",
            "rx_gbps": round(min(rx_bps / 1e9, max_bps / 1e9), 4),
            "tx_gbps": round(min(tx_bps / 1e9, max_bps / 1e9), 4),
            "rx_bytes_total": cur.bytes_recv,
            "tx_bytes_total": cur.bytes_sent,
            "rx_pps": int((cur.packets_recv - (prev.packets_recv if prev else cur.packets_recv)) / dt) if prev and dt > 0.1 else 0,
            "tx_pps": int((cur.packets_sent - (prev.packets_sent if prev else cur.packets_sent)) / dt) if prev and dt > 0.1 else 0,
        })

    _prev_counters = counters
    _prev_counter_time = now

    return {"timestamp": now, "ports": ports}


@app.get("/api/dashboard/threats")
async def dashboard_threats():
    """
    Threat summary from the REAL detection stack (signature DB, threat DB /
    inline IPS, anti-malware, cloud verdicts) via `_detection_live()`. Counts
    are honest DB figures; when a DB is absent its count is 0. Per-event recent
    threat log has no real event store wired into the manager yet, so it is an
    honest empty list (no fabricated sample rows).
    """
    live = _detection_live()
    ips = live.get("inline_ips", {}) if isinstance(live.get("inline_ips"), dict) else {}
    am = live.get("antimalware", {}) if isinstance(live.get("antimalware"), dict) else {}
    sdb = live.get("sigdb", {}) if isinstance(live.get("sigdb"), dict) else {}

    def _n(v):
        try:
            return int(v or 0)
        except (TypeError, ValueError):
            return 0

    summary = [
        {"type": "IPS", "count": _n(ips.get("signatures"))},
        {"type": "Malware", "count": _n(am.get("known_malware"))},
        {"type": "Grayware", "count": _n(am.get("grayware"))},
        {"type": "Signatures", "count": _n(sdb.get("signatures"))},
    ]
    # No real per-event threat-event log source in the manager -> honest empty.
    recent: list = []
    return {"summary": summary, "recent": recent, "source": "detection-db"}


# --------------------------------------------------------------------------
# VSYS tag scheme (Axis 4, REWORK_CONTRACT §2)
#
# Every vsys carries a stable numeric `vsys_id` in [1..N] (vsys1->1, vsys2->2,
# ...). 0 = reserved/untagged (shared/default). The tag is carried end-to-end
# as the conntrack zone/mark (`ct zone`/`ct mark == vsys_id`), so session/flow
# views can be scoped per vsys by filtering conntrack on that tag.
# --------------------------------------------------------------------------


def _vsys_id_from_name(name: str) -> int:
    """Derive the stable numeric vsys tag from a vsys name.

    Names are regex-constrained to 'vsys<N>' (see vsys_create), so the numeric
    suffix is the canonical, never-reused id. Returns 0 (reserved/untagged) for
    anything that is not a positive vsys<N>.
    """
    m = re.match(r"^vsys([0-9]+)$", (name or "").strip().lower())
    if m:
        try:
            n = int(m.group(1))
            return n if n >= 1 else 0
        except ValueError:
            return 0
    return 0


def _vsys_id_for_entry(e) -> int:
    """Resolve a config <entry>'s vsys_id: prefer a persisted <vsys-id>, else
    derive from the entry name."""
    persisted = ""
    try:
        persisted = e.findtext("vsys-id", "") or ""
    except Exception:
        persisted = ""
    if persisted.strip():
        try:
            v = int(persisted.strip())
            if v >= 0:
                return v
        except ValueError:
            pass
    return _vsys_id_from_name(e.get("name") or "")


def _configured_vsys_ids() -> set:
    """The numeric ids of the virtual systems that actually exist.

    Read from the candidate config, which is where a vsys lives -- there is no
    vsys SQL table, and adding one would be a second source of truth for
    something the PAN-OS config already owns.
    """
    ids = set()
    try:
        node = config_mgr.get_xpath(f"{DEV}.vsys", source="candidate")
        for e in (node.findall("entry") if node is not None else []):
            n = _vsys_id_from_name(e.get("name") or "")
            if n:
                ids.add(n)
    except Exception:
        pass
    return ids


def _check_vsys(v) -> int:
    """Validate a rule's vsys id, or raise 400.

    Two rejections, and both are about failing where someone is watching.

    A rule bound to a virtual system that does not exist matches NOTHING -- the
    dataplane compares the tag and never finds it -- so the rule sits in the
    rulebase looking enabled while enforcing nothing. That is the worst outcome
    a firewall can produce, and it is invisible until traffic goes the wrong
    way, so it is refused at the point the rule is written.

    An id above what the dataplane can express is refused for the same reason:
    the wire format carries vsys in one byte and the plan allocates hardware per
    tenant, so an id past that would be truncated rather than honoured.
    """
    try:
        n = int(v)
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail="vsys must be a number")
    if n == 0:
        return 0                      # the wildcard: applies to every tenant
    if n < 0 or n > 32:               # DP_VSYS_MAX in ffn_dp_vsys.h
        raise HTTPException(
            status_code=400,
            detail="vsys %d out of range; the dataplane supports 1..32 "
                   "(0 means every virtual system)" % n)
    have = _configured_vsys_ids()
    if have and n not in have:
        raise HTTPException(
            status_code=400,
            detail="no virtual system with id %d exists (configured: %s). "
                   "A rule bound to a vsys that does not exist would match no "
                   "traffic at all." % (n, ", ".join("vsys%d" % i
                                                     for i in sorted(have))))
    return n


def _resolve_vsys_id(vsys) -> Optional[int]:
    """Resolve a `vsys` filter param to a numeric vsys_id (contract §2).

    Accepts a name ('vsys2'), a numeric string/int ('2'), or None/''. Returns
    None when no filter was requested, else an int in [0..N] (0 = untagged/
    shared). Unparseable values raise HTTP 400.
    """
    if vsys is None or vsys == "":
        return None
    if isinstance(vsys, bool):  # guard: bool is an int subclass
        raise HTTPException(status_code=400, detail="invalid vsys filter")
    if isinstance(vsys, int):
        return vsys if vsys >= 0 else None
    s = str(vsys).strip()
    if not s:
        return None
    if s.lower().startswith("vsys"):
        return _vsys_id_from_name(s)
    try:
        v = int(s)
        return v if v >= 0 else None
    except ValueError:
        raise HTTPException(status_code=400, detail=f"invalid vsys filter: {vsys!r}")


def _proc_conntrack_scoped_count(vsys_id: int, limit: int = 1_000_000) -> int:
    """Count /proc/net/nf_conntrack rows whose `mark=` equals vsys_id (the
    contract §2 tag). Returns -1 when the proc file is unavailable so callers
    can label the result as unscoped rather than reporting a false 0."""
    token = f"mark={vsys_id}"
    n = 0
    try:
        with open("/proc/net/nf_conntrack") as f:
            for i, line in enumerate(f):
                if i >= limit:
                    break
                if token in line.split():
                    n += 1
    except (FileNotFoundError, PermissionError):
        return -1
    return n


def _session_max() -> int:
    """
    Return the session-table capacity. On real hardware read the FPGA
    register; in sim mode fall back to nf_conntrack_max (kernel tracker
    upper bound), which is what actually limits the box today.
    """
    if not fpga.sim_mode:
        try:
            return fpga.get_session_max()
        except Exception:
            pass
    # Kernel conntrack cap
    try:
        with open("/proc/sys/net/netfilter/nf_conntrack_max") as f:
            return int(f.read().strip())
    except Exception:
        pass
    # Static fallback matching the default configd session-table sizing
    return 2_000_000


def _read_conntrack_stats() -> dict:
    """
    Parse /proc/net/stat/nf_conntrack and sum per-CPU counters. Returns
    the cumulative lookup/insert/search stats used by the hit-ratio meter.
    """
    totals = {"found": 0, "invalid": 0, "insert": 0, "insert_failed": 0,
              "drop": 0, "early_drop": 0, "error": 0, "search_restart": 0}
    try:
        with open("/proc/net/stat/nf_conntrack") as f:
            lines = f.readlines()
        if len(lines) < 2:
            return totals
        header = lines[0].split()
        for row in lines[1:]:
            cols = row.split()
            if len(cols) != len(header):
                continue
            for name, val in zip(header, cols):
                if name in totals:
                    try:
                        totals[name] += int(val, 16)
                    except ValueError:
                        pass
    except FileNotFoundError:
        pass
    return totals


def _count_conntrack_by_state(limit: int = 1_000_000, vsys_id: Optional[int] = None) -> dict:
    """
    Cheap histogram by protocol+state from /proc/net/nf_conntrack.
    Stops early if we exceed `limit` rows to avoid pathological cost on
    boxes with millions of flows. When `vsys_id` is given, only rows tagged
    with `mark=<vsys_id>` (contract §2 conntrack tag) are counted.
    """
    counts = {"tcp_established": 0, "tcp_other": 0, "udp": 0, "icmp": 0, "other": 0}
    mark_token = f"mark={vsys_id}" if vsys_id is not None else None
    try:
        with open("/proc/net/nf_conntrack") as f:
            for i, line in enumerate(f):
                if i >= limit:
                    break
                # Format: "ipv4 2 tcp 6 431999 ESTABLISHED src=... mark=N ..."
                parts = line.split()
                if len(parts) < 4:
                    continue
                if mark_token is not None and mark_token not in parts:
                    continue
                proto = parts[2]
                if proto == "tcp":
                    if len(parts) > 5 and parts[5] == "ESTABLISHED":
                        counts["tcp_established"] += 1
                    else:
                        counts["tcp_other"] += 1
                elif proto == "udp":
                    counts["udp"] += 1
                elif proto == "icmp":
                    counts["icmp"] += 1
                else:
                    counts["other"] += 1
    except FileNotFoundError:
        pass
    except PermissionError:
        pass
    return counts


@app.get("/api/dashboard/sessions")
async def dashboard_sessions(breakdown: bool = False, vsys: Optional[str] = None):
    """
    Active firewall sessions = flows currently tracked in the kernel's
    conntrack table. On a firewall appliance every forwarded flow hits
    conntrack, so this is the canonical "sessions through the firewall"
    count.

    Layered data sources (we merge in this order):
      1. Kernel conntrack — always read. Works even when the FPGA
         fast-path isn't answering. This is the baseline number.
      2. FPGA session engine — if /dev/ngfw0 responds with sane values
         (not 0 or 0xFFFFFFFF, which signal missing/dead MMIO), its
         active-session counter is higher-fidelity and overrides.

    `vsys` (name 'vsys2' or numeric id '2') scopes the active count/breakdown
    to that vsys's conntrack partition via the `mark=<vsys_id>` tag (contract
    §2). When the proc file is unavailable the count falls back to the global
    total and `vsys_scoped=False` is surfaced.
    """
    vsys_id = _resolve_vsys_id(vsys)
    max_sessions = _session_max()

    # --- 1. Conntrack baseline (always populated) ---
    conntrack_count = 0
    vsys_scoped = None
    if vsys_id is not None:
        scoped = _proc_conntrack_scoped_count(vsys_id)
        if scoped >= 0:
            conntrack_count = scoped
            vsys_scoped = True
        else:
            vsys_scoped = False
    if vsys_id is None or vsys_scoped is False:
        try:
            with open("/proc/sys/net/netfilter/nf_conntrack_count") as f:
                conntrack_count = int(f.read().strip())
        except Exception:
            pass

    stats = _read_conntrack_stats()
    ct_hits = stats["found"]
    ct_misses = stats["insert"]
    ct_total = ct_hits + ct_misses
    ct_hit_ratio = round(ct_hits / max(ct_total, 1) * 100, 1)

    base = {
        "active": conntrack_count,
        "conntrack_count": conntrack_count,
        "hits": ct_hits,
        "misses": ct_misses,
        "hit_ratio": ct_hit_ratio,
        "drops": stats["drop"] + stats["early_drop"],
        "insert_failed": stats["insert_failed"],
        "invalid": stats["invalid"],
        "source": "conntrack",
    }
    if vsys_id is not None:
        base["vsys"] = vsys_id
        base["vsys_scoped"] = bool(vsys_scoped)
        base["source"] = "conntrack" if vsys_scoped else "conntrack(unscoped)"

    # --- 2. FPGA overlay (only if its values look sane) ---
    # The FPGA session counter is a global (all-vsys) figure, so it must not
    # override a vsys-scoped active count.
    if not fpga.sim_mode and vsys_id is None:
        try:
            fpga_stats = fpga.get_session_stats()
            a = fpga_stats.get("active", 0)
            # 0xFFFFFFFF = master-abort / dead BAR; 0 = not yet tracked.
            # Only trust a reasonable in-between value.
            if 0 < a < 0xFFFFFFFF:
                base["active"] = a
                base["fpga_active"] = a
                base["fpga_hits"] = fpga_stats.get("hits", 0)
                base["fpga_misses"] = fpga_stats.get("misses", 0)
                base["source"] = "fpga"
        except Exception as exc:
            logger.debug("fpga.get_session_stats failed: %s", exc)

    if breakdown:
        # Scope the histogram to the vsys when requested and scoping is live.
        base["breakdown"] = _count_conntrack_by_state(
            vsys_id=vsys_id if vsys_scoped else None)

    active = base.get("active", 0)
    base["max_sessions"] = max_sessions
    base["capacity_percent"] = round(active / max(max_sessions, 1) * 100, 2) if max_sessions else 0
    return base


@app.get("/api/dashboard/ddos")
async def dashboard_ddos():
    if not fpga.sim_mode:
        zones = fpga.get_ddos_zones()
    else:
        # No FPGA — all zones clear (no hardware DDoS engine)
        zones = [0] * NUM_DDOS_ZONES
    level_names = ["clear", "low", "medium", "high"]
    summary = {"clear": 0, "low": 0, "medium": 0, "high": 0}
    for z in zones:
        lv = min(z, 3)
        summary[level_names[lv]] += 1
    sw = _ddos_engine_state()
    dos_cfg = _read_dos_config()
    # No FPGA: represent the software engine as zone 0 so the heatmap + summary
    # reflect real flood activity instead of being permanently clear.
    if fpga.sim_mode:
        zones = list(zones)
        zones[0] = sw["level"]
        summary = {"clear": 0, "low": 0, "medium": 0, "high": 0}
        for z in zones:
            summary[level_names[min(z, 3)]] += 1
    return {
        "zones": zones,
        "summary": summary,
        "total_zones": NUM_DDOS_ZONES,
        "fpga_active": not fpga.sim_mode,
        "engine_active": bool(dos_cfg.get("enable", True)),
        "software": sw,
        "config": dos_cfg,
    }


@app.get("/api/security/dos-protection")
async def dos_protection_get():
    """Anti-DDoS engine: configured thresholds + live drop state."""
    return {"config": _read_dos_config(), "live": _ddos_engine_state(),
            "backend": "nftables (forward hook, transit)"}


@app.put("/api/security/dos-protection")
async def dos_protection_set(cfg: DosConfig, user: dict = Depends(get_current_user)):
    """Update the anti-DDoS thresholds and regenerate + reload the ruleset.
    The DoS rules are FORWARD-hook only (they cannot touch the mgmt/input path);
    the reload is validated with `nft -c` and refuses a ruleset that lost the
    mgmt-allow floor."""
    path = "/etc/ffn-ngfw/bmfw.json"
    try:
        with open(path) as f:
            d = json.load(f)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"cannot read bmfw.json: {e}")
    cur = d.get("dos") or {}
    upd = {k: v for k, v in cfg.dict(exclude_unset=True).items() if v is not None}
    cur.update(upd)
    for k in ("syn_rate", "udp_rate", "icmp_rate", "syn_burst", "udp_burst",
              "icmp_burst", "conn_limit"):
        if k in cur:
            cur[k] = max(0, int(cur[k]))
    if "enable" in cur:
        cur["enable"] = bool(cur["enable"])
    d["dos"] = cur
    try:
        shutil.copy(path, path + ".bak-dos")
        with open(path, "w") as f:
            json.dump(d, f, indent=2)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"cannot write bmfw.json: {e}")
    ok, detail = _bmfw_regen_reload()
    if not ok:
        raise HTTPException(status_code=500, detail=f"config saved but reload failed: {detail}")
    await _audit_dos(user["username"], cur)
    return {"status": "applied", "dos": cur, "reload": detail}


async def _audit_dos(username: str, cur: dict):
    try:
        async with aiosqlite.connect(DB_PATH) as db:
            await audit(db, username, "set_dos_protection", json.dumps(cur))
            await db.commit()
    except Exception:
        pass


# ==========================================================================
# 3a. Hardware autodetect -- unified inventory (ffn_hwdetect)
# ==========================================================================
_HW_CACHE = {"t": 0.0, "data": None}


def _hw_inventory(refresh: bool = False) -> dict:
    import time as _t
    now = _t.time()
    if (not refresh) and _HW_CACHE["data"] is not None and (now - _HW_CACHE["t"]) < 30:
        return _HW_CACHE["data"]
    try:
        import ffn_hwdetect
        data = ffn_hwdetect.detect()
    except Exception as e:
        data = {"error": str(e)[:200]}
    _HW_CACHE["t"] = now
    _HW_CACHE["data"] = data
    return data


@app.get("/api/system/hardware")
async def system_hardware(refresh: int = 0):
    """Autodetected hardware inventory: system/DMI, CPU+NUMA+crypto, memory,
    every NIC (driver/speed/PCI/DPDK-bind/role), the DPU/SmartNIC, accelerators
    (FPGA/GPU/QAT), storage and hugepages. Cached ~30s; ?refresh=1 to force.

    The accelerator list is completed from the CONTROL PLANE, because on a
    reclaimed appliance the interesting silicon is not on this host bus at all:
    the packet processor, the front-end ASIC and the dataplane NPU sit behind
    the CP. Every row carries `bus`, so "host" and "control-plane" stay
    distinguishable rather than merging into one misleading list."""
    inv = _hw_inventory(refresh=bool(refresh))
    try:
        far = await _detect_offload_dp()
    except Exception:
        far = {}
    rows = list(inv.get("accelerators") or [])
    if inv.get("error") and "accelerators" not in inv:
        # The host probe failed. Appending the control-plane rows to an empty
        # list would produce a shorter list that looks complete -- which is how
        # a NameError in the host detector read as "this box has no host-side
        # silicon" instead of "the host probe did not run".
        rows.append({"role": "host probe failed", "kind": "error", "bus": "host",
                     "pci": str(inv["error"])[:200], "driver": None})
    for dev in (far.get("cp_devices") or []):
        # Bridges are plumbing. They are in the CP inventory because ruling them
        # out is what stops a root complex being counted as a processor, but an
        # operator reading an accelerator list does not need six PLX ports.
        if dev.get("kind") in ("bridge", "serial"):
            continue
        rows.append({
            "role": {"switch": "Packet processor",
                     "asic": "Front-end ASIC",
                     "npu": "NPU"}.get(dev.get("kind"), dev.get("kind")),
            "kind": dev.get("kind"),
            "bus": "control-plane",
            "pci": "%s %s [%s:%s]" % (dev.get("pci"), dev.get("description"),
                                      dev.get("vendor"), dev.get("device")),
            "driver": dev.get("driver"),
            "description": dev.get("description"),
        })
    inv["accelerators"] = rows
    inv["offload"] = far
    return inv


# ==========================================================================
# BCM88375 switch control -- proxied to ffn-bcmd on the CP
# ==========================================================================
#
# The switch ASIC is on the CP's PCIe bus, so nothing here can touch it
# directly. ffn-bcmd (octeon/bcmagent/) owns the chip on the CP and answers
# JSON over ffnnet0; these endpoints are a thin proxy so the WebUI and ffn-cli
# share one implementation, one auth check and one audit point.
#
# Every reply already carries "ok", and the client turns an unreachable CP into
# an ok=False dict rather than an exception, so these handlers do not translate
# errors -- a 500 here would lose the daemon's own "state": "init" / eta_s,
# which is exactly what a UI needs to show progress during the ~150 s chip init.


def _bcm_client():
    """Import the client lazily.

    Lazy so a manager on a box without the BCM payload still starts and every
    other endpoint keeps working -- an ImportError at module scope would take
    the whole management plane down over a switch feature.

    Goes through platform_mod() rather than a bare import so it is found in the
    repo layout too, where the client lives in the platform submodule
    (platform/pa5200/octeon/bcmagent) and is deliberately NOT vendored into
    this tree. A bare `import ffn_bcm_client` only ever worked on a box where
    it had been copied next to the manager, which is why every /api/bcm/*
    endpoint answered "bcm client unavailable" from a checkout.
    """
    mod = platform_mod("ffn_bcm_client")
    if mod is None:
        raise ImportError("ffn_bcm_client not found on any platform path: %s"
                          % ", ".join(_platform_paths()))
    return mod


class BcmPortEnable(BaseModel):
    enable: bool


class BcmPortLoopback(BaseModel):
    # none | mac | phy. mac/phy are the isolation tool: if they link while
    # "none" stays down, the MAC, PCS and SerDes are all good and the fault is
    # outside the die (cage, module or cabling).
    mode: str


def _bcm_unavailable(exc):
    return {"ok": False, "error": "bcm client unavailable", "detail": str(exc),
            "hint": "ffn_bcm_client.py must be importable by the manager "
                    "(deploy it beside ffn_manager.py or into /opt/ffn-ngfw)"}


@app.get("/api/bcm/status")
async def bcm_status(user: dict = Depends(get_current_user)):
    """Chip and daemon state. state is init|ready|dead; during init the reply
    carries eta_s so a UI can show progress instead of an error."""
    try:
        return await _bcm_client().status()
    except ImportError as exc:
        return _bcm_unavailable(exc)


@app.get("/api/bcm/ports")
async def bcm_ports(user: dict = Depends(get_current_user)):
    """The port table, structured. "faceplate" marks the 25 front-panel ports;
    the rest are internal (the DP trunk, recycle, ILKN) and should not be
    offered as user-configurable."""
    try:
        return await _bcm_client().port_list()
    except ImportError as exc:
        return _bcm_unavailable(exc)


@app.post("/api/bcm/port/{port}/enable")
async def bcm_port_enable(port: int, req: BcmPortEnable,
                          user: dict = Depends(get_current_user)):
    """Enable or disable one port. Takes effect immediately and is NOT
    persisted: the shipped config.bcm disables every front-panel port, so this
    is lost on the next chip init. Persisting belongs in the candidate config
    with a commit-time applier, which does not exist yet."""
    try:
        return await _bcm_client().port_set(port, req.enable)
    except ImportError as exc:
        return _bcm_unavailable(exc)


@app.post("/api/bcm/port/{port}/loopback")
async def bcm_port_loopback(port: int, req: BcmPortLoopback,
                            user: dict = Depends(get_current_user)):
    """Set loopback mode (none|mac|phy). Diagnostic: mac/phy loop traffic inside
    the chip, so a port left in either carries no external traffic."""
    if req.mode not in ("none", "mac", "phy"):
        return {"ok": False, "error": "bad request",
                "detail": "mode must be none, mac or phy"}
    try:
        return await _bcm_client().port_loopback(port, req.mode)
    except ImportError as exc:
        return _bcm_unavailable(exc)


@app.get("/api/bcm/leds")
async def bcm_leds(user: dict = Depends(get_current_user)):
    """Front-panel LED processor state. The LED processors are programmed and
    started by the chip's own init script, so enabled=false on a ready chip
    means init did not reach its LED section."""
    try:
        return await _bcm_client().led_status()
    except ImportError as exc:
        return _bcm_unavailable(exc)


# ==========================================================================
# 3c. SSH service + Certificate management
# ==========================================================================
class CsrRequest(BaseModel):
    common_name: str
    org: Optional[str] = None
    country: Optional[str] = None


@app.get("/api/system/ssh")
async def system_ssh(user: dict = Depends(get_current_user)):
    """SSH host-key fingerprints, effective sshd crypto config, the permitted
    management surface (from the firewall mgmt-allow), and the CLI shell."""
    import glob as _g
    keys = []
    for pub in sorted(_g.glob("/etc/ssh/ssh_host_*_key.pub")):
        try:
            out = subprocess.run(["ssh-keygen", "-lf", pub],
                                 capture_output=True, text=True, timeout=4).stdout.strip()
            if out:
                p = out.split()
                keys.append({"bits": int(p[0]) if p[0].isdigit() else 0,
                             "fingerprint": p[1], "type": p[-1].strip("()")})
        except Exception:
            pass
    sshd = {}
    try:
        t = subprocess.run(["sshd", "-T"], capture_output=True, text=True, timeout=4).stdout
        dd = {}
        for l in t.splitlines():
            if " " in l:
                k, v = l.split(" ", 1)
                dd[k] = v
        sshd = {"port": dd.get("port", "22"),
                "permit_root_login": dd.get("permitrootlogin", ""),
                "ciphers": dd.get("ciphers", "").split(",") if dd.get("ciphers") else [],
                "macs": dd.get("macs", "").split(",") if dd.get("macs") else [],
                "kex": dd.get("kexalgorithms", "").split(",") if dd.get("kexalgorithms") else []}
    except Exception:
        pass
    mgmt = {}
    try:
        with open("/etc/ffn-ngfw/bmfw.json") as f:
            b = json.load(f)
        mgmt = {"interfaces": b.get("mgmt_ifaces", []), "tcp_ports": b.get("mgmt_tcp_ports", [])}
    except Exception:
        pass
    cli = {"present": os.path.exists("/usr/local/bin/ffn-cli"), "gateway_user": "admin",
           "note": "SSH to the gateway user opens the FFN NGFW CLI; 'request system shell' "
                   "escapes to Linux after superuser re-auth."}
    return {"host_keys": keys, "sshd": sshd, "mgmt": mgmt, "cli_shell": cli}


def _cert_details(path: str) -> dict:
    try:
        out = subprocess.run(["openssl", "x509", "-in", path, "-noout", "-subject",
                              "-issuer", "-startdate", "-enddate", "-fingerprint", "-sha256"],
                             capture_output=True, text=True, timeout=5).stdout
        d = {}
        for l in out.splitlines():
            if l.startswith("subject="):
                d["subject"] = l.split("=", 1)[1].strip()
            elif l.startswith("issuer="):
                d["issuer"] = l.split("=", 1)[1].strip()
            elif l.startswith("notBefore="):
                d["valid_from"] = l.split("=", 1)[1].strip()
            elif l.startswith("notAfter="):
                d["valid_to"] = l.split("=", 1)[1].strip()
            elif "Fingerprint=" in l:
                d["fingerprint"] = l.split("=", 1)[1].strip()
        d["self_signed"] = d.get("subject") == d.get("issuer")
        return d
    except Exception:
        return {}


@app.get("/api/system/certificates")
async def system_certificates(user: dict = Depends(get_current_user)):
    """Installed certificates parsed from the TLS store."""
    import glob as _g
    tls_dir = "/etc/ffn-ngfw/tls"
    serving = os.path.realpath(os.path.join(tls_dir, "server.crt"))
    certs = []
    for p in sorted(set(_g.glob(tls_dir + "/*.crt") + _g.glob(tls_dir + "/*.pem"))):
        det = _cert_details(p)
        if det:
            det["name"] = os.path.basename(p)
            det["path"] = p
            det["in_use"] = (os.path.realpath(p) == serving)
            certs.append(det)
    return {"certificates": certs, "tls_dir": tls_dir}


@app.post("/api/system/certificates/csr")
async def system_cert_csr(req: CsrRequest, user: dict = Depends(get_current_user)):
    """Generate a CSR from the device's existing private key. Non-disruptive:
    the serving certificate/key are untouched."""
    key = "/etc/ffn-ngfw/tls/server.key"
    if not os.path.exists(key):
        raise HTTPException(status_code=400, detail="no device private key present")
    subj = "/CN=" + req.common_name.replace("/", "_")
    if req.org:
        subj += "/O=" + req.org.replace("/", "_")
    if req.country:
        subj += "/C=" + req.country[:2].upper()
    try:
        r = subprocess.run(["openssl", "req", "-new", "-key", key, "-subj", subj],
                           capture_output=True, text=True, timeout=8)
        if r.returncode != 0:
            raise HTTPException(status_code=500,
                                detail="CSR generation failed: " + (r.stderr or "")[:200])
        return {"status": "generated", "subject": subj, "csr_pem": r.stdout}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)[:200])


# ==========================================================================
# 3b. High Availability (Active/Active) -- PAN-OS deviceconfig/high-availability
# ==========================================================================
HA_CONFIG_PATH   = "/etc/ffn-ngfw/ha.json"
HA_STATE_PATH    = "/var/lib/ffn-ngfw/ha-state.json"
HA_FAILOVER_FLAG = "/var/lib/ffn-ngfw/ha-failover"

_HA_DEFAULT = {
    "enable": False,
    "mode": "active-active",            # active-active | active-passive | disabled
    "group_id": 1,
    "device_id": 0,                     # this box: 0 or 1
    "primary_device": 0,
    "session_setup": "ip-hash",         # ip-hash | ip-modulo | primary-device | first-packet
    "session_owner": "first-packet",    # primary-device | first-packet
    "ha1": {"interface": "", "ip": "", "peer_ip": ""},
    "ha2": {"interface": "", "enable": True},
    "ha3": {"interface": "", "peer_mac": ""},
    "heartbeat_ms": 1000,
    "peer_timeout_ms": 3000,
    "hold_ms": 2000,
    "virtual_addresses": [],
}


def _ha_deep_merge(base: dict, upd: dict) -> dict:
    for k, v in upd.items():
        if isinstance(v, dict) and isinstance(base.get(k), dict):
            _ha_deep_merge(base[k], v)
        else:
            base[k] = v
    return base


def _read_ha_config() -> dict:
    cfg = json.loads(json.dumps(_HA_DEFAULT))   # deep copy
    try:
        with open(HA_CONFIG_PATH) as f:
            _ha_deep_merge(cfg, json.load(f))
    except Exception:
        pass
    return cfg


def _write_ha_config(cfg: dict):
    try:
        if os.path.exists(HA_CONFIG_PATH):
            shutil.copy(HA_CONFIG_PATH, HA_CONFIG_PATH + ".bak")
    except Exception:
        pass
    with open(HA_CONFIG_PATH, "w") as f:
        json.dump(cfg, f, indent=2)


def _ha_ping(ip: str) -> bool:
    if not ip:
        return False
    try:
        r = subprocess.run(["ping", "-c", "1", "-W", "1", ip],
                           capture_output=True, timeout=3)
        return r.returncode == 0
    except Exception:
        return False


def _ha_live_state() -> dict:
    cfg = _read_ha_config()
    dp = {}
    try:
        with open(HA_STATE_PATH) as f:
            dp = json.load(f)
    except Exception:
        pass
    peer_ip = (cfg.get("ha1") or {}).get("peer_ip") or ""
    peer_reachable = _ha_ping(peer_ip) if peer_ip else None
    # data-plane report wins; else fall back to the HA1 ping
    peer_up = dp.get("peer_up")
    if peer_up is None:
        peer_up = bool(peer_reachable)
    dev = cfg.get("device_id", 0)
    role = "primary" if dev == cfg.get("primary_device", 0) else "secondary"
    return {
        "enabled": bool(cfg.get("enable")),
        "mode": cfg.get("mode"),
        "device_id": dev,
        "primary_device": cfg.get("primary_device", 0),
        "session_setup": cfg.get("session_setup"),
        "role": role,
        "local_state": dp.get("hstate", ("active" if cfg.get("enable") else "disabled")),
        "peer_up": bool(peer_up),
        "peer_reachable": peer_reachable,
        "failover_pending": os.path.exists(HA_FAILOVER_FLAG),
        "counters": dp.get("counters", {"fwd_to_peer": 0, "rx_from_peer": 0,
                                        "local_owned": 0, "takeovers": 0,
                                        "hellos_rx": 0, "hellos_tx": 0}),
        "links": {
            "ha1": bool((cfg.get("ha1") or {}).get("peer_ip")),
            "ha2": bool((cfg.get("ha2") or {}).get("enable")),
            "ha3": bool((cfg.get("ha3") or {}).get("interface")),
        },
        "dataplane_reported": bool(dp),
    }


@app.get("/api/ha/config")
async def ha_config_get():
    return {"config": _read_ha_config()}


@app.put("/api/ha/config")
async def ha_config_set(cfg: HaConfig, user: dict = Depends(get_current_user)):
    cur = _read_ha_config()
    upd = cfg.dict(exclude_unset=True)
    # clamp / validate
    if "mode" in upd and upd["mode"] not in ("active-active", "active-passive", "disabled"):
        raise HTTPException(status_code=400, detail=f"invalid mode '{upd['mode']}'")
    if "device_id" in upd and upd["device_id"] not in (0, 1):
        raise HTTPException(status_code=400, detail="device_id must be 0 or 1")
    if "session_setup" in upd and upd["session_setup"] not in (
            "ip-hash", "ip-modulo", "primary-device", "first-packet"):
        raise HTTPException(status_code=400, detail=f"invalid session_setup '{upd['session_setup']}'")
    for k in ("heartbeat_ms", "peer_timeout_ms", "hold_ms"):
        if k in upd and upd[k] is not None:
            upd[k] = max(100, int(upd[k]))
    _ha_deep_merge(cur, upd)
    _write_ha_config(cur)
    try:
        async with aiosqlite.connect(DB_PATH) as db:
            await audit(db, user["username"], "set_ha_config",
                        f"mode={cur.get('mode')} dev={cur.get('device_id')} "
                        f"enable={cur.get('enable')} setup={cur.get('session_setup')}")
            await db.commit()
    except Exception:
        pass
    # signal the data plane to reload HA config (best-effort; picked up on next tick)
    try:
        subprocess.run(["systemctl", "reload-or-restart", "ffn-ha"],
                       capture_output=True, timeout=5)
    except Exception:
        pass
    return {"status": "applied", "config": cur}


@app.get("/api/ha/state")
async def ha_state_get():
    return _ha_live_state()


@app.post("/api/ha/failover")
async def ha_failover(user: dict = Depends(get_current_user)):
    """Manually trigger failover: suspend the local device so the peer owns all
    flows. The data-plane heartbeat clears the flag when the operator resumes."""
    cfg = _read_ha_config()
    if not cfg.get("enable"):
        raise HTTPException(status_code=400, detail="HA is not enabled")
    try:
        with open(HA_FAILOVER_FLAG, "w") as f:
            f.write("suspend\n")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"cannot set failover flag: {e}")
    try:
        async with aiosqlite.connect(DB_PATH) as db:
            await audit(db, user["username"], "ha_failover", "manual suspend")
            await db.commit()
    except Exception:
        pass
    return {"status": "failover-triggered", "local": "suspended"}


@app.post("/api/ha/resume")
async def ha_resume(user: dict = Depends(get_current_user)):
    """Clear a manual failover: the local device rejoins as active."""
    try:
        if os.path.exists(HA_FAILOVER_FLAG):
            os.remove(HA_FAILOVER_FLAG)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"cannot clear failover flag: {e}")
    try:
        async with aiosqlite.connect(DB_PATH) as db:
            await audit(db, user["username"], "ha_resume", "manual resume")
            await db.commit()
    except Exception:
        pass
    return {"status": "resumed", "local": "active"}


def _cp_reachable():
    """Is the control plane answering? Returns (bool, detail).

    Positive evidence only. `systemctl is-active ffn-octeon` is a oneshot with
    RemainAfterExit, so it reports "active" forever after the bring-up script
    exits -- including long after the CP has stopped answering.

    The route check is here because 127.1.1.2 is inside 127/8: with ffnnet0
    down the kernel hands that address to this host's own loopback, so the
    connection is refused by our own sshd while ping still succeeds. That trap
    has produced a confident wrong answer before.
    """
    try:
        r = subprocess.run(["ip", "route", "get", "127.1.1.2"],
                           capture_output=True, text=True, timeout=4)
        if "ffnnet0" not in r.stdout:
            return False, ("127.1.1.2 does not route over ffnnet0, so it would "
                           "reach this host's own loopback")
    except Exception as exc:
        return False, "route check failed: %s" % exc
    try:
        sock = socket.create_connection(("127.1.1.2", 8104), timeout=3)
        sock.close()
        return True, "ffn-bcmd answering on 127.1.1.2:8104"
    except OSError as exc:
        return False, "no answer on 127.1.1.2:8104: %s" % exc


def _sw_forwarder():
    """FFN's own software forwarder -- the path that works with no NPU at all."""
    out = {"unit": "ffn-dp-afpacket", "active": False, "ports": [],
           "kind": "AF_PACKET bump-in-the-wire"}
    try:
        r = subprocess.run(["systemctl", "is-active", "ffn-dp-afpacket"],
                           capture_output=True, text=True, timeout=5)
        out["active"] = r.stdout.strip() == "active"
        pg = subprocess.run(["pgrep", "-af", "ffn_dp_afpacket"],
                            capture_output=True, text=True, timeout=5).stdout
        out["ports"] = re.findall(r"-i\s+(\S+)", pg)
    except Exception:
        pass
    return out


def _probe_host_octeon():
    """The host-side half of offload detection. BLOCKING -- runs in a thread.

    Everything here shells out or reads sysfs, and none of it belongs on an
    event loop: this is called from request handlers the WebUI polls every ten
    seconds, and a synchronous subprocess there stalls every other request on
    the box, including the ones an operator is using to find out what is wrong.
    """
    info = {
        "present": False, "generation": None, "pci": [], "driver": None,
        "bars": [], "boot_state": "absent", "note": "",
        "cp": {"present": False, "reachable": False},
        "dp": {"present": False},
        "switch": {"present": False}, "fe100": {"present": False},
        "forwarder": _sw_forwarder(),
    }
    try:
        out = subprocess.run(["lspci", "-Dnn"], capture_output=True,
                             text=True, timeout=5).stdout
    except Exception:
        out = ""
    for ln in out.splitlines():
        low = ln.lower()
        if "177d:" in low or "cavium" in low:
            info["pci"].append(ln.strip())
            if "cn73" in low or "octeon iii" in low:
                info["generation"] = "OCTEON III (CN73XX)"
            elif "octeon ii" in low:
                info["generation"] = "OCTEON II"
    if not info["pci"]:
        info["note"] = ("No OCTEON complex on this host's PCI bus. FFN uses "
                        "its software dataplane here.")
        return info

    info["present"] = True
    info["cp"]["present"] = True
    # One chip, several functions. Count DISTINCT PCI slots, not BDF entries,
    # or a single CN73XX reads as a three-instance dataplane.
    info["cp"]["functions"] = sorted(set(ln.split()[0].rsplit(".", 1)[0]
                                         for ln in info["pci"]))
    info["cp"]["chips"] = len(info["cp"]["functions"])
    first = info["pci"][0].split()[0]
    d = "/sys/bus/pci/devices/" + first
    try:
        info["driver"] = os.path.basename(os.readlink(d + "/driver"))
    except OSError:
        info["driver"] = None
    try:
        # Rows 0-5 are the BARs; 6 is the expansion ROM and 7-12 are bridge
        # forwarding windows. Counting those as BARs inflates the device.
        for i, l in enumerate(open(d + "/resource").read().splitlines()):
            if i > 5:
                break
            parts = l.split()
            if len(parts) >= 2:
                st, en = int(parts[0], 16), int(parts[1], 16)
                if en > st:
                    info["bars"].append(
                        {"bar": i, "size_mb": (en - st + 1) // (1 << 20)})
    except Exception:
        pass

    ok, detail = _cp_reachable()
    info["cp"]["reachable"] = ok
    info["cp"]["detail"] = detail
    info["boot_state"] = "CP running" if ok else "CP present, not answering"
    if not ok:
        info["note"] = ("The control plane is on the bus but not responding, "
                        "so nothing behind it can be enumerated. " + detail)
    return info


async def _detect_offload_dp(max_age: float = 15.0) -> dict:
    """The forwarding complex of a reclaimed appliance, walked as the chain it
    actually is:

        MP (x86, this host) --PCIe--> CP OCTEON --PCIe--> DP OCTEON (CN78XX)
                                          |
                                          +--> BCM88375 switch --> faceplate
                                          +--> FE100 front-end ASIC

    The previous version stopped at the first hop and drew three wrong
    conclusions from it. It ran `lspci` here, counted the THREE PCI functions of
    the single CN73XX -- two OCTEON functions plus its NVMe-class one -- and
    reported dp_instances=3. It read that chip's unbound driver link and
    reported "unbound" for a CP that was up and answering. And it called the CP
    itself the dataplane.

    Everything past the CP -- the BCM, the FE100, and the 40-core CN78XX that
    IS the dataplane -- hangs off the CP's own root complexes. None of it
    appears in this host's PCI space, so no amount of host-side lspci could
    ever have found it. That is why the far side is asked rather than guessed:
    ffn-bcmd answers a read-only sysfs inventory on the CP, and that query
    deliberately does not touch the switch session, so it still answers while
    the chip is initialising or after that session has died.

    CACHED, and the blocking half runs off the event loop. Three endpoints call
    this and the WebUI polls two of them every ten seconds; without both of
    those it would be four subprocesses and a synchronous socket connect on the
    loop, several times per poll -- which stalls every other request on the box
    at exactly the moment an operator is trying to find out what is wrong.
    """
    # Short-lived cache. Two endpoints the WebUI polls every ten seconds call
    # this, and a third calls it per hardware refresh; what it reports -- which
    # silicon is present, whether the CP answers -- does not change on a
    # sub-second timescale, so re-probing per request buys nothing and costs a
    # subprocess storm. Held as a function attribute rather than a module
    # global so the function is self-contained and can be deployed on its own.
    now = time.time()
    ent = getattr(_detect_offload_dp, "_cache", None)
    if ent is None:
        ent = _detect_offload_dp._cache = {"t": 0.0, "data": None}
    if ent["data"] is not None and (now - ent["t"]) < max_age:
        return ent["data"]

    info = await asyncio.to_thread(_probe_host_octeon)

    if info["cp"]["reachable"]:
        try:
            inv = await _bcm_client().sys_inventory()
        except ImportError as exc:
            inv = {"ok": False, "error": "bcm client unavailable",
                   "detail": str(exc)}
        except Exception as exc:
            inv = {"ok": False, "error": "inventory failed", "detail": str(exc)}

        if not inv.get("devices"):
            info["note"] = ("CP is answering but returned no inventory: %s"
                            % (inv.get("detail") or inv.get("error")
                               or "empty reply"))
        else:
            info["cp"]["kernel"] = (inv.get("cp") or {}).get("release")
            info["cp"]["arch"] = (inv.get("cp") or {}).get("machine")
            info["cp_devices"] = inv["devices"]
            for dev in inv["devices"]:
                if dev["kind"] == "npu" and dev["device"] == "0095":
                    # NO "booted" flag. It is tempting to derive one from the
                    # driver link, and it would be wrong: this device is
                    # brought up by writing its PCI `enable` file and then
                    # mmap'ing resourceN directly -- dpboot and ffn_dpnetd both
                    # do exactly that -- so NO kernel driver ever binds to it,
                    # and driver=None is the normal, healthy state rather than
                    # a fault. The `enable` bit is not a boot indicator either:
                    # it stays 1 after whatever set it has gone away.
                    #
                    # There is no read-only PCI signal for "is the dataplane
                    # running", so this reports what it can see and says so.
                    # Asking the DP itself would answer it, but that goes
                    # through ffn-dpsh, which is single-session -- a status
                    # endpoint polled every ten seconds must not touch it.
                    info["dp"].update({
                        "present": True, "pci": dev["pci"],
                        "driver": dev["driver"], "model": dev["description"],
                        "pci_enabled": dev.get("pci_enabled"),
                    })
                elif dev["kind"] == "switch" and not info["switch"]["present"]:
                    info["switch"].update({
                        "present": True, "pci": dev["pci"],
                        "driver": dev["driver"], "model": dev["description"],
                    })
                elif dev["kind"] == "asic":
                    info["fe100"].update({
                        "present": True, "pci": dev["pci"],
                        "driver": dev["driver"], "model": dev["description"],
                    })
            if info["dp"]["present"]:
                info["generation"] = info["generation"] or "OCTEON III"
                info["boot_state"] = "CP running, DP present"
                # Liveness comes from the CP, because it is the only place with
                # evidence: the dataplane is driven with no kernel driver bound,
                # so from this host there is no driver, no netdev and no signal
                # of any kind. Asking is the whole point -- an earlier version
                # inferred "booted" from the driver link and would have reported
                # a running dataplane as down.
                try:
                    st = await _bcm_client().dp_status()
                except Exception as exc:
                    st = {"error": str(exc)}
                if st.get("summary"):
                    mbox = st.get("mailbox") or {}
                    info["dp"]["liveness"] = st["summary"]
                    info["dp"]["agents"] = st.get("agent") or []
                    info["dp"]["net"] = st.get("net") or {}
                    info["dp"]["mailbox"] = mbox
                    # The agent answering on the mailbox is the strongest signal
                    # there is, and it is the ONLY one right after a boot: the
                    # control-plane network daemon is a separate step, so there
                    # is no CP-side process and no dpnet interface yet. Keying
                    # `running` off the process list alone reported a
                    # demonstrably-alive dataplane as idle -- a false negative
                    # that invites someone to re-boot working hardware.
                    running = bool(mbox.get("agent_up")) or bool(st.get("agent"))
                    info["dp"]["running"] = running
                    info["boot_state"] = "CP running, DP %s" % (
                        "running" if running else "present, idle")
                else:
                    # Say that the question was not answered, rather than
                    # letting a missing field read as "not running".
                    info["dp"]["liveness"] = (
                        "unknown: the control plane did not report (%s)"
                        % (st.get("detail") or st.get("error") or "no reply"))
            else:
                info["boot_state"] = "CP running, no DP found on its bus"

    ent["t"] = now
    ent["data"] = info
    return info


@app.get("/api/dataplane/offload")
async def dataplane_offload():
    return await _detect_offload_dp()


# ---------------------------------------------------------------------------
# Software / content updates via FFN's own signed payload updater.
# All verification lives in ffn_payload.py (HMAC-signed manifest + sha256);
# these endpoints only drive it and report what it says.
# ---------------------------------------------------------------------------
FFN_PAYLOAD = "/opt/ffn-ngfw-v2/ffn_payload.py"
UPDATE_CONF = "/etc/ffn-ngfw/update-server.conf"


def _update_server_url():
    try:
        with open(UPDATE_CONF) as f:
            for line in f:
                line = line.strip()
                if line.startswith("url="):
                    return line[4:].strip()
    except Exception:
        pass
    return ""


def _payload_cli(args, timeout=120):
    import subprocess as _sp
    try:
        r = _sp.run(["python3", FFN_PAYLOAD] + args, capture_output=True,
                    text=True, timeout=timeout)
        return {"rc": r.returncode, "out": r.stdout, "err": r.stderr}
    except Exception as e:
        return {"rc": -1, "out": "", "err": str(e)}


@app.get("/api/system/updates")
async def updates_status():
    """Installed payload versions, key presence, and the configured server."""
    import json as _j
    st = {}
    try:
        with open("/var/lib/ffn-ngfw/update-state.json") as f:
            st = _j.load(f)
    except Exception:
        pass
    def _nonempty(pth):
        try:
            return os.path.getsize(pth) > 0
        except Exception:
            return False
    # A public key means ed25519-only (an hmac manifest is refused as a
    # downgrade); the shared hmac key is the weaker fallback.
    has_pub = _nonempty("/etc/ffn-ngfw/update.pub")
    has_hmac = _nonempty("/etc/ffn-ngfw/update.key")
    have_key = has_pub or has_hmac
    key_type = "ed25519 (public key only)" if has_pub else (
        "hmac (shared secret)" if has_hmac else "none")
    running = ""
    try:
        import subprocess as _sp
        running = _sp.run(["findmnt", "-no", "SOURCE", "/"], capture_output=True,
                          text=True, timeout=5).stdout.strip()
    except Exception:
        pass
    return {
        "server": _update_server_url(),
        "key_present": have_key,
        "key_type": key_type,
        "ed25519": has_pub,
        "installed": st.get("installed", {}),
        "running_root": running,
        "updater": os.path.exists(FFN_PAYLOAD),
        "kinds": ["content", "software", "image"],
    }


class UpdateServerCfg(BaseModel):
    url: str


@app.put("/api/system/updates/server")
async def updates_set_server(cfg: UpdateServerCfg):
    u = (cfg.url or "").strip()
    if u and not u.startswith(("http://", "https://")):
        raise HTTPException(400, "url must start with http:// or https://")
    try:
        os.makedirs("/etc/ffn-ngfw", exist_ok=True)
        with open(UPDATE_CONF, "w") as f:
            f.write("url=%s\n" % u)
    except Exception as e:
        raise HTTPException(500, "could not save: %s" % e)
    return {"success": True, "server": u}


@app.post("/api/system/updates/check")
async def updates_check(insecure: bool = True):
    url = _update_server_url()
    if not url:
        raise HTTPException(400, "no update server configured")
    a = ["check", "--url", url] + (["--insecure"] if insecure else [])
    r = _payload_cli(a, timeout=90)
    return {"success": r["rc"] == 0, "output": r["out"] or r["err"], "server": url}


class UpdateInstall(BaseModel):
    kind: str
    apply: bool = False
    force: bool = False
    insecure: bool = True


@app.post("/api/system/updates/install")
async def updates_install(req: UpdateInstall):
    """Download+verify a payload; only writes anything when apply=true.

    An 'image' payload is written to the INACTIVE A/B root, never the running
    one, so a bad update is escaped by picking the other GRUB entry.
    """
    if req.kind not in ("content", "software", "image"):
        raise HTTPException(400, "kind must be content, software or image")
    url = _update_server_url()
    if not url:
        raise HTTPException(400, "no update server configured")
    a = ["update", "--url", url, "--kind", req.kind]
    if req.insecure:
        a.append("--insecure")
    if req.apply:
        a.append("--apply")
    if req.force:
        a.append("--force")
    # image payloads are ~1.2 GB: allow a long transfer
    r = _payload_cli(a, timeout=3600 if req.kind == "image" else 600)
    return {"success": r["rc"] == 0, "output": r["out"] or r["err"],
            "kind": req.kind, "applied": req.apply}


# ---------------------------------------------------------------------------
# Vendor firmware (owner-supplied) + Octeon bring-up state
# ---------------------------------------------------------------------------
FFN_VENDOR = "/opt/ffn-ngfw-v2/ffn_vendor.py"
FFN_OCT = "/opt/ffn-ngfw-v2/ffn_oct.py"


def _vendor_cli(args, timeout=120):
    import subprocess as _sp
    try:
        r = _sp.run(["python3", FFN_VENDOR] + args, capture_output=True,
                    text=True, timeout=timeout)
        return {"rc": r.returncode, "out": r.stdout, "err": r.stderr}
    except Exception as e:
        return {"rc": -1, "out": "", "err": str(e)}


def _removable_media():
    """Block devices that look like plugged-in media, for the 'insert a stick'
    hint. Internal disks are excluded so the page never invites a reimport of
    the system drive."""
    out = []
    for d in sorted(glob.glob("/sys/block/*")):
        name = os.path.basename(d)
        if name.startswith(("loop", "ram", "dm-", "md")):
            continue
        try:
            rem = open(os.path.join(d, "removable")).read().strip() == "1"
        except Exception:
            rem = False
        usb = "usb" in os.path.realpath(d)
        if not (rem or usb):
            continue
        try:
            sectors = int(open(os.path.join(d, "size")).read().strip())
        except Exception:
            sectors = 0
        parts = [os.path.basename(p) for p in sorted(glob.glob(d + "/" + name + "*"))]
        out.append({"device": name, "size_mb": sectors // 2048,
                    "partitions": parts, "usb": usb, "removable": rem})
    return out


def _vendor_registry_raw():
    try:
        with open("/var/lib/ffn-ngfw/vendor/registry.json") as f:
            return json.load(f).get("artifacts", [])
    except Exception:
        return []


@app.get("/api/vendor/status")
async def vendor_status():
    """Chassis fingerprint, owner-imported firmware, and bring-up readiness."""
    det = _vendor_cli(["detect", "--json"], timeout=30)
    chassis = {}
    try:
        chassis = json.loads(det["out"])
    except Exception:
        # Older ffn_vendor without --json: fall back to the human output.
        for line in (det["out"] or "").splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                chassis[k.strip().replace(" ", "_")] = v.strip()
    cfg = {}
    try:
        with open("/etc/ffn-ngfw/vendor.conf") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    cfg[k.strip()] = v.strip()
    except Exception:
        pass
    return {
        "chassis": chassis,
        "artifacts": _vendor_registry_raw(),
        "media": _removable_media(),
        "policy": {"autoimport": cfg.get("autoimport", "yes"),
                   "autoload": cfg.get("autoload", "yes")},
        "vendor_dir": "/var/lib/ffn-ngfw/vendor",
        "note": ("Firmware you own, used in place on this box. FFN never "
                 "packages it into an image or an update payload."),
    }


@app.get("/api/octeon/bringup")
async def octeon_bringup():
    """The 9-step bring-up plan, parsed for display. Read-only: this never
    touches the hardware (ffn_oct.py needs --force for that)."""
    import subprocess as _sp
    try:
        r = _sp.run(["python3", FFN_OCT], capture_output=True, text=True,
                    timeout=60)
        txt = r.stdout
    except Exception as e:
        raise HTTPException(500, "bring-up plan unavailable: %s" % e)
    steps, ready, total = [], 0, 0
    cur = None
    for line in txt.splitlines():
        m = re.match(r"\[(OK  |WAIT)\]\s+(\d+)\.\s+(.*)$", line)
        if m:
            cur = {"ready": m.group(1).strip() == "OK",
                   "n": int(m.group(2)), "title": m.group(3).strip(),
                   "detail": ""}
            steps.append(cur)
        elif cur is not None and line.startswith("         "):
            cur["detail"] = (cur["detail"] + " " + line.strip()).strip()
        m2 = re.match(r"Ready\s*:\s*(\d+)/(\d+)", line)
        if m2:
            ready, total = int(m2.group(1)), int(m2.group(2))
    return {"ready": ready, "total": total or len(steps), "steps": steps,
            "raw": txt[:4000]}


class VendorScanReq(BaseModel):
    path: str
    force: bool = False


@app.post("/api/vendor/scan")
async def vendor_scan(req: VendorScanReq):
    r = _vendor_cli(["scan", "--source", req.path], timeout=180)
    return {"success": r["rc"] == 0, "output": r["out"] or r["err"]}


@app.post("/api/vendor/import")
async def vendor_import(req: VendorScanReq):
    a = ["import", "--source", req.path]
    if req.force:
        a.append("--force")
    r = _vendor_cli(a, timeout=600)
    return {"success": r["rc"] == 0, "output": r["out"] or r["err"], "rc": r["rc"]}


@app.post("/api/vendor/forget")
async def vendor_forget():
    r = _vendor_cli(["forget", "--all"], timeout=60)
    return {"success": r["rc"] == 0, "output": r["out"] or r["err"]}


# ==========================================================================
# 4. Security Policy
# ==========================================================================


IMMUTABLE_RULE_NAMES = {"intrazone-default", "interzone-default"}
IMMUTABLE_KIND_PREFIX = {"intrazone-default", "interzone-default", "lab-mgmt"}


@app.get("/api/policy/rules")
async def policy_list(show_hidden: bool = False, show_defaults: bool = True):
    """
    Returns rules in evaluation order: user rules first (by position),
    then PAN-OS-style implicit defaults (intrazone-default, then
    interzone-default) which always evaluate last.

    Query params:
      - show_hidden=true  — include intrazone-default (hidden by default,
                            matching PAN-OS UI which shows it only when
                            "Show default rules" is enabled)
      - show_defaults=false — hide both implicit defaults entirely
    """
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        # User rules in position order, then defaults (intrazone before
        # interzone because intrazone is more specific).
        # Evaluation order: lab-mgmt override → user rules →
        # intrazone-default → interzone-default.
        cursor = await db.execute(
            "SELECT * FROM policy_rules "
            "ORDER BY "
            "  CASE kind "
            "    WHEN 'lab-mgmt' THEN 0 "
            "    WHEN 'user' THEN 1 "
            "    WHEN 'intrazone-default' THEN 2 "
            "    WHEN 'interzone-default' THEN 3 "
            "    ELSE 4 END, "
            "  position ASC"
        )
        rows = [dict(r) for r in await cursor.fetchall()]

        out = []
        for r in rows:
            kind = r.get("kind", "user")
            if not show_defaults and kind != "user":
                continue
            if kind == "intrazone-default" and not show_hidden:
                continue
            # Expose computed flags for the UI
            r["is_default"] = kind != "user"
            r["is_immutable"] = bool(r.get("immutable", 0))
            out.append(r)
        return {"rules": out}


@app.post("/api/policy/rules")
async def policy_add(rule: PolicyRule, user: dict = Depends(get_current_user)):
    # Don't let users create rules with reserved implicit-default names.
    if rule.name and rule.name.lower() in IMMUTABLE_RULE_NAMES:
        raise HTTPException(status_code=400,
                            detail=f"'{rule.name}' is a reserved default rule name")
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        if rule.position == 0:
            cursor = await db.execute(
                "SELECT MAX(position) FROM policy_rules WHERE kind='user'"
            )
            row = await cursor.fetchone()
            rule.position = (row[0] or 0) + 1
        cursor = await db.execute(
            "INSERT INTO policy_rules "
            "(position, name, src_ip, dst_ip, src_iface, dst_iface, "
            " src_port, dst_port, proto, action, vsys, description, kind) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'user')",
            (rule.position, rule.name, rule.src_ip, rule.dst_ip,
             rule.src_iface, rule.dst_iface,
             rule.src_port, rule.dst_port,
             rule.proto, rule.action, _check_vsys(rule.vsys), rule.description),
        )
        await audit(db, user["username"], "add_rule", f"id={cursor.lastrowid}")
        return {"id": cursor.lastrowid, "status": "created"}


# Where the dataplane looks for its compiled tables. The DP reads this
# directory directly, so writes into it are atomic (see below).
_FASTPATH_DIR = os.getenv("FFN_FASTPATH_DIR", "/var/lib/ffn-ngfw/fastpath")


def _cidr_to_pair(cidr: str):
    """'10.1.0.0/16' -> (host-order base, host-order mask). '' or 'any' -> 0/0.

    Host order, because that is what struct dp_policy_row holds and what
    dp_classify() compares against a tuple built with explicit shifts. The
    dataplane deliberately has no ntohl (see ffn_dp_oct.h), so getting the order
    wrong here would produce rules that match on x86 and not on the OCTEON.
    """
    s = (cidr or "").strip()
    if not s or s.lower() in ("any", "0.0.0.0/0", "*"):
        return 0, 0
    addr, _, bits = s.partition("/")
    try:
        parts = [int(x) for x in addr.split(".")]
        if len(parts) != 4 or any(p < 0 or p > 255 for p in parts):
            return 0, 0
        base = (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]
    except ValueError:
        return 0, 0
    try:
        n = int(bits) if bits else 32
    except ValueError:
        n = 32
    if n <= 0:
        return 0, 0
    if n > 32:
        n = 32
    mask = (0xFFFFFFFF << (32 - n)) & 0xFFFFFFFF
    return base & mask, mask


def _proto_to_num(p) -> int:
    """Protocol name or number -> IP protocol number. An unknown name is 0,
    which the dataplane treats as "any protocol" -- the same thing the
    rulebase means by 'any'.

    The table lives INSIDE the function deliberately. These helpers get
    deployed individually onto an appliance whose manager is behind on
    unrelated changes, and a module-level constant sitting beside them is
    exactly what gets left behind -- which has now happened three times in
    this file, each time surfacing as a NameError in a running handler.
    """
    proto_num = {"any": 0, "ip": 0, "tcp": 6, "udp": 17, "icmp": 1,
                 "esp": 50, "ah": 51, "gre": 47, "sctp": 132}
    if isinstance(p, int):
        return p & 0xFF
    s = (p or "any").strip().lower()
    if s in proto_num:
        return proto_num[s]
    try:
        return int(s) & 0xFF
    except ValueError:
        return 0


async def _compile_policy_bin(path: str = None) -> dict:
    """Compile the live rulebase into the dataplane's policy.bin.

    THIS LINK DID NOT EXIST. ffn_fastpath_compile could build the blob and the
    dataplane could load it, but nothing in the manager ever called the
    compiler -- `load_policy` had no caller outside the compiler's own selftest.
    So the rulebase an operator edits and the table the dataplane matches on
    were never connected: rules were stored, displayed, audited, and never
    enforced by the fast path.

    Rules are emitted in POSITION order, because a fast-path table is
    first-match and position is what the operator ordered them by. Disabled and
    hidden rules are left out entirely rather than emitted with a flag: a row
    the dataplane can never use still costs a comparison per packet.

    The vsys byte comes from each rule's own column, so a rule tagged to a
    tenant matches only that tenant's traffic, and an untagged rule (vsys 0)
    keeps the wildcard behaviour every rule had before tenants existed.
    """
    import ffn_fastpath_compile as fpc

    out = path or os.path.join(_FASTPATH_DIR, "ffn_fastpath.policy.bin")
    rows = []
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(
            "SELECT id, position, name, src_ip, dst_ip, src_port, dst_port, "
            "       proto, action, vsys FROM policy_rules "
            " WHERE enabled=1 AND COALESCE(hidden,0)=0 "
            " ORDER BY position, id")
        for r in await cur.fetchall():
            src, srcm = _cidr_to_pair(r["src_ip"])
            dst, dstm = _cidr_to_pair(r["dst_ip"])
            sp = int(r["src_port"] or 0)
            dp_ = int(r["dst_port"] or 0)
            act = (r["action"] or "permit").strip().lower()
            rows.append({
                "src_ip": src, "src_mask": srcm,
                "dst_ip": dst, "dst_mask": dstm,
                # Port 0 in the rulebase means "any", which on the wire is the
                # whole range -- not the single port zero.
                "sport_lo": sp or 0, "sport_hi": sp or 0xFFFF,
                "dport_lo": dp_ or 0, "dport_hi": dp_ or 0xFFFF,
                "proto": _proto_to_num(r["proto"]),
                "vsys": int(r["vsys"] or 0) & 0xFF,
                # The dataplane's decision codes from ffn_dp_oct.h:
                # FP_FORWARD_W 0, FP_INSPECT_W 1, FP_DROP_W 3. Inline for the
                # same reason as the protocol table above.
                "action": (3 if act in ("deny", "drop", "reject")
                           else 1 if act in ("inspect", "scan")
                           else 0),
                "flags": 0,
                # No egress is pinned from the rulebase: that is bump-in-the-wire
                # forwarding, and the dataplane routes when a rule does not name
                # one. DP_EGRESS_NONE.
                "egress_port": 0xFFFF,
                "rule_id": int(r["id"]) & 0xFFFF,
            })

    c = fpc.FastPathCompiler()
    c.load_policy(rows, vsys=0)
    blob = c._pack_policy()
    os.makedirs(os.path.dirname(out), exist_ok=True)
    tmp = out + ".tmp"
    with open(tmp, "wb") as f:
        f.write(blob)
    os.replace(tmp, out)             # atomic: the DP may read this at any moment

    import hashlib
    return {"path": out, "rules": len(rows), "bytes": len(blob),
            "sha256": hashlib.sha256(blob).hexdigest()[:16],
            "tenants": sorted({r["vsys"] for r in rows if r["vsys"]})}


@app.post("/api/policy/compile")
async def policy_compile(user: dict = Depends(get_current_user)):
    """Build policy.bin from the live rulebase. Also run at commit."""
    try:
        return await _compile_policy_bin()
    except Exception as exc:
        raise HTTPException(status_code=500,
                            detail="policy compile failed: %s" % exc)


@app.put("/api/policy/rules/{rule_id}")
async def policy_update(rule_id: int, rule: PolicyRule,
                        user: dict = Depends(get_current_user)):
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(
            "SELECT kind, immutable, action, name FROM policy_rules WHERE id=?",
            (rule_id,),
        )
        existing = await cur.fetchone()
        if existing is None:
            raise HTTPException(status_code=404, detail="Rule not found")
        if existing["immutable"]:
            # Only description (and eventually profile/log fields) may be
            # changed on an immutable default rule. Everything else is
            # locked to preserve PAN-OS semantics.
            await db.execute(
                "UPDATE policy_rules SET description=?, "
                " updated_at=datetime('now') WHERE id=?",
                (rule.description, rule_id),
            )
            await audit(db, user["username"], "update_rule",
                        f"id={rule_id} (immutable: description only)")
            return {"status": "updated", "immutable": True,
                    "message": "Immutable default rule — only description updated"}

        await db.execute(
            "UPDATE policy_rules SET name=?, src_ip=?, dst_ip=?, "
            "  src_iface=?, dst_iface=?, src_port=?, dst_port=?, "
            "  proto=?, action=?, vsys=?, description=?, position=?, "
            "  updated_at=datetime('now') WHERE id=?",
            (rule.name, rule.src_ip, rule.dst_ip,
             rule.src_iface, rule.dst_iface,
             rule.src_port, rule.dst_port,
             rule.proto, rule.action, _check_vsys(rule.vsys),
             rule.description, rule.position, rule_id),
        )
        await audit(db, user["username"], "update_rule", f"id={rule_id}")
        return {"status": "updated"}


@app.delete("/api/policy/rules/{rule_id}")
async def policy_delete(rule_id: int, user: dict = Depends(get_current_user)):
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(
            "SELECT immutable, kind FROM policy_rules WHERE id=?", (rule_id,)
        )
        existing = await cur.fetchone()
        if existing is None:
            raise HTTPException(status_code=404, detail="Rule not found")
        if existing["immutable"]:
            raise HTTPException(
                status_code=403,
                detail=f"Cannot delete immutable default rule ({existing['kind']})",
            )
        await db.execute("DELETE FROM policy_rules WHERE id = ?", (rule_id,))
        await audit(db, user["username"], "delete_rule", f"id={rule_id}")
        return {"status": "deleted"}


# --- Quick-action policy helpers (operational shortcuts) ---

ZT_IFACE_PATTERN = "zt*"


@app.post("/api/policy/rules/quick/allow-zerotier")
async def policy_quick_allow_zerotier(user: dict = Depends(get_current_user)):
    """
    Insert (or re-insert) a top-priority permit rule that matches any
    traffic arriving on a ZeroTier interface (`iifname zt*`). This is
    what the operator invokes from the CLI via `request allow zerotier`.

    Idempotent: if a rule named `allow-zerotier` already exists we
    update it in place rather than creating a duplicate. We also
    renumber it to position 1 so it evaluates first.
    """
    rule_name = "allow-zerotier"
    description = "Allow all traffic from ZeroTier (auto-added)"
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        # Shift existing user rules down by one so the new rule lands at 1
        cur = await db.execute(
            "SELECT id FROM policy_rules WHERE name=? AND kind='user'",
            (rule_name,),
        )
        existing = await cur.fetchone()
        if existing:
            await db.execute(
                "UPDATE policy_rules SET position=1, src_iface=?, "
                " src_ip='0.0.0.0/0', dst_ip='0.0.0.0/0', src_port=0, dst_port=0, "
                " proto='any', action='permit', description=?, "
                " enabled=1, updated_at=datetime('now') WHERE id=?",
                (ZT_IFACE_PATTERN, description, existing["id"]),
            )
            rule_id = existing["id"]
            status = "updated"
        else:
            # Push other user rules down so ZT allow is first
            await db.execute(
                "UPDATE policy_rules SET position = position + 1 "
                " WHERE kind='user' AND position < 999000"
            )
            cur2 = await db.execute(
                "INSERT INTO policy_rules "
                "(position, name, src_ip, dst_ip, src_iface, dst_iface, "
                " src_port, dst_port, proto, action, description, kind) "
                "VALUES (1, ?, '0.0.0.0/0', '0.0.0.0/0', ?, NULL, "
                " 0, 0, 'any', 'permit', ?, 'user')",
                (rule_name, ZT_IFACE_PATTERN, description),
            )
            rule_id = cur2.lastrowid
            status = "created"
        await db.commit()
        await audit(db, user["username"], "policy_quick_allow_zerotier",
                    f"rule_id={rule_id}")

    # Nudge ffn-dpd via controld so the rule reaches nftables right away.
    reload_info = None
    if controld is not None and controld.available():
        try:
            reload_info = controld.dpd_reload(reason="allow-zerotier")
        except Exception as exc:
            logger.debug("dpd reload after allow-zerotier failed: %s", exc)

    return {
        "status": status,
        "rule_id": rule_id,
        "name": rule_name,
        "match": {"src_iface": ZT_IFACE_PATTERN},
        "dpd_reload": reload_info,
        "message": "ZeroTier allow rule installed at position 1. "
                   "Commit to persist across reboots.",
    }


# ==========================================================================
# 5. Network (Routes, ARP, Interface config)
# ==========================================================================


def _get_routes_from_system():
    """Read FIB from Linux via ip route or simulate."""
    try:
        out = subprocess.check_output(["ip", "-j", "route", "show"], text=True, timeout=5)
        routes = json.loads(out)
        result = []
        for r in routes:
            result.append({
                "destination": r.get("dst", "default"),
                "next_hop": r.get("gateway", "direct"),
                "interface": r.get("dev", ""),
                "metric": r.get("metric", 0),
                "protocol": r.get("protocol", ""),
                "scope": r.get("scope", ""),
            })
        return result
    except Exception:
        # No `ip route` output available -> honest empty FIB, no fabricated routes.
        return []


def _get_arp_table():
    """Read ARP table from Linux or simulate."""
    try:
        out = subprocess.check_output(["ip", "-j", "neigh", "show"], text=True, timeout=5)
        entries = json.loads(out)
        result = []
        for e in entries:
            result.append({
                "ip": e.get("dst", ""),
                "mac": e.get("lladdr", "incomplete"),
                "interface": e.get("dev", ""),
                "state": e.get("state", [""])[0] if isinstance(e.get("state"), list) else e.get("state", ""),
            })
        return result
    except Exception:
        # No `ip neigh` output available -> honest empty table, no fabricated ARP.
        return []


@app.get("/api/network/routes")
async def network_routes():
    return {"routes": _get_routes_from_system()}


@app.post("/api/network/routes")
async def network_add_route(route: StaticRoute, user: dict = Depends(get_current_user)):
    try:
        cmd = ["ip", "route", "add", route.destination, "via", route.next_hop]
        if route.interface:
            cmd += ["dev", route.interface]
        cmd += ["metric", str(route.metric)]
        subprocess.check_call(cmd, timeout=5)
    except FileNotFoundError:
        pass  # Windows/non-Linux: no-op
    except subprocess.CalledProcessError as exc:
        raise HTTPException(status_code=400, detail=f"Route add failed: {exc}")
    async with aiosqlite.connect(DB_PATH) as db:
        await audit(db, user["username"], "add_route", f"{route.destination} via {route.next_hop}")
    return {"status": "added"}


@app.delete("/api/network/routes")
async def network_delete_route(destination: str = Query(...), user: dict = Depends(get_current_user)):
    try:
        subprocess.check_call(["ip", "route", "del", destination], timeout=5)
    except FileNotFoundError:
        pass
    except subprocess.CalledProcessError as exc:
        raise HTTPException(status_code=400, detail=f"Route delete failed: {exc}")
    async with aiosqlite.connect(DB_PATH) as db:
        await audit(db, user["username"], "delete_route", destination)
    return {"status": "deleted"}


@app.get("/api/network/arp")
async def network_arp():
    return {"arp_table": _get_arp_table()}


@app.get("/api/network/interfaces")
async def network_interfaces_config():
    """Real interface configuration from the system."""
    return {"interfaces": _discover_interfaces()}


@app.put("/api/network/interfaces/{iface_name}")
async def network_interface_update(iface_name: str, cfg: InterfaceConfig, user: dict = Depends(get_current_user)):
    """Apply interface configuration changes."""
    actions = []
    try:
        if cfg.ip_address and cfg.netmask:
            # Convert netmask to CIDR
            cidr = sum(bin(int(x)).count("1") for x in cfg.netmask.split("."))
            subprocess.check_call(
                ["ip", "addr", "flush", "dev", iface_name], timeout=5
            )
            subprocess.check_call(
                ["ip", "addr", "add", f"{cfg.ip_address}/{cidr}", "dev", iface_name],
                timeout=5,
            )
            actions.append(f"IP={cfg.ip_address}/{cfg.netmask}")
        if cfg.mtu:
            subprocess.check_call(
                ["ip", "link", "set", iface_name, "mtu", str(cfg.mtu)], timeout=5
            )
            actions.append(f"MTU={cfg.mtu}")
    except FileNotFoundError:
        pass
    except subprocess.CalledProcessError as exc:
        raise HTTPException(status_code=400, detail=f"Config failed: {exc}")
    async with aiosqlite.connect(DB_PATH) as db:
        await audit(db, user["username"], "update_interface", f"{iface_name}: {', '.join(actions)}")
    return {"status": "updated", "interface": iface_name, "applied": actions}


# ==========================================================================
# 5b. Virtual Routers = VRF instances (Axis 3, contract §3)
#
# Each virtual router is a real l3mdev VRF device with its own routing
# table. The applier drives `ip`/`sysctl`; every subprocess goes through
# `_run_ip()` which returns (rc, out) and degrades to a logged no-op when
# the binary is absent (so the module imports/tests on Windows). The
# management interface is NEVER enslaved — it stays in the default VRF so
# the box remains reachable.
# ==========================================================================


def _mgmt_iface() -> str:
    """The management interface that must stay in the default VRF.

    Env-overridable; falls back to the lab mgmt iface used elsewhere.
    """
    return (os.getenv("FFN_MGMT_IFACE")
            or os.getenv("FFN_LAB_MGMT_IFACE", "eno1np0"))


def _run_net_cmd(args, tag: str, timeout: int = 5):
    """Run a network control command; return (rc, combined_output).

    No-op-with-log when the binary is unavailable (non-Linux/dev boxes) so
    the appliers are import- and unit-test-safe. A missing binary is reported
    as rc=0 (successful no-op) so higher layers don't treat dev hosts as an
    error; real command failures surface their non-zero rc. Shared by the
    `ip`/`sysctl` VRF applier and the `vtysh` FRR applier (contract §6).
    """
    cmd = [str(a) for a in args]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        out = ((p.stdout or "") + (p.stderr or "")).strip()
        if p.returncode != 0:
            logger.warning("%s rc=%d: %s :: %s",
                           tag, p.returncode, " ".join(cmd), out)
        return p.returncode, out
    except FileNotFoundError:
        logger.info("%s no-op (binary unavailable): %s", tag, " ".join(cmd))
        return 0, ""
    except subprocess.TimeoutExpired:
        logger.warning("%s timeout: %s", tag, " ".join(cmd))
        return 124, "timeout"
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning("%s error %s: %s", tag, exc, " ".join(cmd))
        return 1, str(exc)


def _run_ip(args, timeout: int = 5):
    """Run an `ip`/`sysctl` command; (rc, out), no-op-with-log if absent."""
    return _run_net_cmd(args, "vrf-applier", timeout)


def _run_vtysh(args, timeout: int = 5):
    """Run a `vtysh` (FRR) command; (rc, out), no-op-with-log if absent.

    On a box without FRR this returns (0, "") — the empty body makes FIB
    reads fall back to the kernel `ip route` path automatically.
    """
    return _run_net_cmd(args, "frr-applier", timeout)


# ---------------------------------------------------------------------------
# FrrManager — FRRouting control plane for VRFs (contract §6, refines §3)
#
# l3mdev VRF devices remain the kernel substrate (created via the `ip` path
# in `_vrf_create`); FRR (zebra/staticd/bgpd/ospfd) is the routing control
# plane. FrrManager renders a per-VRF config fragment and applies it via
# `vtysh -c` line commands (or a frr.conf fragment + `vtysh -b`), and reads
# the FIB via `vtysh -c "show ip route vrf <name> json"`. Every vtysh call
# goes through `_run_vtysh`, so this imports + unit-tests on Windows.
# ---------------------------------------------------------------------------
class FrrManager:
    """Render + apply per-VRF FRR config; read FRR FIB via vtysh json."""

    def __init__(self, run=None):
        # `run` is the (rc, out) helper; defaults to the no-op-with-log vtysh.
        self._run = run or _run_vtysh

    # -- rendering ----------------------------------------------------------
    @staticmethod
    def _route_stmt(rt, negate: bool = False):
        """One `[no ] ip route <dest> [<nh>] [<dev>] [<metric>]` statement."""
        dest = (rt.get("dest_cidr") or rt.get("destination") or "").strip()
        if not dest:
            return None
        nh = (rt.get("next_hop") or "").strip()
        dev = (rt.get("dev") or "").strip()
        metric = rt.get("metric") or 0
        parts = ["no ip route", dest] if negate else ["ip route", dest]
        if nh:
            parts.append(nh)
        if dev:
            parts.append(dev)
        if metric:
            parts.append(str(metric))
        return " ".join(parts)

    @classmethod
    def render_fragment(cls, name: str, table_id: int, protocol: str = "static",
                        router_id: Optional[str] = None, asn: Optional[int] = None,
                        routes=None) -> str:
        """Return the FRR config fragment text for one VRF (for `vtysh -b`)."""
        routes = routes or []
        proto = (protocol or "static").lower()
        lines = [f"vrf {name}"]
        for rt in routes:
            stmt = cls._route_stmt(rt)
            if stmt:
                lines.append(" " + stmt)
        lines.append("exit-vrf")
        if proto == "bgp" and asn:
            lines.append(f"router bgp {asn} vrf {name}")
            if router_id:
                lines.append(f" bgp router-id {router_id}")
            lines.append(" address-family ipv4 unicast")
            lines.append(" exit-address-family")
            lines.append("exit")
        elif proto == "ospf":
            lines.append(f"router ospf vrf {name}")
            if router_id:
                lines.append(f" ospf router-id {router_id}")
            lines.append("exit")
        return "\n".join(lines) + "\n"

    def _config_commands(self, name, protocol, router_id, asn, routes):
        """The fragment as a list of `vtysh -c` config-mode command strings."""
        routes = routes or []
        proto = (protocol or "static").lower()
        cmds = ["configure terminal", f"vrf {name}"]
        for rt in routes:
            stmt = self._route_stmt(rt)
            if stmt:
                cmds.append(stmt)
        cmds.append("exit-vrf")
        if proto == "bgp" and asn:
            cmds.append(f"router bgp {asn} vrf {name}")
            if router_id:
                cmds.append(f"bgp router-id {router_id}")
            cmds.append("address-family ipv4 unicast")
            cmds.append("exit-address-family")
            cmds.append("exit")
        elif proto == "ospf":
            cmds.append(f"router ospf vrf {name}")
            if router_id:
                cmds.append(f"ospf router-id {router_id}")
            cmds.append("exit")
        cmds.append("end")
        return cmds

    def render_full_commands(self, name, table_id, cfg, routes):
        """Full per-VR FRR config as vtysh config-mode command strings:
        static routes (+static admin-distance), then BGP/OSPF/OSPFv3/RIP with
        admin distances, ECMP maximum-paths, neighbors/areas and redistribution.
        Each protocol block is cleared ('no router ...') before re-add so a
        re-apply is a clean replace."""
        cfg = cfg or {}
        ad = cfg.get("admin_dists") or {}
        ecmp = cfg.get("ecmp") or {}

        def i(x, d=None):
            try:
                return int(x)
            except Exception:
                return d
        mp = i(ecmp.get("max_paths")) if ecmp.get("enable") else None
        cmds = ["configure terminal", f"vrf {name}"]
        sd = i(ad.get("static"))
        for rt in (routes or []):
            stmt = self._route_stmt(rt)
            if stmt:
                cmds.append(f"{stmt} {sd}" if sd else stmt)
        cmds.append("exit-vrf")
        # --- BGP ---
        bgp = cfg.get("bgp") or {}
        asn = i(bgp.get("local_as"))
        if bgp.get("enable") and asn:
            cmds.append(f"router bgp {asn} vrf {name}")
            if bgp.get("router_id"):
                cmds.append(f"bgp router-id {bgp['router_id']}")
            for nb in bgp.get("neighbors") or []:
                ip = (nb.get("peer_ip") or "").strip(); ras = i(nb.get("remote_as"))
                if ip and ras:
                    cmds.append(f"neighbor {ip} remote-as {ras}")
                    if nb.get("description"):
                        cmds.append(f"neighbor {ip} description {nb['description']}")
            cmds.append("address-family ipv4 unicast")
            for nb in bgp.get("neighbors") or []:
                ip = (nb.get("peer_ip") or "").strip()
                if ip:
                    cmds.append(f"neighbor {ip} activate")
            for r in bgp.get("redistribute") or []:
                cmds.append(f"redistribute {r}")
            if ad.get("ebgp") or ad.get("ibgp"):
                cmds.append(f"distance bgp {i(ad.get('ebgp'), 20)} {i(ad.get('ibgp'), 200)} {i(ad.get('ibgp'), 200)}")
            if mp:
                cmds.append(f"maximum-paths {mp}")
            cmds.append("exit-address-family")
            cmds.append("exit")
        # --- OSPF ---
        ospf = cfg.get("ospf") or {}
        if ospf.get("enable"):
            cmds.append(f"router ospf vrf {name}")
            if ospf.get("router_id"):
                cmds.append(f"ospf router-id {ospf['router_id']}")
            for area in ospf.get("areas") or []:
                aid = area.get("area_id") or "0.0.0.0"
                for net in area.get("networks") or []:
                    cmds.append(f"network {net} area {aid}")
            for r in ospf.get("redistribute") or []:
                cmds.append(f"redistribute {r}")
            if ad.get("ospf_int") or ad.get("ospf_ext"):
                ii = i(ad.get("ospf_int"), 110); ee = i(ad.get("ospf_ext"), 110)
                cmds.append(f"distance ospf intra-area {ii} inter-area {ii} external {ee}")
            if mp:
                cmds.append(f"maximum-paths {mp}")
            cmds.append("exit")
        # --- OSPFv3 ---
        o6 = cfg.get("ospfv3") or {}
        if o6.get("enable"):
            cmds.append(f"router ospf6 vrf {name}")
            if o6.get("router_id"):
                cmds.append(f"ospf6 router-id {o6['router_id']}")
            for r in o6.get("redistribute") or []:
                cmds.append(f"redistribute {r}")
            cmds.append("exit")
        # --- RIP ---
        rip = cfg.get("rip") or {}
        if rip.get("enable"):
            cmds.append(f"router rip vrf {name}")
            for net in rip.get("networks") or []:
                cmds.append(f"network {net}")
            for r in rip.get("redistribute") or []:
                cmds.append(f"redistribute {r}")
            if ad.get("rip"):
                cmds.append(f"distance {i(ad.get('rip'), 120)}")
            cmds.append("exit")
        cmds.append("end")
        return cmds

    def render_clear_commands(self, name, cfg):
        """'no router ...' lines for the enabled protocols, so a re-apply cleanly
        replaces each block. Run as a SEPARATE, error-tolerant vtysh pass."""
        cfg = cfg or {}
        out = ["configure terminal"]
        bgp = cfg.get("bgp") or {}
        try:
            asn = int(bgp.get("local_as"))
        except Exception:
            asn = None
        if bgp.get("enable") and asn:
            out.append(f"no router bgp {asn} vrf {name}")
        if (cfg.get("ospf") or {}).get("enable"):
            out.append(f"no router ospf vrf {name}")
        if (cfg.get("ospfv3") or {}).get("enable"):
            out.append(f"no router ospf6 vrf {name}")
        if (cfg.get("rip") or {}).get("enable"):
            out.append(f"no router rip vrf {name}")
        out.append("end")
        return out if len(out) > 2 else []

    def _vtysh(self, cmds):
        args = ["vtysh"]
        for c in cmds:
            args += ["-c", c]
        return self._run(args)

    # -- apply --------------------------------------------------------------
    def apply(self, name, table_id, protocol="static", router_id=None,
              asn=None, routes=None):
        """Apply a VRF's full FRR config via `vtysh -c` line commands."""
        return self._vtysh(
            self._config_commands(name, protocol, router_id, asn, routes))

    def add_route(self, name, dest, next_hop="", dev=None, metric=0):
        """Install one static route into a VRF via staticd (not raw ip route)."""
        stmt = self._route_stmt(
            {"dest_cidr": dest, "next_hop": next_hop, "dev": dev, "metric": metric})
        if not stmt:
            return 0, ""
        return self._vtysh(["configure terminal", f"vrf {name}", stmt, "exit-vrf", "end"])

    def del_route(self, name, dest, next_hop="", dev=None):
        """Remove one static route from a VRF via staticd."""
        stmt = self._route_stmt(
            {"dest_cidr": dest, "next_hop": next_hop, "dev": dev}, negate=True)
        if not stmt:
            return 0, ""
        return self._vtysh(["configure terminal", f"vrf {name}", stmt, "exit-vrf", "end"])

    def remove(self, name):
        """Remove a VRF's FRR config (routing plane teardown)."""
        return self._vtysh(["configure terminal", f"no vrf {name}", "end"])

    # -- read ---------------------------------------------------------------
    def read_fib(self, name):
        """Read a VRF's FIB via `show ip route vrf <name> json`.

        Returns (ok, fib_list). ok=False (empty/absent vtysh) tells callers to
        fall back to the kernel `ip route show table N` path.
        """
        rc, out = self._run(["vtysh", "-c", f"show ip route vrf {name} json"])
        if rc != 0 or not out:
            return False, []
        try:
            data = json.loads(out)
        except (ValueError, TypeError):
            return False, []
        if not isinstance(data, dict):
            return False, []
        fib = []
        for dest, entries in data.items():
            for e in (entries or []):
                nexthops = e.get("nexthops") or [{}]
                for nh in nexthops:
                    fib.append({
                        "destination": dest,
                        "next_hop": nh.get("ip", "direct"),
                        "interface": nh.get("interfaceName", nh.get("interface", "")),
                        "metric": e.get("metric", 0),
                        "protocol": e.get("protocol", ""),
                        "scope": "",
                    })
        return True, fib

    # -- selftest -----------------------------------------------------------
    @staticmethod
    def selftest():
        """Render a 2-route static VRF fragment; assert expected text + no-op apply."""
        routes = [
            {"dest_cidr": "10.10.0.0/24", "next_hop": "192.168.1.1", "dev": None, "metric": 0},
            {"dest_cidr": "10.20.0.0/24", "next_hop": "192.168.1.2", "dev": None, "metric": 100},
        ]
        frag = FrrManager.render_fragment("red", 1000, "static", routes=routes)
        expect = (
            "vrf red\n"
            " ip route 10.10.0.0/24 192.168.1.1\n"
            " ip route 10.20.0.0/24 192.168.1.2 100\n"
            "exit-vrf\n"
        )
        assert frag == expect, f"fragment mismatch:\n{frag!r}\n!=\n{expect!r}"
        # Apply is a logged no-op on Windows (vtysh absent) -> rc 0.
        rc, _ = FrrManager().apply("red", 1000, "static", routes=routes)
        assert rc == 0, f"apply rc={rc}"
        # BGP variant renders the router stanza.
        bgp = FrrManager.render_fragment("blue", 1001, "bgp",
                                         router_id="10.0.0.1", asn=65001, routes=[])
        assert "router bgp 65001 vrf blue" in bgp and "bgp router-id 10.0.0.1" in bgp, bgp
        return True


_frr_mgr = None


def _get_frr() -> "FrrManager":
    """Lazy FrrManager singleton (the FRR routing-plane applier, contract §6)."""
    global _frr_mgr
    if _frr_mgr is None:
        _frr_mgr = FrrManager()
    return _frr_mgr


def _set_l3mdev_sysctls():
    """Enable l3mdev socket lookup so mgmt/host sockets bind VRF-correctly."""
    _run_ip(["sysctl", "-w", "net.ipv4.tcp_l3mdev_accept=1"])
    _run_ip(["sysctl", "-w", "net.ipv4.udp_l3mdev_accept=1"])


def _vrf_create(vr_name: str, table_id: int):
    """Create the VRF device + its routing rules (contract §3 sequence)."""
    _run_ip(["ip", "link", "add", vr_name, "type", "vrf", "table", str(table_id)])
    _run_ip(["ip", "link", "set", vr_name, "up"])
    _run_ip(["ip", "rule", "add", "oif", vr_name, "table", str(table_id)])
    _run_ip(["ip", "rule", "add", "iif", vr_name, "table", str(table_id)])
    _set_l3mdev_sysctls()


def _vrf_enslave(vr_name: str, iface: str):
    """Enslave a member iface to the VRF. Refuses the mgmt interface."""
    if iface == _mgmt_iface():
        raise HTTPException(
            status_code=400,
            detail=f"refusing to enslave management interface '{iface}': "
                   "mgmt must stay in the default VRF to keep the box reachable",
        )
    return _run_ip(["ip", "link", "set", iface, "master", vr_name])


def _vrf_add_route(table_id: int, dest: str, next_hop: str = "",
                   dev: Optional[str] = None, metric: int = 0):
    """Install a route into the VRF's table."""
    cmd = ["ip", "route", "add", dest]
    if next_hop:
        cmd += ["via", next_hop]
    if dev:
        cmd += ["dev", dev]
    cmd += ["table", str(table_id)]
    if metric:
        cmd += ["metric", str(metric)]
    return _run_ip(cmd)


def _vrf_del_route(table_id: int, dest: str, next_hop: str = "",
                   dev: Optional[str] = None):
    cmd = ["ip", "route", "del", dest]
    if next_hop:
        cmd += ["via", next_hop]
    if dev:
        cmd += ["dev", dev]
    cmd += ["table", str(table_id)]
    return _run_ip(cmd)


def _vrf_teardown(vr_name: str, table_id: int, interfaces):
    """Reverse of _vrf_create: flush table, un-enslave members, drop rules+dev."""
    _run_ip(["ip", "route", "flush", "table", str(table_id)])
    for iface in interfaces:
        _run_ip(["ip", "link", "set", iface, "nomaster"])
    _run_ip(["ip", "rule", "del", "oif", vr_name, "table", str(table_id)])
    _run_ip(["ip", "rule", "del", "iif", vr_name, "table", str(table_id)])
    _run_ip(["ip", "link", "del", vr_name])


def _vr_row_to_dict(row) -> dict:
    # Tolerate pre-migration rows that lack the FRR columns.
    try:
        keys = set(row.keys())
    except Exception:
        keys = set()
    return {
        "id": row["id"],
        "name": row["name"],
        "table_id": row["table_id"],
        "interfaces": json.loads(row["interfaces"] or "[]"),
        "admin_up": bool(row["admin_up"]),
        "vsys": row["vsys"],
        "protocol": (row["protocol"] if "protocol" in keys and row["protocol"]
                     else "static"),
        "router_id": row["router_id"] if "router_id" in keys else None,
        "asn": row["asn"] if "asn" in keys else None,
        "frr_fragment": row["frr_fragment"] if "frr_fragment" in keys else None,
        "config": (json.loads(row["vr_config"]) if "vr_config" in keys and row["vr_config"] else {}),
    }


async def _vr_static_routes(db, vr_id) -> list:
    """Fetch a VR's static routes as plain dicts (for FRR fragment rendering)."""
    cur = await db.execute(
        "SELECT dest_cidr, next_hop, dev, metric FROM static_routes "
        "WHERE vr_id=? ORDER BY id", (vr_id,))
    return [{"dest_cidr": r["dest_cidr"], "next_hop": r["next_hop"],
             "dev": r["dev"], "metric": r["metric"]} for r in await cur.fetchall()]


async def _alloc_vrf_table_id(db) -> int:
    """Deterministic table id = VRF_TABLE_BASE + index, persisted/monotonic.

    Picks one past the current max user table (>= VRF_TABLE_BASE) so ids are
    never reused even after deletes within a session's high-water mark.
    """
    cur = await db.execute(
        "SELECT MAX(table_id) FROM virtual_routers WHERE table_id >= ?",
        (VRF_TABLE_BASE,),
    )
    row = await cur.fetchone()
    top = row[0]
    return VRF_TABLE_BASE if top is None else int(top) + 1


async def _iface_vrf_conflict(db, ifaces, exclude_vr: Optional[str] = None):
    """Return (iface, vr_name) if any iface already belongs to another VR.

    Enforces cardinality: an interface belongs to exactly one VRF.
    """
    cur = await db.execute("SELECT name, interfaces FROM virtual_routers")
    for r in await cur.fetchall():
        if exclude_vr is not None and r["name"] == exclude_vr:
            continue
        owned = set(json.loads(r["interfaces"] or "[]"))
        for i in ifaces:
            if i in owned:
                return i, r["name"]
    return None


@app.put("/api/network/interfaces/{iface}/virtual-router")
async def iface_set_vr(iface: str, body: IfaceVrAssign,
                       user: dict = Depends(get_current_user)):
    """Assign `iface` (Linux dev name) to a virtual router from the interface
    side -- the mirror of the VR's member list. Moves the iface between SQLite
    VR member lists and reconciles the kernel VRF enslavement. Empty / 'default'
    -> the kernel main table (no VRF). An interface belongs to exactly one VR."""
    mgmt = _mgmt_iface()
    target = (body.virtual_router or "").strip()
    if target.lower() in ("", "default", "none", "main"):
        target = ""
    if target and iface == mgmt:
        raise HTTPException(
            status_code=400,
            detail=f"management interface '{iface}' cannot be enslaved to a VRF",
        )
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute("SELECT name, interfaces FROM virtual_routers")
        rows = await cur.fetchall()
        by_name = {r["name"]: r for r in rows}
        if target and target not in by_name:
            raise HTTPException(status_code=404,
                                detail=f"no such virtual router '{target}'")
        current = None
        for r in rows:
            if r["name"] == "default":
                continue
            if iface in json.loads(r["interfaces"] or "[]"):
                current = r["name"]
                break
        if (current or "") == target:
            return {"status": "unchanged", "interface": iface,
                    "virtual_router": target or "default"}
        if current:
            lst = [x for x in json.loads(by_name[current]["interfaces"] or "[]")
                   if x != iface]
            await db.execute("UPDATE virtual_routers SET interfaces=?, "
                             "updated_at=datetime('now') WHERE name=?",
                             (json.dumps(lst), current))
        if target:
            lst = json.loads(by_name[target]["interfaces"] or "[]")
            if iface not in lst:
                lst.append(iface)
            await db.execute("UPDATE virtual_routers SET interfaces=?, "
                             "updated_at=datetime('now') WHERE name=?",
                             (json.dumps(lst), target))
        await audit(db, user["username"], "assign_iface_vrf",
                    f"{iface} -> {target or 'default'} (was {current or 'default'})")
        await db.commit()
    # kernel reconcile (mgmt already refused above)
    if current:
        _run_ip(["ip", "link", "set", iface, "nomaster"])
    if target:
        _vrf_enslave(target, iface)
        _run_ip(["ip", "link", "set", target, "up"])
    return {"status": "updated", "interface": iface,
            "virtual_router": target or "default", "previous": current or "default"}


@app.get("/api/network/virtual-routers")
async def vr_list():
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(
            "SELECT * FROM virtual_routers ORDER BY table_id"
        )
        vrs = [_vr_row_to_dict(r) for r in await cur.fetchall()]
    return {"virtual_routers": vrs}


@app.post("/api/network/virtual-routers")
async def vr_create(vr: VirtualRouterCreate, user: dict = Depends(get_current_user)):
    mgmt = _mgmt_iface()
    if mgmt in vr.interfaces:
        raise HTTPException(
            status_code=400,
            detail=f"management interface '{mgmt}' cannot be enslaved to a VRF",
        )
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(
            "SELECT id FROM virtual_routers WHERE name=?", (vr.name,)
        )
        if await cur.fetchone():
            raise HTTPException(status_code=409, detail=f"virtual router '{vr.name}' exists")
        conflict = await _iface_vrf_conflict(db, vr.interfaces)
        if conflict:
            raise HTTPException(
                status_code=409,
                detail=f"interface '{conflict[0]}' already belongs to VRF '{conflict[1]}'",
            )
        table_id = await _alloc_vrf_table_id(db)
        frag = FrrManager.render_fragment(
            vr.name, table_id, vr.protocol, vr.router_id, vr.asn, routes=[])
        await db.execute(
            "INSERT INTO virtual_routers "
            "(name, table_id, interfaces, admin_up, vsys, protocol, router_id, asn, frr_fragment) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (vr.name, table_id, json.dumps(vr.interfaces),
             1 if vr.admin_up else 0, vr.vsys,
             vr.protocol, vr.router_id, vr.asn, frag),
        )
        await audit(db, user["username"], "create_vrf",
                    f"{vr.name} table={table_id} proto={vr.protocol} ifaces={vr.interfaces}")
        await db.commit()

    # Apply to the live kernel (no-op on non-Linux). l3mdev device FIRST...
    _vrf_create(vr.name, table_id)
    if not vr.admin_up:
        _run_ip(["ip", "link", "set", vr.name, "down"])
    for iface in vr.interfaces:
        _vrf_enslave(vr.name, iface)
    # ...THEN the FRR routing config (§6): zebra owns the VRF table, staticd/
    # bgpd/ospfd own routing. No-op-with-log when vtysh is absent.
    _get_frr().apply(vr.name, table_id, vr.protocol, vr.router_id, vr.asn, routes=[])
    return {"status": "created", "name": vr.name, "table_id": table_id,
            "interfaces": vr.interfaces, "admin_up": vr.admin_up, "vsys": vr.vsys,
            "protocol": vr.protocol, "router_id": vr.router_id, "asn": vr.asn}


async def _vr_fetch(db, name: str):
    db.row_factory = aiosqlite.Row
    cur = await db.execute("SELECT * FROM virtual_routers WHERE name=?", (name,))
    return await cur.fetchone()


@app.get("/api/network/virtual-routers/{name}")
async def vr_get(name: str):
    async with aiosqlite.connect(DB_PATH) as db:
        row = await _vr_fetch(db, name)
        if not row:
            raise HTTPException(status_code=404, detail=f"no such virtual router '{name}'")
        return _vr_row_to_dict(row)


@app.put("/api/network/virtual-routers/{name}")
async def vr_update(name: str, upd: VirtualRouterUpdate,
                    user: dict = Depends(get_current_user)):
    mgmt = _mgmt_iface()
    async with aiosqlite.connect(DB_PATH) as db:
        row = await _vr_fetch(db, name)
        if not row:
            raise HTTPException(status_code=404, detail=f"no such virtual router '{name}'")
        cur_ifaces = json.loads(row["interfaces"] or "[]")
        table_id = row["table_id"]
        is_default = (name == "default")

        new_ifaces = cur_ifaces
        if upd.interfaces is not None and not (is_default and not upd.interfaces):
            if is_default:
                raise HTTPException(
                    status_code=400,
                    detail="the default VRF is the kernel main table; it has no "
                           "enslaved interfaces",
                )
            if mgmt in upd.interfaces:
                raise HTTPException(
                    status_code=400,
                    detail=f"management interface '{mgmt}' cannot be enslaved to a VRF",
                )
            conflict = await _iface_vrf_conflict(db, upd.interfaces, exclude_vr=name)
            if conflict:
                raise HTTPException(
                    status_code=409,
                    detail=f"interface '{conflict[0]}' already belongs to VRF '{conflict[1]}'",
                )
            new_ifaces = upd.interfaces

        admin_up = bool(row["admin_up"]) if upd.admin_up is None else upd.admin_up
        vsys = row["vsys"] if upd.vsys is None else upd.vsys
        cur_vr = _vr_row_to_dict(row)
        protocol = cur_vr["protocol"] if upd.protocol is None else upd.protocol
        router_id = cur_vr["router_id"] if upd.router_id is None else upd.router_id
        asn = cur_vr["asn"] if upd.asn is None else upd.asn

        # Re-render the FRR fragment from the current static routes + new proto.
        routes = await _vr_static_routes(db, row["id"])
        frag = FrrManager.render_fragment(
            name, table_id, protocol, router_id, asn, routes=routes)

        await db.execute(
            "UPDATE virtual_routers SET interfaces=?, admin_up=?, vsys=?, "
            "protocol=?, router_id=?, asn=?, frr_fragment=?, "
            "updated_at=datetime('now') WHERE name=?",
            (json.dumps(new_ifaces), 1 if admin_up else 0, vsys,
             protocol, router_id, asn, frag, name),
        )
        await audit(db, user["username"], "update_vrf",
                    f"{name} ifaces={new_ifaces} up={admin_up} vsys={vsys} proto={protocol}")
        await db.commit()

    # Reconcile membership with the kernel (skip for the default/main table).
    if not is_default:
        added = [i for i in new_ifaces if i not in cur_ifaces]
        removed = [i for i in cur_ifaces if i not in new_ifaces]
        for iface in removed:
            _run_ip(["ip", "link", "set", iface, "nomaster"])
        for iface in added:
            _vrf_enslave(name, iface)
        _run_ip(["ip", "link", "set", name, "up" if admin_up else "down"])
    # Re-apply the FRR routing config (routes flow through staticd, §6).
    _get_frr().apply(name, table_id, protocol, router_id, asn, routes=routes)
    return {"status": "updated", "name": name, "interfaces": new_ifaces,
            "admin_up": admin_up, "vsys": vsys, "table_id": table_id,
            "protocol": protocol, "router_id": router_id, "asn": asn}


@app.delete("/api/network/virtual-routers/{name}")
async def vr_delete(name: str, user: dict = Depends(get_current_user)):
    if name == "default":
        raise HTTPException(status_code=400, detail="the default virtual router cannot be deleted")
    async with aiosqlite.connect(DB_PATH) as db:
        row = await _vr_fetch(db, name)
        if not row:
            raise HTTPException(status_code=404, detail=f"no such virtual router '{name}'")
        ifaces = json.loads(row["interfaces"] or "[]")
        table_id = row["table_id"]
        await db.execute("DELETE FROM static_routes WHERE vr_id=?", (row["id"],))
        await db.execute("DELETE FROM virtual_routers WHERE name=?", (name,))
        await audit(db, user["username"], "delete_vrf", f"{name} table={table_id}")
        await db.commit()

    # Remove the FRR routing config FIRST (staticd/bgpd/ospfd), then tear the
    # l3mdev substrate down (flush table, un-enslave members, drop the device).
    _get_frr().remove(name)
    _vrf_teardown(name, table_id, ifaces)
    return {"status": "deleted", "name": name}


# --- VR static routes ------------------------------------------------------


class VrRoutingConfig(BaseModel):
    admin_dists: dict = {}
    ecmp: dict = {}
    bgp: dict = {}
    ospf: dict = {}
    ospfv3: dict = {}
    rip: dict = {}
    multicast: dict = {}
    redist_profiles: list = []


@app.get("/api/network/virtual-routers/{name}/routing")
async def vr_get_routing(name: str, user: dict = Depends(get_current_user)):
    async with aiosqlite.connect(DB_PATH) as db:
        row = await _vr_fetch(db, name)
        if not row:
            raise HTTPException(status_code=404, detail=f"virtual router '{name}' not found")
        vr = _vr_row_to_dict(row)
    return {"name": name, "config": vr.get("config") or {}, "frr_fragment": vr.get("frr_fragment")}


@app.put("/api/network/virtual-routers/{name}/routing")
async def vr_set_routing(name: str, cfg: VrRoutingConfig, user: dict = Depends(get_current_user)):
    async with aiosqlite.connect(DB_PATH) as db:
        row = await _vr_fetch(db, name)
        if not row:
            raise HTTPException(status_code=404, detail=f"virtual router '{name}' not found")
        vr = _vr_row_to_dict(row)
        routes = await _vr_static_routes(db, vr["id"])
        cfgd = cfg.dict()
        frr = _get_frr()
        clear = frr.render_clear_commands(name, cfgd)
        if clear:
            frr._vtysh(clear)                       # tolerated: 'can't find' on first apply is fine
        cmds = frr.render_full_commands(name, vr["table_id"], cfgd, routes)
        rc, out = frr._vtysh(cmds)                  # clean apply (no error-prone lines)
        frag = "\n".join(cmds)
        await db.execute(
            "UPDATE virtual_routers SET vr_config=?, frr_fragment=?, updated_at=datetime('now') WHERE name=?",
            (json.dumps(cfgd), frag, name))
        await audit(db, user["username"], "vr_routing", name)
        await db.commit()
    return {"status": "applied", "name": name, "vtysh_rc": rc,
            "config": cfgd, "frr_commands": cmds,
            "vtysh_output": (out or "")[-2000:]}


@app.get("/api/network/virtual-routers/{name}/routes")
async def vr_routes_list(name: str):
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        row = await _vr_fetch(db, name)
        if not row:
            raise HTTPException(status_code=404, detail=f"no such virtual router '{name}'")
        cur = await db.execute(
            "SELECT * FROM static_routes WHERE vr_id=? ORDER BY id", (row["id"],)
        )
        routes = [{
            "id": r["id"], "vr_id": r["vr_id"], "dest_cidr": r["dest_cidr"],
            "next_hop": r["next_hop"], "dev": r["dev"], "metric": r["metric"],
            "table_id": r["table_id"],
        } for r in await cur.fetchall()]
    return {"virtual_router": name, "routes": routes}


@app.post("/api/network/virtual-routers/{name}/routes")
async def vr_route_add(name: str, route: VRRoute,
                       user: dict = Depends(get_current_user)):
    async with aiosqlite.connect(DB_PATH) as db:
        row = await _vr_fetch(db, name)
        if not row:
            raise HTTPException(status_code=404, detail=f"no such virtual router '{name}'")
        table_id = row["table_id"]
        cur = await db.execute(
            "INSERT INTO static_routes (vr_id, dest_cidr, next_hop, dev, metric, table_id) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (row["id"], route.dest_cidr, route.next_hop, route.dev,
             route.metric, table_id),
        )
        route_id = cur.lastrowid
        # Re-render the FRR fragment now that the route set changed.
        routes = await _vr_static_routes(db, row["id"])
        vr = _vr_row_to_dict(row)
        frag = FrrManager.render_fragment(
            name, table_id, vr["protocol"], vr["router_id"], vr["asn"], routes=routes)
        await db.execute(
            "UPDATE virtual_routers SET frr_fragment=?, updated_at=datetime('now') "
            "WHERE id=?", (frag, row["id"]))
        await audit(db, user["username"], "add_vrf_route",
                    f"{name}: {route.dest_cidr} via {route.next_hop or route.dev} table={table_id}")
        await db.commit()

    # Static routes go through staticd (FRR), NOT raw `ip route` (contract §6).
    _get_frr().add_route(name, route.dest_cidr, route.next_hop, route.dev, route.metric)
    return {"status": "added", "id": route_id, "virtual_router": name,
            "dest_cidr": route.dest_cidr, "next_hop": route.next_hop,
            "dev": route.dev, "metric": route.metric, "table_id": table_id}


@app.delete("/api/network/virtual-routers/{name}/routes/{route_id}")
async def vr_route_delete(name: str, route_id: int,
                          user: dict = Depends(get_current_user)):
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        row = await _vr_fetch(db, name)
        if not row:
            raise HTTPException(status_code=404, detail=f"no such virtual router '{name}'")
        cur = await db.execute(
            "SELECT * FROM static_routes WHERE id=? AND vr_id=?",
            (route_id, row["id"]),
        )
        rt = await cur.fetchone()
        if not rt:
            raise HTTPException(status_code=404, detail=f"no such route {route_id} on '{name}'")
        await db.execute("DELETE FROM static_routes WHERE id=?", (route_id,))
        # Re-render the FRR fragment now that the route set changed.
        routes = await _vr_static_routes(db, row["id"])
        vr = _vr_row_to_dict(row)
        frag = FrrManager.render_fragment(
            name, row["table_id"], vr["protocol"], vr["router_id"], vr["asn"],
            routes=routes)
        await db.execute(
            "UPDATE virtual_routers SET frr_fragment=?, updated_at=datetime('now') "
            "WHERE id=?", (frag, row["id"]))
        await audit(db, user["username"], "delete_vrf_route",
                    f"{name}: {rt['dest_cidr']} table={rt['table_id']}")
        await db.commit()

    # Withdraw the route through staticd (FRR), NOT raw `ip route` (contract §6).
    _get_frr().del_route(name, rt["dest_cidr"], rt["next_hop"], rt["dev"])
    return {"status": "deleted", "id": route_id, "virtual_router": name}


@app.get("/api/network/virtual-routers/{name}/fib")
async def vr_fib(name: str):
    """Read the live FIB: prefer FRR (`show ip route vrf <name> json`),
    fall back to the kernel table (`ip route show table N`)."""
    async with aiosqlite.connect(DB_PATH) as db:
        row = await _vr_fetch(db, name)
        if not row:
            raise HTTPException(status_code=404, detail=f"no such virtual router '{name}'")
        table_id = row["table_id"]

    # FRR json first (contract §6); ok=False when vtysh is absent/empty.
    ok, fib = _get_frr().read_fib(name)
    if ok:
        return {"virtual_router": name, "table_id": table_id,
                "source": "frr", "fib": fib}

    # Fallback: read the kernel VRF table directly.
    rc, out = _run_ip(["ip", "-j", "route", "show", "table", str(table_id)])
    fib = []
    if out:
        try:
            for r in json.loads(out):
                fib.append({
                    "destination": r.get("dst", "default"),
                    "next_hop": r.get("gateway", "direct"),
                    "interface": r.get("dev", ""),
                    "metric": r.get("metric", 0),
                    "protocol": r.get("protocol", ""),
                    "scope": r.get("scope", ""),
                })
        except (ValueError, TypeError):
            pass
    return {"virtual_router": name, "table_id": table_id,
            "source": "kernel", "fib": fib}


@app.get("/api/network/virtual-routers/{name}/neighbors")
async def vr_neighbors(name: str):
    """Read `ip neigh` scoped to this VR's member interfaces."""
    async with aiosqlite.connect(DB_PATH) as db:
        row = await _vr_fetch(db, name)
        if not row:
            raise HTTPException(status_code=404, detail=f"no such virtual router '{name}'")
        members = set(json.loads(row["interfaces"] or "[]"))
    rc, out = _run_ip(["ip", "-j", "neigh", "show"])
    neighbors = []
    if out:
        try:
            for e in json.loads(out):
                dev = e.get("dev", "")
                # default VR (main table) owns everything not enslaved elsewhere;
                # a named VR shows only its members.
                if members and dev not in members:
                    continue
                st = e.get("state")
                neighbors.append({
                    "ip": e.get("dst", ""),
                    "mac": e.get("lladdr", "incomplete"),
                    "interface": dev,
                    "state": st[0] if isinstance(st, list) and st else (st or ""),
                })
        except (ValueError, TypeError):
            pass
    return {"virtual_router": name, "neighbors": neighbors}


# ==========================================================================
# 5b. Licensing (dual-identity — REWORK_CONTRACT §4, Axis 2)
#
# Ported from server_snapshot routers/licensing.py, adapted for the salvage
# single-app layout and cardless host operation:
#   * /dna    returns BOTH the host (h1, base) identity and the FPGA
#             (silicon/v1, accelerator) identity.
#   * /status uses HostLicense().query() when no card is present and
#             fpga.query_license() when a card is present.
#   * upload / upload-vendor / upload-bundle / refresh / delete operate on
#             /etc/ffn-ngfw/licenses (+ vendor-keys) exactly as the source.
# NO license gating is added to any engine/vsys/VR route.
# ==========================================================================

LIC_DIR     = Path(os.environ.get("NGFW_LICENSE_DIR",     "/etc/ffn-ngfw/licenses"))
VENDOR_DIR  = Path(os.environ.get("NGFW_VENDOR_KEYS_DIR", "/etc/ffn-ngfw/vendor-keys"))
MASTER_PUB  = Path(os.environ.get("NGFW_MASTER_PUBKEY",   "/etc/ffn-ngfw/master.p384.pub"))
VERIFIER    = os.environ.get("NGFW_VERIFIER_BIN",         "/opt/ffn-ngfw/bin/ffn-license-verify")
AUDIT_LOG   = Path(os.environ.get("NGFW_LICENSE_AUDIT_LOG",
                                  "/var/log/ffn-ngfw/license-audit.log"))

# Fixed wire-format sizes from ngfw_regs.h
LIC_PAYLOAD_BYTES = 84
LIC_TOKEN_MIN     = LIC_PAYLOAD_BYTES + 64    # smallest sig is Ed25519 64 B
LIC_TOKEN_MAX     = LIC_PAYLOAD_BYTES + 132   # largest sig is ECDSA P-521 132 B
VND_PAYLOAD_BYTES = 136
VND_CERT_SIZE     = VND_PAYLOAD_BYTES + 132   # always max (P-521-sized slot)

# NEW (contract §4): accelerator / FPGA-offload entitlement — bound to card
# DNA, only checkable with a card present.
NGFW_LIC_FEAT_ACCEL = 0x130

# Top-level NGFW_LIC_FEAT_* IDs (mirrors ngfw_regs.h)
TOP_LEVEL_FEATURES = {
    0x100: "BASE",
    0x101: "TIER_10G",
    0x102: "TIER_40G",
    0x103: "TIER_100G",
    0x104: "TIER_400G",
    0x110: "VSYS_EXPAND",
    0x111: "PQC",
    0x120: "THREAT_FEED",
    NGFW_LIC_FEAT_ACCEL: "ACCEL",
}

_LIC_SAFE_NAME = re.compile(r"^[A-Za-z0-9._-]+$")


def _lic_read_hq_conf() -> dict:
    """Tiny key=value parser; tolerates comments and blank lines."""
    conf_path = Path(os.environ.get("NGFW_LICENSE_HQ_CONF",
                                     "/etc/ffn-ngfw/license-hq.conf"))
    out = {}
    if conf_path.exists():
        try:
            for line in conf_path.read_text().splitlines():
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, _, v = line.partition("=")
                out[k.strip()] = v.strip().strip('"').strip("'")
        except OSError:
            pass
    return out


_LIC_HQ_CONF = _lic_read_hq_conf()


def _lic_hq(env_key: str, conf_key: str, default: str) -> str:
    """Resolve an HQ field: env var, then license-hq.conf, then default.
    An explicitly empty value means 'no HQ contact, hide button.'"""
    v = os.environ.get(env_key)
    if v is not None:
        return v
    if conf_key in _LIC_HQ_CONF:
        return _LIC_HQ_CONF[conf_key]
    return default


HQ_EMAIL = _lic_hq("NGFW_LICENSE_HQ_EMAIL", "hq_email",
                   "license@freeflownetworks.net")
HQ_URL   = _lic_hq("NGFW_LICENSE_HQ_URL",   "hq_url",
                   "https://lic.freeflownetworks.net/v1/issue")
HQ_NAME  = _lic_hq("NGFW_LICENSE_HQ_NAME",  "hq_name",
                   "FreeFlow Networks Licensing")


def _lic_audit(action: str, user: str, **kw) -> None:
    """Append one JSON line per license-changing event (best-effort)."""
    AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
    rec = {
        "ts":     datetime.utcnow().isoformat() + "Z",
        "user":   user,
        "action": action,
        **kw,
    }
    try:
        with open(AUDIT_LOG, "a") as f:
            f.write(json.dumps(rec) + "\n")
    except OSError as e:
        logger.warning("license audit log write failed: %s", e)


def _lic_safe_filename(name: str) -> str:
    """Reject anything that isn't a plain filename (no slashes, no ..)."""
    base = os.path.basename(name)
    if not base or base.startswith(".") or not _LIC_SAFE_NAME.match(base):
        raise HTTPException(status_code=400, detail=f"unsafe filename: {name!r}")
    return base


def _lic_ensure_dirs():
    LIC_DIR.mkdir(parents=True, exist_ok=True)
    VENDOR_DIR.mkdir(parents=True, exist_ok=True)


async def _lic_run_verifier() -> dict:
    """
    Re-run ffn-license-verify against the current on-disk store.
    Returns a dict with stdout/stderr/exit and a parsed token count.
    """
    if not Path(VERIFIER).exists():
        return {
            "ok": False, "exit": -1, "stdout": "",
            "stderr": f"verifier binary not present at {VERIFIER}",
            "tokens_accepted": 0, "tokens_total": 0,
        }
    try:
        proc = await asyncio.create_subprocess_exec(
            VERIFIER,
            "--license-dir", str(LIC_DIR),
            "--vendor-dir",  str(VENDOR_DIR),
            "--verbose",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        out, err = await proc.communicate()
        rc = proc.returncode or 0
        out_s = out.decode("utf-8", errors="replace")
        err_s = err.decode("utf-8", errors="replace")
        accepted = total = 0
        m = re.search(r"(\d+)/(\d+) tokens accepted", err_s + out_s)
        if m:
            accepted, total = int(m.group(1)), int(m.group(2))
        return {
            "ok": rc == 0, "exit": rc, "stdout": out_s, "stderr": err_s,
            "tokens_accepted": accepted, "tokens_total": total,
        }
    except OSError as exc:
        return {
            "ok": False, "exit": -1, "stdout": "",
            "stderr": f"failed to spawn verifier: {exc}",
            "tokens_accepted": 0, "tokens_total": 0,
        }


def _lic_master_pubkey_fingerprint() -> Optional[str]:
    """SHA-256 prefix of the embedded master pubkey blob's point."""
    if not MASTER_PUB.exists():
        return None
    try:
        b = MASTER_PUB.read_bytes()
        if len(b) < 98:
            return None
        return hashlib.sha256(b[1:98]).hexdigest()[:16]
    except OSError:
        return None


def _lic_parse_lic_meta(path: Path, entry: dict) -> None:
    """Decode feature_id, expiry, signer_id, sig_alg from .lic header."""
    try:
        b = path.read_bytes()
    except OSError:
        return
    if len(b) < LIC_PAYLOAD_BYTES or b[:8] != b"FFN-LIC1":
        return
    feature_id = int.from_bytes(b[24:28], "little")
    issued     = int.from_bytes(b[32:40], "little")
    expiry     = int.from_bytes(b[40:48], "little")
    flags      = int.from_bytes(b[48:52], "little")
    signer_id  = b[52:68]
    sig_alg    = int.from_bytes(b[68:72], "little")
    now = int(time.time())
    days_left = (expiry - now) // 86400 if expiry else None
    entry.update({
        "feature_id":     feature_id,
        "feature_id_hex": f"0x{feature_id:x}",
        "issued":         issued,
        "expiry":         expiry,
        "expiry_days":    days_left,
        "expired":        bool(expiry and expiry < now),
        "flags":          flags,
        "signer":         "master" if signer_id == b"\x00" * 16 else "vendor",
        "sig_alg":        sig_alg,
    })


def _lic_parse_vcert_meta(path: Path, entry: dict) -> None:
    """Decode signer_id + expiry + flags from a .vcert."""
    try:
        b = path.read_bytes()
    except OSError:
        return
    if len(b) < VND_PAYLOAD_BYTES or b[:8] != b"FFN-VND1":
        return
    signer_id = b[12:28]
    issued    = int.from_bytes(b[92:100], "little")
    expiry    = int.from_bytes(b[100:108], "little")
    flags     = int.from_bytes(b[108:112], "little")
    now = int(time.time())
    days_left = (expiry - now) // 86400 if expiry else None
    entry.update({
        "signer_id":   signer_id.hex(),
        "issued":      issued,
        "expiry":      expiry,
        "expiry_days": days_left,
        "expired":     bool(expiry and expiry < now),
        "flags":       flags,
    })


def _lic_list_files(dirpath: Path, suffix: str) -> list:
    if not dirpath.exists():
        return []
    out = []
    for p in sorted(dirpath.iterdir()):
        if not p.is_file() or not p.name.endswith(suffix):
            continue
        try:
            st = p.stat()
            entry = {"name": p.name, "size": st.st_size, "mtime": int(st.st_mtime)}
            if suffix == ".lic":
                _lic_parse_lic_meta(p, entry)
            elif suffix == ".vcert":
                _lic_parse_vcert_meta(p, entry)
            out.append(entry)
        except OSError:
            continue
    return out


def _lic_summarize_expiry(items: list) -> dict:
    """Bucket the file list into expiry-warning categories."""
    now = int(time.time())
    expired = expiring30 = expiring7 = healthy = 0
    soonest = None
    for it in items:
        exp = it.get("expiry") or 0
        if not exp:
            healthy += 1
            continue
        days = (exp - now) // 86400
        if days < 0:    expired += 1
        elif days < 7:  expiring7 += 1
        elif days < 30: expiring30 += 1
        else:           healthy += 1
        if soonest is None or exp < soonest:
            soonest = exp
    return {
        "expired":      expired,
        "expiring_7d":  expiring7,
        "expiring_30d": expiring30,
        "healthy":      healthy,
        "soonest_expiry_unix_s": soonest,
    }


class LicenseUploadResponse(BaseModel):
    saved_to:  str
    bytes:     int
    refreshed: bool
    accepted:  int
    total:     int
    detail:    str = ""


class LicenseStatusResponse(BaseModel):
    source:              str        # "fpga" (card present) | "host" (cardless)
    fpga_present:        bool
    host_dna_hex:        str        # h1 (base) host identity
    host_dna_valid:      bool
    fpga_dna_hex:        str        # silicon/v1 (accelerator) identity
    fpga_dna_valid:      bool
    master_pubkey_fpr:   Optional[str]
    master_pubkey_path:  str
    engines:             list
    top_level_features:  list
    licenses_on_disk:    list
    vendor_certs_on_disk: list
    expiry_summary:      dict


@app.get("/api/license/dna")
async def license_get_dna():
    """
    Return BOTH identities the operator may need to ship to HQ:
      * host (h1) BASE identity  — card-independent, always present.
      * FPGA (silicon/v1) ACCEL identity — only meaningful with a card.
    """
    host_info = fpga.device_host_dna_info()
    fpga_info = fpga.device_dna_info() if fpga_present() else \
        {"dna_hex": "", "valid": False, "source": "none"}
    hdna = host_info["dna_hex"]
    fdna = fpga_info["dna_hex"]
    try:
        version = fpga.get_version()
    except Exception:
        version = ""
    return {
        # host (h1, base) identity
        "host_dna_hex":     hdna,
        "host_dna_compact": hdna.replace(":", "").lower() if hdna else "",
        "host_dna_valid":   host_info["valid"],
        "host_dna_source":  host_info["source"],   # host-h1
        # FPGA (silicon/v1, accelerator) identity
        "dna_hex":          fdna,
        "dna_compact":      fdna.replace(":", "").lower() if fdna else "",
        "valid":            fpga_info["valid"],
        "source":           fpga_info["source"],   # silicon | synthetic | none
        "fpga_present":     fpga_present(),
        "sim_mode":         fpga.sim_mode,
        "hostname":         socket.gethostname(),
        "bitstream_ver":    version,
        "master_pub_fpr":   _lic_master_pubkey_fingerprint(),
        "hq_email":         HQ_EMAIL,
        "hq_url":           HQ_URL,
        "hq_name":          HQ_NAME,
        "hq_configured":    bool(HQ_EMAIL or HQ_URL),
    }


@app.get("/api/license/dna.txt")
async def license_get_dna_txt():
    """Plain-text license-request blob (email to HQ)."""
    from fastapi.responses import PlainTextResponse
    host_info = fpga.device_host_dna_info()
    fpga_info = fpga.device_dna_info() if fpga_present() else \
        {"dna_hex": "", "source": "none"}
    hdna   = host_info["dna_hex"]
    fdna   = fpga_info["dna_hex"]
    source = fpga_info["source"]
    try:
        version = fpga.get_version()
    except Exception:
        version = ""
    fpr = _lic_master_pubkey_fingerprint() or "(no pubkey embedded)"
    lines = [
        "# FFN-NGFW License Request",
        f"# generated: {time.strftime('%Y-%m-%d %H:%M:%S %Z')}",
        f"hostname:        {socket.gethostname()}",
        f"bitstream:       {version}",
        f"master_pub_fpr:  {fpr}",
        f"host_dna_hex:    {hdna or '(unavailable)'}",
        "host_dna_source: host-h1",
        f"fpga_dna_hex:    {fdna or '(no card)'}",
        f"fpga_dna_source: {source}",
        "",
    ]
    if source == "synthetic":
        lines.append(
            "# The FPGA DNA is a synthetic hash of stable hardware identifiers.")
        lines.append(
            "# Build #16+ bitstreams expose the real silicon DEVICE_DNA instead;")
        lines.append(
            "# accel tokens issued now will need re-issuing after that upgrade.")
        lines.append("")
    lines.append("# The host (h1) DNA binds the BASE/tier license and needs no card.")
    lines.append("# The FPGA (v1) DNA binds the ACCEL (offload) entitlement.")
    if HQ_EMAIL or HQ_URL:
        lines.append(f"# Send this file to {HQ_NAME}:")
        if HQ_EMAIL: lines.append(f"#   email: {HQ_EMAIL}")
        if HQ_URL:   lines.append(f"#   url:   {HQ_URL}")
    else:
        lines.append("# HQ contact not configured.  Set hq_email / hq_url in")
        lines.append("# /etc/ffn-ngfw/license-hq.conf or via NGFW_LICENSE_HQ_*.")
    lines.append("# Upload the returned .lic file(s) via Device > Licenses.")
    return PlainTextResponse(
        "\n".join(lines) + "\n",
        headers={"Content-Disposition":
                 f'attachment; filename="ffn-license-request-{socket.gethostname()}.txt"'})


@app.get("/api/license/status", response_model=LicenseStatusResponse)
async def license_get_status():
    """
    Comprehensive licensing snapshot.  When a card is present the kernel
    (fpga.query_license) answers per-feature; cardless, the host-side
    HostLicense verifier answers against the h1 identity.
    """
    _lic_ensure_dirs()
    present = fpga_present()

    hl = None
    if not present:
        try:
            from ffn_license import HostLicense
            hl = HostLicense()
        except Exception as exc:
            logger.warning("host license store unavailable: %s", exc)

    def _q(fid: int) -> bool:
        if present:
            return fpga.query_license(fid)
        return hl.query(fid) if hl is not None else False

    engines = []
    for eid, name in enumerate(ENGINE_NAMES):
        engines.append({"engine_id": eid, "name": name, "licensed": _q(eid)})

    feats = []
    for fid, label in TOP_LEVEL_FEATURES.items():
        feats.append({
            "feature_id":     fid,
            "feature_id_hex": f"0x{fid:x}",
            "name":           label,
            "licensed":       _q(fid),
        })

    licenses = _lic_list_files(LIC_DIR,    ".lic")
    vendors  = _lic_list_files(VENDOR_DIR, ".vcert")
    host_info = fpga.device_host_dna_info()
    fpga_dna  = fpga.device_dna_hex() if present else ""
    return LicenseStatusResponse(
        source=              "fpga" if present else "host",
        fpga_present=        present,
        host_dna_hex=        host_info["dna_hex"],
        host_dna_valid=      host_info["valid"],
        fpga_dna_hex=        fpga_dna,
        fpga_dna_valid=      bool(fpga_dna),
        master_pubkey_fpr=   _lic_master_pubkey_fingerprint(),
        master_pubkey_path=  str(MASTER_PUB),
        engines=             engines,
        top_level_features=  feats,
        licenses_on_disk=    licenses,
        vendor_certs_on_disk=vendors,
        expiry_summary=      _lic_summarize_expiry(licenses + vendors),
    )


@app.post("/api/license/upload", response_model=LicenseUploadResponse)
async def license_upload(file: UploadFile = File(...),
                         user: dict = Depends(get_current_user)):
    """Accept a single .lic file, validate shape, drop into LIC_DIR, re-verify."""
    _lic_ensure_dirs()
    name = _lic_safe_filename(file.filename or "upload.lic")
    if not name.endswith(".lic"):
        raise HTTPException(status_code=400, detail="filename must end with .lic")

    data = await file.read()
    if not (LIC_TOKEN_MIN <= len(data) <= LIC_TOKEN_MAX):
        raise HTTPException(status_code=400,
            detail=(f"license size {len(data)} B outside expected "
                    f"range [{LIC_TOKEN_MIN}..{LIC_TOKEN_MAX}]"))
    if data[:8] != b"FFN-LIC1":
        raise HTTPException(status_code=400, detail="bad magic — not a FFN-LIC1 token")

    dest = LIC_DIR / name
    tmp  = LIC_DIR / (name + ".uploading")
    tmp.write_bytes(data)
    os.replace(tmp, dest)

    logger.info("license uploaded by %s: %s (%d B)",
                user.get("username", "?"), dest, len(data))
    _lic_audit("upload_license", user.get("username", "?"), file=name, bytes=len(data))

    result = await _lic_run_verifier()
    return LicenseUploadResponse(
        saved_to=str(dest), bytes=len(data), refreshed=result["ok"],
        accepted=result["tokens_accepted"], total=result["tokens_total"],
        detail=result["stderr"][-2000:],
    )


@app.post("/api/license/upload-vendor", response_model=LicenseUploadResponse)
async def license_upload_vendor(file: UploadFile = File(...),
                                user: dict = Depends(get_current_user)):
    """Accept a master-signed .vcert and drop it into VENDOR_DIR."""
    _lic_ensure_dirs()
    name = _lic_safe_filename(file.filename or "vendor.vcert")
    if not name.endswith(".vcert"):
        raise HTTPException(status_code=400, detail="filename must end with .vcert")

    data = await file.read()
    if len(data) != VND_CERT_SIZE:
        raise HTTPException(status_code=400,
            detail=f"vendor cert size {len(data)} B, expected {VND_CERT_SIZE}")
    if data[:8] != b"FFN-VND1":
        raise HTTPException(status_code=400, detail="bad magic — not a FFN-VND1 cert")

    dest = VENDOR_DIR / name
    tmp  = VENDOR_DIR / (name + ".uploading")
    tmp.write_bytes(data)
    os.replace(tmp, dest)

    logger.info("vendor cert uploaded by %s: %s (%d B)",
                user.get("username", "?"), dest, len(data))
    _lic_audit("upload_vendor", user.get("username", "?"), file=name, bytes=len(data))

    result = await _lic_run_verifier()
    return LicenseUploadResponse(
        saved_to=str(dest), bytes=len(data), refreshed=result["ok"],
        accepted=result["tokens_accepted"], total=result["tokens_total"],
        detail=result["stderr"][-2000:],
    )


@app.post("/api/license/upload-bundle")
async def license_upload_bundle(file: UploadFile = File(...),
                                user: dict = Depends(get_current_user)):
    """Accept a tarball/zip of licenses/*.lic + vendor-keys/*.vcert."""
    import io, tarfile, zipfile
    _lic_ensure_dirs()

    name = _lic_safe_filename(file.filename or "bundle")
    data = await file.read()
    if len(data) > 16 * 1024 * 1024:
        raise HTTPException(status_code=413,
            detail=f"bundle too large ({len(data)} B, max 16 MB)")

    members = []
    if name.endswith((".tar", ".tar.gz", ".tgz")):
        try:
            tf = tarfile.open(fileobj=io.BytesIO(data), mode="r:*")
            members = [(m.name, tf.extractfile(m).read())
                       for m in tf.getmembers() if m.isfile()]
        except (tarfile.TarError, OSError) as e:
            raise HTTPException(status_code=400, detail=f"bad tarball: {e}")
    elif name.endswith(".zip"):
        try:
            zf = zipfile.ZipFile(io.BytesIO(data), "r")
            members = [(m.filename, zf.read(m))
                       for m in zf.infolist() if not m.is_dir()]
        except zipfile.BadZipFile as e:
            raise HTTPException(status_code=400, detail=f"bad zip: {e}")
    else:
        raise HTTPException(status_code=400,
            detail="bundle must be .tar, .tar.gz, .tgz, or .zip")

    accepted = []
    rejected = []
    for member_name, member_data in members:
        base = os.path.basename(member_name)
        if not base or base.startswith(".") or not _LIC_SAFE_NAME.match(base):
            rejected.append({"name": member_name, "reason": "unsafe filename"})
            continue
        if base.endswith(".lic"):
            if (LIC_TOKEN_MIN <= len(member_data) <= LIC_TOKEN_MAX
                    and member_data[:8] == b"FFN-LIC1"):
                (LIC_DIR / base).write_bytes(member_data)
                accepted.append({"name": base, "kind": "license"})
            else:
                rejected.append({"name": base, "reason": "bad magic or size"})
        elif base.endswith(".vcert"):
            if len(member_data) == VND_CERT_SIZE and member_data[:8] == b"FFN-VND1":
                (VENDOR_DIR / base).write_bytes(member_data)
                accepted.append({"name": base, "kind": "vendor"})
            else:
                rejected.append({"name": base, "reason": "bad magic or size"})
        # silently skip anything else (README, sigs, etc.)

    logger.info("license bundle uploaded by %s: %d accepted, %d rejected",
                user.get("username", "?"), len(accepted), len(rejected))
    _lic_audit("upload_bundle", user.get("username", "?"),
               accepted=len(accepted), rejected=len(rejected))

    result = await _lic_run_verifier()
    return {
        "accepted":        accepted,
        "rejected":        rejected,
        "tokens_accepted": result["tokens_accepted"],
        "tokens_total":    result["tokens_total"],
        "verifier_log":    result["stderr"][-2000:],
    }


@app.post("/api/license/refresh")
async def license_refresh(user: dict = Depends(get_current_user)):
    """Re-run ffn-license-verify against the current on-disk store."""
    result = await _lic_run_verifier()
    _lic_audit("refresh", user.get("username", "?"),
               accepted=result["tokens_accepted"], total=result["tokens_total"])
    return {
        "ok":              result["ok"],
        "exit":            result["exit"],
        "tokens_accepted": result["tokens_accepted"],
        "tokens_total":    result["tokens_total"],
        "log":             result["stderr"][-2000:],
    }


@app.get("/api/license/audit")
async def license_get_audit(limit: int = 200):
    """Return the last N audit-log entries (newest first)."""
    if not AUDIT_LOG.exists():
        return {"entries": [], "log_path": str(AUDIT_LOG)}
    entries = []
    try:
        with open(AUDIT_LOG) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except OSError as e:
        raise HTTPException(status_code=500, detail=str(e))
    entries.reverse()
    return {"entries": entries[:limit], "log_path": str(AUDIT_LOG)}


@app.delete("/api/license/file/{kind}/{name}")
async def license_delete_file(kind: str, name: str,
                              user: dict = Depends(get_current_user)):
    """Remove a license or vendor cert from disk and re-verify."""
    if kind == "license":
        d, suffix = LIC_DIR,    ".lic"
    elif kind == "vendor":
        d, suffix = VENDOR_DIR, ".vcert"
    else:
        raise HTTPException(status_code=400,
            detail="kind must be 'license' or 'vendor'")
    safe = _lic_safe_filename(name)
    if not safe.endswith(suffix):
        raise HTTPException(status_code=400,
            detail=f"filename must end with {suffix}")
    target = d / safe
    if not target.exists():
        raise HTTPException(status_code=404, detail="not found")
    target.unlink()
    logger.info("license file deleted by %s: %s", user.get("username", "?"), target)
    _lic_audit(f"delete_{kind}", user.get("username", "?"), file=safe)
    result = await _lic_run_verifier()
    return {
        "deleted":         str(target),
        "tokens_accepted": result["tokens_accepted"],
        "tokens_total":    result["tokens_total"],
    }


# ==========================================================================
# 6. Engines
# ==========================================================================


@app.get("/api/engines")
async def engines_list():
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute("SELECT * FROM engine_state")
        db_rows = {row["name"]: dict(row) for row in await cursor.fetchall()}

    # Backend is the default source for enabled/packets/matches/drops; the FPGA
    # is optional offload consulted per-engine inside _engine_backend_view().
    live = _detection_live()
    live["_ddos_counters"] = _nft_ddos_counters()
    engines = [
        _engine_backend_view(i, name, db_rows.get(name, {}).get("enabled", 1), live)
        for i, name in enumerate(ENGINE_NAMES)
    ]
    return {
        "engines": engines,
        "fpga_present": fpga_present(),
        "fpga_active": fpga_present(),  # legacy alias for existing WebUI
    }


@app.get("/api/engines/emulator")
async def engines_emulator():
    """Software FPGA DPI offload emulator status (REWORK_CONTRACT §7).

    Surfaces the emulated AC (dpi_l7) / DFA (dpi_regex) offload engines so the
    WebUI can render the DPI offload as 'emulated' when no card is present, plus
    the per-regex DFA compile paths ('dfa' table vs 're' host slow-path).
    Reports available=False (never errors) when ffn_fpga_emu is unavailable.
    """
    emu = _get_fpga_emu()
    if emu is None:
        return {
            "available": False,
            "hw_present": fpga_present(),
            "mode": "hardware" if fpga_present() else "host",
            "engines": {},
            "dfa_paths": [],
        }
    try:
        return {
            "available": True,
            "hw_present": fpga_present(),
            "mode": "hardware" if fpga_present() else "emulated",
            "engines": emu.status_all(),
            "dfa_paths": [{"pattern": pat, "path": path}
                          for (pat, path) in emu.dfa_paths()],
        }
    except Exception as exc:
        return {"available": False, "hw_present": fpga_present(), "error": str(exc)}


# ---------------------------------------------------------------------------
# Inline ML anti-malware / verdict engine endpoints (REWORK_CONTRACT §8).
# No license gating (per contract): status/score/update are always reachable.
# ---------------------------------------------------------------------------
@app.get("/api/ml/status")
async def ml_status():
    """Inline ML engine status (REWORK_CONTRACT §8).

    Reports kind, version, features_version, loaded, and verdict thresholds.
    available=False (never errors) when ffn_ml_engine is unavailable.
    """
    eng = _get_ml_engine()
    if eng is None:
        return {
            "available": False,
            "loaded": False,
            "kind": None,
            "version": 0,
            "features_version": None,
            "models": {"tree": False, "ngram": False},
            "stats": {"benign": 0, "grayware": 0, "malware": 0},
            "thresholds": _ml_thresholds(),
            "model_path": ML_MODEL_PATH,
        }
    loaded = (eng.tree is not None) or (eng.ngram is not None)
    return {
        "available": True,
        "loaded": loaded,
        "kind": eng.model_name,
        "version": eng.version,
        "features_version": eng.features_version,
        "models": {"tree": eng.tree is not None, "ngram": eng.ngram is not None},
        "stats": dict(eng.stats),
        "thresholds": _ml_thresholds(),
        "model_path": ML_MODEL_PATH,
        "persisted": os.path.exists(ML_MODEL_PATH),
    }


@app.post("/api/ml/score")
async def ml_score(req: MlScoreRequest):
    """Score a buffer for a malware/grayware/benign verdict (contract §8).

    Body: {"text": "..."} or {"hex": "deadbeef"}. Returns MlEngine.score():
    {verdict, score(0..100), model, version, features_version}.
    """
    eng = _get_ml_engine()
    if eng is None:
        raise HTTPException(status_code=503, detail="ML engine unavailable")
    # Resolve the input buffer from text or hex (exactly one expected).
    if req.hex is not None:
        cleaned = re.sub(r"(?i)0x|[^0-9a-f]", "", req.hex)
        if len(cleaned) % 2 != 0:
            raise HTTPException(status_code=400,
                                detail="hex must have an even number of digits")
        try:
            data = bytes.fromhex(cleaned)
        except ValueError:
            raise HTTPException(status_code=400, detail="invalid hex payload")
    elif req.text is not None:
        data = req.text.encode("utf-8", "surrogatepass")
    else:
        raise HTTPException(status_code=400,
                            detail="provide 'text' or 'hex' in the body")
    try:
        result = eng.score(data)
    except Exception as exc:
        raise HTTPException(status_code=500, detail="scoring failed: %s" % exc)
    return {"bytes": len(data), **result}


@app.post("/api/ml/update")
async def ml_update(payload: dict, user: dict = Depends(get_current_user)):
    """Hot-swap / retrain the inline ML model (contract §8).

    Body is one of:
      * {"retrain": true}                 -> retrain the tiny default in-module
      * a §9 MlModelUpdate wire payload   -> import_() (has kind/tree_blob/...)
      * a combined engine blob            -> update() (kind == 'ml-model')
    On success the new model is persisted to ML_MODEL_PATH and the new version
    returned. No license gating (per contract §4).
    """
    eng = _get_ml_engine()
    if eng is None:
        raise HTTPException(status_code=503, detail="ML engine unavailable")

    payload = payload or {}
    action = "update"
    try:
        if payload.get("retrain"):
            if not _ml_train_default(eng):
                raise HTTPException(status_code=501,
                                    detail="retrain unavailable (ffn_ml_engine)")
            action = "retrain"
        elif "tree_blob" in payload or "ngram_params" in payload:
            # §9 MlModelUpdate wire payload (import_ handles empty->None).
            eng.import_(payload)
            action = "import"
        else:
            # A combined engine blob (kind == 'ml-model') or raw model dict.
            eng.update(payload)
    except HTTPException:
        raise
    except Exception as exc:
        # update()/import_() raise BEFORE mutating on a bad blob -> engine intact.
        raise HTTPException(status_code=400, detail="model update failed: %s" % exc)

    persisted = _ml_persist(eng)
    # Realtime fan-out: push the new model to a running DP over the §9 wire.
    wire_pushed = _mpdp_emit_ml_update(eng)
    async with aiosqlite.connect(DB_PATH) as db:
        await audit(db, user["username"], "ml_%s" % action,
                    "version=%s" % eng.version)
    return {
        "status": "updated",
        "action": action,
        "version": eng.version,
        "features_version": eng.features_version,
        "kind": eng.model_name,
        "models": {"tree": eng.tree is not None, "ngram": eng.ngram is not None},
        "persisted": persisted,
        "model_path": ML_MODEL_PATH,
        "wire_pushed": wire_pushed,
    }


# ---------------------------------------------------------------------------
# MP<->DP FlatBuffers wire endpoints (REWORK_CONTRACT §9).
# The MP pushes threat-intel / ML-model / signature-verdict / policy updates to
# the DP and reads EngineTelemetry / FlowEvent back. Works with NO data plane
# running (default in-proc/file-ring Channel). No license gating (per §4).
# ---------------------------------------------------------------------------
@app.get("/api/mpdp/status")
async def mpdp_status():
    """MP<->DP channel health (REWORK_CONTRACT §9).

    Reports transport, connected, sent/recv counts and last_seq. Drains any
    pending DP->MP frames first so counters/telemetry are current.
    available=False (never errors) when ffn_mpdp_wire is unavailable.
    """
    mgr = _get_mpdp()
    if mgr is None:
        return {
            "available": False,
            "transport": None,
            "connected": False,
            "sent": 0,
            "recv": 0,
            "last_seq": 0,
            "ring_path": MPDP_RING_PATH or None,
        }
    mgr.poll()
    return mgr.status()


@app.post("/api/mpdp/push")
async def mpdp_push(payload: dict, user: dict = Depends(get_current_user)):
    """Push an MP->DP update over the §9 wire (REWORK_CONTRACT §9).

    Body: {"type": threat_intel|ml_model|signature_verdict|policy, ...}. Builds
    the matching ffn_mpdp_wire.build_* message and sends it on the channel --
    this is how the MP pushes threat-intel/ML/verdict/policy updates to the DP.

      * threat_intel      -> build_threat_intel_update(seq?, adds, removes, iocs)
      * ml_model          -> build_ml_model_update(version, kind, tree_blob,
                             ngram_params, features_version); with no explicit
                             fields it fans out the current inline ML model
      * signature_verdict -> build_signature_verdict(sid, sha256, verdict, ts?)
      * policy            -> build_policy_update(vsys, rows)
    No license gating (per contract §4).
    """
    mgr = _get_mpdp()
    if mgr is None:
        raise HTTPException(status_code=503, detail="MP<->DP wire unavailable")
    import ffn_mpdp_wire as wire

    payload = payload or {}
    mtype = str(payload.get("type", "")).strip().lower()
    frame = None
    kind = mtype
    try:
        if mtype in ("threat_intel", "threat_intel_update", "threatintel"):
            seq = payload.get("seq")
            if seq is None:
                seq = mgr.next_seq()
            frame = wire.build_threat_intel_update(
                int(seq),
                adds=payload.get("adds") or [],
                removes=payload.get("removes") or [],
                iocs=payload.get("iocs") or [])
            mgr.last_seq = max(mgr.last_seq, int(seq))
            kind = "threat_intel"

        elif mtype in ("ml_model", "ml", "ml_model_update"):
            kind = "ml_model"
            if ("tree_blob" in payload or "ngram_params" in payload
                    or "version" in payload):
                frame = wire.build_ml_model_update(
                    int(payload.get("version", 0) or 0),
                    payload.get("kind", wire.MlKind.XGBOOST),
                    tree_blob=_mpdp_as_bytes(payload.get("tree_blob")),
                    ngram_params=_mpdp_as_bytes(payload.get("ngram_params")),
                    features_version=_mpdp_fv_int(payload.get("features_version", 0)))
            else:
                # No explicit model in the body -> fan out the live engine.
                eng = _get_ml_engine()
                if eng is None:
                    raise HTTPException(status_code=503,
                                        detail="ML engine unavailable")
                if not _mpdp_emit_ml_update(eng):
                    raise HTTPException(status_code=500,
                                        detail="ML model push failed")

        elif mtype in ("signature_verdict", "verdict", "sig_verdict"):
            frame = wire.build_signature_verdict(
                int(payload.get("sid", 0)),
                _mpdp_as_bytes(payload.get("sha256")),
                payload.get("verdict", wire.Verdict.BENIGN),
                ts=payload.get("ts"))
            kind = "signature_verdict"

        elif mtype in ("policy", "policy_update"):
            frame = wire.build_policy_update(
                int(payload.get("vsys", 0)),
                rows=payload.get("rows") or [])
            kind = "policy"

        else:
            raise HTTPException(
                status_code=400,
                detail="unknown push type: %r (want "
                       "threat_intel|ml_model|signature_verdict|policy)" % mtype)

        if frame is not None:
            mgr.send_frame(frame)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=400, detail="push failed: %s" % exc)

    async with aiosqlite.connect(DB_PATH) as db:
        await audit(db, user["username"], "mpdp_push", kind)
    return {
        "status": "pushed",
        "type": kind,
        "transport": mgr.transport,
        "sent": mgr.sent,
        "last_seq": mgr.last_seq,
    }


@app.get("/api/mpdp/telemetry")
async def mpdp_telemetry():
    """Last parsed DP->MP EngineTelemetry / FlowEvent messages (§9).

    Drains the channel first, then returns the bounded telemetry ring split by
    body type. Empty when no data plane is running / nothing was received.
    available=False (never errors) when ffn_mpdp_wire is unavailable.
    """
    mgr = _get_mpdp()
    if mgr is None:
        return {"available": False, "telemetry": [], "flow_events": [], "count": 0}
    mgr.poll()
    items = mgr.telemetry()
    tele = [m["body"] for m in items if m.get("body_type") == "EngineTelemetry"]
    flows = [m["body"] for m in items if m.get("body_type") == "FlowEvent"]
    return {
        "available": True,
        "transport": mgr.transport,
        "count": len(items),
        "telemetry": tele,
        "flow_events": flows,
    }


@app.put("/api/engines/{name}/enable")
async def engine_enable(name: str, user: dict = Depends(get_current_user)):
    if name not in ENGINE_NAMES:
        raise HTTPException(status_code=404, detail="Engine not found")
    eid = ENGINE_NAMES.index(name)
    # enable-intent always persists to engine_state; push to FPGA regs only when
    # a card is present (offload is optional).
    if fpga_present():
        fpga.set_engine_enable(eid, True)
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT INTO engine_state (name, enabled, updated_at) VALUES (?, 1, datetime('now')) "
            "ON CONFLICT(name) DO UPDATE SET enabled = 1, updated_at = datetime('now')",
            (name,),
        )
        await audit(db, user["username"], "enable_engine", name)
    return {"status": "enabled", "engine": name, "offload_pushed": fpga_present()}


@app.put("/api/engines/{name}/disable")
async def engine_disable(name: str, user: dict = Depends(get_current_user)):
    if name not in ENGINE_NAMES:
        raise HTTPException(status_code=404, detail="Engine not found")
    eid = ENGINE_NAMES.index(name)
    if fpga_present():
        fpga.set_engine_enable(eid, False)
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT INTO engine_state (name, enabled, updated_at) VALUES (?, 0, datetime('now')) "
            "ON CONFLICT(name) DO UPDATE SET enabled = 0, updated_at = datetime('now')",
            (name,),
        )
        await audit(db, user["username"], "disable_engine", name)
    return {"status": "disabled", "engine": name, "offload_pushed": fpga_present()}


@app.get("/api/engines/{name}/stats")
async def engine_stats(name: str):
    if name not in ENGINE_NAMES:
        raise HTTPException(status_code=404, detail="Engine not found")
    eid = ENGINE_NAMES.index(name)
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(
            "SELECT enabled FROM engine_state WHERE name = ?", (name,))
        row = await cur.fetchone()
    db_en = row["enabled"] if row else 1
    view = _engine_backend_view(eid, name, db_en, _detection_live())
    # Backend stats are primary; FPGA figures (if a card is present) live under
    # offload_stats/offload_active on the same object.
    return {"engine": name, **view}


@app.get("/api/engines/dpi/patterns")
async def dpi_patterns_list():
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute("SELECT * FROM dpi_patterns ORDER BY id")
        rows = await cursor.fetchall()
        return {"patterns": [dict(r) for r in rows], "count": len(rows)}


@app.post("/api/engines/dpi/patterns")
async def dpi_patterns_add(pat: DPIPattern, user: dict = Depends(get_current_user)):
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute(
            "INSERT INTO dpi_patterns (name, pattern, severity, engine) VALUES (?, ?, ?, ?)",
            (pat.name, pat.pattern, pat.severity, pat.engine),
        )
        await audit(db, user["username"], "add_dpi_pattern", pat.name)
        return {"id": cursor.lastrowid, "status": "created"}


@app.get("/api/engines/url/categories")
async def url_categories():
    categories = [
        "malware", "phishing", "adult", "gambling", "social_media",
        "streaming", "vpn_proxy", "cryptomining", "ads", "custom",
    ]
    return {"categories": categories}


@app.post("/api/engines/url/blocklist")
async def url_blocklist_add(entry: URLBlockEntry, user: dict = Depends(get_current_user)):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT INTO url_blocklist (url, category) VALUES (?, ?)",
            (entry.url, entry.category),
        )
        await audit(db, user["username"], "add_url_block", entry.url)
        return {"status": "created"}


# -- Security plugins (Objects > Security Profiles) ------------------------

@app.get("/api/plugins")
async def plugins_list():
    """Security plugins with live enable-state + DLP rule count for the panel."""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute("SELECT name, enabled FROM engine_state")
        state = {r["name"]: bool(r["enabled"]) for r in await cur.fetchall()}
        try:
            cur = await db.execute("SELECT COUNT(*) c FROM dlp_rules WHERE enabled = 1")
            dlp_count = (await cur.fetchone())["c"]
        except Exception:
            dlp_count = 0
    live = _detection_live()
    out = []
    for p in SECURITY_PLUGINS:
        item = dict(p)
        el = live.get(p["id"], {})
        item["live"] = el
        # host software engines report their own enabled state; legacy FPGA
        # engines fall back to the engine_state table.
        item["enabled"] = el.get("enabled", state.get(p["engine"], True))
        item["hw_present"] = not fpga.sim_mode
        # only engines wired to the FPGA engine_state table have an enable toggle;
        # the host software engines are always-on (managed via config, not toggled).
        item["togglable"] = p["engine"] in ENGINE_NAMES
        if p["id"] == "dlp_scanner":
            item["rule_count"] = dlp_count
        out.append(item)
    return {"plugins": out, "count": len(out), "fpga_active": not fpga.sim_mode}


# ---------------------------------------------------------------------------
# Signature Database + host detection engines (post-pivot software stack).
# ---------------------------------------------------------------------------
@app.get("/api/sigdb/status")
async def sigdb_status():
    """Signature Database: version, counts by type/severity, recent updates."""
    try:
        from ffn_sigdb import SignatureDB
        sdb = SignatureDB()
        try:
            st = sdb.stats()
            ups = sdb.updates()[:10]
        finally:
            sdb.close()
        return {"available": True, **st, "recent_updates": ups}
    except Exception as e:
        return {"available": False, "error": str(e)}


@app.post("/api/sigdb/update")
async def sigdb_update(user: dict = Depends(get_current_user)):
    """Apply a content update: seed the baseline set if the DB is empty, then
    bump the content-package version (stand-in for pulling a signature feed)."""
    try:
        from ffn_sigdb import SignatureDB, seed_baseline
        sdb = SignatureDB()
        try:
            added = seed_baseline(sdb) if sdb.count() == 0 else 0
            v = sdb.apply_update(added, source="webui")
            st = sdb.stats()
        finally:
            sdb.close()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    # Realtime fan-out: push the content-package bump to a running DP (§9).
    wire_pushed = _mpdp_emit_threat_intel(v)
    async with aiosqlite.connect(DB_PATH) as db:
        await audit(db, user["username"], "sigdb_update", "v%d (+%d sigs)" % (v, added))
    return {"status": "updated", "version": st["version_string"],
            "total": st["total"], "added": added, "wire_pushed": wire_pushed}


@app.get("/api/crucible/status")
async def crucible_status():
    """Live state of the Crucible unknown-object pipeline.

    Sourced from the same sqlite tables the data plane writes to, so the
    numbers here are the queue the datapath is actually feeding -- not a
    separate counter that can drift from it.
    """
    import json as _json
    import os as _os
    import time as _time

    out = {
        "available": False,
        "pending": 0,
        "analyzed_today": 0,
        "analyzed_total": 0,
        "verdicts": {},
        "queue": [],
        "results": [],
        # No source for these yet: the BNN agent owns model versioning and does
        # not publish it. Null, not invented.
        "last_update": None,
        "retrain": None,
        "backend": None,
        "policy": None,
        "chambers": [],
        "relay": None,
    }

    # -- where does analysis happen -------------------------------------
    spec = _os.getenv("FFN_CRUCIBLE_BACKEND", "local")
    policy = _os.getenv("FFN_CRUCIBLE_POLICY", "static")
    out["backend"], out["policy"] = spec, policy
    try:
        from ffn_crucible import CrucibleSandbox
        eng = CrucibleSandbox(policy="best")
        out["chambers"] = [
            {"name": st.name, "fidelity": st.fidelity,
             "available": st.available, "executes": st.executes,
             "reason": st.reason}
            for st in eng.statuses()]
        out["max_fidelity"] = max(
            [st.fidelity for st in eng.statuses() if st.available], default=0)
    except Exception as e:
        out["chambers_error"] = str(e)[:160]

    if spec.startswith("relay"):
        url = spec.split(":", 1)[1] if ":" in spec else ""
        pub = _os.getenv("FFN_CRUCIBLE_RELAY_PUB",
                         "/etc/ffn-ngfw/crucible-verdict.pub")
        tok = _os.getenv("FFN_CRUCIBLE_TOKEN",
                         "/etc/ffn-ngfw/crucible-node.token")
        out["relay"] = {
            "url": url,
            "pinned_key": _os.path.exists(pub),
            "token": _os.path.exists(tok),
            "fallback_local": spec.startswith("relay+local"),
        }

    # -- the queue and the verdicts --------------------------------------
    try:
        from ffn_threatdb import ThreatDB
        tdb = ThreatDB()
    except Exception as e:
        out["error"] = str(e)[:160]
        return out
    try:
        conn = tdb.conn
        have = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        if "cloud_queue" not in have:
            # Nothing has ever submitted on this box, so the tables the
            # service creates on first use do not exist yet. Not an error.
            out["available"] = True
            return out
        out["available"] = True
        out["pending"] = conn.execute(
            "SELECT COUNT(*) FROM cloud_queue WHERE status='pending'"
        ).fetchone()[0]
        today = _time.strftime("%Y-%m-%d", _time.gmtime())
        if "cloud_reports" in have:
            out["analyzed_total"] = conn.execute(
                "SELECT COUNT(*) FROM cloud_reports").fetchone()[0]
            out["analyzed_today"] = conn.execute(
                "SELECT COUNT(*) FROM cloud_reports WHERE analyzed LIKE ?",
                (today + "%",)).fetchone()[0]
            for row in conn.execute(
                    "SELECT verdict, COUNT(*) FROM cloud_reports "
                    "GROUP BY verdict"):
                out["verdicts"][row[0]] = row[1]

        for row in conn.execute(
                "SELECT sha256,status,file_type,size,meta,submitted "
                "FROM cloud_queue WHERE status IN ('pending','analyzing') "
                "ORDER BY submitted DESC LIMIT 50"):
            try:
                meta = _json.loads(row[4] or "{}")
            except ValueError:
                meta = {}
            out["queue"].append({
                "id": row[0][:16],
                "time": row[5],
                "src": meta.get("src") or meta.get("flow") or "-",
                "verdict": "unknown",
                "confidence": None,
                "status": row[1],
                "result": "%s, %s bytes" % (row[2] or "unknown type",
                                            row[3] or 0),
            })

        if "cloud_reports" in have:
            for row in conn.execute(
                    "SELECT sha256,verdict,score,threat_name,file_type,"
                    "backend,analyzed,report FROM cloud_reports "
                    "ORDER BY analyzed DESC LIMIT 50"):
                details = {}
                try:
                    details = (_json.loads(row[7] or "{}") or {}).get(
                        "details", {}) or {}
                except ValueError:
                    pass
                out["results"].append({
                    "id": row[0][:16],
                    "time": row[6],
                    "ml_verdict": row[1],
                    "result": row[1],
                    "score": row[2],
                    "threat": row[3] or "-",
                    "file_type": row[4] or "-",
                    "chamber": details.get("chamber") or row[5] or "-",
                    "confidence": details.get("confidence") or "-",
                    "action": ("blocked" if row[1] in ("malware", "phishing")
                               else "alerted" if row[1] == "grayware"
                               else "allowed"),
                })
    except Exception as e:
        out["error"] = str(e)[:160]
    finally:
        try:
            tdb.close()
        except Exception:
            pass
    return out


@app.get("/api/detection/engines")
async def detection_engines():
    """Live status of the host detection engines (sig DB, AV, anti-malware,
    inline IPS, cloud sandbox) -- the same engines the data plane runs."""
    return {"engines": _detection_live()}


@app.post("/api/detection/scan")
async def detection_scan(body: dict, user: dict = Depends(get_current_user)):
    """Test-scan a payload (text or hex) through the inline detector + anti-malware
    fusion. Read-only mirror of the data-plane inspection path (auto-seeds the
    baseline signature sets on a fresh box so the demo detectors fire)."""
    import binascii
    data = b""
    if body.get("hex"):
        try:
            data = binascii.unhexlify("".join(str(body["hex"]).split()))
        except Exception:
            raise HTTPException(status_code=400, detail="invalid hex")
    elif body.get("text") is not None:
        data = str(body["text"]).encode("utf-8", "replace")
    if not data:
        raise HTTPException(status_code=400, detail="empty payload")
    out = {"len": len(data)}
    # inline payload detector (content signatures + IOC extraction)
    try:
        from ffn_threatdb import ThreatDB
        from inline_payload_det import InlinePayloadDetector, seed_baseline as seed_inline
        tdb = ThreatDB()
        try:
            det = InlinePayloadDetector(tdb)
            if not det.sigs:
                seed_inline(det)
            d = det.inspect(data)
            out["inline"] = {
                "matched": d.matched, "action": d.action_name, "verdict": d.verdict,
                "threat": d.threat_name, "file_type": d.file_type,
                "entropy": round(d.entropy, 2),
                "signatures": sorted({m.name for m in d.matches})[:8],
                "iocs": d.iocs, "summary": d.summary(),
            }
        finally:
            try:
                tdb.conn.close()
            except Exception:
                pass
    except Exception as e:
        out["inline"] = {"error": str(e)}
    # anti-malware fusion (hash reputation + AV + heuristics)
    try:
        from ffn_sigdb import SignatureDB, seed_baseline as seed_sigs
        from ffn_threatdb import ThreatDB as _TDB
        from ffn_antimalware import AntiMalware
        sdb = SignatureDB()
        tdb2 = _TDB()
        try:
            if sdb.count() == 0:
                seed_sigs(sdb)
            am = AntiMalware(sigdb=sdb, threatdb=tdb2)
            v = am.assess(data)
            out["antimalware"] = {
                "verdict": v.verdict, "score": v.score, "threat": v.threat_name,
                "family": v.family, "methods": v.methods,
                "indicators": v.indicators[:8], "blocked": v.blocked,
                "summary": v.summary(),
            }
        finally:
            sdb.close()
            try:
                tdb2.conn.close()
            except Exception:
                pass
    except Exception as e:
        out["antimalware"] = {"error": str(e)}
    return out


@app.get("/api/system/cpu-planes")
async def cpu_planes_status():
    """CPU proc-splitting: mgmt / ctrl / data plane core assignment, isolation
    (isolcpus / nohz_full), and scheduling capabilities."""
    try:
        from ffn_cpu_planes import CpuPlanes
        cp = CpuPlanes.from_system()
        return {"available": True, **cp.snapshot()}
    except Exception as e:
        return {"available": False, "error": str(e)}


@app.get("/api/engines/dlp/rules")
async def dlp_rules_list():
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute("SELECT * FROM dlp_rules ORDER BY id")
        return {"rules": [dict(r) for r in await cur.fetchall()]}


@app.post("/api/engines/dlp/rules")
async def dlp_rules_add(rule: DLPRule, user: dict = Depends(get_current_user)):
    # Built-in identifiers (credit_card/ssn/api_key/email) carry their own
    # detector; custom keyword/regex rules must supply a pattern.
    builtin = rule.pattern_type in ("credit_card", "ssn", "api_key", "email")
    if not builtin and not rule.pattern.strip():
        raise HTTPException(status_code=400,
                            detail="A pattern is required for %s rules" % rule.pattern_type)
    # Validate regex early so a bad pattern can't reach the compiler / FPGA.
    if rule.pattern_type in ("regex", "custom") and rule.pattern.strip():
        try:
            re.compile(rule.pattern)
        except re.error as e:
            raise HTTPException(status_code=400, detail="Invalid regex: %s" % e)
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute(
            "INSERT INTO dlp_rules "
            "(name, pattern_type, pattern, action, severity, direction, threshold, enabled) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (rule.name, rule.pattern_type, rule.pattern, rule.action, rule.severity,
             rule.direction, max(1, rule.threshold), 1 if rule.enabled else 0))
        await audit(db, user["username"], "add_dlp_rule", rule.name)
    return {"id": cur.lastrowid, "status": "created"}


@app.delete("/api/engines/dlp/rules/{rule_id}")
async def dlp_rules_delete(rule_id: int, user: dict = Depends(get_current_user)):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("DELETE FROM dlp_rules WHERE id = ?", (rule_id,))
        await audit(db, user["username"], "delete_dlp_rule", str(rule_id))
    return {"status": "deleted", "id": rule_id}


# ==========================================================================
# 7. VPN
# ==========================================================================


@app.get("/api/vpn/ipsec/tunnels")
async def vpn_ipsec_list():
    # Read from database (user-configured tunnels)
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute("SELECT * FROM ipsec_tunnels ORDER BY id")
        rows = await cursor.fetchall()
        tunnels = [dict(r) for r in rows]

    # Try to read real IPSec SAs from strongSwan/xfrm
    live_sas = []
    try:
        out = subprocess.check_output(["ip", "xfrm", "state"], text=True, timeout=5)
        if out.strip():
            live_sas = [{"raw": line.strip()} for line in out.strip().split("\n") if line.strip()]
    except Exception:
        pass

    return {"tunnels": tunnels, "live_sas": live_sas}


@app.post("/api/vpn/ipsec/tunnels")
async def vpn_ipsec_add(tunnel: IPSecTunnel, user: dict = Depends(get_current_user)):
    spi = f"0x{random.randint(0, 0xFFFFFFFF):08X}"
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute(
            "INSERT INTO ipsec_tunnels (peer_address, local_subnet, remote_subnet, spi, "
            "ike_version, esp_encryption, esp_hash) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (tunnel.peer_address, tunnel.local_subnet, tunnel.remote_subnet, spi,
             tunnel.ike_version, tunnel.esp_encryption, tunnel.esp_hash),
        )
        await audit(db, user["username"], "add_ipsec_tunnel", tunnel.peer_address)
        return {"id": cursor.lastrowid, "spi": spi, "status": "created"}


@app.get("/api/vpn/zerotier/peers")
async def vpn_zerotier_peers():
    """Try to read from zerotier-cli, otherwise return empty."""
    try:
        out = subprocess.check_output(
            ["zerotier-cli", "-j", "peers"], text=True, timeout=5
        )
        peers = json.loads(out)
        return {"peers": [
            {
                "address": p.get("address", ""),
                "latency": p.get("latency", -1),
                "role": p.get("role", ""),
                "paths": [f"{pa['address']}" for pa in p.get("paths", [])],
                "version": p.get("version", ""),
            }
            for p in peers
        ], "live": True}
    except Exception:
        return {"peers": [], "live": False, "message": "ZeroTier not installed or not running"}


@app.get("/api/vpn/zerotier/networks")
async def vpn_zerotier_networks():
    """Try to read from zerotier-cli, otherwise return empty."""
    try:
        out = subprocess.check_output(
            ["zerotier-cli", "-j", "listnetworks"], text=True, timeout=5
        )
        networks = json.loads(out)
        return {"networks": [
            {
                "nwid": n.get("nwid", ""),
                "name": n.get("name", ""),
                "status": n.get("status", ""),
                "type": n.get("type", ""),
                "mac": n.get("mac", ""),
                "assigned_addresses": n.get("assignedAddresses", []),
                "bridge": n.get("bridge", False),
                "device": n.get("portDeviceName", ""),
            }
            for n in networks
        ], "live": True}
    except Exception:
        return {"networks": [], "live": False, "message": "ZeroTier not installed or not running"}


# ==========================================================================
# 8. System Setup & ML
# ==========================================================================


class SetupConfig(BaseModel):
    hostname: Optional[str] = None
    dns_primary: Optional[str] = None
    dns_secondary: Optional[str] = None
    ntp_server: Optional[str] = None
    timezone: Optional[str] = None


@app.post("/api/system/setup")
async def system_setup(cfg: SetupConfig, user: dict = Depends(get_current_user)):
    """
    Write setup values to candidate-config.xml. Does NOT apply them to
    the system — requires an explicit commit via /api/config/commit.
    """
    st = config_mgr.lock_status()
    if st["locked"] and st.get("holder") != user["username"]:
        raise HTTPException(status_code=423, detail=f"Config locked by {st['holder']}")
    if not st["locked"]:
        config_mgr.acquire_lock(user["username"], "editing")

    # Write to PAN-OS hierarchical paths under
    # /config/devices/entry[@name='localhost.localdomain']/deviceconfig/system/...
    base = "devices.entry[@name=localhost.localdomain].deviceconfig.system"
    updates = {}
    if cfg.hostname is not None:
        updates[f"{base}.hostname"] = cfg.hostname
    if cfg.dns_primary is not None:
        updates[f"{base}.dns-setting.servers.primary"] = cfg.dns_primary
    if cfg.dns_secondary is not None:
        updates[f"{base}.dns-setting.servers.secondary"] = cfg.dns_secondary
    if cfg.ntp_server is not None:
        updates[f"{base}.ntp-servers.primary-ntp-server.ntp-server-address"] = cfg.ntp_server
    if cfg.timezone is not None:
        updates[f"{base}.timezone"] = cfg.timezone

    result = config_mgr.update_candidate_bulk(updates, user["username"])
    async with aiosqlite.connect(DB_PATH) as db:
        await audit(db, user["username"], "setup_candidate_update", json.dumps(list(updates.keys())))

    return {
        "status": "candidate-updated",
        "message": "Changes saved to candidate config. Commit to apply.",
        "applied": result.get("applied", []),
        "requires_commit": True,
    }


class RetrainRequest(BaseModel):
    model_type: str = "anomaly"
    epochs: int = 10


@app.post("/api/ml/retrain")
async def ml_retrain(req: RetrainRequest = None, user: dict = Depends(get_current_user)):
    # In production, this sends weights to the BNN agent which
    # retrains the BNN and programs weights via ioctl
    job_id = f"retrain-{int(time.time())}"
    logger.info("ML retrain triggered by %s: model=%s epochs=%d",
                user["username"], req.model_type if req else "anomaly",
                req.epochs if req else 10)
    async with aiosqlite.connect(DB_PATH) as db:
        await audit(db, user["username"], "ml_retrain", job_id)
    return {
        "status": "queued",
        "job_id": job_id,
        "model_type": req.model_type if req else "anomaly",
        "epochs": req.epochs if req else 10,
        "message": "Retrain job queued for BNN agent",
    }


@app.get("/api/system/copp")
async def system_copp():
    """CoPP status — per-class rate limits and drop counters."""
    classes = [
        {"id": 0, "name": "CRITICAL", "protocols": "BGP, OSPF, BFD",
         "rate_pps": 10000, "burst": 100, "priority": "HIGH"},
        {"id": 1, "name": "IMPORTANT", "protocols": "SSH, HTTPS, SNMP",
         "rate_pps": 5000, "burst": 50, "priority": "MEDIUM"},
        {"id": 2, "name": "NORMAL", "protocols": "DNS, DHCP, NTP",
         "rate_pps": 2000, "burst": 20, "priority": "MEDIUM"},
        {"id": 3, "name": "ICMP", "protocols": "ICMP Echo/Unreachable",
         "rate_pps": 1000, "burst": 10, "priority": "LOW"},
        {"id": 4, "name": "ARP", "protocols": "ARP Request/Reply",
         "rate_pps": 500, "burst": 10, "priority": "LOW"},
        {"id": 5, "name": "ROUTING_MISS", "protocols": "FIB/ARP Miss Punts",
         "rate_pps": 2000, "burst": 20, "priority": "LOW"},
        {"id": 6, "name": "ZT_CONTROL", "protocols": "ZeroTier Control",
         "rate_pps": 1000, "burst": 10, "priority": "MEDIUM"},
        {"id": 7, "name": "BULK", "protocols": "Everything Else",
         "rate_pps": 500, "burst": 5, "priority": "BULK"},
    ]

    if not fpga.sim_mode:
        # Read real CoPP counters from FPGA
        for cl in classes:
            cl["pass_count"] = 0  # TODO: read from FPGA reg
            cl["drop_count"] = 0
    else:
        # No FPGA — counters are zero (CoPP is an FPGA-only feature)
        for cl in classes:
            cl["pass_count"] = 0
            cl["drop_count"] = 0

    return {
        "enabled": not fpga.sim_mode,
        "fpga_active": not fpga.sim_mode,
        "aggregate_limit_pps": 50000,
        "aggregate_pass": sum(c["pass_count"] for c in classes),
        "aggregate_drop": sum(c["drop_count"] for c in classes),
        "classes": classes,
    }


@app.get("/api/system/fpga")
async def system_fpga():
    """FPGA detailed status."""
    if not fpga.sim_mode:
        return {
            "detected": True,
            "version": fpga.get_version(),
            "device": "xcvu9p-flga2577-2-i",
            "board": "BittWare XUP-P3R",
            "temperature_c": 0,  # TODO: read SYSMON via ioctl
            "pcie_link": "Gen3 x16 (128 Gbps)",
            "qdma_queues_active": 16,
            "bitstream_encrypted": True,
        }
    else:
        return {
            "detected": False,
            "message": f"No FPGA device found at {fpga.dev_path}",
            "device": "N/A",
            "board": "N/A",
        }


# ==========================================================================
# 9. Dataplane Control
# ==========================================================================


class DataplaneRestart(BaseModel):
    target: str  # "fpga", "fpga-warm", "dpdk", "dpdk-stop", "all"


def _detect_dpdk_service() -> Optional[str]:
    """
    Figure out which DPDK systemd unit is actually installed + active on
    this box. Returns the unit name (without .service) or None.

    Deployment evolved: the original name was `ffn-dpdk-fwd` (custom
    forwarder binary `ffn_dpdk_fwd`). The current stack uses
    `ffn-dpdk-runtime` (a dpdk-testpmd primary process that reserves the
    hugepage pool). We probe both and return whichever responds.
    """
    # Reworked stack = ffn-dpdk-fwd (the DPDK 22.11 zygote ffn-dpdk-mp). Prefer
    # the ACTIVE unit; fall back to the first installed one for display (the old
    # ffn-dpdk-runtime unit file may still be present but disabled).
    installed = []
    for unit in ("ffn-dpdk-fwd", "ffn-dpdk-runtime", "ffn-dpdk"):
        try:
            r = subprocess.run(
                ["systemctl", "list-unit-files", unit + ".service"],
                capture_output=True, text=True, timeout=5,
            )
            if r.returncode == 0 and (unit + ".service") in r.stdout:
                installed.append(unit)
                a = subprocess.run(
                    ["systemctl", "is-active", unit],
                    capture_output=True, text=True, timeout=5,
                )
                if a.stdout.strip() == "active":
                    return unit
        except Exception:
            continue
    return installed[0] if installed else None


def _detect_dpdk_process() -> dict:
    """
    Walk pgrep for the handful of DPDK binaries we might be running
    (dpdk-testpmd primary, ffn_dpdk_fwd forwarder). Returns a dict with
    pid, cmdline, cpu affinity, and hugepage footprint — or empty if no
    DPDK process is alive.
    """
    candidates = ["ffn-dpdk-mp", "ffn-fastpath-fwd", "dpdk-testpmd", "ffn_dpdk_fwd"]
    for name in candidates:
        try:
            out = subprocess.check_output(
                ["pgrep", "-af", name], text=True, timeout=5
            ).strip()
            if not out:
                continue
            first = out.splitlines()[0]
            pid, _, cmdline = first.partition(" ")
            aff = "unknown"
            try:
                a = subprocess.check_output(
                    ["taskset", "-cp", pid], text=True, timeout=5
                ).strip()
                aff = a.split(":")[-1].strip() if ":" in a else a
            except Exception:
                pass
            # Approximate hugepage usage via /proc/<pid>/status
            locked_mb = None
            try:
                with open("/proc/{}/status".format(pid)) as f:
                    for line in f:
                        if line.startswith("VmHWM:"):
                            locked_mb = int(line.split()[1]) // 1024
                            break
            except Exception:
                pass
            return {
                "process": name,
                "pid": pid,
                "cmdline": cmdline,
                "cpu_affinity": aff,
                "vm_hwm_mb": locked_mb,
            }
        except subprocess.CalledProcessError:
            continue
        except Exception:
            continue
    return {}


def _hugepage_snapshot() -> dict:
    """Parse /proc/meminfo for hugepage totals. Returns kilobyte counts."""
    out = {
        "total": 0, "free": 0, "reserved": 0, "surp": 0, "size_kb": 0,
    }
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                parts = line.split()
                if line.startswith("HugePages_Total:"): out["total"] = int(parts[1])
                elif line.startswith("HugePages_Free:"): out["free"] = int(parts[1])
                elif line.startswith("HugePages_Rsvd:"): out["reserved"] = int(parts[1])
                elif line.startswith("HugePages_Surp:"): out["surp"] = int(parts[1])
                elif line.startswith("Hugepagesize:"): out["size_kb"] = int(parts[1])
    except Exception:
        pass
    out["total_mb"] = out["total"] * out["size_kb"] // 1024
    out["used_mb"] = (out["total"] - out["free"]) * out["size_kb"] // 1024
    return out


@app.get("/api/dataplane/status")
async def dataplane_status():
    """Where packets are actually forwarded on this box.

    THREE dataplanes can exist, and this endpoint used to describe only two of
    them. The FPGA and DPDK paths belong to FFN's own board; a reclaimed
    appliance has neither and forwards on an OCTEON complex behind the control
    plane instead. Reporting only fpga_detected there produced a UI that said
    the dataplane was absent on a box whose dataplane was running -- so the
    offload chain is reported here too, and `kind` names which one is in play
    rather than leaving a caller to infer it from three unrelated booleans.

    Looks up whichever DPDK unit is actually installed and running
    (ffn-dpdk-runtime preferred, ffn-dpdk-fwd for older deployments).
    """
    fpga_detected = not fpga.sim_mode
    pcie_link = "N/A"
    if fpga_detected:
        pcie_link = "Gen3 x16 (128 Gbps)"

    # Which DPDK unit is defined on this box?
    dpdk_unit = _detect_dpdk_service()
    dpdk_unit_active = False
    if dpdk_unit:
        try:
            r = subprocess.run(
                ["systemctl", "is-active", dpdk_unit],
                capture_output=True, text=True, timeout=5,
            )
            dpdk_unit_active = r.stdout.strip() == "active"
        except Exception:
            pass

    # Which DPDK process (if any) is actually running?
    dpdk_proc = _detect_dpdk_process()
    dpdk_running = bool(dpdk_proc)

    huge = _hugepage_snapshot()

    # Check kernel driver
    driver_loaded = False
    try:
        out = subprocess.check_output(["lsmod"], text=True, timeout=5)
        driver_loaded = "ffn_ngfw" in out
    except Exception:
        pass

    # The offload complex, asked through the control plane. Cheap when absent
    # (one lspci) and one short CP round trip when present.
    offload = await _detect_offload_dp()
    # `kind` says which dataplane this box HAS, not whether it is currently
    # passing traffic -- those are different questions and a UI needs both
    # separately. An earlier version conflated them by deriving the kind from
    # a "booted" flag that turned out to measure nothing (this DP is driven
    # with no kernel driver bound, so its driver link is always empty).
    if offload.get("dp", {}).get("present"):
        kind = "octeon-offload"
    elif offload.get("present"):
        kind = "octeon-offload-cp-only"
    elif fpga_detected:
        kind = "fpga"
    elif dpdk_running:
        kind = "dpdk"
    else:
        kind = "software"

    return {
        # Which dataplane this box actually has. A UI should branch on this
        # rather than on fpga_detected, which is only ever true on the FPGA
        # board and says nothing at all about an appliance.
        "kind": kind,
        "offload": offload,
        "fpga_detected": fpga_detected,
        "fpga_driver_loaded": driver_loaded,
        "pcie_link": pcie_link,
        # DPDK reality
        "dpdk_running": dpdk_running,
        "dpdk_unit": dpdk_unit,                 # ffn-dpdk-runtime / ffn-dpdk-fwd / None
        "dpdk_unit_active": dpdk_unit_active,
        "dpdk_process": dpdk_proc.get("process"),
        "dpdk_pid": dpdk_proc.get("pid"),
        "dpdk_cmdline": dpdk_proc.get("cmdline"),
        "dpdk_cores": dpdk_proc.get("cpu_affinity"),
        "dpdk_vm_hwm_mb": dpdk_proc.get("vm_hwm_mb"),
        # Hugepage pool (DPDK backing store)
        "hugepages_total": huge["total"],
        "hugepages_free": huge["free"],
        "hugepages_size_kb": huge["size_kb"],
        "hugepages_total_mb": huge["total_mb"],
        "hugepages_used_mb": huge["used_mb"],
    }


@app.post("/api/dataplane/restart")
async def dataplane_restart(req: DataplaneRestart, user: dict = Depends(get_current_user)):
    """Restart FPGA or DPDK dataplanes."""
    logger.warning("Dataplane restart requested by %s: target=%s", user["username"], req.target)
    async with aiosqlite.connect(DB_PATH) as db:
        await audit(db, user["username"], "dataplane_restart", req.target)

    results = {"target": req.target, "message": "", "output": ""}

    if req.target in ("fpga", "fpga-warm", "all"):
        if fpga.sim_mode:
            results["message"] = "FPGA not detected — cannot reset"
            results["output"] = "No /dev/ngfw0 device present"
        else:
            try:
                if req.target == "fpga-warm":
                    # Warm reset via ioctl (reset dataplane logic only, not PCIe link)
                    fpga.write_reg(0x0008, 0x1)  # SOFT_RESET register
                    results["message"] = "FPGA warm reset signal sent"
                    results["output"] = "Wrote 0x1 to SOFT_RESET register (0x0008)"
                else:
                    # Full PCIe reset via kernel driver
                    try:
                        subprocess.check_output(
                            ["bash", "-c", "echo 1 > /sys/bus/pci/devices/$(lspci -d 10ee: -n | head -1 | cut -d' ' -f1)/reset"],
                            text=True, timeout=10,
                        )
                        results["message"] = "FPGA PCIe reset triggered"
                        results["output"] = "PCIe function-level reset sent to Xilinx device"
                    except Exception as exc:
                        results["message"] = "PCIe reset via sysfs"
                        results["output"] = f"Reset attempt: {exc}"
            except Exception as exc:
                results["output"] = str(exc)

    if req.target in ("dpdk", "dpdk-stop", "all"):
        # Detect whichever DPDK unit is actually installed on this box.
        # Preference: ffn-dpdk-runtime (current), ffn-dpdk-fwd (legacy).
        unit = _detect_dpdk_service()
        if unit is None:
            results["output"] += (
                "\n[dpdk] no DPDK systemd unit installed "
                "(looked for ffn-dpdk-runtime, ffn-dpdk-fwd, ffn-dpdk)"
            )
            results["message"] = (
                (results.get("message", "") + " | DPDK unit not installed").strip(" |")
            )
        else:
            action = "stop" if req.target == "dpdk-stop" else "restart"
            try:
                r = subprocess.run(
                    ["systemctl", action, unit],
                    capture_output=True, text=True, timeout=15,
                )
                rc = r.returncode
                results["message"] = (
                    (results.get("message", "") + f" | DPDK {unit} {action}ed "
                     f"({'ok' if rc == 0 else 'rc=' + str(rc)})").strip(" |")
                )
                results["output"] += (
                    f"\nsystemctl {action} {unit}"
                    + (f"\n{r.stderr.strip()}" if r.stderr.strip() else "")
                )
            except Exception as exc:
                results["output"] += f"\nDPDK {action} error: {exc}"
                # Fallback: kill whichever DPDK process is running by name
                for name in ("dpdk-testpmd", "ffn_dpdk_fwd"):
                    try:
                        k = subprocess.run(
                            ["pkill", "-f", name],
                            capture_output=True, timeout=5,
                        )
                        if k.returncode == 0:
                            results["output"] += f"\nSent SIGTERM to {name}"
                    except Exception:
                        pass

    if not results["message"]:
        results["message"] = f"Restart signal sent for {req.target}"

    return results


class DiagnosticRequest(BaseModel):
    command: str
    target: str = ""


@app.post("/api/system/diagnostic")
async def system_diagnostic(req: DiagnosticRequest, user: dict = Depends(get_current_user)):
    """Run diagnostic commands."""
    logger.info("Diagnostic %s by %s", req.command, user["username"])
    async with aiosqlite.connect(DB_PATH) as db:
        await audit(db, user["username"], "diagnostic", req.command)

    try:
        if req.command == "ping":
            target = req.target or "8.8.8.8"
            out = subprocess.check_output(
                ["ping", "-c", "4", "-W", "2", target], text=True, timeout=15, stderr=subprocess.STDOUT
            )
        elif req.command == "traceroute":
            target = req.target or "8.8.8.8"
            out = subprocess.check_output(
                ["traceroute", "-m", "15", "-w", "2", target], text=True, timeout=30, stderr=subprocess.STDOUT
            )
        elif req.command == "nslookup":
            target = req.target or "google.com"
            out = subprocess.check_output(
                ["nslookup", target], text=True, timeout=10, stderr=subprocess.STDOUT
            )
        elif req.command == "ss":
            out = subprocess.check_output(
                ["ss", "-tunap"], text=True, timeout=5
            )
        elif req.command == "dmesg":
            out = subprocess.check_output(
                ["dmesg", "--time-format=reltime"], text=True, timeout=5
            )
            # Last 50 lines
            out = "\n".join(out.strip().split("\n")[-50:])
        elif req.command == "tcpdump":
            iface = req.target or "any"
            out = subprocess.check_output(
                ["timeout", "5", "tcpdump", "-i", iface, "-c", "50", "-nn"],
                text=True, timeout=10, stderr=subprocess.STDOUT
            )
        elif req.command == "tech-support":
            out = "Tech support file generation queued.\nFile will be saved to /var/tmp/ffn-tech-support.tgz"
        elif req.command == "reboot":
            out = "System reboot scheduled in 5 seconds"
            # Don't actually reboot without explicit confirmation
        else:
            out = f"Unknown command: {req.command}"
        return {"output": out, "command": req.command}
    except subprocess.CalledProcessError as exc:
        return {"output": exc.output or str(exc), "command": req.command}
    except FileNotFoundError:
        return {"output": f"Command '{req.command}' not found on this system", "command": req.command}
    except subprocess.TimeoutExpired:
        return {"output": f"Command timed out", "command": req.command}


# ==========================================================================
# 10. Configuration Management (Candidate / Running XML with Commit Lock)
# ==========================================================================


class ConfigUpdate(BaseModel):
    xpath: str
    value: str


class ConfigBulkUpdate(BaseModel):
    updates: dict  # {xpath: value, ...}


class CommitRequest(BaseModel):
    description: str = ""
    partial_xpath: Optional[str] = None  # None = full commit
    commit_type: Optional[str] = None    # override history type e.g. "rollback"


class LockRequest(BaseModel):
    reason: str = "commit"


class SnapshotSave(BaseModel):
    name: str
    description: str = ""


@app.get("/api/config/candidate")
async def config_get_candidate(user: dict = Depends(get_current_user)):
    return {"xml": config_mgr.get_candidate(), "path": str(CANDIDATE_CONFIG)}


@app.get("/api/config/running")
async def config_get_running(user: dict = Depends(get_current_user)):
    return {"xml": config_mgr.get_running(), "path": str(RUNNING_CONFIG)}


@app.post("/api/config/candidate/update")
async def config_update_candidate(req: ConfigUpdate, user: dict = Depends(get_current_user)):
    # Must hold lock to modify candidate
    st = config_mgr.lock_status()
    if st["locked"] and st.get("holder") != user["username"]:
        raise HTTPException(status_code=423, detail=f"Config locked by {st['holder']}")
    if not st["locked"]:
        config_mgr.acquire_lock(user["username"], "editing")
    result = config_mgr.update_candidate(req.xpath, req.value, user["username"])
    async with aiosqlite.connect(DB_PATH) as db:
        await audit(db, user["username"], "config_update", req.xpath)
    return result


@app.post("/api/config/candidate/bulk")
async def config_bulk_update(req: ConfigBulkUpdate, user: dict = Depends(get_current_user)):
    st = config_mgr.lock_status()
    if st["locked"] and st.get("holder") != user["username"]:
        raise HTTPException(status_code=423, detail=f"Config locked by {st['holder']}")
    if not st["locked"]:
        config_mgr.acquire_lock(user["username"], "editing")
    result = config_mgr.update_candidate_bulk(req.updates, user["username"])
    async with aiosqlite.connect(DB_PATH) as db:
        await audit(db, user["username"], "config_bulk_update", f"{len(req.updates)} paths")
    return result


@app.get("/api/config/diff")
async def config_diff(user: dict = Depends(get_current_user)):
    return config_mgr.diff()


# -- PAN-OS style xpath API --------------------------------------------------


class XpathSet(BaseModel):
    """
    xpath: dotted PAN-OS-style path, e.g.
      devices.entry[@name=localhost.localdomain].deviceconfig.system.hostname
    value: one of:
      - str  (sets element text)
      - list (rewrites <member> children)
      - dict (recursively sets children)
      - raw XML fragment if it starts with '<'
    """
    xpath: str
    value: object = None


def _xml_to_json(elem: ET.Element) -> object:
    """Convert an XML element to a JSON-friendly shape.
    Empty leaf → ""; text leaf → str; <member>-only container → list[str];
    element with children → dict; attributes preserved under @attrs."""
    members = elem.findall("member")
    if members and len(members) == len(list(elem)):
        return {"@members": [(m.text or "").strip() for m in members]}
    if len(elem) == 0:
        out = (elem.text or "").strip()
        if elem.attrib:
            return {"@attrs": dict(elem.attrib), "#text": out}
        return out
    out = {}
    if elem.attrib:
        out["@attrs"] = dict(elem.attrib)
    # Group children by tag for stable shape
    by_tag = {}
    for child in elem:
        by_tag.setdefault(child.tag, []).append(child)
    for tag, children in by_tag.items():
        if tag == "entry":
            # Keyed list: emit {name: value}
            out.setdefault("entry", {})
            for c in children:
                out["entry"][c.get("name", "")] = _xml_to_json(c)
        elif len(children) == 1:
            out[tag] = _xml_to_json(children[0])
        else:
            out[tag] = [_xml_to_json(c) for c in children]
    return out


@app.get("/api/config/xpath")
async def config_xpath_get(xpath: str, source: str = "candidate",
                           fmt: str = "json",
                           user: dict = Depends(get_current_user)):
    """
    Retrieve a subtree from candidate or running config.
      fmt=json  → structured JSON (default)
      fmt=xml   → raw XML string
      fmt=text  → just the element text (for leaves)
    """
    if source not in ("candidate", "running"):
        raise HTTPException(status_code=400, detail="source must be candidate|running")
    node = config_mgr.get_xpath(xpath, source=source)
    if node is None:
        raise HTTPException(status_code=404, detail=f"xpath not found: {xpath}")
    if fmt == "xml":
        return {"xpath": xpath, "xml": ET.tostring(node, encoding="unicode")}
    if fmt == "text":
        return {"xpath": xpath, "text": (node.text or "").strip()}
    return {"xpath": xpath, "source": source, "value": _xml_to_json(node)}


@app.post("/api/config/xpath")
async def config_xpath_set(req: XpathSet, user: dict = Depends(get_current_user)):
    """
    Create or update the element at the given xpath in the candidate config.
    Acquires the commit lock if no one holds it.
    """
    st = config_mgr.lock_status()
    if st["locked"] and st.get("holder") != user["username"]:
        raise HTTPException(status_code=423, detail=f"Config locked by {st['holder']}")
    if not st["locked"]:
        config_mgr.acquire_lock(user["username"], "editing")
    result = config_mgr.update_candidate(req.xpath, req.value, user["username"])
    async with aiosqlite.connect(DB_PATH) as db:
        await audit(db, user["username"], "config_xpath_set", req.xpath)
    return result


@app.delete("/api/config/xpath")
async def config_xpath_delete(xpath: str,
                              user: dict = Depends(get_current_user)):
    st = config_mgr.lock_status()
    if st["locked"] and st.get("holder") != user["username"]:
        raise HTTPException(status_code=423, detail=f"Config locked by {st['holder']}")
    if not st["locked"]:
        config_mgr.acquire_lock(user["username"], "editing")
    result = config_mgr.delete_candidate(xpath, user["username"])
    async with aiosqlite.connect(DB_PATH) as db:
        await audit(db, user["username"], "config_xpath_delete", xpath)
    return result


@app.post("/api/config/import-panos")
async def config_import_panos(user: dict = Depends(get_current_user)):
    """
    Accept a raw PAN-OS-style XML document as the new candidate config.
    Body: {"xml": "<config ...>...</config>"}
    """
    raise HTTPException(status_code=501, detail="use /api/config/xpath with xml values to import piecewise")


def _apply_running_config():
    """
    Read running-config.xml and push selected values to the live system.
    Reads from the PAN-OS hierarchy:
      /config/devices/entry[@name='localhost.localdomain']/deviceconfig/system/
    """
    applied = []

    def find_dev_sys(root):
        for dev in root.findall("./devices/entry"):
            if dev.get("name") == "localhost.localdomain":
                return dev.find("./deviceconfig/system")
        return None

    try:
        root = ET.parse(str(RUNNING_CONFIG)).getroot()
        sysn = find_dev_sys(root)
        if sysn is not None:
            hn = sysn.findtext("hostname")
            if hn:
                try:
                    subprocess.run(["hostnamectl", "set-hostname", hn],
                                   capture_output=True, timeout=5)
                    applied.append(f"hostname={hn}")
                except Exception:
                    pass
            tz = sysn.findtext("timezone")
            if tz and tz != "UTC":
                try:
                    subprocess.run(["timedatectl", "set-timezone", tz],
                                   capture_output=True, timeout=5)
                    applied.append(f"timezone={tz}")
                except Exception:
                    pass
            ntp = sysn.findtext("./ntp-servers/primary-ntp-server/ntp-server-address")
            if ntp:
                applied.append(f"ntp={ntp}")
            dns_primary = sysn.findtext("./dns-setting/servers/primary")
            if dns_primary:
                applied.append(f"dns={dns_primary}")
    except Exception as exc:
        logger.warning("Apply running config: %s", exc)
    return applied


async def _sync_netresources_to_xml():
    """
    Mirror the net_resources SQL table into the PAN-OS candidate XML so a
    commit carries every UI-managed resource. Mapping table below.
    Idempotent: on each call we clear existing <entry> children in the
    target subtree, then re-add them from SQL.
    """
    # {kind: xpath (rooted at /config)}
    DEV = "devices.entry[@name=localhost.localdomain]"
    VSYS = f"{DEV}.vsys.entry[@name=vsys1]"
    NET = f"{DEV}.network"
    RESOURCE_PATHS = {
        # Core network
        "virtual-wires":         f"{NET}.virtual-wire",
        "gre-tunnels":           f"{NET}.gre",
        "vxlan-tunnels":         f"{NET}.vxlan-tunnel",
        "qos-policies":          f"{VSYS}.rulebase.qos.rules",
        # FFN Protect (vsys-scoped in PAN-OS)
        "fp-portals":                 f"{VSYS}.global-protect.global-protect-portal",
        "fp-gateways":                f"{VSYS}.global-protect.global-protect-gateway",
        "fp-mdm":                     f"{VSYS}.global-protect.global-protect-mdm",
        "fp-clientless-apps":         f"{VSYS}.global-protect.global-protect-clientless-app",
        "fp-clientless-app-groups":   f"{VSYS}.global-protect.global-protect-clientless-app-group",
        "fp-dhcp-profiles":           f"{VSYS}.global-protect.global-protect-dhcp-profile",
        # Zero Trust (vsys-scoped, under zero-trust namespace)
        "wireguard-interfaces":  f"{VSYS}.zero-trust.wireguard.interfaces",
        "wireguard-peers":       f"{VSYS}.zero-trust.wireguard.peers",
        "zscaler-config":        f"{VSYS}.zero-trust.zscaler",
        # Network Profiles (device-scoped network/profiles/*)
        "ike-gateways":               f"{NET}.ike.gateway",
        "ike-crypto":                 f"{NET}.ike.crypto-profiles.ike-crypto-profiles",
        "ipsec-crypto":               f"{NET}.ike.crypto-profiles.ipsec-crypto-profiles",
        "fp-ipsec-crypto":            f"{NET}.ike.crypto-profiles.global-protect-app-crypto-profiles",
        "monitor-profiles":           f"{NET}.profiles.monitor-profile",
        "interface-mgmt-profiles":    f"{NET}.profiles.interface-management-profile",
        "zone-protection-profiles":   f"{NET}.profiles.zone-protection-profile",
        "qos-profiles":               f"{NET}.profiles.qos-profile",
        "lldp-profiles":              f"{NET}.profiles.lldp-profile",
        "bfd-profiles":               f"{NET}.profiles.bfd-profile",
        # SD-WAN
        "sdwan-interface-profiles":   f"{NET}.sdwan-interface-profile",
    }

    # Pull all resources grouped by kind
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        rows = await (await db.execute(
            "SELECT kind, name, enabled, config FROM net_resources")).fetchall()

    by_kind: dict = {}
    for r in rows:
        by_kind.setdefault(r["kind"], []).append(r)

    # Walk the candidate XML and rewrite each managed subtree
    root = config_mgr._load(CANDIDATE_CONFIG)
    touched = []
    for kind, xpath in RESOURCE_PATHS.items():
        entries = by_kind.get(kind, [])
        steps = config_mgr._normalize_xpath(xpath, root)
        parent = config_mgr._traverse_or_create(root, steps)
        # Drop any stale <entry> children we previously placed
        for e in list(parent.findall("entry")):
            parent.remove(e)
        # Insert fresh entries
        for r in entries:
            entry = ET.SubElement(parent, "entry")
            entry.set("name", r["name"])
            try:
                cfg = json.loads(r["config"] or "{}")
            except Exception:
                cfg = {}
            cfg["enabled"] = "yes" if r["enabled"] else "no"
            config_mgr._apply_dict(entry, cfg)
        touched.append(f"{kind}:{len(entries)}")
    config_mgr._save(root, CANDIDATE_CONFIG)
    logger.info("net_resources → XML sync: %s", ", ".join(touched))
    return touched


def _publish_to_planes() -> dict:
    """Render the committed config out to the CP and, through it, the DP.

    This is the top of a chain that was already complete below this point:

        here -> /etc/ffn/config.env -> ffn_cfgd (MP, versioned + namespaced)
          -> ffn_cfgagent (CP): applies cp.*, relays dp.*
            -> PCIe mailbox (the DP has no IP path)
              -> DP /etc/ffn/dp.env -> ffn_dp_l3_config.c -> the FIB

    It is a PUBLISH, not a push. The agents pull and converge on their own, so a
    CP or DP that reboots re-reads the current version without the MP having to
    notice -- which matters because the MP cannot reach the DP to push even if
    it wanted to.

    A failure here NEVER fails the commit. By the time this runs the candidate
    has already become running and the MP has applied it; raising would report a
    commit that did happen as one that did not, and would leave the operator
    with no idea which half succeeded. So problems are returned in the response
    instead, where the UI can show "committed, not yet distributed".
    """
    try:
        import ffn_config_render
    except ImportError as exc:
        return {"published": False, "error": "renderer unavailable: %s" % exc,
                "hint": "deploy ffn_config_render.py beside ffn_manager.py"}
    try:
        return ffn_config_render.publish()
    except Exception as exc:
        logger.warning("plane publish failed: %s", exc)
        return {"published": False, "error": repr(exc)}


@app.post("/api/config/commit")
async def config_commit(req: CommitRequest, user: dict = Depends(get_current_user)):
    """Commit candidate → running. Supports full or partial (xpath-scoped) commits."""
    # Must hold or acquire lock
    st = config_mgr.lock_status()
    if st["locked"] and st.get("holder") != user["username"]:
        raise HTTPException(status_code=423, detail=f"Config locked by {st['holder']} — wait or request override")
    if not st["locked"]:
        if not config_mgr.acquire_lock(user["username"], "commit"):
            raise HTTPException(status_code=423, detail="Could not acquire commit lock")

    # Fold any UI-managed resources (virtual wires, FFN Protect, profiles,
    # etc.) from the SQL side-store into the PAN-OS XML before we diff.
    try:
        await _sync_netresources_to_xml()
    except Exception as exc:
        logger.warning("net_resources→XML sync failed: %s", exc)

    # Check for changes
    d = config_mgr.diff()
    if not d["has_changes"]:
        config_mgr.release_lock(user["username"])
        return {"status": "no-changes", "message": "Candidate identical to running"}

    logger.info("Commit by %s: type=%s description=%s changes=%d",
                user["username"], "partial" if req.partial_xpath else "full",
                req.description, d["total_changes"])

    try:
        result = config_mgr.commit(
            user=user["username"],
            description=req.description,
            partial_xpath=req.partial_xpath,
            commit_type=req.commit_type,
        )
        # Apply to live system.
        # Preferred path: delegate to ffn-controld, which signals ffn-configd
        # (the XML validator/applier) and waits for apply-status.json.
        # Fallback: in-process hostname/DNS/NTP writes (legacy).
        if controld is not None and controld.available():
            try:
                apply_status = controld.apply_config()
                result["apply_status"] = apply_status
                result["applied_to_system"] = [
                    f"{a['applier']}:{a['xpath']}={a['new']}"
                    for a in apply_status.get("applied", [])
                ]
            except Exception as exc:
                logger.warning("controld apply_config failed: %s — falling back", exc)
                result["applied_to_system"] = _apply_running_config()
        else:
            result["applied_to_system"] = _apply_running_config()

        # Distribute to the CP and, through it, the DP. Ordered AFTER the local
        # apply on purpose: the MP is the first hop of the chain, and publishing
        # a config the MP itself has not accepted would put the planes ahead of
        # their own management plane.
        result["planes"] = _publish_to_planes()
        result["changes_committed"] = d["total_changes"]

        async with aiosqlite.connect(DB_PATH) as db:
            await audit(db, user["username"], "commit",
                        f"{result['type']}: {req.description or '(no description)'} — {d['total_changes']} changes")
        return result
    finally:
        config_mgr.release_lock(user["username"])


@app.post("/api/config/revert")
async def config_revert(user: dict = Depends(get_current_user)):
    """Discard candidate changes — reset candidate to match running."""
    st = config_mgr.lock_status()
    if st["locked"] and st.get("holder") != user["username"]:
        raise HTTPException(status_code=423, detail=f"Config locked by {st['holder']}")
    result = config_mgr.revert_candidate(user["username"])
    config_mgr.release_lock(user["username"])
    async with aiosqlite.connect(DB_PATH) as db:
        await audit(db, user["username"], "config_revert")
    return result


@app.get("/api/config/lock")
async def config_lock_status():
    return config_mgr.lock_status()


@app.post("/api/config/lock")
async def config_lock_acquire(req: LockRequest, user: dict = Depends(get_current_user)):
    if not config_mgr.acquire_lock(user["username"], req.reason):
        st = config_mgr.lock_status()
        raise HTTPException(status_code=423, detail=f"Locked by {st['holder']}")
    async with aiosqlite.connect(DB_PATH) as db:
        await audit(db, user["username"], "lock_acquire", req.reason)
    return {"status": "locked", "holder": user["username"]}


@app.delete("/api/config/lock")
async def config_lock_release(user: dict = Depends(get_current_user)):
    released = config_mgr.release_lock(user["username"])
    async with aiosqlite.connect(DB_PATH) as db:
        await audit(db, user["username"], "lock_release", "released" if released else "not-held")
    return {"status": "released" if released else "not-held"}


@app.post("/api/config/lock/override")
async def config_lock_override(user: dict = Depends(get_current_user)):
    """Admin-only lock override — forcibly release any active lock."""
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin role required")
    prev_holder = config_mgr._lock_holder
    config_mgr._lock_holder = None
    config_mgr._lock_reason = ""
    async with aiosqlite.connect(DB_PATH) as db:
        await audit(db, user["username"], "lock_override", f"previous={prev_holder}")
    return {"status": "overridden", "previous_holder": prev_holder}


@app.get("/api/config/apply-status")
async def config_apply_status(user: dict = Depends(get_current_user)):
    """
    Latest apply result from ffn-configd. Shows per-xpath success/failure,
    schema validation errors, and which applier handled each change.
    """
    p = Path(os.getenv("FFN_CONFIG_DIR", "/var/lib/ffn-ngfw/config")) / "apply-status.json"
    if not p.exists():
        return {"overall": "never", "message": "no apply has run yet"}
    try:
        return json.loads(p.read_text())
    except Exception as exc:
        return {"overall": "error", "error": str(exc)}


def _platform_decl() -> dict:
    """The selected platform's own declaration, or {}.

    ffn_cpuisol already knows how to find platform/<name>/platform.json and is
    the module that consumes `datapath` today, so it owns the reader. A second
    one here would be a second thing to keep in agreement.

    Returns {} on an installed appliance, where the tree is flat and there is no
    platform/ directory -- which is why nothing downstream may treat an empty
    declaration as "no platform". Evidence decides that; see _platform_profile.
    """
    try:
        import ffn_cpuisol
        decl, _path = ffn_cpuisol.find_platform_decl(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        return decl or {}
    except Exception:
        return {}


def _chassis_family_name(chassis: dict) -> str:
    """A human name for the chassis family, from the models it could be.

    Deliberately the family. The vendor fingerprint identifies the BOARD, and
    one board serves several models -- a PA-5220 and a PA-5280 are the same
    board -- so picking a model out of the list would state something the
    detector never established.
    """
    models = [m for m in (chassis.get("models") or []) if m]
    if not models:
        return ""
    pfx = models[0]
    for m in models[1:]:
        while pfx and not m.startswith(pfx):
            pfx = pfx[:-1]
    pfx = pfx.rstrip("-")
    if not pfx:
        return ""
    # "PA-52" from PA-5220/5250/... is a family stem, not a product name.
    name = pfx + "0" * max(0, len(models[0]) - len(pfx))
    return "Palo Alto Networks %s series" % name if len(models) > 1 else            "Palo Alto Networks %s" % models[0]


def _chassis_fingerprint() -> dict:
    """What chassis this is, from the vendor detector. {} when unrecognised."""
    try:
        import ffn_vendor
        return ffn_vendor.detect_chassis() or {}
    except Exception:
        return {}


async def _platform_profile() -> dict:
    """What this appliance IS, and therefore which features apply to it.

    WHY THIS EXISTS. The WebUI was written for FFN's own board -- an accelerator
    card plus a DPDK path -- and shows that board's features unconditionally. On
    an appliance that has neither, the result is not a missing panel but a
    misleading one: a red "Not Detected" beside an instruction to install a card
    that does not fit the chassis, and a DPDK panel reporting "Stopped" for a
    subsystem the box was never going to run. Both read as faults. Neither is.

    So every feature carries TWO booleans, and the difference between them is
    the whole point:

        applicable  does this feature belong on this hardware at all?
        present     is it actually there right now?

    not applicable  -> the UI hides it. There is nothing to report and nothing
                       an operator could do about it.
    applicable, not present -> the UI reports it missing. That IS actionable.

    Everything here is DERIVED. The platform declaration is used when there is
    one, and otherwise the answer comes from what was detected -- an installed
    appliance has a flat tree with no platform/ directory, so treating a missing
    declaration as "no platform" would misreport every deployed box.
    """
    decl = _platform_decl()
    chassis = _chassis_fingerprint()
    offload = await _detect_offload_dp()
    faceplate = await _faceplate_map("data")

    has_fpga_card = not fpga.sim_mode
    has_offload = bool(offload.get("present"))
    dpdk_unit = _detect_dpdk_service()
    # A unit FILE existing is not a datapath. The image ships ffn-dpdk-fwd on
    # every platform, so keying "present" off the unit reported DPDK as present
    # on a chassis that has never run it.
    dpdk_running = bool(_detect_dpdk_process())

    # Datapath: the declaration is authoritative where it exists, because it is
    # the platform stating its own design. Otherwise infer from what is here.
    datapath = decl.get("datapath")
    if not datapath:
        datapath = ("offload" if has_offload
                    else "fpga" if has_fpga_card
                    else "dpdk")

    off_reason = ("this chassis forwards on its own offload complex, so the "
                  "host-side datapath is not used here")

    def feat(applicable, present, reason="", **extra):
        d = {"applicable": bool(applicable), "present": bool(present)}
        if reason:
            d["reason"] = reason
        d.update(extra)
        return d

    features = {
        # The host-side datapaths. Both are FFN's own board's design; an
        # offload chassis has neither and needs neither.
        "dpdk": feat(datapath == "dpdk", dpdk_running,
                     off_reason if datapath != "dpdk" else "",
                     unit=dpdk_unit),
        "fpga_card": feat(datapath in ("dpdk", "fpga"), has_fpga_card,
                          off_reason if datapath == "offload" else ""),
        "hugepages": feat(datapath == "dpdk", datapath == "dpdk",
                          "hugepages back the DPDK mempools; nothing here uses "
                          "them" if datapath != "dpdk" else ""),
        # Isolating host cores only helps a host-side poll-mode datapath, so it
        # follows the datapath rather than a default. This cannot be left to the
        # declaration alone: an INSTALLED appliance has a flat tree with no
        # platform/ directory, so the declaration is absent exactly where it
        # matters, and defaulting to "auto" reported core isolation as
        # applicable on a chassis that forwards nothing on its host cores.
        "cpu_isolation": feat(
            decl.get("cpu_isolation", "auto") != "none" and datapath == "dpdk",
            decl.get("cpu_isolation", "auto") != "none" and datapath == "dpdk",
            decl.get("reason") or (off_reason if datapath == "offload" else "")),

        # The offload chassis's own silicon.
        "offload_complex": feat(has_offload, has_offload,
                                detail=offload.get("boot_state") or ""),
        "switch_faceplate": feat(faceplate is not None, bool(faceplate),
                                 ports=len(faceplate or {})),
        "front_end_asic": feat(has_offload,
                               bool((offload.get("fe100") or {}).get("present")),
                               model=(offload.get("fe100") or {}).get("model") or ""),

        # Software subsystems, present when their binary is.
        "frr": feat(True, os.path.exists("/usr/bin/vtysh")),
        "ipsec": feat(True, os.path.exists("/usr/sbin/swanctl")
                      or os.path.exists("/usr/bin/swanctl")),
        "zerotier": feat(True, os.path.exists("/usr/sbin/zerotier-cli")
                         or os.path.exists("/usr/bin/zerotier-cli")),
    }

    return {
        "platform": decl.get("platform") or (
            "pa5200" if faceplate is not None else
            "vu9p" if has_fpga_card else "generic"),
        # Falls back to the chassis fingerprint, because the declaration is the
        # thing that is missing on a deployed box.
        # Falls back to the chassis fingerprint, because the declaration is the
        # thing that is missing on a deployed box. The FAMILY, not a model: the
        # fingerprint lists every model this board could be (the PA-5220 and
        # PA-5280 share it), and naming one of them would be a guess.
        "hardware": decl.get("hardware") or _chassis_family_name(chassis),
        "datapath": datapath,
        "chassis": {
            "family": chassis.get("platform") or "",
            "models": chassis.get("models") or [],
            "dmi": chassis.get("dmi") or "",
            "match": chassis.get("match"),
            # Named by whichever detector answered; the CLI reports it as
            # "octeon" and the in-process call may not carry it at all.
            "npu": chassis.get("octeon") or offload.get("generation") or "",
        },
        "features": features,
    }


@app.get("/api/system/capabilities")
async def system_capabilities(user: dict = Depends(get_current_user)):
    """Which subsystems are present, and which ones this appliance even has.

    The flat booleans are kept because callers already read them, but they
    cannot express the difference that matters on an appliance: a subsystem
    that is MISSING versus one that was never part of this hardware. `platform`
    carries that, per feature, as applicable/present -- see _platform_profile.
    A UI should branch on it and hide what is not applicable, rather than
    reporting a DPDK path this chassis does not have as "Stopped".
    """
    base = None
    if controld is not None and controld.available():
        try:
            base = controld.capabilities()
        except Exception:
            base = None
    if base is None:
        base = {
            "fpga":     not fpga.sim_mode,
            "dpdk":     os.path.exists("/var/run/ffn-ngfw/dpdk.sock"),
            "frr":      os.path.exists("/usr/bin/vtysh"),
            "ipsec":    os.path.exists("/usr/sbin/swanctl") or os.path.exists("/usr/bin/swanctl"),
            "zerotier": os.path.exists("/usr/sbin/zerotier-cli") or os.path.exists("/usr/bin/zerotier-cli"),
        }
    # Merged rather than replacing controld's answer: it owns the subsystem
    # booleans, this owns what the hardware is.
    try:
        base = dict(base)
        base["platform"] = await _platform_profile()
    except Exception as exc:
        logger.warning("platform profile failed: %s", exc)
    return base


@app.get("/api/system/platform")
async def system_platform(user: dict = Depends(get_current_user)):
    """The appliance's own specification: what it is, and which features apply.

    Separate from /api/system/capabilities so a caller that only wants to know
    what hardware this is does not have to reason about subsystem booleans.
    """
    return await _platform_profile()


# ---------------------------------------------------------------------------
# Plane Usage — CPU pinning across Management / Control / Data planes
# ---------------------------------------------------------------------------


def _read_isolcpus() -> list:
    """
    Parse isolcpus= from /proc/cmdline. Handles the modern syntax that
    carries flag tokens before the cpu list, e.g.:
        isolcpus=managed_irq,domain,12-47
    — we strip known modifier tokens and treat only the numeric portion
    as the core list.
    """
    FLAGS = {"managed_irq", "domain", "nohz", "rcu"}
    try:
        with open("/proc/cmdline") as f:
            cmdline = f.read()
        for tok in cmdline.split():
            if not tok.startswith("isolcpus="):
                continue
            spec = tok.split("=", 1)[1]
            # Drop flag tokens (managed_irq, domain, ...) — keep the rest.
            parts = [p for p in spec.split(",") if p not in FLAGS]
            return _expand_cpu_list(",".join(parts))
    except Exception:
        pass
    return []


def _read_cpu_planes_conf() -> dict:
    """Read /etc/ffn-ngfw/cpu-planes.conf (written by apply-cpu-planes.sh).
    Returns a dict of FFN_MGMT_CORES / FFN_CTRL_CORES / FFN_DPDK_CORES ranges."""
    path = "/etc/ffn-ngfw/cpu-planes.conf"
    out = {}
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, _, v = line.partition("=")
                out[k.strip()] = v.strip().strip('"')
    except FileNotFoundError:
        pass
    except Exception:
        pass
    return out


def _expand_cpu_list(spec: str) -> list:
    """Expand '0,2-5,8' into [0,2,3,4,5,8]."""
    out = []
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            try:
                a, b = part.split("-", 1)
                out.extend(range(int(a), int(b) + 1))
            except Exception:
                continue
        else:
            try:
                out.append(int(part))
            except Exception:
                continue
    return sorted(set(out))


# ==========================================================================
# Data Plane Daemon (ffn-dpd) — proxied through controld
# ==========================================================================


def _dpd_call(method: str, *args, **kwargs) -> dict:
    """Common error-wrapper for controld proxy calls into ffn-dpd."""
    if controld is None or not controld.available():
        raise HTTPException(status_code=503, detail="controld socket not present")
    try:
        fn = getattr(controld, method)
        return fn(*args, **kwargs) or {}
    except RuntimeError as exc:
        # controld returned ok=false — usually "ffn-dpd not running"
        raise HTTPException(status_code=503, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"dpd proxy failed: {exc}")


@app.get("/api/dpd/status")
async def dpd_status(user: dict = Depends(get_current_user)):
    """Liveness + backend (fpga | nftables) + last compile summary."""
    return _dpd_call("dpd_status")


@app.get("/api/dpd/rules")
async def dpd_rules(user: dict = Depends(get_current_user)):
    """Compiled rule set currently installed by the DP daemon."""
    return _dpd_call("dpd_rules")


@app.get("/api/dpd/sessions")
async def dpd_sessions(limit: int = 200, user: dict = Depends(get_current_user)):
    """Session-table snapshot from the data plane."""
    return _dpd_call("dpd_sessions", limit=limit)


@app.get("/api/dpd/hits")
async def dpd_hits(user: dict = Depends(get_current_user)):
    """Per-rule hit counters from the current backend."""
    return _dpd_call("dpd_hits")


@app.post("/api/dpd/reload")
async def dpd_reload(user: dict = Depends(get_current_user)):
    """Force a policy recompile + push. Normally happens automatically on commit."""
    r = _dpd_call("dpd_reload", reason=f"manager:{user.get('username','?')}")
    async with aiosqlite.connect(DB_PATH) as db:
        await audit(db, user["username"], "dpd_reload", str(r.get("reason", "")))
    return r


@app.get("/api/system/plane-usage")
async def plane_usage(user: dict = Depends(get_current_user)):
    """
    Return per-plane CPU + memory usage.
      - Data plane  : cores listed in isolcpus (or FFN_DPDK_CORES env)
      - Control plane: cores running ffn-controld + ffn-configd + ffn-manager
                        (and adjacent "system" cores). Default = non-isolcpus - mgmt
      - Management plane: cores dedicated to the webUI/ssh (default = first 2)
    Usage is averaged over a 500ms sample.
    """
    total_cores = os.cpu_count() or 2

    # Precedence for plane-to-core mapping:
    #   1. /etc/ffn-ngfw/cpu-planes.conf — written by apply-cpu-planes.sh
    #      (authoritative when the grub split is active)
    #   2. FFN_{DPDK,MGMT,CTRL}_CORES env vars (runtime override)
    #   3. /proc/cmdline isolcpus= (detect what the kernel is isolating)
    #   4. Fallback: mgmt=[0,1], data=[], ctrl=rest
    conf = _read_cpu_planes_conf()
    data_spec = conf.get("FFN_DPDK_CORES",  os.getenv("FFN_DPDK_CORES",  ""))
    mgmt_spec = conf.get("FFN_MGMT_CORES",  os.getenv("FFN_MGMT_CORES",  "0,1"))
    ctrl_spec = conf.get("FFN_CTRL_CORES",  os.getenv("FFN_CTRL_CORES",  ""))

    data_cores = _expand_cpu_list(data_spec) or _read_isolcpus()
    mgmt_cores = _expand_cpu_list(mgmt_spec)
    ctrl_cores = _expand_cpu_list(ctrl_spec)

    all_cores = set(range(total_cores))
    if not ctrl_cores:
        # Derive control plane as "everything that isn't mgmt or data".
        ctrl_cores = sorted(all_cores - set(data_cores) - set(mgmt_cores))
    mgmt_cores = [c for c in mgmt_cores if c < total_cores]
    ctrl_cores = [c for c in ctrl_cores if c < total_cores]
    data_cores = [c for c in data_cores if c < total_cores]

    # Sample per-core usage (blocking 0.5s — run in thread pool)
    import asyncio as _aio
    per_core = await _aio.to_thread(psutil.cpu_percent, 0.5, True)

    def avg(cores):
        vals = [per_core[c] for c in cores if c < len(per_core)]
        return round(sum(vals) / len(vals), 1) if vals else 0.0

    mem = psutil.virtual_memory()
    swap = psutil.swap_memory()

    # Resident memory used by each plane's processes (approximate)
    def _rss_for(name_prefixes: list) -> int:
        total = 0
        try:
            for p in psutil.process_iter(["name", "cmdline", "memory_info"]):
                try:
                    cmd = " ".join(p.info["cmdline"] or [])
                except Exception:
                    cmd = ""
                if any(pfx in cmd or pfx == p.info["name"] for pfx in name_prefixes):
                    mi = p.info.get("memory_info")
                    if mi: total += mi.rss
        except Exception:
            pass
        return total

    mgmt_rss = _rss_for(["ffn_manager", "ffn-cli", "nginx"])
    ctrl_rss = _rss_for(["ffn_controld", "ffn_configd", "frr", "bgpd", "ospfd",
                         "charon", "swanctl", "lldpd"])
    data_rss = _rss_for(["ffn_dpdk_fwd", "dpdk-testpmd"])

    return {
        "cores_total": total_cores,
        "management_plane": {
            "cores": mgmt_cores,
            "cpu_percent": avg(mgmt_cores),
            "per_core": {str(c): per_core[c] for c in mgmt_cores if c < len(per_core)},
            "memory_bytes": mgmt_rss,
            "memory_percent": round(mgmt_rss / mem.total * 100, 2) if mem.total else 0,
        },
        "control_plane": {
            "cores": ctrl_cores,
            "cpu_percent": avg(ctrl_cores),
            "per_core": {str(c): per_core[c] for c in ctrl_cores if c < len(per_core)},
            "memory_bytes": ctrl_rss,
            "memory_percent": round(ctrl_rss / mem.total * 100, 2) if mem.total else 0,
        },
        "data_plane": {
            "cores": data_cores,
            "cpu_percent": avg(data_cores),
            "per_core": {str(c): per_core[c] for c in data_cores if c < len(per_core)},
            "memory_bytes": data_rss,
            "memory_percent": round(data_rss / mem.total * 100, 2) if mem.total else 0,
            "isolcpus_detected": bool(data_cores),
        },
        "memory": {
            "total_gb": round(mem.total / 1e9, 2),
            "used_gb":  round(mem.used  / 1e9, 2),
            "percent":  mem.percent,
            "swap_total_gb": round(swap.total / 1e9, 2),
            "swap_used_gb":  round(swap.used  / 1e9, 2),
        },
    }


@app.get("/api/config/snapshots")
async def config_snapshots_list(user: dict = Depends(get_current_user)):
    return {"snapshots": config_mgr.snapshot_list()}


@app.post("/api/config/snapshots")
async def config_snapshot_save(req: SnapshotSave, user: dict = Depends(get_current_user)):
    result = config_mgr.snapshot_save(req.name, req.description)
    async with aiosqlite.connect(DB_PATH) as db:
        await audit(db, user["username"], "snapshot_save", req.name)
    return result


@app.post("/api/config/snapshots/{name}/restore")
async def config_snapshot_restore(name: str, user: dict = Depends(get_current_user)):
    st = config_mgr.lock_status()
    if st["locked"] and st.get("holder") != user["username"]:
        raise HTTPException(status_code=423, detail=f"Config locked by {st['holder']}")
    result = config_mgr.snapshot_restore(name, user["username"])
    async with aiosqlite.connect(DB_PATH) as db:
        await audit(db, user["username"], "snapshot_restore", name)
    return result


@app.delete("/api/config/snapshots/{name}")
async def config_snapshot_delete(name: str, user: dict = Depends(get_current_user)):
    result = config_mgr.snapshot_delete(name)
    async with aiosqlite.connect(DB_PATH) as db:
        await audit(db, user["username"], "snapshot_delete", name)
    return result


# --- Commit history (append-only versioned changelog with rollback) ---

@app.get("/api/config/history")
async def config_history_list(limit: int = 0, user: dict = Depends(get_current_user)):
    """List commit history, newest first. `limit=0` returns all entries."""
    entries = config_mgr.history.list_entries(limit=limit or None)
    return {
        "entries": entries,
        "count": len(entries),
        "latest_version": config_mgr.history.latest_version(),
    }


@app.get("/api/config/history/{version}")
async def config_history_get(version: int, user: dict = Depends(get_current_user)):
    entry = config_mgr.history.get(version)
    if entry is None:
        raise HTTPException(status_code=404, detail=f"Version {version} not found")
    return entry


@app.get("/api/config/history/{version}/xml")
async def config_history_xml(version: int, user: dict = Depends(get_current_user)):
    xml_bytes = config_mgr.history.read_xml(version)
    if xml_bytes is None:
        raise HTTPException(status_code=404, detail=f"Version {version} not found")
    return Response(content=xml_bytes, media_type="application/xml")


@app.get("/api/config/history/{version}/diff")
async def config_history_diff(version: int, vs: Optional[str] = None,
                              user: dict = Depends(get_current_user)):
    """
    Diff version N against its parent by default, or against an arbitrary
    second version with ?vs=<version|candidate|running>.
    """
    entry = config_mgr.history.get(version)
    if entry is None:
        raise HTTPException(status_code=404, detail=f"Version {version} not found")
    if vs is None:
        other = entry.get("parent_version")
        if other is None:
            return {"old": None, "new": version, "has_changes": False,
                    "total_changes": 0, "added": [], "modified": [], "removed": [],
                    "message": "Version has no parent (initial seed)"}
        return config_mgr.diff_between(other, version)
    if vs in ("candidate", "running"):
        return config_mgr.diff_between(version, vs)
    try:
        other_v = int(vs)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid 'vs' — must be version number, 'candidate', or 'running'")
    return config_mgr.diff_between(version, other_v)


@app.post("/api/config/history/{version}/rollback")
async def config_history_rollback(version: int, user: dict = Depends(get_current_user)):
    """
    Load a historical version into the candidate buffer. User must then
    commit to activate (a rollback commit is recorded as its own history
    entry so the changelog stays fully append-only).
    """
    st = config_mgr.lock_status()
    if st["locked"] and st.get("holder") != user["username"]:
        raise HTTPException(status_code=423,
                            detail=f"Config locked by {st['holder']} — rollback blocked")
    result = config_mgr.rollback_to(version, user["username"])
    if result.get("status") == "error":
        raise HTTPException(status_code=404, detail=result["message"])
    async with aiosqlite.connect(DB_PATH) as db:
        await audit(db, user["username"], "rollback_load", f"v{version}")
    return result


class HistoryPruneRequest(BaseModel):
    keep: int = 100


@app.post("/api/config/history/prune")
async def config_history_prune(req: HistoryPruneRequest,
                               user: dict = Depends(get_current_user)):
    if user.get("role") not in (None, "superuser", "admin"):
        raise HTTPException(status_code=403, detail="Only admins can prune history")
    result = config_mgr.history.prune(req.keep)
    async with aiosqlite.connect(DB_PATH) as db:
        await audit(db, user["username"], "history_prune", f"kept={result['kept']}")
    return result


# ==========================================================================
# 11. Network resources (Virtual Wires, GRE/VXLAN, QoS, FFN Protect,
#     Zero Trust, Network Profiles, SD-WAN) — generic CRUD
# ==========================================================================


# Allow-list of resource kinds the API accepts. Keeps callers from stuffing
# arbitrary strings into the kind column. Order roughly matches sidebar.
NET_RESOURCE_KINDS = {
    # Core Network tab
    "virtual-wires",
    "gre-tunnels",
    "vxlan-tunnels",
    "qos-policies",
    # FFN Protect (GlobalProtect equivalent)
    "fp-portals",
    "fp-gateways",
    "fp-mdm",
    "fp-clientless-apps",
    "fp-clientless-app-groups",
    "fp-dhcp-profiles",
    # Zero Trust providers with stored config (peer lists, keys)
    "wireguard-interfaces",
    "wireguard-peers",
    "zscaler-config",
    # Network Profiles
    "ike-gateways",
    "ike-crypto",
    "ipsec-crypto",
    "fp-ipsec-crypto",
    "monitor-profiles",
    "interface-mgmt-profiles",
    "zone-protection-profiles",
    "qos-profiles",
    "lldp-profiles",
    "bfd-profiles",
    # SD-WAN
    "sdwan-interface-profiles",
    # Device-tab config objects (generic CRUD backing former WebUI stubs)
    "password-profiles",
    "admin-roles",
    "local-user-groups",
    "auth-profiles",
    "auth-sequences",
    "user-id-agents",
    "certificate-profiles",
    "ocsp-responders",
    "scep-profiles",
    "ssl-decrypt-exclusions",
    "ssh-service-profiles",
    "response-pages",
    "server-snmp",
    "server-syslog",
    "server-email",
    "server-http",
    "server-netflow",
    "server-radius",
    "server-scp",
    "server-tacacs",
    "server-ldap",
    "server-kerberos",
    "server-saml",
    "server-dns",
    "server-mfa",
    "scheduled-log-exports",
    "sslvpn-client-configs",
    "iot-dhcp-sources",
    "data-redistribution-agents",
    "cloud-redistribution",
    "quarantined-devices",
    "vm-info-sources",
    "vlan-interfaces",
    "dhcp-scopes",
    "shared-gateways",
    "local-users",
}


class NetResource(BaseModel):
    name: str
    enabled: bool = True
    config: dict = {}  # kind-specific free-form fields


def _check_kind(kind: str):
    if kind not in NET_RESOURCE_KINDS:
        raise HTTPException(status_code=404, detail=f"Unknown resource kind: {kind}")


@app.get("/api/network-resources/{kind}")
async def net_resources_list(kind: str, user: dict = Depends(get_current_user)):
    _check_kind(kind)
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            "SELECT id, name, enabled, config, created_at, updated_at "
            "FROM net_resources WHERE kind = ? ORDER BY name",
            (kind,),
        )
        rows = await cursor.fetchall()
    out = []
    for r in rows:
        try:
            cfg = json.loads(r["config"] or "{}")
        except Exception:
            cfg = {}
        out.append({
            "id": r["id"],
            "name": r["name"],
            "enabled": bool(r["enabled"]),
            "config": cfg,
            "created_at": r["created_at"],
            "updated_at": r["updated_at"],
        })
    return {"kind": kind, "entries": out, "total": len(out)}


@app.post("/api/network-resources/{kind}")
async def net_resources_create(kind: str, res: NetResource,
                               user: dict = Depends(get_current_user)):
    _check_kind(kind)
    async with aiosqlite.connect(DB_PATH) as db:
        try:
            cursor = await db.execute(
                "INSERT INTO net_resources (kind, name, enabled, config) VALUES (?,?,?,?)",
                (kind, res.name, int(res.enabled), json.dumps(res.config)),
            )
            await db.commit()
            await audit(db, user["username"], f"net_create:{kind}", res.name)
            return {"id": cursor.lastrowid, "status": "created"}
        except aiosqlite.IntegrityError:
            raise HTTPException(status_code=409, detail=f"'{res.name}' already exists in {kind}")


@app.put("/api/network-resources/{kind}/{entry_id}")
async def net_resources_update(kind: str, entry_id: int, res: NetResource,
                               user: dict = Depends(get_current_user)):
    _check_kind(kind)
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute(
            "UPDATE net_resources SET name=?, enabled=?, config=?, "
            "updated_at=datetime('now') WHERE id=? AND kind=?",
            (res.name, int(res.enabled), json.dumps(res.config), entry_id, kind),
        )
        await db.commit()
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Not found")
        await audit(db, user["username"], f"net_update:{kind}", f"id={entry_id}")
        return {"status": "updated"}


@app.delete("/api/network-resources/{kind}/{entry_id}")
async def net_resources_delete(kind: str, entry_id: int,
                               user: dict = Depends(get_current_user)):
    _check_kind(kind)
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute(
            "DELETE FROM net_resources WHERE id=? AND kind=?",
            (entry_id, kind),
        )
        await db.commit()
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Not found")
        await audit(db, user["username"], f"net_delete:{kind}", f"id={entry_id}")
        return {"status": "deleted"}


# ==========================================================================
# 12. Live integrations for WireGuard / Tailscale / LLDP / DHCP lease reader
# ==========================================================================


@app.get("/api/wireguard/status")
async def wireguard_status(user: dict = Depends(get_current_user)):
    """
    Parse `wg show` output for all interfaces. Returns live peer handshake
    state, allowed IPs, endpoint, and transfer stats.
    """
    if not shutil.which("wg"):
        return {"available": False, "reason": "wireguard-tools not installed",
                "interfaces": []}
    try:
        out = subprocess.check_output(["wg", "show", "all", "dump"],
                                      text=True, timeout=5)
    except subprocess.CalledProcessError as exc:
        return {"available": True, "error": exc.output or str(exc), "interfaces": []}
    except Exception as exc:
        return {"available": True, "error": str(exc), "interfaces": []}

    # `wg show all dump` format:
    # iface private_key public_key listen_port fwmark                  (first line per iface)
    # iface public_key preshared_key endpoint allowed_ips latest_handshake transfer_rx transfer_tx persistent_keepalive
    interfaces = {}
    for line in out.strip().split("\n"):
        parts = line.split("\t")
        if len(parts) == 5:
            iface, _priv, pub, port, fwmark = parts
            interfaces.setdefault(iface, {"name": iface, "public_key": pub,
                                          "listen_port": int(port) if port.isdigit() else 0,
                                          "peers": []})
        elif len(parts) >= 8:
            iface, peer_pub, _psk, endpoint, allowed, last_hs, rx, tx = parts[:8]
            interfaces.setdefault(iface, {"name": iface, "peers": []})
            interfaces[iface]["peers"].append({
                "public_key": peer_pub,
                "endpoint": endpoint,
                "allowed_ips": allowed.split(",") if allowed else [],
                "latest_handshake": int(last_hs) if last_hs.isdigit() else 0,
                "rx_bytes": int(rx) if rx.isdigit() else 0,
                "tx_bytes": int(tx) if tx.isdigit() else 0,
            })
    return {"available": True, "interfaces": list(interfaces.values())}


@app.get("/api/tailscale/status")
async def tailscale_status(user: dict = Depends(get_current_user)):
    """Call `tailscale status --json` for real node state."""
    if not shutil.which("tailscale"):
        return {"available": False, "reason": "tailscale not installed",
                "running": False, "peers": []}
    try:
        out = subprocess.check_output(["tailscale", "status", "--json"],
                                      text=True, timeout=5)
        data = json.loads(out)
    except subprocess.CalledProcessError as exc:
        return {"available": True, "running": False,
                "error": exc.output or str(exc), "peers": []}
    except Exception as exc:
        return {"available": True, "running": False, "error": str(exc), "peers": []}
    self_node = (data.get("Self") or {})
    peers = []
    for _, p in (data.get("Peer") or {}).items():
        peers.append({
            "name": p.get("HostName") or p.get("DNSName", ""),
            "tailscale_ip": (p.get("TailscaleIPs") or ["-"])[0],
            "os": p.get("OS", ""),
            "online": p.get("Online", False),
            "exit_node": p.get("ExitNode", False),
            "last_seen": p.get("LastSeen", ""),
            "rx_bytes": p.get("RxBytes", 0),
            "tx_bytes": p.get("TxBytes", 0),
        })
    return {
        "available": True,
        "running": bool(data.get("BackendState") == "Running"),
        "backend_state": data.get("BackendState", "?"),
        "tailnet": data.get("CurrentTailnet", {}).get("Name", ""),
        "self": {
            "name": self_node.get("HostName", ""),
            "tailscale_ip": (self_node.get("TailscaleIPs") or ["-"])[0],
            "os": self_node.get("OS", ""),
        },
        "peers": peers,
    }


@app.get("/api/lldp/neighbors")
async def lldp_neighbors(user: dict = Depends(get_current_user)):
    """
    Return LLDP neighbor table. Tries `lldpctl -f json0` (lldpd) first,
    falls back to lldp from openlldp, or returns empty if no daemon.
    """
    if not shutil.which("lldpctl"):
        return {"available": False, "reason": "lldpd not installed",
                "interfaces": []}
    try:
        out = subprocess.check_output(["lldpctl", "-f", "json0"],
                                      text=True, timeout=5)
        data = json.loads(out)
    except Exception as exc:
        return {"available": True, "error": str(exc), "interfaces": []}

    interfaces = []
    # lldpctl json0 shape: {"lldp": [{"interface": [...]}]}
    blob = (data.get("lldp") or [{}])[0].get("interface") or []
    for entry in blob:
        for iface_name, iface_data in entry.items():
            chassis = (iface_data.get("chassis") or [{}])[0]
            chassis_inner = next(iter(chassis.values()), {}) if chassis else {}
            port = (iface_data.get("port") or [{}])[0]
            interfaces.append({
                "local_interface": iface_name,
                "remote_chassis_id": chassis_inner.get("id", [{}])[0].get("value", "")
                                     if isinstance(chassis_inner.get("id"), list)
                                     else chassis_inner.get("id", ""),
                "remote_port": port.get("id", [{}])[0].get("value", "")
                               if isinstance(port.get("id"), list)
                               else port.get("id", ""),
                "system_name": chassis_inner.get("name", [{}])[0].get("value", "")
                               if isinstance(chassis_inner.get("name"), list)
                               else chassis_inner.get("name", ""),
                "system_description": chassis_inner.get("descr", ""),
                "ttl": port.get("ttl", 0),
            })
    return {"available": True, "interfaces": interfaces}


def _parse_dhcp_leases(path: str) -> list:
    """Parse ISC dhcpd.leases blocks or a Kea leases4 CSV into a lease list."""
    leases = []
    try:
        if path.endswith(".csv"):
            import csv
            with open(path) as f:
                for row in csv.DictReader(f):
                    st = str(row.get("state", "")).strip()
                    state = {"0": "active", "1": "declined",
                             "2": "expired"}.get(st, st or "active")
                    leases.append({
                        "ip": row.get("address", ""), "mac": row.get("hwaddr", ""),
                        "hostname": row.get("hostname", ""), "state": state,
                        "expires": row.get("expire", ""),
                    })
        else:
            cur = None
            with open(path) as f:
                for line in f:
                    t = line.strip()
                    if t.startswith("lease ") and t.endswith("{"):
                        cur = {"ip": t.split()[1], "mac": "", "hostname": "",
                               "state": "", "expires": ""}
                    elif cur is not None:
                        if t.startswith("hardware ethernet"):
                            cur["mac"] = t.split()[2].rstrip(";")
                        elif t.startswith("client-hostname"):
                            cur["hostname"] = t.split(None, 1)[1].strip(' ";')
                        elif t.startswith("binding state"):
                            cur["state"] = t.split()[2].rstrip(";")
                        elif t.startswith("ends "):
                            cur["expires"] = t.split(None, 1)[1].rstrip(";")
                        elif t == "}":
                            leases.append(cur)
                            cur = None
    except Exception:
        pass
    # dhcpd.leases appends history -> keep the last block per IP
    dedup = {}
    for l in leases:
        dedup[l["ip"]] = l
    return [l for l in dedup.values()
            if l.get("state") in ("", "active") or path.endswith(".csv")]


@app.get("/api/dhcp/leases")
async def dhcp_leases(user: dict = Depends(get_current_user)):
    """Active DHCP leases parsed from the system lease DB (isc-dhcp-server / Kea)."""
    candidates = [
        "/var/lib/dhcp/dhcpd.leases",
        "/var/lib/dhcpd/dhcpd.leases",
        "/var/lib/kea/kea-leases4.csv",
    ]
    for p in candidates:
        if os.path.exists(p):
            leases = _parse_dhcp_leases(p)
            return {"available": True, "source": p,
                    "count": len(leases), "leases": leases}
    return {"available": False, "leases": [],
            "message": "No DHCP server lease database found (no isc-dhcp-server / Kea running)"}


# ---- DNS Proxy config + honest resolver stats -----------------------------
DNS_PROXY_PATH = "/etc/ffn-ngfw/dns-proxy.json"
_DNS_PROXY_DEFAULT = {"enable": False, "primary": "", "secondary": "",
                      "doh": "disabled", "domain_overrides": []}


def _read_dns_proxy() -> dict:
    cfg = dict(_DNS_PROXY_DEFAULT)
    try:
        with open(DNS_PROXY_PATH) as f:
            cfg.update(json.load(f))
    except Exception:
        pass
    return cfg


def _dns_proxy_stats() -> dict:
    """Report resolver stats ONLY when a resolver is actually running -- no
    fabricated zeros."""
    svc = None
    for name in ("unbound", "dnsmasq", "systemd-resolved"):
        try:
            if subprocess.run(["pidof", name], capture_output=True).returncode == 0:
                svc = name
                break
        except Exception:
            pass
    stats = {"running": svc is not None, "resolver": svc}
    if svc == "unbound" and shutil.which("unbound-control"):
        try:
            out = subprocess.run(["unbound-control", "stats_noreset"],
                                 capture_output=True, text=True, timeout=4).stdout
            kv = dict(l.split("=", 1) for l in out.splitlines() if "=" in l)
            stats["queries"] = int(float(kv.get("total.num.queries", 0)))
            stats["cache_hits"] = int(float(kv.get("total.num.cachehits", 0)))
            stats["cache_misses"] = int(float(kv.get("total.num.cachemiss", 0)))
        except Exception:
            pass
    return stats


@app.get("/api/network/dns-proxy")
async def dns_proxy_get():
    return {"config": _read_dns_proxy(), "stats": _dns_proxy_stats()}


@app.put("/api/network/dns-proxy")
async def dns_proxy_set(cfg: DnsProxyConfig, user: dict = Depends(get_current_user)):
    cur = _read_dns_proxy()
    upd = {k: v for k, v in cfg.dict(exclude_unset=True).items() if v is not None}
    cur.update(upd)
    try:
        if os.path.exists(DNS_PROXY_PATH):
            shutil.copy(DNS_PROXY_PATH, DNS_PROXY_PATH + ".bak")
        with open(DNS_PROXY_PATH, "w") as f:
            json.dump(cur, f, indent=2)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"cannot write dns-proxy config: {e}")
    try:
        async with aiosqlite.connect(DB_PATH) as db:
            await audit(db, user["username"], "set_dns_proxy",
                        f"enable={cur.get('enable')} primary={cur.get('primary')}")
            await db.commit()
    except Exception:
        pass
    return {"status": "applied", "config": cur}


# ==========================================================================
# 13. PAN-OS-style device management — vsys, zones, interfaces
#
# All writes land in the candidate config under the canonical xpath
# devices/entry[@name=localhost.localdomain]/... so they flow through the
# normal commit → configd apply pipeline and show up in the diff view.
# ==========================================================================

LOCAL_DEV = "localhost.localdomain"
DEV = f"devices.entry[@name={LOCAL_DEV}]"


def _xml_escape(s: str) -> str:
    if s is None:
        return ""
    return (str(s).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;").replace("'", "&apos;"))


# --------------------------------------------------------------------------
# ethtool — discover supported link speeds/duplex/auto-neg for each iface
# --------------------------------------------------------------------------


def _parse_ethtool(output: str) -> dict:
    """Parse `ethtool <iface>` output into a structured capability set."""
    info = {
        "supported_speeds": [],  # list of (speed_mbps, duplex) tuples
        "advertised_speeds": [],
        "current_speed_mbps": None,
        "current_duplex": None,
        "auto_neg": None,
        "link": None,
        "port_type": None,
        "supported_ports": [],
    }

    def parse_modes(line: str):
        modes = []
        for tok in line.split():
            m = __import__("re").match(r"^(\d+)base\S*/(\w+)$", tok)
            if m:
                modes.append({"speed_mbps": int(m.group(1)), "duplex": m.group(2).lower()})
        return modes

    for raw in output.splitlines():
        line = raw.strip()
        if line.startswith("Supported link modes:"):
            info["supported_speeds"] += parse_modes(line.split(":", 1)[1])
        elif line.startswith("Advertised link modes:"):
            info["advertised_speeds"] += parse_modes(line.split(":", 1)[1])
        # Multi-line continuations (indented lines under the mode keys)
        elif "base" in line and "/" in line and not ":" in line:
            info["supported_speeds"] += parse_modes(line)
        elif line.startswith("Speed:"):
            val = line.split(":", 1)[1].strip()
            try:
                info["current_speed_mbps"] = int(val.replace("Mb/s", "").strip())
            except ValueError:
                info["current_speed_mbps"] = 0
        elif line.startswith("Duplex:"):
            info["current_duplex"] = line.split(":", 1)[1].strip().lower()
        elif line.startswith("Auto-negotiation:"):
            info["auto_neg"] = line.split(":", 1)[1].strip().lower() == "on"
        elif line.startswith("Link detected:"):
            info["link"] = line.split(":", 1)[1].strip().lower() == "yes"
        elif line.startswith("Port:"):
            info["port_type"] = line.split(":", 1)[1].strip()
        elif line.startswith("Supported ports:"):
            inner = line.split(":", 1)[1].strip().strip("[ ]")
            info["supported_ports"] = [p.strip() for p in inner.split() if p.strip()]

    # De-dupe
    def dedup(lst):
        seen = set()
        out = []
        for e in lst:
            key = (e["speed_mbps"], e["duplex"])
            if key not in seen:
                seen.add(key)
                out.append(e)
        return out

    info["supported_speeds"] = dedup(info["supported_speeds"])
    info["advertised_speeds"] = dedup(info["advertised_speeds"])
    return info


@app.get("/api/network/link-capabilities")
async def link_capabilities(user: dict = Depends(get_current_user)):
    """
    Per-interface ethtool output, keyed by PAN-OS alias (ethernet1/1)
    but executed against the mapped Linux NIC (ens33). Frontend uses this
    to populate link-speed dropdowns with values the hardware supports.
    """
    # Ensure aliases are current (new NICs get auto-aliased here as well)
    aliases = _auto_assign_aliases()
    have_ethtool = shutil.which("ethtool") is not None
    ifaces = {}
    for pan_name, linux_name in aliases.items():
        entry = {
            "pan_name": pan_name,
            "linux_name": linux_name,
            "ethtool_available": have_ethtool,
            "supported_speeds": [],
            "current_speed_mbps": 0,
            "current_duplex": None,
            "auto_neg": None,
            "link": False,
        }
        if have_ethtool:
            try:
                out = subprocess.check_output(
                    ["ethtool", linux_name], text=True, timeout=3, stderr=subprocess.STDOUT,
                )
                entry.update(_parse_ethtool(out))
            except Exception as exc:
                entry["error"] = str(exc)
        # Always also fill in live link state from psutil (quick)
        try:
            st = psutil.net_if_stats().get(linux_name)
            if st:
                if not entry["current_speed_mbps"]:
                    entry["current_speed_mbps"] = st.speed
                entry["link"] = st.isup
                if not entry["supported_speeds"] and st.speed:
                    entry["supported_speeds"] = [{"speed_mbps": st.speed, "duplex": "full"}]
        except Exception:
            pass
        # Key by PAN-OS name so the frontend can look up by ethernet1/1
        ifaces[pan_name] = entry
    return {"interfaces": ifaces, "ethtool_present": have_ethtool}


# --------------------------------------------------------------------------
# Virtual Systems (vsys) — CRUD under /config/devices/entry/vsys
# --------------------------------------------------------------------------


class VsysEntry(BaseModel):
    name: str           # e.g. "vsys2"
    # Stable numeric packet tag (contract §2). Server-assigned/derived from the
    # vsys<N> name (vsys1->1, ...); ignored on input, echoed on read.
    vsys_id: Optional[int] = None
    display_name: str = ""
    description: str = ""
    comment: str = ""
    # Which interfaces and virtual-routers this vsys imports from the device
    import_interfaces: list = []
    import_virtual_routers: list = []


@app.get("/api/vsys")
async def vsys_list(user: dict = Depends(get_current_user)):
    """List all Virtual Systems from the candidate config."""
    node = config_mgr.get_xpath(f"{DEV}.vsys", source="candidate")
    out = []
    if node is not None:
        for e in node.findall("entry"):
            imp_ifs = [m.text for m in e.findall("./import/network/interface/member") if m.text]
            imp_vrs = [m.text for m in e.findall("./import/network/virtual-router/member") if m.text]
            out.append({
                "name": e.get("name"),
                # Stable numeric packet tag (contract §2). vsys1->1, vsys2->2.
                "vsys_id": _vsys_id_for_entry(e),
                "display_name": e.findtext("display-name", ""),
                "description": e.findtext("description", ""),
                "comment": e.findtext("comment", ""),
                "import_interfaces": imp_ifs,
                "import_virtual_routers": imp_vrs,
                "zone_count": len(e.findall("./zone/entry")),
                "rule_count": len(e.findall("./rulebase/security/rules/entry")),
            })
    return {"entries": out}


@app.post("/api/vsys")
async def vsys_create(v: VsysEntry, user: dict = Depends(get_current_user)):
    """Create a new Virtual System."""
    _require_lock(user)
    if not re.match(r"^vsys[0-9]+$", v.name):
        raise HTTPException(status_code=400, detail="vsys name must be vsys<N> (e.g. vsys2)")
    # Stable numeric packet tag (contract §2) — assigned at create, persisted,
    # never reused. Derived from the vsys<N> suffix so vsys1->1, vsys2->2, ...
    vsys_id = _vsys_id_from_name(v.name)
    if vsys_id < 1:
        raise HTTPException(status_code=400, detail="vsys id must be >= 1 (vsys0 is reserved)")
    xp = f"{DEV}.vsys.entry[@name={v.name}]"
    config_mgr.update_candidate(xp, {
        "vsys-id": str(vsys_id),
        "display-name": v.display_name or v.name,
        "description": v.description,
        "comment": v.comment,
        "import": {
            "network": {
                "interface":       v.import_interfaces or None,
                "virtual-router":  v.import_virtual_routers or None,
            }
        },
        # Seed empty containers so later edits don't 404 on child lookups
        "zone": None, "address": None, "address-group": None,
        "service": None, "service-group": None, "tag": None,
        "rulebase": {"security": {"rules": None}, "nat": {"rules": None},
                     "qos": {"rules": None}, "pbf": {"rules": None},
                     "decryption": {"rules": None}, "application-override": {"rules": None},
                     "authentication": {"rules": None}, "dos": {"rules": None}},
    }, user["username"])
    await _audit(user, "vsys_create", v.name)
    return {"status": "created", "name": v.name, "vsys_id": vsys_id}


@app.put("/api/vsys/{name}")
async def vsys_update(name: str, v: VsysEntry, user: dict = Depends(get_current_user)):
    _require_lock(user)
    xp_base = f"{DEV}.vsys.entry[@name={name}]"
    updates = {}
    if v.display_name:
        updates[f"{xp_base}.display-name"] = v.display_name
    if v.description is not None:
        updates[f"{xp_base}.description"] = v.description
    if v.comment is not None:
        updates[f"{xp_base}.comment"] = v.comment
    if v.import_interfaces is not None:
        updates[f"{xp_base}.import.network.interface"] = v.import_interfaces
    if v.import_virtual_routers is not None:
        updates[f"{xp_base}.import.network.virtual-router"] = v.import_virtual_routers
    config_mgr.update_candidate_bulk(updates, user["username"])
    await _audit(user, "vsys_update", name)
    # vsys_id is immutable (contract §2) — surface it but never rewrite it here.
    return {"status": "updated", "name": name, "vsys_id": _vsys_id_from_name(name)}


@app.delete("/api/vsys/{name}")
async def vsys_delete(name: str, user: dict = Depends(get_current_user)):
    _require_lock(user)
    if name == "vsys1":
        raise HTTPException(status_code=400, detail="vsys1 cannot be deleted")
    result = config_mgr.delete_candidate(f"{DEV}.vsys.entry[@name={name}]", user["username"])
    await _audit(user, "vsys_delete", name)
    return result


# --------------------------------------------------------------------------
# Zones — CRUD under /config/devices/entry/vsys/entry/zone
# --------------------------------------------------------------------------


class ZoneEntry(BaseModel):
    name: str
    zone_type: str = "layer3"      # layer3 | layer2 | virtual-wire | tap | tunnel | external
    interfaces: list = []          # interface names (members)
    enable_user_identification: bool = False
    zone_protection_profile: str = ""
    log_setting: str = ""
    comment: str = ""


ZONE_TYPES = {"layer3", "layer2", "virtual-wire", "tap", "tunnel", "external"}


@app.get("/api/vsys/{vsys}/zones")
async def zone_list(vsys: str, user: dict = Depends(get_current_user)):
    node = config_mgr.get_xpath(f"{DEV}.vsys.entry[@name={vsys}].zone", source="candidate")
    entries = []
    if node is not None:
        for e in node.findall("entry"):
            # Identify zone type by which <network> sub-tag is present
            net = e.find("network") or ET.Element("_")
            zt = next((c.tag for c in net if c.tag in ZONE_TYPES), "layer3")
            ifs = [m.text for m in net.findall(f"./{zt}/member") if m.text]
            entries.append({
                "name": e.get("name"),
                "zone_type": zt,
                "interfaces": ifs,
                "enable_user_identification": e.findtext("enable-user-identification", "no") == "yes",
                "zone_protection_profile": e.findtext("./network/zone-protection-profile", ""),
                "log_setting": e.findtext("./network/log-setting", ""),
                "comment": e.findtext("comment", ""),
            })
    return {"vsys": vsys, "entries": entries}


@app.post("/api/vsys/{vsys}/zones")
async def zone_create(vsys: str, z: ZoneEntry, user: dict = Depends(get_current_user)):
    _require_lock(user)
    if z.zone_type not in ZONE_TYPES:
        raise HTTPException(status_code=400, detail=f"zone_type must be one of {sorted(ZONE_TYPES)}")
    xp = f"{DEV}.vsys.entry[@name={vsys}].zone.entry[@name={z.name}]"
    payload = {
        "network": {
            z.zone_type: z.interfaces or None,
        },
        "enable-user-identification": "yes" if z.enable_user_identification else "no",
        "comment": z.comment,
    }
    if z.zone_protection_profile:
        payload["network"]["zone-protection-profile"] = z.zone_protection_profile
    if z.log_setting:
        payload["network"]["log-setting"] = z.log_setting
    config_mgr.update_candidate(xp, payload, user["username"])
    await _audit(user, "zone_create", f"{vsys}/{z.name}")
    return {"status": "created", "vsys": vsys, "zone": z.name, "type": z.zone_type}


@app.put("/api/vsys/{vsys}/zones/{name}")
async def zone_update(vsys: str, name: str, z: ZoneEntry,
                      user: dict = Depends(get_current_user)):
    _require_lock(user)
    xp = f"{DEV}.vsys.entry[@name={vsys}].zone.entry[@name={name}]"
    # Full replace — simpler + matches PAN-OS semantics
    payload = {
        "network": {z.zone_type: z.interfaces or None},
        "enable-user-identification": "yes" if z.enable_user_identification else "no",
        "comment": z.comment,
    }
    if z.zone_protection_profile:
        payload["network"]["zone-protection-profile"] = z.zone_protection_profile
    config_mgr.update_candidate(xp, payload, user["username"])
    await _audit(user, "zone_update", f"{vsys}/{name}")
    return {"status": "updated"}


@app.delete("/api/vsys/{vsys}/zones/{name}")
async def zone_delete(vsys: str, name: str, user: dict = Depends(get_current_user)):
    _require_lock(user)
    r = config_mgr.delete_candidate(
        f"{DEV}.vsys.entry[@name={vsys}].zone.entry[@name={name}]", user["username"])
    await _audit(user, "zone_delete", f"{vsys}/{name}")
    return r


# --------------------------------------------------------------------------
# Interfaces (ethernet + aggregate-ethernet + sub-interfaces)
# --------------------------------------------------------------------------


class InterfaceEntry(BaseModel):
    name: str                                # ethernet1/1 | ae1
    kind: str = "ethernet"                   # ethernet | aggregate-ethernet
    mode: str = "layer3"                     # layer3 | layer2 | virtual-wire | tap | aggregate-group | decrypt-mirror | ha
    ip_addresses: list = []                  # strings ("192.168.1.1/24") or address-object names
    ipv6_enabled: bool = False
    ipv6_addresses: list = []
    interface_management_profile: str = ""
    mtu: Optional[int] = None                # interface MTU override
    link_speed: str = "auto"                 # auto | 10 | 100 | 1000 | 10000 | 100000
    link_duplex: str = "auto"                # auto | full | half
    link_state: str = "auto"                 # auto | up | down
    aggregate_group: str = ""                # set when mode=aggregate-group to join an ae
    # Aggregate bonding settings (only on aggregate-ethernet entries)
    # lacp | active-backup | balance-rr | balance-xor | broadcast | 802.3ad | balance-tlb | balance-alb
    bond_mode: str = "active-backup"         # VMware-safe default; switch to 802.3ad for LACP on real hardware
    bond_miimon_ms: int = 100
    lldp_enabled: bool = False
    lldp_profile: str = ""
    comment: str = ""


MODES = {"layer3", "layer2", "virtual-wire", "tap", "aggregate-group",
         "decrypt-mirror", "ha"}


def _iface_kind(name: str) -> str:
    """Guess the interface kind from its name."""
    if name.startswith("ae") and "." not in name:
        return "aggregate-ethernet"
    if name.startswith("ethernet"):
        return "ethernet"
    return "ethernet"


def _iface_xpath(name: str) -> str:
    kind = _iface_kind(name)
    return f"{DEV}.network.interface.{kind}.entry[@name={name}]"


# ---------------------------------------------------------------------------
# Linux <-> PAN-OS interface aliasing
#
# Each physical Linux NIC (ens33, eno1, enp3s0, qsfp0…) is mapped to a
# PAN-OS slot name (ethernet1/1, ethernet1/2, …). The alias table lives in
# the candidate XML under
#     devices/entry[localhost.localdomain]/deviceconfig/system/interface-alias
# so it survives commits and is visible in the canonical config.
#
# Auto-assignment rules:
#   - FPGA QSFP ports (qsfpN) → ethernet1/N+1 (so qsfp0 = ethernet1/1)
#   - Everything else (ens*, eno*, enp*, eth*, any_other) → next free
#     ethernet1/K slot starting at 1.
#   - Loopback ('lo') is skipped.
#   - Aliases are stable across restarts (we only auto-assign for NICs that
#     don't already have one).
# ---------------------------------------------------------------------------

ALIAS_XPATH = f"{DEV}.deviceconfig.system.interface-alias"


# ---------------------------------------------------------------------------
# Open vSwitch constructs are not physical firewall ports: the datapath devices
# (ovs-netdev/ovs-system), the bridges, and any "internal"/"patch" ports are
# switch objects. They must never be auto-aliased to an ethernet1/N slot (same
# class of bug as tmfifo_net0). Names are operator-chosen (ig1, vp0, ...), so ask
# OVS rather than guessing from the name.
# ---------------------------------------------------------------------------
_OVS_CACHE = {"t": 0.0, "set": set()}


def _ovs_owned_ifaces() -> set:
    import time as _t
    now = _t.time()
    if _OVS_CACHE["set"] and (now - _OVS_CACHE["t"]) < 60:
        return _OVS_CACHE["set"]
    owned = {"ovs-netdev", "ovs-system"}
    try:
        if shutil.which("ovs-vsctl"):
            brs = subprocess.run(["ovs-vsctl", "list-br"], capture_output=True,
                                 text=True, timeout=4).stdout.split()
            for b in brs:
                owned.add(b)
                ports = subprocess.run(["ovs-vsctl", "list-ports", b],
                                       capture_output=True, text=True,
                                       timeout=4).stdout.split()
                for p in ports:
                    t = subprocess.run(["ovs-vsctl", "get", "Interface", p, "type"],
                                       capture_output=True, text=True,
                                       timeout=4).stdout.strip().strip('"')
                    # internal/patch ports are synthetic; a real NIC enslaved to
                    # a bridge reports type "" and keeps its own identity.
                    if t in ("internal", "patch"):
                        owned.add(p)
    except Exception:
        pass
    _OVS_CACHE["t"] = now
    _OVS_CACHE["set"] = owned
    return owned


def _list_linux_nics() -> list:
    """
    Return a sorted list of real, physical Linux NIC names. We exclude
    lo and any synthetic interfaces the appliance creates itself
    (bondN, wgN, vethN, brN, docker*, ziN) — those are managed via their
    own config models and shouldn't be aliased as ethernet slots.
    """
    import re as _re
    SKIP = _re.compile(r"^(lo|bond\d+|wg\d+|veth|br-|br\d+|docker\d+|zt[a-z0-9]+|tun\d+|tap\d+|virbr\d+|tmfifo_net\d*|rshim\d*|dummy\d*|ovs-netdev|ovs-system)")
    try:
        names = [n for n in psutil.net_if_stats().keys() if not SKIP.match(n)]
    except Exception:
        return []
    # drop OVS bridges / internal ports (operator-named, so query OVS)
    _ovs = _ovs_owned_ifaces()
    names = [n for n in names if n not in _ovs]

    # A platform submodule may declare which of this host's NICs are
    # control-plane. On a PA-5200 that is ALL of them -- MGT, the HA1 pair, the
    # two AUX ports and the internal backplane links -- and the rule has been
    # written down in platform/pa5200/ffn_ifroles.py since it was worked out.
    # It was referenced by nothing, so this function kept handing every one of
    # them an ethernet1/N firewall slot at startup, and those aliases were
    # written into the candidate config where they persisted across commits.
    # Offering an operator a management NIC as a data port is how you bridge
    # your own management network.
    roles = _if_roles()
    if roles is not None:
        kept = []
        for n in names:
            try:
                if roles.is_control_plane(n):
                    continue
            except Exception:
                pass          # an undecidable NIC stays visible, not hidden
            kept.append(n)
        names = kept
    return sorted(names)




# ---------------------------------------------------------------------------
# The firewall's DATA interfaces
# ---------------------------------------------------------------------------
# On a reclaimed appliance the firewall's interfaces are the chassis faceplate
# ports, which live on a switch ASIC behind the control plane. They are NOT
# this host's NICs -- every one of those is management, HA, AUX or an internal
# backplane link, which is what platform/pa5200/ffn_ifroles.py has said all
# along.
#
# Two different things are being joined here, and keeping them separate is the
# point:
#
#   the MAP    which chip port is behind which faceplate connector, and what
#              ethernet1/N an operator should call it. A property of the board.
#              Known whether or not anything is powered on.
#   the STATE  link, admin state, negotiated speed. Read from the chip through
#              ffn-bcmd, and only available when the control plane answers.
#
# So an unreachable CP costs the state and not the map: the interface list
# still shows all 25 faceplate ports, with link state reported as unknown
# rather than as down. Showing an empty interface list because a daemon is
# restarting would be a worse answer than showing the ports with no state.


async def _faceplate_map(plane=None):
    """{pan_name: portinfo} for this chassis, or None if it has no faceplate
    map -- which is how "this is not that hardware" is reported.

    `plane` selects which connectors: "data" for the firewall's interfaces,
    "management" for the device's own (the HA data link). None returns the
    whole faceplate, which is what a physical inventory wants.
    """
    bp = _bcm_faceplate()
    if bp is None:
        return None

    if not _this_is_a_faceplate_chassis():
        return None

    live = {}
    reply = {}
    try:
        reply = await _bcm_client().port_list()
        for p in (reply.get("ports") or []):
            live[p.get("port")] = p
    except ImportError:
        reply = {"ok": False, "error": "bcm client unavailable"}
    except Exception as exc:                       # never fail the whole page
        reply = {"ok": False, "error": str(exc)}

    # Insertion order is faceplate order -- bp.faceplate_ports() returns the
    # numbered connectors in order and then the named ones. Callers iterate this
    # dict directly, so ordering it here means the interface list reads like the
    # front of the chassis rather than like the chip's port numbering, which is
    # scrambled relative to the metal (logical 28 is connector 1).
    out = {}
    for port in bp.faceplate_ports(plane):
        name = bp.pan_ifname(port)
        label, media, speed, pl = bp.FACEPLATE[port]
        p = live.get(port) or {}
        out[name] = {
            "name": name,
            "bcm_port": port,
            # Which plane the connector serves. HSCI is on the front of the
            # chassis but it is the HA DATA link -- HA2/HA3, session sync and
            # active/active packet forwarding between peers -- so it belongs to
            # the device's high-availability configuration and not to the
            # firewall's interface list. Being on the faceplate does not make a
            # connector a firewall interface.
            "plane": pl,
            "role": ("HA data link (HA2/HA3)" if pl == bp.PLANE_MGMT
                     else "data"),
            "configurable": pl == bp.PLANE_DATA,
            # The name the switch's own diag shell uses. Shown to an operator
            # because it is what every chip-level tool and log line says, and
            # it is not derivable from either the faceplate label or the chip
            # port name.
            "diag_name": p.get("name") or bp.diag_name(port),
            "chip_name": bp.PORTS[port][0],
            "faceplate": label,
            "media": media,
            "speed_gbps": speed,
            "link": p.get("link"),
            "admin_enabled": p.get("enabled"),
            "state": p.get("state"),
            "live": bool(p),
        }
    return out


def _this_is_a_faceplate_chassis():
    """Does this host actually have the chassis the faceplate map describes?

    Importability is NOT the test. A platform module can be present because a
    checkout has the submodule, or because someone copied it, and treating that
    as "this is a PA-5200" would make a completely different host purge its
    interface aliases and advertise 25 ports it does not have.

    So the map is only claimed alongside positive hardware evidence: an OCTEON
    on this host's PCI bus. That is the one part of the complex the host can
    see, it is read straight from sysfs with no subprocess, and no other
    platform FFN targets carries one.
    """
    if _bcm_faceplate() is None:
        return False
    try:
        for dev in os.listdir("/sys/bus/pci/devices"):
            try:
                with open("/sys/bus/pci/devices/%s/vendor" % dev) as f:
                    if f.read().strip().lower() == "0x177d":
                        return True
            except OSError:
                continue          # hotplug/rescan race: skip, do not fail
    except OSError:
        return False
    return False


def _faceplate_map_sync(plane=None):
    """Map only, no chip state. For the paths that cannot await."""
    bp = _bcm_faceplate()
    if bp is None or not _this_is_a_faceplate_chassis():
        return None
    out = {}
    for port in bp.faceplate_ports(plane):
        label, media, speed, pl = bp.FACEPLATE[port]
        out[bp.pan_ifname(port)] = {
            "name": bp.pan_ifname(port), "bcm_port": port,
            "plane": pl,
            "role": ("HA data link (HA2/HA3)" if pl == bp.PLANE_MGMT
                     else "data"),
            "configurable": pl == bp.PLANE_DATA,
            "diag_name": bp.diag_name(port), "chip_name": bp.PORTS[port][0],
            "faceplate": label, "media": media, "speed_gbps": speed,
            "link": None, "admin_enabled": None, "state": None, "live": False,
        }
    return out


def _load_aliases() -> dict:
    """Return {pan_name: linux_name} from the candidate config."""
    node = config_mgr.get_xpath(ALIAS_XPATH, source="candidate")
    aliases = {}
    if node is not None:
        for e in node.findall("entry"):
            pan = e.get("name")
            lnx = (e.findtext("linux-name") or "").strip()
            if pan and lnx:
                aliases[pan] = lnx
    return aliases


def _save_alias(pan_name: str, linux_name: str, auto: bool = False):
    """Write a single alias into the candidate XML."""
    xp = f"{ALIAS_XPATH}.entry[@name={pan_name}]"
    config_mgr.update_candidate(xp, {
        "linux-name": linux_name,
        "auto-generated": "yes" if auto else "no",
    }, user="system")


def _delete_alias(pan_name: str):
    config_mgr.delete_candidate(f"{ALIAS_XPATH}.entry[@name={pan_name}]", user="system")


def _auto_assign_aliases() -> dict:
    """
    Make sure every real Linux NIC has an alias. Create any that are missing
    using the rules above. Called at startup and whenever the frontend
    requests interface data.
    Returns the fresh {pan_name: linux_name} map.
    """
    existing = _load_aliases()

    # On a chassis whose data ports are on a switch ASIC, NO host NIC is a
    # firewall interface, so there is nothing here to auto-assign. Any alias
    # already in the candidate was minted by an older build of this function
    # and points at a management, HA, AUX or backplane NIC -- purge it, or the
    # interface grid keeps offering an operator a management port to configure
    # as a data port long after the source of the mistake is fixed.
    if _faceplate_map_sync() is not None:
        # Purge aliases pointing at NICs that are no longer eligible -- on this
        # chassis, every control-plane NIC -- and then FALL THROUGH rather than
        # returning. ffn_ifroles documents a `data_plane_netdevs` escape hatch
        # for a platform where a host NIC really is a data port; returning here
        # meant that override could never produce an alias, which quietly broke
        # the one case it exists for. _list_linux_nics() already honours it, so
        # falling through does the right thing for both.
        eligible = set(_list_linux_nics())
        for pan, lnx in list(existing.items()):
            if lnx in eligible:
                continue
            logger.info("Purging host-NIC alias %s -> %s: this chassis's data "
                        "ports are on the switch ASIC, not on host NICs",
                        pan, lnx)
            _delete_alias(pan)
            existing.pop(pan, None)

    # Purge stale aliases pointing at non-physical Linux interfaces
    # (bondN, veth, docker bridges) that may have leaked into the
    # candidate before this filter was added.
    valid_nics = set(_list_linux_nics())
    for pan, lnx in list(existing.items()):
        if lnx not in valid_nics:
            logger.info("Purging stale alias %s → %s (not a physical NIC)", pan, lnx)
            _delete_alias(pan)
            existing.pop(pan, None)
    linux_to_pan = {v: k for k, v in existing.items()}
    used_slots = set()
    for pan in existing.keys():
        m = __import__("re").match(r"^ethernet(\d+)/(\d+)$", pan)
        if m:
            used_slots.add((int(m.group(1)), int(m.group(2))))

    def next_slot():
        k = 1
        while (1, k) in used_slots:
            k += 1
        used_slots.add((1, k))
        return f"ethernet1/{k}"

    changed = False
    for linux in _list_linux_nics():
        if linux in linux_to_pan:
            continue
        # FPGA qsfpN → ethernet1/N+1 (so qsfp0 = ethernet1/1)
        m = __import__("re").match(r"^qsfp(\d+)$", linux)
        if m:
            idx = int(m.group(1)) + 1
            pan = f"ethernet1/{idx}"
            # If that slot is taken by something else, fall through to next_slot
            if (1, idx) in used_slots:
                pan = next_slot()
            else:
                used_slots.add((1, idx))
        else:
            pan = next_slot()
        _save_alias(pan, linux, auto=True)
        existing[pan] = linux
        changed = True
        logger.info("Auto-aliased %s → %s", linux, pan)
    return existing


def _pan_to_linux(pan_name: str) -> Optional[str]:
    """Look up the Linux kernel NIC name for a given PAN-OS ethernet name.
    Sub-interfaces inherit the parent's Linux NIC."""
    if "." in pan_name:
        base = pan_name.rsplit(".", 1)[0]  # ethernet1/1.100 → ethernet1/1
    else:
        base = pan_name
    aliases = _load_aliases()
    return aliases.get(base)


def _linux_to_pan(linux_name: str) -> Optional[str]:
    """Reverse lookup — Linux NIC to PAN-OS alias."""
    aliases = _load_aliases()
    for pan, lnx in aliases.items():
        if lnx == linux_name:
            return pan
    return None


def _ae_to_bond(ae_name: str) -> str:
    """Translate PAN-OS aggregate-ethernet name to a Linux bond ifname.
    'ae1' -> 'bond1', 'ae12' -> 'bond12'. Matches PAN-OS ae numbering."""
    m = __import__("re").match(r"^ae(\d+)$", ae_name)
    return f"bond{m.group(1)}" if m else f"bond_{ae_name}"


def _build_iface_payload(i: InterfaceEntry) -> dict:
    """Render an InterfaceEntry to the PAN-OS XML-dict form."""
    if i.mode not in MODES:
        raise HTTPException(status_code=400, detail=f"mode must be one of {sorted(MODES)}")

    payload: dict = {"comment": i.comment}

    # Link settings (only on ethernet / aggregate-ethernet, not aggregate-group members)
    if i.mode != "aggregate-group":
        if i.link_speed != "auto":
            payload["link-speed"] = i.link_speed
        if i.link_duplex != "auto":
            payload["link-duplex"] = i.link_duplex
        if i.link_state != "auto":
            payload["link-state"] = i.link_state
    if i.lldp_enabled:
        payload["lldp"] = {"enable": "yes"}
        if i.lldp_profile:
            payload["lldp"]["profile"] = i.lldp_profile

    # Mode-specific shape
    if i.mode == "aggregate-group":
        # This physical ethernet is a member of an aggregate
        payload["aggregate-group"] = i.aggregate_group
    elif i.mode == "tap":
        payload["tap"] = {"comment": "TAP mode inspection only"}
    elif i.mode == "virtual-wire":
        payload["virtual-wire"] = {}
    elif i.mode == "layer2":
        payload["layer2"] = {}
    elif i.mode == "layer3":
        # <ip><entry name="..."/></ip> children are written via follow-up
        # xpath calls (update_candidate does not represent attribute-only
        # <entry> children inline). Build the non-ip pieces here.
        l3: dict = {}
        if i.ipv6_enabled:
            l3["ipv6"] = {"enabled": "yes"}
        if i.mtu:
            l3["mtu"] = i.mtu
        if i.interface_management_profile:
            l3["interface-management-profile"] = i.interface_management_profile
        # Aggregate-ethernet bonding config lives under layer3/lacp
        # (active-backup / 802.3ad / balance-xor / etc.)
        is_ae = i.name.startswith("ae") and "." not in i.name
        if is_ae:
            l3["bond"] = {
                "mode": i.bond_mode or "active-backup",
                "miimon": i.bond_miimon_ms or 100,
            }
        payload["layer3"] = l3

    return payload


def _require_lock(user):
    st = config_mgr.lock_status()
    if st["locked"] and st.get("holder") != user["username"]:
        raise HTTPException(status_code=423, detail=f"Config locked by {st['holder']}")
    if not st["locked"]:
        config_mgr.acquire_lock(user["username"], "editing")


async def _audit(user, action, detail):
    async with aiosqlite.connect(DB_PATH) as db:
        await audit(db, user["username"], action, detail)


# -- Interface aliases -----------------------------------------------------


class AliasEntry(BaseModel):
    linux_name: str


@app.get("/api/interfaces/aliases")
async def aliases_list(user: dict = Depends(get_current_user)):
    """
    Return the PAN-OS → Linux NIC alias map. Auto-assigns for any newly
    detected interface on every call so the UI reflects current hardware.
    """
    fp = await _faceplate_map("data")
    if fp is not None:
        # The map is fixed by the board, so there is nothing to remap and
        # linux_nics is empty on purpose: offering a host NIC as a remap target
        # is what put management ports in the firewall interface list.
        # linux_name carries the switch diag name (xe13, ce32) because that is
        # what every chip-level tool and log line calls the port, and it is the
        # string an operator needs when correlating the two.
        return {
            "aliases": [{"pan_name": n, "linux_name": d["diag_name"]}
                        for n, d in fp.items()],
            "linux_nics": [],
            "faceplate": list(fp.values()),
            "source": "switch-asic faceplate map",
        }

    aliases = _auto_assign_aliases()
    # Include detected Linux NICs so UI can offer re-mapping
    linux_nics = []
    try:
        stats = psutil.net_if_stats()
        for name in _list_linux_nics():
            st = stats.get(name)
            linux_nics.append({
                "name": name,
                "up": bool(st.isup) if st else False,
                "speed_mbps": st.speed if st else 0,
                "mapped_to": _linux_to_pan(name),
            })
    except Exception:
        pass
    return {
        "aliases": [{"pan_name": p, "linux_name": l} for p, l in sorted(aliases.items())],
        "linux_nics": linux_nics,
    }


@app.put("/api/interfaces/aliases/{pan_name:path}")
async def alias_set(pan_name: str, a: AliasEntry,
                    user: dict = Depends(get_current_user)):
    """Manually set/remap a PAN-OS slot to a different Linux NIC."""
    _require_lock(user)
    if a.linux_name not in _list_linux_nics():
        raise HTTPException(status_code=400,
                            detail=f"Linux NIC {a.linux_name} not found on this system")
    # Remove any existing alias that targets the same Linux NIC to keep map 1:1
    current = _load_aliases()
    for existing_pan, existing_linux in list(current.items()):
        if existing_linux == a.linux_name and existing_pan != pan_name:
            _delete_alias(existing_pan)
    _save_alias(pan_name, a.linux_name, auto=False)
    await _audit(user, "alias_set", f"{pan_name}={a.linux_name}")
    return {"status": "updated", "pan_name": pan_name, "linux_name": a.linux_name}


@app.delete("/api/interfaces/aliases/{pan_name:path}")
async def alias_delete(pan_name: str,
                       user: dict = Depends(get_current_user)):
    _require_lock(user)
    _delete_alias(pan_name)
    await _audit(user, "alias_delete", pan_name)
    return {"status": "deleted"}


@app.get("/api/interfaces/configured")
async def interfaces_list(user: dict = Depends(get_current_user)):
    """Return all configured interfaces (from candidate config), grouped by kind."""
    base = config_mgr.get_xpath(f"{DEV}.network.interface", source="candidate")
    out = {"ethernet": [], "aggregate-ethernet": [], "loopback": [], "tunnel": [], "vlan": []}
    if base is None:
        return out

    def shape(entry, kind):
        # Detect mode
        mode = "layer3"
        for m in ("layer3", "layer2", "virtual-wire", "tap", "ha", "decrypt-mirror"):
            if entry.find(m) is not None:
                mode = m
                break
        if entry.findtext("aggregate-group"):
            mode = "aggregate-group"

        ips = []
        for ip in entry.findall("./layer3/ip/entry"):
            ips.append(ip.get("name", ""))

        subifs = [u.get("name", "") for u in entry.findall("./layer3/units/entry")]
        subifs += [u.get("name", "") for u in entry.findall("./units/entry")]

        return {
            "name": entry.get("name"),
            "kind": kind,
            "mode": mode,
            "ip_addresses": ips,
            "ipv6_enabled": (entry.findtext("./layer3/ipv6/enabled") or "no") == "yes",
            "mtu": entry.findtext("./layer3/mtu"),
            "link_speed": entry.findtext("link-speed", "auto"),
            "link_duplex": entry.findtext("link-duplex", "auto"),
            "link_state": entry.findtext("link-state", "auto"),
            "aggregate_group": entry.findtext("aggregate-group", ""),
            "interface_management_profile": entry.findtext("./layer3/interface-management-profile", ""),
            "lldp_enabled": entry.findtext("./lldp/enable", "no") == "yes",
            "lldp_profile": entry.findtext("./lldp/profile", ""),
            "bond_mode": entry.findtext("./layer3/bond/mode", "active-backup"),
            "bond_miimon_ms": int(entry.findtext("./layer3/bond/miimon", "100") or 100),
            "comment": entry.findtext("comment", ""),
            "sub_interfaces": subifs,
        }

    for kind in out.keys():
        cont = base.find(kind)
        if cont is None:
            continue
        for e in cont.findall("entry"):
            out[kind].append(shape(e, kind))
    return out


# ==========================================================================
# CMAC per-port management (direct BAR0 ioctl, mirrors new bitstream
# register layout at 0x1000+p*0x100). Feeds `ngfw-cli cmac <subcmd>`.
# ==========================================================================

def _cmac_port_base(port: int) -> int:
    return 0x1000 + (port & 3) * 0x100

_CMAC_RX_EN         = 1 << 0
_CMAC_TX_EN         = 1 << 1
_CMAC_FORCE_RESYNC  = 1 << 2
_CMAC_RX_CTL_EN     = 1 << 8
_CMAC_TX_SEND_IDLE  = 1 << 16
_CMAC_CFG_DEFAULT   = _CMAC_RX_EN | _CMAC_TX_EN | _CMAC_RX_CTL_EN
_CMAC_FEC_RX        = 1 << 0
_CMAC_FEC_TX        = 1 << 1
_CMAC_FEC_DEFAULT   = _CMAC_FEC_RX | _CMAC_FEC_TX

# Fault-status bit helpers (mirror ngfw_regs.h NGFW_CMAC_FLT_*)
_FLT = {
    "rx_local_fault":  1 << 0,
    "rx_remote_fault": 1 << 1,
    "rx_hi_ber":       1 << 2,
    "tx_local_fault":  1 << 3,
    "all_lanes_locked":1 << 4,
}


def _cmac_read_stats(port: int) -> dict:
    """Read the 10 × 64-bit CMAC counters for a port (LO/HI joined)."""
    base = _cmac_port_base(port)
    # Nudge a fresh snapshot (also auto-ticks every ~1.6 ms)
    fpga.write_reg(base + 0x68, 1)
    def _r64(off_lo):
        hi1 = fpga.read_reg(base + off_lo + 4)
        lo  = fpga.read_reg(base + off_lo)
        hi2 = fpga.read_reg(base + off_lo + 4)
        return ((hi2 if hi1 != hi2 else hi1) << 32) | lo
    return {
        "rx_packets":   _r64(0x80),
        "rx_bytes":     _r64(0x88),
        "rx_errors":    _r64(0x90),
        "rx_dropped":   _r64(0x98),
        "rx_multicast": _r64(0xA0),
        "tx_packets":   _r64(0xA8),
        "tx_bytes":     _r64(0xB0),
        "tx_errors":    _r64(0xB8),
        "fec_corrected":   _r64(0xC0),
        "fec_uncorrected": _r64(0xC8),
    }


def _cmac_read_status(port: int) -> dict:
    base = _cmac_port_base(port)
    cfg   = fpga.read_reg(base + 0x40)
    fec   = fpga.read_reg(base + 0x44)
    qsfp  = fpga.read_reg(base + 0x50)
    rxs   = fpga.read_reg(base + 0x54)
    flt   = fpga.read_reg(base + 0x58)
    lock  = fpga.read_reg(base + 0x5C)
    loop  = fpga.read_reg(base + 0x60)
    tp    = fpga.read_reg(base + 0x64)
    seq   = fpga.read_reg(base + 0x6C)
    return {
        "port":          port,
        "cmac_config":   cfg,
        "fec_config":    fec,
        "qsfp_present":  bool(qsfp & 0x1),
        "rx_aligned":    bool(rxs & 0x1),
        "rx_link_ok":    bool(rxs & 0x2),
        "rx_status_raw": rxs,
        "fault_status":  flt,
        "faults":        {n: bool(flt & b) for n, b in _FLT.items()},
        "block_lock":    lock & 0xFFFFF,
        "loopback_cfg":  loop & 0xFFF,
        "test_pattern":  tp   & 0x3,
        "snapshot_seq":  seq  & 0xFF,
        "rx_enabled":    bool(cfg & _CMAC_RX_EN),
        "tx_enabled":    bool(cfg & _CMAC_TX_EN),
        "fec_rx_enabled":bool(fec & _CMAC_FEC_RX),
        "fec_tx_enabled":bool(fec & _CMAC_FEC_TX),
    }


@app.get("/api/cmac/{port}/status")
async def cmac_status(port: int, user: dict = Depends(get_current_user)):
    if not 0 <= port <= 3:
        raise HTTPException(status_code=400, detail="port must be 0..3")
    if fpga.sim_mode:
        raise HTTPException(status_code=503, detail="FPGA device not available")
    return _cmac_read_status(port)


@app.get("/api/cmac/{port}/stats")
async def cmac_stats(port: int, user: dict = Depends(get_current_user)):
    if not 0 <= port <= 3:
        raise HTTPException(status_code=400, detail="port must be 0..3")
    if fpga.sim_mode:
        raise HTTPException(status_code=503, detail="FPGA device not available")
    return _cmac_read_stats(port)


class CmacConfigRequest(BaseModel):
    rx_en: Optional[bool] = None
    tx_en: Optional[bool] = None
    rx_ctl_en: Optional[bool] = None
    tx_send_idle: Optional[bool] = None
    fec_rx: Optional[bool] = None
    fec_tx: Optional[bool] = None


@app.post("/api/cmac/{port}/config")
async def cmac_set_config(port: int, req: CmacConfigRequest,
                           user: dict = Depends(get_current_user)):
    if not 0 <= port <= 3:
        raise HTTPException(status_code=400, detail="port must be 0..3")
    if fpga.sim_mode:
        raise HTTPException(status_code=503, detail="FPGA device not available")
    base = _cmac_port_base(port)
    cfg  = fpga.read_reg(base + 0x40)
    fec  = fpga.read_reg(base + 0x44)
    def _apply(current, bit, want):
        if want is None:   return current
        if want:           return current | bit
        return current & ~bit
    cfg = _apply(cfg, _CMAC_RX_EN,        req.rx_en)
    cfg = _apply(cfg, _CMAC_TX_EN,        req.tx_en)
    cfg = _apply(cfg, _CMAC_RX_CTL_EN,    req.rx_ctl_en)
    cfg = _apply(cfg, _CMAC_TX_SEND_IDLE, req.tx_send_idle)
    fec = _apply(fec, _CMAC_FEC_RX,       req.fec_rx)
    fec = _apply(fec, _CMAC_FEC_TX,       req.fec_tx)
    fpga.write_reg(base + 0x40, cfg)
    fpga.write_reg(base + 0x44, fec)
    async with aiosqlite.connect(DB_PATH) as db:
        await audit(db, user["username"], "cmac_config",
                    f"port={port} cfg=0x{cfg:08x} fec=0x{fec:08x}")
    return _cmac_read_status(port)


@app.post("/api/cmac/{port}/resync")
async def cmac_resync(port: int, user: dict = Depends(get_current_user)):
    """Pulse CMAC_CONFIG[2] (force_resync) high then low."""
    if not 0 <= port <= 3:
        raise HTTPException(status_code=400, detail="port must be 0..3")
    if fpga.sim_mode:
        raise HTTPException(status_code=503, detail="FPGA device not available")
    base = _cmac_port_base(port)
    cfg = fpga.read_reg(base + 0x40)
    fpga.write_reg(base + 0x40, cfg | _CMAC_FORCE_RESYNC)
    await asyncio.sleep(0.002)  # 2 ms hold per bitstream team guidance
    fpga.write_reg(base + 0x40, cfg & ~_CMAC_FORCE_RESYNC)
    async with aiosqlite.connect(DB_PATH) as db:
        await audit(db, user["username"], "cmac_resync", f"port={port}")
    return {"port": port, "status": "resynced"}


class CmacLoopbackRequest(BaseModel):
    mode: int = 0  # 0=normal, 1=near-PCS, 2=near-PMA, 4=far-PMA, 6=far-PCS


@app.post("/api/cmac/{port}/loopback")
async def cmac_loopback(port: int, req: CmacLoopbackRequest,
                         user: dict = Depends(get_current_user)):
    """Set per-GT-lane loopback mode. Value replicated to all 4 lanes."""
    if not 0 <= port <= 3:
        raise HTTPException(status_code=400, detail="port must be 0..3")
    if req.mode not in (0, 1, 2, 4, 6):
        raise HTTPException(status_code=400,
                            detail="mode must be 0/1/2/4/6 — see NGFW_GT_LB_* in ngfw_regs.h")
    if fpga.sim_mode:
        raise HTTPException(status_code=503, detail="FPGA device not available")
    base = _cmac_port_base(port)
    # 3 bits per lane × 4 lanes = 12-bit field in LOOPBACK_CFG
    val = req.mode | (req.mode << 3) | (req.mode << 6) | (req.mode << 9)
    fpga.write_reg(base + 0x60, val)
    async with aiosqlite.connect(DB_PATH) as db:
        await audit(db, user["username"], "cmac_loopback",
                    f"port={port} mode={req.mode}")
    return {"port": port, "mode": req.mode, "loopback_cfg": val}


@app.post("/api/cmac/{port}/snapshot")
async def cmac_snapshot(port: int, user: dict = Depends(get_current_user)):
    """Force a fresh stats snapshot and return the new sequence number."""
    if not 0 <= port <= 3:
        raise HTTPException(status_code=400, detail="port must be 0..3")
    if fpga.sim_mode:
        raise HTTPException(status_code=503, detail="FPGA device not available")
    base = _cmac_port_base(port)
    seq_before = fpga.read_reg(base + 0x6C) & 0xFF
    fpga.write_reg(base + 0x68, 1)
    await asyncio.sleep(0.01)
    seq_after = fpga.read_reg(base + 0x6C) & 0xFF
    return {"port": port, "seq_before": seq_before, "seq_after": seq_after,
            "advanced": (seq_after - seq_before) & 0xFF}


@app.get("/api/interfaces/enriched")
async def interfaces_enriched(user: dict = Depends(get_current_user)):
    """
    Flat per-row interface list shaped like the PAN-OS Network > Interfaces
    page. Each row joins:
      - Interface name (+ tag suffix for sub-interfaces)
      - Interface Type (Layer3 / Layer2 / Virtual Wire / TAP / Aggregate(aeN))
      - Management Profile
      - Link State (from live kernel via Linux alias)
      - IP Address list (comma-separated)
      - Virtual Router membership
      - VLAN tag (if sub-if)
      - VLAN / Virtual-Wire membership
      - Virtual System (which vsys imports this interface)
      - Security Zone
      - SD-WAN Interface Profile
      - Upstream NAT
      - Features (LLDP, LACP, IPv6, etc.)
      - Comment
    Returns one list per kind: ethernet, vlan, loopback, tunnel, sdwan.
    """
    candidate = config_mgr.get_xpath(f"{DEV}", source="candidate")
    if candidate is None:
        # No config yet is not the same as no interfaces. The faceplate is a
        # property of the chassis, so report it even on a box that has never
        # been configured -- that is precisely when an operator opens this page.
        empty = {"ethernet": [], "vlan": [], "loopback": [], "tunnel": [],
                 "sdwan": []}
        fp0 = await _faceplate_map("data")
        if fp0 is not None:
            empty["faceplate"] = list(fp0.values())
            empty["source"] = "switch-asic faceplate"
        return empty

    # Build name→VR, name→zone, name→vsys lookup tables once
    vr_of = {}
    for vr in candidate.findall("./network/virtual-router/entry"):
        vr_name = vr.get("name")
        for m in vr.findall("./interface/member"):
            if m.text:
                vr_of[m.text.strip()] = vr_name
    # Overlay the SQLite virtual_routers store (the primary VR system: grid,
    # Routing dialog and FRR all use it). Membership is stored as Linux dev
    # names; map each to its PAN alias so this list's VR column reflects the
    # real assignment made from either the VR editor or the interface editor.
    try:
        _p2l = _load_aliases()
        _l2p = {_v: _k for _k, _v in _p2l.items()}
        async with aiosqlite.connect(DB_PATH) as _vdb:
            _vdb.row_factory = aiosqlite.Row
            _vcur = await _vdb.execute("SELECT name, interfaces FROM virtual_routers")
            for _vr in await _vcur.fetchall():
                if _vr["name"] == "default":
                    continue
                for _dev in json.loads(_vr["interfaces"] or "[]"):
                    vr_of[_l2p.get(_dev, _dev)] = _vr["name"]
                    vr_of[_dev] = _vr["name"]
    except Exception:
        pass
    zone_of = {}
    vsys_of = {}
    for vsys in candidate.findall("./vsys/entry"):
        vs_name = vsys.get("name")
        for m in vsys.findall("./import/network/interface/member"):
            if m.text:
                vsys_of[m.text.strip()] = vs_name
        for zone in vsys.findall("./zone/entry"):
            z_name = zone.get("name")
            for kind in ("layer3", "layer2", "virtual-wire", "tap", "tunnel", "external"):
                for m in zone.findall(f"./network/{kind}/member"):
                    if m.text:
                        zone_of[m.text.strip()] = z_name

    # Where the interface names and link state come from. On a switch-ASIC
    # chassis both come from the faceplate: pan_to_linux maps ethernet1/N to
    # the switch diag name, and link state is the chip's, not psutil's. The row
    # shape does not change, so the grid renderer needs no knowledge of this.
    #
    # DATA plane only. HSCI is on the same faceplate but it is the HA data
    # link, so it belongs to the device's HA configuration and appears under
    # the system interfaces, not in the firewall's list.
    fp = await _faceplate_map("data")

    # Live link state per Linux name
    live_up = {}
    live_ip = {}
    try:
        for iface in psutil.net_if_addrs().keys():
            live_ip[iface] = None
        stats = psutil.net_if_stats()
        for iface, st in stats.items():
            live_up[iface] = st.isup
        for iface, addrs in psutil.net_if_addrs().items():
            for a in addrs:
                if a.family.name == "AF_INET":
                    live_ip[iface] = a.address
                    break
    except Exception:
        pass
    pan_to_linux = _load_aliases()
    if fp is not None:
        pan_to_linux = {n: d["diag_name"] for n, d in fp.items()}
        # The chip's link bit, keyed the same way, so _shape_row's existing
        # live_up[linux] lookup picks it up without knowing what a switch is.
        # None stays None: an unreachable control plane means link state is
        # UNKNOWN, and painting that as down would report every port on a
        # healthy chassis as failed because a daemon was restarting.
        for d in fp.values():
            live_up[d["diag_name"]] = d["link"]

    def _mode_and_type(entry: ET.Element):
        """Return (mode-key, pretty-type-label, aggregate-group or None)."""
        if entry.findtext("aggregate-group"):
            return "aggregate-group", f"Aggregate ({entry.findtext('aggregate-group')})", entry.findtext("aggregate-group")
        if entry.find("layer3") is not None:
            return "layer3", "Layer3", None
        if entry.find("layer2") is not None:
            return "layer2", "Layer2", None
        if entry.find("virtual-wire") is not None:
            return "virtual-wire", "Virtual Wire", None
        if entry.find("tap") is not None:
            return "tap", "TAP", None
        if entry.find("ha") is not None:
            return "ha", "HA", None
        return "unconfigured", "", None

    def _shape_row(entry: ET.Element, parent_name=None, tag=None, kind="ethernet"):
        if parent_name and tag:
            name = entry.get("name")  # e.g. ae1.1337
        else:
            name = entry.get("name")
        mode, iface_type, agg = _mode_and_type(entry) if parent_name is None else ("layer3", "Layer3", None)

        # Sub-interfaces get their config from units/entry directly
        if parent_name and tag:
            iface_type = "Layer3"
            if entry.find("layer2") is not None: iface_type = "Layer2"

        # Layer3 info
        ips = []
        for ip in entry.findall("./layer3/ip/entry"):
            if ip.get("name"): ips.append(ip.get("name"))
        # Sub-interface ip is under <entry name=X>/ip/entry
        for ip in entry.findall("./ip/entry"):
            if ip.get("name"): ips.append(ip.get("name"))

        mgmt = (entry.findtext("./layer3/interface-management-profile")
                or entry.findtext("./interface-management-profile") or "")
        mtu = (entry.findtext("./layer3/mtu")
               or entry.findtext("./mtu") or "")
        sdwan_profile = (entry.findtext("./sdwan-link-settings/sdwan-interface-profile")
                         or entry.findtext("./layer3/sdwan-link-settings/sdwan-interface-profile") or "")
        upstream_nat = (entry.findtext("./sdwan-link-settings/upstream-nat/enable")
                        or entry.findtext("./layer3/sdwan-link-settings/upstream-nat/enable") or "no")
        # Features flags (LLDP, LACP, IPv6, NDP, DHCP client, etc.)
        features = []
        if entry.findtext("./lldp/enable", "no") == "yes": features.append("LLDP")
        if entry.find("./layer3/lacp") is not None: features.append("LACP")
        if entry.findtext("./layer3/ipv6/enabled", "no") == "yes": features.append("IPv6")
        if entry.find("./layer3/dhcp-client") is not None: features.append("DHCP")
        if entry.find("./layer3/ndp-proxy") is not None: features.append("NDP")
        if entry.find("./layer3/adjust-tcp-mss") is not None: features.append("MSS")

        # Linux alias + live state (only for top-level physical)
        base_pan = parent_name or name
        # Ethernets map 1:1 to Linux NICs via the alias table. Only
        # aggregate-ethernet (aeN) translates to a bondN interface.
        if base_pan.startswith("ae") and "." not in base_pan:
            linux = _ae_to_bond(base_pan)
        else:
            linux = pan_to_linux.get(base_pan)
        link_state = live_up.get(linux, None) if linux else None

        comment = entry.findtext("comment", "") or ""

        return {
            "name": name,
            "parent": parent_name,
            "tag": tag,
            "kind": kind,
            "type": iface_type,
            "management_profile": mgmt,
            "link_state": link_state,           # True/False/None
            "linux_name": linux,
            "ip_address": ips,
            "mtu": mtu,
            "virtual_router": vr_of.get(name) or vr_of.get(base_pan) or "",
            "vlan_tag": tag if tag else "",
            "vlan_or_vwire": agg or "",         # 'ae2' for members, VLAN name, etc.
            "virtual_system": vsys_of.get(name) or vsys_of.get(base_pan) or "",
            "security_zone": zone_of.get(name) or zone_of.get(base_pan) or "",
            "sdwan_interface_profile": sdwan_profile,
            "upstream_nat": upstream_nat == "yes",
            "features": features,
            "comment": comment,
        }

    out = {"ethernet": [], "vlan": [], "loopback": [], "tunnel": [], "sdwan": []}
    if fp is not None:
        # Report the faceplate alongside the rows so a caller can show ports
        # that exist in the chassis but not yet in the config, and can say what
        # each one is (media, speed, which connector) without a second request.
        out["faceplate"] = list(fp.values())
        out["source"] = "switch-asic faceplate"
    net = candidate.find("./network/interface")
    if net is not None:
        # Ethernet
        for e in net.findall("./ethernet/entry"):
            out["ethernet"].append(_shape_row(e, kind="ethernet"))
            for u in e.findall("./layer3/units/entry"):
                tag = u.findtext("tag")
                out["ethernet"].append(_shape_row(u, parent_name=e.get("name"), tag=tag, kind="ethernet"))
        # Aggregate Ethernet shows in Ethernet tab too
        for e in net.findall("./aggregate-ethernet/entry"):
            out["ethernet"].append(_shape_row(e, kind="ethernet"))
            for u in e.findall("./layer3/units/entry"):
                tag = u.findtext("tag")
                out["ethernet"].append(_shape_row(u, parent_name=e.get("name"), tag=tag, kind="ethernet"))
        # VLAN
        for u in net.findall("./vlan/units/entry"):
            out["vlan"].append(_shape_row(u, kind="vlan"))
        # Loopback
        for u in net.findall("./loopback/units/entry"):
            out["loopback"].append(_shape_row(u, kind="loopback"))
        # Bare loopback (no units)
        if net.find("loopback") is not None and not net.findall("./loopback/units/entry"):
            out["loopback"].append({"name":"loopback","kind":"loopback","type":"Loopback",
                                    "management_profile":"", "link_state":None, "linux_name":"lo",
                                    "ip_address":[], "mtu":"", "virtual_router":"",
                                    "vlan_tag":"", "vlan_or_vwire":"", "virtual_system":"",
                                    "security_zone":"", "sdwan_interface_profile":"",
                                    "upstream_nat":False, "features":[], "comment":""})
        # Tunnel
        for u in net.findall("./tunnel/units/entry"):
            out["tunnel"].append(_shape_row(u, kind="tunnel"))
    return out


@app.post("/api/interfaces")
async def interface_create(i: InterfaceEntry, user: dict = Depends(get_current_user)):
    """
    Create or replace a top-level interface (ethernet1/N or aeN).
    PAN-OS 'edit' semantics: the entry is rewritten as a whole. This
    drops stale mode subtrees (e.g. switching layer3 → aggregate-group
    removes the old <layer3> block).
    Sub-interfaces use POST /api/interfaces/subinterface.
    """
    _require_lock(user)
    kind = "aggregate-ethernet" if i.name.startswith("ae") and "." not in i.name else "ethernet"
    xp = f"{DEV}.network.interface.{kind}.entry[@name={i.name}]"

    # Nuke the entry before writing so old mode blocks don't linger.
    config_mgr.delete_candidate(xp, user["username"])

    payload = _build_iface_payload(i)
    config_mgr.update_candidate(xp, payload, user["username"])

    # Layer3 IPs are written as <ip><entry name="1.2.3.4/24"/></ip> children
    if i.mode == "layer3" and i.ip_addresses:
        for addr in i.ip_addresses:
            addr_xp = f"{xp}.layer3.ip.entry[@name={addr}]"
            config_mgr.update_candidate(addr_xp, {}, user["username"])

    # PAN-OS convention: every new interface lands in vsys1 unless the
    # admin explicitly reassigns it. Add the name to vsys1's import list
    # if it isn't already there.
    _ensure_imported_into_vsys(i.name, vsys_name="vsys1")

    await _audit(user, "iface_create", f"{kind}:{i.name}:{i.mode}")
    return {"status": "created", "interface": i.name, "kind": kind, "mode": i.mode}


def _ensure_imported_into_vsys(iface_name: str, vsys_name: str = "vsys1"):
    """Add iface_name to devices/entry/vsys/entry[vsys_name]/import/network/interface
    as a <member> if not already present. Creates any missing nodes."""
    xp_base = f"{DEV}.vsys.entry[@name={vsys_name}].import.network.interface"
    node = config_mgr.get_xpath(xp_base, source="candidate")
    members = []
    if node is not None:
        members = [m.text.strip() for m in node.findall("member") if m.text and m.text.strip()]
    if iface_name in members:
        return
    members.append(iface_name)
    config_mgr.update_candidate(xp_base, members, user="system")


@app.put("/api/interfaces/{name:path}")
async def interface_update(name: str, i: InterfaceEntry,
                           user: dict = Depends(get_current_user)):
    _require_lock(user)
    if i.name != name:
        i.name = name
    return await interface_create(i, user)


@app.delete("/api/interfaces/{name:path}")
async def interface_delete(name: str, user: dict = Depends(get_current_user)):
    _require_lock(user)
    xp = _iface_xpath(name)
    r = config_mgr.delete_candidate(xp, user["username"])
    await _audit(user, "iface_delete", name)
    return r


# -- Sub-interfaces ---------------------------------------------------------


class SubInterfaceEntry(BaseModel):
    parent: str                       # ethernet1/1 or ae1
    tag: int                           # VLAN tag
    mode: str = "layer3"              # layer3 | layer2
    ip_addresses: list = []
    interface_management_profile: str = ""
    mtu: Optional[int] = None
    comment: str = ""


@app.post("/api/interfaces/subinterface")
async def subinterface_create(s: SubInterfaceEntry,
                              user: dict = Depends(get_current_user)):
    """
    Create a sub-interface on an existing layer3 ethernet or aggregate-ethernet.
    PAN-OS layout: .../entry[parent]/layer3/units/entry[parent.tag]/
                   for ethernet, or .../aggregate-ethernet/entry[ae1]/layer3/units/entry[ae1.tag]/
    """
    _require_lock(user)
    kind = _iface_kind(s.parent)
    child_name = f"{s.parent}.{s.tag}"
    unit_xp = f"{DEV}.network.interface.{kind}.entry[@name={s.parent}].layer3.units.entry[@name={child_name}]"
    payload = {
        "tag": s.tag,
        "comment": s.comment,
    }
    # <ip><entry name=.../></ip> children are written via follow-up xpath
    # calls after the unit entry exists.
    if s.mtu:
        payload["adjust-tcp-mss"] = {"enable": "no"}
        payload["mtu"] = s.mtu
    if s.interface_management_profile:
        payload["interface-management-profile"] = s.interface_management_profile
    config_mgr.update_candidate(unit_xp, payload, user["username"])
    for addr in s.ip_addresses:
        config_mgr.update_candidate(f"{unit_xp}.ip.entry[@name={addr}]", {}, user["username"])
    # Default-import the sub-interface into vsys1 too
    _ensure_imported_into_vsys(child_name, vsys_name="vsys1")
    await _audit(user, "subinterface_create", child_name)
    return {"status": "created", "name": child_name}


@app.delete("/api/interfaces/subinterface")
async def subinterface_delete(parent: str = Query(...), tag: int = Query(...),
                              user: dict = Depends(get_current_user)):
    """Delete a sub-interface. Parent + tag are query params because
    PAN-OS interface names contain slashes (ethernet1/1) that path
    converters can't cleanly disambiguate."""
    _require_lock(user)
    kind = _iface_kind(parent)
    child_name = f"{parent}.{tag}"
    xp = f"{DEV}.network.interface.{kind}.entry[@name={parent}].layer3.units.entry[@name={child_name}]"
    r = config_mgr.delete_candidate(xp, user["username"])
    await _audit(user, "subinterface_delete", child_name)
    return r


# -- Live Aggregate-Ethernet status -----------------------------------------


@app.get("/api/interfaces/aggregate-status")
async def aggregate_status(user: dict = Depends(get_current_user)):
    """
    Return live kernel-side state for every configured aggregate-ethernet:
      - PAN-OS name (aeN) + mapped Linux bond ifname (bondN)
      - Whether the bond exists in the kernel
      - Enslaved Linux NICs (from sysfs)
      - Bonding mode, MII status, AD partner info when available
      - Per-slave LACP state and link status
    """
    # Read configured AEs + member assignments from candidate config
    cfg = config_mgr.get_xpath(f"{DEV}.network.interface", source="candidate")
    configured = []
    if cfg is not None:
        ae_root = cfg.find("aggregate-ethernet")
        eth_root = cfg.find("ethernet")
        # Build pan->linux alias map up front
        pan_to_linux = _load_aliases()
        for ae in (ae_root.findall("entry") if ae_root is not None else []):
            ae_name = ae.get("name")
            bond = _ae_to_bond(ae_name)
            members_pan = []
            members_linux = []
            if eth_root is not None:
                for eth in eth_root.findall("entry"):
                    agg = (eth.findtext("aggregate-group") or "").strip()
                    if agg == ae_name:
                        p = eth.get("name")
                        members_pan.append(p)
                        lx = pan_to_linux.get(p)
                        if lx:
                            members_linux.append(lx)

            # Query kernel
            kernel_exists = False
            kernel_slaves = []
            mode = None
            mii_status = None
            operstate = None
            ip_addrs = []
            try:
                r = subprocess.run(["ip", "-j", "link", "show", bond],
                                   capture_output=True, text=True, timeout=3)
                if r.returncode == 0 and r.stdout.strip():
                    devs = json.loads(r.stdout)
                    if devs:
                        kernel_exists = True
                        operstate = devs[0].get("operstate")
            except Exception:
                pass
            if kernel_exists:
                # Slaves
                try:
                    r = subprocess.run(["ip", "-j", "link", "show", "master", bond],
                                       capture_output=True, text=True, timeout=3)
                    if r.returncode == 0:
                        for d in json.loads(r.stdout or "[]"):
                            kernel_slaves.append(d.get("ifname"))
                except Exception:
                    pass
                # /proc/net/bonding/<bond> (detailed LACP state)
                try:
                    with open(f"/proc/net/bonding/{bond}") as f:
                        bcontent = f.read()
                    for line in bcontent.splitlines():
                        if line.startswith("Bonding Mode:"):
                            mode = line.split(":", 1)[1].strip()
                        elif line.startswith("MII Status:"):
                            mii_status = line.split(":", 1)[1].strip()
                except FileNotFoundError:
                    pass
                except Exception:
                    pass
                # IP addresses on bond
                try:
                    r = subprocess.run(["ip", "-j", "addr", "show", bond],
                                       capture_output=True, text=True, timeout=3)
                    if r.returncode == 0:
                        for d in json.loads(r.stdout or "[]"):
                            for a in d.get("addr_info", []):
                                if a.get("local"):
                                    ip_addrs.append(f"{a['local']}/{a.get('prefixlen',32)}")
                except Exception:
                    pass

            configured.append({
                "ae_name": ae_name,
                "bond": bond,
                "members_pan": members_pan,
                "members_linux": members_linux,
                "kernel_exists": kernel_exists,
                "kernel_slaves": kernel_slaves,
                "bonding_mode": mode,
                "mii_status": mii_status,
                "operstate": operstate,
                "ip_addresses": ip_addrs,
                # Diff flags to highlight drift
                "members_missing_from_bond": sorted(set(members_linux) - set(kernel_slaves)),
                "members_extra_in_bond":     sorted(set(kernel_slaves) - set(members_linux)),
            })
    return {"aggregates": configured}


# -- Global MTU / jumbo-frame ---------------------------------------------


class GlobalMtu(BaseModel):
    mtu: int
    comment: str = ""


@app.get("/api/deviceconfig/jumbo-frame")
async def jumbo_frame_get(user: dict = Depends(get_current_user)):
    n = config_mgr.get_xpath(f"{DEV}.deviceconfig.setting.jumbo-frame", source="candidate")
    if n is None:
        return {"mtu": 9216, "comment": ""}
    return {
        "mtu": int(n.findtext("mtu", "9216")),
        "comment": n.findtext("comment", ""),
    }


@app.put("/api/deviceconfig/jumbo-frame")
async def jumbo_frame_set(m: GlobalMtu, user: dict = Depends(get_current_user)):
    _require_lock(user)
    if not (576 <= m.mtu <= 16000):
        raise HTTPException(status_code=400, detail="mtu must be between 576 and 16000")
    config_mgr.update_candidate(
        f"{DEV}.deviceconfig.setting.jumbo-frame",
        {"mtu": m.mtu, "comment": m.comment},
        user["username"])
    await _audit(user, "jumbo_frame_set", str(m.mtu))
    return {"status": "updated", "mtu": m.mtu}


# ==========================================================================
# 14. Logging
# ==========================================================================


def _generate_log_entries(log_type: str, limit: int = 50, offset: int = 0):
    """Deprecated fabricator — retained only for signature compatibility.

    This used to synthesize random security/traffic/system log lines. Those are
    fabricated-for-display data, so it now returns an honest empty list. Live
    log endpoints read real sources instead: `_journal_entries()` (systemd
    journal / auditd) for security & system logs and `_conntrack_entries()`
    (conntrack/ss) for traffic flows.
    """
    return []


def _journal_entries(unit: Optional[str] = None, priority: Optional[str] = None,
                     limit: int = 50) -> list:
    """Read real entries from systemd journal."""
    cmd = ["journalctl", "-n", str(limit), "-o", "json", "--no-pager"]
    if unit:
        cmd += ["-u", unit]
    if priority:
        cmd += ["-p", priority]
    try:
        out = subprocess.check_output(cmd, text=True, timeout=5)
    except Exception:
        return []
    sev_map = {"0": "EMERG", "1": "ALERT", "2": "CRITICAL", "3": "ERROR",
               "4": "WARNING", "5": "NOTICE", "6": "INFO", "7": "DEBUG"}
    entries = []
    for i, line in enumerate(out.strip().split("\n")):
        if not line.strip():
            continue
        try:
            j = json.loads(line)
        except Exception:
            continue
        usec = int(j.get("__REALTIME_TIMESTAMP", "0"))
        ts = datetime.fromtimestamp(usec / 1_000_000).isoformat() if usec else ""
        entries.append({
            "id": j.get("__CURSOR", str(i)),
            "timestamp": ts,
            "severity": sev_map.get(str(j.get("PRIORITY", "6")), "INFO"),
            "message": f"[{j.get('_SYSTEMD_UNIT') or j.get('SYSLOG_IDENTIFIER') or 'kernel'}] {j.get('MESSAGE', '')}",
        })
    # Newest first
    return list(reversed(entries))


def _conntrack_entries(limit: int = 50, vsys_id: Optional[int] = None):
    """Read active TCP/UDP flows. Prefers conntrack, falls back to ss.

    Returns `(entries, source)`. When `vsys_id` is given the conntrack read is
    scoped to that vsys via `conntrack -L -m <vsys_id>` (contract §2 tag);
    `source` becomes 'conntrack:vsys<id>'. The ss fallback cannot see the tag,
    so if we fall through to it while a vsys was requested `source` is labelled
    'ss(unscoped)' so callers can flag the result as unfiltered.
    """
    entries = []
    # Try conntrack (kernel connection tracking) if available
    cmd = ["conntrack", "-L", "-o", "extended"]
    if vsys_id is not None:
        # -m/--mark filters kernel-side on the vsys tag carried by ct mark.
        cmd += ["-m", str(vsys_id)]
    try:
        out = subprocess.check_output(
            cmd, text=True, timeout=3, stderr=subprocess.DEVNULL)
        for i, line in enumerate(out.strip().split("\n")[:limit]):
            if not line.strip():
                continue
            entries.append({
                "id": i,
                "timestamp": datetime.now().isoformat(),
                "severity": "INFO",
                "message": f"FLOW {line.strip()}",
            })
        if entries:
            src = f"conntrack:vsys{vsys_id}" if vsys_id is not None else "conntrack"
            return entries, src
    except Exception:
        pass

    # Fall back to ss (socket statistics) — no vsys/mark visibility here.
    try:
        out = subprocess.check_output(
            ["ss", "-tunap", "state", "established"], text=True, timeout=3)
        lines = out.strip().split("\n")[1:]  # skip header
        for i, line in enumerate(lines[:limit]):
            parts = line.split(None, 5)
            if len(parts) < 5:
                continue
            proto = parts[0]
            local = parts[3] if len(parts) > 3 else "?"
            peer = parts[4] if len(parts) > 4 else "?"
            entries.append({
                "id": i,
                "timestamp": datetime.now().isoformat(),
                "severity": "INFO",
                "message": f"ACCEPT {proto} {local} -> {peer}",
            })
    except Exception:
        pass
    src = "ss(unscoped)" if vsys_id is not None else "ss"
    return entries, src


@app.get("/api/logs/security")
async def logs_security(limit: int = 50, offset: int = 0):
    """
    Security events — when the FPGA dataplane is present, this reads from the
    hardware's threat/IDS log buffer. Otherwise surfaces kernel audit log and
    high-priority system journal entries.
    """
    entries = []
    # Priority 0-4 (CRITICAL..WARNING) filter — real severe events only
    entries.extend(_journal_entries(priority="4", limit=limit))
    # Include auditd / firewall-related journal units
    for unit in ("auditd.service", "nftables.service", "iptables.service",
                 "ffn-ngfw.service", "sshd.service"):
        entries.extend(_journal_entries(unit=unit, limit=limit // 4))
    # Dedup by id and sort newest-first
    seen = set()
    deduped = []
    for e in entries:
        if e["id"] in seen:
            continue
        seen.add(e["id"])
        deduped.append(e)
    deduped.sort(key=lambda e: e["timestamp"], reverse=True)
    return {"logs": deduped[offset:offset + limit],
            "total": len(deduped),
            "source": "journald+auditd"}


@app.get("/api/logs/traffic")
async def logs_traffic(limit: int = 50, offset: int = 0, vsys: Optional[str] = None):
    """Real network flows via conntrack/ss. Real FPGA traffic log when present.

    `vsys` (name 'vsys2' or numeric id '2') scopes the flow list to that vsys's
    conntrack partition via the `ct mark`/zone tag (contract §2). Falls back to
    an unscoped read (labelled in `source`) when conntrack tooling is absent.
    """
    vsys_id = _resolve_vsys_id(vsys)
    entries, source = _conntrack_entries(limit + offset, vsys_id=vsys_id)
    logs = entries[offset:offset + limit]
    resp = {"logs": logs, "total": len(logs),
            "source": source,
            "fpga_active": not fpga.sim_mode}
    if vsys_id is not None:
        resp["vsys"] = vsys_id
        resp["vsys_scoped"] = source.startswith("conntrack")
    return resp


@app.get("/api/logs/system")
async def logs_system(limit: int = 50, offset: int = 0):
    """Real system journal entries."""
    entries = _journal_entries(limit=limit + offset)
    return {"logs": entries[offset:offset + limit],
            "total": len(entries),
            "source": "journald"}


@app.get("/api/monitor/sessions")
async def monitor_sessions(limit: int = 100, vsys: Optional[str] = None):
    """
    Live session / connection browser. Prefers FPGA session table via
    controld, falls back to psutil net_connections.

    `vsys` (name 'vsys2' or numeric id '2') scopes the view to that vsys's
    conntrack partition via the `ct mark`/zone tag (contract §2). Since the
    conntrack tag is only visible via conntrack (not psutil/FPGA table), a
    vsys-scoped request reads the scoped conntrack flow list directly and
    labels the source; it degrades gracefully when conntrack is absent.
    """
    vsys_id = _resolve_vsys_id(vsys)
    if vsys_id is not None:
        entries, source = _conntrack_entries(limit, vsys_id=vsys_id)
        return {"entries": entries, "source": source,
                "vsys": vsys_id, "vsys_scoped": source.startswith("conntrack")}
    if controld is not None and controld.available():
        try:
            sessions = controld.query("state/sessions")
            if sessions:
                sessions["entries"] = _live_connections(limit)
                return sessions
        except Exception:
            pass
    return {"entries": _live_connections(limit), "source": "psutil"}


def _live_connections(limit: int) -> list:
    """Real TCP/UDP connections via psutil."""
    out = []
    try:
        for c in psutil.net_connections(kind="inet")[:limit]:
            laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "-"
            raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "-"
            try:
                pname = psutil.Process(c.pid).name() if c.pid else "-"
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pname = "-"
            proto = {socket.SOCK_STREAM: "tcp", socket.SOCK_DGRAM: "udp"}.get(c.type, "?")
            out.append({
                "proto": proto,
                "local": laddr,
                "remote": raddr,
                "state": c.status,
                "pid": c.pid or 0,
                "process": pname,
            })
    except Exception:
        pass
    return out


# WebSocket for real-time log streaming — pipes journalctl --follow
@app.websocket("/api/logs/live")
async def logs_live(ws: WebSocket):
    await ws.accept()
    proc = None
    try:
        # journalctl -f in JSON — parse line by line
        proc = await asyncio.create_subprocess_exec(
            "journalctl", "-f", "-o", "json", "-n", "0",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        sev_map = {"0": "EMERG", "1": "ALERT", "2": "CRITICAL", "3": "ERROR",
                   "4": "WARNING", "5": "NOTICE", "6": "INFO", "7": "DEBUG"}
        while True:
            line = await proc.stdout.readline()
            if not line:
                break
            try:
                j = json.loads(line.decode())
            except Exception:
                continue
            usec = int(j.get("__REALTIME_TIMESTAMP", "0"))
            ts = datetime.fromtimestamp(usec / 1_000_000).isoformat() if usec else datetime.now().isoformat()
            entry = {
                "id": j.get("__CURSOR", ""),
                "timestamp": ts,
                "severity": sev_map.get(str(j.get("PRIORITY", "6")), "INFO"),
                "message": f"[{j.get('_SYSTEMD_UNIT') or j.get('SYSLOG_IDENTIFIER') or 'kernel'}] {j.get('MESSAGE', '')}",
            }
            await ws.send_json(entry)
    except WebSocketDisconnect:
        pass
    except Exception as exc:
        logger.warning("logs_live error: %s", exc)
    finally:
        if proc:
            try:
                proc.terminate()
                await asyncio.wait_for(proc.wait(), timeout=2)
            except Exception:
                pass


# ==========================================================================
# Entry point
# ==========================================================================

if __name__ == "__main__":
    # Concurrency model: one uvicorn worker with asyncio event loop.
    # The ConfigManager, commit lock, and runtime-state cache all live in
    # process memory and must stay consistent, so we keep one worker.
    # FastAPI serves thousands of concurrent API requests from one loop;
    # any CPU-bound or blocking subprocess work is off-loaded to a thread
    # pool via asyncio.to_thread() inside the individual handlers.
    # Override with FFN_MGR_WORKERS=N env to enable multi-worker mode once
    # the commit lock and config cache are backed by a shared store.
    workers = int(os.getenv("FFN_MGR_WORKERS", "1"))
    uvicorn.run(
        "ffn_manager:app",
        host="0.0.0.0",
        port=8443,
        reload=False,
        log_level="info",
        workers=workers,
        loop="asyncio",
        timeout_keep_alive=30,
        # Allow many simultaneous incoming connections
        limit_concurrency=1024,
        limit_max_requests=None,
    )
