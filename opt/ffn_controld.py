#!/usr/bin/env python3
"""
ffn-controld — FFN NGFW Control Plane Daemon

This is the single persistent backend process that owns runtime state
and drives every control-plane subsystem. Both the web UI (via
ffn_manager.py) and the CLI (ffn-cli) connect to it for any non-trivial
operation.

Responsibilities:
  - Aggregate live state: interfaces, sessions, routes, ARP, counters,
    FPGA engines, DPDK stats, VPN tunnels, HA status.
  - Talk to protocol daemons: FRR (vtysh), strongSwan (swanctl),
    ZeroTier (zerotier-cli), DHCP.
  - Talk to the dataplane: FPGA via /dev/ngfw0, DPDK via unix socket.
  - Orchestrate commits: candidate XML -> ffn-configd signal -> wait
    for apply-status -> return result to caller.
  - Cache expensive queries with short TTLs so the API layer doesn't
    hammer the kernel / FPGA every 3 seconds.

Transport:
  - Unix domain socket at /var/run/ffn-ngfw/controld.sock (NEWLINE-
    delimited JSON, request/response). Permissions 660, group ffn-mgmt.
  - Callers: ffn_manager.py (HTTP API), ffn-cli (optional fast path),
    ffn-wildfire-agent, ffn-route-agent.

Why a separate daemon?
  - The HTTP manager runs as a non-root sandboxed user. Many control
    operations need netlink, privileged socket calls, or FRR vtysh —
    things you don't want to hand to a web worker.
  - Persistent state (session cache, connection pool to FRR/strongSwan,
    FPGA memory map) is expensive to set up on every HTTP request.
  - CLI users can talk to controld directly over the unix socket,
    bypassing HTTP entirely for sub-millisecond command latency.
"""

import argparse
import asyncio
import hashlib
import json
import logging
import os
import signal
import socket
import struct
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from ffn_control_plane import CONTROL_LIMIT, ControlPlane, load_config
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

CONFIG_DIR = Path(os.getenv("FFN_CONFIG_DIR", "/var/lib/ffn-ngfw/config"))
RUNNING_CONFIG = CONFIG_DIR / "running-config.xml"
CANDIDATE_CONFIG = CONFIG_DIR / "candidate-config.xml"
HISTORY_MANIFEST = CONFIG_DIR / "history" / "manifest.json"
APPLY_STATUS = CONFIG_DIR / "apply-status.json"
RUN_DIR = Path(os.getenv("FFN_RUN_DIR", "/var/run/ffn-ngfw"))
SOCKET_PATH = Path(os.getenv("FFN_CONTROLD_SOCKET", str(RUN_DIR / "controld.sock")))
CONFIGD_SIGNAL = os.getenv("FFN_CONFIGD_SIGNAL", "sighup")  # how to nudge ffn-configd
DEV_PATH = os.getenv("FFN_NGFW_DEV", "/dev/ngfw0")
DPDK_SOCKET = os.getenv("FFN_DPDK_SOCKET", str(RUN_DIR / "dpdk.sock"))
DPD_SOCKET = Path(os.getenv("FFN_DPD_SOCKET", str(RUN_DIR / "dpd.sock")))
LOG_PATH = "/var/log/ffn-ngfw/controld.log"

# Permissions for the unix socket
SOCKET_GROUP = os.getenv("FFN_CONTROLD_GROUP", "ffn-mgmt")
SOCKET_MODE = 0o660

# Default TTLs for cached state (seconds)
TTL_INTERFACES = 2
TTL_ROUTES = 5
TTL_ARP = 5
TTL_FRR = 5
TTL_SESSIONS = 2

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
try:
    Path(LOG_PATH).parent.mkdir(parents=True, exist_ok=True)
    fh = logging.FileHandler(LOG_PATH)
    fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s"))
    logging.getLogger().addHandler(fh)
except Exception:
    pass
logger = logging.getLogger("ffn-controld")


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------


def run(cmd: list, timeout: float = 5.0, check: bool = False) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True,
                          timeout=timeout, check=check)


def has_cmd(cmd: str) -> bool:
    return subprocess.run(["which", cmd], capture_output=True, timeout=2).returncode == 0


class TTLCache:
    """Tiny in-memory cache with per-entry TTL."""
    def __init__(self):
        self._s: Dict[str, tuple] = {}

    def get(self, key: str):
        v = self._s.get(key)
        if v is None:
            return None
        expires, value = v
        if time.time() > expires:
            self._s.pop(key, None)
            return None
        return value

    def set(self, key: str, value, ttl: float):
        self._s[key] = (time.time() + ttl, value)

    def invalidate(self, key: Optional[str] = None):
        if key is None:
            self._s.clear()
        else:
            self._s.pop(key, None)


# ---------------------------------------------------------------------------
# Adapters — each wraps one external subsystem
# ---------------------------------------------------------------------------


class FpgaAdapter:
    """Reads runtime stats from /dev/ngfw0 via ioctls."""
    IOCTL_READ_REG = 0xC0084E00
    IOCTL_WRITE_REG = 0xC0084E01

    # Important register offsets (must match ngfw_regs.h)
    REG_VERSION = 0x0000
    REG_STATUS = 0x0004
    REG_PORT_BASE = 0x1000
    REG_PORT_STRIDE = 0x0100
    REG_ENGINE_BASE = 0x4000
    REG_ENGINE_STRIDE = 0x0040
    REG_SESSION_BASE = 0xE000

    def __init__(self, path: str = DEV_PATH):
        self.path = path
        self.available = os.path.exists(path)
        self._fd = None
        if self.available:
            try:
                self._fd = os.open(path, os.O_RDWR)
                logger.info("FPGA adapter: opened %s", path)
            except OSError as exc:
                logger.warning("FPGA adapter: cannot open %s (%s) — read-only", path, exc)
                self.available = False

    def close(self):
        if self._fd is not None:
            try:
                os.close(self._fd)
            except Exception:
                pass
            self._fd = None

    def read_reg(self, offset: int) -> int:
        if not self.available or self._fd is None:
            return 0
        import fcntl
        try:
            buf = struct.pack("II", offset, 0)
            result = fcntl.ioctl(self._fd, self.IOCTL_READ_REG, buf)
            return struct.unpack("II", result)[1]
        except Exception as exc:
            logger.warning("FPGA read 0x%04X failed: %s", offset, exc)
            return 0

    def port_stats(self, port: int) -> dict:
        base = self.REG_PORT_BASE + port * self.REG_PORT_STRIDE
        return {
            "link_up": bool(self.read_reg(base) & 1),
            "rx_bytes": (self.read_reg(base + 8) << 32) | self.read_reg(base + 4),
            "tx_bytes": (self.read_reg(base + 16) << 32) | self.read_reg(base + 12),
            "rx_packets": self.read_reg(base + 20),
            "tx_packets": self.read_reg(base + 24),
            "rx_drops": self.read_reg(base + 28),
        }

    def session_stats(self) -> dict:
        return {
            "active": self.read_reg(self.REG_SESSION_BASE),
            "hits": self.read_reg(self.REG_SESSION_BASE + 4),
            "misses": self.read_reg(self.REG_SESSION_BASE + 8),
        }


class DpdkAdapter:
    """Unix-socket IPC to whichever DPDK primary process is running
    (ffn-dpdk-runtime testpmd or legacy ffn_dpdk_fwd forwarder). The
    socket path is the same in both cases — /var/run/ffn-ngfw/dpdk.sock —
    so the adapter doesn't need to know which flavor is live."""
    def __init__(self, path: str = DPDK_SOCKET):
        self.path = path

    def available(self) -> bool:
        return os.path.exists(self.path)

    def query(self, op: str, **kw) -> dict:
        if not self.available():
            return {"ok": False, "error": "DPDK socket absent"}
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(3.0)
        try:
            s.connect(self.path)
            msg = {"op": op, **kw}
            s.sendall((json.dumps(msg) + "\n").encode())
            data = b""
            while not data.endswith(b"\n"):
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
            return json.loads(data.decode()) if data else {}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}
        finally:
            s.close()


class FrrAdapter:
    """Query FRRouting via vtysh -c 'show ip bgp summary' etc."""
    def __init__(self):
        self.available = has_cmd("vtysh")

    def show(self, cmd: str) -> str:
        if not self.available:
            return ""
        try:
            r = run(["vtysh", "-c", cmd], timeout=5)
            return r.stdout
        except Exception:
            return ""

    def bgp_summary(self) -> dict:
        text = self.show("show ip bgp summary json")
        if not text:
            return {"running": False}
        try:
            return json.loads(text)
        except Exception:
            return {"running": True, "raw": text[:2048]}

    def ospf_summary(self) -> dict:
        text = self.show("show ip ospf json")
        if not text:
            return {"running": False}
        try:
            return json.loads(text)
        except Exception:
            return {"running": True, "raw": text[:2048]}


class NetlinkAdapter:
    """Read real kernel state: interfaces, routes, ARP via `ip -j ...`."""
    def interfaces(self) -> list:
        try:
            r = run(["ip", "-j", "-s", "addr", "show"], timeout=3)
            if r.returncode != 0:
                return []
            return json.loads(r.stdout)
        except Exception:
            return []

    def routes(self) -> list:
        try:
            r = run(["ip", "-j", "route", "show"], timeout=3)
            if r.returncode != 0:
                return []
            return json.loads(r.stdout)
        except Exception:
            return []

    def neighbors(self) -> list:
        try:
            r = run(["ip", "-j", "neigh", "show"], timeout=3)
            if r.returncode != 0:
                return []
            return json.loads(r.stdout)
        except Exception:
            return []

    def route_add(self, dest: str, via: str, dev: Optional[str] = None,
                  metric: int = 100) -> dict:
        cmd = ["ip", "route", "add", dest, "via", via]
        if dev:
            cmd += ["dev", dev]
        cmd += ["metric", str(metric)]
        r = run(cmd, timeout=5)
        return {"ok": r.returncode == 0, "stdout": r.stdout, "stderr": r.stderr}

    def route_del(self, dest: str) -> dict:
        r = run(["ip", "route", "del", dest], timeout=5)
        return {"ok": r.returncode == 0, "stderr": r.stderr}


class SwanctlAdapter:
    """strongSwan swanctl for IPsec SA state."""
    def __init__(self):
        self.available = has_cmd("swanctl")

    def list_sas(self) -> list:
        if not self.available:
            return []
        try:
            r = run(["swanctl", "--list-sas", "--raw"], timeout=5)
            # swanctl --raw emits one vici-style record per line — simpler to
            # parse --list-sas normally and just return the text for now
            r = run(["swanctl", "--list-sas"], timeout=5)
            return [l for l in r.stdout.splitlines() if l.strip()]
        except Exception:
            return []


class ZeroTierAdapter:
    """zerotier-cli wrapper."""
    def __init__(self):
        self.available = has_cmd("zerotier-cli")

    def networks(self) -> list:
        if not self.available:
            return []
        try:
            r = run(["zerotier-cli", "-j", "listnetworks"], timeout=5)
            return json.loads(r.stdout) if r.returncode == 0 else []
        except Exception:
            return []

    def peers(self) -> list:
        if not self.available:
            return []
        try:
            r = run(["zerotier-cli", "-j", "peers"], timeout=5)
            return json.loads(r.stdout) if r.returncode == 0 else []
        except Exception:
            return []


# ---------------------------------------------------------------------------
# Data-plane daemon client (ffn-dpd proxy)
# ---------------------------------------------------------------------------


class DpdClient:
    """
    Thin sync-over-async client for the data-plane daemon IPC socket.
    Used when the manager (via controld proxy) asks for compiled-rule
    state, session snapshots, or hit counters. Re-opens the socket on
    each call — ffn-dpd is local and cheap to connect to.
    """

    def __init__(self, path: Path = DPD_SOCKET):
        self.path = path

    @property
    def available(self) -> bool:
        return self.path.exists()

    def call(self, cmd: str, data: Optional[dict] = None,
             timeout: float = 3.0) -> dict:
        if not self.available:
            return {"ok": False, "error": "ffn-dpd not running"}
        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect(str(self.path))
            req = json.dumps({"cmd": cmd, "data": data or {}}).encode() + b"\n"
            s.sendall(req)
            # Read up to one \n-terminated JSON document
            buf = b""
            while b"\n" not in buf:
                chunk = s.recv(65536)
                if not chunk:
                    break
                buf += chunk
            s.close()
            line, _, _ = buf.partition(b"\n")
            return json.loads(line.decode())
        except Exception as exc:
            return {"ok": False, "error": str(exc)}


# ---------------------------------------------------------------------------
# Commit orchestration
# ---------------------------------------------------------------------------


class CommitOrchestrator:
    """Owns the commit lock and coordinates candidate -> running -> apply."""

    COMMIT_LOCK_TIMEOUT = 300

    def __init__(self):
        self._holder: Optional[str] = None
        self._acquired_at: float = 0
        self._reason: str = ""

    def lock_status(self) -> dict:
        if self._holder:
            age = time.time() - self._acquired_at
            if age > self.COMMIT_LOCK_TIMEOUT:
                self._holder = None
                return {"locked": False}
            return {
                "locked": True,
                "holder": self._holder,
                "reason": self._reason,
                "acquired_at": datetime.fromtimestamp(self._acquired_at).isoformat(),
                "age_seconds": int(age),
                "expires_in": int(self.COMMIT_LOCK_TIMEOUT - age),
            }
        return {"locked": False}

    def acquire(self, user: str, reason: str = "commit") -> bool:
        st = self.lock_status()
        if st["locked"] and st["holder"] != user:
            return False
        self._holder = user
        self._acquired_at = time.time()
        self._reason = reason
        return True

    def release(self, user: str) -> bool:
        if self._holder == user:
            self._holder = None
            self._reason = ""
            return True
        return False

    def nudge_configd(self):
        """Signal ffn-configd that running-config has changed. Inotify already
        picks this up via IN_CLOSE_WRITE, but we also send SIGHUP as a
        belt-and-suspenders fallback."""
        try:
            pid_file = Path("/var/run/ffn-configd.pid")
            if pid_file.exists():
                pid = int(pid_file.read_text().strip())
                os.kill(pid, signal.SIGHUP)
                logger.info("Sent SIGHUP to ffn-configd pid=%d", pid)
        except Exception as exc:
            logger.debug("Could not signal configd: %s", exc)

    def read_apply_status(self, timeout: float = 10.0) -> dict:
        """Wait for ffn-configd to finish and return its apply-status.json."""
        deadline = time.time() + timeout
        last_mtime = APPLY_STATUS.stat().st_mtime if APPLY_STATUS.exists() else 0
        while time.time() < deadline:
            if APPLY_STATUS.exists() and APPLY_STATUS.stat().st_mtime > last_mtime:
                try:
                    return json.loads(APPLY_STATUS.read_text())
                except Exception:
                    pass
            time.sleep(0.1)
        return {"overall": "unknown", "message": "configd did not report within timeout"}


# ---------------------------------------------------------------------------
# Runtime state aggregator
# ---------------------------------------------------------------------------


class RuntimeState:
    """Single-source-of-truth for live state — cached, refreshed on demand."""

    def __init__(self):
        self.cache = TTLCache()
        self.fpga = FpgaAdapter()
        self.dpdk = DpdkAdapter()
        self.nl = NetlinkAdapter()
        self.frr = FrrAdapter()
        self.ipsec = SwanctlAdapter()
        self.zt = ZeroTierAdapter()
        self.dpd = DpdClient()

    # -- live queries ----------------------------------------------------

    def interfaces(self) -> list:
        cached = self.cache.get("interfaces")
        if cached is not None:
            return cached
        out = []
        for ifa in self.nl.interfaces():
            name = ifa.get("ifname", "?")
            if name == "lo":
                continue
            addrs = ifa.get("addr_info", []) or []
            ip_addr = next((a["local"] for a in addrs if a.get("family") == "inet"), "")
            out.append({
                "name": name,
                "type": "cpu",
                "link_up": ifa.get("operstate") == "UP",
                "mac": ifa.get("address", ""),
                "mtu": ifa.get("mtu", 0),
                "ip_address": ip_addr,
                "rx_bytes": (ifa.get("stats64", {}).get("rx", {}) or {}).get("bytes", 0),
                "tx_bytes": (ifa.get("stats64", {}).get("tx", {}) or {}).get("bytes", 0),
                "rx_packets": (ifa.get("stats64", {}).get("rx", {}) or {}).get("packets", 0),
                "tx_packets": (ifa.get("stats64", {}).get("tx", {}) or {}).get("packets", 0),
                "rx_errors": (ifa.get("stats64", {}).get("rx", {}) or {}).get("errors", 0),
                "rx_drops": (ifa.get("stats64", {}).get("rx", {}) or {}).get("dropped", 0),
                "tx_drops": (ifa.get("stats64", {}).get("tx", {}) or {}).get("dropped", 0),
            })
        # Append FPGA ports if present
        if self.fpga.available:
            for p in range(4):
                s = self.fpga.port_stats(p)
                out.append({
                    "name": f"qsfp{p}",
                    "type": "fpga",
                    "link_up": s["link_up"],
                    "mac": f"00:1A:2B:3C:4D:{0xE0+p:02X}",
                    "mtu": 9000,
                    "ip_address": "",
                    "rx_bytes": s["rx_bytes"],
                    "tx_bytes": s["tx_bytes"],
                    "rx_packets": s["rx_packets"],
                    "tx_packets": s["tx_packets"],
                    "rx_drops": s["rx_drops"],
                    "tx_drops": 0,
                    "rx_errors": 0,
                })
        self.cache.set("interfaces", out, TTL_INTERFACES)
        return out

    def routes(self) -> list:
        cached = self.cache.get("routes")
        if cached is not None:
            return cached
        raw = self.nl.routes()
        out = [{
            "destination": r.get("dst", "default"),
            "next_hop": r.get("gateway", "direct"),
            "interface": r.get("dev", ""),
            "metric": r.get("metric", 0),
            "protocol": r.get("protocol", ""),
            "scope": r.get("scope", ""),
        } for r in raw]
        self.cache.set("routes", out, TTL_ROUTES)
        return out

    def arp(self) -> list:
        cached = self.cache.get("arp")
        if cached is not None:
            return cached
        raw = self.nl.neighbors()
        out = [{
            "ip": e.get("dst", ""),
            "mac": e.get("lladdr", "incomplete"),
            "interface": e.get("dev", ""),
            "state": (e.get("state") or ["?"])[0] if isinstance(e.get("state"), list) else e.get("state", "?"),
        } for e in raw]
        self.cache.set("arp", out, TTL_ARP)
        return out

    def sessions(self) -> dict:
        cached = self.cache.get("sessions")
        if cached is not None:
            return cached
        if self.fpga.available:
            s = self.fpga.session_stats()
            out = {"active": s["active"], "hits": s["hits"], "misses": s["misses"],
                   "hit_ratio": round(s["hits"] / max(s["hits"] + s["misses"], 1) * 100, 1),
                   "source": "fpga"}
        else:
            # Fall back to psutil / ss for real CPU-side conntrack
            try:
                import psutil
                conns = psutil.net_connections(kind="inet")
                est = sum(1 for c in conns if c.status == "ESTABLISHED")
                out = {"active": est, "established": est,
                       "listen": sum(1 for c in conns if c.status == "LISTEN"),
                       "time_wait": sum(1 for c in conns if c.status == "TIME_WAIT"),
                       "total_connections": len(conns),
                       "hits": est, "misses": max(len(conns) - est, 0),
                       "hit_ratio": round(est / max(len(conns), 1) * 100, 1),
                       "source": "psutil"}
            except ImportError:
                out = {"active": 0, "source": "unavailable"}
        self.cache.set("sessions", out, TTL_SESSIONS)
        return out

    def routing_protocols(self) -> dict:
        cached = self.cache.get("frr")
        if cached is not None:
            return cached
        out = {"bgp": self.frr.bgp_summary(), "ospf": self.frr.ospf_summary()}
        self.cache.set("frr", out, TTL_FRR)
        return out


# ---------------------------------------------------------------------------
# IPC server (newline-delimited JSON over unix socket)
# ---------------------------------------------------------------------------


class IPCServer:
    """
    Protocol: each message is a JSON object on one line.
      Request : {"id": "...", "cmd": "query", "path": "state/interfaces", "args": {...}}
      Response: {"id": "...", "ok": true/false, "data": {...}, "error": "..."}
    """
    def __init__(self, state: RuntimeState, commit: CommitOrchestrator, planes=None):
        self.state = state
        self.commit = commit
        self.planes = planes or ControlPlane({'worker_socket': None, 'agents': {}})
        self.handlers: Dict[str, Callable] = {}
        from ffn_policy_config import PolicyController
        self.policy = PolicyController(os.getenv('FFN_CONFIG_DIR','/var/lib/ffn-ngfw/config'), commit)
        self._register_handlers()

    def _register_handlers(self):
        self.handlers.update({
            "policy/request":           self.policy.request,
            "plane/request":            self.planes.request,
            "state/control":            self.planes.status,
            "state/agents":             self.planes.status,
            "state/control-events":     lambda a: list(self.planes.events),
            # Read-only state
            "state/interfaces":         lambda a: self.state.interfaces(),
            "state/routes":             lambda a: self.state.routes(),
            "state/arp":                lambda a: self.state.arp(),
            "state/sessions":           lambda a: self.state.sessions(),
            "state/routing-protocols":  lambda a: self.state.routing_protocols(),
            "state/zerotier/peers":     lambda a: self.state.zt.peers(),
            "state/zerotier/networks":  lambda a: self.state.zt.networks(),
            "state/ipsec/sas":          lambda a: self.state.ipsec.list_sas(),
            "state/fpga/available":     lambda a: self.state.fpga.available,
            "state/dpdk/available":     lambda a: self.state.dpdk.available(),
            # Commit lock
            "commit/lock/status":       lambda a: self.commit.lock_status(),
            "commit/lock/acquire":      lambda a: {"ok": self.commit.acquire(
                                            a.get("user", "?"), a.get("reason", "commit"))},
            "commit/lock/release":      lambda a: {"ok": self.commit.release(a.get("user", "?"))},
            # Config apply — trigger configd + return status
            "commit/apply":             self._cmd_commit_apply,
            "commit/apply-status":      lambda a: self._read_apply_status(),
            # Route ops
            "route/add":                self._cmd_route_add,
            "route/del":                self._cmd_route_del,
            # DPDK proxy
            "dpdk/query":               lambda a: self.state.dpdk.query(**a),
            # Data-plane daemon proxy (ffn-dpd). Each call unwraps the
            # dpd envelope ({ok,data}) so the manager sees the inner
            # payload directly after controld's own envelope is stripped.
            "dpd/status":               lambda a: self._dpd_unwrap(self.state.dpd.call("status")),
            "dpd/sessions":             lambda a: self._dpd_unwrap(self.state.dpd.call("sessions", a)),
            "dpd/rules":                lambda a: self._dpd_unwrap(self.state.dpd.call("rules")),
            "dpd/hits":                 lambda a: self._dpd_unwrap(self.state.dpd.call("hits")),
            "dpd/reload":               lambda a: self._dpd_unwrap(self.state.dpd.call(
                                            "reload", {"reason": a.get("reason", "controld")})),
            # Diagnostic passthrough
            "diag/ping":                self._cmd_diag_ping,
            "diag/frr":                 lambda a: {"text": self.state.frr.show(a.get("command", "show ip route"))},
            # Introspection
            "system/capabilities":      self._cmd_capabilities,
        })

    def _dpd_unwrap(self, resp: dict) -> dict:
        """Flatten the dpd envelope. Returns inner data on success,
        re-raises the error as a RuntimeError on failure so the outer
        controld envelope reports it consistently."""
        if not isinstance(resp, dict):
            return {"_raw": resp}
        if resp.get("ok"):
            return resp.get("data") or {}
        raise RuntimeError(resp.get("error") or "dpd call failed")

    def _cmd_capabilities(self, args):
        return {
            "fpga":      self.state.fpga.available,
            "dpdk":      self.state.dpdk.available(),
            "frr":       self.state.frr.available,
            "ipsec":     self.state.ipsec.available,
            "zerotier":  self.state.zt.available,
            "dpd":       self.state.dpd.available,
            "control_gateway": bool(self.planes.config['worker_socket']),
            "agent_channels": list(self.planes.config['agents']),
        }

    def _cmd_route_add(self, args):
        return self.state.nl.route_add(
            args.get("destination"), args.get("next_hop"),
            args.get("interface"), int(args.get("metric", 100)))

    def _cmd_route_del(self, args):
        return self.state.nl.route_del(args.get("destination"))

    def _cmd_diag_ping(self, args):
        target = args.get("target", "8.8.8.8")
        r = run(["ping", "-c", "4", "-W", "2", target], timeout=15)
        return {"output": r.stdout + r.stderr, "returncode": r.returncode}

    def _cmd_commit_apply(self, args):
        """Signal ffn-configd and return synchronous status."""
        self.commit.nudge_configd()
        status = self.commit.read_apply_status(timeout=15)
        # Invalidate caches after apply so subsequent queries see fresh state
        self.state.cache.invalidate()
        return status

    def _read_apply_status(self):
        try:
            return json.loads(APPLY_STATUS.read_text())
        except Exception as exc:
            return {"overall": "unknown", "error": str(exc)}

    async def handle_client(self, reader: asyncio.StreamReader,
                            writer: asyncio.StreamWriter):
        peer = writer.get_extra_info("peername") or "unix"
        try:
            while True:
                line = await asyncio.wait_for(reader.readline(), 135)
                if not line:
                    break
                if len(line) > CONTROL_LIMIT or not line.endswith(b'\n'):
                    break
                t0 = time.perf_counter()
                resp = await self._process(line)
                raw = (json.dumps(resp, allow_nan=False) + "\n").encode()
                if len(raw) > CONTROL_LIMIT:
                    raw = (json.dumps({'id': resp.get('id'), 'ok': False,
                                      'error': 'Control response exceeds limit'}) + '\n').encode()
                writer.write(raw)
                await asyncio.wait_for(writer.drain(), 10)
                dt = (time.perf_counter() - t0) * 1000
                if dt > 50:
                    logger.info("slow request %s: %.1fms", resp.get("cmd", "?"), dt)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.warning("client error: %s", exc)
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def _process(self, line: bytes) -> dict:
        try:
            msg = json.loads(line.decode())
        except Exception as exc:
            return {"ok": False, "error": f"bad JSON: {exc}"}
        if not isinstance(msg, dict):
            return {"ok": False, "error": "request object required"}
        req_id = msg.get("id")
        path = msg.get("cmd") or msg.get("path")
        args = msg.get("args") or {}
        if not isinstance(path, str) or not isinstance(args, dict):
            return {"id": req_id, "ok": False, "error": "invalid command or arguments"}
        handler = self.handlers.get(path)
        if handler is None:
            return {"id": req_id, "ok": False, "error": f"unknown cmd: {path}"}
        try:
            # Run in thread if sync (most handlers are fast; subprocess calls
            # are offloaded so they don't block the event loop)
            loop = asyncio.get_running_loop()
            if asyncio.iscoroutinefunction(handler):
                data = await handler(args)
            else:
                data = await loop.run_in_executor(None, handler, args)
            return {"id": req_id, "ok": True, "cmd": path, "data": data}
        except Exception as exc:
            logger.exception("handler %s failed", path)
            return {"id": req_id, "ok": False, "error": str(exc)}

    async def start(self):
        RUN_DIR.mkdir(parents=True, exist_ok=True)
        # Remove stale socket
        if SOCKET_PATH.exists():
            SOCKET_PATH.unlink()
        server = await asyncio.start_unix_server(
            self.handle_client, path=str(SOCKET_PATH), limit=CONTROL_LIMIT + 1)
        # Permissions
        try:
            os.chmod(SOCKET_PATH, SOCKET_MODE)
            import grp
            gid = grp.getgrnam(SOCKET_GROUP).gr_gid
            os.chown(SOCKET_PATH, 0, gid)
        except Exception as exc:
            logger.warning("Could not set socket perms: %s", exc)
        logger.info("IPC listening on %s (mode=%o group=%s)",
                    SOCKET_PATH, SOCKET_MODE, SOCKET_GROUP)
        return server


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def _log_startup_config_state():
    if not RUNNING_CONFIG.exists():
        logger.warning("running-config.xml missing at %s — ffn-manager will seed "
                       "defaults on its next startup", RUNNING_CONFIG)
        return
    size = RUNNING_CONFIG.stat().st_size
    try:
        manifest = json.loads(HISTORY_MANIFEST.read_text(encoding="utf-8"))
        entries = manifest.get("entries", [])
        if entries:
            top = entries[0]
            logger.info("Config loaded: running-config=%s (%d bytes), "
                        "history v%d @ %s by %s — %d total versions",
                        RUNNING_CONFIG, size, top["version"], top["timestamp"],
                        top["user"], len(entries))
        else:
            logger.info("Config loaded: running-config=%s (%d bytes), "
                        "no history yet", RUNNING_CONFIG, size)
    except FileNotFoundError:
        logger.info("Config loaded: running-config=%s (%d bytes), "
                    "manifest absent (ffn-manager not yet started)",
                    RUNNING_CONFIG, size)
    except Exception as exc:
        logger.warning("Could not read history manifest: %s", exc)


async def amain():
    ap = argparse.ArgumentParser(description="FFN NGFW Control Plane Daemon")
    ap.add_argument("--foreground", action="store_true", help="(kept for compat)")
    args = ap.parse_args()

    # Log which config is considered "active" at startup. controld itself
    # does not parse/apply the XML — ffn-configd owns that — but we read the
    # history manifest so operators have a single place to see the running
    # config version when controld comes up.
    _log_startup_config_state()

    state = RuntimeState()
    commit = CommitOrchestrator()
    planes = ControlPlane(load_config(os.getenv('FFN_CONTROL_CONFIG', '/etc/ffn/controld.json')))
    ipc = IPCServer(state, commit, planes)

    server = await ipc.start()
    planes.start()

    stop_event = asyncio.Event()

    def on_signal():
        logger.info("Shutdown signal received")
        stop_event.set()

    for sig in (signal.SIGTERM, signal.SIGINT):
        asyncio.get_running_loop().add_signal_handler(sig, on_signal)

    logger.info("ffn-controld ready — capabilities: fpga=%s dpdk=%s frr=%s ipsec=%s zt=%s dpd=%s",
                state.fpga.available, state.dpdk.available(),
                state.frr.available, state.ipsec.available, state.zt.available,
                state.dpd.available)

    await stop_event.wait()
    logger.info("shutting down")
    server.close()
    await server.wait_closed()
    await planes.close()
    state.fpga.close()
    try:
        SOCKET_PATH.unlink()
    except Exception:
        pass


def main():
    asyncio.run(amain())


if __name__ == "__main__":
    main()
