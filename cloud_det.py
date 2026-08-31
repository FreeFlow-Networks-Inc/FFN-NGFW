#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""
cloud_det.py -- FFN NGFW Cloud-Backed Detection System (WildFire-like).

The "unknown-threat" half of the detection stack. Where inline_payload_det.py
enforces what is already known at line rate, this system takes the UNKNOWN
objects the inline engine carves out of flows, detonates/analyses them, and
turns a verdict into new enforceable content -- closing the WildFire loop:

    inline_payload_det.carve_files()        (unknown PE / PDF / script / ...)
                 |
                 v
      CloudDetectionService.submit()        dedup vs ThreatDB verdict cache
                 |                           persistent submission queue
                 v
          CloudBackend.analyze()            LocalSandbox (offline static) OR
                 |                           HttpCloudBackend (real REST cloud)
                 v
             SandboxReport                  verdict + score + generated sigs/IOCs
                 |
     +-----------+-----------------------------+
     |                        |                 |
  ThreatDB.record_sample   ThreatDB.record_ioc  InlinePayloadDetector.add_signature
  (hash blocklist)         (C2 domains/ips)      (behavioural content sigs)
     |                        |                 |
     +-----------> InlinePayloadDetector.compile_to_fpga() -> hardware fast path

So the *next* time the same file (by hash), a variant (by behavioural string),
or its C2 infrastructure (by IOC) appears, the inline engine blocks it -- in
software immediately and in the FPGA after the compile push.

Design:
  * Pluggable backend. LocalSandbox is a dependency-free static-analysis
    "sandbox" (file-magic, entropy/packing, embedded IOCs, behavioural string
    rules) that is fully deterministic and offline -- so the whole loop is
    unit-testable with no network. HttpCloudBackend speaks a WildFire-style
    submit/verdict REST API (stdlib urllib) for a real cloud when configured.
  * Verdict cache with TTL in ThreatDB + a cloud_reports table; a re-submit of
    a known sample is answered from cache, not re-detonated.
  * Sample bytes are spooled in a bounded cloud_queue row (BLOB) so pending
    work survives a restart; oversized objects are truncated for analysis.
  * `--selftest` proves the closed loop with no hardware and no network.

CLI:
    cloud_det.py selftest
    cloud_det.py submit <file>
    cloud_det.py process [--limit N]
    cloud_det.py verdict <sha256>
    cloud_det.py report <sha256>
    cloud_det.py stats
"""

import argparse
import hashlib
import json
import logging
import os
import re
import sys
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

try:
    from ffn_threatdb import ThreatDB, VERDICT_SCORE, VERDICT_ACTION, ACTION_ALERT
except Exception:
    ThreatDB = None
    VERDICT_SCORE = {"unknown": 0, "benign": 0, "grayware": 40,
                     "phishing": 80, "malware": 100}
    ACTION_ALERT = 0

from inline_payload_det import (
    InlinePayloadDetector, ContentSignature, detect_file_type, shannon_entropy,
    extract_iocs, seed_baseline, ACTION_DROP, ACTION_RESET,
)

logger = logging.getLogger("ffn-cloud-det")

# Generated-signature SID range: keep well clear of builtin (1000..) and manual
# ranges so cloud sig-gen never clobbers a hand-authored rule.
GENERATED_SID_BASE = 5_000_000
# Max object we will spool/analyse inline (bytes). Larger files are truncated
# for static features (a real sandbox would stream the whole file).
MAX_SPOOL = 32 * 1024 * 1024


# ===========================================================================
# Report model
# ===========================================================================
@dataclass
class SandboxReport:
    """Structured verdict returned by a CloudBackend for one sample."""
    sha256: str
    verdict: str = "unknown"                     # WildFire taxonomy
    score: int = 0
    threat_name: str = ""
    file_type: Optional[str] = None
    signatures: List[ContentSignature] = field(default_factory=list)
    iocs: List[Tuple[str, str, str, str]] = field(default_factory=list)  # (type,value,verdict,name)
    details: Dict = field(default_factory=dict)
    backend: str = "local"
    analyzed: float = 0.0

    def to_json(self) -> str:
        return json.dumps({
            "sha256": self.sha256, "verdict": self.verdict, "score": self.score,
            "threat_name": self.threat_name, "file_type": self.file_type,
            "signatures": [{"name": s.name, "pattern_hex": s.pattern.hex(),
                            "action": s.action, "severity": s.severity} for s in self.signatures],
            "iocs": [{"type": t, "value": v, "verdict": vd, "name": nm}
                     for (t, v, vd, nm) in self.iocs],
            "details": self.details, "backend": self.backend,
        }, sort_keys=True)


# ===========================================================================
# Backend interface + implementations
# ===========================================================================
class CloudBackend:
    """Abstract analysis backend. analyze() must be deterministic for a hash."""

    name = "abstract"

    def analyze(self, sha256: str, data: bytes, meta: dict) -> SandboxReport:
        raise NotImplementedError


class LocalSandbox(CloudBackend):
    """Offline static-analysis reference sandbox (no network, deterministic).

    Not a full detonation engine -- it scores a sample from file type, entropy
    (packing), embedded network IOCs, and a table of behavioural / capability
    strings, then synthesises the verdict + the enforceable signatures a real
    cloud would return. Good enough to (a) run the whole loop in CI and (b)
    serve as the on-box fallback when the cloud is unreachable.
    """

    name = "local"

    # (indicator bytes, weight, threat class, human name). Weight ~ how strongly
    # this capability implies malware. Kept lowercase; matched case-folded.
    INDICATORS: List[Tuple[bytes, int, str, str]] = [
        (b"createremotethread",   60, "malware",  "Behavior.ProcessInjection"),
        (b"virtualallocex",       45, "malware",  "Behavior.RemoteAlloc"),
        (b"writeprocessmemory",   45, "malware",  "Behavior.ProcessInjection"),
        (b"setwindowshookex",     35, "malware",  "Behavior.Hook"),
        (b"urldownloadtofile",    50, "malware",  "Behavior.Downloader"),
        (b"wscript.shell",        40, "malware",  "Behavior.ScriptExec"),
        (b"powershell -enc",      55, "malware",  "Downloader.PowerShell"),
        (b"frombase64string",     30, "grayware", "Obfuscation.Base64"),
        (b"cmd.exe /c",           25, "grayware", "Behavior.Shell"),
        (b"/dev/tcp/",            60, "malware",  "Backdoor.ReverseShell"),
        (b"eval(base64_decode",   60, "malware",  "Webshell.PHP"),
        (b"schtasks /create",     35, "grayware", "Persistence.ScheduledTask"),
        (b"reg add",              15, "grayware", "Persistence.Registry"),
        # the canonical AV test string -> always malware
        (b"eicar-standard-antivirus-test-file", 100, "malware", "EICAR.Test"),
    ]

    def analyze(self, sha256: str, data: bytes, meta: dict) -> SandboxReport:
        blob = data[:MAX_SPOOL]
        low = blob.lower()
        ftype = detect_file_type(blob) or (meta.get("file_type") if meta else None)
        ent = shannon_entropy(blob[:65536])

        score = 0
        threats: List[str] = []
        matched: List[Tuple[bytes, int, str, str]] = []
        for ind, w, cls, name in self.INDICATORS:
            if ind in low:
                score += w
                threats.append(name)
                matched.append((ind, w, cls, name))

        # packing heuristic: high-entropy executable body is suspicious
        if ftype in ("pe", "elf", "macho") and ent >= 7.2:
            score += 20
            threats.append("Packer.HighEntropy")

        # embedded network IOCs raise score + become blockable indicators
        iocs_found = extract_iocs(blob)
        ioc_rows: List[Tuple[str, str, str, str]] = []
        for t in ("url", "domain", "ip"):
            for v in iocs_found.get(t, [])[:16]:
                # only treat as malicious IOC if the sample already looks bad;
                # otherwise record as unknown (observed, not condemned).
                ioc_rows.append((t, v, "unknown", "Observed.%s" % t))
        if score >= 60 and ioc_rows:
            score += 15
            ioc_rows = [(t, v, "malware", "C2.FromSample") for (t, v, _vd, _n) in ioc_rows]

        verdict = ("malware" if score >= 60 else
                   "grayware" if score >= 25 else
                   "benign")
        threat_name = threats[0] if threats else ("Suspicious.Generic"
                                                  if verdict != "benign" else "")

        # Generated behavioural signatures: the highest-weight distinctive
        # indicators become inline content rules so *variants* (new hash, same
        # capability) are caught next time. Skip weak/short tokens to limit FP.
        sigs: List[ContentSignature] = []
        if verdict == "malware":
            for ind, w, cls, name in sorted(matched, key=lambda x: -x[1])[:3]:
                if w < 40 or len(ind) < 8:
                    continue
                sigs.append(ContentSignature(
                    sid=0,  # assigned by the service
                    name="cloudgen.%s" % name,
                    pattern=ind, nocase=True,
                    action=VERDICT_ACTION.get(cls, ACTION_RESET),
                    severity="high", threat_name=name, verdict=cls,
                    source="cloudgen"))

        return SandboxReport(
            sha256=sha256, verdict=verdict, score=min(score, 100),
            threat_name=threat_name, file_type=ftype,
            signatures=sigs, iocs=ioc_rows,
            details={"entropy": round(ent, 3), "size": len(data),
                     "indicators": [n for (_i, _w, _c, n) in matched]},
            backend=self.name, analyzed=meta.get("_now", 0.0) if meta else 0.0)


class HttpCloudBackend(CloudBackend):
    """WildFire-style REST cloud backend (stdlib urllib).

    Protocol (configurable, defaults to a WildFire-ish shape):
      POST {base}/submit        (multipart file)   -> {"sha256":..,"ticket":..}
      GET  {base}/verdict/<sha> (apikey header)     -> {"verdict":..,"score":..,
                                                        "threat":..,"signatures":[..],
                                                        "iocs":[..]}
    Used only when a base_url is configured; never exercised by the offline
    selftest. Network/parse failures degrade to an 'unknown' report (fail open
    for availability; the inline engine still enforces known content).
    """

    name = "http"

    def __init__(self, base_url: str, api_key: str = "", *, timeout: float = 20.0):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout

    def analyze(self, sha256: str, data: bytes, meta: dict) -> SandboxReport:
        import urllib.request
        import urllib.error
        hdrs = {"X-API-KEY": self.api_key, "Content-Type": "application/octet-stream"}
        try:
            # submit
            req = urllib.request.Request(self.base_url + "/submit", data=data,
                                         headers=hdrs, method="POST")
            urllib.request.urlopen(req, timeout=self.timeout).read()
            # verdict (a real client would poll until analysis completes)
            vreq = urllib.request.Request(
                "%s/verdict/%s" % (self.base_url, sha256),
                headers={"X-API-KEY": self.api_key})
            body = urllib.request.urlopen(vreq, timeout=self.timeout).read()
            j = json.loads(body.decode("utf-8", "ignore"))
        except (urllib.error.URLError, OSError, ValueError) as e:
            logger.warning("cloud backend unreachable (%s); verdict=unknown", e)
            return SandboxReport(sha256=sha256, verdict="unknown", backend=self.name)

        verdict = j.get("verdict", "unknown")
        sigs = []
        for s in j.get("signatures", []):
            try:
                sigs.append(ContentSignature(
                    sid=0, name=s.get("name", "cloudgen"),
                    pattern=bytes.fromhex(s["pattern_hex"]), nocase=True,
                    action=int(s.get("action", ACTION_RESET)),
                    severity=s.get("severity", "high"),
                    threat_name=s.get("name", ""), verdict=verdict, source="cloudgen"))
            except Exception:
                continue
        iocs = [(i.get("type"), i.get("value"), i.get("verdict", verdict),
                 i.get("name", "")) for i in j.get("iocs", []) if i.get("value")]
        return SandboxReport(
            sha256=sha256, verdict=verdict, score=int(j.get("score", 0)),
            threat_name=j.get("threat", ""), file_type=j.get("file_type"),
            signatures=sigs, iocs=iocs, details=j.get("details", {}),
            backend=self.name)


# ===========================================================================
# The service
# ===========================================================================
class CloudDetectionService:
    """Queue + dedup + verdict-cache + feedback wiring around a CloudBackend."""

    SCHEMA = """
    CREATE TABLE IF NOT EXISTS cloud_queue (
        sha256    TEXT PRIMARY KEY,
        status    TEXT NOT NULL DEFAULT 'pending',   -- pending/analyzing/done/error
        file_type TEXT,
        size      INTEGER,
        meta      TEXT,
        sample    BLOB,
        submitted TEXT,
        updated   TEXT,
        attempts  INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS cloud_reports (
        sha256      TEXT PRIMARY KEY,
        verdict     TEXT NOT NULL,
        score       INTEGER NOT NULL DEFAULT 0,
        threat_name TEXT,
        file_type   TEXT,
        backend     TEXT,
        report      TEXT,
        analyzed    TEXT
    );
    """

    def __init__(self, threatdb: "ThreatDB", inline: Optional[InlinePayloadDetector] = None,
                 backend: Optional[CloudBackend] = None, *, cache_ttl: int = 7 * 24 * 3600,
                 auto_compile: bool = False):
        if threatdb is None:
            raise ValueError("CloudDetectionService requires a ThreatDB")
        self.threatdb = threatdb
        self.inline = inline
        self.backend = backend or LocalSandbox()
        self.cache_ttl = cache_ttl
        self.auto_compile = auto_compile
        self.stats = {"submitted": 0, "deduped": 0, "analyzed": 0,
                      "malware": 0, "grayware": 0, "benign": 0,
                      "sigs_generated": 0, "iocs_recorded": 0, "errors": 0}
        self.threatdb.conn.executescript(self.SCHEMA)
        self.threatdb.conn.commit()

    # -- submission --------------------------------------------------------
    def submit(self, data: bytes, meta: Optional[dict] = None) -> dict:
        """Queue an object for analysis. Returns {sha256, status, verdict?}.

        Dedup: if we already hold a fresh verdict for this hash (in ThreatDB
        samples or cloud_reports within cache_ttl) we return it immediately and
        do NOT re-detonate.
        """
        meta = dict(meta or {})
        sha = hashlib.sha256(data).hexdigest()
        self.stats["submitted"] += 1

        cached = self._cached_verdict(sha)
        if cached is not None:
            self.stats["deduped"] += 1
            return {"sha256": sha, "status": "cached", "verdict": cached}

        now = self._now()
        row = self.threatdb.conn.execute(
            "SELECT status FROM cloud_queue WHERE sha256=?", (sha,)).fetchone()
        if row and row["status"] in ("pending", "analyzing"):
            return {"sha256": sha, "status": row["status"]}

        ftype = detect_file_type(data) or meta.get("file_type")
        self.threatdb.conn.execute(
            """INSERT INTO cloud_queue (sha256,status,file_type,size,meta,sample,submitted,updated)
               VALUES (?,?,?,?,?,?,?,?)
               ON CONFLICT(sha256) DO UPDATE SET status='pending', updated=excluded.updated""",
            (sha, "pending", ftype, len(data), json.dumps(meta),
             data[:MAX_SPOOL], now, now))
        self.threatdb.conn.commit()
        return {"sha256": sha, "status": "queued"}

    def _cached_verdict(self, sha: str) -> Optional[str]:
        # definitive sample verdict wins
        samp = self.threatdb.lookup_sample(sha)
        if samp and samp["verdict"] in ("malware", "phishing", "benign", "grayware"):
            return samp["verdict"]
        # else a fresh cloud report
        r = self.threatdb.conn.execute(
            "SELECT verdict,analyzed FROM cloud_reports WHERE sha256=?", (sha,)).fetchone()
        if r and r["verdict"] != "unknown":
            if self._fresh(r["analyzed"]):
                return r["verdict"]
        return None

    def _fresh(self, ts: str) -> bool:
        try:
            t = time.mktime(time.strptime(ts, "%Y-%m-%dT%H:%M:%SZ"))
        except Exception:
            return False
        return (time.time() - t) < self.cache_ttl

    # -- processing --------------------------------------------------------
    def process_pending(self, limit: int = 50) -> List[SandboxReport]:
        """Analyse queued samples, record verdicts, and feed back the results."""
        rows = self.threatdb.conn.execute(
            "SELECT sha256,sample,meta,file_type FROM cloud_queue "
            "WHERE status='pending' ORDER BY submitted LIMIT ?", (limit,)).fetchall()
        reports = []
        for r in rows:
            sha = r["sha256"]
            self._set_status(sha, "analyzing")
            try:
                meta = json.loads(r["meta"] or "{}")
                meta["_now"] = time.time()
                rep = self.backend.analyze(sha, bytes(r["sample"] or b""), meta)
                self._apply_report(rep)
                self._set_status(sha, "done")
                reports.append(rep)
                self.stats["analyzed"] += 1
                self.stats[rep.verdict if rep.verdict in self.stats else "benign"] = \
                    self.stats.get(rep.verdict, 0) + 1
            except Exception as e:
                logger.exception("analysis failed for %s: %s", sha, e)
                self.stats["errors"] += 1
                self.threatdb.conn.execute(
                    "UPDATE cloud_queue SET status='error', attempts=attempts+1, updated=? "
                    "WHERE sha256=?", (self._now(), sha))
                self.threatdb.conn.commit()
        if reports and self.auto_compile and self.inline is not None:
            try:
                self.inline.compile_to_fpga()
            except Exception as e:
                logger.warning("auto compile_to_fpga failed: %s", e)
        return reports

    def _apply_report(self, rep: SandboxReport) -> None:
        """Persist the verdict + wire generated content back into enforcement."""
        now = self._now()
        rep.analyzed = time.time()
        self.threatdb.conn.execute(
            """INSERT INTO cloud_reports (sha256,verdict,score,threat_name,file_type,
                   backend,report,analyzed) VALUES (?,?,?,?,?,?,?,?)
               ON CONFLICT(sha256) DO UPDATE SET verdict=excluded.verdict,
                   score=excluded.score, threat_name=excluded.threat_name,
                   file_type=excluded.file_type, backend=excluded.backend,
                   report=excluded.report, analyzed=excluded.analyzed""",
            (rep.sha256, rep.verdict, rep.score, rep.threat_name, rep.file_type,
             rep.backend, rep.to_json(), now))

        # 1) file-hash verdict -> ThreatDB samples (hash blocklist next time)
        if rep.verdict in ("malware", "phishing", "grayware", "benign"):
            self.threatdb.record_sample(
                rep.sha256, rep.verdict, file_type=rep.file_type,
                threat_name=rep.threat_name or None, source="cloud")

        # 2) behavioural signatures -> inline content rules (variant coverage)
        if rep.signatures and self.inline is not None:
            for sig in rep.signatures:
                sig.sid = self._alloc_sid()
                try:
                    self.inline.add_signature(sig, persist=True)
                    self.stats["sigs_generated"] += 1
                except Exception as e:
                    logger.debug("sig add failed: %s", e)

        # 3) embedded IOCs -> ThreatDB iocs (C2 infra coverage)
        for (ioc_type, value, verdict, name) in rep.iocs:
            if verdict in ("benign", "unknown"):
                continue
            try:
                self.threatdb.record_ioc(ioc_type, value, verdict,
                                         threat_name=name, source="cloud")
                self.stats["iocs_recorded"] += 1
            except Exception as e:
                logger.debug("ioc record failed: %s", e)

        self.threatdb.conn.commit()

    def _alloc_sid(self) -> int:
        row = self.threatdb.conn.execute(
            "SELECT MAX(sid) m FROM content_signatures WHERE sid>=?",
            (GENERATED_SID_BASE,)).fetchone()
        return (row["m"] + 1) if row and row["m"] else GENERATED_SID_BASE

    def _set_status(self, sha: str, status: str) -> None:
        self.threatdb.conn.execute(
            "UPDATE cloud_queue SET status=?, updated=?, attempts=attempts+1 WHERE sha256=?",
            (status, self._now(), sha))
        self.threatdb.conn.commit()

    # -- queries -----------------------------------------------------------
    def verdict(self, sha256: str) -> dict:
        sha = sha256.lower().strip()
        v = self._cached_verdict(sha)
        r = self.threatdb.conn.execute(
            "SELECT * FROM cloud_reports WHERE sha256=?", (sha,)).fetchone()
        return {"sha256": sha, "verdict": v or "unknown",
                "report": dict(r) if r else None}

    def get_report(self, sha256: str) -> Optional[dict]:
        r = self.threatdb.conn.execute(
            "SELECT report FROM cloud_reports WHERE sha256=?",
            (sha256.lower().strip(),)).fetchone()
        return json.loads(r["report"]) if r and r["report"] else None

    def queue_depth(self) -> int:
        return self.threatdb.conn.execute(
            "SELECT COUNT(*) c FROM cloud_queue WHERE status='pending'").fetchone()["c"]

    @staticmethod
    def _now() -> str:
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    def summary_stats(self) -> dict:
        s = dict(self.stats)
        s["queue_depth"] = self.queue_depth()
        s["backend"] = self.backend.name
        return s


# ===========================================================================
# Self-test -- proves the closed WildFire loop, no HW / no network
# ===========================================================================
def selftest() -> int:
    print("cloud_det selftest")
    if ThreatDB is None:
        print("  [fail] ffn_threatdb unavailable"); return 1

    db = ThreatDB(":memory:")
    inline = InlinePayloadDetector(db)
    seed_baseline(inline)
    cloud = CloudDetectionService(db, inline=inline, backend=LocalSandbox())

    # -- craft an UNKNOWN malware sample the baseline inline rules miss ----
    # A PE that imports process-injection APIs and phones home to a C2 host.
    unknown_a = (b"MZ\x90\x00" + b"benign looking header " * 4 +
                 b"CreateRemoteThread" + b"\x00" + b"VirtualAllocEx" +
                 b" connect http://c2.evilcorp.example/gate " +
                 os.urandom(64))
    sha_a = hashlib.sha256(unknown_a).hexdigest()

    # 1) inline is blind to it today (no matching known signature)
    d0 = inline.inspect(unknown_a)
    assert not d0.matched, "sample should be unknown to inline before cloud: %s" % d0.summary()
    print("  [ok] step1: inline verdict on unknown sample = clean")

    # 2) submit -> queued (not cached)
    r = cloud.submit(unknown_a, {"file_type": "pe", "flow": "test"})
    assert r["status"] == "queued", r
    assert cloud.queue_depth() == 1
    print("  [ok] step2: submitted -> queued (depth=1)")

    # 3) detonate the queue
    reps = cloud.process_pending()
    assert len(reps) == 1
    rep = reps[0]
    assert rep.verdict == "malware", "sandbox should convict: %r (%s)" % (rep.verdict, rep.details)
    assert rep.signatures, "sandbox should generate behavioural signatures"
    print("  [ok] step3: sandbox verdict=%s score=%d threat=%s sigs=%d iocs=%d" % (
        rep.verdict, rep.score, rep.threat_name, len(rep.signatures), len(rep.iocs)))

    # 4) verdict is now cached in ThreatDB (hash blocklist) ...
    assert db.is_malicious_hash(sha_a), "cloud verdict must persist to ThreatDB samples"
    #    ... and the C2 domain became a blockable IOC
    ioc = db.lookup_ioc("domain", "c2.evilcorp.example")
    assert ioc and ioc["verdict"] == "malware", "C2 domain should be recorded malicious"
    print("  [ok] step4: ThreatDB now blocks the hash + C2 domain")

    # 5) THE LOOP: inline now convicts the exact file (hash) AND a variant
    #    (different bytes, same behavioural string) via the generated signature.
    d1 = inline.inspect(unknown_a)
    assert d1.matched and d1.action == ACTION_RESET, "inline should block known-bad hash now"
    variant_b = (b"MZ\x90\x00" + b"TOTALLY different padding " * 3 +
                 b"CreateRemoteThread" + os.urandom(128))   # new hash, same capability
    assert hashlib.sha256(variant_b).hexdigest() != sha_a
    d2 = inline.inspect(variant_b)
    assert d2.matched, "generated behavioural signature should catch the variant"
    assert any(m.name.startswith("cloudgen.") for m in d2.matches), \
        "variant must match a cloud-generated signature, not just the hash"
    print("  [ok] step5: LOOP CLOSED -> inline blocks exact file (hash) AND variant (cloudgen sig)")

    # 6) dedup: re-submitting a known sample is answered from cache, no re-run
    before = cloud.stats["analyzed"]
    r2 = cloud.submit(unknown_a)
    assert r2["status"] == "cached" and r2["verdict"] == "malware", r2
    assert cloud.process_pending() == [], "nothing new to analyse"
    assert cloud.stats["analyzed"] == before, "cached sample must not re-detonate"
    print("  [ok] step6: verdict cache dedup (no re-detonation)")

    # 7) a benign sample stays benign and generates no enforcement
    benign = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n<html>hi</html>"
    cloud.submit(benign, {"file_type": "html_js"})
    brep = cloud.process_pending()[0]
    assert brep.verdict == "benign", "benign sample misclassified: %s" % brep.details
    print("  [ok] step7: benign sample -> benign, no signatures generated")

    # 8) report retrieval + stats
    got = cloud.get_report(sha_a)
    assert got and got["verdict"] == "malware" and got["backend"] == "local"
    print("  [ok] step8: report retrieval ->", got["details"])

    print("  all assertions passed:", cloud.summary_stats())
    db.close()
    return 0


# ===========================================================================
# CLI
# ===========================================================================
def _make_service(db_path: str, backend_url: str = "", api_key: str = "") -> \
        Tuple["ThreatDB", InlinePayloadDetector, CloudDetectionService]:
    db = ThreatDB(db_path)
    inline = InlinePayloadDetector(db)
    backend = HttpCloudBackend(backend_url, api_key) if backend_url else LocalSandbox()
    svc = CloudDetectionService(db, inline=inline, backend=backend, auto_compile=True)
    return db, inline, svc


def main(argv=None):
    ap = argparse.ArgumentParser(description="FFN NGFW cloud-backed (WildFire-like) detection")
    ap.add_argument("--db", default=os.getenv("FFN_THREATDB_PATH",
                                              "/var/lib/ffn-ngfw/threatdb.sqlite"))
    ap.add_argument("--cloud-url", default=os.getenv("FFN_CLOUD_URL", ""),
                    help="WildFire-style REST endpoint (empty = local sandbox)")
    ap.add_argument("--api-key", default=os.getenv("FFN_CLOUD_APIKEY", ""))
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("selftest")
    sp = sub.add_parser("submit"); sp.add_argument("file")
    sp = sub.add_parser("process"); sp.add_argument("--limit", type=int, default=50)
    sp = sub.add_parser("verdict"); sp.add_argument("sha256")
    sp = sub.add_parser("report"); sp.add_argument("sha256")
    sub.add_parser("stats")
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    if args.cmd == "selftest":
        return selftest()
    if ThreatDB is None:
        print("ffn_threatdb unavailable", file=sys.stderr); return 1

    db, inline, svc = _make_service(args.db, args.cloud_url, args.api_key)
    try:
        if args.cmd == "submit":
            data = open(args.file, "rb").read()
            print(json.dumps(svc.submit(data, {"file_type": detect_file_type(data),
                                               "source": "cli", "path": args.file})))
        elif args.cmd == "process":
            reps = svc.process_pending(limit=args.limit)
            for rep in reps:
                print("%s  %-9s score=%-3d %s  sigs=%d iocs=%d" % (
                    rep.sha256[:16], rep.verdict, rep.score, rep.threat_name,
                    len(rep.signatures), len(rep.iocs)))
            print("processed", len(reps))
        elif args.cmd == "verdict":
            print(json.dumps(svc.verdict(args.sha256), indent=2, default=str))
        elif args.cmd == "report":
            print(json.dumps(svc.get_report(args.sha256), indent=2))
        elif args.cmd == "stats":
            print(json.dumps(svc.summary_stats(), indent=2))
    finally:
        db.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
