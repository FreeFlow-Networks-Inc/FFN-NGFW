#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""
ffn_antivirus.py -- FFN NGFW Anti-Virus file scanner.

Scans complete files (the objects carved out of flows by the dataplane)
against the Signature Database (ffn_sigdb). A real, if compact, ClamAV-style
engine:

  * hash signatures   -- md5 / sha1 / sha256 (+ optional size), exact match
  * body signatures   -- ClamAV .ndb hex patterns compiled to a byte-regex:
                         `??` byte wildcard, `a?`/`?a` nibble wildcards,
                         `{n}` / `{n-m}` / `{-m}` / `{n-}` gaps, `*` any gap,
                         `(aa|bb)` alternation; offset-anchored
                         (*/absolute/EOF-n), file-type targeted
  * YARA-lite rules   -- multi-string (hex/text) + all/any/N-of-them condition

Performance: an Aho-Corasick pre-filter over the longest literal run of each
body signature narrows the file to a handful of candidate rules before the
(more expensive) anchored regex confirm -- so thousands of signatures scan in
one pass, the same trick a production AV uses.

    file bytes ─▶ hash index ─▶ AC pre-filter ─▶ regex confirm ─▶ YARA ─▶ AvResult

stdlib only. `--selftest` needs no hardware and no network.

CLI:
    ffn_antivirus.py selftest
    ffn_antivirus.py scan <file>
    ffn_antivirus.py scan-hex <hexstring>
    ffn_antivirus.py test-eicar
"""

import argparse
import hashlib
import logging
import os
import re
import sys
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

try:
    from ffn_sigdb import SignatureDB, seed_baseline, ACTION_RESET, ACTION_ALERT
except Exception:
    SignatureDB = None
    ACTION_RESET, ACTION_ALERT = 2, 0

# reuse the file-type detector + Aho-Corasick from the inline engine
try:
    from inline_payload_det import detect_file_type, AhoCorasick
except Exception:  # standalone fallback (keeps this module importable alone)
    AhoCorasick = None

    def detect_file_type(data: bytes):
        if data[:2] == b"MZ":
            return "pe"
        if data[:4] == b"\x7fELF":
            return "elf"
        if data[:4] == b"%PDF":
            return "pdf"
        return None

logger = logging.getLogger("ffn-av")


# ===========================================================================
# ClamAV-style hex signature -> compiled byte-regex
# ===========================================================================
def _pair_re(pair: str) -> bytes:
    """One ClamAV hex token -> a regex fragment (bytes)."""
    hi, lo = pair[0].lower(), pair[1].lower()
    if hi == "?" and lo == "?":
        return b"."                                  # any byte (DOTALL)
    if hi == "?":                                    # low nibble fixed
        lov = int(lo, 16)
        return b"[" + b"".join(b"\\x%02x" % ((n << 4) | lov) for n in range(16)) + b"]"
    if lo == "?":                                    # high nibble fixed (contiguous)
        hiv = int(hi, 16)
        return b"[\\x%02x-\\x%02x]" % (hiv << 4, (hiv << 4) | 0xF)
    return b"\\x%02x" % int(pair, 16)                # full byte


def _alt_re(alt: str) -> bytes:
    """A single alternation branch (a hex string) -> regex fragment."""
    out = []
    i = 0
    while i < len(alt) - 1:
        out.append(_pair_re(alt[i:i + 2]))
        i += 2
    return b"".join(out)


def _gap_re(spec: str) -> bytes:
    spec = spec.strip()
    if "-" in spec:
        a, _, b = spec.partition("-")
        a = a or "0"
        return b".{%d,}" % int(a) if b == "" else b".{%d,%d}" % (int(a), int(b))
    return b".{%d}" % int(spec)


def compile_hexsig(hexsig: str) -> Optional["re.Pattern"]:
    """Compile a ClamAV .ndb body signature into a bytes regex (DOTALL)."""
    s = hexsig.replace(" ", "")
    out: List[bytes] = []
    i = 0
    try:
        while i < len(s):
            c = s[i]
            if c == "*":
                out.append(b".*")
                i += 1
            elif c == "{":
                j = s.index("}", i)
                out.append(_gap_re(s[i + 1:j]))
                i = j + 1
            elif c == "(":
                j = s.index(")", i)
                alts = s[i + 1:j].split("|")
                out.append(b"(?:" + b"|".join(_alt_re(a) for a in alts) + b")")
                i = j + 1
            elif c == "[":                            # ClamAV byte range [aa-bb]
                j = s.index("]", i)
                lo, _, hi = s[i + 1:j].partition("-")
                out.append(b"[\\x%02x-\\x%02x]" % (int(lo, 16), int(hi, 16)))
                i = j + 1
            else:
                out.append(_pair_re(s[i:i + 2]))
                i += 2
        return re.compile(b"".join(out), re.DOTALL)
    except (ValueError, re.error) as e:
        logger.debug("hexsig compile failed %r: %s", hexsig, e)
        return None


def literal_anchor(hexsig: str, minlen: int = 4) -> Optional[bytes]:
    """Longest run of full hex bytes (no wildcards/gaps) -> AC pre-filter anchor."""
    s = hexsig.replace(" ", "")
    best = bytearray()
    cur = bytearray()
    i = 0
    while i < len(s):
        c = s[i]
        if c in "0123456789abcdefABCDEF" and i + 1 < len(s) and \
                s[i + 1] in "0123456789abcdefABCDEF":
            cur.append(int(s[i:i + 2], 16))
            i += 2
            continue
        if c in "{([":
            close = {"{": "}", "(": ")", "[": "]"}[c]
            i = s.index(close, i) + 1
        else:
            i += 1
        if len(cur) > len(best):
            best = cur[:]
        cur = bytearray()
    if len(cur) > len(best):
        best = cur[:]
    return bytes(best) if len(best) >= minlen else None


# ===========================================================================
# Result + compiled-signature models
# ===========================================================================
@dataclass
class AvResult:
    infected: bool = False
    virus_name: str = ""
    sig_id: Optional[int] = None
    family: str = ""
    severity: str = ""
    verdict: str = "benign"
    action: int = ACTION_ALERT
    method: str = ""                 # hash / pattern / yara
    offset: int = -1
    file_type: Optional[str] = None
    sha256: str = ""

    def summary(self) -> str:
        return ("CLEAN" if not self.infected else
                "INFECTED %s (%s, via %s)" % (self.virus_name, self.family or "?", self.method))


@dataclass
class _Pat:
    sig_id: int
    name: str
    rx: "re.Pattern"
    offset: str
    target: str
    family: str
    severity: str
    verdict: str
    action: int


@dataclass
class _Yara:
    sig_id: int
    name: str
    strings: List[bytes]
    condition: str
    target: str
    family: str
    severity: str
    verdict: str
    action: int


# ===========================================================================
# The scanner
# ===========================================================================
class AntiVirus:
    def __init__(self, sigdb: "SignatureDB"):
        self.sigdb = sigdb
        self._hash_index: Dict[Tuple[str, str], dict] = {}
        self._pat_by_anchor: Dict[int, _Pat] = {}     # sig_id -> pat (AC candidates)
        self._pat_noanchor: List[_Pat] = []           # patterns with no literal anchor
        self._ac = None
        self._yara: List[_Yara] = []
        self.stats = {"scanned": 0, "infected": 0, "hash": 0, "pattern": 0, "yara": 0}
        self.compile()

    def compile(self) -> None:
        """(Re)build the in-memory matchers from the signature DB."""
        self._hash_index.clear()
        self._pat_by_anchor.clear()
        self._pat_noanchor.clear()
        self._yara.clear()
        ac = AhoCorasick() if AhoCorasick else None
        n_anchor = 0

        for s in self.sigdb.iter_signatures():
            st = s["sig_type"]
            if st == "hash":
                self._hash_index[(s["hash_type"], s["hash_value"])] = s
            elif st == "pattern":
                rx = compile_hexsig(s["hex_pattern"])
                if rx is None:
                    continue
                pat = _Pat(s["sig_id"], s["name"], rx, s["offset"], s["target"],
                           s["malware_family"] or "", s["severity"], s["verdict"], s["action"])
                anchor = literal_anchor(s["hex_pattern"])
                if anchor and ac is not None:
                    ac.add(anchor, s["sig_id"])
                    self._pat_by_anchor[s["sig_id"]] = pat
                    n_anchor += 1
                else:
                    self._pat_noanchor.append(pat)
            elif st == "yara":
                import json
                y = json.loads(s["yara_json"])
                strings = []
                for v in y.get("strings", {}).values():
                    strings.append(bytes.fromhex(v[4:]) if isinstance(v, str) and v.startswith("hex:")
                                   else v.encode("utf-8", "ignore") if isinstance(v, str) else v)
                self._yara.append(_Yara(
                    s["sig_id"], s["name"], strings, y.get("condition", "all"),
                    s["target"], s["malware_family"] or "", s["severity"],
                    s["verdict"], s["action"]))
        self._ac = ac.build() if (ac is not None and n_anchor) else None
        logger.info("AV compiled: %d hash, %d anchored + %d unanchored patterns, %d yara",
                    len(self._hash_index), n_anchor, len(self._pat_noanchor), len(self._yara))

    # -- offset-anchored confirm ------------------------------------------
    @staticmethod
    def _offset_match(rx: "re.Pattern", data: bytes, offset: str):
        offset = (offset or "*").strip()
        if offset in ("*", "") or offset.startswith(("EP", "S")):
            return rx.search(data)                    # anywhere (EP/Sx approximated)
        if offset.startswith("EOF-"):
            try:
                n = int(offset[4:])
            except ValueError:
                return rx.search(data)
            return rx.search(data, max(0, len(data) - n - 256))
        if offset.lstrip("-").isdigit():
            return rx.match(data, int(offset))        # absolute: must start at N
        return rx.search(data)

    def _target_ok(self, target: str, ftype: Optional[str]) -> bool:
        return target == "any" or ftype is None or target == ftype

    def _cond_met(self, condition: str, hits: int, total: int) -> bool:
        c = (condition or "all").strip().lower()
        if c == "all":
            return hits == total
        if c == "any":
            return hits >= 1
        m = re.match(r"(\d+)\s+of\s+them", c)
        if m:
            return hits >= int(m.group(1))
        return hits == total

    # -- scan --------------------------------------------------------------
    def scan_file(self, data: bytes) -> AvResult:
        self.stats["scanned"] += 1
        res = AvResult(file_type=detect_file_type(data))
        if not data:
            return res
        res.sha256 = hashlib.sha256(data).hexdigest()

        # 1) hash signatures (cheapest, most specific)
        digests = {"md5": hashlib.md5(data).hexdigest(),
                   "sha1": hashlib.sha1(data).hexdigest(),
                   "sha256": res.sha256}
        for ht, hv in digests.items():
            sig = self._hash_index.get((ht, hv))
            if sig and sig["file_size"] in (0, len(data)):
                return self._hit(res, sig, "hash", 0)

        # 2) body signatures: AC pre-filter -> anchored regex confirm
        candidates: List[_Pat] = list(self._pat_noanchor)
        if self._ac is not None:
            seen = set()
            for _end, sid in self._ac.iter_matches(data):
                if sid not in seen:
                    seen.add(sid)
                    p = self._pat_by_anchor.get(sid)
                    if p:
                        candidates.append(p)
        for pat in candidates:
            if not self._target_ok(pat.target, res.file_type):
                continue
            m = self._offset_match(pat.rx, data, pat.offset)
            if m:
                return self._hit(res, self._pat_dict(pat), "pattern", m.start())

        # 3) YARA-lite rules
        for y in self._yara:
            if not self._target_ok(y.target, res.file_type):
                continue
            hits = sum(1 for s in y.strings if s and s in data)
            if self._cond_met(y.condition, hits, len(y.strings)):
                return self._hit(res, self._yara_dict(y), "yara", 0)

        return res

    def scan(self, data: bytes) -> AvResult:
        return self.scan_file(data)

    # -- helpers -----------------------------------------------------------
    def _hit(self, res: AvResult, sig: dict, method: str, offset: int) -> AvResult:
        res.infected = True
        res.virus_name = sig["name"]
        res.sig_id = sig.get("sig_id")
        res.family = sig.get("malware_family") or ""
        res.severity = sig.get("severity", "high")
        res.verdict = sig.get("verdict", "malware")
        res.action = sig.get("action", ACTION_RESET)
        res.method = method
        res.offset = offset
        self.stats["infected"] += 1
        self.stats[method] = self.stats.get(method, 0) + 1
        return res

    @staticmethod
    def _pat_dict(p: _Pat) -> dict:
        return {"sig_id": p.sig_id, "name": p.name, "malware_family": p.family,
                "severity": p.severity, "verdict": p.verdict, "action": p.action}

    @staticmethod
    def _yara_dict(y: _Yara) -> dict:
        return {"sig_id": y.sig_id, "name": y.name, "malware_family": y.family,
                "severity": y.severity, "verdict": y.verdict, "action": y.action}


# ===========================================================================
# Self-test -- no hardware, no network
# ===========================================================================
def selftest() -> int:
    print("ffn_antivirus selftest")

    # -- 1. hexsig compiler unit checks -----------------------------------
    rx = compile_hexsig("4d5a??00")          # MZ, any byte, 00
    assert rx.match(b"MZ\x99\x00") and not rx.match(b"MZ\x99\x01")
    rx = compile_hexsig("4?5a")              # nibble wildcard: 4?
    assert rx.match(b"\x4a\x5a") and rx.match(b"\x4f\x5a") and not rx.match(b"\x5a\x5a")
    rx = compile_hexsig("9090{2}9090")       # exact 2-byte gap
    assert rx.match(b"\x90\x90ab\x90\x90") and not rx.match(b"\x90\x90abc\x90\x90")
    rx = compile_hexsig("90{2-4}90")         # variable gap
    assert rx.match(b"\x90aa\x90") and rx.match(b"\x90aaaa\x90") and not rx.match(b"\x90a\x90")
    rx = compile_hexsig("(4d5a|7f45)9000")   # alternation
    assert rx.match(b"MZ\x90\x00") and rx.match(b"\x7fE\x90\x00")
    print("  [ok] hexsig compiler: ?? / nibble / {n} / {n-m} / alternation")

    # -- 2. literal anchor extraction -------------------------------------
    assert literal_anchor("4d5a????90909090") == b"\x90\x90\x90\x90"
    assert literal_anchor("4d5a90000300") == b"\x4d\x5a\x90\x00\x03\x00"
    assert literal_anchor("??{4}9090") is None          # no 4-byte literal run
    print("  [ok] literal anchor extraction for AC pre-filter")

    if SignatureDB is None:
        print("  [skip] ffn_sigdb unavailable"); print("  all (available) assertions passed")
        return 0

    # -- 3. scan against the baseline signature DB ------------------------
    db = SignatureDB(":memory:")
    seed_baseline(db)
    av = AntiVirus(db)

    eicar = (rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
    r = av.scan_file(eicar)
    assert r.infected and r.family == "EICAR", r.summary()
    print("  [ok] EICAR ->", r.summary(), "(sha256 hash sig)")

    # embed EICAR body in a larger buffer -> body pattern (not exact hash)
    r2 = av.scan_file(b"harmless header ... " + eicar + b" ... trailer")
    assert r2.infected and r2.method == "pattern", "embedded EICAR should hit body sig"
    print("  [ok] embedded EICAR body ->", r2.summary())

    # PE importing CreateRemoteThread -> pattern (target=pe)
    pe = b"MZ\x90\x00" + b"\x00" * 40 + b"CreateRemoteThread" + os.urandom(32)
    r3 = av.scan_file(pe)
    assert r3.infected and r3.file_type == "pe", r3.summary()
    print("  [ok] PE injector body ->", r3.summary())

    # ELF reverse shell marker -> pattern (target=elf), NOT matched on a PE
    elf = b"\x7fELF" + b"\x00" * 30 + b"/bin/sh\x00-c" + os.urandom(16)
    r4 = av.scan_file(elf)
    assert r4.infected and r4.family == "Backdoor", r4.summary()
    # the elf-target sig must NOT fire on a PE-typed file
    pe_no = av.scan_file(b"MZ\x90\x00" + b"/bin/sh\x00-c" + os.urandom(16))
    assert not (pe_no.infected and pe_no.family == "Backdoor"), "elf sig leaked onto PE"
    print("  [ok] ELF backdoor body + file-type targeting (no PE leak)")

    # YARA-lite: Dropper needs BOTH URLDownloadToFile AND WinExec
    y_both = av.scan_file(b"MZ\x90\x00 URLDownloadToFile ... WinExec ...")
    y_one = av.scan_file(b"MZ\x90\x00 URLDownloadToFile only")
    assert y_both.infected and y_both.method == "yara", y_both.summary()
    assert not y_one.infected, "YARA 'all of them' must require both strings"
    print("  [ok] YARA-lite 'all of them' ->", y_both.summary())

    # -- 4. clean file + offset anchoring ---------------------------------
    assert not av.scan_file(b"just some totally benign text file contents").infected
    db.add_pattern("Abs.Offset.Test", b"DEADBEEF".hex(), target="any", offset="4")
    av.compile()
    assert av.scan_file(b"....DEADBEEF").infected, "absolute-offset sig should match at 4"
    assert not av.scan_file(b".....DEADBEEF").infected, "should NOT match at offset 5"
    print("  [ok] clean file passes; absolute-offset anchoring exact")

    # -- 5. AC pre-filter actually narrows the candidate set --------------
    # add 50 noise patterns; scanning a benign file confirms none fire
    for i in range(50):
        db.add_pattern("Noise-%d" % i, ("%08x" % (0xA0000000 + i)), target="any")
    av.compile()
    assert not av.scan_file(b"nothing to see here, move along").infected
    assert av._ac is not None, "AC pre-filter should be built with anchored sigs"
    print("  [ok] AC pre-filter with 50+ sigs; benign file clean; stats:", av.stats)

    db.close()
    print("  all assertions passed")
    return 0


# ===========================================================================
# CLI
# ===========================================================================
def main(argv=None):
    ap = argparse.ArgumentParser(description="FFN NGFW anti-virus file scanner")
    ap.add_argument("--db", default=os.getenv("FFN_SIGDB_PATH", "/var/lib/ffn-ngfw/sigdb.sqlite"))
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("selftest")
    sub.add_parser("test-eicar")
    sp = sub.add_parser("scan"); sp.add_argument("file")
    sp = sub.add_parser("scan-hex"); sp.add_argument("hex")
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    if args.cmd == "selftest":
        return selftest()
    if SignatureDB is None:
        print("ffn_sigdb unavailable", file=sys.stderr); return 1

    db = SignatureDB(args.db)
    if db.count() == 0:
        seed_baseline(db)
    av = AntiVirus(db)
    try:
        if args.cmd == "test-eicar":
            data = (rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
        elif args.cmd == "scan":
            data = open(args.file, "rb").read()
        else:
            import binascii
            data = binascii.unhexlify(args.hex)
        r = av.scan_file(data)
        print(r.summary())
        if r.infected:
            print("  sig_id=%s severity=%s verdict=%s action=%d offset=%d" %
                  (r.sig_id, r.severity, r.verdict, r.action, r.offset))
        return 1 if r.infected else 0
    finally:
        db.close()


if __name__ == "__main__":
    sys.exit(main())
