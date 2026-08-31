#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""
ffn_fastpath_compile.py -- compile the FFN signature DBs into the DPDK
fast-path's Hyperscan pattern file + mmap'd binary tables.

This is the control-plane bridge for the smart-NIC pivot: the host DPDK data
plane (ffn_dpdk_fwd) does line-rate content inspection with Hyperscan, but it
does not know about our Python sig stores. This compiler reads them and emits
the exact artifacts the C fast path loads:

    ffn_sigdb.av_signatures  (hash / pattern[ClamAV] / yara)  ┐
    inline_payload_det.content_signatures (IPS content/pcre)  ├─▶ compile
    ffn_bmfw policy (zones/rules) [optional]                  ┘
                              │
        ┌────────────┬────────┴─────┬───────────┬───────────┐
   .hspat        patmeta.bin    avhash.bin   policy.bin   strings.bin
 (Hyperscan     (per-pattern    (file-hash   (5-tuple     (threat
  patterns)      action/off)     blocklist)   policy)      names)
                              │
                        manifest.json  (crc/count cross-check)

Everything except the final `hs_compile` (which needs libhs) is pure stdlib and
offline-testable: the `.hspat` is stock Hyperscan text, and the selftest
round-trips every .bin (crc/count/record_size) and verifies every emitted PCRE
compiles under Python `re` with the mapped flags. The libhs step is separate
(ffn_hs_build / hs_compile_ext_multi) and gated on the data-plane host.

ABI: see docs/FASTPATH_ABI.md (this file is the reference producer).

CLI:
    ffn_fastpath_compile.py selftest
    ffn_fastpath_compile.py build --out /var/lib/ffn-ngfw/fastpath [--sigdb ...] [--threatdb ...]
"""

import argparse
import binascii
import hashlib
import json
import logging
import os
import re
import struct
import sys
import time
import zlib

logger = logging.getLogger("ffn-fastpath-compile")

# --- Hyperscan flag bits (libhs hs_compile.h) -------------------------------
HS_CASELESS      = 1      # HS_FLAG_CASELESS
HS_DOTALL        = 2      # HS_FLAG_DOTALL
HS_SINGLEMATCH   = 8      # HS_FLAG_SINGLEMATCH
HS_PREFILTER     = 128    # HS_FLAG_PREFILTER
HS_SOM_LEFTMOST  = 256    # HS_FLAG_SOM_LEFTMOST
HS_COMBINATION   = 512    # HS_FLAG_COMBINATION
HS_QUIET         = 1024   # HS_FLAG_QUIET
# .hspat single-letter flags -> HS flag bit  (hsbench/hscollider convention)
FLAG_LETTER = {"i": HS_CASELESS, "s": HS_DOTALL, "H": HS_SINGLEMATCH,
               "P": HS_PREFILTER, "L": HS_SOM_LEFTMOST, "C": HS_COMBINATION,
               "Q": HS_QUIET}
# for the offline selftest: map HS flags we can honour to python re flags
_PY_RE_FLAGS = {HS_CASELESS: re.I, HS_DOTALL: re.S}

# action codes (shared with ffn_sigdb / ffn_threatdb)
ACT_ALERT, ACT_DROP, ACT_RESET = 0, 1, 2
SEV_CODE = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
VERDICT_CODE = {"grayware": 0, "phishing": 1, "malware": 2, "benign": 0, "unknown": 0}
ORIGIN_IPS, ORIGIN_AV_NDB, ORIGIN_YARA_SUB, ORIGIN_YARA_COMBO = 0, 1, 2, 3

# table_type ids
T_POLICY, T_PATMETA, T_AVHASH, T_STRINGS = 0x40, 0x41, 0x42, 0x43
MAGIC = {T_POLICY: b"FPPO", T_PATMETA: b"FPPM", T_AVHASH: b"FPPH", T_STRINGS: b"FPPS"}

# struct formats (little-endian, packed) -- record_size is written into the
# header so the C app validates sizeof() dynamically.
HDR_FMT = "<4sHHIQIIII"                    # magic,ver,type,count,ts,crc,recsz,pop,rsvd
HDR_SIZE = struct.calcsize(HDR_FMT)        # 36
POLICY_FMT  = "<IIIIHHHHBBBBHH"            # 32
PATMETA_FMT = "<IIIIHBBBBHHHH"            # pat_id,flags,minoff,maxoff,minlen,act,sev,orig,hconf,combo,name,verdict,sid
AVHASH_FMT  = "<32sIBBH"                  # sha256,size,act,sev,name_idx
POLICY_SIZE  = struct.calcsize(POLICY_FMT)
PATMETA_SIZE = struct.calcsize(PATMETA_FMT)
AVHASH_SIZE  = struct.calcsize(AVHASH_FMT)


def _now() -> int:
    return int(time.time())


def _hdr(table_type: int, count: int, payload: bytes, record_size: int,
         populated: int = None) -> bytes:
    if populated is None:
        populated = count
    crc = zlib.crc32(payload) & 0xFFFFFFFF
    return struct.pack(HDR_FMT, MAGIC[table_type], 1, table_type, count,
                       _now(), crc, record_size, populated, 0)


# ===========================================================================
# byte -> PCRE-text helpers
# ===========================================================================
def byte_pcre(b: int) -> str:
    """One raw byte as a byte-exact PCRE token (always \\xNN, ASCII-safe)."""
    return "\\x%02x" % b


def bytes_pcre(data: bytes) -> str:
    return "".join(byte_pcre(b) for b in data)


def _nibble_class(hi: str, lo: str) -> str:
    if hi == "?" and lo == "?":
        return "."                                   # any byte (needs s flag)
    if hi == "?":                                     # low nibble fixed
        lov = int(lo, 16)
        return "[" + "".join(byte_pcre((n << 4) | lov) for n in range(16)) + "]"
    if lo == "?":                                     # high nibble fixed (contiguous)
        hiv = int(hi, 16)
        return "[%s-%s]" % (byte_pcre(hiv << 4), byte_pcre((hiv << 4) | 0xF))
    return byte_pcre(int(hi + lo, 16))


def hexsig_to_pcre(hexsig: str) -> str:
    """ClamAV .ndb body signature -> PCRE text (mirrors ffn_antivirus.compile_hexsig)."""
    s = hexsig.replace(" ", "")
    out, i = [], 0
    while i < len(s):
        c = s[i]
        if c == "*":
            out.append(".*"); i += 1
        elif c == "{":
            j = s.index("}", i); spec = s[i + 1:j].strip()
            if "-" in spec:
                a, _, b = spec.partition("-")
                a = a or "0"
                out.append(".{%s,}" % a if b == "" else ".{%s,%s}" % (a, b))
            else:
                out.append(".{%s}" % spec)
            i = j + 1
        elif c == "(":
            j = s.index(")", i)
            alts = s[i + 1:j].split("|")
            out.append("(?:" + "|".join(bytes_pcre(binascii.unhexlify(a)) for a in alts) + ")")
            i = j + 1
        elif c == "[":
            j = s.index("]", i)
            lo, _, hi = s[i + 1:j].partition("-")
            out.append("[%s-%s]" % (byte_pcre(int(lo, 16)), byte_pcre(int(hi, 16))))
            i = j + 1
        else:
            out.append(_nibble_class(s[i], s[i + 1])); i += 2
    return "".join(out)


def clamav_offset_ext(offset: str, patlen_guess: int):
    """ClamAV offset -> (min_offset, max_offset, host_confirm)."""
    offset = (offset or "*").strip()
    if offset in ("*", ""):
        return 0, 0, 0
    if offset.startswith(("EP", "S")):                # entrypoint/section: needs host confirm
        return 0, 0, 1
    if offset.startswith("EOF-"):
        return 0, 0, 1
    if offset.lstrip("-").isdigit():
        n = int(offset)
        return n, n + max(patlen_guess, 1), 0
    return 0, 0, 1


# ===========================================================================
# The compiler
# ===========================================================================
class FastPathCompiler:
    def __init__(self, sigdb=None, threatdb=None):
        self.sigdb = sigdb          # ffn_sigdb.SignatureDB
        self.threatdb = threatdb    # ffn_threatdb.ThreatDB (has content_signatures)
        # accumulated outputs
        self.hspat = []             # list of (id, pcre, flags_str)
        self.patmeta = []           # list of dict per id (dense, index==id)
        self.avhash = []            # list of (sha256_bytes, size, action, sev, name)
        self.strings = bytearray()  # NUL-terminated blob
        self._str_index = {}        # str -> offset
        self._next_id = 0

    # -- string interning -------------------------------------------------
    def _intern(self, s):
        if not s:
            return 0xFFFF
        if s in self._str_index:
            return self._str_index[s]
        off = len(self.strings)
        if off > 0xFFFE:
            return 0xFFFF
        self._str_index[s] = off
        self.strings += s.encode("utf-8", "ignore") + b"\x00"
        return off

    # -- add one Hyperscan pattern ---------------------------------------
    def _add_pattern(self, pcre, *, flags, action, severity, origin, verdict,
                     threat_name, src_sid, min_off=0, max_off=0, min_len=0,
                     host_confirm=0, combo_group=0xFFFF):
        pid = self._next_id
        self._next_id += 1
        # ensure byte-oriented sigs get DOTALL, single-shot reporting
        if "s" not in flags and "C" not in flags:
            flags += "s"
        if "H" not in flags and "C" not in flags and "Q" not in flags:
            flags += "H"
        if (min_off or max_off) and "L" not in flags:
            flags += "L"
        hsf = 0
        for ch in flags:
            hsf |= FLAG_LETTER.get(ch, 0)
        self.hspat.append((pid, pcre, "".join(sorted(set(flags)))))
        self.patmeta.append({
            "pat_id": pid, "hs_flags": hsf, "min_offset": min_off,
            "max_offset": max_off, "min_length": min_len,
            "action": action, "severity": SEV_CODE.get(severity, 3),
            "origin": origin, "host_confirm": host_confirm,
            "combo_group": combo_group, "name_idx": self._intern(threat_name),
            "verdict": VERDICT_CODE.get(verdict, 2), "src_sid": src_sid & 0xFFFF,
        })
        return pid

    # -- load from the sig DBs -------------------------------------------
    def load_content_signatures(self):
        """IPS stream sigs from inline_payload_det.content_signatures."""
        if self.threatdb is None:
            return 0
        n = 0
        try:
            cur = self.threatdb.conn.execute(
                "SELECT * FROM content_signatures WHERE enabled=1")
        except Exception:
            return 0
        for r in cur:
            try:
                raw = binascii.unhexlify(r["pattern_hex"])
            except Exception:
                continue
            if r["is_pcre"]:
                pcre = raw.decode("latin-1")           # already a regex body
                host_confirm = 0
            else:
                pcre = bytes_pcre(raw)                  # literal bytes
                host_confirm = 0
            flags = "i" if r["nocase"] else ""
            off, depth = r["offset"] or 0, r["depth"] or 0
            min_off = off if off > 0 else 0
            max_off = (off + depth) if depth > 0 else 0
            self._add_pattern(
                pcre, flags=flags, action=r["action"], severity=r["severity"],
                origin=ORIGIN_IPS, verdict=r["verdict"],
                threat_name=r["threat_name"] or r["name"], src_sid=r["sid"],
                min_off=min_off, max_off=max_off, host_confirm=host_confirm)
            n += 1
        return n

    def load_av_signatures(self):
        """AV file sigs from ffn_sigdb.av_signatures (pattern/yara/hash)."""
        if self.sigdb is None:
            return {"pattern": 0, "yara": 0, "hash": 0}
        counts = {"pattern": 0, "yara": 0, "hash": 0}
        for s in self.sigdb.iter_signatures():
            st = s["sig_type"]
            if st == "hash":
                if s["hash_type"] != "sha256":
                    continue                            # fast path is sha256-only
                try:
                    h = bytes.fromhex(s["hash_value"])
                except Exception:
                    continue
                if len(h) != 32:
                    continue
                self.avhash.append((h, s["file_size"] or 0, s["action"],
                                    SEV_CODE.get(s["severity"], 3),
                                    self._intern(s["name"])))
                counts["hash"] += 1
            elif st == "pattern":
                pcre = hexsig_to_pcre(s["hex_pattern"])
                patlen = len(s["hex_pattern"].replace(" ", "")) // 2
                min_off, max_off, hc = clamav_offset_ext(s["offset"], patlen)
                flags = "P" if hc else ""
                self._add_pattern(
                    pcre, flags=flags, action=s["action"], severity=s["severity"],
                    origin=ORIGIN_AV_NDB, verdict=s["verdict"],
                    threat_name=s["name"], src_sid=s["sig_id"],
                    min_off=min_off, max_off=max_off, host_confirm=hc)
                counts["pattern"] += 1
            elif st == "yara":
                self._load_yara(s)
                counts["yara"] += 1
        return counts

    def _load_yara(self, s):
        """YARA rule -> Q sub-string patterns + a C combination expression."""
        y = json.loads(s["yara_json"])
        strings = y.get("strings", {})
        condition = y.get("condition", "all")
        sub_ids = []
        combo_grp = s["sig_id"] & 0xFFFF
        for val in strings.values():
            if isinstance(val, str) and val.startswith("hex:"):
                pcre = bytes_pcre(bytes.fromhex(val[4:]))
            else:
                pcre = bytes_pcre(val.encode("utf-8", "ignore"))
            sid = self._add_pattern(
                pcre, flags="Q", action=s["action"], severity=s["severity"],
                origin=ORIGIN_YARA_SUB, verdict=s["verdict"],
                threat_name=s["name"], src_sid=s["sig_id"],
                combo_group=combo_grp)
            sub_ids.append(sid)
        if not sub_ids:
            return
        if condition == "all":
            expr = "(" + " & ".join(str(i) for i in sub_ids) + ")"
            self._add_pattern(expr, flags="C", action=s["action"],
                              severity=s["severity"], origin=ORIGIN_YARA_COMBO,
                              verdict=s["verdict"], threat_name=s["name"],
                              src_sid=s["sig_id"], combo_group=combo_grp)
        elif condition == "any":
            expr = "(" + " | ".join(str(i) for i in sub_ids) + ")"
            self._add_pattern(expr, flags="C", action=s["action"],
                              severity=s["severity"], origin=ORIGIN_YARA_COMBO,
                              verdict=s["verdict"], threat_name=s["name"],
                              src_sid=s["sig_id"], combo_group=combo_grp)
        else:  # "N of them": prefilter + host confirm (counts hits host-side)
            for i in sub_ids:
                self.patmeta[i]["host_confirm"] = 1
                self.patmeta[i]["hs_flags"] |= HS_PREFILTER

    def load_policy(self, rules=None, vsys=0):
        """5-tuple policy rows -> policy.bin. rules = list of dicts (optional).

        `vsys` is the numeric vsys_id of the rulebase being compiled (contract
        §2: stable int in [1..N], 0 = shared/untagged). It becomes the default
        tag written into `fp_policy_ent.vsys` for every row that does not carry
        its own per-rule `vsys`; a row may override it by setting `r['vsys']`.
        """
        self.policy_vsys = int(vsys) & 0xFF
        self.policy = []
        for r in (rules or []):
            self.policy.append(r)
        return len(self.policy)

    # -- serialise --------------------------------------------------------
    def _pack_patmeta(self):
        buf = bytearray()
        for m in self.patmeta:
            buf += struct.pack(PATMETA_FMT, m["pat_id"], m["hs_flags"],
                               m["min_offset"], m["max_offset"], m["min_length"],
                               m["action"], m["severity"], m["origin"],
                               m["host_confirm"], m["combo_group"], m["name_idx"],
                               m["verdict"], m["src_sid"])
        return _hdr(T_PATMETA, len(self.patmeta), bytes(buf), PATMETA_SIZE) + buf

    def _pack_avhash(self):
        n = len(self.avhash)
        slots = 1
        while slots < max(n * 2, 8):
            slots <<= 1
        table = [None] * slots
        for ent in self.avhash:
            h = ent[0]
            bucket = struct.unpack("<Q", h[:8])[0] & (slots - 1)
            while table[bucket] is not None:
                bucket = (bucket + 1) & (slots - 1)
            table[bucket] = ent
        buf = bytearray()
        empty = struct.pack(AVHASH_FMT, b"\x00" * 32, 0, 0, 0, 0)
        for slot in table:
            if slot is None:
                buf += empty
            else:
                h, size, act, sev, name = slot
                buf += struct.pack(AVHASH_FMT, h, size, act, sev, name)
        return _hdr(T_AVHASH, slots, bytes(buf), AVHASH_SIZE, populated=n) + buf

    def _pack_policy(self):
        rows = getattr(self, "policy", [])
        default_vsys = getattr(self, "policy_vsys", 0)
        buf = bytearray()
        for r in rows:
            # real numeric vsys_id: per-rule override, else the rulebase's vsys
            vsys = int(r.get("vsys", default_vsys)) & 0xFF
            buf += struct.pack(
                POLICY_FMT,
                r.get("src_ip", 0), r.get("src_mask", 0),
                r.get("dst_ip", 0), r.get("dst_mask", 0),
                r.get("sport_lo", 0), r.get("sport_hi", 0xFFFF),
                r.get("dport_lo", 0), r.get("dport_hi", 0xFFFF),
                r.get("proto", 0), vsys, r.get("action", 1),
                r.get("flags", 0), r.get("egress_port", 0xFFFF),
                r.get("rule_id", 0))
        return _hdr(T_POLICY, len(rows), bytes(buf), POLICY_SIZE) + buf

    def _pack_strings(self):
        return _hdr(T_STRINGS, len(self.strings), bytes(self.strings), 1) + bytes(self.strings)

    def write_hspat(self):
        lines = ["# ffn_fastpath.hspat v1"]
        for pid, pcre, flags in self.hspat:
            lines.append("%d:/%s/%s" % (pid, pcre, flags))
        return "\n".join(lines) + "\n"

    def build(self, out_dir):
        os.makedirs(out_dir, exist_ok=True)
        artifacts = {
            "ffn_fastpath.hspat":      self.write_hspat().encode(),
            "ffn_fastpath.patmeta.bin": self._pack_patmeta(),
            "ffn_fastpath.avhash.bin":  self._pack_avhash(),
            "ffn_fastpath.policy.bin":  self._pack_policy(),
            "ffn_fastpath.strings.bin": self._pack_strings(),
        }
        for name, data in artifacts.items():
            with open(os.path.join(out_dir, name), "wb") as f:
                f.write(data)
        manifest = {
            "version": 1, "build_unix": _now(),
            "sigdb_version": (self.sigdb.version_string() if self.sigdb else None),
            "tables": {
                "hspat":   {"path": "ffn_fastpath.hspat", "pattern_count": len(self.hspat)},
                "patmeta": {"path": "ffn_fastpath.patmeta.bin", "count": len(self.patmeta),
                            "record_size": PATMETA_SIZE, "crc32": self._crc(artifacts["ffn_fastpath.patmeta.bin"])},
                "avhash":  {"path": "ffn_fastpath.avhash.bin", "populated": len(self.avhash),
                            "crc32": self._crc(artifacts["ffn_fastpath.avhash.bin"])},
                "policy":  {"path": "ffn_fastpath.policy.bin", "count": len(getattr(self, "policy", [])),
                            "crc32": self._crc(artifacts["ffn_fastpath.policy.bin"])},
                "strings": {"path": "ffn_fastpath.strings.bin", "bytes": len(self.strings),
                            "crc32": self._crc(artifacts["ffn_fastpath.strings.bin"])},
                "hsdb":    {"present": False, "note": "run ffn_hs_build with libhs to serialize"},
            },
            "action_codes": {"alert": 0, "drop": 1, "reset": 2},
        }
        with open(os.path.join(out_dir, "manifest.json"), "w") as f:
            json.dump(manifest, f, indent=2)
        return manifest

    @staticmethod
    def _crc(table_bytes):
        # crc of payload after the 36-byte header (matches _hdr)
        return zlib.crc32(table_bytes[HDR_SIZE:]) & 0xFFFFFFFF


# ===========================================================================
# header/record round-trip validators (used by the C app + selftest)
# ===========================================================================
def parse_header(buf):
    magic, ver, ttype, count, ts, crc, recsz, pop, rsvd = struct.unpack(
        HDR_FMT, buf[:HDR_SIZE])
    return {"magic": magic, "version": ver, "type": ttype, "count": count,
            "crc32": crc, "record_size": recsz, "populated": pop}


def validate_table(buf, expect_type):
    h = parse_header(buf)
    assert h["magic"] == MAGIC[expect_type], "bad magic %r" % h["magic"]
    assert h["version"] == 1
    payload = buf[HDR_SIZE:]
    assert (zlib.crc32(payload) & 0xFFFFFFFF) == h["crc32"], "crc mismatch"
    return h


# ===========================================================================
# Self-test -- no libhs, no hardware
# ===========================================================================
def selftest():
    print("ffn_fastpath_compile selftest")

    # -- 1. hexsig -> PCRE mapping ---------------------------------------
    assert hexsig_to_pcre("4d5a") == "\\x4d\\x5a"
    assert hexsig_to_pcre("4d5a??00") == "\\x4d\\x5a.\\x00"
    assert hexsig_to_pcre("90{2-4}90").startswith("\\x90.{2,4}")
    assert "(?:" in hexsig_to_pcre("(4d5a|7f45)")
    assert hexsig_to_pcre("4?").startswith("[")           # nibble class
    print("  [ok] ClamAV hexsig -> PCRE (byte/??/{n-m}/alternation/nibble)")

    # -- 2. build against baseline sig DBs -------------------------------
    try:
        from ffn_sigdb import SignatureDB, seed_baseline as seed_sigs
        from ffn_threatdb import ThreatDB
        from inline_payload_det import InlinePayloadDetector, seed_baseline as seed_inline
    except Exception as e:
        print("  [skip] sig modules unavailable:", e); return 0

    sigdb = SignatureDB(":memory:"); seed_sigs(sigdb)
    tdb = ThreatDB(":memory:")
    inline = InlinePayloadDetector(tdb); seed_inline(inline)   # populates content_signatures

    c = FastPathCompiler(sigdb=sigdb, threatdb=tdb)
    n_ips = c.load_content_signatures()
    av = c.load_av_signatures()
    # rulebase compiled under vsys 2: rule_id=1 inherits the rulebase vsys,
    # rule_id=2 carries an explicit per-rule override (contract §2).
    c.load_policy([{"src_ip": 0, "dst_ip": 0, "dport_lo": 80, "dport_hi": 80,
                    "proto": 6, "action": 1, "rule_id": 1},
                   {"src_ip": 0, "dst_ip": 0, "dport_lo": 443, "dport_hi": 443,
                    "proto": 6, "action": 1, "rule_id": 2, "vsys": 5}],
                  vsys=2)
    assert n_ips >= 10, "expected IPS content sigs, got %d" % n_ips
    assert av["pattern"] >= 3 and av["hash"] >= 1 and av["yara"] >= 1, av
    print("  [ok] loaded %d IPS + %s AV sigs" % (n_ips, av))

    import tempfile
    out = tempfile.mkdtemp(prefix="ffn_fp_")
    manifest = c.build(out)
    print("  [ok] emitted:", sorted(os.listdir(out)))

    # -- 3. every .bin round-trips (magic/crc/count) ---------------------
    for fn, ttype in (("ffn_fastpath.patmeta.bin", T_PATMETA),
                      ("ffn_fastpath.avhash.bin", T_AVHASH),
                      ("ffn_fastpath.policy.bin", T_POLICY),
                      ("ffn_fastpath.strings.bin", T_STRINGS)):
        with open(os.path.join(out, fn), "rb") as f:
            h = validate_table(f.read(), ttype)
        print("  [ok] %-28s magic=%s count=%d recsz=%d" %
              (fn, h["magic"].decode(), h["count"], h["record_size"]))

    # patmeta count == hspat line count == dense id space
    hspat = open(os.path.join(out, "ffn_fastpath.hspat")).read().splitlines()
    pat_lines = [l for l in hspat if l and not l.startswith("#")]
    assert len(pat_lines) == len(c.patmeta), "hspat/patmeta count mismatch"
    ids = [int(l.split(":", 1)[0]) for l in pat_lines]
    assert ids == list(range(len(ids))), "pattern ids must be dense 0..N-1"
    print("  [ok] %d patterns, ids dense 0..%d, patmeta aligned" % (len(ids), len(ids) - 1))

    # -- 3b. policy vsys tag round-trips (contract §2) -------------------
    with open(os.path.join(out, "ffn_fastpath.policy.bin"), "rb") as f:
        praw = f.read()
    phdr = parse_header(praw)
    pol_by_rule = {}
    for i in range(phdr["count"]):
        off = HDR_SIZE + i * POLICY_SIZE
        fields = struct.unpack(POLICY_FMT, praw[off:off + POLICY_SIZE])
        rule_vsys, rule_id = fields[9], fields[13]
        pol_by_rule[rule_id] = rule_vsys
    assert pol_by_rule.get(1) == 2, \
        "rulebase vsys not inherited: rule 1 vsys=%r (want 2)" % pol_by_rule.get(1)
    assert pol_by_rule.get(2) == 5, \
        "per-rule vsys override lost: rule 2 vsys=%r (want 5)" % pol_by_rule.get(2)
    print("  [ok] policy vsys tag: rule1 inherits vsys=2, rule2 override vsys=5")

    # -- 4. every emitted PCRE compiles (catches \\xNN escaping bugs) ----
    bad = 0
    for line in pat_lines:
        pid, rest = line.split(":", 1)
        body, _, flags = rest[1:].rpartition("/")
        if "C" in flags:               # combination expr (id refs), not a regex
            continue
        pyflags = 0
        meta = c.patmeta[int(pid)]
        for bit, rf in _PY_RE_FLAGS.items():
            if meta["hs_flags"] & bit:
                pyflags |= rf
        try:
            re.compile(body.encode("latin-1"), pyflags)
        except re.error as e:
            bad += 1
            if bad <= 3:
                print("     BAD pcre id=%s: %s (%s)" % (pid, body[:50], e))
    assert bad == 0, "%d emitted PCREs failed to compile" % bad
    print("  [ok] all %d non-combination PCREs compile under python re" % (len(pat_lines)))

    # -- 5. avhash lookup works (the exact algorithm the C app uses) -----
    eicar = (r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
    sha = hashlib.sha256(eicar.encode("latin-1")).digest()
    with open(os.path.join(out, "ffn_fastpath.avhash.bin"), "rb") as f:
        raw = f.read()
    hdr = parse_header(raw)
    slots = hdr["count"]
    found = False
    bucket = struct.unpack("<Q", sha[:8])[0] & (slots - 1)
    for _ in range(slots):
        off = HDR_SIZE + bucket * AVHASH_SIZE
        rec = raw[off:off + AVHASH_SIZE]
        rh = rec[:32]
        if rh == b"\x00" * 32:
            break
        if rh == sha:
            found = True; break
        bucket = (bucket + 1) & (slots - 1)
    assert found, "EICAR sha256 not found via open-addressed probe"
    print("  [ok] avhash open-addressed lookup (EICAR sha256 hit)")

    # -- 6. manifest cross-check -----------------------------------------
    assert manifest["tables"]["patmeta"]["count"] == len(c.patmeta)
    assert manifest["sigdb_version"] == sigdb.version_string()
    print("  [ok] manifest:", {"pats": manifest["tables"]["hspat"]["pattern_count"],
                                "sigdb": manifest["sigdb_version"]})

    import shutil
    shutil.rmtree(out, ignore_errors=True)
    sigdb.close(); tdb.close()
    print("  all assertions passed")
    return 0


# ===========================================================================
# CLI
# ===========================================================================
def main(argv=None):
    ap = argparse.ArgumentParser(description="FFN fast-path table compiler")
    ap.add_argument("--sigdb", default=os.getenv("FFN_SIGDB_PATH", "/var/lib/ffn-ngfw/sigdb.sqlite"))
    ap.add_argument("--threatdb", default=os.getenv("FFN_THREATDB_PATH", "/var/lib/ffn-ngfw/threatdb.sqlite"))
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("selftest")
    sp = sub.add_parser("build"); sp.add_argument("--out", default="/var/lib/ffn-ngfw/fastpath")
    sp.add_argument("--seed", action="store_true", help="seed baseline sigs if empty")
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    if args.cmd == "selftest":
        return selftest()

    from ffn_sigdb import SignatureDB, seed_baseline as seed_sigs
    from ffn_threatdb import ThreatDB
    from inline_payload_det import InlinePayloadDetector, seed_baseline as seed_inline
    sigdb = SignatureDB(args.sigdb)
    tdb = ThreatDB(args.threatdb)
    inline = InlinePayloadDetector(tdb)
    if args.seed:
        if sigdb.count() == 0:
            seed_sigs(sigdb)
        if not inline.sigs:
            seed_inline(inline)
    c = FastPathCompiler(sigdb=sigdb, threatdb=tdb)
    n_ips = c.load_content_signatures()
    av = c.load_av_signatures()
    c.load_policy([])
    manifest = c.build(args.out)
    print("compiled %d IPS + %s AV -> %s" % (n_ips, av, args.out))
    print(json.dumps(manifest["tables"], indent=2))
    sigdb.close(); tdb.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
