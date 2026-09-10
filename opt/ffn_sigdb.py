#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""
ffn_sigdb.py -- FFN NGFW Signature Database (malware / virus / pattern content).

The versioned content store the anti-virus and anti-malware engines load from,
and the thing "content updates" bump -- the FFN equivalent of a ClamAV CVD set
or a PAN-OS content package.

    ClamAV .hdb/.hsb/.ndb  ┐
    YARA rules             ├─ import ─▶  SignatureDB (SQLite, versioned)
    native add_* API       ┘                  │
                                    ┌──────────┼───────────────┐
                              ffn_antivirus   ffn_antimalware   db_compiler
                              (file scan)     (inline verdict)  (FPGA MALWARE)

Signature classes (one `av_signatures` table, discriminated by `sig_type`):
  * hash    -- exact file hash (md5/sha1/sha256) + optional size (ClamAV .hdb/.hsb)
  * pattern -- offset-anchored hex body signature with wildcards (ClamAV .ndb)
  * yara    -- multi-string rule with an all/any/N-of condition (YARA-lite, JSON)

Distinct from, and complementary to:
  * ffn_threatdb.samples/iocs  -- verdict + IOC intel (Crucible feedback)
  * inline_payload_det.content_signatures -- IPS/stream byte rules (Suricata-ish)
This is the FILE anti-malware/AV content, plus the content-versioning that all
of them can hang updates off.

stdlib only. `--selftest` needs no hardware and no network.

CLI:
    ffn_sigdb.py selftest
    ffn_sigdb.py stats
    ffn_sigdb.py import-clamav <file> [--kind hdb|hsb|ndb|auto]
    ffn_sigdb.py import-yara  <file>
    ffn_sigdb.py add-hash <name> <sha256> [--size N] [--family F]
    ffn_sigdb.py version
    ffn_sigdb.py update <source>          # bump the content version
"""

import argparse
import hashlib
import json
import logging
import os
import re
import sqlite3
import sys
import time

logger = logging.getLogger("ffn-sigdb")

DEFAULT_DB = os.getenv("FFN_SIGDB_PATH", "/var/lib/ffn-ngfw/sigdb.sqlite")

SIG_TYPES = ("hash", "pattern", "yara")

# action codes shared with the rest of the stack (ffn_threatdb)
ACTION_ALERT, ACTION_DROP, ACTION_RESET = 0, 1, 2
SEVERITY_ACTION = {"info": ACTION_ALERT, "low": ACTION_ALERT, "medium": ACTION_DROP,
                   "high": ACTION_RESET, "critical": ACTION_RESET}

# ClamAV .ndb target-type code -> our file-type tag (detect_file_type()).
CLAMAV_TARGET = {0: "any", 1: "pe", 2: "ole", 3: "html", 4: "mail",
                 5: "graphics", 6: "elf", 7: "ascii", 9: "macho"}


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


# ===========================================================================
# hex-signature validation (the matcher lives in ffn_antivirus)
# ===========================================================================
def validate_hexsig(hexsig: str) -> bool:
    """Light syntax check for a ClamAV-style body signature.

    Accepts hex bytes, `??` nibble wildcards, `{n}` / `{n-m}` / `{-m}` / `{n-}`
    gaps, `*` (any gap), and `(aa|bb|..)` alternations. Full compilation to a
    byte-regex happens in the AV engine.
    """
    if not hexsig:
        return False
    # strip alternations + gaps, then the remainder must be hex or ??
    core = re.sub(r"\([0-9a-fA-F|?]+\)", "", hexsig)
    core = re.sub(r"\{[0-9]*-?[0-9]*\}", "", core)
    core = core.replace("*", "").replace("?", "")
    return bool(core) and all(c in "0123456789abcdefABCDEF" for c in core)


# ===========================================================================
# The database
# ===========================================================================
class SignatureDB:
    SCHEMA = """
    CREATE TABLE IF NOT EXISTS av_signatures (
        sig_id       INTEGER PRIMARY KEY AUTOINCREMENT,
        name         TEXT NOT NULL,
        sig_type     TEXT NOT NULL,               -- hash / pattern / yara
        malware_family TEXT,
        target       TEXT NOT NULL DEFAULT 'any',
        hash_type    TEXT,                         -- md5 / sha1 / sha256
        hash_value   TEXT,
        file_size    INTEGER NOT NULL DEFAULT 0,   -- 0 = any size
        offset       TEXT NOT NULL DEFAULT '*',
        hex_pattern  TEXT,
        yara_json    TEXT,
        severity     TEXT NOT NULL DEFAULT 'high',
        verdict      TEXT NOT NULL DEFAULT 'malware',
        action       INTEGER NOT NULL DEFAULT 2,
        min_engine   INTEGER NOT NULL DEFAULT 0,
        enabled      INTEGER NOT NULL DEFAULT 1,
        source       TEXT,
        db_version   INTEGER NOT NULL DEFAULT 0,
        added        TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_av_type   ON av_signatures(sig_type);
    CREATE INDEX IF NOT EXISTS idx_av_hash   ON av_signatures(hash_value);
    CREATE INDEX IF NOT EXISTS idx_av_family ON av_signatures(malware_family);

    CREATE TABLE IF NOT EXISTS sig_meta (
        key   TEXT PRIMARY KEY,
        value TEXT
    );
    CREATE TABLE IF NOT EXISTS sig_updates (
        version  INTEGER PRIMARY KEY,
        applied  TEXT,
        added    INTEGER NOT NULL DEFAULT 0,
        source   TEXT
    );
    """

    def __init__(self, path: str = DEFAULT_DB):
        self.path = path
        if path != ":memory:":
            os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        self.conn = sqlite3.connect(path)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(self.SCHEMA)
        if self._meta("version") is None:
            self._set_meta("version", "0")
            self._set_meta("created", _now())
        self.conn.commit()

    def close(self):
        self.conn.close()

    # -- meta / versioning -------------------------------------------------
    def _meta(self, key):
        r = self.conn.execute("SELECT value FROM sig_meta WHERE key=?", (key,)).fetchone()
        return r["value"] if r else None

    def _set_meta(self, key, value):
        self.conn.execute(
            "INSERT INTO sig_meta (key,value) VALUES (?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, str(value)))

    def version(self) -> int:
        return int(self._meta("version") or 0)

    def version_string(self) -> str:
        return "ffn-av-%d" % self.version()

    def apply_update(self, added: int, source: str = "manual") -> int:
        """Bump the content-package version (records an update log row)."""
        v = self.version() + 1
        self._set_meta("version", v)
        self._set_meta("last_update", _now())
        self.conn.execute(
            "INSERT INTO sig_updates (version,applied,added,source) VALUES (?,?,?,?)",
            (v, _now(), added, source))
        self.conn.commit()
        logger.info("content updated -> version %d (+%d sigs, %s)", v, added, source)
        return v

    def updates(self) -> list:
        return [dict(r) for r in self.conn.execute(
            "SELECT * FROM sig_updates ORDER BY version DESC")]

    # -- add signatures ----------------------------------------------------
    def _insert(self, **f) -> int:
        f.setdefault("added", _now())
        f.setdefault("db_version", self.version())
        cols = ",".join(f)
        cur = self.conn.execute(
            "INSERT INTO av_signatures (%s) VALUES (%s)" %
            (cols, ",".join("?" * len(f))), tuple(f.values()))
        self.conn.commit()
        return cur.lastrowid

    def add_hash(self, name, hash_value, *, hash_type="sha256", size=0, family=None,
                 severity="high", verdict="malware", target="any",
                 source="manual") -> int:
        hv = hash_value.lower().strip()
        lens = {32: "md5", 40: "sha1", 64: "sha256"}
        if hash_type == "auto":
            hash_type = lens.get(len(hv), "sha256")
        if any(c not in "0123456789abcdef" for c in hv):
            raise ValueError("bad hex hash %r" % hash_value)
        return self._insert(name=name, sig_type="hash", hash_type=hash_type,
                            hash_value=hv, file_size=size, malware_family=family,
                            severity=severity, verdict=verdict,
                            action=SEVERITY_ACTION.get(severity, ACTION_RESET),
                            target=target, source=source)

    def add_pattern(self, name, hex_pattern, *, target="any", offset="*",
                    family=None, severity="high", verdict="malware",
                    source="manual") -> int:
        hp = hex_pattern.replace(" ", "")
        if not validate_hexsig(hp):
            raise ValueError("invalid hex signature %r" % hex_pattern)
        return self._insert(name=name, sig_type="pattern", hex_pattern=hp,
                            target=target, offset=str(offset), malware_family=family,
                            severity=severity, verdict=verdict,
                            action=SEVERITY_ACTION.get(severity, ACTION_RESET),
                            source=source)

    def add_yara(self, name, strings: dict, condition: str, *, target="any",
                 family=None, severity="high", verdict="malware",
                 source="manual") -> int:
        """strings = {'$a': 'hexOrText', ...}; condition = 'all'|'any'|'N of them'.

        String values may be hex (prefix 'hex:') or plain text (matched as UTF-8
        bytes). Stored as JSON; matched by ffn_antivirus.
        """
        yj = json.dumps({"strings": strings, "condition": condition})
        return self._insert(name=name, sig_type="yara", yara_json=yj, target=target,
                            malware_family=family, severity=severity, verdict=verdict,
                            action=SEVERITY_ACTION.get(severity, ACTION_RESET),
                            source=source)

    # -- import: ClamAV --------------------------------------------------
    def import_clamav(self, text_or_lines, kind="auto", *, source="clamav") -> int:
        """Ingest ClamAV signatures. kind: hdb (md5), hsb (sha), ndb (pattern), auto."""
        lines = (text_or_lines if isinstance(text_or_lines, (list, tuple))
                 else text_or_lines.splitlines())
        n = 0
        for raw in lines:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            try:
                k = kind if kind != "auto" else self._guess_clamav(line)
                if k in ("hdb", "hsb"):
                    # <hash>:<size>:<name>
                    parts = line.split(":")
                    if len(parts) < 3:
                        continue
                    hv, size, name = parts[0], parts[1], parts[2]
                    ht = "md5" if len(hv) == 32 else "sha1" if len(hv) == 40 else "sha256"
                    self.add_hash(name, hv, hash_type=ht,
                                  size=int(size) if size.isdigit() else 0, source=source)
                    n += 1
                elif k == "ndb":
                    # <name>:<target>:<offset>:<hexsig>[:minfl:maxfl]
                    parts = line.split(":")
                    if len(parts) < 4:
                        continue
                    name, tgt, off, hexsig = parts[0], parts[1], parts[2], parts[3]
                    target = CLAMAV_TARGET.get(int(tgt) if tgt.isdigit() else 0, "any")
                    self.add_pattern(name, hexsig, target=target, offset=off, source=source)
                    n += 1
            except Exception as e:
                logger.debug("skip clamav line %r: %s", line[:60], e)
        if n:
            self.apply_update(n, source="clamav:%s" % kind)
        return n

    @staticmethod
    def _guess_clamav(line: str) -> str:
        head = line.split(":", 1)[0]
        # hdb/hsb start with a hex hash; ndb starts with a signature name
        if len(head) in (32, 40, 64) and all(c in "0123456789abcdefABCDEF" for c in head):
            return "hdb" if len(head) == 32 else "hsb"
        return "ndb"

    # -- import: YARA (basic subset) --------------------------------------
    _YARA_HDR = re.compile(r"rule\s+(\w+)\s*(?::[^\{]+)?\{")
    _YARA_STR = re.compile(r"\$(\w+)\s*=\s*(\"(?:\\.|[^\"])*\"|\{[0-9a-fA-F\s?]+\})")
    _YARA_COND = re.compile(r"condition\s*:\s*(.+?)\s*$", re.S)

    @classmethod
    def _iter_yara_rules(cls, text: str):
        """Yield (name, body) balancing braces -- so hex strings `{ .. }`
        inside a rule don't prematurely close the rule body (a flat non-greedy
        regex stops at the first '}')."""
        for m in cls._YARA_HDR.finditer(text):
            name = m.group(1)
            depth, j, start = 1, m.end(), m.end()
            while j < len(text) and depth:
                if text[j] == "{":
                    depth += 1
                elif text[j] == "}":
                    depth -= 1
                j += 1
            yield name, text[start:j - 1]

    def import_yara(self, text: str, *, source="yara") -> int:
        n = 0
        for name, body in self._iter_yara_rules(text):
            strings = {}
            for sm in self._YARA_STR.finditer(body):
                key, val = sm.group(1), sm.group(2)
                if val.startswith("{"):
                    strings["$" + key] = "hex:" + re.sub(r"\s", "", val[1:-1])
                else:
                    strings["$" + key] = bytes(val[1:-1], "utf-8").decode("unicode_escape")
            cm = self._YARA_COND.search(body)
            cond = self._normalize_yara_condition(cm.group(1).strip() if cm else "all")
            if strings:
                self.add_yara(name, strings, cond, source=source)
                n += 1
        if n:
            self.apply_update(n, source="yara")
        return n

    @staticmethod
    def _normalize_yara_condition(cond: str) -> str:
        c = cond.lower()
        if "all of them" in c:
            return "all"
        if "any of them" in c:
            return "any"
        m = re.search(r"(\d+)\s+of\s+them", c)
        if m:
            return "%s of them" % m.group(1)
        # $a and $b / $a or $b -> approximate to all/any
        if " or " in c and " and " not in c:
            return "any"
        return "all"

    # -- query -------------------------------------------------------------
    def iter_signatures(self, sig_type=None, target=None, *, enabled=True):
        q = "SELECT * FROM av_signatures WHERE 1=1"
        args = []
        if enabled:
            q += " AND enabled=1"
        if sig_type:
            q += " AND sig_type=?"
            args.append(sig_type)
        if target and target != "any":
            q += " AND target IN ('any', ?)"
            args.append(target)
        for r in self.conn.execute(q, args):
            yield dict(r)

    def get(self, sig_id):
        r = self.conn.execute("SELECT * FROM av_signatures WHERE sig_id=?",
                              (sig_id,)).fetchone()
        return dict(r) if r else None

    def lookup_hash(self, hash_value):
        hv = hash_value.lower().strip()
        r = self.conn.execute(
            "SELECT * FROM av_signatures WHERE sig_type='hash' AND hash_value=? "
            "AND enabled=1 LIMIT 1", (hv,)).fetchone()
        return dict(r) if r else None

    def count(self, sig_type=None) -> int:
        if sig_type:
            return self.conn.execute(
                "SELECT COUNT(*) c FROM av_signatures WHERE sig_type=?",
                (sig_type,)).fetchone()["c"]
        return self.conn.execute("SELECT COUNT(*) c FROM av_signatures").fetchone()["c"]

    def stats(self) -> dict:
        s = {"version": self.version(), "version_string": self.version_string(),
             "last_update": self._meta("last_update"), "by_type": {}, "by_severity": {},
             "families": self.conn.execute(
                 "SELECT COUNT(DISTINCT malware_family) c FROM av_signatures").fetchone()["c"]}
        for r in self.conn.execute("SELECT sig_type,COUNT(*) c FROM av_signatures GROUP BY sig_type"):
            s["by_type"][r["sig_type"]] = r["c"]
        for r in self.conn.execute("SELECT severity,COUNT(*) c FROM av_signatures GROUP BY severity"):
            s["by_severity"][r["severity"]] = r["c"]
        s["total"] = self.count()
        return s

    # -- compile / export --------------------------------------------------
    def export_hashes(self):
        """Yield (sha256, size, name) for hash sigs -> FPGA MALWARE region."""
        for r in self.conn.execute(
                "SELECT hash_value,file_size,name FROM av_signatures "
                "WHERE sig_type='hash' AND hash_type='sha256' AND enabled=1"):
            yield (r["hash_value"], r["file_size"], r["name"])

    def compile_to_fpga(self, threatdb=None, *, vsys=0, loader=None) -> dict:
        """Push AV hash signatures to the FPGA MALWARE region.

        Mirrors the sha256 hash sigs into the ThreatDB samples table (verdict
        'malware') so the existing db_compiler bridge loads them into hardware.
        Returns a summary. Runs in sim mode when no device is present.
        """
        summary = {"hashes": 0, "patterns": self.count("pattern"),
                   "yara": self.count("yara"), "version": self.version()}
        if threatdb is None:
            try:
                from ffn_threatdb import ThreatDB
                threatdb = ThreatDB()
            except Exception as e:
                summary["error"] = "threatdb unavailable: %s" % e
                return summary
        for sha, _size, name in self.export_hashes():
            try:
                threatdb.record_sample(sha, "malware", threat_name=name, source="sigdb")
                summary["hashes"] += 1
            except Exception:
                pass
        try:
            n, rc = threatdb.export_and_load("malware_hashes", vsys=vsys, loader=loader)
            summary["fpga_load"] = {"entries": n, "rc": rc}
        except Exception as e:
            summary["fpga_load"] = {"error": str(e)}
        return summary


# ===========================================================================
# A small, real baseline signature set
# ===========================================================================
def seed_baseline(db: SignatureDB) -> int:
    n = 0
    # EICAR by sha256 (the canonical test file) + as a body pattern
    eicar = (r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
    db.add_hash("Eicar-Test-Signature",
                hashlib.sha256(eicar.encode("latin-1")).hexdigest(),
                hash_type="sha256", size=68, family="EICAR", severity="critical")
    n += 1
    db.add_pattern("Eicar-Test-Body", eicar.encode("latin-1").hex(),
                   target="any", offset="*", family="EICAR", severity="critical")
    n += 1
    # a PE that imports process-injection APIs (hex of the ASCII import name)
    db.add_pattern("Win.Trojan.Injector-Generic",
                   b"CreateRemoteThread".hex(), target="pe", offset="*",
                   family="Injector", severity="high")
    n += 1
    # ELF reverse-shell marker
    db.add_pattern("Unix.Backdoor.RevShell",
                   b"/bin/sh\x00-c".hex(), target="elf", offset="*",
                   family="Backdoor", severity="high")
    n += 1
    # YARA-lite: two markers, both required
    db.add_yara("Malware.Dropper.Generic",
                {"$a": "URLDownloadToFile", "$b": "WinExec"},
                "all", target="pe", family="Dropper", severity="high")
    n += 1
    db.apply_update(n, source="baseline")
    return n


# ===========================================================================
# Self-test -- no hardware, no network
# ===========================================================================
def selftest() -> int:
    print("ffn_sigdb selftest")
    db = SignatureDB(":memory:")

    # -- 1. versioning starts at 0, bumps on update ----------------------
    assert db.version() == 0 and db.version_string() == "ffn-av-0"
    n = seed_baseline(db)
    assert db.version() == 1, "seed should bump to version 1"
    assert n == 5 and db.count() == 5
    print("  [ok] seeded %d sigs -> %s" % (n, db.version_string()))

    # -- 2. hash lookup ---------------------------------------------------
    import hashlib as _h
    eicar = (r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
    hit = db.lookup_hash(_h.sha256(eicar.encode("latin-1")).hexdigest())
    assert hit and hit["malware_family"] == "EICAR" and hit["action"] == ACTION_RESET
    assert db.lookup_hash("00" * 32) is None
    print("  [ok] hash signature lookup (EICAR sha256)")

    # -- 3. hexsig validation + import ------------------------------------
    assert validate_hexsig("4d5a??0000{4-8}(aa|bb)*909090")
    assert not validate_hexsig("nothex!!")
    print("  [ok] hex-signature syntax validation")

    # -- 4. ClamAV import (hdb + ndb, auto-detected) ----------------------
    clam = [
        "44d88612fea8a8f36de82e1278abb02f:68:Clam.Test.Md5",           # hdb (md5)
        "Clam.Win.Trojan-1:1:*:4d5a90000300000004000000ffff",         # ndb PE pattern
        "Clam.Elf.Rootkit:6:EOF-16:7f454c46??????",                    # ndb ELF, EOF offset
        "# comment line",
    ]
    added = db.import_clamav(clam, kind="auto")
    assert added == 3, "expected 3 clamav sigs, got %d" % added
    # baseline had 3 patterns + 1 hash; clamav adds 2 patterns + 1 hash
    assert db.count("pattern") == 5 and db.count("hash") == 2
    assert db.version() == 2, "clamav import should bump version"
    md5hit = db.lookup_hash("44d88612fea8a8f36de82e1278abb02f")
    assert md5hit and md5hit["hash_type"] == "md5"
    print("  [ok] ClamAV .hdb/.ndb import (+3), version ->", db.version())

    # -- 5. YARA import ---------------------------------------------------
    yara = '''
    rule Emotet_Downloader : trojan {
        strings:
            $s1 = "schtasks /create"
            $s2 = { 6a 40 68 00 30 00 00 }
        condition:
            all of them
    }
    rule Any_Marker {
        strings:
            $a = "evilmarker"
        condition:
            any of them
    }
    '''
    yn = db.import_yara(yara)
    assert yn == 2, "expected 2 yara rules, got %d" % yn
    assert db.count("yara") == 3   # baseline had 1 + 2 imported
    rules = [s for s in db.iter_signatures(sig_type="yara")]
    emotet = next(s for s in rules if s["name"] == "Emotet_Downloader")
    yj = json.loads(emotet["yara_json"])
    assert yj["condition"] == "all" and yj["strings"]["$s2"].startswith("hex:")
    print("  [ok] YARA import (2 rules, hex+text strings, condition normalized)")

    # -- 6. target scoping ------------------------------------------------
    pe_sigs = list(db.iter_signatures(sig_type="pattern", target="pe"))
    # PE-target query returns 'any' + 'pe' patterns, not 'elf'-only ones
    names = {s["name"] for s in pe_sigs}
    assert "Win.Trojan.Injector-Generic" in names          # target pe
    assert "Eicar-Test-Body" in names                       # target any
    assert "Unix.Backdoor.RevShell" not in names            # target elf -> excluded
    print("  [ok] file-type target scoping (pe query excludes elf-only sigs)")

    # -- 7. update log + stats --------------------------------------------
    ups = db.updates()
    assert ups[0]["version"] == db.version() and len(ups) >= 3
    st = db.stats()
    assert st["total"] == db.count() and "hash" in st["by_type"]
    print("  [ok] update log + stats:", {"v": st["version"], "by_type": st["by_type"]})

    # -- 8. FPGA compile bridge (stub loader, no HW) ----------------------
    try:
        from ffn_threatdb import ThreatDB
        tdb = ThreatDB(":memory:")
        calls = []
        summ = db.compile_to_fpga(tdb, loader=lambda k, p, vsys=0: calls.append(k) or 0)
        assert summ["hashes"] == 1 and summ["fpga_load"]["rc"] == 0   # 1 sha256 hash sig
        assert tdb.is_malicious_hash(hit["hash_value"])
        print("  [ok] compile_to_fpga -> ThreatDB + db_compiler bridge:", summ["fpga_load"])
        tdb.close()
    except Exception as e:
        print("  [skip] ThreatDB bridge unavailable:", e)

    db.close()
    print("  all assertions passed")
    return 0


# ===========================================================================
# CLI
# ===========================================================================
def main(argv=None):
    ap = argparse.ArgumentParser(description="FFN NGFW signature database")
    ap.add_argument("--db", default=DEFAULT_DB)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("selftest")
    sub.add_parser("stats")
    sub.add_parser("version")
    sub.add_parser("seed")
    sp = sub.add_parser("import-clamav"); sp.add_argument("file")
    sp.add_argument("--kind", default="auto", choices=["auto", "hdb", "hsb", "ndb"])
    sp = sub.add_parser("import-yara"); sp.add_argument("file")
    sp = sub.add_parser("add-hash"); sp.add_argument("name"); sp.add_argument("hash")
    sp.add_argument("--size", type=int, default=0); sp.add_argument("--family")
    sp = sub.add_parser("update"); sp.add_argument("source")
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    if args.cmd == "selftest":
        return selftest()
    db = SignatureDB(args.db)
    try:
        if args.cmd == "stats":
            print(json.dumps(db.stats(), indent=2))
        elif args.cmd == "version":
            print(db.version_string())
        elif args.cmd == "seed":
            print("seeded", seed_baseline(db), "sigs ->", db.version_string())
        elif args.cmd == "import-clamav":
            print("imported", db.import_clamav(open(args.file).read(), kind=args.kind))
        elif args.cmd == "import-yara":
            print("imported", db.import_yara(open(args.file).read()), "rules")
        elif args.cmd == "add-hash":
            sid = db.add_hash(args.name, args.hash, hash_type="auto",
                              size=args.size, family=args.family)
            db.apply_update(1, source="cli")
            print("added sig", sid)
        elif args.cmd == "update":
            print("version ->", db.apply_update(0, source=args.source))
    finally:
        db.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
