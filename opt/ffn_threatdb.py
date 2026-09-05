#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""
ffn_threatdb.py -- FFN NGFW canonical threat-intelligence database.

This is the Crucible intelligence core: the single source of truth for sample
verdicts and network indicators (IOCs), shared by every part of the
pipeline:

    feeds / sandbox / agent  --record-->  ThreatDB (SQLite)
                                              |
                                  export_region() / export_compiler_text()
                                              |
                                       db_compiler.py  --ioctl-->  FPGA tables
                                              |
              Lynceus URAM (fast feature-hash match)  +  DDR MALWARE/DNSBL/...

Before this module the only "database" was a flat file of known-bad
SHA256 in ffn_bnn_agent.HashDB -- no verdict metadata, no IOC store,
no signature registry, and no way to persist what the agent discovered.
ThreatDB replaces that with a real store and closes the Crucible feedback
loop: the agent records a verdict here, the compiler pushes it to the
FPGA, and the next packet matches in hardware.

Design goals:
  * stdlib only (sqlite3, hashlib, zlib) so it runs anywhere, no deps.
  * Verdict taxonomy is the industry-standard four classes: benign / grayware /
    phishing / malware (+ unknown for not-yet-analyzed).
  * Region IDs match enum ngfw_ddr_region in the driver / db_compiler.
  * A --selftest that needs no hardware and no network.

CLI:
    ffn_threatdb.py init
    ffn_threatdb.py ingest <kind> <file>     # kind: malware_hashes, dns_blocklist, ...
    ffn_threatdb.py lookup <sha256|ioc>
    ffn_threatdb.py export <region> [outfile] # region: malware, dnsbl, blocklist, url, tlsfp
    ffn_threatdb.py stats
    ffn_threatdb.py selftest
"""

import argparse
import hashlib
import logging
import os
import sqlite3
import sys
import tempfile
import time
import zlib

logger = logging.getLogger("ffn-threatdb")

DEFAULT_DB_PATH = os.getenv("FFN_THREATDB_PATH", "/var/lib/ffn-ngfw/threatdb.sqlite")

# ---------------------------------------------------------------------------
# Verdict taxonomy (industry-standard classes) + scores
# ---------------------------------------------------------------------------
VERDICTS = ("unknown", "benign", "grayware", "phishing", "malware")
VERDICT_SCORE = {
    "unknown":  0,
    "benign":   0,
    "grayware": 40,
    "phishing": 80,
    "malware":  100,
}

# Data-plane action the FPGA applies for an indicator of this verdict.
# Mirrors the Lynceus <action> field and the verdict aggregator precedence.
ACTION_ALERT = 0   # log only
ACTION_DROP  = 1   # silently drop
ACTION_RESET = 2   # drop + TCP reset
VERDICT_ACTION = {
    "unknown":  ACTION_ALERT,
    "benign":   ACTION_ALERT,
    "grayware": ACTION_ALERT,
    "phishing": ACTION_DROP,
    "malware":  ACTION_RESET,
}

# ---------------------------------------------------------------------------
# FPGA DDR region IDs -- MUST match enum ngfw_ddr_region in
# sw/.../ffn_ngfw_driver/ffn_ngfw.c and db_compiler.py.
# ---------------------------------------------------------------------------
NGFW_RGN_GEOIP     = 6
NGFW_RGN_BLOCKLIST = 7
NGFW_RGN_URL       = 8
NGFW_RGN_THREATS   = 10
NGFW_RGN_MALWARE   = 11
NGFW_RGN_FILEMAGIC = 12
NGFW_RGN_TLSFP     = 13
NGFW_RGN_DNSBL     = 14
NGFW_RGN_SPYWARE   = 15

# IOC type -> (region, db_compiler text "db_type"). sha256 file hashes are
# tracked in the samples table; everything else is a network IOC.
IOC_REGION = {
    "domain": (NGFW_RGN_DNSBL,     "dns_blocklist"),
    "dns":    (NGFW_RGN_DNSBL,     "dns_blocklist"),
    "ip":     (NGFW_RGN_BLOCKLIST, "blocklist"),
    "url":    (NGFW_RGN_URL,       "url"),
    "tlsfp":  (NGFW_RGN_TLSFP,     "tls_fingerprints"),
}

# ---------------------------------------------------------------------------
# Feature hash -- the 32-bit fingerprint the Lynceus URAM engine exact-matches.
#
# CONTRACT: this MUST produce the same value as the FPGA's feature-hash
# precomputer (the pre-aggregation logic in mqnic_app_block feeding
# ngfw_lynceus.s_feat_hash). The RTL hash is not yet pinned in a shared
# header, so we use CRC32 (little-endian, zlib) as the documented default and
# isolate it here. If/when the RTL settles on a different polynomial, change
# ONLY this function and re-export. The DDR MALWARE path does NOT use this --
# it stores full SHA256 and the engine does an exact compare -- so file-hash
# blocklisting is correct regardless of this function.
# ---------------------------------------------------------------------------
FEATURE_KIND = {"url": 1, "domain": 2, "dns": 2, "tlsfp": 3, "ip": 4, "sha256": 5}


def feature_hash(kind: str, value: str) -> int:
    """32-bit feature hash for the Lynceus fast-path. See CONTRACT above."""
    k = FEATURE_KIND.get(kind, 0)
    return zlib.crc32(bytes([k]) + value.encode("utf-8", "ignore")) & 0xFFFFFFFF


def _now() -> str:
    # caller-stamped wall clock; time.time() is fine here (not in a workflow).
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


# ---------------------------------------------------------------------------
# The database
# ---------------------------------------------------------------------------
class ThreatDB:
    """SQLite-backed canonical threat-intelligence store."""

    SCHEMA = """
    CREATE TABLE IF NOT EXISTS samples (
        sha256      TEXT PRIMARY KEY,
        sha1        TEXT,
        md5         TEXT,
        size        INTEGER,
        file_type   TEXT,
        verdict     TEXT NOT NULL DEFAULT 'unknown',
        score       INTEGER NOT NULL DEFAULT 0,
        threat_name TEXT,
        first_seen  TEXT,
        last_seen   TEXT,
        hits        INTEGER NOT NULL DEFAULT 0,
        source      TEXT,
        sig_id      INTEGER
    );
    CREATE INDEX IF NOT EXISTS idx_samples_verdict ON samples(verdict);

    CREATE TABLE IF NOT EXISTS iocs (
        ioc_type    TEXT NOT NULL,
        value       TEXT NOT NULL,
        verdict     TEXT NOT NULL DEFAULT 'unknown',
        score       INTEGER NOT NULL DEFAULT 0,
        category    TEXT,
        threat_name TEXT,
        feat_hash   INTEGER,
        first_seen  TEXT,
        last_seen   TEXT,
        hits        INTEGER NOT NULL DEFAULT 0,
        source      TEXT,
        expiry      TEXT,
        sig_id      INTEGER,
        PRIMARY KEY (ioc_type, value)
    );
    CREATE INDEX IF NOT EXISTS idx_iocs_verdict ON iocs(verdict);

    CREATE TABLE IF NOT EXISTS signatures (
        sig_id      INTEGER PRIMARY KEY AUTOINCREMENT,
        kind        TEXT NOT NULL,
        feat_hash   INTEGER,
        ref         TEXT,
        threat_name TEXT,
        action      INTEGER NOT NULL DEFAULT 0,
        region      INTEGER,
        created     TEXT
    );

    CREATE TABLE IF NOT EXISTS feeds (
        kind        TEXT PRIMARY KEY,
        url         TEXT,
        last_pull   TEXT,
        etag        TEXT,
        entry_count INTEGER NOT NULL DEFAULT 0
    );
    """

    def __init__(self, path: str = DEFAULT_DB_PATH):
        self.path = path
        if path != ":memory:":
            os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        # check_same_thread=False on purpose: the Crucible queue drainer reads
        # and writes this handle from a worker thread while the data plane
        # submits from another. SQLite is compiled serialized, so the sharing
        # is safe; callers that run MULTI-STATEMENT transactions must still
        # serialize themselves (see CloudDetectionService._lock).
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(self.SCHEMA)
        self.conn.commit()

    def close(self):
        self.conn.close()

    # -- samples -----------------------------------------------------------
    def record_sample(self, sha256, verdict="unknown", *, sha1=None, md5=None,
                      size=None, file_type=None, threat_name=None,
                      source="agent", score=None):
        """Upsert a file sample verdict. Bumps last_seen + hit count.

        This is the agent's feedback entry point: when the BNN or sandbox
        classifies a carved file, it lands here and becomes blocklistable.
        """
        sha256 = sha256.lower().strip()
        if len(sha256) != 64:
            raise ValueError("sha256 must be 64 hex chars")
        if verdict not in VERDICTS:
            raise ValueError("bad verdict %r" % verdict)
        if score is None:
            score = VERDICT_SCORE[verdict]
        now = _now()
        cur = self.conn.execute("SELECT verdict FROM samples WHERE sha256=?", (sha256,))
        exists = cur.fetchone()
        if exists:
            self.conn.execute(
                """UPDATE samples SET verdict=?, score=?, threat_name=COALESCE(?,threat_name),
                       sha1=COALESCE(?,sha1), md5=COALESCE(?,md5), size=COALESCE(?,size),
                       file_type=COALESCE(?,file_type), last_seen=?, hits=hits+1,
                       source=? WHERE sha256=?""",
                (verdict, score, threat_name, sha1, md5, size, file_type, now, source, sha256))
        else:
            self.conn.execute(
                """INSERT INTO samples
                   (sha256,sha1,md5,size,file_type,verdict,score,threat_name,
                    first_seen,last_seen,hits,source)
                   VALUES (?,?,?,?,?,?,?,?,?,?,1,?)""",
                (sha256, sha1, md5, size, file_type, verdict, score, threat_name,
                 now, now, source))
        self.conn.commit()
        return sha256

    def lookup_sample(self, sha256):
        sha256 = sha256.lower().strip()
        row = self.conn.execute("SELECT * FROM samples WHERE sha256=?", (sha256,)).fetchone()
        return dict(row) if row else None

    def is_malicious_hash(self, sha256):
        """Fast path for the agent: True if the hash is a known bad verdict."""
        row = self.conn.execute(
            "SELECT verdict FROM samples WHERE sha256=?", (sha256.lower().strip(),)).fetchone()
        return bool(row) and row["verdict"] in ("malware", "phishing")

    # -- IOCs --------------------------------------------------------------
    def record_ioc(self, ioc_type, value, verdict="malware", *, category=None,
                   threat_name=None, source="feed", expiry=None, score=None):
        """Upsert a network indicator (domain/ip/url/tlsfp). Computes feat_hash."""
        if ioc_type not in IOC_REGION:
            raise ValueError("unknown ioc_type %r" % ioc_type)
        if verdict not in VERDICTS:
            raise ValueError("bad verdict %r" % verdict)
        value = value.strip()
        if score is None:
            score = VERDICT_SCORE[verdict]
        fh = feature_hash(ioc_type, value)
        now = _now()
        row = self.conn.execute(
            "SELECT value FROM iocs WHERE ioc_type=? AND value=?", (ioc_type, value)).fetchone()
        if row:
            self.conn.execute(
                """UPDATE iocs SET verdict=?, score=?, category=COALESCE(?,category),
                       threat_name=COALESCE(?,threat_name), last_seen=?, hits=hits+1,
                       source=?, expiry=COALESCE(?,expiry), feat_hash=?
                   WHERE ioc_type=? AND value=?""",
                (verdict, score, category, threat_name, now, source, expiry, fh,
                 ioc_type, value))
        else:
            self.conn.execute(
                """INSERT INTO iocs
                   (ioc_type,value,verdict,score,category,threat_name,feat_hash,
                    first_seen,last_seen,hits,source,expiry)
                   VALUES (?,?,?,?,?,?,?,?,?,1,?,?)""",
                (ioc_type, value, verdict, score, category, threat_name, fh,
                 now, now, source, expiry))
        self.conn.commit()
        return fh

    def lookup_ioc(self, ioc_type, value):
        row = self.conn.execute(
            "SELECT * FROM iocs WHERE ioc_type=? AND value=?",
            (ioc_type, value.strip())).fetchone()
        return dict(row) if row else None

    # -- feed ingest -------------------------------------------------------
    def ingest_feed(self, kind, path_or_lines, *, source=None):
        """Parse a threat feed and bulk-load it. Returns the entry count.

        Supported `kind` values map to the FEED_URLS in db_api.py:
          malware_hashes   : one SHA256 per line              -> samples (malware)
          dns_blocklist    : one domain per line              -> iocs/domain
          blocklist        : one IP or CIDR per line          -> iocs/ip
          url              : "<url>[\t<category>]" per line   -> iocs/url
          tls_fingerprints : one JA3 hash per line            -> iocs/tlsfp
          spyware_iocs     : "<type> <value> [threat]"        -> mixed
        Lines starting with '#' and blank lines are ignored.
        """
        source = source or kind
        if isinstance(path_or_lines, (list, tuple)):
            lines = list(path_or_lines)
        else:
            with open(path_or_lines, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()

        n = 0
        for raw in lines:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            try:
                if self._ingest_line(kind, line, source):
                    n += 1
            except Exception as exc:  # one bad line must not abort a feed
                logger.debug("skip bad %s line %r: %s", kind, line, exc)
        # record feed metadata
        self.conn.execute(
            """INSERT INTO feeds (kind,last_pull,entry_count) VALUES (?,?,?)
               ON CONFLICT(kind) DO UPDATE SET last_pull=excluded.last_pull,
                   entry_count=excluded.entry_count""",
            (kind, _now(), n))
        self.conn.commit()
        logger.info("ingested %d entries from %s", n, kind)
        return n

    def _ingest_line(self, kind, line, source):
        if kind == "malware_hashes":
            h = line.split()[0].lower()
            if len(h) != 64 or any(c not in "0123456789abcdef" for c in h):
                return False
            self.record_sample(h, "malware", source=source)
            return True
        if kind in ("dns_blocklist", "dns"):
            self.record_ioc("domain", line.split()[0], "malware", category="c2",
                            source=source)
            return True
        if kind == "blocklist":
            self.record_ioc("ip", line.split()[0], "malware", category="c2",
                            source=source)
            return True
        if kind == "url":
            parts = line.split("\t") if "\t" in line else line.split(None, 1)
            url = parts[0]
            cat = parts[1].strip() if len(parts) > 1 else "malware"
            verdict = "phishing" if "phish" in cat.lower() else "malware"
            self.record_ioc("url", url, verdict, category=cat, source=source)
            return True
        if kind == "tls_fingerprints":
            self.record_ioc("tlsfp", line.split()[0], "malware", category="c2",
                            source=source)
            return True
        if kind == "spyware_iocs":
            parts = line.split()
            if len(parts) < 2:
                return False
            t, v = parts[0].lower(), parts[1]
            threat = parts[2] if len(parts) > 2 else None
            if t in ("domain", "dns"):
                self.record_ioc("domain", v, "malware", category="spyware",
                                threat_name=threat, source=source)
            elif t == "ip":
                self.record_ioc("ip", v, "malware", category="spyware",
                                threat_name=threat, source=source)
            elif t in ("hash", "sha256"):
                self.record_sample(v, "malware", threat_name=threat, source=source)
            else:
                return False
            return True
        raise ValueError("unknown feed kind %r" % kind)

    # -- export to FPGA / compiler ----------------------------------------
    def export_region(self, region_id):
        """Yield (value, feat_hash, action, threat_name) rows for a DDR region.

        db_compiler consumes this to build the table image. MALWARE is the
        sample sha256 set; the rest come from the IOC table.
        """
        if region_id == NGFW_RGN_MALWARE:
            cur = self.conn.execute(
                "SELECT sha256,score,verdict,threat_name FROM samples "
                "WHERE verdict IN ('malware','phishing') ORDER BY sha256")
            for r in cur:
                yield (r["sha256"], int(r["sha256"][:8], 16),
                       VERDICT_ACTION[r["verdict"]], r["threat_name"])
            return
        ioc_type = next((t for t, (rg, _) in IOC_REGION.items() if rg == region_id), None)
        if ioc_type is None:
            return
        cur = self.conn.execute(
            "SELECT value,feat_hash,verdict,threat_name FROM iocs "
            "WHERE ioc_type=? AND verdict!='benign' ORDER BY value", (ioc_type,))
        for r in cur:
            yield (r["value"], r["feat_hash"], VERDICT_ACTION[r["verdict"]],
                   r["threat_name"])

    # db_compiler verdict -> category id (see compile_url cat_map: 3=malware,
    # 4=phishing, 1=adult/grayware placeholder).
    _COMPILER_CAT = {"malware": 3, "phishing": 4, "grayware": 1}

    def export_compiler_text(self, kind, out_path):
        """Write the on-disk text file db_compiler.py expects for `kind`.

        Each db_compiler compiler parses a BESPOKE format (verified against
        db_compiler.py) -- a generic "<value>\\t<name>" would corrupt the
        domain/url/ja3 parsers. Emit exactly what each one reads:
          malware_hashes   : <sha256>                    (parts[0], 64 hex)
          dns_blocklist    : <domain>                     (whole line)
          blocklist        : <ipv4>                       (split()[0])
          url              : <url>                         (whole line)
          tls_fingerprints : <ja3_md5_hex> <cat> <name>   (3 fields, cat int)
        """
        written = 0
        with open(out_path, "w", encoding="utf-8") as f:
            f.write("# generated by ffn_threatdb at %s -- do not edit\n" % _now())
            if kind == "malware_hashes":
                for sha, _fh, _act, _name in self.export_region(NGFW_RGN_MALWARE):
                    f.write("%s\n" % sha)
                    written += 1
            elif kind in ("dns_blocklist", "blocklist", "url"):
                region = {"dns_blocklist": NGFW_RGN_DNSBL,
                          "blocklist": NGFW_RGN_BLOCKLIST,
                          "url": NGFW_RGN_URL}[kind]
                for val, _fh, _act, _name in self.export_region(region):
                    f.write("%s\n" % val)
                    written += 1
            elif kind == "tls_fingerprints":
                cur = self.conn.execute(
                    "SELECT value,verdict,threat_name FROM iocs "
                    "WHERE ioc_type='tlsfp' AND verdict!='benign' ORDER BY value")
                for r in cur:
                    ja3 = r["value"].strip()
                    if len(ja3) != 32:  # compile_tls_fingerprints requires md5 hex
                        continue
                    cat = self._COMPILER_CAT.get(r["verdict"], 3)
                    name = (r["threat_name"] or "threat").replace(" ", "_")
                    f.write("%s %d %s\n" % (ja3, cat, name))
                    written += 1
            else:
                raise ValueError("no compiler-text mapping for %r" % kind)
        return written

    def export_and_load(self, kind, vsys=0, loader=None):
        """Bridge the verdict store to the FPGA.

        Export `kind` to the compiler's text format and load it into the
        FPGA via db_compiler.do_load (which compiles the text to a table
        image and pushes it over the driver ioctls -- DDR_WRITE / TBL_WRITE
        / IP_CFG_WRITE). When /dev/ngfw0 is absent, db_compiler's FPGADevice
        transparently runs in sim mode, so this is testable offline.

        `loader` can be injected for tests; by default db_compiler.do_load is
        imported lazily (only needed when actually loading).
        Returns (entry_count, load_rc).
        """
        if loader is None:
            from db_compiler import do_load as loader
        fd, tmp = tempfile.mkstemp(suffix=".txt", prefix="threatdb_%s_" % kind)
        os.close(fd)
        try:
            n = self.export_compiler_text(kind, tmp)
            rc = loader(kind, tmp, vsys=vsys)
            logger.info("export_and_load: %d %s entries -> FPGA (rc=%s)", n, kind, rc)
            return n, rc
        finally:
            try:
                os.unlink(tmp)
            except OSError:
                pass

    # -- stats -------------------------------------------------------------
    def stats(self):
        s = {"samples": {}, "iocs": {}}
        for r in self.conn.execute(
                "SELECT verdict,COUNT(*) c FROM samples GROUP BY verdict"):
            s["samples"][r["verdict"]] = r["c"]
        for r in self.conn.execute(
                "SELECT ioc_type,verdict,COUNT(*) c FROM iocs GROUP BY ioc_type,verdict"):
            s["iocs"].setdefault(r["ioc_type"], {})[r["verdict"]] = r["c"]
        s["samples_total"] = self.conn.execute("SELECT COUNT(*) c FROM samples").fetchone()["c"]
        s["iocs_total"] = self.conn.execute("SELECT COUNT(*) c FROM iocs").fetchone()["c"]
        return s


# ---------------------------------------------------------------------------
# Self-test -- no hardware, no network
# ---------------------------------------------------------------------------
def selftest():
    print("ffn_threatdb selftest")
    db = ThreatDB(":memory:")

    # 1. feed ingest
    sha_a = "a" * 64
    sha_b = "b" * 64
    n = db.ingest_feed("malware_hashes", [sha_a, sha_b, "# comment", "tooShort"])
    assert n == 2, "expected 2 hashes, got %d" % n
    n = db.ingest_feed("dns_blocklist", ["evil.example.com", "c2.bad.net"])
    assert n == 2
    n = db.ingest_feed("blocklist", ["198.51.100.7", "203.0.113.9"])
    assert n == 2
    n = db.ingest_feed("url", ["http://phish.example/login\tphishing",
                               "http://mal.example/x\tmalware"])
    assert n == 2

    # 2. lookups
    assert db.is_malicious_hash(sha_a)
    assert not db.is_malicious_hash("c" * 64)
    dom = db.lookup_ioc("domain", "evil.example.com")
    assert dom and dom["verdict"] == "malware"
    url = db.lookup_ioc("url", "http://phish.example/login")
    assert url and url["verdict"] == "phishing", "phish url should be phishing verdict"

    # 3. agent feedback path: record a freshly classified sample, then it is
    #    immediately blocklistable.
    db.record_sample("c" * 64, "malware", threat_name="Trojan.Test", source="agent")
    assert db.is_malicious_hash("c" * 64)
    samp = db.lookup_sample("c" * 64)
    assert samp["threat_name"] == "Trojan.Test" and samp["hits"] == 1

    # 4. feature hash determinism + contract
    assert feature_hash("domain", "evil.example.com") == feature_hash("domain", "evil.example.com")
    assert dom["feat_hash"] == feature_hash("domain", "evil.example.com")

    # 5. export for the compiler
    mal = list(db.export_region(NGFW_RGN_MALWARE))
    assert len(mal) == 3, "3 malicious hashes (a,b,c), got %d" % len(mal)
    for value, fh, action, _name in mal:
        assert action == ACTION_RESET            # malware -> reset
        assert fh == int(value[:8], 16)
    dnsbl = list(db.export_region(NGFW_RGN_DNSBL))
    assert len(dnsbl) == 2

    import tempfile
    tf = tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False)
    tf.close()
    w = db.export_compiler_text("malware_hashes", tf.name)
    assert w == 3
    with open(tf.name) as f:
        body = [l for l in f if not l.startswith("#")]
    assert len([l for l in body if l.strip()]) == 3
    os.unlink(tf.name)

    # 6. stats
    st = db.stats()
    assert st["samples_total"] == 3
    assert st["iocs_total"] == 6  # 2 dns + 2 ip + 2 url

    # 7. exported text round-trips through the REAL db_compiler compilers
    #    (proves the per-kind formats match), and the export_and_load bridge
    #    plumbs correctly (stub loader -> no filesystem side effects).
    try:
        from db_compiler import do_compile
    except Exception as exc:
        print("  [skip] db_compiler unavailable:", exc)
    else:
        for kind, want in (("malware_hashes", 3), ("dns_blocklist", 2),
                           ("blocklist", 2), ("url", 2)):
            fd, tp = tempfile.mkstemp(suffix=".txt"); os.close(fd)
            try:
                wrote = db.export_compiler_text(kind, tp)
                _res, _payload, rc = do_compile(kind, tp)
                assert rc == 0 and wrote == want, "%s wrote=%d rc=%d" % (kind, wrote, rc)
            finally:
                os.unlink(tp)
        calls = []
        n, rc = db.export_and_load(
            "malware_hashes", loader=lambda k, p, vsys=0: calls.append((k, p)) or 0)
        assert rc == 0 and n == 3 and calls and calls[0][0] == "malware_hashes"
        print("  [ok] formats compile via db_compiler; export_and_load bridge OK")

    db.close()
    print("  all assertions passed:", st)
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main(argv=None):
    ap = argparse.ArgumentParser(description="FFN NGFW threat-intelligence database")
    ap.add_argument("--db", default=DEFAULT_DB_PATH, help="SQLite path")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("init")
    sp = sub.add_parser("ingest"); sp.add_argument("kind"); sp.add_argument("file")
    sp = sub.add_parser("lookup"); sp.add_argument("value")
    sp = sub.add_parser("export"); sp.add_argument("region"); sp.add_argument("out", nargs="?")
    sub.add_parser("stats")
    sub.add_parser("selftest")
    args = ap.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    if args.cmd == "selftest":
        return selftest()

    db = ThreatDB(args.db)
    try:
        if args.cmd == "init":
            print("initialized", args.db)
        elif args.cmd == "ingest":
            print("ingested", db.ingest_feed(args.kind, args.file), "entries")
        elif args.cmd == "lookup":
            v = args.value.strip()
            if len(v) == 64 and all(c in "0123456789abcdef" for c in v.lower()):
                print(db.lookup_sample(v))
            else:
                for t in IOC_REGION:
                    hit = db.lookup_ioc(t, v)
                    if hit:
                        print(hit); break
                else:
                    print(None)
        elif args.cmd == "export":
            region = {"malware": NGFW_RGN_MALWARE, "dnsbl": NGFW_RGN_DNSBL,
                      "blocklist": NGFW_RGN_BLOCKLIST, "url": NGFW_RGN_URL,
                      "tlsfp": NGFW_RGN_TLSFP}[args.region]
            rows = list(db.export_region(region))
            if args.out:
                kind = {"malware": "malware_hashes", "dnsbl": "dns_blocklist",
                        "blocklist": "blocklist", "url": "url",
                        "tlsfp": "tls_fingerprints"}[args.region]
                print("wrote", db.export_compiler_text(kind, args.out), "->", args.out)
            else:
                for r in rows:
                    print(r)
        elif args.cmd == "stats":
            import json
            print(json.dumps(db.stats(), indent=2))
    finally:
        db.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
