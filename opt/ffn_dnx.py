#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 FreeFlow Networks, Inc.
"""ffn_dnx.py -- the dataplane's Broadcom DNX file set: verify, import, load.

The BCM88375 in a PA-5200 will not forward a packet until the DNX device is
initialised, and that initialisation is driven by a set of files the vendor's
SDK reads at runtime: two .soc property files, an entry script, a port/property
config, and a handful of cint scripts.

FFN does not have those files and must never ship them. They belong to whoever
owns the appliance. So this module treats them as strictly owner-supplied
material: it verifies the set, refuses anything that did not come from the
owner, and loads it from removable media when the owner plugs it in.

Three separate things are checked, because they fail in different ways:

  1. COMPLETENESS -- is the required set present at all?
  2. PROVENANCE   -- did every file come from the owner, and is FFN shipping
                     none of them? This is the "user-supplied only" rule, and
                     it is the reason this file exists.
  3. FITNESS      -- does the content match THIS chassis, and does it parse as
                     the kind of file it claims to be?

Fitness matters more than it looks. gryphon_dram_tune.soc is not vendor-shipped
content: it is generated per chassis and carries the board's serial number in
its header. Applying another appliance's DRAM calibration to this one is a
hardware-correctness hazard, not a licensing question, so a serial mismatch is
refused outright.

There is no authoritative serial source on the host to check it against: DMI on
this board reports product_serial "123456789" and product_name "Grangeville"
(the Intel board codename), and the PAN serial appears nowhere in the host
filesystem. So the serial is pinned on first sight and enforced thereafter, and
can be set explicitly in vendor.conf. Do not spend an afternoon looking for a
better source on the MP; it is not there.

Commands:
    scan    --source DIR    is there a DNX set on this media?
    verify  --source DIR    check a set without importing it
    import  --source DIR    copy the set into FFN's owner-local store
    check                   the standing check: user-supplied only, and fit
    load                    place the set where the dataplane reads it
    status                  what is pinned and staged
    selftest                self-checks, no hardware needed
"""

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

VENDOR_DIR = os.environ.get("FFN_VENDOR_DIR", "/var/lib/ffn-ngfw/vendor")
CONF = os.environ.get("FFN_VENDOR_CONF", "/etc/ffn-ngfw/vendor.conf")

# The dataplane rootfs as assembled on the host. This is what the DP will see,
# so it is what the check inspects by default.
DP_ROOT = os.environ.get("FFN_DP_ROOT", "/opt/dpfs")
DNX_REL = "usr/share/broadcom"

STORE = os.path.join(VENDOR_DIR, "dnx")
SERIAL_PIN = os.path.join(VENDOR_DIR, "chassis-serial")

# ---------------------------------------------------------------------------
# The file set.
#
# "role" drives policy, and the roles are genuinely different:
#
#   shipped  -- vendor-authored, identical across appliances of the same PAN-OS
#               version. Required for init to run.
#   chassis  -- generated on one specific board, carries its serial. Required,
#               and refused if it belongs to a different board.
#   optional -- vendor- or PAN-authored helpers. Loaded when present; their
#               absence degrades function but does not stop init.
#   refused  -- must NOT be taken from media. runningConfig.soc is a saved
#               runtime snapshot: it is output, not input, and importing another
#               board's snapshot would silently override the real config.
# ---------------------------------------------------------------------------
FILES = {
    "rc.soc":                 {"role": "shipped",  "kind": "soc_script"},
    "jer.soc":                {"role": "shipped",  "kind": "soc_script"},
    "bcm88375_board.soc":     {"role": "shipped",  "kind": "soc_props"},
    "config.bcm":             {"role": "shipped",  "kind": "config_bcm"},
    "gryphon_dram_tune.soc":  {"role": "chassis",  "kind": "soc_props"},
    "files.md5":              {"role": "optional", "kind": "md5_manifest"},
    "combo28_dram.soc":       {"role": "optional", "kind": "soc_script"},
    "enable_fp_ports.c":      {"role": "optional", "kind": "cint"},
    "phy_tx_settings.c":      {"role": "optional", "kind": "cint"},
    "gryphon_llfc.c":         {"role": "optional", "kind": "cint"},
    "panEgrTcMap.c":          {"role": "optional", "kind": "cint"},
    "dsa_tag_support.c":      {"role": "optional", "kind": "cint"},
    "runningConfig.soc":      {"role": "refused",  "kind": "soc_saved"},
}

REQUIRED = [n for n, s in FILES.items() if s["role"] in ("shipped", "chassis")]
REFUSED = [n for n, s in FILES.items() if s["role"] == "refused"]

# This chip answers to the Jericho-family base ID in property names, not to its
# own part number. Checking for "BCM88375" in config.bcm finds nothing at all.
PROP_IDS = ("BCM88650", "BCM88370", "BCM88375")


def log(msg):
    print(msg)
    try:
        subprocess.run(["logger", "-t", "ffn-dnx", msg], timeout=2,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass


def sha256_file(p, chunk=1 << 20):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        while True:
            b = f.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def md5_file(p, chunk=1 << 20):
    h = hashlib.md5()
    with open(p, "rb") as f:
        while True:
            b = f.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def load_conf():
    cfg = {}
    try:
        with open(CONF) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    cfg[k.strip()] = v.strip()
    except Exception:
        pass
    return cfg


# ------------------------------------------------------------------ serial ---
SERIAL_RE = re.compile(r"^#\s*Serial\s+Number\s+(\S+)", re.M)
GENDATE_RE = re.compile(r"^#\s*Date\s+Generated\s+(.+?)\s*$", re.M)


def serial_of_tune(path):
    """Read the chassis serial out of a gryphon_dram_tune.soc header.

    Only the header is read: these files are ~26 KB of config statements and
    the serial is in the first few lines.
    """
    try:
        with open(path, errors="replace") as f:
            head = f.read(4096)
    except Exception:
        return None
    m = SERIAL_RE.search(head)
    return m.group(1) if m else None


def gendate_of_tune(path):
    try:
        with open(path, errors="replace") as f:
            head = f.read(4096)
    except Exception:
        return None
    m = GENDATE_RE.search(head)
    return m.group(1) if m else None


def pinned_serial():
    """The serial this appliance is bound to.

    vendor.conf wins if it names one, because an explicit statement by the
    operator beats anything inferred. Otherwise the pin file, written the first
    time a tune file is seen.
    """
    cfg = load_conf()
    if cfg.get("chassis_serial"):
        return cfg["chassis_serial"].strip(), "vendor.conf"
    try:
        with open(SERIAL_PIN) as f:
            s = f.read().strip()
        return (s, "pinned") if s else (None, None)
    except Exception:
        return None, None


def pin_serial(serial):
    os.makedirs(os.path.dirname(SERIAL_PIN), exist_ok=True)
    tmp = SERIAL_PIN + ".new"
    with open(tmp, "w") as f:
        f.write(serial + "\n")
    os.replace(tmp, SERIAL_PIN)


# -------------------------------------------------------------- validators ---
def _lines(path, limit=None):
    try:
        with open(path, errors="replace") as f:
            data = f.read(limit) if limit else f.read()
    except Exception:
        return None
    return data.splitlines()


def v_soc_props(path):
    """A property file: every meaningful line is a config statement.

    This is the check that told us bcm88375_board.soc is not an init sequence
    at all -- 324 config statements and nothing else. If a file claiming to be
    a property file has procedural commands in it, it is not the file we think.
    """
    ls = _lines(path)
    if ls is None:
        return "unreadable"
    bad = [l for l in ls if l.strip() and not l.lstrip().startswith("#")
           and not re.match(r"^\s*config\b", l)]
    if bad:
        return "not a property file: %d non-config lines (first: %r)" % (
            len(bad), bad[0][:60])
    if not any(re.match(r"^\s*config\b", l) for l in ls):
        return "no config statements"
    return None


def v_soc_script(path):
    """An entry script: procedural, and must reference something it loads."""
    ls = _lines(path)
    if ls is None:
        return "unreadable"
    txt = "\n".join(ls)
    if not re.search(r"^\s*(rcload|local|if|setreg|led)\b", txt, re.M):
        return "no procedural commands; looks like a property file"
    return None


def v_config_bcm(path):
    """The port/property config. Must carry a port map for a chip we know."""
    ls = _lines(path)
    if ls is None:
        return "unreadable"
    txt = "\n".join(ls)
    if not re.search(r"^\s*ucode_port_\d+", txt, re.M):
        return "no ucode_port_<n> entries; not a port map"
    if not any(pid in txt for pid in PROP_IDS):
        return "no recognised property suffix (%s)" % ", ".join(PROP_IDS)
    return None


def v_cint(path):
    """A cint script: C source that actually calls into the SDK."""
    ls = _lines(path)
    if ls is None:
        return "unreadable"
    txt = "\n".join(ls)
    if not re.search(r"\bbcm_\w+\s*\(", txt):
        return "no bcm_* calls; not a cint script"
    return None


def v_md5_manifest(path):
    ls = _lines(path)
    if ls is None:
        return "unreadable"
    ok = [l for l in ls if re.match(r"^[0-9a-f]{32}\s+\S", l.strip())]
    if not ok:
        return "no md5 lines"
    return None


def v_soc_saved(path):
    """`config save` output: bare key=value lines, no `config add` prefix.

    A third syntax, and the reason this validator exists separately: checking a
    saved config with the property-file rule reports 1244 bogus findings.
    """
    ls = _lines(path)
    if ls is None:
        return "unreadable"
    meaningful = [l for l in ls if l.strip() and not l.lstrip().startswith("#")]
    bad = [l for l in meaningful if not re.match(r"^\s*[\w.]+\s*=", l)]
    if bad:
        return "not a saved config: %d lines are not key=value (first: %r)" % (
            len(bad), bad[0][:60])
    if not meaningful:
        return "empty"
    return None


VALIDATORS = {
    "soc_props": v_soc_props,
    "soc_saved": v_soc_saved,
    "soc_script": v_soc_script,
    "config_bcm": v_config_bcm,
    "cint": v_cint,
    "md5_manifest": v_md5_manifest,
}


def validate(path, kind):
    fn = VALIDATORS.get(kind)
    return fn(path) if fn else None


def check_md5_manifest(root):
    """Honour files.md5 if the set carries one.

    It is md5 and it is unsigned, so it proves the file was not corrupted in
    transit. It proves nothing about who produced it. Treated accordingly.
    """
    man = os.path.join(root, "files.md5")
    out = []
    if not os.path.isfile(man):
        return out
    for line in _lines(man) or []:
        parts = line.split()
        if len(parts) < 2 or len(parts[0]) != 32:
            continue
        want, name = parts[0], os.path.basename(parts[1].lstrip("*"))
        p = os.path.join(root, name)
        if not os.path.isfile(p):
            out.append((name, "listed in files.md5 but absent"))
            continue
        got = md5_file(p)
        if got != want:
            out.append((name, "md5 mismatch (want %s, got %s)"
                        % (want[:12], got[:12])))
    return out


# -------------------------------------------------------------------- scan ---
def find_set(root):
    """Locate a DNX file set under `root`.

    Two shapes are supported, because both are how people actually carry these:
    a PAN-OS sysroot (usr/share/broadcom/...) and a directory of loose files
    copied onto a stick.
    """
    cands = [os.path.join(root, DNX_REL), os.path.join(root, "broadcom"),
             os.path.join(root, "dnx"), root]
    for d in cands:
        if not os.path.isdir(d):
            continue
        try:
            names = set(os.listdir(d))
        except Exception:
            continue
        # Two shipped files is enough to say "this is a DNX set" without
        # matching ordinary media that happens to hold one .soc file.
        hits = [n for n in names if n in FILES and FILES[n]["role"] == "shipped"]
        if len(hits) >= 2:
            return d
    return None


def inventory(d):
    recs = []
    for name in sorted(os.listdir(d)):
        if name.startswith("."):
            continue        # FFN's own bookkeeping, and OS turds on removable media
        p = os.path.join(d, name)
        if not os.path.isfile(p):
            continue
        spec = FILES.get(name)
        rec = {"name": name, "path": p, "size": os.path.getsize(p),
               "role": spec["role"] if spec else "unknown",
               "kind": spec["kind"] if spec else None,
               "problem": None}
        if spec:
            rec["problem"] = validate(p, spec["kind"])
        recs.append(rec)
    return recs


def verify_set(d, want_serial=None, strict_serial=True, from_media=True):
    """Verify a set. Returns (ok, findings, info).

    `from_media` separates the two callers, which have different rules. When
    verifying removable media a runtime snapshot is refused, because importing
    another board's saved state would silently override the real config. When
    checking the dataplane's own tree the same file is expected: the SDK writes
    it there itself with `config save`. Same file, opposite verdicts.
    """
    findings = []
    info = {"dir": d, "serial": None, "gendate": None, "files": []}

    recs = inventory(d)
    info["files"] = recs
    present = {r["name"] for r in recs}

    for name in REQUIRED:
        if name not in present:
            findings.append(("MISSING", name,
                             "required (%s)" % FILES[name]["role"]))

    for name in REFUSED:
        if name in present:
            if from_media:
                findings.append(("REFUSED", name,
                                 "runtime snapshot, not input -- must not be "
                                 "imported from media; the SDK regenerates it "
                                 "with config save"))
            else:
                findings.append(("SNAPSHOT", name,
                                 "runtime snapshot written by the SDK; not part "
                                 "of the required set and not imported"))

    for r in recs:
        if r["role"] == "unknown":
            findings.append(("EXTRA", r["name"],
                             "not part of the DNX set; ignored, not imported"))
        elif r["problem"]:
            findings.append(("MALFORMED", r["name"], r["problem"]))

    tune = os.path.join(d, "gryphon_dram_tune.soc")
    if os.path.isfile(tune):
        s = serial_of_tune(tune)
        info["serial"] = s
        info["gendate"] = gendate_of_tune(tune)
        if not s:
            findings.append(("MALFORMED", "gryphon_dram_tune.soc",
                             "no '# Serial Number' header -- cannot tell which "
                             "chassis this calibration belongs to"))
        elif want_serial and s != want_serial:
            sev = "CHASSIS-MISMATCH" if strict_serial else "CHASSIS-WARN"
            findings.append((sev, "gryphon_dram_tune.soc",
                             "generated for chassis %s, this appliance is %s -- "
                             "DRAM calibration is per-board and applying another "
                             "board's values is a hardware hazard"
                             % (s, want_serial)))

    for name, why in check_md5_manifest(d):
        findings.append(("CORRUPT", name, why))

    hard = {"MISSING", "REFUSED", "MALFORMED", "CORRUPT", "CHASSIS-MISMATCH"}
    ok = not any(f[0] in hard for f in findings)
    return ok, findings, info


# ------------------------------------------------------------------ import ---
def do_import(source, force=False):
    d = find_set(source)
    if not d:
        log("ffn-dnx: no DNX file set on %s" % source)
        return 1

    want, _how = pinned_serial()
    ok, findings, info = verify_set(d, want_serial=want,
                                    strict_serial=not force)
    report(findings, info, header="importing from %s" % d)

    if not ok and not force:
        log("ffn-dnx: import REFUSED -- see findings above")
        return 1
    if not ok:
        log("ffn-dnx: import forced despite findings (--force)")

    os.makedirs(STORE, exist_ok=True)
    n = 0
    for r in info["files"]:
        if r["role"] in ("unknown", "refused"):
            continue
        dst = os.path.join(STORE, r["name"])
        tmp = dst + ".new"
        shutil.copyfile(r["path"], tmp)
        os.chmod(tmp, 0o600 if r["role"] == "chassis" else 0o644)
        os.replace(tmp, dst)
        n += 1

    if info["serial"] and not want:
        pin_serial(info["serial"])
        log("ffn-dnx: pinned chassis serial %s (first import)" % info["serial"])

    meta = {"source": d, "serial": info["serial"], "gendate": info["gendate"],
            "files": {r["name"]: {"size": r["size"],
                                  "sha256": sha256_file(r["path"]),
                                  "role": r["role"]}
                      for r in info["files"]
                      if r["role"] not in ("unknown", "refused")}}
    with open(os.path.join(STORE, ".ffn-dnx.json"), "w") as f:
        json.dump(meta, f, indent=2, sort_keys=True)

    log("ffn-dnx: imported %d files into %s" % (n, STORE))
    return 0


def read_store_meta():
    try:
        with open(os.path.join(STORE, ".ffn-dnx.json")) as f:
            return json.load(f)
    except Exception:
        return None


# -------------------------------------------------------------------- load ---
def do_load(dp_root=DP_ROOT, dry_run=False):
    """Place the imported set where the dataplane reads it."""
    meta = read_store_meta()
    if not meta:
        log("ffn-dnx: nothing imported; plug in media carrying the DNX set")
        return 1

    want, _how = pinned_serial()
    ok, findings, info = verify_set(STORE, want_serial=want)
    if not ok:
        report(findings, info, header="store %s" % STORE)
        log("ffn-dnx: load REFUSED -- the store does not verify")
        return 1

    target = os.path.join(dp_root, DNX_REL)
    if not os.path.isdir(dp_root):
        log("ffn-dnx: dataplane root %s absent; nothing to load into" % dp_root)
        return 1

    if dry_run:
        log("ffn-dnx: would place %d files into %s"
            % (len(meta["files"]), target))
        return 0

    os.makedirs(target, exist_ok=True)
    n = 0
    for name in sorted(meta["files"]):
        src = os.path.join(STORE, name)
        if not os.path.isfile(src):
            continue
        dst = os.path.join(target, name)
        tmp = dst + ".new"
        shutil.copyfile(src, tmp)
        os.chmod(tmp, 0o600 if FILES.get(name, {}).get("role") == "chassis"
                 else 0o644)
        os.replace(tmp, dst)
        n += 1
    log("ffn-dnx: placed %d files into %s" % (n, target))
    return 0


# ------------------------------------------------------------------- check ---
def image_leak(tree):
    """Is FFN shipping any DNX file? Returns a list of offending paths.

    This is the "user-supplied only" rule as a grep: if one of these filenames
    appears in FFN's own source or image, the build is wrong however it got
    there.
    """
    hits = []
    names = set(FILES)
    for root, dirs, files in os.walk(tree):
        dirs[:] = [d for d in dirs if d not in (".git", "__pycache__")]
        for fn in files:
            if fn in names:
                hits.append(os.path.relpath(os.path.join(root, fn), tree))
    return hits


def do_check(dp_root=DP_ROOT, source_tree=None, quiet=False):
    """The standing check: the dataplane holds user-supplied DNX files only.

    Exit codes are distinct so a caller can tell "not supplied yet" -- an
    ordinary state on a fresh appliance -- from "supplied wrongly", which is not.

        0  set present, user-supplied, fits this chassis
        1  set incomplete or unfit -- refuse to init the switch
        2  FFN is shipping vendor files -- packaging bug, hard stop
        3  no set present at all -- awaiting owner media
    """
    target = os.path.join(dp_root, DNX_REL)
    meta = read_store_meta()
    want, how = pinned_serial()
    out = []

    if source_tree:
        leaks = image_leak(source_tree)
        if leaks:
            print("PACKAGING BUG: FFN source tree %s contains vendor DNX files:"
                  % source_tree)
            for h in leaks[:15]:
                print("    " + h)
            print("\nThese are the appliance owner's files. FFN must not ship "
                  "them.")
            return 2
        out.append("  image        clean: no DNX files in %s" % source_tree)

    if not os.path.isdir(target):
        if not quiet:
            print("dataplane DNX set: NOT PRESENT")
            print("  %s does not exist." % target)
            print("  Plug in media carrying the appliance's own DNX files.")
        return 3

    present = {n for n in os.listdir(target)
               if os.path.isfile(os.path.join(target, n))}
    if not any(n in present for n in REQUIRED):
        if not quiet:
            print("dataplane DNX set: NOT PRESENT (%s holds no known files)"
                  % target)
        return 3

    ok, findings, info = verify_set(target, want_serial=want, from_media=False)

    # Provenance: every file must trace to the owner's import. A file in the DP
    # tree that FFN's store has never seen is the case this check exists to
    # catch -- something other than the owner put it there.
    unaccounted = []
    if meta:
        known = meta.get("files", {})
        for r in info["files"]:
            if r["role"] in ("unknown", "refused"):
                continue
            k = known.get(r["name"])
            if not k:
                unaccounted.append((r["name"],
                                    "not in the owner's import record"))
            elif sha256_file(r["path"]) != k["sha256"]:
                unaccounted.append((r["name"],
                                    "content differs from what was imported"))
    else:
        unaccounted.append(("*", "no import record: these files were not placed "
                                 "here by ffn_dnx import. On an appliance still "
                                 "running its own vendor rootfs that is expected "
                                 "-- the files are the owner's, in place. On an "
                                 "FFN rootfs it is not."))

    for name, why in unaccounted:
        findings.append(("PROVENANCE", name, why))

    if not quiet:
        report(findings, info, header="dataplane %s" % target,
               extra=out, serial_how=how, want_serial=want)

    hard = {"MISSING", "REFUSED", "MALFORMED", "CORRUPT", "CHASSIS-MISMATCH"}
    if any(f[0] in hard for f in findings):
        return 1
    # Only a hard failure when we DO have a record to compare against.
    if meta and any(f[0] == "PROVENANCE" for f in findings):
        return 1
    return 0


def report(findings, info, header="", extra=None, serial_how=None,
           want_serial=None):
    print("DNX file set: %s" % header)
    for line in (extra or []):
        print(line)
    if info.get("serial"):
        s = "  chassis      %s" % info["serial"]
        if want_serial and info["serial"] == want_serial:
            s += "  (matches %s)" % (serial_how or "pin")
        print(s)
    if info.get("gendate"):
        print("  calibrated   %s" % info["gendate"])

    roles = {}
    for r in info.get("files", []):
        roles.setdefault(r["role"], []).append(r["name"])
    for role in ("shipped", "chassis", "optional", "refused", "unknown"):
        if roles.get(role):
            print("  %-12s %s" % (role, ", ".join(sorted(roles[role]))))

    if not findings:
        print("  result       OK -- complete, owner-supplied, fits this chassis")
        return
    print("  result       %d finding(s):" % len(findings))
    for sev, name, why in findings:
        print("    %-17s %-24s %s" % (sev, name, why))


# ---------------------------------------------------------------- selftest ---
def selftest():
    fails = []
    groups = 0

    def grp(name, fn):
        nonlocal groups
        groups += 1
        try:
            fn()
        except AssertionError as e:
            fails.append("%s: %s" % (name, e))
        except Exception as e:
            fails.append("%s: unexpected %s: %s" % (name, type(e).__name__, e))

    tmp = tempfile.mkdtemp(prefix="ffn-dnx-test.")

    def w(name, text, d=tmp):
        p = os.path.join(d, name)
        with open(p, "w") as f:
            f.write(text)
        return p

    GOOD_PROPS = "# c\nconfig add a=0x1;\nconfig add b=0x2;\n"
    GOOD_TUNE = ("# Version 2.0\n# Serial Number 013201019751\n"
                 "# Date Generated 08/18/26 11:51:38\nconfig add x=0x0;\n")
    GOOD_SCRIPT = "local QMX 1\nrcload jer.soc\n"
    GOOD_BCM = ("ucode_port_12.BCM88650=CGE1:core_0.12\n"
                "port_init_speed_12=-1\n")
    GOOD_CINT = "int f(){ bcm_port_enable_set(0,12,1); return 0; }\n"
    GOOD_SAVED = ("ext_ram_freq.BCM88370=1400" + chr(10)
                  + "port_init_speed_32=-1" + chr(10))

    def full_set(d, tune=GOOD_TUNE):
        os.makedirs(d, exist_ok=True)
        w("rc.soc", GOOD_SCRIPT, d)
        w("jer.soc", GOOD_SCRIPT, d)
        w("bcm88375_board.soc", GOOD_PROPS, d)
        w("config.bcm", GOOD_BCM, d)
        w("gryphon_dram_tune.soc", tune, d)
        return d

    # [1] property-file validator rejects procedural content
    def t1():
        p = w("bcm88375_board.soc", GOOD_PROPS)
        assert v_soc_props(p) is None, "good props rejected"
        p = w("bad.soc", "config add a=0x1;\nrcload other.soc\n")
        assert v_soc_props(p) is not None, "procedural line accepted"
    grp("[1] soc_props", t1)

    # [2] script validator is the mirror image
    def t2():
        p = w("jer.soc", GOOD_SCRIPT)
        assert v_soc_script(p) is None, "good script rejected"
        p = w("props.soc", GOOD_PROPS)
        assert v_soc_script(p) is not None, "property file accepted as script"
    grp("[2] soc_script", t2)

    # [3] config.bcm needs a port map and a known property suffix
    def t3():
        p = w("config.bcm", GOOD_BCM)
        assert v_config_bcm(p) is None, "good config.bcm rejected"
        p = w("c2.bcm", "port_init_speed_12=-1\n")
        assert v_config_bcm(p) is not None, "no ucode_port accepted"
        p = w("c3.bcm", "ucode_port_1.BCM99999=X:core_0.1\n")
        assert v_config_bcm(p) is not None, "unknown suffix accepted"
    grp("[3] config_bcm", t3)

    # [4] cint must actually call the SDK
    def t4():
        p = w("enable_fp_ports.c", GOOD_CINT)
        assert v_cint(p) is None, "good cint rejected"
        p = w("x.c", "int main(){return 0;}\n")
        assert v_cint(p) is not None, "non-cint C accepted"
    grp("[4] cint", t4)

    # [5] serial extraction
    def t5():
        p = w("gryphon_dram_tune.soc", GOOD_TUNE)
        assert serial_of_tune(p) == "013201019751", serial_of_tune(p)
        assert "08/18/26" in (gendate_of_tune(p) or "")
        p = w("t2.soc", GOOD_PROPS)
        assert serial_of_tune(p) is None, "serial invented from a file with none"
    grp("[5] serial header", t5)

    # [6] a complete, matching set verifies
    def t6():
        d = full_set(os.path.join(tmp, "good"))
        ok, f, i = verify_set(d, want_serial="013201019751")
        assert ok, list(f)
        assert i["serial"] == "013201019751"
    grp("[6] complete set", t6)

    # [7] chassis mismatch is refused -- the hardware-hazard case
    def t7():
        other = GOOD_TUNE.replace("013201019751", "013201099999")
        d = full_set(os.path.join(tmp, "otherbox"), tune=other)
        ok, f, _i = verify_set(d, want_serial="013201019751")
        assert not ok, "another board's calibration accepted"
        assert any(s == "CHASSIS-MISMATCH" for s, _n, _w in f), list(f)
    grp("[7] chassis mismatch", t7)

    # [8] missing required file is caught
    def t8():
        d = full_set(os.path.join(tmp, "incomplete"))
        os.remove(os.path.join(d, "config.bcm"))
        ok, f, _i = verify_set(d, want_serial="013201019751")
        assert not ok
        assert any(s == "MISSING" and n == "config.bcm"
                   for s, n, _w in f), list(f)
    grp("[8] incomplete set", t8)

    # [9] runningConfig.soc is refused from media
    def t9():
        d = full_set(os.path.join(tmp, "withrunning"))
        w("runningConfig.soc", GOOD_SAVED, d)
        ok, f, _i = verify_set(d, want_serial="013201019751")
        assert not ok, "runtime snapshot accepted as input"
        assert any(s == "REFUSED" for s, _n, _w in f), list(f)
    grp("[9] refuse snapshot", t9)

    # [10] unrecognised content is refused, not silently loaded
    def t10():
        d = full_set(os.path.join(tmp, "extra"))
        w("evil.soc", GOOD_PROPS, d)
        w(".DS_Store", "mac turd", d)
        ok, f, _i = verify_set(d, want_serial="013201019751")
        assert ok, "an unrelated extra file blocked a good set: %s" % list(f)
        assert any(s == "EXTRA" and n == "evil.soc"
                   for s, n, _w in f), list(f)
        assert not any(n == ".DS_Store" for _s, n, _w in f), "dotfile reported"
    grp("[10] unknown content", t10)

    # [11] files.md5 corruption is caught, and a correct one passes
    def t11():
        d = full_set(os.path.join(tmp, "corrupt"))
        tune = os.path.join(d, "gryphon_dram_tune.soc")
        w("files.md5", "%s  %s\n" % ("0" * 32, tune), d)
        ok, f, _i = verify_set(d, want_serial="013201019751")
        assert not ok
        assert any(s == "CORRUPT" for s, _n, _w in f), list(f)
        w("files.md5", "%s  %s\n" % (md5_file(tune), tune), d)
        ok, f, _i = verify_set(d, want_serial="013201019751")
        assert ok, list(f)
    grp("[11] md5 manifest", t11)

    # [12] find_set locates both shapes and ignores ordinary media
    def t12():
        sysroot = os.path.join(tmp, "sysroot")
        full_set(os.path.join(sysroot, DNX_REL))
        assert find_set(sysroot) == os.path.join(sysroot, DNX_REL)
        loose = full_set(os.path.join(tmp, "loose"))
        assert find_set(loose) == loose
        plain = os.path.join(tmp, "holidayphotos")
        os.makedirs(plain, exist_ok=True)
        w("cat.jpg", "not a soc file", plain)
        assert find_set(plain) is None, "ordinary media matched as a DNX set"
        # one lone .soc file is not a set either
        w("rc.soc", GOOD_SCRIPT, plain)
        assert find_set(plain) is None, "single file matched as a set"
    grp("[12] find_set", t12)

    # [13] the packaging gate catches FFN shipping vendor files
    def t13():
        tree = os.path.join(tmp, "ffnsrc")
        os.makedirs(os.path.join(tree, "image"), exist_ok=True)
        w("README.md", "hello", tree)
        assert image_leak(tree) == [], image_leak(tree)
        w("config.bcm", GOOD_BCM, os.path.join(tree, "image"))
        leaks = image_leak(tree)
        assert leaks and leaks[0].endswith("config.bcm"), leaks
    grp("[13] packaging gate", t13)

    # [17] import -> load -> check round trip, with FFN's own metadata in the
    #      store. This is the path a plugged-in stick takes.
    def t17():
        g = globals()
        saved = (g["STORE"], g["SERIAL_PIN"], g["CONF"])
        try:
            vd = os.path.join(tmp, "vendordir")
            g["STORE"] = os.path.join(vd, "dnx")
            g["SERIAL_PIN"] = os.path.join(vd, "chassis-serial")
            g["CONF"] = os.path.join(vd, "no-such-vendor.conf")
            stick = full_set(os.path.join(tmp, "stick"))
            tune = os.path.join(stick, "gryphon_dram_tune.soc")
            w("files.md5", md5_file(tune) + "  gryphon_dram_tune.soc" + chr(10),
              stick)
            assert do_import(stick) == 0, "clean stick refused"
            dproot = os.path.join(tmp, "dproot")
            os.makedirs(dproot, exist_ok=True)
            assert do_load(dp_root=dproot) == 0, "load refused after clean import"
            got = set(os.listdir(os.path.join(dproot, DNX_REL)))
            assert set(REQUIRED) <= got, "required files not placed: %s" % (
                set(REQUIRED) - got)
            assert do_check(dp_root=dproot, quiet=True) == 0, "check failed"
        finally:
            g["STORE"], g["SERIAL_PIN"], g["CONF"] = saved
    grp("[17] round trip", t17)

    # [16] the three .soc syntaxes are told apart, not conflated
    def t16():
        props = w("p.soc", GOOD_PROPS)
        script = w("s.soc", 'if $?dram_type_DDR4 "config add a=0x1;"' + chr(10))
        saved = w("v.soc", "ext_ram_freq.BCM88370=1400" + chr(10)
                  + "port_init_speed_32=-1" + chr(10))
        assert v_soc_props(props) is None
        assert v_soc_props(saved) is not None, "saved config passed as properties"
        assert v_soc_script(script) is None, v_soc_script(script)
        assert v_soc_saved(saved) is None, v_soc_saved(saved)
        assert v_soc_saved(props) is not None, "properties passed as saved config"
    grp("[16] three soc syntaxes", t16)

    # [15] the media/tree asymmetry: same file, opposite verdicts
    def t15():
        d = full_set(os.path.join(tmp, "asym"))
        w("runningConfig.soc", GOOD_SAVED, d)
        ok, f, _i = verify_set(d, want_serial="013201019751", from_media=True)
        assert not ok, "snapshot accepted from media"
        ok, f, _i = verify_set(d, want_serial="013201019751", from_media=False)
        assert ok, "snapshot rejected in the dataplane tree: %s" % list(f)
        assert any(s == "SNAPSHOT" for s, _n, _w in f), list(f)
    grp("[15] media/tree asymmetry", t15)

    # [14] REQUIRED/REFUSED derive from FILES and stay consistent
    def t14():
        assert "runningConfig.soc" in REFUSED
        assert "runningConfig.soc" not in REQUIRED
        assert "gryphon_dram_tune.soc" in REQUIRED
        assert "config.bcm" in REQUIRED
        assert "files.md5" not in REQUIRED, "manifest must not be mandatory"
        for n in REQUIRED:
            assert FILES[n]["kind"] in VALIDATORS, "%s has no validator" % n
    grp("[14] set consistency", t14)

    shutil.rmtree(tmp, ignore_errors=True)

    print("ffn_dnx selftest: %d groups, %d failed" % (groups, len(fails)))
    for f in fails:
        print("  FAIL " + f)
    return 1 if fails else 0


# --------------------------------------------------------------------- CLI ---
def main():
    ap = argparse.ArgumentParser(
        description="Verify and load the dataplane's owner-supplied DNX set")
    sub = ap.add_subparsers(dest="cmd")

    p = sub.add_parser("scan", help="is there a DNX set on this media?")
    p.add_argument("--source", required=True)

    p = sub.add_parser("verify", help="check a set without importing it")
    p.add_argument("--source", required=True)

    p = sub.add_parser("import", help="copy a set into FFN's owner-local store")
    p.add_argument("--source", required=True)
    p.add_argument("--force", action="store_true",
                   help="import despite findings; the mismatch is still recorded")

    p = sub.add_parser("check",
                       help="standing check: user-supplied only, and fit")
    p.add_argument("--dp-root", default=DP_ROOT)
    p.add_argument("--source-tree", default=None,
                   help="also assert FFN is shipping none of these files")
    p.add_argument("--quiet", action="store_true")

    p = sub.add_parser("load", help="place the set where the dataplane reads it")
    p.add_argument("--dp-root", default=DP_ROOT)
    p.add_argument("--dry-run", action="store_true")

    sub.add_parser("status", help="what is pinned and staged")
    sub.add_parser("selftest", help="self-checks, no hardware needed")

    a = ap.parse_args()

    if a.cmd == "scan":
        d = find_set(a.source)
        if not d:
            print("no DNX file set on %s" % a.source)
            return 1
        print("DNX file set at %s" % d)
        for r in inventory(d):
            print("  %-24s %7d  %-8s %s" % (r["name"], r["size"], r["role"],
                                            r["problem"] or ""))
        return 0

    if a.cmd == "verify":
        d = find_set(a.source)
        if not d:
            print("no DNX file set on %s" % a.source)
            return 1
        want, how = pinned_serial()
        ok, f, i = verify_set(d, want_serial=want)
        report(f, i, header=d, serial_how=how, want_serial=want)
        return 0 if ok else 1

    if a.cmd == "import":
        return do_import(a.source, force=a.force)

    if a.cmd == "check":
        return do_check(dp_root=a.dp_root, source_tree=a.source_tree,
                        quiet=a.quiet)

    if a.cmd == "load":
        return do_load(dp_root=a.dp_root, dry_run=a.dry_run)

    if a.cmd == "status":
        want, how = pinned_serial()
        print("chassis serial   %s (%s)" % (want or "not pinned", how or "-"))
        print("store            %s" % STORE)
        meta = read_store_meta()
        if not meta:
            print("                 nothing imported")
        else:
            print("  imported from  %s" % meta.get("source"))
            print("  calibrated     %s" % meta.get("gendate"))
            for n, v in sorted(meta.get("files", {}).items()):
                print("    %-24s %7d  %-8s %s" % (n, v["size"], v["role"],
                                                  v["sha256"][:16]))
        print("dataplane root   %s" % DP_ROOT)
        return 0

    if a.cmd == "selftest":
        return selftest()

    ap.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
