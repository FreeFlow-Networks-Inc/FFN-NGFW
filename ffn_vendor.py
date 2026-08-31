#!/usr/bin/env python3
"""ffn_vendor.py -- use YOUR OWN vendor firmware with FFN.

If you own a Palo Alto appliance, you own the firmware that shipped on it. FFN
cannot legally redistribute that firmware, but nothing stops you from using your
own copy on your own box. This module is the supported way to do that:

    * find vendor artifacts on locally attached media -- an original appliance
      SSD, a recovery partition, or a USB stick you copied them onto,
    * work out which PLATFORM they belong to, and refuse to pair a PA-3200
      bitstream with a PA-5200 chassis (an easy and destructive mistake),
    * check them against Palo Alto's own SHA-256 manifest,
    * register them in a local-only directory, and load them.

Nothing here downloads vendor content, and nothing here lets vendor content
into an FFN image or payload. `check-clean` exists so the build pipeline can
prove that, and it is wired into build.sh, verify-image.sh and the publisher.

TRUST, STATED PLAINLY
    The `fpga-images` manifest gives INTEGRITY, not AUTHENTICITY: whoever
    controls the media controls both the bitstream and the manifest that
    describes it. The signed `fpga-images.sgn` would give authenticity, but
    verifying it needs Palo Alto's public key, which FFN does not have and does
    not work around. So a platform match plus a manifest match means "this is
    intact and belongs to this chassis type" -- it does not mean "Palo Alto
    signed this". Treat removable media accordingly; that is why auto-load is
    limited to artifacts matching this exact chassis and why every step is
    logged.

    ffn_vendor.py detect                      # what chassis is this?
    ffn_vendor.py scan   --source /mnt/usb    # what is on that media?
    ffn_vendor.py import --source /mnt/usb    # register it locally
    ffn_vendor.py load   [--kind fpga|octeon] # hand off to the loader
    ffn_vendor.py status
    ffn_vendor.py check-clean <dir-or-tar>    # build gate: assert none present
"""
import argparse
import glob
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time

VENDOR_DIR = os.environ.get("FFN_VENDOR_DIR", "/var/lib/ffn-ngfw/vendor")
CONF = os.environ.get("FFN_VENDOR_CONF", "/etc/ffn-ngfw/vendor.conf")

# Platform fingerprints, taken from Palo Alto's own per-platform installer
# scripts (swmscript/<name>.py) and the udev rules they write. The PCI
# addresses are the discriminator: they are fixed by the board layout, so they
# identify a chassis far more reliably than any string in DMI.
PLATFORMS = {
    "gryphon": {
        "panos": "52xx",
        "models": ["PA-5220", "PA-5250", "PA-5260", "PA-5280"],
        "igb": ["0000:0f:00.0", "0000:10:00.0", "0000:11:00.0"],
        "ixgbe": ["0000:08:00.0", "0000:08:00.1", "0000:0b:00.0", "0000:0b:00.1"],
        "diskdev": "/dev/md",
        "octeon": "OCTEON III CN73XX",
        # Front-panel RJ-45 roles. Keyed by PCI address, not interface name,
        # because udev naming can change but the board layout cannot. The three
        # I210s are NOT interchangeable: one is management, the other two are the
        # HA control pair, so HA1 must not be pointed at a random one of them.
        # Front-panel roles, keyed by PCI address because udev naming can change
        # but the board layout cannot. Nothing here is a DATA port: on a PA-5200
        # every host-visible interface is management-class or the internal
        # backplane link to the dataplane complex, and the real data ports sit
        # behind the Octeon. Bridging AUX-1/AUX-2 as a bump-in-the-wire would
        # join two management interfaces.
        "port_roles": {
            "0000:0f:00.0": "mgmt",     # MGT      RJ-45
            "0000:10:00.0": "ha1-a",    # HA1-A    RJ-45, HA control
            "0000:11:00.0": "ha1-b",    # HA1-B    RJ-45, HA control
            "0000:0b:00.0": "aux-1",    # AUX-1    10G SFP+, management-class
            "0000:0b:00.1": "aux-2",    # AUX-2    10G SFP+, management-class
            "0000:08:00.0": "backplane-0",  # internal link to the DP complex
            "0000:08:00.1": "backplane-1",
        },
    },
    "redtail": {
        "panos": "32xx",
        "models": ["PA-3220", "PA-3250", "PA-3260"],
        "igb": ["0000:0d:00.0", "0000:0e:00.0"],
        "ixgbe": ["0000:08:00.0", "0000:08:00.1"],
        "diskdev": None,
        "octeon": "OCTEON II",
        # Not yet confirmed on a PA-3200 chassis; left empty rather than guessed.
        "port_roles": {},
    },
}

# Where vendor artifacts live inside a PAN-OS sysroot, and what they are.
ARTIFACTS = {
    "fpga": {
        # Both shapes are supported: a full PAN-OS sysroot, and loose files
        # copied onto a USB stick (which is how most owners will carry them).
        "globs": ["boot/fpga/*.bin", "fpga/*.bin", "ce*.bin", "ca*.bin"],
        "manifest": ["etc/pan-manifest/fpga-images", "fpga-images",
                     "pan-manifest/fpga-images"],
        "signature": ["etc/pan-manifest/fpga-images.sgn", "fpga-images.sgn"],
        "desc": "FPGA bitstream",
    },
    "octeon": {
        "globs": ["opt/dpfs/boot/u-boot-*_pciboot.bin", "opt/dpfs/boot/vmlinux-*-dp",
                  "opt/dpfs/boot/vmlinux.oct*-dp", "u-boot-*_pciboot.bin",
                  "vmlinux-*-dp", "vmlinux.oct*-dp"],
        "manifest": None,
        "signature": None,
        "desc": "Octeon dataplane boot image",
    },
}


def log(msg):
    print(msg)
    try:
        subprocess.run(["logger", "-t", "ffn-vendor", msg], timeout=2,
                       capture_output=True)
    except Exception:
        pass


def sha256_file(p, chunk=1 << 20):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(chunk), b""):
            h.update(b)
    return h.hexdigest()


# --------------------------------------------------------------- chassis ----
def pci_of(driver):
    """PCI addresses of every net device bound to `driver` on this machine."""
    out = []
    for n in sorted(glob.glob("/sys/class/net/*/device")):
        try:
            drv = os.path.basename(os.path.realpath(os.path.join(n, "driver")))
            if drv == driver:
                out.append(os.path.basename(os.path.realpath(n)))
        except Exception:
            pass
    return sorted(out)


def detect_chassis():
    """Identify this chassis by its PCI layout, falling back to DMI."""
    igb, ixgbe = pci_of("igb"), pci_of("ixgbe")
    best, score = None, 0.0
    for name, p in PLATFORMS.items():
        want = set(p["igb"]) | set(p["ixgbe"])
        have = set(igb) | set(ixgbe)
        if not want:
            continue
        s = len(want & have) / float(len(want))
        if s > score:
            best, score = name, s
    dmi = ""
    try:
        with open("/sys/class/dmi/id/product_name") as f:
            dmi = f.read().strip()
    except Exception:
        pass
    return {
        "platform": best if score >= 0.99 else None,
        "match": round(score, 3),
        "dmi": dmi,
        "igb": igb,
        "ixgbe": ixgbe,
        "models": PLATFORMS[best]["models"] if best and score >= 0.99 else [],
    }



def port_roles(platform=None):
    """Map this chassis's special RJ-45 ports to their current interface names.

    Roles come from the board layout (PCI address), so they survive any udev
    renaming. Returns {role: {"iface", "pci", "carrier", "operstate"}} for the
    roles this platform defines -- typically mgmt plus the HA1 control pair.
    Empty for a platform whose layout has not been confirmed.
    """
    if platform is None:
        platform = detect_chassis().get("platform")
    roles = (PLATFORMS.get(platform) or {}).get("port_roles") or {}
    if not roles:
        return {}

    # invert: PCI -> current ifname
    bypci = {}
    for n in sorted(glob.glob("/sys/class/net/*/device")):
        try:
            pci = os.path.basename(os.path.realpath(n))
            bypci[pci] = os.path.basename(os.path.dirname(n))
        except Exception:
            pass

    out = {}
    for pci, role in roles.items():
        iface = bypci.get(pci)
        rec = {"pci": pci, "iface": iface, "carrier": None, "operstate": None}
        if iface:
            for k, f in (("carrier", "carrier"), ("operstate", "operstate")):
                try:
                    with open("/sys/class/net/%s/%s" % (iface, f)) as fh:
                        rec[k] = fh.read().strip()
                except Exception:
                    pass
        out[role] = rec
    return out

# ---------------------------------------------------------------- source ----
def identify_source(root):
    """Which platform do the artifacts on `root` belong to?

    Three independent tells, in decreasing reliability:
      1. the udev rules PAN-OS actually installed ("# panos 52xx ...")
      2. the DP boot image name (u-boot-<codename>_pciboot.bin)
      3. the swmscript modules present (weak: images ship every platform's)
    """
    ev = {"udev": None, "uboot": None, "swmscript": [], "platform": None,
          "why": []}

    for rules in glob.glob(os.path.join(root, "etc/udev/rules.d/*.rules")):
        try:
            with open(rules, errors="replace") as f:
                txt = f.read()
        except Exception:
            continue
        m = re.search(r"#\s*panos\s+(\w+)\s+added rules", txt)
        if m:
            ev["udev"] = m.group(1)
            for name, p in PLATFORMS.items():
                if p["panos"] == m.group(1):
                    ev["platform"] = name
                    ev["why"].append("installed udev rules say 'panos %s'" % m.group(1))
            break

    for g in ("opt/dpfs/boot/u-boot-*_pciboot.bin", "u-boot-*_pciboot.bin"):
        for f in glob.glob(os.path.join(root, g)):
            m = re.search(r"u-boot-([a-z0-9]+)_", os.path.basename(f))
            if m:
                ev["uboot"] = m.group(1)
                if not ev["platform"] and m.group(1) in PLATFORMS:
                    ev["platform"] = m.group(1)
                    ev["why"].append("DP boot image is %s" % os.path.basename(f))
                elif ev["platform"] and m.group(1) != ev["platform"]:
                    ev["why"].append("WARNING: u-boot says %s but udev says %s"
                                     % (m.group(1), ev["platform"]))
            break

    for f in glob.glob(os.path.join(root, "usr/lib*/python*/site-packages/swmscript/*.py")):
        n = os.path.splitext(os.path.basename(f))[0]
        if n in PLATFORMS:
            ev["swmscript"].append(n)
    if len(ev["swmscript"]) > 1:
        ev["why"].append("swmscript lists %d platforms (multi-platform image; "
                         "not a discriminator)" % len(ev["swmscript"]))
    return ev


def read_manifest(root, rels):
    """PAN's manifest lines look like:  <sha256> */boot/fpga/ce10.bin

    Returns {relative_path: sha256} and additionally keys each entry by its
    BASENAME, so a manifest copied alongside loose files on a USB stick still
    matches even though the original directory structure is gone.
    """
    out = {}
    if not rels:
        return out
    if isinstance(rels, str):
        rels = [rels]
    for rel in rels:
        p = os.path.join(root, rel)
        if not os.path.isfile(p):
            continue
        try:
            with open(p, errors="replace") as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 2 and len(parts[0]) == 64:
                        key = parts[1].lstrip("*").lstrip("/")
                        out[key] = parts[0]
                        out[os.path.basename(key)] = parts[0]
        except Exception:
            pass
    return out


def scan_source(root):
    """Find vendor artifacts under `root` and check them against the manifest."""
    found = []
    for kind, spec in ARTIFACTS.items():
        man = read_manifest(root, spec["manifest"])
        seen = set()
        for g in spec["globs"]:
            for f in sorted(glob.glob(os.path.join(root, g))):
                if not os.path.isfile(f) or f in seen:
                    continue
                seen.add(f)
                rel = os.path.relpath(f, root)
                rec = {"kind": kind, "path": f, "rel": rel,
                       "size": os.path.getsize(f), "desc": spec["desc"],
                       "manifest": None, "sha256": None, "integrity": "unchecked"}
                want = man.get(rel) or man.get(os.path.basename(rel))
                if want:
                    rec["manifest"] = want
                    rec["sha256"] = sha256_file(f)
                    rec["integrity"] = "ok" if rec["sha256"] == want else "MISMATCH"
                found.append(rec)
        if man and spec["signature"]:
            sigs = spec["signature"]
            if isinstance(sigs, str):
                sigs = [sigs]
            if any(os.path.isfile(os.path.join(root, s)) for s in sigs):
                for r in found:
                    if r["kind"] == kind:
                        # Present, but NOT verified: checking it needs Palo
                        # Alto's public key, which FFN does not have.
                        r["signed_manifest_present"] = True
    return found


# ---------------------------------------------------------------- import ----
def load_conf():
    cfg = {"autoload": "yes", "autoimport": "yes"}
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


def registry_path():
    return os.path.join(VENDOR_DIR, "registry.json")


def read_registry():
    try:
        with open(registry_path()) as f:
            return json.load(f)
    except Exception:
        return {"artifacts": []}


def write_registry(reg):
    os.makedirs(VENDOR_DIR, exist_ok=True)
    tmp = registry_path() + ".tmp"
    with open(tmp, "w") as f:
        json.dump(reg, f, indent=2)
    os.replace(tmp, registry_path())
    # A visible, unmissable marker for anyone who finds this directory later.
    with open(os.path.join(VENDOR_DIR, "DO-NOT-PACKAGE"), "w") as f:
        f.write(
            "Vendor firmware belonging to THIS machine's owner.\n\n"
            "These files came off the owner's own appliance or their own media.\n"
            "They are used in place on this machine only. They must never be\n"
            "copied into an FFN image, an update payload, or any artifact that\n"
            "leaves this box -- that would be redistributing another company's\n"
            "firmware.\n\n"
            "The build pipeline enforces this: build.sh excludes this directory\n"
            "and aborts if vendor artifacts appear in a payload, verify-image.sh\n"
            "fails an image containing them, and ffn_payload.py refuses to\n"
            "publish one. Do not remove those checks.\n")


def do_import(source, force=False, chassis=None):
    if chassis is None:
        chassis = detect_chassis()
    ev = identify_source(source)
    arts = scan_source(source)
    if not arts:
        log("ffn-vendor: no vendor artifacts under %s" % source)
        return 1, []

    src_plat, box_plat = ev.get("platform"), chassis.get("platform")
    if src_plat and box_plat and src_plat != box_plat:
        log("ffn-vendor: REFUSING -- media holds %s (%s) firmware but this "
            "chassis is %s (%s). Loading it could brick the box."
            % (src_plat, PLATFORMS[src_plat]["panos"],
               box_plat, PLATFORMS[box_plat]["panos"]))
        if not force:
            return 2, []
        log("ffn-vendor: --force given; recording the mismatch and continuing")

    bad = [a for a in arts if a["integrity"] == "MISMATCH"]
    if bad:
        for a in bad:
            log("ffn-vendor: REFUSING %s -- sha256 does not match the vendor "
                "manifest (corrupt or altered)" % a["rel"])
        arts = [a for a in arts if a["integrity"] != "MISMATCH"]
        if not arts:
            return 3, []

    dest = os.path.join(VENDOR_DIR, src_plat or "unknown")
    os.makedirs(dest, exist_ok=True)
    reg = read_registry()
    imported = []
    for a in arts:
        out = os.path.join(dest, os.path.basename(a["path"]))
        try:
            shutil.copy2(a["path"], out)
        except Exception as e:
            log("ffn-vendor: could not copy %s: %s" % (a["rel"], e))
            continue
        rec = {
            "kind": a["kind"], "file": out, "from": a["rel"],
            "source": source, "size": a["size"],
            "sha256": a["sha256"] or sha256_file(out),
            "integrity": a["integrity"],
            "platform": src_plat, "chassis": box_plat,
            "platform_mismatch": bool(src_plat and box_plat and src_plat != box_plat),
            "imported": int(time.time()),
            "local_only": True,
        }
        reg["artifacts"] = [r for r in reg.get("artifacts", [])
                            if r.get("file") != out] + [rec]
        imported.append(rec)
        log("ffn-vendor: imported %s (%s, %d bytes, integrity=%s)"
            % (os.path.basename(out), a["desc"], a["size"], a["integrity"]))
    write_registry(reg)
    return 0, imported


# ------------------------------------------------------------------ load ----
def do_load(kind=None):
    """Hand registered artifacts to the loader that owns that hardware."""
    reg = read_registry()
    arts = [a for a in reg.get("artifacts", []) if not kind or a["kind"] == kind]
    if not arts:
        log("ffn-vendor: nothing registered to load")
        return 1
    rc = 0
    for a in arts:
        if a.get("platform_mismatch"):
            log("ffn-vendor: SKIPPING %s -- imported with a platform mismatch"
                % os.path.basename(a["file"]))
            rc = 2
            continue
        if not os.path.isfile(a["file"]):
            log("ffn-vendor: missing %s" % a["file"])
            rc = 1
            continue
        if a["kind"] == "octeon":
            oct_py = "/opt/ffn-ngfw-v2/ffn_oct.py"
            if os.path.isfile(oct_py):
                log("ffn-vendor: handing %s to ffn_oct.py"
                    % os.path.basename(a["file"]))
                r = subprocess.run(["python3", oct_py, "load",
                                    "--image", a["file"]],
                                   capture_output=True, text=True)
                print((r.stdout or r.stderr)[:800])
                rc = rc or r.returncode
            else:
                log("ffn-vendor: ffn_oct.py absent; %s staged only"
                    % os.path.basename(a["file"]))
        elif a["kind"] == "fpga":
            # On this platform the FPGA sits BEHIND the Octeon, so it cannot be
            # loaded from the host until the NPU is running FFN code. Staged
            # and recorded; the Octeon bring-up path consumes it.
            log("ffn-vendor: %s staged for the FPGA loader. The fabric is "
                "behind the NPU on this chassis, so it loads as part of Octeon "
                "bring-up, not directly from the host."
                % os.path.basename(a["file"]))
    return rc


# ------------------------------------------------------------ build gate ----
# Matches vendor firmware however it is laid out: inside a PAN-OS sysroot, in
# FFN's local vendor directory, or as loose files someone copied off a stick.
# A build gate should err toward catching too much -- a false positive is loud
# and rare, a miss ships another company's firmware.
VENDOR_SIGNS = re.compile(
    r"(ffn-ngfw/vendor/"          # FFN's owner-local store
    r"|^\./vendor/|^vendor/"      # a bare vendor/ tree at archive root
    r"|/boot/fpga/|opt/dpfs/"     # PAN-OS sysroot locations
    r"|u-boot-\w+_pciboot\.bin"   # Octeon boot images
    r"|vmlinux-[\d.]+-oct\d-dp"
    r"|pan-manifest/fpga-images"
    r"|(^|/)c[ae]\d+\.bin$)")     # ce10/ce40/ca1 bitstreams, loose


def check_clean(target):
    """Assert no vendor artifacts in a directory or tarball. Build-gate use."""
    names = []
    if os.path.isdir(target):
        for root, _d, files in os.walk(target):
            for fn in files:
                names.append(os.path.relpath(os.path.join(root, fn), target))
    elif os.path.isfile(target):
        cmd = ["tar", "tf", target]
        if target.endswith((".tgz", ".tar.gz")):
            cmd = ["tar", "tzf", target]
        elif target.endswith(".zst"):
            cmd = ["tar", "-I", "zstd", "-tf", target]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
            names = r.stdout.splitlines()
        except Exception as e:
            print("could not read %s: %s" % (target, e), file=sys.stderr)
            return 2
    else:
        print("no such target: %s" % target, file=sys.stderr)
        return 2

    hits = [n for n in names if VENDOR_SIGNS.search(n)]
    if hits:
        print("VENDOR ARTIFACTS PRESENT in %s -- must not ship:" % target)
        for h in hits[:15]:
            print("    " + h)
        if len(hits) > 15:
            print("    ... and %d more" % (len(hits) - 15))
        return 1
    print("clean: no vendor artifacts in %s" % target)
    return 0


# ------------------------------------------------------------------ CLI -----
def cmd_detect(a):
    c = detect_chassis()
    c["port_roles"] = port_roles(c["platform"])
    c["octeon"] = (PLATFORMS[c["platform"]]["octeon"]
                   if c["platform"] else None)
    if getattr(a, "json", False):
        # Machine-readable: the manager consumes this rather than
        # scraping the human output, which shifts whenever a field
        # is added.
        print(json.dumps(c, indent=2))
        return 0
    print("chassis platform : %s" % (c["platform"] or "unrecognised"))
    print("  PCI match      : %.0f%%" % (c["match"] * 100))
    print("  DMI product    : %s" % (c["dmi"] or "?"))
    print("  models         : %s" % (", ".join(c["models"]) or "-"))
    print("  igb            : %s" % " ".join(c["igb"]))
    print("  ixgbe          : %s" % " ".join(c["ixgbe"]))
    if c["platform"]:
        print("  expects        : %s" % PLATFORMS[c["platform"]]["octeon"])
    pr = port_roles(c["platform"])
    if pr:
        print("  port roles     :")
        for role in ("mgmt", "ha1-a", "ha1-b", "aux-1", "aux-2",
                     "backplane-0", "backplane-1"):
            r = pr.get(role)
            if not r:
                continue
            print("    %-7s %-10s %-14s link=%s"
                  % (role, r["iface"] or "(absent)", r["pci"],
                     "up" if r["carrier"] == "1" else "down"))
    return 0


def cmd_scan(a):
    ev = identify_source(a.source)
    arts = scan_source(a.source)
    print("source          : %s" % a.source)
    print("platform        : %s" % (ev["platform"] or "unidentified"))
    for w in ev["why"]:
        print("   - %s" % w)
    if not arts:
        print("no vendor artifacts found")
        return 1
    print("artifacts:")
    for x in arts:
        print("  %-8s %-38s %10d B  integrity=%s"
              % (x["kind"], os.path.basename(x["rel"])[:38], x["size"],
                 x["integrity"]))
    c = detect_chassis()
    if ev["platform"] and c["platform"] and ev["platform"] != c["platform"]:
        print("\nMISMATCH: media is %s, this chassis is %s -- import will refuse"
              % (ev["platform"], c["platform"]))
    return 0


def cmd_import(a):
    rc, imported = do_import(a.source, force=a.force)
    if rc == 0 and a.load:
        return do_load()
    return rc


def cmd_load(a):
    return do_load(a.kind)


def cmd_status(a):
    reg = read_registry()
    arts = reg.get("artifacts", [])
    c = detect_chassis()
    print("chassis   : %s" % (c["platform"] or "unrecognised"))
    print("vendor dir: %s   (local only, never packaged)" % VENDOR_DIR)
    if not arts:
        print("nothing registered")
        return 0
    for x in arts:
        flag = "  <-- PLATFORM MISMATCH" if x.get("platform_mismatch") else ""
        print("  %-8s %-30s %10d B  %s  %s%s"
              % (x["kind"], os.path.basename(x["file"]), x["size"],
                 x.get("platform") or "?", x.get("integrity"), flag))
    return 0


def cmd_forget(a):
    reg = read_registry()
    keep = []
    for x in reg.get("artifacts", []):
        if a.all or os.path.basename(x["file"]) == a.name:
            try:
                os.unlink(x["file"])
            except Exception:
                pass
            log("ffn-vendor: removed %s" % os.path.basename(x["file"]))
        else:
            keep.append(x)
    reg["artifacts"] = keep
    write_registry(reg)
    return 0


def cmd_check_clean(a):
    return check_clean(a.target)


def cmd_selftest(a):
    import tempfile
    global VENDOR_DIR
    fails = []

    def chk(c, m):
        print(("  ok   " if c else "  FAIL ") + m)
        if not c:
            fails.append(m)

    d = tempfile.mkdtemp(prefix="ffnvend")
    saved = VENDOR_DIR
    VENDOR_DIR = os.path.join(d, "vendor")
    try:
        # a fake PA-3200 media tree
        src = os.path.join(d, "media")
        os.makedirs(os.path.join(src, "boot/fpga"))
        os.makedirs(os.path.join(src, "etc/udev/rules.d"))
        os.makedirs(os.path.join(src, "etc/pan-manifest"))
        os.makedirs(os.path.join(src, "opt/dpfs/boot"))
        bit = os.path.join(src, "boot/fpga/ce10.bin")
        open(bit, "wb").write(b"BITSTREAM" * 100)
        open(os.path.join(src, "etc/udev/rules.d/70-net.rules"), "w").write(
            '# panos 32xx added rules by install scripts\n'
            'KERNELS=="0000:0d:00.0", DRIVERS=="igb", NAME="eth0"\n')
        open(os.path.join(src, "opt/dpfs/boot/u-boot-redtail_pciboot.bin"), "wb").write(b"UB")
        h = sha256_file(bit)
        open(os.path.join(src, "etc/pan-manifest/fpga-images"), "w").write(
            "%s */boot/fpga/ce10.bin\n" % h)

        ev = identify_source(src)
        chk(ev["platform"] == "redtail", "identifies redtail from installed udev rules")
        arts = scan_source(src)
        kinds = sorted({x["kind"] for x in arts})
        chk(kinds == ["fpga", "octeon"], "finds both artifact kinds (%s)" % kinds)
        f = [x for x in arts if x["kind"] == "fpga"][0]
        chk(f["integrity"] == "ok", "verifies bitstream against the vendor manifest")

        # corrupt it: integrity must fail and import must refuse
        open(bit, "ab").write(b"X")
        arts2 = scan_source(src)
        f2 = [x for x in arts2 if x["kind"] == "fpga"][0]
        chk(f2["integrity"] == "MISMATCH", "detects a corrupted bitstream")
        rc, imp = do_import(src, chassis={"platform": "redtail"})
        chk(all(i["kind"] != "fpga" for i in imp),
            "refuses to import the corrupted bitstream")

        # restore, then the safety property: wrong chassis must refuse
        open(bit, "wb").write(b"BITSTREAM" * 100)
        rc, imp = do_import(src, chassis={"platform": "gryphon"})
        chk(rc == 2 and not imp,
            "REFUSES redtail firmware on a gryphon chassis")
        rc, imp = do_import(src, chassis={"platform": "gryphon"}, force=True)
        chk(rc == 0 and imp and imp[0]["platform_mismatch"],
            "--force imports but records the mismatch")
        chk(do_load("fpga") == 2, "load SKIPS a mismatched artifact")

        # matching chassis works
        cmd_forget(argparse.Namespace(all=True, name=None))
        rc, imp = do_import(src, chassis={"platform": "redtail"})
        chk(rc == 0 and len(imp) == 2, "imports cleanly on a matching chassis")
        chk(os.path.isfile(os.path.join(VENDOR_DIR, "DO-NOT-PACKAGE")),
            "writes the DO-NOT-PACKAGE marker")

        # the build gate
        chk(check_clean(VENDOR_DIR) == 1, "check-clean FAILS a tree with vendor artifacts")
        clean = os.path.join(d, "clean"); os.makedirs(clean)
        open(os.path.join(clean, "ffn_manager.py"), "w").write("x")
        chk(check_clean(clean) == 0, "check-clean passes a clean tree")

        # chassis fingerprinting
        c = detect_chassis()
        chk(isinstance(c.get("match"), float), "chassis detection returns a match score")
    finally:
        VENDOR_DIR = saved
        shutil.rmtree(d, ignore_errors=True)

    print("\n==== ffn_vendor selftest: %d failed ====" % len(fails))
    return 1 if fails else 0


def main():
    ap = argparse.ArgumentParser(description="Use your own vendor firmware with FFN")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("detect")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_detect)

    p = sub.add_parser("scan"); p.add_argument("--source", required=True)
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser("import"); p.add_argument("--source", required=True)
    p.add_argument("--force", action="store_true",
                   help="import despite a platform mismatch (records it; load still skips)")
    p.add_argument("--load", action="store_true")
    p.set_defaults(func=cmd_import)

    p = sub.add_parser("load"); p.add_argument("--kind", choices=list(ARTIFACTS))
    p.set_defaults(func=cmd_load)

    sub.add_parser("status").set_defaults(func=cmd_status)

    p = sub.add_parser("forget"); p.add_argument("--name"); p.add_argument("--all", action="store_true")
    p.set_defaults(func=cmd_forget)

    p = sub.add_parser("check-clean"); p.add_argument("target")
    p.set_defaults(func=cmd_check_clean)

    sub.add_parser("selftest").set_defaults(func=cmd_selftest)

    a = ap.parse_args()
    sys.exit(a.func(a))


if __name__ == "__main__":
    main()
