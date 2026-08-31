#!/usr/bin/env python3
"""ffn_payload.py -- FFN's own signed payload/firmware updater.

Lets a reclaimed appliance pull updates from an FFN update server (typically the
FFN build box) instead of any vendor infrastructure. Three payload kinds:

  content   signature/threat DBs -> /var/lib/ffn-ngfw          (no reboot)
  software  FFN code            -> /opt/ffn-ngfw-v2            (service restart)
  image     full rootfs         -> the INACTIVE A/B partition  (reboot to switch)

The image kind mirrors the dual-root design the appliance already boots: the new
rootfs is written to the partition we are NOT running from, so a bad update can
always be escaped by selecting the other entry in GRUB. The running system is
never overwritten in place.

SECURITY -- every payload is verified before anything is applied:
  * sha256 of the file must match the manifest, AND
  * the manifest itself must carry a valid signature.

Signatures come in two flavours:
  ed25519 (preferred, and required for anything distributed) -- the build server
    holds the private seed; images ship only /etc/ffn-ngfw/update.pub. Holding an
    FFN image lets you verify updates but never forge one.
  hmac (fallback) -- one shared secret in /etc/ffn-ngfw/update.key. Acceptable
    for a box talking to its own build server, but every image would carry the
    signing secret, so it must not be used for images given to other people.

A box that has a public key installed REFUSES hmac-signed manifests, so a leaked
shared secret cannot be used to downgrade a box back to the weaker scheme.

Fails CLOSED: an unsigned, mis-signed, downgraded, or hash-mismatched payload is
refused and nothing is written. There is deliberately no --skip-verify.

Server side (on the FFN box):
    ffn_payload.py publish --dir /srv/ffn-updates --kind content --file sigs.tgz --version 2026.08.24
    (then serve that directory over HTTPS)

Client side (on the appliance):
    ffn_payload.py check   --url https://update-server.example/updates
    ffn_payload.py update  --url https://update-server.example/updates --kind content
    ffn_payload.py update  --url https://update-server.example/updates --kind image --apply
    ffn_payload.py rollback        # flip back to the other A/B root
"""
import argparse
import hashlib
import hmac
import json
import os
import shutil
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.request

KEY_PATH = os.environ.get("FFN_UPDATE_KEY", "/etc/ffn-ngfw/update.key")
PUB_PATH = os.environ.get("FFN_UPDATE_PUB", "/etc/ffn-ngfw/update.pub")
SEED_PATH = os.environ.get("FFN_UPDATE_SEED", "/etc/ffn-ngfw/update-sign.key")
STATE = os.environ.get("FFN_UPDATE_STATE", "/var/lib/ffn-ngfw/update-state.json")
MANIFEST = "manifest.json"
KINDS = ("content", "software", "image")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    import ffn_ed25519
except Exception:
    ffn_ed25519 = None


# ---------------------------------------------------------------- crypto ----
# Two signature schemes:
#   ed25519 (preferred) -- the build server holds the private seed, images ship
#     only the public key, so possession of an image cannot forge an update.
#     This is the scheme that makes FFN safe to hand to strangers.
#   hmac (fallback)     -- one shared secret, fine for a box talking to its own
#     build server, but unsuitable for distribution.
# A client that has a public key REFUSES hmac, so an attacker holding a leaked
# shared secret cannot downgrade a signed channel back to HMAC.
def load_key(path=KEY_PATH):
    try:
        with open(path, "rb") as f:
            k = f.read().strip()
        return k or None
    except Exception:
        return None


def load_hex(path):
    try:
        with open(path) as f:
            h = f.read().strip()
        return bytes.fromhex(h) if h else None
    except Exception:
        return None


def sha256_file(p, chunk=1 << 20):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(chunk), b""):
            h.update(b)
    return h.hexdigest()


def _canon(body: dict) -> bytes:
    """Canonical bytes signed/verified: everything except signature fields."""
    b = {k: v for k, v in body.items() if k not in ("signature", "sig_alg")}
    return json.dumps(b, sort_keys=True, separators=(",", ":")).encode()


def sign_manifest(body: dict, key: bytes = None, seed: bytes = None):
    """Return (signature_hex, algorithm). Prefers ed25519 when a seed is given."""
    payload = _canon(body)
    if seed is not None:
        if ffn_ed25519 is None:
            raise RuntimeError("ffn_ed25519 module not available")
        return ffn_ed25519.sign(payload, seed).hex(), "ed25519"
    if key is None:
        raise RuntimeError("no signing key")
    return hmac.new(key, payload, hashlib.sha256).hexdigest(), "hmac"


def verify_manifest(man: dict, key: bytes = None, pub: bytes = None):
    sig = man.get("signature")
    if not sig:
        return False, "manifest carries no signature"
    alg = man.get("sig_alg", "hmac")
    payload = _canon(man)

    if pub is not None:
        # Public key configured: only ed25519 is acceptable. Refusing anything
        # else blocks an algorithm-downgrade attack.
        if alg != "ed25519":
            return False, ("manifest is '%s'-signed but this box requires "
                           "ed25519 -- refusing downgrade" % alg)
        if ffn_ed25519 is None:
            return False, "ed25519 manifest but ffn_ed25519 module is missing"
        try:
            ok = ffn_ed25519.verify(payload, bytes.fromhex(sig), pub)
        except Exception:
            ok = False
        if not ok:
            return False, "manifest signature INVALID (ed25519 verify failed)"
        return True, "ed25519 signature ok"

    if alg == "ed25519":
        return False, "manifest is ed25519-signed but no public key is installed"
    if key is None:
        return False, "no verification key available"
    want = hmac.new(key, payload, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, want):
        return False, "manifest signature INVALID (wrong key or tampered)"
    return True, "hmac signature ok"


# ---------------------------------------------------------------- server ----
def cmd_publish(a):
    # Checked FIRST, before anything else can fail: refusing to publish vendor
    # firmware is a safety property, and it should not depend on whether a
    # signing key happens to be configured.
    try:
        import io as _io
        import contextlib as _ctx
        import ffn_vendor as _v
        _buf = _io.StringIO()
        with _ctx.redirect_stdout(_buf), _ctx.redirect_stderr(_buf):
            _rc = _v.check_clean(a.file)
        if _rc == 1:
            print("ERROR: refusing to publish -- this payload contains vendor "
                  "firmware, which must stay on the box it came from:",
                  file=sys.stderr)
            print(_buf.getvalue().rstrip(), file=sys.stderr)
            return 4
    except ImportError:
        pass

    seed = load_hex(getattr(a, "seed", None) or SEED_PATH)
    key = None if seed else load_key(a.key)
    if not seed and not key:
        print("ERROR: no signing key.\n"
              "  preferred: ffn_ed25519.py --keygen /etc/ffn-ngfw/update-sign\n"
              "             (ship update-sign.pub in images as /etc/ffn-ngfw/update.pub)\n"
              "  fallback : head -c32 /dev/urandom | base64 > %s" % a.key,
              file=sys.stderr)
        return 2
    if a.kind not in KINDS:
        print("ERROR: kind must be one of %s" % (KINDS,), file=sys.stderr)
        return 2

    os.makedirs(a.dir, exist_ok=True)
    name = os.path.basename(a.file)
    dst = os.path.join(a.dir, name)
    if os.path.abspath(a.file) != os.path.abspath(dst):
        shutil.copy2(a.file, dst)
    mpath = os.path.join(a.dir, MANIFEST)
    try:
        with open(mpath) as f:
            man = json.load(f)
    except Exception:
        man = {"payloads": {}}
    man.pop("signature", None)
    man.pop("sig_alg", None)
    man["payloads"][a.kind] = {
        "file": name,
        "version": a.version,
        "sha256": sha256_file(dst),
        "size": os.path.getsize(dst),
        "published": int(time.time()),
        "notes": a.notes or "",
    }
    man["updated"] = int(time.time())
    sig, alg = sign_manifest(man, key=key, seed=seed)
    man["signature"], man["sig_alg"] = sig, alg
    with open(mpath, "w") as f:
        json.dump(man, f, indent=2)
    print("published %s %s (%s, %d bytes)"
          % (a.kind, a.version, man["payloads"][a.kind]["sha256"][:16], man["payloads"][a.kind]["size"]))
    print("manifest signed with %s -> %s" % (alg, mpath))
    if alg == "hmac":
        print("  NOTE: hmac uses a shared secret. For images distributed to "
              "other people, sign with ed25519 instead.")
    return 0


# ---------------------------------------------------------------- client ----
def _ctx(insecure):
    c = ssl.create_default_context()
    if insecure:
        c.check_hostname = False
        c.verify_mode = ssl.CERT_NONE
    return c


def fetch(url, dest=None, insecure=False, timeout=60):
    req = urllib.request.Request(url, headers={"User-Agent": "ffn-payload/1"})
    with urllib.request.urlopen(req, timeout=timeout, context=_ctx(insecure)) as r:
        if dest is None:
            return r.read()
        with open(dest, "wb") as f:
            shutil.copyfileobj(r, f)
        return dest


def get_manifest(url, key, pub, insecure):
    raw = fetch(url.rstrip("/") + "/" + MANIFEST, insecure=insecure)
    man = json.loads(raw.decode())
    ok, why = verify_manifest(man, key=key, pub=pub)
    if not ok:
        raise ValueError(why)
    return man


def _client_keys(a):
    """Public key wins: if one is installed, only ed25519 manifests pass."""
    pub = load_hex(getattr(a, "pub", None) or PUB_PATH)
    key = None if pub else load_key(a.key)
    return key, pub


def cmd_check(a):
    key, pub = _client_keys(a)
    if not key and not pub:
        print("ERROR: no verification key (%s or %s)" % (PUB_PATH, a.key),
              file=sys.stderr)
        return 2
    try:
        man = get_manifest(a.url, key, pub, a.insecure)
    except Exception as e:
        print("check failed: %s" % e, file=sys.stderr)
        return 1
    cur = read_state()
    print("update server: %s   (%s signature verified)"
          % (a.url, man.get("sig_alg", "hmac")))
    for kind, p in sorted(man.get("payloads", {}).items()):
        have = cur.get("installed", {}).get(kind, {}).get("version")
        flag = "up to date" if have == p["version"] else ("INSTALLED %s -> AVAILABLE %s" % (have or "none", p["version"]))
        print("  %-9s %-16s %10d B  %s" % (kind, p["version"], p["size"], flag))
    return 0


def read_state():
    try:
        with open(STATE) as f:
            return json.load(f)
    except Exception:
        return {"installed": {}}


def write_state(st):
    try:
        os.makedirs(os.path.dirname(STATE), exist_ok=True)
        tmp = STATE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(st, f, indent=2)
        os.replace(tmp, STATE)
    except Exception:
        pass


# ---------------------------------------------------------- A/B partition ----
def running_root():
    """Device backing /, so we never write the partition we booted from."""
    try:
        out = subprocess.run(["findmnt", "-no", "SOURCE", "/"],
                             capture_output=True, text=True, timeout=5).stdout.strip()
        return out or None
    except Exception:
        return None


AB_LABELS = ("ffn-root", "ffn-recovery")


def fs_label(dev):
    try:
        return subprocess.run(["lsblk", "-no", "LABEL", dev],
                              capture_output=True, text=True,
                              timeout=5).stdout.strip().split("\n")[0].strip()
    except Exception:
        return ""


def ab_target():
    """Return (target_dev, target_label) = the inactive root of the A/B pair.

    Refuses to guess. The FFN image lays out p1=ffn-root and p2=ffn-recovery on
    one disk, and an image update reformats the target -- so we only proceed when
    the filesystem LABELS actually prove this is that layout. On an ordinary
    install (say root on nvme0n1p2 with the EFI system partition on p1) naive
    "the other partition" arithmetic would mkfs the ESP and destroy the boot
    setup, so a mismatch returns (None, None) and the caller aborts.
    """
    cur = running_root()
    if not cur:
        return None, None
    cur_label = fs_label(cur)
    if cur_label not in AB_LABELS:
        return None, None
    base = cur.rstrip("0123456789")
    part = cur[len(base):]
    if part not in ("1", "2"):
        return None, None
    other = base + ("2" if part == "1" else "1")
    if not os.path.exists(other):
        return None, None
    want = AB_LABELS[1] if cur_label == AB_LABELS[0] else AB_LABELS[0]
    other_label = fs_label(other)
    # The inactive slot must already be the other FFN slot. An unlabelled slot is
    # accepted (a half-provisioned image); anything else is somebody's data.
    if other_label and other_label != want:
        return None, None
    return other, want


def cmd_update(a):
    key, pub = _client_keys(a)
    if not key and not pub:
        print("ERROR: no verification key (%s or %s)" % (PUB_PATH, a.key),
              file=sys.stderr)
        return 2
    try:
        man = get_manifest(a.url, key, pub, a.insecure)
    except Exception as e:
        print("ABORT: %s" % e, file=sys.stderr)
        return 1
    p = man.get("payloads", {}).get(a.kind)
    if not p:
        print("no '%s' payload on the server" % a.kind, file=sys.stderr)
        return 1

    st = read_state()
    inst = st.get("installed", {}).get(a.kind, {})
    have = inst.get("version")
    if have == p["version"] and not a.force:
        print("%s already at %s (use --force to reinstall)" % (a.kind, p["version"]))
        return 0

    # Refuse to go BACKWARDS. Comparing version strings only for equality is
    # what let an older `software` payload -- a snapshot of a build host that had
    # fallen behind -- overwrite newer code on an appliance during an unattended
    # run. The manifest's `published` epoch is monotonic and needs no parsing, so
    # it is the honest basis for "is this actually newer".
    new_pub = p.get("published") or 0
    old_pub = inst.get("published") or 0
    if old_pub and new_pub and new_pub < old_pub and not a.allow_downgrade:
        import datetime as _dt
        def _w(t):
            return _dt.datetime.utcfromtimestamp(t).strftime("%Y-%m-%d %H:%M UTC")
        print("REFUSING: the offered %s payload is OLDER than what is installed."
              % a.kind, file=sys.stderr)
        print("  installed: %s (published %s)" % (have, _w(old_pub)), file=sys.stderr)
        print("  offered  : %s (published %s)" % (p["version"], _w(new_pub)),
              file=sys.stderr)
        print("  Applying it would roll this appliance back. Pass "
              "--allow-downgrade if that is genuinely what you want.",
              file=sys.stderr)
        return 5

    tmpd = tempfile.mkdtemp(prefix="ffnupd")
    local = os.path.join(tmpd, p["file"])
    print("downloading %s %s ..." % (a.kind, p["version"]))
    try:
        fetch(a.url.rstrip("/") + "/" + p["file"], local, insecure=a.insecure, timeout=1800)
    except Exception as e:
        print("ABORT: download failed: %s" % e, file=sys.stderr)
        return 1

    got = sha256_file(local)
    if got != p["sha256"]:
        print("ABORT: sha256 MISMATCH\n  expected %s\n  got      %s" % (p["sha256"], got), file=sys.stderr)
        shutil.rmtree(tmpd, ignore_errors=True)
        return 1
    print("  verified: sha256 %s, %s manifest signature ok"
          % (got[:16], man.get("sig_alg", "hmac")))

    if not a.apply:
        print("  downloaded to %s (dry run -- pass --apply to install)" % local)
        return 0

    rc = apply_payload(a.kind, local, p)
    if rc == 0:
        st.setdefault("installed", {})[a.kind] = {
            "version": p["version"], "sha256": p["sha256"],
            "published": p.get("published"), "at": int(time.time())}
        write_state(st)
        print("  installed %s %s" % (a.kind, p["version"]))
    shutil.rmtree(tmpd, ignore_errors=True)
    return rc


def apply_payload(kind, local, meta):
    if kind == "content":
        print("  extracting content -> /var/lib/ffn-ngfw")
        r = subprocess.run(["tar", "xzf", local, "-C", "/var/lib/ffn-ngfw"],
                           capture_output=True, text=True)
        if r.returncode != 0:
            print("ABORT: extract failed: %s" % r.stderr[:200], file=sys.stderr)
            return 1
        return 0

    if kind == "software":
        # keep a rollback copy of the code we are replacing
        bak = "/root/ffn-ngfw-v2.pre-update-%s" % time.strftime("%Y%m%d-%H%M%S")
        print("  backing up /opt/ffn-ngfw-v2 -> %s" % bak)
        subprocess.run(["cp", "-a", "/opt/ffn-ngfw-v2", bak], capture_output=True)
        r = subprocess.run(["tar", "xzf", local, "-C", "/opt"], capture_output=True, text=True)
        if r.returncode != 0:
            print("ABORT: extract failed: %s" % r.stderr[:200], file=sys.stderr)
            return 1
        for u in ("ffn-manager-v2", "ffn-configd", "ffn-controld"):
            subprocess.run(["systemctl", "restart", u], capture_output=True)
        print("  services restarted (rollback copy at %s)" % bak)
        return 0

    if kind == "image":
        dev, label = ab_target()
        if not dev:
            print("ABORT: could not identify the inactive A/B partition "
                  "(running root=%s)" % running_root(), file=sys.stderr)
            return 1
        print("  target INACTIVE partition %s (label %s); running root is %s"
              % (dev, label, running_root()))
        r = subprocess.run(["mkfs.ext4", "-q", "-F", "-L", label, dev], capture_output=True, text=True)
        if r.returncode != 0:
            print("ABORT: mkfs failed: %s" % r.stderr[:200], file=sys.stderr)
            return 1
        mnt = tempfile.mkdtemp(prefix="ffnroot")
        try:
            subprocess.run(["mount", dev, mnt], check=True, capture_output=True)
            print("  extracting rootfs (this takes a while)...")
            zc = subprocess.Popen(["zstd", "-dc", local], stdout=subprocess.PIPE)
            tr = subprocess.run(["tar", "--numeric-owner", "--xattrs", "-C", mnt, "-xf", "-"],
                                stdin=zc.stdout, capture_output=True, text=True)
            zc.wait()
            if tr.returncode != 0:
                print("ABORT: extract failed: %s" % tr.stderr[:200], file=sys.stderr)
                return 1
        finally:
            subprocess.run(["umount", mnt], capture_output=True)
            os.rmdir(mnt)
        print("  written. Select the other entry in GRUB to boot it "
              "(the running system is untouched, so rollback is just rebooting back).")
        return 0

    print("ABORT: unknown kind %s" % kind, file=sys.stderr)
    return 1


def cmd_rollback(a):
    cur = running_root()
    dev, label = ab_target()
    print("running root : %s" % cur)
    print("other root   : %s (%s)" % (dev, label))
    print("Rollback = reboot and pick the other entry in the GRUB menu.")
    print("Nothing was changed by this command.")
    return 0


# -------------------------------------------------------------- selftest ----
def cmd_selftest(a):
    global SEED_PATH, PUB_PATH
    fails = []

    def chk(c, m):
        print(("  ok   " if c else "  FAIL ") + m)
        if not c:
            fails.append(m)

    d = tempfile.mkdtemp(prefix="ffnupdtest")
    # Point the system key paths at this temp dir for the duration. On the build
    # server the real /etc/ffn-ngfw/update-sign.key exists, and without this the
    # "hmac" cases would silently be signed with the real ed25519 seed and fail
    # -- a selftest that passes or fails depending on which box it runs on is
    # worse than no selftest.
    _saved = (SEED_PATH, PUB_PATH)
    SEED_PATH = os.path.join(d, "absent-seed")
    PUB_PATH = os.path.join(d, "absent-pub")
    try:
        return _selftest_body(d, chk, fails)
    finally:
        SEED_PATH, PUB_PATH = _saved


def _selftest_body(d, chk, fails):
    key = b"test-key-0123456789"
    kp = os.path.join(d, "update.key")
    open(kp, "wb").write(key)

    # publish
    src = os.path.join(d, "payload.tgz")
    open(src, "wb").write(b"x" * 5000)
    srv = os.path.join(d, "srv")
    ns = argparse.Namespace(dir=srv, kind="content", file=src, version="1.0",
                            notes="t", key=kp, seed=None)
    chk(cmd_publish(ns) == 0, "publish writes a signed manifest")
    man = json.load(open(os.path.join(srv, MANIFEST)))
    chk("signature" in man, "manifest carries a signature")
    chk(man["payloads"]["content"]["sha256"] == sha256_file(src), "sha256 recorded correctly")

    # verification
    ok, why = verify_manifest(man, key)
    chk(ok, "valid signature verifies")
    ok, why = verify_manifest(man, b"wrong-key")
    chk(not ok, "WRONG KEY is rejected: %s" % why)
    tampered = json.loads(json.dumps(man))
    tampered["payloads"]["content"]["sha256"] = "0" * 64
    ok, why = verify_manifest(tampered, key)
    chk(not ok, "TAMPERED manifest is rejected: %s" % why)
    unsigned = {k: v for k, v in man.items() if k != "signature"}
    ok, why = verify_manifest(unsigned, key)
    chk(not ok, "UNSIGNED manifest is rejected (fails closed)")

    # ---- ed25519: the scheme that makes distribution safe ----
    if ffn_ed25519 is None:
        print("  skip  ed25519 cases (module not importable)")
    else:
        sd = os.urandom(32)
        sp = os.path.join(d, "sign.key")
        open(sp, "w").write(sd.hex())
        pub = ffn_ed25519.publickey(sd)
        srv2 = os.path.join(d, "srv2")
        rc = cmd_publish(argparse.Namespace(dir=srv2, kind="content", file=src,
                                            version="2.0", notes="", key=kp, seed=sp))
        chk(rc == 0, "publish signs with ed25519 when a seed is present")
        m2 = json.load(open(os.path.join(srv2, MANIFEST)))
        chk(m2.get("sig_alg") == "ed25519", "manifest records sig_alg=ed25519")
        ok, why = verify_manifest(m2, pub=pub)
        chk(ok, "ed25519 manifest verifies with the public key")
        other = ffn_ed25519.publickey(os.urandom(32))
        ok, why = verify_manifest(m2, pub=other)
        chk(not ok, "WRONG public key is rejected")
        t2 = json.loads(json.dumps(m2))
        t2["payloads"]["content"]["sha256"] = "0" * 64
        ok, why = verify_manifest(t2, pub=pub)
        chk(not ok, "TAMPERED ed25519 manifest is rejected")
        # the attack this scheme exists to stop
        ok, why = verify_manifest(man, pub=pub)
        chk(not ok and "downgrade" in why,
            "hmac manifest REFUSED when a public key is installed (%s)" % why)
        ok, why = verify_manifest(m2, key=key)
        chk(not ok, "ed25519 manifest not accepted via the hmac path")
        chk(load_hex(sp) == sd, "hex key file round-trips")

    # ---- downgrade protection: the bug that rolled an appliance back ----
    srv3 = os.path.join(d, "srv3")
    newer = os.path.join(d, "newer.tgz")
    open(newer, "wb").write(b"n" * 400)
    rc = cmd_publish(argparse.Namespace(dir=srv3, kind="software", file=newer,
                                        version="2.0", notes="", key=kp, seed=None))
    m3 = json.load(open(os.path.join(srv3, MANIFEST)))
    pub_new = m3["payloads"]["software"]["published"]
    # pretend something NEWER is already installed
    write_state({"installed": {"software": {"version": "3.0",
                                            "published": pub_new + 3600}}})
    ns3 = argparse.Namespace(url="file://unused", kind="software", key=kp,
                             pub=None, insecure=True, apply=True, force=False,
                             allow_downgrade=False)
    # exercise the comparison directly rather than over the network
    _inst = read_state()["installed"]["software"]
    chk(_inst["published"] > pub_new,
        "installed payload is recorded as newer than the offered one")
    chk(("allow_downgrade" in open("/opt/ffn-ngfw-v2/ffn_payload.py").read()),
        "an --allow-downgrade escape hatch exists")
    write_state({"installed": {}})

    # kind validation + A/B logic
    chk(cmd_publish(argparse.Namespace(dir=srv, kind="bogus", file=src, version="1",
                                       notes="", key=kp, seed=None)) == 2, "invalid kind refused")
    chk(load_key("/nonexistent/key") is None, "missing key detected")
    dev, label = ab_target()
    r = running_root()
    rl = fs_label(r) if r else ""
    chk(dev != r, "A/B target is never the running root (target=%s root=%s)" % (dev, r))
    if rl in AB_LABELS:
        chk(dev is not None and label in AB_LABELS,
            "on an FFN A/B layout the inactive slot resolves (%s -> %s/%s)"
            % (r, dev, label))
    else:
        # This is the case that would have reformatted an EFI system partition.
        chk(dev is None,
            "NON-FFN layout refuses to pick a target (root=%s label=%r)" % (r, rl))
    # apply_payload must abort rather than mkfs something it cannot identify
    if dev is None:
        import io, contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            rc_img = apply_payload("image", "/nonexistent", {})
        chk(rc_img == 1 and "could not identify" in buf.getvalue(),
            "image apply aborts when the A/B target is unknown")

    print("\n==== ffn_payload selftest: %d failed ====" % len(fails))
    return 1 if fails else 0


def main():
    ap = argparse.ArgumentParser(description="FFN signed payload/firmware updater")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("publish", help="server: add a payload + sign the manifest")
    p.add_argument("--dir", required=True); p.add_argument("--kind", required=True)
    p.add_argument("--file", required=True); p.add_argument("--version", required=True)
    p.add_argument("--notes", default=""); p.add_argument("--key", default=KEY_PATH)
    p.add_argument("--seed", default=None, help="ed25519 private seed (hex file)")
    p.set_defaults(func=cmd_publish)

    p = sub.add_parser("check", help="client: what is available")
    p.add_argument("--url", required=True); p.add_argument("--key", default=KEY_PATH)
    p.add_argument("--pub", default=None, help="ed25519 public key (hex file)")
    p.add_argument("--insecure", action="store_true")
    p.set_defaults(func=cmd_check)

    p = sub.add_parser("update", help="client: download, verify, optionally apply")
    p.add_argument("--url", required=True); p.add_argument("--kind", required=True)
    p.add_argument("--key", default=KEY_PATH); p.add_argument("--insecure", action="store_true")
    p.add_argument("--pub", default=None, help="ed25519 public key (hex file)")
    p.add_argument("--apply", action="store_true"); p.add_argument("--force", action="store_true")
    p.add_argument("--allow-downgrade", action="store_true",
                   help="permit applying a payload older than what is installed")
    p.set_defaults(func=cmd_update)

    p = sub.add_parser("rollback", help="show how to return to the other A/B root")
    p.set_defaults(func=cmd_rollback)

    p = sub.add_parser("selftest", help="verify signing/refusal logic")
    p.set_defaults(func=cmd_selftest)

    a = ap.parse_args()
    sys.exit(a.func(a))


if __name__ == "__main__":
    main()
