#!/usr/bin/env python3
"""ffn_updated.py -- unattended firmware updates that roll themselves back.

The appliance checks the FFN update server on a timer and applies what policy
allows. The interesting part is the image path, because a firmware update that
can brick a remote box is worse than no firmware update at all.

HOW A FIRMWARE UPDATE LANDS WITHOUT RISKING THE BOX
---------------------------------------------------
  1. WRITE   the new rootfs goes to the INACTIVE A/B slot. The running system is
             never touched, so at this point nothing can have broken.
  2. ARM     grub-reboot sets a ONE-SHOT boot into the new slot. The saved
             default still points at the slot we know works.
  3. REBOOT  (only if policy allows it, otherwise it waits for a human).
  4. CONFIRM on the new slot, ffn-update-confirm runs health checks. Healthy ->
             grub-set-default commits the new slot. Unhealthy, kernel panic,
             failed mount, no boot at all -> the one-shot is already spent, so
             the NEXT boot returns to the old slot on its own.

The asymmetry is deliberate: committing takes a positive act, and rolling back
takes nothing at all. A box that dies mid-update recovers by power-cycling,
which is the only thing you can do to a appliance you cannot reach.

PREREQUISITE: this needs GRUB_DEFAULT=saved. With GRUB_DEFAULT=0 (the default)
grub-reboot writes a next_entry that GRUB then ignores, so the "one-shot" would
silently never happen and a bad image would become permanent. `arm` refuses
unless that is configured, and `setup-grub` fixes it.

    ffn_updated.py status
    ffn_updated.py setup-grub [--force]     # make one-shot boot possible
    ffn_updated.py check
    ffn_updated.py run [--force]            # apply what policy allows
    ffn_updated.py arm --slot <n> [--force] # one-shot boot into a slot
    ffn_updated.py confirm                  # post-boot health commit/rollback
    ffn_updated.py selftest
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.request

POLICY = os.environ.get("FFN_UPDATE_POLICY", "/etc/ffn-ngfw/update-policy.conf")
STATE = os.environ.get("FFN_UPDATE_AGENT_STATE",
                       "/var/lib/ffn-ngfw/update-agent.json")
PAYLOAD_CLI = "/opt/ffn-ngfw-v2/ffn_payload.py"
GRUB_DEFAULTS = "/etc/default/grub"
GRUB_CFG = "/boot/grub/grub.cfg"

DEFAULT_POLICY = {
    # content is data, applies live, and is trivially reversible -- safe to
    # take unattended.
    "auto_content": "yes",
    # software restarts services and keeps a rollback copy. Default on, but a
    # cautious operator may want to stage it.
    "auto_software": "yes",
    # image WRITES the inactive slot unattended (harmless -- nothing running is
    # touched) but does NOT switch to it by default. Switching is a reboot.
    "auto_image_write": "yes",
    "auto_image_arm": "no",
    # rebooting a firewall on its own initiative is a real decision. Off.
    "auto_reboot": "no",
    # how long the new slot has to prove itself before we call it bad
    "confirm_timeout": "300",
}


def log(msg):
    print(msg)
    try:
        subprocess.run(["logger", "-t", "ffn-updated", msg], timeout=2,
                       capture_output=True)
    except Exception:
        pass


def policy():
    p = dict(DEFAULT_POLICY)
    try:
        with open(POLICY) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    p[k.strip()] = v.strip()
    except Exception:
        pass
    return p


def yes(v):
    return str(v).strip().lower() in ("1", "yes", "true", "on")


def state():
    try:
        with open(STATE) as f:
            return json.load(f)
    except Exception:
        return {}


def save_state(st):
    try:
        os.makedirs(os.path.dirname(STATE), exist_ok=True)
        tmp = STATE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(st, f, indent=2)
        os.replace(tmp, STATE)
    except Exception as e:
        log("could not save state: %s" % e)


def run(cmd, timeout=60):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, (r.stdout or "") + (r.stderr or "")
    except Exception as e:
        return -1, str(e)


# ------------------------------------------------------------- A/B slots ----
def running_root():
    rc, out = run(["findmnt", "-no", "SOURCE", "/"], 10)
    return out.strip() if rc == 0 else ""


def slots():
    """The two A/B roots, identified by LABEL rather than partition number.

    Labels are the only reliable discriminator: on an ordinary install p1 is the
    EFI partition, and 'the other partition' arithmetic would target that.
    """
    out = []
    rc, txt = run(["lsblk", "-lno", "NAME,LABEL,PATH"], 15)
    if rc != 0:
        return out
    for line in txt.splitlines():
        f = line.split()
        if len(f) >= 3 and f[1] in ("ffn-root", "ffn-recovery"):
            out.append({"dev": f[2], "label": f[1]})
    return out


def grub_entries():
    """Top-level GRUB menu entries, in index order. Submenus count as one
    entry, which is what grub-reboot's numbering expects."""
    ents = []
    try:
        with open(GRUB_CFG, errors="replace") as f:
            depth = 0
            for line in f:
                s = line.strip()
                if s.startswith("menuentry ") and depth == 0:
                    m = re.match(r"menuentry\s+['\"]([^'\"]+)", s)
                    ents.append(m.group(1) if m else "(unnamed)")
                elif s.startswith("submenu ") and depth == 0:
                    m = re.match(r"submenu\s+['\"]([^'\"]+)", s)
                    ents.append((m.group(1) if m else "(submenu)") + " [submenu]")
                    depth += 1
                elif depth and s == "}":
                    depth -= 1
                elif s.endswith("{") and depth:
                    depth += 1
    except Exception:
        pass
    return ents


def grub_saved_default_ok():
    """True when GRUB is configured so a one-shot boot actually works."""
    try:
        with open(GRUB_DEFAULTS) as f:
            txt = f.read()
    except Exception:
        return False, "cannot read %s" % GRUB_DEFAULTS
    m = re.search(r"^GRUB_DEFAULT=(.*)$", txt, re.M)
    val = (m.group(1).strip().strip('"').strip("'") if m else "")
    if val != "saved":
        return False, ("GRUB_DEFAULT=%r -- grub-reboot's one-shot is IGNORED "
                       "unless it is 'saved', so a bad image would become "
                       "permanent" % val)
    return True, "GRUB_DEFAULT=saved"


def cmd_setup_grub(a):
    ok, why = grub_saved_default_ok()
    if ok:
        log("grub already set up for one-shot boot (%s)" % why)
        return 0
    log("grub needs GRUB_DEFAULT=saved: %s" % why)
    if not a.force:
        log("DRY-RUN: would set GRUB_DEFAULT=saved, GRUB_SAVEDEFAULT=false and "
            "run grub-mkconfig. Re-run with --force.")
        return 0
    try:
        with open(GRUB_DEFAULTS) as f:
            txt = f.read()
        shutil.copy2(GRUB_DEFAULTS, GRUB_DEFAULTS + ".bak-ffnupd")
        if re.search(r"^GRUB_DEFAULT=", txt, re.M):
            txt = re.sub(r"^GRUB_DEFAULT=.*$", "GRUB_DEFAULT=saved", txt,
                         count=1, flags=re.M)
        else:
            txt += "\nGRUB_DEFAULT=saved\n"
        # We want explicit control of what the default is, not "whatever booted
        # last" -- otherwise a one-shot boot would silently become the default.
        if re.search(r"^GRUB_SAVEDEFAULT=", txt, re.M):
            txt = re.sub(r"^GRUB_SAVEDEFAULT=.*$", "GRUB_SAVEDEFAULT=false",
                         txt, count=1, flags=re.M)
        else:
            txt += "GRUB_SAVEDEFAULT=false\n"
        with open(GRUB_DEFAULTS, "w") as f:
            f.write(txt)
    except Exception as e:
        log("could not edit %s: %s" % (GRUB_DEFAULTS, e))
        return 1

    rc, out = run(["grub-mkconfig", "-o", GRUB_CFG], 180)
    if rc != 0:
        log("grub-mkconfig FAILED: %s" % out[-300:])
        return 1
    # Pin the saved default to the slot we are running now -- the known-good one.
    cur = current_entry_index()
    if cur is not None:
        run(["grub-set-default", str(cur)], 30)
        log("saved default pinned to entry %d (the running slot)" % cur)
    log("grub set up for one-shot boot")
    return 0


def current_entry_index():
    """Best-effort index of the menu entry matching the running root."""
    root = running_root()
    if not root:
        return None
    # find the label of the running root, then the entry naming that slot
    lbl = ""
    rc, out = run(["lsblk", "-no", "LABEL", root], 10)
    if rc == 0:
        lbl = out.strip().splitlines()[0].strip() if out.strip() else ""
    ents = grub_entries()
    for i, e in enumerate(ents):
        if lbl == "ffn-recovery" and "Recovery" in e:
            return i
        if lbl == "ffn-root" and "Recovery" not in e and "submenu" not in e:
            return i
    return 0 if ents else None


def inactive_slot_entry():
    """(entry_index, label) of the slot we are NOT running, or (None, None)."""
    root = running_root()
    rc, out = run(["lsblk", "-no", "LABEL", root], 10) if root else (1, "")
    cur_lbl = out.strip().splitlines()[0].strip() if rc == 0 and out.strip() else ""
    if cur_lbl not in ("ffn-root", "ffn-recovery"):
        return None, None
    want = "ffn-recovery" if cur_lbl == "ffn-root" else "ffn-root"
    ents = grub_entries()
    for i, e in enumerate(ents):
        if want == "ffn-recovery" and "Recovery" in e:
            return i, want
        if want == "ffn-root" and "Recovery" not in e and "submenu" not in e:
            return i, want
    return None, want


# ---------------------------------------------------------------- health ----
def health(timeout=20):
    """Is this appliance actually working? Used to decide commit vs rollback.

    Deliberately checks that the management plane ANSWERS, not merely that a
    process exists -- a manager that starts and then wedges is exactly the
    failure an unattended update must catch.
    """
    checks = {}
    rc, _ = run(["systemctl", "is-active", "--quiet", "ffn-manager-v2"], 15)
    checks["manager_active"] = (rc == 0)

    api = False
    try:
        import ssl as _ssl
        ctx = _ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = _ssl.CERT_NONE
        req = urllib.request.Request("https://127.0.0.1:8443/api/system/status")
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            api = r.status in (200, 401, 403)   # answering at all is the point
    except Exception:
        api = False
    checks["api_responds"] = api

    root = running_root()
    checks["root_mounted"] = bool(root)

    rc, out = run(["findmnt", "-no", "TARGET", "/"], 10)
    checks["rootfs_rw"] = True
    try:
        p = "/var/lib/ffn-ngfw/.wtest"
        with open(p, "w") as f:
            f.write("x")
        os.unlink(p)
    except Exception:
        checks["rootfs_rw"] = False

    checks["ok"] = all(v for k, v in checks.items() if k != "ok")
    return checks


# ------------------------------------------------------------------ flow ----
def payload_check(url, insecure=True):
    a = ["python3", PAYLOAD_CLI, "check", "--url", url]
    if insecure:
        a.append("--insecure")
    return run(a, 120)


def payload_update(url, kind, apply_it, insecure=True, force=False):
    a = ["python3", PAYLOAD_CLI, "update", "--url", url, "--kind", kind]
    if insecure:
        a.append("--insecure")
    if apply_it:
        a.append("--apply")
    if force:
        a.append("--force")
    return run(a, 3600 if kind == "image" else 600)


def server_url():
    try:
        with open("/etc/ffn-ngfw/update-server.conf") as f:
            for line in f:
                if line.strip().startswith("url="):
                    return line.strip()[4:]
    except Exception:
        pass
    return ""


def cmd_check(a):
    url = a.url or server_url()
    if not url:
        log("no update server configured")
        return 2
    rc, out = payload_check(url)
    print(out.strip())
    return 0 if rc == 0 else 1


def cmd_run(a):
    """Apply what policy allows. Never switches slots or reboots on its own
    unless policy explicitly says so."""
    p = policy()
    url = a.url or server_url()
    if not url:
        log("no update server configured")
        return 2

    st = state()
    st["last_run"] = int(time.time())
    applied = []

    for kind, gate in (("content", "auto_content"), ("software", "auto_software")):
        if not yes(p.get(gate)):
            log("%s: policy says no (%s=%s)" % (kind, gate, p.get(gate)))
            continue
        rc, out = payload_update(url, kind, apply_it=a.force)
        tail = out.strip().splitlines()[-1] if out.strip() else ""
        log("%s: %s" % (kind, tail or ("rc=%d" % rc)))
        if rc == 0 and a.force:
            applied.append(kind)

    # --- image: writing is safe, switching is not -------------------------
    if yes(p.get("auto_image_write")):
        rc, out = payload_update(url, "image", apply_it=a.force)
        tail = out.strip().splitlines()[-1] if out.strip() else ""
        log("image: %s" % (tail or ("rc=%d" % rc)))
        if rc == 0 and a.force:
            applied.append("image-written")
            if yes(p.get("auto_image_arm")):
                idx, lbl = inactive_slot_entry()
                if idx is None:
                    log("image armed: SKIPPED -- could not identify the inactive slot")
                else:
                    r = do_arm(idx, lbl, force=a.force)
                    if r == 0:
                        applied.append("image-armed")
                        if yes(p.get("auto_reboot")):
                            log("policy allows auto_reboot: rebooting into the "
                                "new slot (one-shot; falls back by itself if it "
                                "does not come up healthy)")
                            if a.force:
                                run(["systemctl", "reboot"], 30)
                        else:
                            log("armed. Reboot when you are ready; the switch is "
                                "one-shot and reverts on its own if the new slot "
                                "does not come up healthy.")
            else:
                log("image written to the inactive slot but NOT armed "
                    "(auto_image_arm=no). Arm it with: ffn_updated.py arm")
    else:
        log("image: policy says no (auto_image_write=%s)" % p.get("auto_image_write"))

    st["last_applied"] = applied
    save_state(st)
    if not a.force:
        log("DRY-RUN: nothing was written. Re-run with --force to apply.")
    return 0


def do_arm(idx, label, force=False):
    ok, why = grub_saved_default_ok()
    if not ok:
        log("REFUSING to arm: %s" % why)
        log("  fix it first: ffn_updated.py setup-grub --force")
        return 2
    if not force:
        log("DRY-RUN: would grub-reboot %d (one-shot into %s)" % (idx, label))
        return 0
    rc, out = run(["grub-reboot", str(idx)], 30)
    if rc != 0:
        log("grub-reboot failed: %s" % out[-200:])
        return 1
    st = state()
    st["pending"] = {
        "armed_at": int(time.time()),
        "target_entry": idx,
        "target_label": label,
        "from_root": running_root(),
        "from_entry": current_entry_index(),
    }
    save_state(st)
    log("armed one-shot boot into entry %d (%s). If it does not come up "
        "healthy, the next boot returns here by itself." % (idx, label))
    return 0


def cmd_arm(a):
    if a.slot is not None:
        idx, lbl = a.slot, "entry %d" % a.slot
    else:
        idx, lbl = inactive_slot_entry()
        if idx is None:
            log("could not identify the inactive A/B slot; pass --slot")
            return 2
    return do_arm(idx, lbl, force=a.force)


def cmd_confirm(a):
    """Run on boot. Commit the slot we are on if healthy; otherwise leave the
    one-shot spent so the next boot falls back."""
    st = state()
    pend = st.get("pending")
    if not pend:
        return 0            # nothing to confirm; normal boot

    root = running_root()
    if root == pend.get("from_root"):
        # We are back on the OLD slot -- the one-shot boot failed and GRUB
        # already fell back. Record it rather than silently retrying forever.
        log("rollback detected: still on %s, the new slot did not take" % root)
        st["last_rollback"] = {"at": int(time.time()), "pending": pend}
        st.pop("pending", None)
        save_state(st)
        return 0

    h = health()
    if not h.get("ok"):
        bad = [k for k, v in h.items() if k != "ok" and not v]
        log("health check FAILED on the new slot (%s) -- NOT committing. "
            "Reboot to fall back." % ", ".join(bad))
        st["last_failed_confirm"] = {"at": int(time.time()), "checks": h}
        st.pop("pending", None)
        save_state(st)
        return 1

    idx = pend.get("target_entry")
    if idx is None:
        idx = current_entry_index()
    rc, out = run(["grub-set-default", str(idx)], 30)
    if rc != 0:
        log("healthy, but grub-set-default failed: %s" % out[-200:])
        return 1
    log("new slot is healthy; committed entry %s as the default" % idx)
    st["last_commit"] = {"at": int(time.time()), "entry": idx, "checks": h}
    st.pop("pending", None)
    save_state(st)
    return 0


def cmd_status(a):
    p = policy()
    st = state()
    ok, why = grub_saved_default_ok()
    root = running_root()
    idx, lbl = inactive_slot_entry()
    print("update server : %s" % (server_url() or "(none)"))
    print("running root  : %s" % (root or "?"))
    print("inactive slot : %s (grub entry %s)" % (lbl or "?", idx))
    print("one-shot boot : %s" % ("ready" if ok else "NOT POSSIBLE -- " + why))
    print("policy        :")
    for k in sorted(DEFAULT_POLICY):
        print("    %-18s %s" % (k, p.get(k)))
    print("grub entries  :")
    for i, e in enumerate(grub_entries()):
        mark = " <- running" if i == current_entry_index() else ""
        print("    [%d] %s%s" % (i, e, mark))
    if st.get("pending"):
        print("PENDING commit: %s" % json.dumps(st["pending"]))
    for k in ("last_commit", "last_rollback", "last_failed_confirm"):
        if st.get(k):
            print("%-14s: %s" % (k, json.dumps(st[k])[:160]))
    return 0


# -------------------------------------------------------------- selftest ----
def cmd_selftest(a):
    global POLICY, STATE, GRUB_DEFAULTS, GRUB_CFG
    import tempfile
    fails = []

    def chk(c, m):
        print(("  ok   " if c else "  FAIL ") + m)
        if not c:
            fails.append(m)

    d = tempfile.mkdtemp(prefix="ffnupd")
    saved = (POLICY, STATE, GRUB_DEFAULTS, GRUB_CFG)
    POLICY = os.path.join(d, "policy.conf")
    STATE = os.path.join(d, "state.json")
    GRUB_DEFAULTS = os.path.join(d, "grub")
    GRUB_CFG = os.path.join(d, "grub.cfg")
    try:
        # --- policy defaults are the cautious ones ---
        p = policy()
        chk(yes(p["auto_content"]), "content auto-applies by default (live, reversible)")
        chk(not yes(p["auto_image_arm"]),
            "image switch does NOT auto-arm by default")
        chk(not yes(p["auto_reboot"]),
            "the appliance does NOT reboot itself by default")

        # --- the GRUB prerequisite ---
        open(GRUB_DEFAULTS, "w").write("GRUB_DEFAULT=0\nGRUB_TIMEOUT=3\n")
        ok, why = grub_saved_default_ok()
        chk(not ok and "one-shot" in why,
            "GRUB_DEFAULT=0 is correctly refused (one-shot would be ignored)")
        r = do_arm(2, "ffn-recovery", force=True)
        chk(r == 2, "arm REFUSES while one-shot boot is impossible")
        chk("pending" not in state(), "a refused arm records no pending state")

        open(GRUB_DEFAULTS, "w").write("GRUB_DEFAULT=saved\nGRUB_SAVEDEFAULT=false\n")
        ok, why = grub_saved_default_ok()
        chk(ok, "GRUB_DEFAULT=saved is accepted")

        # --- dry run arms nothing ---
        r = do_arm(2, "ffn-recovery", force=False)
        chk(r == 0 and "pending" not in state(), "dry-run arm writes no state")

        # --- entry parsing: submenus count as ONE entry ---
        open(GRUB_CFG, "w").write(
            "menuentry 'FFN NGFW GNU/Linux' {\n  linux /boot/x\n}\n"
            "submenu 'Advanced options' {\n"
            "  menuentry 'FFN, kernel A' {\n    linux /boot/a\n  }\n"
            "  menuentry 'FFN, kernel B' {\n    linux /boot/b\n  }\n"
            "}\n"
            "menuentry 'FFN NGFW Recovery / Maintenance' {\n  linux /boot/r\n}\n")
        ents = grub_entries()
        chk(len(ents) == 3,
            "3 top-level entries parsed, submenu counted once (got %d)" % len(ents))
        chk("Recovery" in ents[2], "the recovery slot is entry 2")

        # --- confirm: rollback detection ---
        st = {"pending": {"from_root": "/dev/sda1", "target_entry": 2,
                          "target_label": "ffn-recovery", "armed_at": 1}}
        save_state(st)
        real_rr = globals()["running_root"]
        globals()["running_root"] = lambda: "/dev/sda1"      # still on the old slot
        rc = cmd_confirm(argparse.Namespace())
        chk(rc == 0 and "last_rollback" in state(),
            "confirm detects a rollback when we are back on the old slot")
        chk("pending" not in state(), "rollback clears the pending record")

        # --- confirm: unhealthy new slot must NOT commit ---
        save_state({"pending": {"from_root": "/dev/sda1", "target_entry": 2,
                                "target_label": "ffn-recovery", "armed_at": 1}})
        globals()["running_root"] = lambda: "/dev/sda2"       # on the new slot
        real_health = globals()["health"]
        globals()["health"] = lambda timeout=20: {"ok": False, "api_responds": False,
                                                  "manager_active": True}
        calls = []
        real_run = globals()["run"]
        globals()["run"] = lambda c, t=60: (calls.append(c) or (0, ""))
        rc = cmd_confirm(argparse.Namespace())
        chk(rc == 1, "unhealthy new slot returns failure")
        chk(not any("grub-set-default" in " ".join(c) for c in calls),
            "unhealthy new slot is NOT committed (so the next boot falls back)")
        chk("last_failed_confirm" in state(), "the failed confirm is recorded")

        # --- confirm: healthy new slot commits ---
        save_state({"pending": {"from_root": "/dev/sda1", "target_entry": 2,
                                "target_label": "ffn-recovery", "armed_at": 1}})
        globals()["health"] = lambda timeout=20: {"ok": True, "api_responds": True,
                                                  "manager_active": True}
        calls.clear()
        rc = cmd_confirm(argparse.Namespace())
        chk(rc == 0, "healthy new slot confirms")
        chk(any("grub-set-default" in " ".join(c) for c in calls),
            "healthy new slot IS committed")
        chk("last_commit" in state() and "pending" not in state(),
            "commit is recorded and pending cleared")

        globals()["run"] = real_run
        globals()["health"] = real_health
        globals()["running_root"] = real_rr

        # --- no pending: confirm is a no-op ---
        save_state({})
        chk(cmd_confirm(argparse.Namespace()) == 0,
            "confirm is a no-op on an ordinary boot")
    finally:
        POLICY, STATE, GRUB_DEFAULTS, GRUB_CFG = saved
        shutil.rmtree(d, ignore_errors=True)

    print("\n==== ffn_updated selftest: %d failed ====" % len(fails))
    return 1 if fails else 0


def main():
    ap = argparse.ArgumentParser(description="FFN unattended firmware updates")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("status").set_defaults(func=cmd_status)

    p = sub.add_parser("setup-grub")
    p.add_argument("--force", action="store_true")
    p.set_defaults(func=cmd_setup_grub)

    p = sub.add_parser("check")
    p.add_argument("--url", default="")
    p.set_defaults(func=cmd_check)

    p = sub.add_parser("run")
    p.add_argument("--url", default="")
    p.add_argument("--force", action="store_true")
    p.set_defaults(func=cmd_run)

    p = sub.add_parser("arm")
    p.add_argument("--slot", type=int, default=None)
    p.add_argument("--force", action="store_true")
    p.set_defaults(func=cmd_arm)

    sub.add_parser("confirm").set_defaults(func=cmd_confirm)
    sub.add_parser("selftest").set_defaults(func=cmd_selftest)

    a = ap.parse_args()
    sys.exit(a.func(a))


if __name__ == "__main__":
    main()
