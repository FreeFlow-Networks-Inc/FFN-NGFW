#!/usr/bin/env python3
"""ffn_watchdogd.py -- FFN hardware watchdog daemon.

WHY: appliance chassis (PA-3200/PA-5200 and friends) arm a hardware watchdog that
force-reboots the box unless the OS services it. A custom OS that never pets it
gets rebooted at a fixed interval, which looks like a random reboot loop rather
than a watchdog bite. This daemon opens /dev/watchdog and pets it.

It is a REAL watchdog, not a blind "while True: write()":
  * optional health gating -- it can stop petting when FFN is actually wedged, so
    the hardware does its job and reboots a dead firewall (that is the whole
    point of a watchdog). Health comes from systemd unit state plus ffn-sysd
    heartbeats, with a startup grace period and an N-strike rule so a single
    hiccup never reboots a working box;
  * clean shutdown writes the 'V' magic character so the watchdog is DISARMED on
    a deliberate stop instead of biting after we exit;
  * it reports WDIOC_GETBOOTSTATUS, so you can tell whether the last reboot was a
    watchdog bite -- exactly the evidence needed when debugging "why did the
    appliance reboot?".

MUTUALLY EXCLUSIVE with systemd's RuntimeWatchdogSec: only one process may hold
/dev/watchdog. If you set RuntimeWatchdogSec in system.conf, do NOT run this
daemon (and vice versa). systemd's version is simpler; this one adds FFN health
gating and reporting.

Stdlib only, so it can start before any venv exists.

CLI:
    ffn_watchdogd.py --serve       run the daemon
    ffn_watchdogd.py --probe       report watchdog hardware + last boot cause
    ffn_watchdogd.py --selftest    logic tests (no hardware needed)
"""
import array
import fcntl
import glob
import json
import os
import signal
import subprocess
import sys
import time

CONFIG_PATH = os.environ.get("FFN_WD_CONFIG", "/etc/ffn-ngfw/watchdog.json")
STATE_PATH = os.environ.get("FFN_WD_STATE", "/var/lib/ffn-ngfw/watchdog-state.json")

# --- linux/watchdog.h ioctls (WATCHDOG_IOCTL_BASE = 'W') -------------------
_IOC_NONE, _IOC_WRITE, _IOC_READ = 0, 1, 2


def _IOC(direction, typ, nr, size):
    return (direction << 30) | (size << 16) | (ord(typ) << 8) | nr


_WD_INFO_SIZE = 4 + 4 + 32          # struct watchdog_info
WDIOC_GETSUPPORT    = _IOC(_IOC_READ, "W", 0, _WD_INFO_SIZE)
WDIOC_GETBOOTSTATUS = _IOC(_IOC_READ, "W", 2, 4)
WDIOC_SETOPTIONS    = _IOC(_IOC_READ, "W", 4, 4)
WDIOC_KEEPALIVE     = _IOC(_IOC_READ, "W", 5, 4)
WDIOC_SETTIMEOUT    = _IOC(_IOC_READ | _IOC_WRITE, "W", 6, 4)
WDIOC_GETTIMEOUT    = _IOC(_IOC_READ, "W", 7, 4)
WDIOC_GETTIMELEFT   = _IOC(_IOC_READ, "W", 10, 4)

DEFAULT_CONFIG = {
    "enable": True,
    "device": "",                 # "" = autodetect /dev/watchdog, /dev/watchdogN
    "timeout_sec": 60,            # hardware timeout to request
    "pet_interval_sec": 15,       # must be comfortably < timeout
    # Health gating. Default OFF: pet unconditionally, which is what you want
    # while bringing a new chassis up. Turn it on for production so a wedged
    # firewall actually gets rebooted.
    "require_health": False,
    "startup_grace_sec": 300,     # always pet for this long after start
    "strikes_to_bite": 3,         # consecutive unhealthy checks before we stop
    "critical_units": ["ffn-configd", "ffn-manager-v2"],
    "sysd_heartbeats": [],        # e.g. ["ffn-configd"] -- stale => unhealthy
    "sysd_stale_sec": 90,
    "disarm_on_exit": True,       # write 'V' magic close on clean shutdown
}


def load_config(path=CONFIG_PATH):
    cfg = dict(DEFAULT_CONFIG)
    try:
        with open(path) as f:
            got = json.load(f)
        if isinstance(got, dict):
            cfg.update(got)
    except Exception:
        pass
    return cfg


def find_devices():
    devs = []
    if os.path.exists("/dev/watchdog"):
        devs.append("/dev/watchdog")
    for p in sorted(glob.glob("/dev/watchdog[0-9]*")):
        devs.append(p)
    return devs


def driver_info():
    """Which watchdog drivers the kernel actually has bound."""
    out = []
    for p in sorted(glob.glob("/sys/class/watchdog/watchdog*")):
        ent = {"sysfs": p, "name": "", "state": "", "timeout": ""}
        for key, fname in (("name", "identity"), ("state", "state"),
                           ("timeout", "timeout")):
            try:
                with open(os.path.join(p, fname)) as fh:
                    ent[key] = fh.read().strip()
            except Exception:
                pass
        out.append(ent)
    return out


class Watchdog:
    """Thin wrapper so the daemon logic is testable against a plain file."""

    def __init__(self, path):
        self.path = path
        self.fd = None
        self.identity = ""
        self.options = 0
        self.supports_ioctl = False

    def open(self):
        self.fd = os.open(self.path, os.O_WRONLY | os.O_CLOEXEC)
        buf = array.array("B", [0] * _WD_INFO_SIZE)
        try:
            fcntl.ioctl(self.fd, WDIOC_GETSUPPORT, buf, True)
            self.options = int.from_bytes(bytes(buf[0:4]), sys.byteorder)
            self.identity = bytes(buf[8:40]).split(b"\x00")[0].decode(errors="replace")
            self.supports_ioctl = True
        except OSError:
            self.supports_ioctl = False      # write-only device (or a plain file)
        return self

    def _ioctl_int(self, req, value=None):
        buf = array.array("i", [value if value is not None else 0])
        fcntl.ioctl(self.fd, req, buf, True)
        return buf[0]

    def set_timeout(self, seconds):
        try:
            return self._ioctl_int(WDIOC_SETTIMEOUT, int(seconds))
        except OSError:
            return None

    def get_timeout(self):
        try:
            return self._ioctl_int(WDIOC_GETTIMEOUT)
        except OSError:
            return None

    def time_left(self):
        try:
            return self._ioctl_int(WDIOC_GETTIMELEFT)
        except OSError:
            return None

    def boot_status(self):
        """Non-zero typically means the last reboot was a watchdog bite."""
        try:
            return self._ioctl_int(WDIOC_GETBOOTSTATUS)
        except OSError:
            return None

    def pet(self):
        """KEEPALIVE ioctl if available, else a single byte write."""
        try:
            self._ioctl_int(WDIOC_KEEPALIVE)
            return "ioctl"
        except OSError:
            os.write(self.fd, b"\0")
            return "write"

    def disarm(self):
        """'V' = magic close: ask the driver to stop the watchdog on close.
        Ignored when the kernel is built with CONFIG_WATCHDOG_NOWAYOUT."""
        try:
            os.write(self.fd, b"V")
            return True
        except OSError:
            return False

    def close(self, disarm=True):
        if self.fd is None:
            return
        if disarm:
            self.disarm()
        try:
            os.close(self.fd)
        finally:
            self.fd = None


# ---------------------------------------------------------------- health ----
def unit_active(unit):
    try:
        r = subprocess.run(["systemctl", "is-active", unit],
                           capture_output=True, text=True, timeout=5)
        return r.stdout.strip() == "active"
    except Exception:
        return True          # cannot tell -> do not manufacture a reboot


def sysd_heartbeats_ok(names, stale_sec):
    """Ask ffn-sysd whether the named daemons are still heartbeating."""
    if not names:
        return True, "no heartbeat checks configured"
    try:
        sys.path.insert(0, "/opt/ffn-ngfw-v2")
        from ffn_sysd import SysdClient
        with SysdClient() as c:
            hb = c.hbstat()
    except Exception as e:
        return True, "sysd unavailable (%s) -- not counted as unhealthy" % str(e)[:60]
    bad = []
    for n in names:
        rec = hb.get(n)
        if rec is None:
            bad.append("%s:absent" % n)
        elif rec.get("age", 0) > stale_sec:
            bad.append("%s:stale(%.0fs)" % (n, rec.get("age", 0)))
    return (not bad), (", ".join(bad) if bad else "heartbeats fresh")


def evaluate_health(cfg):
    """Return (healthy, reason). Conservative: anything we cannot determine is
    treated as healthy, so an inability to check never reboots the box."""
    dead = [u for u in cfg.get("critical_units", []) if not unit_active(u)]
    if dead:
        return False, "units inactive: " + ", ".join(dead)
    ok, why = sysd_heartbeats_ok(cfg.get("sysd_heartbeats", []),
                                 cfg.get("sysd_stale_sec", 90))
    if not ok:
        return False, why
    return True, why


def write_state(d, path=STATE_PATH):
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(d, f, indent=1)
        os.replace(tmp, path)
    except Exception:
        pass


# ----------------------------------------------------------------- probe ----
def probe():
    devs = find_devices()
    drivers = driver_info()
    print("watchdog devices : %s" % (", ".join(devs) if devs else "NONE"))
    if drivers:
        for d in drivers:
            print("  %s  identity=%r state=%s timeout=%s"
                  % (d["sysfs"], d["name"], d["state"], d["timeout"]))
    else:
        print("  no /sys/class/watchdog entries -- no watchdog driver is bound")
    if not devs:
        print("")
        print("No watchdog to pet. On appliance hardware this usually means the")
        print("chassis watchdog is a vendor part with no in-tree driver (e.g. the")
        print("PA-5200 CPLD watchdog, PAN's own cpld_wdt.ko -- which cannot be")
        print("reused: it is built for kernel 3.10 and is ABI-locked to it).")
        print("Options, cheapest first:")
        print("  1. modprobe iTCO_wdt   (Intel PCH/TCO watchdog, in-tree)")
        print("  2. disable the watchdog in BIOS setup")
        print("  3. port a driver for the CPLD part (RE its register interface)")
        return 1
    w = Watchdog(devs[0])
    try:
        w.open()
    except OSError as e:
        print("cannot open %s: %s" % (devs[0], e))
        return 1
    print("")
    print("opened %s" % devs[0])
    print("  identity      : %s" % (w.identity or "(no ioctl support)"))
    print("  hw timeout    : %s s" % w.get_timeout())
    print("  time left     : %s s" % w.time_left())
    bs = w.boot_status()
    print("  boot status   : %s%s"
          % (bs, "  <-- last reboot was a WATCHDOG BITE" if bs else ""))
    w.close(disarm=True)       # probing must never leave it armed
    print("  (disarmed on close)")
    return 0


# ------------------------------------------------------------------ serve ----
def serve():
    cfg = load_config()
    if not cfg.get("enable", True):
        print("ffn-watchdogd: disabled by config", flush=True)
        return 0
    devs = [cfg["device"]] if cfg.get("device") else find_devices()
    devs = [d for d in devs if d and os.path.exists(d)]
    if not devs:
        print("ffn-watchdogd: no watchdog device present -- nothing to pet. "
              "Run --probe for guidance.", flush=True)
        write_state({"state": "no-device", "ts": time.time()})
        return 1

    w = Watchdog(devs[0])
    try:
        w.open()
    except OSError as e:
        print("ffn-watchdogd: cannot open %s: %s" % (devs[0], e), flush=True)
        return 1

    requested = int(cfg.get("timeout_sec", 60))
    w.set_timeout(requested)
    actual = w.get_timeout() or requested
    interval = int(cfg.get("pet_interval_sec", 15))
    # never pet slower than the hardware can tolerate
    if interval >= actual:
        interval = max(1, actual // 3)
    boot = w.boot_status()
    print("ffn-watchdogd: %s identity=%r timeout=%ss (requested %ss) "
          "pet_every=%ss health_gate=%s boot_status=%s"
          % (devs[0], w.identity, actual, requested, interval,
             cfg.get("require_health"), boot), flush=True)
    if boot:
        print("ffn-watchdogd: WARNING previous boot was a watchdog reset "
              "(boot_status=%s)" % boot, flush=True)

    stop = {"v": False}

    def _sig(_s, _f):
        stop["v"] = True

    signal.signal(signal.SIGTERM, _sig)
    signal.signal(signal.SIGINT, _sig)

    started = time.time()
    strikes = 0
    pets = 0
    while not stop["v"]:
        now = time.time()
        healthy, why = True, "gating disabled"
        if cfg.get("require_health"):
            if (now - started) < float(cfg.get("startup_grace_sec", 300)):
                healthy, why = True, "startup grace"
            else:
                healthy, why = evaluate_health(cfg)

        if healthy:
            strikes = 0
            how = w.pet()
            pets += 1
        else:
            strikes += 1
            how = "SKIPPED"
            print("ffn-watchdogd: unhealthy (%s) strike %d/%d"
                  % (why, strikes, cfg.get("strikes_to_bite", 3)), flush=True)
            if strikes >= int(cfg.get("strikes_to_bite", 3)):
                print("ffn-watchdogd: withholding pets -- hardware watchdog will "
                      "reset the box (%s)" % why, flush=True)

        write_state({"state": "running", "device": devs[0],
                     "identity": w.identity, "timeout": actual,
                     "interval": interval, "pets": pets, "how": how,
                     "healthy": healthy, "reason": why, "strikes": strikes,
                     "boot_status": boot, "ts": now})
        # sleep in slices so SIGTERM is honoured promptly
        slept = 0.0
        while slept < interval and not stop["v"]:
            time.sleep(0.5)
            slept += 0.5

    disarm = bool(cfg.get("disarm_on_exit", True))
    w.close(disarm=disarm)
    print("ffn-watchdogd: stopped (%s)"
          % ("disarmed via magic close" if disarm else "left armed"), flush=True)
    write_state({"state": "stopped", "disarmed": disarm, "ts": time.time()})
    return 0


# --------------------------------------------------------------- selftest ----
def selftest():
    import tempfile
    fails = []

    def chk(c, m):
        print(("  ok   " if c else "  FAIL ") + m)
        if not c:
            fails.append(m)

    # ioctl encodings must match linux/watchdog.h exactly
    chk(WDIOC_KEEPALIVE == 0x80045705,
        "WDIOC_KEEPALIVE encoding (0x%08x)" % WDIOC_KEEPALIVE)
    chk(WDIOC_SETTIMEOUT == 0xC0045706,
        "WDIOC_SETTIMEOUT encoding (0x%08x)" % WDIOC_SETTIMEOUT)
    chk(WDIOC_GETTIMEOUT == 0x80045707,
        "WDIOC_GETTIMEOUT encoding (0x%08x)" % WDIOC_GETTIMEOUT)
    chk(WDIOC_GETBOOTSTATUS == 0x80045702, "WDIOC_GETBOOTSTATUS encoding")
    chk(_WD_INFO_SIZE == 40, "struct watchdog_info is 40 bytes")

    # config defaults: must not health-gate out of the box
    cfg = load_config("/nonexistent/watchdog.json")
    chk(cfg["enable"] is True, "enabled by default")
    chk(cfg["require_health"] is False,
        "health gating OFF by default (safe for chassis bring-up)")
    chk(cfg["pet_interval_sec"] < cfg["timeout_sec"],
        "pet interval is shorter than the hardware timeout")
    chk(cfg["disarm_on_exit"] is True, "disarms on clean exit by default")

    # device layer against a plain file (no hardware, no ioctl support)
    d = tempfile.mkdtemp()
    fake = os.path.join(d, "watchdog")
    open(fake, "wb").close()
    w = Watchdog(fake).open()
    chk(w.supports_ioctl is False, "falls back cleanly when ioctls are unsupported")
    chk(w.pet() == "write", "pets by write() when KEEPALIVE ioctl is absent")
    chk(w.get_timeout() is None, "get_timeout tolerates no ioctl")
    chk(w.boot_status() is None, "boot_status tolerates no ioctl")
    chk(w.disarm() is True, "magic close writes 'V'")
    w.close(disarm=False)
    with open(fake, "rb") as f:
        data = f.read()
    chk(b"V" in data, "'V' actually reached the device")

    # health evaluation must fail SAFE: unknown => healthy
    hcfg = dict(DEFAULT_CONFIG)
    hcfg["critical_units"] = ["ffn-definitely-not-a-real-unit"]
    healthy, why = evaluate_health(hcfg)
    chk(healthy is False and "inactive" in why,
        "a genuinely inactive critical unit reads unhealthy")
    hcfg["critical_units"] = []
    hcfg["sysd_heartbeats"] = ["definitely-not-a-daemon"]
    # ORDER MATTERS: ffn_sysd binds its socket path at module-import time, so the
    # reachable case must be exercised BEFORE we poison FFN_SYSD_SOCK -- once the
    # module is imported against a bogus path, restoring the env cannot undo it.
    sock = os.environ.get("FFN_SYSD_SOCK", "/run/ffn-ngfw/sysd.sock")
    if os.path.exists(sock):
        healthy, why = evaluate_health(hcfg)
        chk(healthy is False and "absent" in why,
            "sysd reachable + missing heartbeat reads unhealthy: %s" % why)
    else:
        print("  skip  sysd not running here; reachable-case check not applicable")
    # now force the unreachable case and confirm it fails SAFE
    os.environ["FFN_SYSD_SOCK"] = "/nonexistent/ffn-sysd.sock"
    for m in ("ffn_sysd",):
        sys.modules.pop(m, None)          # drop any binding to the real path
    healthy, why = evaluate_health(hcfg)
    chk(healthy is True,
        "sysd UNREACHABLE is not treated as unhealthy (fail safe): %s" % why)

    # discovery helpers must not raise on a host with no watchdog
    chk(isinstance(find_devices(), list), "find_devices() safe on any host")
    chk(isinstance(driver_info(), list), "driver_info() safe on any host")

    print("")
    print("==== ffn_watchdogd selftest: %d failed ====" % len(fails))
    return 1 if fails else 0


if __name__ == "__main__":
    a = sys.argv[1:]
    if not a or a[0] == "--serve":
        sys.exit(serve())
    if a[0] == "--probe":
        sys.exit(probe())
    if a[0] == "--selftest":
        sys.exit(selftest())
    print(__doc__)
