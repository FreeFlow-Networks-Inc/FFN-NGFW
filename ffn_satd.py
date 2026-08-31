#!/usr/bin/env python3
"""ffn_satd.py -- FFN NGFW satellite daemon (LSVPN-style spoke enrollment).

Replicates the ROLE of PAN-OS `satd` (GlobalProtect Large-Scale VPN satellite):
a spoke firewall auto-enrolls with a portal, receives a certificate + its gateway
list + routes, then builds IPsec tunnels to the assigned gateways and keeps them
up. Config model mirrors PAN-OS `global-protect-satellite` / `satellite-config`
so a PAN-OS config maps cleanly onto FFN.

FFN-native by design: this speaks FFN's own documented LSVPN enrollment protocol
(JSON over HTTPS) and drives FFN's existing strongSwan plane -- it does not
reimplement Palo Alto's proprietary portal protocol, and ships no vendor code.
The transport is isolated in PortalClient so other enrollment backends can be
added without touching the state machine.

State machine:
    INIT -> ENROLLING -> ENROLLED -> CONNECTING -> CONNECTED
              ^                                       |
              +--------------- RETRY <----------------+

Publishes to ffn-sysd (optional, degrades gracefully):
    sw.satd.state, sw.satd.portal, sw.satd.gateway, sw.satd.tunnels,
    sw.satd.cert_expires, plus a "ffn-satd" heartbeat.

CLI:
    ffn_satd.py --serve            run the daemon loop
    ffn_satd.py --enroll           one-shot enrollment (no tunnel bring-up)
    ffn_satd.py --status           print current state
    ffn_satd.py --selftest         mock-portal end-to-end test (no root needed)
"""
import json
import os
import shutil
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request

CONFIG_PATH = os.environ.get("FFN_SAT_CONFIG", "/etc/ffn-ngfw/satellite.json")
STATE_PATH = os.environ.get("FFN_SAT_STATE", "/var/lib/ffn-ngfw/satellite-state.json")
TLS_DIR = os.environ.get("FFN_SAT_TLS", "/etc/ffn-ngfw/tls")
SWAN_CONF_DIR = os.environ.get("FFN_SAT_SWAN", "/etc/swanctl/conf.d")

DEFAULT_CONFIG = {
    "enable": False,
    # PAN-OS analogue: global-protect-satellite/portal-address
    "portal": "",                     # https://portal.example.com:8443
    "identity": "",                   # serial / hostname presented to the portal
    "psk": "",                        # bootstrap secret for first enrollment
    "verify_tls": True,
    "ca_file": "",                    # portal CA bundle (empty = system trust)
    "refresh_sec": 3600,              # config refresh interval
    "retry_sec": 60,                  # retry backoff floor
    "cert_renew_days": 30,            # renew when cert expires within N days
    "publish_routes": [],             # local subnets advertised to the gateway
    "gateways": [],                   # learned from portal; may be pre-seeded
    "ipsec": {"ike": "aes256-sha256-modp2048",
              "esp": "aes256gcm16", "dpd_sec": 30},
}

STATES = ("INIT", "ENROLLING", "ENROLLED", "CONNECTING", "CONNECTED", "RETRY")


def _now():
    return time.time()


def read_config(path=CONFIG_PATH):
    cfg = json.loads(json.dumps(DEFAULT_CONFIG))
    try:
        with open(path) as f:
            got = json.load(f)
        if isinstance(got, dict):
            for k, v in got.items():
                if k == "ipsec" and isinstance(v, dict):
                    cfg["ipsec"].update(v)
                else:
                    cfg[k] = v
    except Exception:
        pass
    if not cfg.get("identity"):
        try:
            cfg["identity"] = os.uname().nodename
        except Exception:
            cfg["identity"] = "ffn-satellite"
    return cfg


def write_state(state, path=STATE_PATH):
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(state, f, indent=1)
        os.replace(tmp, path)
    except Exception:
        pass


def read_state(path=STATE_PATH):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return {}


# ---------------------------------------------------------------------------
class PortalClient:
    """FFN LSVPN enrollment transport (JSON over HTTPS).

    POST {portal}/api/lsvpn/enroll
        {identity, psk, csr_pem, routes[]}
      -> {cert_pem, ca_pem, gateways:[{name,address,id,psk?}], routes[], ttl}
    """

    def __init__(self, cfg):
        self.cfg = cfg

    def _ctx(self):
        if not self.cfg.get("verify_tls", True):
            c = ssl.create_default_context()
            c.check_hostname = False
            c.verify_mode = ssl.CERT_NONE
            return c
        ca = self.cfg.get("ca_file")
        if ca and os.path.exists(ca):
            return ssl.create_default_context(cafile=ca)
        return ssl.create_default_context()

    def enroll(self, csr_pem, timeout=20):
        portal = (self.cfg.get("portal") or "").rstrip("/")
        if not portal:
            raise ValueError("no portal configured")
        body = json.dumps({
            "identity": self.cfg.get("identity"),
            "psk": self.cfg.get("psk", ""),
            "csr_pem": csr_pem,
            "routes": self.cfg.get("publish_routes", []),
        }).encode()
        req = urllib.request.Request(
            portal + "/api/lsvpn/enroll", data=body,
            headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=timeout, context=self._ctx()) as r:
            return json.loads(r.read().decode())


# ---------------------------------------------------------------------------
def generate_csr(identity, key_path=None, tls_dir=TLS_DIR):
    """CSR from the device key (same non-disruptive path as the cert API)."""
    key = key_path or os.path.join(tls_dir, "server.key")
    if not os.path.exists(key):
        return None, "no device private key at %s" % key
    if not shutil.which("openssl"):
        return None, "openssl not available"
    subj = "/CN=" + str(identity).replace("/", "_")
    try:
        r = subprocess.run(["openssl", "req", "-new", "-key", key, "-subj", subj],
                           capture_output=True, text=True, timeout=15)
        if r.returncode != 0:
            return None, "openssl req failed: " + (r.stderr or "")[:200]
        return r.stdout, None
    except Exception as e:
        return None, str(e)[:200]


def cert_expiry_days(cert_pem_path):
    if not (cert_pem_path and os.path.exists(cert_pem_path) and shutil.which("openssl")):
        return None
    try:
        r = subprocess.run(["openssl", "x509", "-in", cert_pem_path, "-noout", "-enddate"],
                           capture_output=True, text=True, timeout=8)
        if r.returncode != 0:
            return None
        s = r.stdout.strip().split("=", 1)[1]
        exp = time.mktime(time.strptime(s.replace(" GMT", ""), "%b %d %H:%M:%S %Y"))
        return int((exp - _now()) / 86400)
    except Exception:
        return None


def render_swanctl(cfg, gateways, cert_file=None):
    """Render a swanctl conn stanza per gateway (strongSwan = FFN's IPsec plane)."""
    ip = cfg.get("ipsec", {})
    ike = ip.get("ike", "aes256-sha256-modp2048")
    esp = ip.get("esp", "aes256gcm16")
    dpd = int(ip.get("dpd_sec", 30) or 30)
    ident = cfg.get("identity", "ffn-satellite")
    locals_ = ",".join(cfg.get("publish_routes", []) or ["0.0.0.0/0"])
    out = ["# generated by ffn-satd -- do not edit by hand"]
    out.append("connections {")
    for gw in gateways:
        name = str(gw.get("name") or gw.get("address") or "gw").replace(" ", "_")
        addr = gw.get("address", "")
        remote_id = gw.get("id") or addr
        auth = "psk" if gw.get("psk") else "pubkey"
        out.append("  ffn-sat-%s {" % name)
        out.append("    remote_addrs = %s" % addr)
        out.append("    version = 2")
        out.append("    proposals = %s" % ike)
        out.append("    dpd_delay = %ds" % dpd)
        out.append("    local {")
        out.append("      auth = %s" % auth)
        out.append("      id = %s" % ident)
        if auth == "pubkey" and cert_file:
            out.append("      certs = %s" % os.path.basename(cert_file))
        out.append("    }")
        out.append("    remote {")
        out.append("      auth = %s" % auth)
        out.append("      id = %s" % remote_id)
        out.append("    }")
        out.append("    children {")
        out.append("      ffn-sat-%s {" % name)
        out.append("        local_ts = %s" % locals_)
        out.append("        remote_ts = %s" % (",".join(gw.get("routes", []) or ["0.0.0.0/0"])))
        out.append("        esp_proposals = %s" % esp)
        out.append("        start_action = trap|start")
        out.append("        dpd_action = restart")
        out.append("      }")
        out.append("    }")
        out.append("  }")
    out.append("}")
    return "\n".join(out) + "\n"


def swanctl(*args, timeout=25):
    exe = shutil.which("swanctl") or "/usr/sbin/swanctl"
    if not os.path.exists(exe) and not shutil.which("swanctl"):
        return None, "swanctl not installed"
    try:
        r = subprocess.run([exe] + list(args), capture_output=True, text=True, timeout=timeout)
        return r, (None if r.returncode == 0 else (r.stderr or r.stdout or "")[:300])
    except Exception as e:
        return None, str(e)[:200]


# ---------------------------------------------------------------------------
class SatelliteDaemon:
    def __init__(self, cfg=None, sysd=None, swan_dir=SWAN_CONF_DIR,
                 tls_dir=TLS_DIR, state_path=STATE_PATH):
        self.cfg = cfg or read_config()
        self.swan_dir = swan_dir
        self.tls_dir = tls_dir
        self.state_path = state_path
        self.state = "INIT"
        self.gateways = []
        self.last_enroll = 0.0
        self.last_error = ""
        self.cert_file = os.path.join(tls_dir, "satellite.crt")
        self.ca_file = os.path.join(tls_dir, "satellite-ca.crt")
        self.tunnels = {}
        self._sysd = sysd
        self._sysd_warned = False

    # ---- sysd integration (optional) ----
    def _publish(self):
        st = {
            "state": self.state, "portal": self.cfg.get("portal", ""),
            "identity": self.cfg.get("identity", ""),
            "gateways": self.gateways, "tunnels": self.tunnels,
            "last_enroll": self.last_enroll, "last_error": self.last_error,
            "cert_expires_days": cert_expiry_days(self.cert_file),
            "enabled": bool(self.cfg.get("enable")), "ts": _now(),
        }
        write_state(st, self.state_path)
        if self._sysd is None:
            try:
                sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
                from ffn_sysd import SysdClient
                self._sysd = SysdClient().connect()
            except Exception:
                if not self._sysd_warned:
                    self._sysd_warned = True
                return st
        try:
            self._sysd.set("sw.satd.state", self.state)
            self._sysd.set("sw.satd.portal", self.cfg.get("portal", ""))
            self._sysd.set("sw.satd.gateway", (self.gateways[0].get("address")
                                               if self.gateways else ""))
            self._sysd.set("sw.satd.tunnels", self.tunnels)
            self._sysd.set("sw.satd.cert_expires", st["cert_expires_days"])
            self._sysd.heartbeat("ffn-satd")
        except Exception:
            self._sysd = None            # reconnect next cycle
        return st

    def _set_state(self, s, err=""):
        self.state = s
        self.last_error = err
        self._publish()

    # ---- enrollment ----
    def enroll(self):
        self._set_state("ENROLLING")
        csr, err = generate_csr(self.cfg.get("identity"), tls_dir=self.tls_dir)
        if not csr:
            self._set_state("RETRY", "csr: %s" % err)
            return False
        try:
            resp = PortalClient(self.cfg).enroll(csr)
        except Exception as e:
            self._set_state("RETRY", "portal: %s" % str(e)[:200])
            return False
        cert = resp.get("cert_pem")
        if not cert:
            self._set_state("RETRY", "portal returned no certificate")
            return False
        try:
            os.makedirs(self.tls_dir, exist_ok=True)
            with open(self.cert_file, "w") as f:
                f.write(cert)
            if resp.get("ca_pem"):
                with open(self.ca_file, "w") as f:
                    f.write(resp["ca_pem"])
        except Exception as e:
            self._set_state("RETRY", "cert write: %s" % str(e)[:160])
            return False
        gws = resp.get("gateways") or []
        if resp.get("routes"):
            for g in gws:
                g.setdefault("routes", resp["routes"])
        self.gateways = gws
        self.last_enroll = _now()
        self._set_state("ENROLLED")
        return True

    # ---- tunnels ----
    def apply_tunnels(self):
        if not self.gateways:
            self._set_state("RETRY", "no gateways assigned by portal")
            return False
        self._set_state("CONNECTING")
        conf = render_swanctl(self.cfg, self.gateways, self.cert_file)
        try:
            os.makedirs(self.swan_dir, exist_ok=True)
            path = os.path.join(self.swan_dir, "ffn-satellite.conf")
            with open(path, "w") as f:
                f.write(conf)
        except Exception as e:
            self._set_state("RETRY", "swan write: %s" % str(e)[:160])
            return False
        r, err = swanctl("--load-all")
        if err:
            self._set_state("RETRY", "swanctl load: %s" % err)
            return False
        up = {}
        for gw in self.gateways:
            name = "ffn-sat-%s" % str(gw.get("name") or gw.get("address")).replace(" ", "_")
            _r, e2 = swanctl("--initiate", "--child", name)
            up[name] = "up" if not e2 else ("error: " + e2[:80])
        self.tunnels = up
        ok = any(v == "up" for v in up.values())
        self._set_state("CONNECTED" if ok else "RETRY",
                        "" if ok else "no tunnel established")
        return ok

    def needs_renewal(self):
        d = cert_expiry_days(self.cert_file)
        return d is not None and d <= int(self.cfg.get("cert_renew_days", 30))

    # ---- main loop ----
    def run_once(self):
        if not self.cfg.get("enable"):
            self._set_state("INIT", "satellite disabled")
            return
        stale = (_now() - self.last_enroll) > float(self.cfg.get("refresh_sec", 3600))
        if self.state in ("INIT", "RETRY") or stale or self.needs_renewal():
            if not self.enroll():
                return
        self.apply_tunnels()

    def serve(self):
        print("ffn-satd: starting (portal=%s identity=%s enable=%s)"
              % (self.cfg.get("portal"), self.cfg.get("identity"),
                 self.cfg.get("enable")), flush=True)
        while True:
            try:
                self.cfg = read_config()
                self.run_once()
            except Exception as e:
                self._set_state("RETRY", "loop: %s" % str(e)[:180])
            delay = (float(self.cfg.get("refresh_sec", 3600))
                     if self.state == "CONNECTED"
                     else float(self.cfg.get("retry_sec", 60)))
            time.sleep(max(5.0, delay))


# ---------------------------------------------------------------------------
def _selftest():
    """End-to-end against an in-process mock portal. No root, no system paths."""
    import tempfile
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    d = tempfile.mkdtemp(prefix="ffnsatd")
    tls, swan = os.path.join(d, "tls"), os.path.join(d, "swan")
    os.makedirs(tls, exist_ok=True)
    fails = []

    def chk(cond, msg):
        print(("  ok  " if cond else "  FAIL") + " " + msg)
        if not cond:
            fails.append(msg)

    # a real key + self-signed CA so the CSR path is genuinely exercised
    have_ssl = shutil.which("openssl") is not None
    if have_ssl:
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                        "-keyout", os.path.join(tls, "server.key"),
                        "-out", os.path.join(tls, "server.crt"),
                        "-subj", "/CN=sat-test", "-days", "3"],
                       capture_output=True, timeout=40)

    seen = {}

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            n = int(self.headers.get("Content-Length", 0))
            req = json.loads(self.rfile.read(n).decode())
            seen.update(req)
            body = json.dumps({
                "cert_pem": open(os.path.join(tls, "server.crt")).read()
                            if have_ssl else "-----BEGIN CERTIFICATE-----\nx\n"
                                             "-----END CERTIFICATE-----\n",
                "ca_pem": "-----BEGIN CERTIFICATE-----\nca\n-----END CERTIFICATE-----\n",
                "gateways": [{"name": "gw1", "address": "198.51.100.10",
                              "id": "gw1.example", "routes": ["10.10.0.0/16"]}],
                "routes": ["10.10.0.0/16"], "ttl": 3600,
            }).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]

    cfg = json.loads(json.dumps(DEFAULT_CONFIG))
    cfg.update(enable=True, portal="http://127.0.0.1:%d" % port,
               identity="sat-test-01", psk="bootstrap", verify_tls=False,
               publish_routes=["192.168.77.0/24"])
    sat = SatelliteDaemon(cfg=cfg, sysd=False, swan_dir=swan, tls_dir=tls,
                          state_path=os.path.join(d, "state.json"))
    sat._sysd = None

    # config defaults
    c2 = read_config(os.path.join(d, "missing.json"))
    chk(c2["enable"] is False and c2["identity"], "config defaults + identity fallback")

    if have_ssl:
        csr, err = generate_csr("sat-test-01", tls_dir=tls)
        chk(csr and "BEGIN CERTIFICATE REQUEST" in csr, "CSR generated from device key")
    else:
        print("  skip CSR (no openssl)")

    ok = sat.enroll()
    chk(ok and sat.state == "ENROLLED", "enroll -> ENROLLED (state=%s err=%s)"
        % (sat.state, sat.last_error))
    chk(seen.get("identity") == "sat-test-01" and seen.get("psk") == "bootstrap",
        "portal received identity + psk")
    chk(seen.get("routes") == ["192.168.77.0/24"], "portal received published routes")
    chk(len(sat.gateways) == 1 and sat.gateways[0]["address"] == "198.51.100.10",
        "gateway list learned from portal")
    chk(os.path.exists(sat.cert_file), "satellite cert written")

    conf = render_swanctl(cfg, sat.gateways, sat.cert_file)
    chk("ffn-sat-gw1" in conf and "remote_addrs = 198.51.100.10" in conf,
        "swanctl conn rendered for gateway")
    chk("local_ts = 192.168.77.0/24" in conf, "published routes -> local_ts")
    chk("remote_ts = 10.10.0.0/16" in conf, "portal routes -> remote_ts")
    chk("esp_proposals = aes256gcm16" in conf, "esp proposal applied")

    # tunnels: swanctl absent in test env -> must degrade to RETRY, not crash
    sat.apply_tunnels()
    chk(sat.state in ("CONNECTED", "RETRY"), "apply_tunnels degrades cleanly (%s)" % sat.state)

    st = read_state(os.path.join(d, "state.json"))
    chk(st.get("identity") == "sat-test-01" and "state" in st, "state file published")

    if have_ssl:
        chk(cert_expiry_days(os.path.join(tls, "server.crt")) is not None,
            "cert expiry parsed")
        sat.cfg["cert_renew_days"] = 9999
        chk(sat.needs_renewal() is True, "renewal triggers near expiry")

    # disabled config must not enroll
    sat.cfg["enable"] = False
    sat.run_once()
    chk(sat.state == "INIT", "disabled -> INIT (no enrollment)")

    srv.shutdown()
    print("\n==== ffn-satd selftest: %d failed ====" % len(fails))
    return 1 if fails else 0


if __name__ == "__main__":
    a = sys.argv[1:]
    if not a or a[0] == "--serve":
        SatelliteDaemon().serve()
    elif a[0] == "--selftest":
        sys.exit(_selftest())
    elif a[0] == "--enroll":
        s = SatelliteDaemon()
        ok = s.enroll()
        print(json.dumps({"enrolled": ok, "state": s.state,
                          "gateways": s.gateways, "error": s.last_error}, indent=2))
        sys.exit(0 if ok else 1)
    elif a[0] == "--status":
        print(json.dumps(read_state(), indent=2))
    else:
        print(__doc__)
