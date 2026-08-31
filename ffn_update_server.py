#!/usr/bin/env python3
"""ffn_update_server.py -- FFN's software-update API and web console.

Serves signed payloads so appliances can pull them with ffn_payload.py, a JSON
API for tooling, and a web console so an operator can see at a glance what is
published, how it is signed, and which appliances have actually collected it.

    ffn_update_server.py [--dir /srv/ffn-updates] [--port 8444]
                         [--cert ...] [--key ...] [--bind 0.0.0.0]

WHAT IS REACHABLE
    GET /                      web console
    GET /manifest.json         the signed manifest (what ffn_payload.py reads)
    GET /api/status            server + signing summary
    GET /api/payloads          structured payload list
    GET /api/payloads/<kind>   one payload
    GET /api/clients           appliances seen, and what they took
    GET /<file>                a payload -- ONLY if the manifest names it

Nothing else exists. This is deliberately not a general file server: a stray
file in the payload directory is not reachable, and path traversal has nothing
to reach. The signing seed lives in /etc/ffn-ngfw and is never read here -- this
process only ever reads the payload directory, so it cannot leak the key even if
it is compromised.
"""
import argparse
import html
import http.server
import json
import os
import ssl
import threading
import time

DIR = "/srv/ffn-updates"
PUBKEY = "/etc/ffn-ngfw/update-sign.pub"
PORT = 8444
HOSTHINT = "update-server.example"
STARTED = time.time()

# Appliance check-ins. Bounded so a busy or hostile client cannot grow it
# without limit; this is an operator convenience, not an audit log.
_clients = {}
_clients_lock = threading.Lock()
MAX_CLIENTS = 256


def note_client(ip, ua, path):
    with _clients_lock:
        rec = _clients.get(ip)
        if rec is None:
            if len(_clients) >= MAX_CLIENTS:
                oldest = min(_clients, key=lambda k: _clients[k]["last"])
                _clients.pop(oldest, None)
            rec = {"ip": ip, "first": time.time(), "checks": 0,
                   "downloads": [], "ua": ua}
            _clients[ip] = rec
        rec["last"] = time.time()
        rec["ua"] = ua or rec.get("ua", "")
        if path == "/manifest.json":
            # Fetching the manifest IS the check -- that is what ffn_payload.py
            # does first, so it is the signal that an appliance is talking to us.
            rec["checks"] += 1
        else:
            # Only real payload collections count as downloads. Browsing the
            # console or hitting the API is not a download, and recording it as
            # one makes the operator view lie about what an appliance took.
            name = os.path.basename(path.lstrip("/"))
            if name and name in allowed_files() and name not in rec["downloads"]:
                rec["downloads"].append(name)
                del rec["downloads"][:-8]


def manifest():
    try:
        with open(os.path.join(DIR, "manifest.json")) as f:
            return json.load(f)
    except Exception:
        return {}


def pubkey():
    try:
        with open(PUBKEY) as f:
            return f.read().strip()
    except Exception:
        return ""


def allowed_files():
    return {p["file"] for p in manifest().get("payloads", {}).values() if p.get("file")}


def fmt_size(n):
    n = float(n)
    for u in ("B", "KB", "MB", "GB"):
        if n < 1024 or u == "GB":
            return "%.0f %s" % (n, u) if u == "B" else "%.1f %s" % (n, u)
        n /= 1024.0


def ago(ts):
    if not ts:
        return "never"
    d = int(time.time() - ts)
    for lim, unit, div in ((60, "s", 1), (3600, "min", 60),
                           (86400, "h", 3600), (10 ** 9, "d", 86400)):
        if d < lim:
            return "%d%s ago" % (d // div, unit)
    return "a while ago"


# --------------------------------------------------------------- API ------
def api_status():
    man = manifest()
    pk = pubkey()
    pays = man.get("payloads", {})
    return {
        "service": "ffn-update-server",
        "uptime_seconds": int(time.time() - STARTED),
        "payload_dir": DIR,
        "signed": bool(man.get("signature")),
        "sig_alg": man.get("sig_alg"),
        "public_key": pk,
        "manifest_updated": man.get("updated"),
        "payload_kinds": sorted(pays.keys()),
        "payload_count": len(pays),
        "clients_seen": len(_clients),
        "pull_url": "https://%s:%d" % (HOSTHINT, PORT),
    }


def api_payloads():
    man = manifest()
    out = []
    for kind, p in sorted(man.get("payloads", {}).items()):
        f = os.path.join(DIR, p.get("file", ""))
        out.append({
            "kind": kind,
            "version": p.get("version"),
            "file": p.get("file"),
            "size": p.get("size"),
            "sha256": p.get("sha256"),
            "published": p.get("published"),
            "notes": p.get("notes"),
            "available": os.path.isfile(f),
            "url": "/%s" % p.get("file", ""),
        })
    return {"payloads": out, "sig_alg": man.get("sig_alg"),
            "signed": bool(man.get("signature"))}


def api_clients():
    with _clients_lock:
        rows = sorted(_clients.values(), key=lambda r: -r.get("last", 0))
        return {"clients": [dict(r) for r in rows], "count": len(rows)}


# --------------------------------------------------------------- web ------
CSS = """
:root{--ink:#14181b;--paper:#eef0f2;--card:#fff;--rule:#d4d9dd;--muted:#5b666e;
--accent:#2f6b8f;--ok:#0b6e5f;--warn:#8a5a00;--crit:#a02020}
@media(prefers-color-scheme:dark){:root{--ink:#dde3e7;--paper:#0f1316;--card:#171c20;
--rule:#2a3238;--muted:#93a1aa;--accent:#7fb4d6;--ok:#5cc9b3;--warn:#d6a44a;--crit:#e58686}}
*{box-sizing:border-box}
body{margin:0;background:var(--paper);color:var(--ink);padding:32px 20px 64px;
font:15px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
.w{max-width:900px;margin:0 auto}
h1{font-size:25px;margin:0 0 4px;letter-spacing:-.01em}
.sub{color:var(--muted);margin:0 0 26px;font-size:14px}
.card{background:var(--card);border:1px solid var(--rule);border-radius:6px;
padding:18px 20px;margin-bottom:16px}
h2{font-size:11.5px;text-transform:uppercase;letter-spacing:.09em;color:var(--muted);
margin:0 0 12px;font-weight:600}
table{border-collapse:collapse;width:100%;font-size:13px}
th{text-align:left;font-size:10.5px;text-transform:uppercase;letter-spacing:.07em;
color:var(--muted);padding:7px 10px;border-bottom:1px solid var(--rule);white-space:nowrap}
td{padding:8px 10px;border-bottom:1px solid var(--rule);vertical-align:top}
tr:last-child td{border-bottom:0}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12px}
.pill{display:inline-block;font-size:10px;font-weight:600;letter-spacing:.05em;
text-transform:uppercase;padding:2px 7px;border-radius:3px;border:1px solid currentColor}
.ok{color:var(--ok)}.warn{color:var(--warn)}.crit{color:var(--crit)}
a{color:var(--accent)}
pre{background:var(--paper);border:1px solid var(--rule);border-radius:4px;
padding:12px 14px;overflow-x:auto;font-size:12px;margin:8px 0 0}
.k{color:var(--muted);display:inline-block;min-width:120px}
.empty{color:var(--muted);font-size:13px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px}
"""


def page():
    man = manifest()
    pk = pubkey()
    alg = man.get("sig_alg", "none")
    signed = bool(man.get("signature"))
    pays = api_payloads()["payloads"]

    rows = ""
    for kind in ("content", "software", "image"):
        p = next((x for x in pays if x["kind"] == kind), None)
        if not p:
            rows += ('<tr><td><b>%s</b></td><td colspan="4" class="empty">'
                     'not published</td></tr>' % kind)
            continue
        rows += (
            '<tr><td><b>%s</b></td><td>%s</td><td class="mono">%s</td>'
            '<td class="mono">%s&hellip;</td><td>%s</td></tr>' % (
                kind, html.escape(str(p["version"])), fmt_size(p["size"] or 0),
                html.escape((p["sha256"] or "")[:16]),
                ('<a href="%s">download</a>' % html.escape(p["url"]))
                if p["available"] else '<span class="crit">file missing</span>'))

    cl = api_clients()["clients"]
    if cl:
        crows = "".join(
            '<tr><td class="mono">%s</td><td>%d</td><td>%s</td>'
            '<td class="mono" style="font-size:11px">%s</td></tr>' % (
                html.escape(c["ip"]), c.get("checks", 0), ago(c.get("last")),
                html.escape(", ".join(c.get("downloads", [])) or "-"))
            for c in cl)
        clients_html = ('<table><thead><tr><th>Appliance</th><th>Checks</th>'
                        '<th>Last seen</th><th>Collected</th></tr></thead><tbody>'
                        + crows + '</tbody></table>')
    else:
        clients_html = ('<div class="empty">No appliance has checked in yet. '
                        'Point one at this server with the commands below; it '
                        'will appear here after its first check.</div>')

    sig_pill = ('<span class="pill ok">%s signed</span>' % html.escape(alg)
                if signed else '<span class="pill crit">UNSIGNED</span>')
    key_html = (
        '<div><span class="k">Public key</span><span class="mono">%s</span></div>'
        '<div style="color:var(--muted);font-size:12.5px;margin-top:6px">'
        'Appliances carry only this public key, as '
        '<span class="mono">/etc/ffn-ngfw/update.pub</span>. The private seed stays '
        'on this server, is never served, and is never packaged into an image &mdash; '
        'so holding an FFN image lets you verify an update but never forge one.</div>'
        % html.escape(pk) if pk else
        '<div class="crit">No signing key found. Generate one with '
        '<span class="mono">ffn_ed25519.py --keygen /etc/ffn-ngfw/update-sign</span>'
        '</div>')

    upd = man.get("updated")
    when = (time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(upd)) + " (%s)" % ago(upd)) \
        if upd else "never"
    base = "https://%s:%d" % (HOSTHINT, PORT)

    return """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>FFN Software Updates</title><style>%s</style></head><body><div class="w">
<h1>FFN Software Updates</h1>
<p class="sub">%s &middot; manifest updated %s &middot; %d appliance(s) seen</p>

<div class="card"><h2>Published payloads</h2>
<table><thead><tr><th>Kind</th><th>Version</th><th>Size</th><th>SHA-256</th><th></th></tr></thead>
<tbody>%s</tbody></table>
<div style="color:var(--muted);font-size:12.5px;margin-top:10px">
<b>content</b> applies live &middot; <b>software</b> restarts services and keeps a
rollback copy &middot; <b>image</b> is written to the appliance's <i>inactive</i> A/B
slot, so a bad update is escaped by picking the other GRUB entry.</div></div>

<div class="card"><h2>Signing</h2>%s</div>

<div class="card"><h2>Appliance check-ins</h2>%s</div>

<div class="card"><h2>Point an appliance here</h2>
<pre>ffn_payload.py check  --url %s
ffn_payload.py update --url %s --kind content --apply
ffn_payload.py update --url %s --kind image   --apply</pre>
<div style="color:var(--muted);font-size:12.5px;margin-top:10px">
Or in the appliance WebUI: <b>Device &rsaquo; Software Updates</b>, set the server to
<span class="mono">%s</span>. Every payload must match both the signed manifest and
its SHA-256 before anything is written.</div></div>

<div class="card"><h2>API</h2>
<div class="grid mono" style="font-size:12px">
<div><a href="/api/status">/api/status</a></div>
<div><a href="/api/payloads">/api/payloads</a></div>
<div><a href="/api/clients">/api/clients</a></div>
<div><a href="/manifest.json">/manifest.json</a></div>
</div></div>
</div></body></html>""" % (CSS, sig_pill, when, len(cl), rows, key_html,
                           clients_html, base, base, base, base)


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "ffn-update/2"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *a):
        print("[%s] %s" % (self.address_string(), fmt % a))

    def _send(self, code, body, ctype="text/html; charset=utf-8"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, obj, code=200):
        self._send(code, json.dumps(obj, indent=2).encode(),
                   "application/json")

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        try:
            note_client(self.client_address[0],
                        self.headers.get("User-Agent", ""), path)
        except Exception:
            pass

        if path in ("/", "/index.html"):
            return self._send(200, page().encode())

        if path == "/api/status":
            return self._json(api_status())
        if path == "/api/payloads":
            return self._json(api_payloads())
        if path.startswith("/api/payloads/"):
            kind = path[len("/api/payloads/"):]
            p = next((x for x in api_payloads()["payloads"]
                      if x["kind"] == kind), None)
            return self._json(p or {"error": "no such payload kind"},
                              200 if p else 404)
        if path == "/api/clients":
            return self._json(api_clients())
        if path.startswith("/api/"):
            return self._json({"error": "no such endpoint"}, 404)

        if path == "/manifest.json":
            p = os.path.join(DIR, "manifest.json")
            if not os.path.isfile(p):
                return self._send(404, b"no manifest\n", "text/plain")
            with open(p, "rb") as f:
                return self._send(200, f.read(), "application/json")

        # Payloads: only files the manifest names. Not a general file server, so
        # an unrelated file in the directory is unreachable and traversal has
        # nothing to reach.
        name = os.path.basename(path.lstrip("/"))
        if name not in allowed_files():
            return self._send(404, b"not found\n", "text/plain")
        full = os.path.join(DIR, name)
        if not os.path.isfile(full):
            return self._send(404, b"payload missing\n", "text/plain")

        size = os.path.getsize(full)
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(size))
        self.send_header("Content-Disposition",
                         'attachment; filename="%s"' % name)
        self.end_headers()
        if self.command == "HEAD":
            return
        with open(full, "rb") as f:
            while True:
                b = f.read(1 << 20)
                if not b:
                    break
                try:
                    self.wfile.write(b)
                except (BrokenPipeError, ConnectionResetError):
                    return


def main():
    global DIR, PORT, HOSTHINT
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", default="/srv/ffn-updates")
    ap.add_argument("--port", type=int, default=8444)
    ap.add_argument("--bind", default="0.0.0.0")
    ap.add_argument("--cert", default="/etc/ffn-ngfw/tls/server.crt")
    ap.add_argument("--key", default="/etc/ffn-ngfw/tls/server.key")
    ap.add_argument("--host-hint", default="")
    a = ap.parse_args()

    DIR = a.dir
    PORT = a.port
    HOSTHINT = a.host_hint or os.environ.get("FFN_UPDATE_HOST") or "update-server.example"

    os.makedirs(DIR, exist_ok=True)
    srv = http.server.ThreadingHTTPServer((a.bind, a.port), Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(a.cert, a.key)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    print("FFN update server on https://%s:%d serving %s" % (a.bind, a.port, DIR))
    srv.serve_forever()


if __name__ == "__main__":
    main()
