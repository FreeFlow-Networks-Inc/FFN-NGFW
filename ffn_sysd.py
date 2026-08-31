#!/usr/bin/env python3
"""ffn_sysd.py -- FFN NGFW central runtime state bus + name service.

Fills FFN's biggest architectural gap versus PAN-OS, whose `sysd` + `lclns` give
every daemon ONE authoritative place for runtime state instead of ad-hoc files.
See Desktop/PAN/panos-daemons-to-ffn-map.md (P0).

Provides:
  * namespaced dotted-key state store (cfg.* persisted; sw./hw./dp./ha./run.* volatile)
  * change subscriptions by key prefix (push events to subscribers)
  * heartbeat registry with staleness (mirrors masterd hb-rule semantics)
  * name service: $(var) expansion, e.g. "cfg.brdagent.$(local.role)"

Stdlib only -- it must start before any venv exists, and before the data plane.

Wire protocol: newline-delimited JSON over a Unix socket (default
/run/ffn-ngfw/sysd.sock). One request object per line, one response per line.

  ops:  set get del list sub unsub hb hbstat resolve vars dump ping stats
  ex:   {"op":"set","key":"hw.cpu.cores","value":48}      -> {"ok":true}
        {"op":"get","key":"hw.cpu.cores"}                 -> {"ok":true,"value":48}
        {"op":"list","prefix":"dp."}                       -> {"ok":true,"keys":{...}}
        {"op":"sub","prefix":"ha."}                        -> {"ok":true} then async
                                                              {"event":"change",...}
        {"op":"hb","name":"ffn-configd"}                   -> {"ok":true}
        {"op":"resolve","template":"cfg.x.$(local.role)"}  -> {"ok":true,"value":"cfg.x.mp"}

CLI:
  ffn_sysd.py --serve                 run the daemon
  ffn_sysd.py --get KEY               one-shot client
  ffn_sysd.py --set KEY VALUE
  ffn_sysd.py --list [PREFIX]
  ffn_sysd.py --hbstat
  ffn_sysd.py --selftest              in-process server+client test (no root)
"""
import json
import os
import socket
import stat
import sys
import threading
import time

SOCK_PATH = os.environ.get("FFN_SYSD_SOCK", "/run/ffn-ngfw/sysd.sock")
STATE_PATH = os.environ.get("FFN_SYSD_STATE", "/var/lib/ffn-ngfw/sysd-state.json")
VARS_PATH = os.environ.get("FFN_SYSD_VARS", "/etc/ffn-ngfw/sysd-vars.json")

# Namespace roots. Only `cfg` survives a restart -- runtime facts must be
# re-published by their owning daemon so stale state can never masquerade as live.
PERSISTED_ROOTS = ("cfg",)
VALID_ROOTS = ("cfg", "sw", "hw", "dp", "ha", "run")

HB_STALE_SEC = 30.0
SNAPSHOT_DEBOUNCE_SEC = 2.0


def _now():
    return time.time()


class SysdStore:
    """Thread-safe state store + heartbeat registry + name service."""

    def __init__(self, state_path=STATE_PATH, vars_path=VARS_PATH):
        self._lock = threading.RLock()
        self._state = {}          # key -> {"value":..., "ts":float}
        self._hb = {}             # name -> {"ts":float, "count":int}
        self._subs = []           # list of (prefix, callback)
        self._state_path = state_path
        self._vars_path = vars_path
        self._dirty = False
        self._last_snapshot = 0.0
        self._stats = {"sets": 0, "gets": 0, "events": 0, "started": _now()}
        self._vars = self._load_vars()
        self._load()

    # ---- name service (lclns equivalent) ----
    def _load_vars(self):
        v = {
            "local.hostname": socket.gethostname(),
            "local.role": os.environ.get("FFN_ROLE", "mp"),
            "local.slot": os.environ.get("FFN_SLOT", "1"),
            "variant": os.environ.get("FFN_VARIANT", "ffn"),
        }
        try:
            with open(self._vars_path) as f:
                got = json.load(f)
            if isinstance(got, dict):
                v.update({str(k): str(x) for k, x in got.items()})
        except Exception:
            pass
        return v

    def resolve(self, template):
        """Expand $(var) references, e.g. cfg.brdagent.$(local.role)."""
        out = str(template)
        for _ in range(8):                      # bounded: no infinite expansion
            if "$(" not in out:
                break
            start = out.find("$(")
            end = out.find(")", start)
            if end < 0:
                break
            name = out[start + 2:end]
            out = out[:start] + self._vars.get(name, "") + out[end + 1:]
        return out

    def vars(self):
        with self._lock:
            return dict(self._vars)

    # ---- persistence ----
    def _load(self):
        try:
            with open(self._state_path) as f:
                data = json.load(f)
            for k, rec in (data.get("state") or {}).items():
                if k.split(".", 1)[0] in PERSISTED_ROOTS:
                    self._state[k] = {"value": rec.get("value"),
                                      "ts": rec.get("ts", _now())}
        except Exception:
            pass

    def snapshot(self, force=False):
        """Debounced write of persisted keys only."""
        with self._lock:
            if not self._dirty and not force:
                return
            if not force and (_now() - self._last_snapshot) < SNAPSHOT_DEBOUNCE_SEC:
                return
            keep = {k: v for k, v in self._state.items()
                    if k.split(".", 1)[0] in PERSISTED_ROOTS}
            payload = {"state": keep, "saved": _now()}
            self._dirty = False
            self._last_snapshot = _now()
        try:
            os.makedirs(os.path.dirname(self._state_path), exist_ok=True)
            tmp = self._state_path + ".tmp"
            with open(tmp, "w") as f:
                json.dump(payload, f, indent=1)
            os.replace(tmp, self._state_path)   # atomic
        except Exception:
            pass

    # ---- state ops ----
    @staticmethod
    def _check_key(key):
        if not key or not isinstance(key, str):
            return "key must be a non-empty string"
        root = key.split(".", 1)[0]
        if root not in VALID_ROOTS:
            return "invalid namespace '%s' (valid: %s)" % (root, ", ".join(VALID_ROOTS))
        return None

    def set(self, key, value):
        err = self._check_key(key)
        if err:
            return err
        with self._lock:
            old = self._state.get(key, {}).get("value")
            self._state[key] = {"value": value, "ts": _now()}
            self._stats["sets"] += 1
            if key.split(".", 1)[0] in PERSISTED_ROOTS:
                self._dirty = True
            changed = (old != value)
            subs = list(self._subs) if changed else []
        for prefix, cb in subs:
            if key.startswith(prefix):
                try:
                    cb({"event": "change", "key": key, "value": value, "ts": _now()})
                    with self._lock:
                        self._stats["events"] += 1
                except Exception:
                    pass
        self.snapshot()
        return None

    def get(self, key):
        with self._lock:
            self._stats["gets"] += 1
            rec = self._state.get(key)
            return (rec["value"], rec["ts"]) if rec else (None, None)

    def delete(self, key):
        with self._lock:
            existed = self._state.pop(key, None) is not None
            if existed and key.split(".", 1)[0] in PERSISTED_ROOTS:
                self._dirty = True
        self.snapshot()
        return existed

    def list(self, prefix=""):
        with self._lock:
            return {k: v["value"] for k, v in self._state.items() if k.startswith(prefix)}

    def dump(self):
        with self._lock:
            return {k: {"value": v["value"], "ts": v["ts"]} for k, v in self._state.items()}

    def subscribe(self, prefix, cb):
        with self._lock:
            self._subs.append((prefix, cb))

    def unsubscribe(self, cb):
        with self._lock:
            self._subs = [(p, c) for (p, c) in self._subs if c is not cb]

    # ---- heartbeats (masterd hb-rule equivalent) ----
    def heartbeat(self, name):
        with self._lock:
            rec = self._hb.setdefault(name, {"ts": 0.0, "count": 0})
            rec["ts"] = _now()
            rec["count"] += 1

    def hbstat(self, stale_sec=HB_STALE_SEC):
        now = _now()
        with self._lock:
            out = {}
            for name, rec in self._hb.items():
                age = now - rec["ts"]
                out[name] = {"age": round(age, 2), "count": rec["count"],
                             "stale": age > stale_sec}
            return out

    def stats(self):
        with self._lock:
            s = dict(self._stats)
            s.update(keys=len(self._state), subscribers=len(self._subs),
                     heartbeats=len(self._hb), uptime=round(_now() - s["started"], 1))
            return s


class SysdServer:
    def __init__(self, sock_path=SOCK_PATH, store=None):
        self.sock_path = sock_path
        self.store = store or SysdStore()
        self._srv = None
        self._running = False
        self._threads = []

    def start(self):
        d = os.path.dirname(self.sock_path)
        if d:
            os.makedirs(d, exist_ok=True)
        if os.path.exists(self.sock_path):
            os.unlink(self.sock_path)
        self._srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._srv.bind(self.sock_path)
        self._srv.listen(64)
        try:                                    # group-readable for ffn-mgmt
            os.chmod(self.sock_path, stat.S_IRUSR | stat.S_IWUSR |
                     stat.S_IRGRP | stat.S_IWGRP)
        except Exception:
            pass
        self._running = True
        self.store.set("sw.sysd.state", "running")
        self.store.set("sw.sysd.socket", self.sock_path)

    def serve_forever(self):
        self._srv.settimeout(1.0)
        while self._running:
            try:
                conn, _ = self._srv.accept()
            except socket.timeout:
                self.store.snapshot()
                continue
            except OSError:
                break
            t = threading.Thread(target=self._client, args=(conn,), daemon=True)
            t.start()
            self._threads.append(t)

    def stop(self):
        self._running = False
        self.store.set("sw.sysd.state", "stopping")
        self.store.snapshot(force=True)
        try:
            if self._srv:
                self._srv.close()
        except Exception:
            pass
        try:
            if os.path.exists(self.sock_path):
                os.unlink(self.sock_path)
        except Exception:
            pass

    def _client(self, conn):
        wlock = threading.Lock()
        my_sub = None

        def push(evt):
            with wlock:
                conn.sendall((json.dumps(evt) + "\n").encode())

        f = conn.makefile("r")
        try:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    req = json.loads(line)
                except Exception:
                    self._reply(conn, wlock, {"ok": False, "error": "bad json"})
                    continue
                resp, sub = self._handle(req, push)
                if sub is not None:
                    my_sub = sub
                self._reply(conn, wlock, resp)
        except Exception:
            pass
        finally:
            if my_sub is not None:
                self.store.unsubscribe(my_sub)
            try:
                conn.close()
            except Exception:
                pass

    @staticmethod
    def _reply(conn, wlock, obj):
        try:
            with wlock:
                conn.sendall((json.dumps(obj) + "\n").encode())
        except Exception:
            pass

    def _handle(self, req, push):
        op = req.get("op")
        s = self.store
        if op == "ping":
            return {"ok": True, "pong": True}, None
        if op == "set":
            err = s.set(req.get("key"), req.get("value"))
            return ({"ok": False, "error": err} if err else {"ok": True}), None
        if op == "get":
            v, ts = s.get(req.get("key"))
            return {"ok": True, "value": v, "ts": ts}, None
        if op == "del":
            return {"ok": True, "deleted": s.delete(req.get("key"))}, None
        if op == "list":
            return {"ok": True, "keys": s.list(req.get("prefix", ""))}, None
        if op == "dump":
            return {"ok": True, "state": s.dump()}, None
        if op == "sub":
            prefix = req.get("prefix", "")
            s.subscribe(prefix, push)
            return {"ok": True, "subscribed": prefix}, push
        if op == "unsub":
            s.unsubscribe(push)
            return {"ok": True}, None
        if op == "hb":
            name = req.get("name")
            if not name:
                return {"ok": False, "error": "name required"}, None
            s.heartbeat(name)
            return {"ok": True}, None
        if op == "hbstat":
            return {"ok": True, "heartbeats": s.hbstat(req.get("stale_sec", HB_STALE_SEC))}, None
        if op == "resolve":
            return {"ok": True, "value": s.resolve(req.get("template", ""))}, None
        if op == "vars":
            return {"ok": True, "vars": s.vars()}, None
        if op == "stats":
            return {"ok": True, "stats": s.stats()}, None
        return {"ok": False, "error": "unknown op '%s'" % op}, None


class SysdClient:
    """Client for other FFN daemons. Usable as a context manager."""

    def __init__(self, sock_path=SOCK_PATH, timeout=5.0):
        self.sock_path = sock_path
        self.timeout = timeout
        self._s = None
        self._f = None

    def connect(self):
        self._s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._s.settimeout(self.timeout)
        self._s.connect(self.sock_path)
        self._f = self._s.makefile("r")
        return self

    __enter__ = connect

    def __exit__(self, *a):
        self.close()

    def close(self):
        for x in (self._f, self._s):
            try:
                if x:
                    x.close()
            except Exception:
                pass
        self._f = self._s = None

    def _rpc(self, obj):
        self._s.sendall((json.dumps(obj) + "\n").encode())
        line = self._f.readline()
        if not line:
            raise IOError("sysd closed the connection")
        return json.loads(line)

    # convenience wrappers
    def set(self, key, value):
        return self._rpc({"op": "set", "key": key, "value": value})

    def get(self, key, default=None):
        r = self._rpc({"op": "get", "key": key})
        v = r.get("value")
        return default if v is None else v

    def delete(self, key):
        return self._rpc({"op": "del", "key": key})

    def list(self, prefix=""):
        return self._rpc({"op": "list", "prefix": prefix}).get("keys", {})

    def heartbeat(self, name):
        return self._rpc({"op": "hb", "name": name})

    def hbstat(self):
        return self._rpc({"op": "hbstat"}).get("heartbeats", {})

    def resolve(self, template):
        return self._rpc({"op": "resolve", "template": template}).get("value")

    def stats(self):
        return self._rpc({"op": "stats"}).get("stats", {})

    def subscribe(self, prefix):
        """Subscribe, then iterate events: for evt in c.events(): ..."""
        return self._rpc({"op": "sub", "prefix": prefix})

    def events(self):
        while True:
            line = self._f.readline()
            if not line:
                return
            try:
                obj = json.loads(line)
            except Exception:
                continue
            if obj.get("event"):
                yield obj


# --------------------------------------------------------------------------
def _seed_platform_facts(store):
    """Publish a few boot-time facts so the bus is useful immediately."""
    store.set("sw.sysd.pid", os.getpid())
    store.set("hw.hostname", socket.gethostname())
    try:
        import ffn_hwdetect                      # optional; unified HW autodetect
        inv = ffn_hwdetect.detect()
        store.set("hw.system.product", (inv.get("system") or {}).get("product", ""))
        store.set("hw.cpu.cores", (inv.get("cpu") or {}).get("cores_physical", 0))
        store.set("hw.cpu.threads", (inv.get("cpu") or {}).get("cores_logical", 0))
        store.set("hw.dpu.present", bool((inv.get("dpu") or {}).get("present")))
        store.set("hw.nic.count", len(inv.get("nics") or []))
    except Exception:
        pass


def _serve():
    srv = SysdServer()
    srv.start()
    _seed_platform_facts(srv.store)
    print("ffn-sysd: listening on %s (keys=%d)"
          % (srv.sock_path, len(srv.store.list())), flush=True)
    import signal

    def _sig(*_a):
        srv.stop()
        sys.exit(0)
    signal.signal(signal.SIGTERM, _sig)
    signal.signal(signal.SIGINT, _sig)
    try:
        srv.serve_forever()
    finally:
        srv.stop()


def _selftest():
    """In-process server + client test; no root, no system paths."""
    import tempfile
    d = tempfile.mkdtemp(prefix="ffnsysd")
    sock = os.path.join(d, "s.sock")
    store = SysdStore(state_path=os.path.join(d, "state.json"),
                      vars_path=os.path.join(d, "vars.json"))
    srv = SysdServer(sock_path=sock, store=store)
    srv.start()
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    time.sleep(0.2)
    fails = []

    def chk(cond, msg):
        print(("  ok  " if cond else "  FAIL") + " " + msg)
        if not cond:
            fails.append(msg)

    c = SysdClient(sock).connect()
    chk(c._rpc({"op": "ping"}).get("pong") is True, "ping")
    chk(c.set("hw.cpu.cores", 48).get("ok") is True, "set hw.cpu.cores")
    chk(c.get("hw.cpu.cores") == 48, "get returns 48")
    chk(c.set("cfg.ha.mode", "active-active").get("ok") is True, "set persisted cfg key")
    chk(c.set("bogus.key", 1).get("ok") is False, "reject invalid namespace")
    c.set("dp.offload.state", "detected")
    chk(sorted(c.list("dp.").keys()) == ["dp.offload.state"], "list by prefix")

    # heartbeats
    c.heartbeat("ffn-configd")
    hb = c.hbstat()
    chk("ffn-configd" in hb and hb["ffn-configd"]["stale"] is False, "heartbeat fresh")

    # name service
    chk(c.resolve("cfg.brdagent.$(local.role)") == "cfg.brdagent.mp", "resolve $(local.role)")

    # pub/sub: subscriber sees a change published by another client
    sub = SysdClient(sock).connect()
    sub.subscribe("ha.")
    got = []

    def reader():
        for evt in sub.events():
            got.append(evt)
            return
    rt = threading.Thread(target=reader, daemon=True)
    rt.start()
    time.sleep(0.2)
    c.set("ha.peer_up", True)
    rt.join(timeout=3)
    chk(len(got) == 1 and got[0]["key"] == "ha.peer_up" and got[0]["value"] is True,
        "subscriber received change event")

    # persistence: only cfg.* survives a reload
    store.snapshot(force=True)
    store2 = SysdStore(state_path=os.path.join(d, "state.json"),
                       vars_path=os.path.join(d, "vars.json"))
    chk(store2.get("cfg.ha.mode")[0] == "active-active", "cfg.* persisted across restart")
    chk(store2.get("hw.cpu.cores")[0] is None, "volatile hw.* NOT persisted")

    st = c.stats()
    chk(st.get("keys", 0) >= 4 and st.get("sets", 0) >= 5, "stats sane")
    c.close(); sub.close(); srv.stop()
    print("\n==== ffn-sysd selftest: %d failed ====" % len(fails))
    return 1 if fails else 0


if __name__ == "__main__":
    a = sys.argv[1:]
    if not a or a[0] == "--serve":
        _serve()
    elif a[0] == "--selftest":
        sys.exit(_selftest())
    else:
        with SysdClient() as c:
            if a[0] == "--get":
                print(json.dumps(c.get(a[1])))
            elif a[0] == "--set":
                v = a[2]
                try:
                    v = json.loads(v)
                except Exception:
                    pass
                print(json.dumps(c.set(a[1], v)))
            elif a[0] == "--list":
                print(json.dumps(c.list(a[1] if len(a) > 1 else ""), indent=2))
            elif a[0] == "--hbstat":
                print(json.dumps(c.hbstat(), indent=2))
            elif a[0] == "--stats":
                print(json.dumps(c.stats(), indent=2))
            else:
                print(__doc__)
