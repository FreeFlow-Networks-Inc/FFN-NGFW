"""
ffn_controld_client — Python client library for ffn-controld IPC.

Used by trusted management handlers for privileged unix-socket calls.
The console uses ffn_cli_transport and controld's separate authenticated
console socket. That transport never falls back to the web listener.
"""

import json
import os
import socket
import threading
import uuid
from typing import Any, Optional

DEFAULT_SOCKET = os.getenv("FFN_CONTROLD_SOCKET", "/var/run/ffn-ngfw/controld.sock")


class ControldClient:
    def __init__(self, socket_path: str = DEFAULT_SOCKET, timeout: float = 5.0):
        self.socket_path = socket_path
        self.timeout = timeout
        self._lock = threading.Lock()  # serialise per-client to keep the stream coherent

    def available(self) -> bool:
        return os.path.exists(self.socket_path)

    def call(self, cmd: str, **args) -> dict:
        """Synchronous call. Returns the full response dict ({ok, data, error, ...})."""
        if not self.available():
            return {"ok": False, "error": f"controld socket not present: {self.socket_path}"}

        msg = {"id": uuid.uuid4().hex[:8], "cmd": cmd, "args": args}
        with self._lock:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            try:
                s.connect(self.socket_path)
                s.sendall((json.dumps(msg) + "\n").encode())
                data = b""
                while not data.endswith(b"\n"):
                    chunk = s.recv(65536)
                    if not chunk:
                        break
                    data += chunk
                    if len(data) > 2 * 1024 * 1024:
                        raise ValueError('controld response exceeds limit')
                if not data:
                    return {"ok": False, "error": "empty response"}
                if not data.endswith(b'\n'):
                    raise ValueError('incomplete controld response')
                response = json.loads(data.decode())
                if not isinstance(response, dict) or response.get('id') != msg['id']:
                    raise ValueError('controld response identity mismatch')
                return response
            except Exception as exc:
                return {"ok": False, "error": str(exc)}
            finally:
                s.close()

    # Convenience helpers

    def query(self, path: str, **args) -> Any:
        r = self.call(path, **args)
        if not r.get("ok"):
            raise RuntimeError(r.get("error", "controld error"))
        return r.get("data")

    # High-level wrappers so callers don't need to remember paths

    def interfaces(self):          return self.query("state/interfaces")
    def routes(self):              return self.query("state/routes")
    def arp(self):                 return self.query("state/arp")
    def sessions(self):            return self.query("state/sessions")
    def routing_protocols(self):   return self.query("state/routing-protocols")
    def zerotier_peers(self):      return self.query("state/zerotier/peers")
    def zerotier_networks(self):   return self.query("state/zerotier/networks")
    def ipsec_sas(self):           return self.query("state/ipsec/sas")
    def capabilities(self):        return self.query("system/capabilities")
    def control_status(self):      return self.query("state/control")
    def agents(self):              return self.query("state/agents")
    def control_events(self):      return self.query("state/control-events")
    def plane_request(self, request):
        # Mutations may take 125 seconds. Retain the caller's durable request ID.
        return ControldClient(self.socket_path, 130).query('plane/request', request=request)
    def lock_status(self):         return self.query("commit/lock/status")
    def acquire_lock(self, user, reason="commit"): return self.query("commit/lock/acquire", user=user, reason=reason)
    def release_lock(self, user):  return self.query("commit/lock/release", user=user)
    def apply_config(self):        return self.query("commit/apply")
    def apply_status(self):        return self.query("commit/apply-status")
    def route_add(self, destination, next_hop, interface="", metric=100):
        return self.query("route/add", destination=destination, next_hop=next_hop,
                          interface=interface, metric=metric)
    def route_del(self, destination):
        return self.query("route/del", destination=destination)
    def ping(self, target):        return self.query("diag/ping", target=target)
    # Data-plane daemon (ffn-dpd) proxy
    def dpd_status(self):          return self.query("dpd/status")
    def dpd_sessions(self, limit=200): return self.query("dpd/sessions", limit=limit)
    def dpd_rules(self):           return self.query("dpd/rules")
    def dpd_hits(self):            return self.query("dpd/hits")
    def dpd_reload(self, reason="manual"): return self.query("dpd/reload", reason=reason)


# Process-global singleton — cheap, connections are per-call
_default: Optional[ControldClient] = None


def get() -> ControldClient:
    global _default
    if _default is None:
        _default = ControldClient()
    return _default
