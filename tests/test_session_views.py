"""The session views read the platform's dataplane session inventory when it is ready.

`/api/dashboard/sessions` and `/api/monitor/sessions` serve the same inventory
(the PA-5200's FE100 observation feed) so the counters and the browser agree;
without a ready stream they keep their management-plane fallbacks and say so.
"""
import asyncio
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

_tmp = tempfile.TemporaryDirectory(prefix="ffn-session-views-")
os.environ["FFN_DB_PATH"] = str(Path(_tmp.name) / "config.db")
os.environ["FFN_CONFIG_DIR"] = str(Path(_tmp.name) / "config")
os.environ["FFN_JWT_SECRET"] = "session-views-test-only-signing-secret"
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "opt"))
import ffn_manager as m  # noqa: E402

USER = {"username": "test", "role": "admin"}


def run(coro):
    return asyncio.run(coro)


def fake_views(ready=True, entries=None, raise_entry=None):
    """A stand-in for the platform's session_inventory module."""
    rows = entries if entries is not None else [
        dict(id="a" * 64, short_id="a" * 12, ct=1, proto=6, protocol="tcp", src="192.0.2.1", sport=1234,
             dst="198.51.100.1", dport=443, nat=dict(source=False, destination=False), rule="allow-web",
             vsys="vsys1", state=3, state_name="ESTABLISHED", ttl=100, bytes=dict(c2s=10, s2c=20),
             packets=dict(c2s=1, s2c=2), candidate=True, blockers=[], l3=None, offload="candidate", age_seconds=5)]
    summary = dict(source="dataplane-session-stream", mode="observation-only", hardware_admission=False,
                   available=True, fresh=ready, ready=ready, sessions=3047 if ready else None, tcp=2000, udp=1000,
                   other=47, software_candidates=1038, l3_candidates=0, hardware_admitted=0, blocked=2009,
                   max_sessions=262144, capacity_percent=1.16, sequence=1234, policy_revision=12,
                   cp_acknowledged=ready, blockers={"inspection-required": 900},
                   reason=None if ready else "awaiting snapshot")
    mod = types.ModuleType("session_inventory")
    mod.calls = []

    def summary_fn():
        return dict(summary)

    def entries_fn(limit=100, offset=0, query=None, vsys=None, offload_filter=None, protocol=None):
        mod.calls.append(dict(limit=limit, offset=offset, query=query, vsys=vsys, offload_filter=offload_filter,
                              protocol=protocol))
        if offload_filter not in (None, "candidate", "blocked", "l3-ready"):
            raise ValueError("offload filter must be one of candidate, blocked, l3-ready")
        return dict(source="dataplane-session-stream", mode="observation-only", hardware_admission=False,
                    available=True, fresh=ready, ready=ready, age_seconds=0.5, sequence=1234,
                    counters=dict(sessions=len(rows), software_candidates=1, l3_candidates=0, hardware_admitted=0,
                                  blocked=0, tcp=1, udp=0, other=0, nat_source=0, nat_destination=0, blockers={}),
                    limits=dict(conntrack_max=262144, stream_capacity=8192),
                    reason=None if ready else "awaiting snapshot", total=len(rows), matched=len(rows),
                    entries=rows[offset:offset + limit] if ready else [])

    def entry_fn(identity):
        if raise_entry:
            raise raise_entry
        found = [r for r in rows if r["id"].startswith(identity)]
        return dict(available=True, fresh=ready, ready=ready, source="dataplane-session-stream",
                    session=found[0] if found and ready else None, reason=None if ready else "awaiting snapshot")

    def breakdown_fn():
        return dict(tcp_established=1900, tcp_other=100, udp=1000, icmp=0, other=47)

    mod.summary, mod.entries, mod.entry, mod.breakdown = summary_fn, entries_fn, entry_fn, breakdown_fn
    return mod


class DashboardSessionsTests(unittest.TestCase):
    def test_ready_stream_supplies_the_headline_count_capacity_and_offload_counters(self):
        with patch.object(m, "platform_mod", lambda name: fake_views() if name == "session_inventory" else None):
            value = run(m.dashboard_sessions(breakdown=True, vsys=None, user=USER))
        self.assertEqual((value["active"], value["max_sessions"], value["source"]), (3047, 262144, "dataplane-session-stream"))
        self.assertEqual(value["capacity_percent"], round(3047 / 262144 * 100, 2))
        self.assertEqual((value["tcp"], value["udp"], value["software_candidates"], value["hardware_admitted"]), (2000, 1000, 1038, 0))
        self.assertEqual(value["breakdown"]["tcp_established"], 1900)
        self.assertTrue(value["stream"]["ready"]);
        self.assertFalse(value["stream"]["hardware_admission"])
        # the MP's own conntrack numbers stay visible under their own name
        self.assertIn("conntrack_count", value)

    def test_unready_stream_keeps_the_fallback_and_reports_why(self):
        with patch.object(m, "platform_mod", lambda name: fake_views(ready=False) if name == "session_inventory" else None):
            value = run(m.dashboard_sessions(breakdown=False, vsys=None, user=USER))
        self.assertNotEqual(value["source"], "dataplane-session-stream")
        self.assertEqual(value["active"], value["conntrack_count"])
        self.assertEqual(value["stream"]["reason"], "awaiting snapshot")
        self.assertFalse(value["stream"]["ready"])

    def test_platform_without_a_stream_is_unchanged(self):
        with patch.object(m, "platform_mod", lambda name: None):
            value = run(m.dashboard_sessions(breakdown=False, vsys=None, user=USER))
        self.assertNotIn("stream", value)

    def test_a_failing_reader_never_fails_the_page(self):
        broken = types.ModuleType("session_inventory")
        broken.summary = lambda: (_ for _ in ()).throw(RuntimeError("report unreadable"))
        with patch.object(m, "platform_mod", lambda name: broken if name == "session_inventory" else None):
            value = run(m.dashboard_sessions(breakdown=False, vsys=None, user=USER))
        self.assertFalse(value["stream"]["ready"]);
        self.assertIn("active", value)


class SessionBrowserTests(unittest.TestCase):
    def test_ready_stream_serves_the_filtered_inventory(self):
        views = fake_views()
        with patch.object(m, "platform_mod", lambda name: views if name == "session_inventory" else None):
            value = run(m.monitor_sessions(limit=50, offset=0, vsys="vsys1", q="198.51", offload="candidate",
                                           protocol="tcp", user=USER))
        self.assertEqual(value["source"], "dataplane-session-stream")
        self.assertEqual(len(value["entries"]), 1);
        self.assertEqual(value["entries"][0]["offload"], "candidate")
        self.assertEqual(value["counters"]["sessions"], 1);
        self.assertEqual((value["vsys"], value["vsys_scoped"]), ("vsys1", True))
        self.assertEqual(views.calls[-1], dict(limit=50, offset=0, query="198.51", vsys="vsys1",
                                               offload_filter="candidate", protocol="tcp"))

    def test_bad_filter_is_a_client_error_and_limits_are_bounded(self):
        views = fake_views()
        with patch.object(m, "platform_mod", lambda name: views if name == "session_inventory" else None):
            with self.assertRaises(m.HTTPException) as caught:
                run(m.monitor_sessions(limit=10, offset=0, vsys=None, q=None, offload="hardware", protocol=None, user=USER))
            self.assertEqual(caught.exception.status_code, 400)
            run(m.monitor_sessions(limit=99999, offset=-5, vsys=None, q=None, offload=None, protocol=None, user=USER))
        self.assertEqual((views.calls[-1]["limit"], views.calls[-1]["offset"]), (5000, 0))

    def test_unready_stream_falls_back_and_carries_the_reason(self):
        with patch.object(m, "platform_mod", lambda name: fake_views(ready=False) if name == "session_inventory" else None), \
             patch.object(m, "_live_connections", lambda limit: [{"proto": "tcp", "local": "a", "remote": "b", "state": "ESTABLISHED", "pid": 1, "process": "x"}]), \
             patch.object(m, "controld", None):
            value = run(m.monitor_sessions(limit=10, offset=0, vsys=None, q=None, offload=None, protocol=None, user=USER))
        self.assertEqual(value["source"], "psutil");
        self.assertEqual(len(value["entries"]), 1)
        self.assertEqual(value["stream"]["reason"], "awaiting snapshot")

    def test_session_detail_by_identity(self):
        with patch.object(m, "platform_mod", lambda name: fake_views() if name == "session_inventory" else None):
            value = run(m.monitor_session("aaaaaaaa", user=USER))
            self.assertEqual(value["session"]["rule"], "allow-web")
            with self.assertRaises(m.HTTPException) as caught:
                run(m.monitor_session("ffffffff", user=USER))
            self.assertEqual(caught.exception.status_code, 404)
        with patch.object(m, "platform_mod", lambda name: fake_views(ready=False) if name == "session_inventory" else None):
            with self.assertRaises(m.HTTPException) as caught:
                run(m.monitor_session("aaaaaaaa", user=USER))
            self.assertEqual(caught.exception.status_code, 503)
        with patch.object(m, "platform_mod", lambda name: fake_views(raise_entry=ValueError("bad id")) if name == "session_inventory" else None):
            with self.assertRaises(m.HTTPException) as caught:
                run(m.monitor_session("zz", user=USER))
            self.assertEqual(caught.exception.status_code, 400)
        with patch.object(m, "platform_mod", lambda name: None):
            with self.assertRaises(m.HTTPException) as caught:
                run(m.monitor_session("aaaaaaaa", user=USER))
            self.assertEqual(caught.exception.status_code, 404)


if __name__ == "__main__":
    unittest.main()
