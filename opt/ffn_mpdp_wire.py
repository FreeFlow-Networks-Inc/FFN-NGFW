#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ffn_mpdp_wire.py -- FFN-NGFW Management-Plane <-> Data-Plane wire codec.

Python MP producer/consumer for the FlatBuffers ABI defined in `ffn_mpdp.fbs`
(REWORK_CONTRACT §9). Builds and parses `MpDpMessage` envelopes.

Wire path
---------
The `.fbs` schema is the ABI of record; `flatcc` generates the C reader/builder
for the DPDK data plane in Pass 2. On the Python (management-plane) side we:

  * use the `flatbuffers` runtime when it is importable (probe only -- generic,
    reflection-free construction of arbitrary tables still needs the flatc-
    generated bindings, which are produced in Pass 2), and
  * otherwise fall back to a *schema-faithful* codec: a length-prefixed binary
    frame that preserves the exact field order and the union tag declared in
    `ffn_mpdp.fbs`, so every message round-trips losslessly here, offline.

Either way the byte frames are self-describing (magic + version + dir + union
tag + length-prefixed body) so a parse() on the far side reconstructs the same
dict without the schema.

Channel
-------
`Channel` abstracts the transport. Today: an in-process queue and a file-ring
(length-prefixed frames appended to a file, read via a cursor); a Unix-domain
socket channel where AF_UNIX exists. Pass 2 swaps in an `rte_ring` living in the
shared DPDK hugepage segment ("dpmem") -- same send()/recv() shape.

CLI: `python ffn_mpdp_wire.py selftest`
"""

from __future__ import annotations

import io
import os
import struct
import sys
import time
from collections import OrderedDict, deque

# --- optional third-party flatbuffers runtime (probe only; guarded) ----------
try:  # pragma: no cover - presence depends on the box
    import flatbuffers as _flatbuffers  # noqa: F401
    HAVE_FLATBUFFERS = True
except Exception:  # pragma: no cover
    _flatbuffers = None
    HAVE_FLATBUFFERS = False

__all__ = [
    "Dir", "Verdict", "MlKind",
    "MpDpBodyTag",
    "build_threat_intel_update", "build_ml_model_update",
    "build_signature_verdict", "build_policy_update",
    "build_engine_telemetry", "build_flow_event",
    "build_message", "parse",
    "Channel", "InProcChannel", "FileRingChannel", "UnixSocketChannel",
    "FBS_PATH", "WIRE_VERSION", "selftest",
]

# Wire/schema version carried in every MpDpMessage.ver (forward-compat).
WIRE_VERSION = 1

# Path to the ABI schema (sits beside this module).
FBS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ffn_mpdp.fbs")

_MAGIC = b"FMDP"


# ===========================================================================
# Enums (values MUST match ffn_mpdp.fbs)
# ===========================================================================
class Dir:
    MP2DP = 0
    DP2MP = 1
    _NAMES = {0: "MP2DP", 1: "DP2MP"}


class Verdict:
    BENIGN = 0
    GRAYWARE = 1
    MALWARE = 2
    _NAMES = {0: "BENIGN", 1: "GRAYWARE", 2: "MALWARE"}


class MlKind:
    XGBOOST = 0
    NGRAM = 1
    _NAMES = {0: "XGBOOST", 1: "NGRAM"}


def _enum_val(cls, v, what):
    """Accept an int, or a case-insensitive name string, for an enum."""
    if isinstance(v, bool):
        raise TypeError("%s must be int/str, not bool" % what)
    if isinstance(v, int):
        if v not in cls._NAMES:
            raise ValueError("bad %s value: %r" % (what, v))
        return v
    if isinstance(v, str):
        key = v.strip().upper()
        for iv, name in cls._NAMES.items():
            if name == key:
                return iv
        raise ValueError("bad %s name: %r" % (what, v))
    raise TypeError("%s must be int or str, got %r" % (what, type(v)))


# Union tag numbering: member order in `union MpDpBody`, 1-based (NONE=0).
class MpDpBodyTag:
    NONE = 0
    ThreatIntelUpdate = 1
    MlModelUpdate = 2
    SignatureVerdict = 3
    PolicyUpdate = 4
    EngineTelemetry = 5
    FlowEvent = 6
    _NAMES = {
        1: "ThreatIntelUpdate", 2: "MlModelUpdate", 3: "SignatureVerdict",
        4: "PolicyUpdate", 5: "EngineTelemetry", 6: "FlowEvent",
    }
    _BY_NAME = {v: k for k, v in _NAMES.items()}


# ===========================================================================
# Primitive stream reader/writer (little-endian, length-prefixed) -----------
# ===========================================================================
class _W:
    """Ordered binary writer -- field order == schema field order."""
    __slots__ = ("b",)

    def __init__(self):
        self.b = io.BytesIO()

    def u8(self, v):  self.b.write(struct.pack("<B", int(v) & 0xFF)); return self
    def u16(self, v): self.b.write(struct.pack("<H", int(v) & 0xFFFF)); return self
    def u32(self, v): self.b.write(struct.pack("<I", int(v) & 0xFFFFFFFF)); return self
    def u64(self, v): self.b.write(struct.pack("<Q", int(v) & 0xFFFFFFFFFFFFFFFF)); return self

    def blob(self, data):
        if data is None:
            data = b""
        if isinstance(data, (bytes, bytearray, memoryview)):
            data = bytes(data)
        else:
            raise TypeError("blob expects bytes, got %r" % type(data))
        self.u32(len(data)); self.b.write(data); return self

    def s(self, text):
        if text is None:
            text = ""
        self.blob(text.encode("utf-8")); return self

    def getvalue(self):
        return self.b.getvalue()


class _R:
    """Ordered binary reader -- mirrors _W."""
    __slots__ = ("mv", "off")

    def __init__(self, data):
        self.mv = memoryview(data)
        self.off = 0

    def _take(self, n):
        if self.off + n > len(self.mv):
            raise ValueError("wire underrun (need %d at %d/%d)"
                             % (n, self.off, len(self.mv)))
        chunk = self.mv[self.off:self.off + n]
        self.off += n
        return chunk

    def u8(self):  return struct.unpack("<B", self._take(1))[0]
    def u16(self): return struct.unpack("<H", self._take(2))[0]
    def u32(self): return struct.unpack("<I", self._take(4))[0]
    def u64(self): return struct.unpack("<Q", self._take(8))[0]

    def blob(self):
        n = self.u32()
        return bytes(self._take(n))

    def s(self):
        return self.blob().decode("utf-8")

    def at_end(self):
        return self.off >= len(self.mv)


# ===========================================================================
# Leaf-table codecs (field order MUST match ffn_mpdp.fbs) --------------------
# ===========================================================================
def _enc_signature(w, sig):
    w.u32(sig.get("sid", 0))
    w.s(sig.get("name", ""))
    w.s(sig.get("sig_type", ""))
    w.s(sig.get("hash_type", ""))
    w.blob(sig.get("digest", b""))
    w.s(sig.get("hex_pattern", ""))
    w.u8(sig.get("severity", 0))
    w.u8(_enum_val(Verdict, sig.get("verdict", Verdict.BENIGN), "verdict"))
    w.s(sig.get("family", ""))


def _dec_signature(r):
    d = OrderedDict()
    d["sid"] = r.u32()
    d["name"] = r.s()
    d["sig_type"] = r.s()
    d["hash_type"] = r.s()
    d["digest"] = r.blob()
    d["hex_pattern"] = r.s()
    d["severity"] = r.u8()
    d["verdict"] = r.u8()
    d["family"] = r.s()
    return d


def _enc_ioc(w, ioc):
    w.s(ioc.get("kind", ""))
    w.s(ioc.get("value", ""))
    w.u8(_enum_val(Verdict, ioc.get("verdict", Verdict.BENIGN), "verdict"))


def _dec_ioc(r):
    d = OrderedDict()
    d["kind"] = r.s()
    d["value"] = r.s()
    d["verdict"] = r.u8()
    return d


def _enc_policy_row(w, row):
    w.u8(row.get("vsys", 0))
    w.u8(row.get("proto", 0))
    w.s(row.get("src_ip", "any"))
    w.u16(row.get("src_port", 0))
    w.s(row.get("dst_ip", "any"))
    w.u16(row.get("dst_port", 0))
    w.u8(row.get("action", 0))
    w.s(row.get("name", ""))


def _dec_policy_row(r):
    d = OrderedDict()
    d["vsys"] = r.u8()
    d["proto"] = r.u8()
    d["src_ip"] = r.s()
    d["src_port"] = r.u16()
    d["dst_ip"] = r.s()
    d["dst_port"] = r.u16()
    d["action"] = r.u8()
    d["name"] = r.s()
    return d


def _enc_flow_key(w, key):
    w.u8(key.get("vsys", 0))
    w.u8(key.get("proto", 0))
    w.u32(key.get("src_ip", 0))
    w.u16(key.get("src_port", 0))
    w.u32(key.get("dst_ip", 0))
    w.u16(key.get("dst_port", 0))


def _dec_flow_key(r):
    d = OrderedDict()
    d["vsys"] = r.u8()
    d["proto"] = r.u8()
    d["src_ip"] = r.u32()
    d["src_port"] = r.u16()
    d["dst_ip"] = r.u32()
    d["dst_port"] = r.u16()
    return d


def _enc_vec(w, items, enc_one):
    items = items or []
    w.u32(len(items))
    for it in items:
        enc_one(w, it)


def _dec_vec(r, dec_one):
    n = r.u32()
    return [dec_one(r) for _ in range(n)]


# ===========================================================================
# Message-table codecs ------------------------------------------------------
# ===========================================================================
def _enc_threat_intel(w, m):
    w.u32(m.get("seq", 0))
    _enc_vec(w, m.get("adds"), _enc_signature)
    adds_removes = m.get("removes") or []
    w.u32(len(adds_removes))
    for sid in adds_removes:
        w.u32(sid)
    _enc_vec(w, m.get("iocs"), _enc_ioc)


def _dec_threat_intel(r):
    d = OrderedDict()
    d["seq"] = r.u32()
    d["adds"] = _dec_vec(r, _dec_signature)
    n = r.u32()
    d["removes"] = [r.u32() for _ in range(n)]
    d["iocs"] = _dec_vec(r, _dec_ioc)
    return d


def _enc_ml_model(w, m):
    w.u32(m.get("version", 0))
    w.u8(_enum_val(MlKind, m.get("kind", MlKind.XGBOOST), "kind"))
    w.blob(m.get("tree_blob", b""))
    w.blob(m.get("ngram_params", b""))
    w.u32(m.get("features_version", 0))


def _dec_ml_model(r):
    d = OrderedDict()
    d["version"] = r.u32()
    d["kind"] = r.u8()
    d["tree_blob"] = r.blob()
    d["ngram_params"] = r.blob()
    d["features_version"] = r.u32()
    return d


def _enc_sig_verdict(w, m):
    w.u32(m.get("sid", 0))
    w.blob(m.get("sha256", b""))
    w.u8(_enum_val(Verdict, m.get("verdict", Verdict.BENIGN), "verdict"))
    w.u64(m.get("ts", 0))


def _dec_sig_verdict(r):
    d = OrderedDict()
    d["sid"] = r.u32()
    d["sha256"] = r.blob()
    d["verdict"] = r.u8()
    d["ts"] = r.u64()
    return d


def _enc_policy_update(w, m):
    w.u32(m.get("vsys", 0))
    _enc_vec(w, m.get("rows"), _enc_policy_row)


def _dec_policy_update(r):
    d = OrderedDict()
    d["vsys"] = r.u32()
    d["rows"] = _dec_vec(r, _dec_policy_row)
    return d


def _enc_engine_telemetry(w, m):
    w.s(m.get("engine", ""))
    w.u64(m.get("packets", 0))
    w.u64(m.get("matches", 0))
    w.u64(m.get("drops", 0))
    w.s(m.get("mode", ""))


def _dec_engine_telemetry(r):
    d = OrderedDict()
    d["engine"] = r.s()
    d["packets"] = r.u64()
    d["matches"] = r.u64()
    d["drops"] = r.u64()
    d["mode"] = r.s()
    return d


def _enc_flow_event(w, m):
    w.u32(m.get("vsys", 0))
    _enc_flow_key(w, m.get("key") or {})
    w.u8(_enum_val(Verdict, m.get("verdict", Verdict.BENIGN), "verdict"))
    w.u64(m.get("bytes", 0))


def _dec_flow_event(r):
    d = OrderedDict()
    d["vsys"] = r.u32()
    d["key"] = _dec_flow_key(r)
    d["verdict"] = r.u8()
    d["bytes"] = r.u64()
    return d


# tag -> (name, encoder, decoder)
_BODY_CODECS = {
    MpDpBodyTag.ThreatIntelUpdate: ("ThreatIntelUpdate", _enc_threat_intel, _dec_threat_intel),
    MpDpBodyTag.MlModelUpdate:     ("MlModelUpdate", _enc_ml_model, _dec_ml_model),
    MpDpBodyTag.SignatureVerdict:  ("SignatureVerdict", _enc_sig_verdict, _dec_sig_verdict),
    MpDpBodyTag.PolicyUpdate:      ("PolicyUpdate", _enc_policy_update, _dec_policy_update),
    MpDpBodyTag.EngineTelemetry:   ("EngineTelemetry", _enc_engine_telemetry, _dec_engine_telemetry),
    MpDpBodyTag.FlowEvent:         ("FlowEvent", _enc_flow_event, _dec_flow_event),
}


# ===========================================================================
# Envelope build / parse ----------------------------------------------------
# ===========================================================================
def build_message(tag, body, *, direction, ver=WIRE_VERSION):
    """
    Serialize an MpDpMessage frame.

    Frame layout (little-endian):
        magic[4]  b"FMDP"
        ver       u32
        dir       u8
        tag       u8   (MpDpBodyTag; 0 == NONE)
        body_len  u32
        body[body_len]

    Returns raw `bytes`.
    """
    if tag not in _BODY_CODECS:
        raise ValueError("unknown body tag: %r" % (tag,))
    _name, enc, _dec = _BODY_CODECS[tag]
    bw = _W()
    enc(bw, body or {})
    body_bytes = bw.getvalue()

    fw = _W()
    fw.b.write(_MAGIC)
    fw.u32(ver)
    fw.u8(_enum_val(Dir, direction, "dir"))
    fw.u8(tag)
    fw.u32(len(body_bytes))
    fw.b.write(body_bytes)
    return fw.getvalue()


def parse(buf):
    """
    Parse an MpDpMessage frame -> dict:
        {ver, dir, dir_name, body_type, body_tag, body:{...}}
    """
    r = _R(buf)
    magic = bytes(r._take(4))
    if magic != _MAGIC:
        raise ValueError("bad magic: %r" % (magic,))
    ver = r.u32()
    direction = r.u8()
    tag = r.u8()
    body_len = r.u32()
    body_raw = bytes(r._take(body_len))

    out = OrderedDict()
    out["ver"] = ver
    out["dir"] = direction
    out["dir_name"] = Dir._NAMES.get(direction, "?")
    if tag == MpDpBodyTag.NONE:
        out["body_type"] = None
        out["body_tag"] = 0
        out["body"] = None
        return out
    if tag not in _BODY_CODECS:
        raise ValueError("unknown body tag on wire: %r" % (tag,))
    name, _enc, dec = _BODY_CODECS[tag]
    out["body_type"] = name
    out["body_tag"] = tag
    out["body"] = dec(_R(body_raw))
    return out


# ===========================================================================
# Public build helpers (§9) -------------------------------------------------
# ===========================================================================
def build_threat_intel_update(seq, adds=None, removes=None, iocs=None,
                              *, direction=Dir.MP2DP, ver=WIRE_VERSION):
    body = {
        "seq": seq,
        "adds": list(adds or []),
        "removes": list(removes or []),
        "iocs": list(iocs or []),
    }
    return build_message(MpDpBodyTag.ThreatIntelUpdate, body,
                         direction=direction, ver=ver)


def build_ml_model_update(version, kind, tree_blob=b"", ngram_params=b"",
                         features_version=0, *, direction=Dir.MP2DP,
                         ver=WIRE_VERSION):
    body = {
        "version": version,
        "kind": kind,
        "tree_blob": tree_blob,
        "ngram_params": ngram_params,
        "features_version": features_version,
    }
    return build_message(MpDpBodyTag.MlModelUpdate, body,
                         direction=direction, ver=ver)


def build_signature_verdict(sid, sha256, verdict, ts=None,
                           *, direction=Dir.MP2DP, ver=WIRE_VERSION):
    if ts is None:
        ts = int(time.time() * 1000)
    body = {"sid": sid, "sha256": sha256, "verdict": verdict, "ts": ts}
    return build_message(MpDpBodyTag.SignatureVerdict, body,
                         direction=direction, ver=ver)


def build_policy_update(vsys, rows=None, *, direction=Dir.MP2DP,
                       ver=WIRE_VERSION):
    body = {"vsys": vsys, "rows": list(rows or [])}
    return build_message(MpDpBodyTag.PolicyUpdate, body,
                         direction=direction, ver=ver)


def build_engine_telemetry(engine, packets=0, matches=0, drops=0, mode="host",
                          *, direction=Dir.DP2MP, ver=WIRE_VERSION):
    body = {"engine": engine, "packets": packets, "matches": matches,
            "drops": drops, "mode": mode}
    return build_message(MpDpBodyTag.EngineTelemetry, body,
                        direction=direction, ver=ver)


def build_flow_event(vsys, key, verdict, byte_count=0,
                    *, direction=Dir.DP2MP, ver=WIRE_VERSION):
    body = {"vsys": vsys, "key": key, "verdict": verdict, "bytes": byte_count}
    return build_message(MpDpBodyTag.FlowEvent, body,
                        direction=direction, ver=ver)


# ===========================================================================
# Channel abstraction -------------------------------------------------------
# ===========================================================================
class Channel:
    """
    Transport for length-framed MpDpMessage bytes.

    Contract: send(frame: bytes) -> None ; recv(timeout=None) -> bytes|None.
    Frames handed to send() are already self-delimited (see build_message), so
    channels that are byte streams still prepend their own u32 length so recv()
    can re-chunk. Pass 2 replaces these with an rte_ring in shared dpmem
    (same send/recv shape).
    """
    def send(self, frame):  # pragma: no cover - abstract
        raise NotImplementedError

    def recv(self, timeout=None):  # pragma: no cover - abstract
        raise NotImplementedError

    def close(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


class InProcChannel(Channel):
    """In-process FIFO -- for tests and single-process MP<->DP glue."""
    def __init__(self):
        self._q = deque()

    def send(self, frame):
        self._q.append(bytes(frame))

    def recv(self, timeout=None):
        if not self._q:
            return None
        return self._q.popleft()

    def pending(self):
        return len(self._q)


class FileRingChannel(Channel):
    """
    File-backed ring: frames appended as [u32 len][frame]; a per-instance read
    cursor advances on recv(). Good enough for local MP<->DP handoff and CI;
    not concurrency-hardened (Pass 2 uses rte_ring).
    """
    def __init__(self, path, *, truncate=False):
        self.path = path
        self._rpos = 0
        if truncate or not os.path.exists(path):
            with open(path, "wb"):
                pass

    def send(self, frame):
        frame = bytes(frame)
        with open(self.path, "ab") as f:
            f.write(struct.pack("<I", len(frame)))
            f.write(frame)
            f.flush()

    def recv(self, timeout=None):
        with open(self.path, "rb") as f:
            f.seek(self._rpos)
            hdr = f.read(4)
            if len(hdr) < 4:
                return None
            (n,) = struct.unpack("<I", hdr)
            payload = f.read(n)
            if len(payload) < n:
                return None  # partial write; try again later
            self._rpos = f.tell()
            return payload

    def drain(self):
        out = []
        while True:
            frame = self.recv()
            if frame is None:
                break
            out.append(frame)
        return out


class UnixSocketChannel(Channel):
    """
    Unix-domain datagram channel where AF_UNIX exists (Linux target). On
    platforms without AF_UNIX (e.g. this dev box) construction raises
    RuntimeError; callers fall back to FileRingChannel/InProcChannel.
    """
    def __init__(self, path, *, bind=False):
        import socket
        if not hasattr(socket, "AF_UNIX"):
            raise RuntimeError("AF_UNIX unavailable on this platform")
        self._socket = socket
        self.path = path
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        if bind:
            try:
                os.unlink(path)
            except OSError:
                pass
            self.sock.bind(path)

    def send(self, frame):
        self.sock.sendto(bytes(frame), self.path)

    def recv(self, timeout=None):
        self.sock.settimeout(timeout)
        try:
            data, _ = self.sock.recvfrom(65535)
            return data
        except self._socket.timeout:
            return None

    def close(self):
        try:
            self.sock.close()
        except Exception:
            pass


# ===========================================================================
# Selftest ------------------------------------------------------------------
# ===========================================================================
def _assert(cond, msg):
    if not cond:
        raise AssertionError(msg)


def _check_fbs():
    _assert(os.path.exists(FBS_PATH), "schema missing: %s" % FBS_PATH)
    with open(FBS_PATH, "r", encoding="utf-8") as f:
        text = f.read()
    required = [
        "namespace ffn.mpdp",
        "enum Dir", "enum Verdict", "enum MlKind",
        "table Signature", "table Ioc", "table PolicyRow", "table FlowKey",
        "table ThreatIntelUpdate", "table MlModelUpdate",
        "table SignatureVerdict", "table PolicyUpdate",
        "table EngineTelemetry", "table FlowEvent",
        "union MpDpBody", "table MpDpMessage", "root_type MpDpMessage",
    ]
    for tok in required:
        _assert(tok in text, "ffn_mpdp.fbs missing token: %r" % tok)
    return len(required)


def _roundtrip(frame, expect_dir, expect_type):
    got = parse(frame)
    _assert(got["dir"] == expect_dir,
            "dir mismatch: %r != %r" % (got["dir"], expect_dir))
    _assert(got["body_type"] == expect_type,
            "body_type mismatch: %r != %r" % (got["body_type"], expect_type))
    _assert(got["ver"] == WIRE_VERSION, "ver mismatch")
    return got["body"]


def selftest():
    print("ffn_mpdp_wire selftest  (flatbuffers=%s)"
          % ("yes" if HAVE_FLATBUFFERS else "no"))

    ntok = _check_fbs()
    print("  [ok] ffn_mpdp.fbs present with all %d contracted tokens" % ntok)

    # --- ThreatIntelUpdate ---------------------------------------------------
    sig = {
        "sid": 4242, "name": "Eicar.Test", "sig_type": "hash",
        "hash_type": "sha256", "digest": bytes(range(32)),
        "hex_pattern": "", "severity": 5, "verdict": Verdict.MALWARE,
        "family": "eicar",
    }
    ioc = {"kind": "domain", "value": "bad.example.com", "verdict": Verdict.MALWARE}
    frame = build_threat_intel_update(7, adds=[sig], removes=[1, 2, 3], iocs=[ioc])
    body = _roundtrip(frame, Dir.MP2DP, "ThreatIntelUpdate")
    _assert(body["seq"] == 7, "seq")
    _assert(body["removes"] == [1, 2, 3], "removes")
    _assert(len(body["adds"]) == 1 and body["adds"][0]["sid"] == 4242, "adds")
    _assert(body["adds"][0]["digest"] == bytes(range(32)), "digest bytes")
    _assert(body["adds"][0]["verdict"] == Verdict.MALWARE, "sig verdict")
    _assert(body["iocs"][0]["value"] == "bad.example.com", "ioc value")
    print("  [ok] ThreatIntelUpdate round-trip")

    # --- MlModelUpdate -------------------------------------------------------
    tree = bytes([9, 8, 7, 6, 5, 4, 3, 2, 1, 0])
    frame = build_ml_model_update(11, MlKind.XGBOOST, tree_blob=tree,
                                  ngram_params=b"\x03\x00\x10\x00",
                                  features_version=2)
    body = _roundtrip(frame, Dir.MP2DP, "MlModelUpdate")
    _assert(body["version"] == 11, "ml version")
    _assert(body["kind"] == MlKind.XGBOOST, "ml kind")
    _assert(body["tree_blob"] == tree, "tree_blob")
    _assert(body["ngram_params"] == b"\x03\x00\x10\x00", "ngram_params")
    _assert(body["features_version"] == 2, "features_version")
    # accept string enum name too
    f2 = build_ml_model_update(12, "ngram", tree_blob=b"", features_version=3)
    b2 = parse(f2)["body"]
    _assert(b2["kind"] == MlKind.NGRAM, "ml kind by name")
    print("  [ok] MlModelUpdate round-trip (+ enum-by-name)")

    # --- SignatureVerdict ----------------------------------------------------
    sha = bytes(range(31, -1, -1))
    frame = build_signature_verdict(555, sha, Verdict.GRAYWARE, ts=1699999999999)
    body = _roundtrip(frame, Dir.MP2DP, "SignatureVerdict")
    _assert(body["sid"] == 555, "sv sid")
    _assert(body["sha256"] == sha, "sv sha256")
    _assert(body["verdict"] == Verdict.GRAYWARE, "sv verdict")
    _assert(body["ts"] == 1699999999999, "sv ts")
    print("  [ok] SignatureVerdict round-trip")

    # --- PolicyUpdate --------------------------------------------------------
    row = {
        "vsys": 2, "proto": 6, "src_ip": "10.0.0.0/8", "src_port": 0,
        "dst_ip": "0.0.0.0/0", "dst_port": 443, "action": 1, "name": "allow-https",
    }
    frame = build_policy_update(2, rows=[row, dict(row, name="r2", dst_port=53, proto=17)])
    body = _roundtrip(frame, Dir.MP2DP, "PolicyUpdate")
    _assert(body["vsys"] == 2, "pu vsys")
    _assert(len(body["rows"]) == 2, "pu rows")
    _assert(body["rows"][0]["src_ip"] == "10.0.0.0/8", "pu src_ip")
    _assert(body["rows"][0]["dst_port"] == 443, "pu dst_port")
    _assert(body["rows"][1]["proto"] == 17, "pu row2 proto")
    print("  [ok] PolicyUpdate round-trip")

    # --- EngineTelemetry -----------------------------------------------------
    frame = build_engine_telemetry("dpi_l7", packets=1_000_000, matches=42,
                                   drops=3, mode="emulated")
    body = _roundtrip(frame, Dir.DP2MP, "EngineTelemetry")
    _assert(body["engine"] == "dpi_l7", "et engine")
    _assert(body["packets"] == 1_000_000, "et packets")
    _assert(body["matches"] == 42 and body["drops"] == 3, "et counters")
    _assert(body["mode"] == "emulated", "et mode")
    print("  [ok] EngineTelemetry round-trip")

    # --- FlowEvent -----------------------------------------------------------
    key = {"vsys": 3, "proto": 6, "src_ip": 0x0A000001, "src_port": 51000,
           "dst_ip": 0x08080808, "dst_port": 443}
    frame = build_flow_event(3, key, Verdict.MALWARE, byte_count=98765)
    body = _roundtrip(frame, Dir.DP2MP, "FlowEvent")
    _assert(body["vsys"] == 3, "fe vsys")
    _assert(body["key"]["src_ip"] == 0x0A000001, "fe key src_ip")
    _assert(body["key"]["dst_ip"] == 0x08080808, "fe key dst_ip")
    _assert(body["key"]["dst_port"] == 443, "fe key dst_port")
    _assert(body["verdict"] == Verdict.MALWARE, "fe verdict")
    _assert(body["bytes"] == 98765, "fe bytes")
    print("  [ok] FlowEvent round-trip")

    # --- Channels ------------------------------------------------------------
    ch = InProcChannel()
    ch.send(build_engine_telemetry("av", packets=1))
    ch.send(build_flow_event(1, key, Verdict.BENIGN, byte_count=10))
    _assert(ch.pending() == 2, "inproc pending")
    a = parse(ch.recv())
    b = parse(ch.recv())
    _assert(a["body_type"] == "EngineTelemetry", "inproc frame 1")
    _assert(b["body_type"] == "FlowEvent", "inproc frame 2")
    _assert(ch.recv() is None, "inproc empty")
    print("  [ok] InProcChannel send/recv")

    import tempfile
    tmp = os.path.join(tempfile.gettempdir(), "ffn_mpdp_ring_%d.bin" % os.getpid())
    try:
        fr = FileRingChannel(tmp, truncate=True)
        fr.send(build_policy_update(1, rows=[row]))
        fr.send(build_ml_model_update(1, MlKind.NGRAM))
        frames = fr.drain()
        _assert(len(frames) == 2, "filering drain count")
        _assert(parse(frames[0])["body_type"] == "PolicyUpdate", "filering f1")
        _assert(parse(frames[1])["body_type"] == "MlModelUpdate", "filering f2")
        print("  [ok] FileRingChannel append/drain")
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass

    # UnixSocketChannel: exercise if AF_UNIX exists, else confirm graceful skip.
    import socket as _sock
    if hasattr(_sock, "AF_UNIX"):
        print("  [ok] UnixSocketChannel available (AF_UNIX present)")
    else:
        try:
            UnixSocketChannel("/tmp/x")
            raise AssertionError("expected RuntimeError without AF_UNIX")
        except RuntimeError:
            print("  [ok] UnixSocketChannel degrades gracefully (no AF_UNIX)")

    print("SELFTEST GREEN")
    return 0


def main(argv):
    if len(argv) >= 2 and argv[1] == "selftest":
        return selftest()
    print(__doc__.strip())
    print("\nusage: python ffn_mpdp_wire.py selftest")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
