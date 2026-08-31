"""
ffn_license.py — host-side (cardless) licensing for FFN-NGFW.

This is the software-first counterpart to the C verifier
(`opt_ffn-ngfw/licensing/ffn-license-verify.c`) and the FPGA-bound DNA
path in `ffn_manager/fpga.py`.  It implements REWORK_CONTRACT §4:

  * ``HostIdentity``  — the NEW card-independent ``h1`` host DNA:
        SHA-256("h1|machine_id=..|product_uuid=..|board_serial=..|
                 product_serial=..|permmac=..")[:12]
    with the SAME rules as the frozen ``v1`` synthetic DNA (fixed field
    order, omit-if-missing, DMI ignore-set, first non-lo PERMANENT MAC),
    but with NO PCI/FPGA field.  ``v1`` stays byte-frozen and is never
    touched here.

  * ``Token``         — parse an FFN-LIC1 84-byte payload (+ variable sig).

  * ``verify()``      — Python ECDSA-P384 verification of the master
    signature over payload bytes[0:84] against
    ``/etc/ffn-ngfw/master.p384.pub`` (self-describing 144-byte blob,
    curve_id byte 0 == 4).  Mirrors the C verifier's accept logic:
    accept iff signer_id is all-zero (master) AND the signature is valid
    AND ``token.dna`` matches ANY live/candidate DNA AND the token is not
    expired.  The vendor / Ed25519 path is a Pass-1 stub (see followups).

  * ``HostLicense``   — scan ``/etc/ffn-ngfw/licenses/*.lic``, verify each
    against the ``h1`` host DNA, cache accepted 84-byte payloads to
    ``/var/lib/ffn-ngfw/licenses.cache``, and expose ``query()`` /
    ``status()`` / ``host_dna_info()`` / ``reload()``.

The ABI (FFN-LIC1 84-byte layout, feature IDs, sig algs) is FROZEN — see
``libngfw/include/ngfw/ngfw_regs.h`` in platform/vu9p (FFN-NGFW-FPGA submodule).
Nothing here renumbers it.

Pass 1: pure Python, locally testable via ``python ffn_license.py selftest``.
"""

from __future__ import annotations

import hashlib
import os
import struct
import time
from pathlib import Path
from typing import List, Optional

# ---------------------------------------------------------------------------
# Optional crypto backend.  Guard the import so this module still imports and
# py_compiles on a box without `cryptography`; verify() then hard-fails closed
# and selftest skips-with-note.
# ---------------------------------------------------------------------------
try:
    from cryptography.hazmat.primitives import hashes as _hashes
    from cryptography.hazmat.primitives.asymmetric import ec as _ec
    from cryptography.hazmat.primitives.asymmetric.utils import (
        decode_dss_signature as _decode_dss_signature,
        encode_dss_signature as _encode_dss_signature,
    )
    from cryptography.exceptions import InvalidSignature as _InvalidSignature

    CRYPTO_OK = True
    CRYPTO_ERR = ""
except Exception as _exc:  # pragma: no cover - environment dependent
    CRYPTO_OK = False
    CRYPTO_ERR = f"{type(_exc).__name__}: {_exc}"


# ---------------------------------------------------------------------------
# Frozen ABI constants (mirror ngfw_regs.h in platform/vu9p (FFN-NGFW-FPGA submodule) —
# do NOT renumber)
# ---------------------------------------------------------------------------
NGFW_LIC_MAGIC = b"FFN-LIC1"
NGFW_LIC_VERSION = 1
NGFW_LIC_PAYLOAD_BYTES = 84
NGFW_DEVICE_DNA_BYTES = 12
NGFW_SIGNER_ID_BYTES = 16

# Signature algorithms
NGFW_SIG_ALG_NONE = 0
NGFW_SIG_ALG_ED25519 = 1
NGFW_SIG_ALG_ECDSA_P521 = 3
NGFW_SIG_ALG_ECDSA_P384 = 4  # master trust root (P-384 / SHA-384)
NGFW_SIG_ALG_ECDSA_P256 = 5

NGFW_SIG_BYTES_ECDSA_P384 = 96  # 48 (r) + 48 (s)
_P384_SCALAR_BYTES = 48

# Master pubkey blob layout (self-describing 144-byte blob)
NGFW_MASTER_PUBKEY_BLOB_BYTES = 144
NGFW_MASTER_PUBKEY_CURVE_OFFSET = 0
NGFW_MASTER_PUBKEY_POINT_OFFSET = 1
NGFW_PUBKEY_BYTES_ECDSA_P384 = 97  # 0x04 || X(48) || Y(48)

# License flags
NGFW_LIC_FLAG_EVALUATION = 1 << 0
NGFW_LIC_FLAG_NONTRANSFER = 1 << 1
NGFW_LIC_FLAG_REVOKED = 1 << 2

# Feature IDs (top-level).  Engine licenses use the engine slot (<12).
NGFW_LIC_FEAT_BASE = 0x100
NGFW_LIC_FEAT_TIER_10G = 0x101
NGFW_LIC_FEAT_TIER_40G = 0x102
NGFW_LIC_FEAT_TIER_100G = 0x103
NGFW_LIC_FEAT_TIER_400G = 0x104
NGFW_LIC_FEAT_VSYS_EXPAND = 0x110
NGFW_LIC_FEAT_PQC = 0x111
NGFW_LIC_FEAT_THREAT_FEED = 0x120
# NEW (contract §4): accelerator / FPGA-offload entitlement.  Bound to card
# DNA only — the host NEVER grants this (only a present card can).
NGFW_LIC_FEAT_ACCEL = 0x130

# feature_id -> tier line rate in Gbps
_TIER_GBPS = {
    NGFW_LIC_FEAT_TIER_10G: 10,
    NGFW_LIC_FEAT_TIER_40G: 40,
    NGFW_LIC_FEAT_TIER_100G: 100,
    NGFW_LIC_FEAT_TIER_400G: 400,
}

_MASTER_SIGNER_ZERO = b"\x00" * NGFW_SIGNER_ID_BYTES


# ---------------------------------------------------------------------------
# Filesystem paths (env-overridable, matching routers/licensing.py conventions)
# ---------------------------------------------------------------------------
LIC_DIR = Path(os.environ.get("NGFW_LICENSE_DIR", "/etc/ffn-ngfw/licenses"))
MASTER_PUB = Path(os.environ.get("NGFW_MASTER_PUBKEY", "/etc/ffn-ngfw/master.p384.pub"))
CACHE_PATH = Path(os.environ.get("NGFW_LICENSE_CACHE", "/var/lib/ffn-ngfw/licenses.cache"))

# DMI values that mean "not really set" — identical set to the v1 canonical form.
_DMI_IGNORE = {
    "",
    "to be filled by o.e.m.",
    "default string",
    "none",
    "0",
    "system serial number",
}


# ---------------------------------------------------------------------------
# Low-level identifier readers
# ---------------------------------------------------------------------------
def _read_first_line(path: str) -> str:
    try:
        with open(path) as f:
            return f.readline().strip()
    except (OSError, ValueError):
        return ""


def _machine_id() -> str:
    """systemd machine-id (D-Bus fallback).  Not a DMI field, so only the
    empty check applies."""
    v = _read_first_line("/etc/machine-id")
    if not v:
        v = _read_first_line("/var/lib/dbus/machine-id")
    return v


def _ethtool_perm_addr(ifname: str) -> str:
    """
    Read the PERMANENT hardware MAC of ``ifname`` via the ETHTOOL_GPERMADDR
    ioctl (SIOCETHTOOL).  Returns 'aa:bb:..:ff' or '' on any failure / all-zero.

    This is the primary source (per contract): the permanent address is stable
    across bonding, macvlan, and admin MAC overrides, unlike the running
    address in /sys/class/net/<if>/address.
    """
    try:
        import array
        import fcntl
        import socket
    except Exception:
        return ""

    SIOCETHTOOL = 0x8946
    ETHTOOL_GPERMADDR = 0x00000020
    MAX_ADDR = 6

    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # struct ethtool_perm_addr { __u32 cmd; __u32 size; __u8 data[size]; }
        ecmd = array.array(
            "B", struct.pack("II", ETHTOOL_GPERMADDR, MAX_ADDR) + b"\x00" * MAX_ADDR
        )
        # struct ifreq: char ifr_name[16]; union { void *ifr_data; ... }
        ifr = struct.pack("16sP", ifname.encode(), ecmd.buffer_info()[0])
        fcntl.ioctl(s.fileno(), SIOCETHTOOL, ifr)
        _cmd, size = struct.unpack("II", ecmd[:8].tobytes())
        if size <= 0:
            return ""
        data = ecmd[8 : 8 + min(size, MAX_ADDR)].tobytes()
        return ":".join(f"{b:02x}" for b in data[:MAX_ADDR])
    except (OSError, AttributeError, ValueError):
        return ""
    finally:
        try:
            if s is not None:
                s.close()
        except OSError:
            pass


def _first_permanent_mac() -> str:
    """
    First non-loopback PERMANENT MAC, deterministic by sorted interface name.
    Tries ethtool GPERMADDR, falls back to /sys/class/net/<if>/address per
    interface.  Returns 'aa:bb:..:ff' or ''.
    """
    try:
        ifs = sorted(os.listdir("/sys/class/net"))
    except OSError:
        ifs = []
    for ifc in ifs:
        if ifc == "lo":
            continue
        mac = _ethtool_perm_addr(ifc)
        if not mac or mac == "00:00:00:00:00:00":
            mac = _read_first_line(f"/sys/class/net/{ifc}/address")
        if mac and mac != "00:00:00:00:00:00":
            return mac
    return ""


# ---------------------------------------------------------------------------
# h1 host DNA
# ---------------------------------------------------------------------------
#
# CANONICAL h1 wire format (card-independent)
# -------------------------------------------
#   h1|machine_id=<x>|product_uuid=<x>|board_serial=<x>|product_serial=<x>
#     |permmac=<aa:bb:..:ff>
#
# Rules (identical to v1 except NO pci/mac-fpga fields, and the "h1" prefix):
#   * FIXED field order (the list below).
#   * Missing / ignored fields are OMITTED (never blank).
#   * Values read raw (strip trailing newline only); DMI ignore-set applies.
#   * Full text -> SHA-256 -> first 12 bytes -> DNA.
#
# `_synthesize_dna` (v1) is FROZEN and lives in ffn_manager/fpga.py; this is a
# separate, additive identity and must never be confused with it.
#
# (out_key, source)  — source is a /sys path (str) or a zero-arg callable.
_H1_FIELDS = (
    ("machine_id", _machine_id),
    ("product_uuid", "/sys/class/dmi/id/product_uuid"),
    ("board_serial", "/sys/class/dmi/id/board_serial"),
    ("product_serial", "/sys/class/dmi/id/product_serial"),
    ("permmac", _first_permanent_mac),
)


class HostIdentity:
    """
    Compute the card-independent ``h1`` host DNA.

    Deterministic per physical machine; changes if the board / machine-id /
    primary NIC changes (soft anti-cloning).  Contains NO FPGA/PCI identifier
    so it is meaningful with no card present.
    """

    def __init__(self) -> None:
        self._stream: Optional[str] = None
        self._dna_hex: Optional[str] = None

    # -- construction ------------------------------------------------------
    def stream(self) -> str:
        """Return the canonical 'h1|...' text stream (may be just 'h1')."""
        if self._stream is not None:
            return self._stream
        parts = ["h1"]
        for key, source in _H1_FIELDS:
            if callable(source):
                val = source()
            else:
                val = _read_first_line(source)
            if not val:
                continue
            if key == "permmac":
                if val == "00:00:00:00:00:00":
                    continue
            elif val.lower() in _DMI_IGNORE:
                continue
            parts.append(f"{key}={val}")
        self._stream = "|".join(parts)
        return self._stream

    def dna_bytes(self) -> bytes:
        """12-byte h1 DNA, or b'' if no identifiers were readable."""
        stream = self.stream()
        if "|" not in stream:  # only the "h1" prefix -> nothing usable
            return b""
        return hashlib.sha256(stream.encode("utf-8")).digest()[:NGFW_DEVICE_DNA_BYTES]

    def dna_hex(self) -> str:
        """':'-separated hex (12 bytes) or '' if unavailable."""
        if self._dna_hex is not None:
            return self._dna_hex
        d = self.dna_bytes()
        self._dna_hex = ":".join(f"{b:02x}" for b in d) if d else ""
        return self._dna_hex

    def info(self) -> dict:
        d = self.dna_hex()
        return {"dna_hex": d, "valid": bool(d), "source": "host-h1"}


# ---------------------------------------------------------------------------
# Token parsing
# ---------------------------------------------------------------------------
def _dna_to_hex(dna: bytes) -> str:
    return ":".join(f"{b:02x}" for b in dna)


def _dna_from_any(dna) -> bytes:
    """Normalize a DNA given as bytes or ':'-hex / bare-hex string to 12 bytes."""
    if isinstance(dna, (bytes, bytearray)):
        return bytes(dna[:NGFW_DEVICE_DNA_BYTES])
    if isinstance(dna, str):
        h = dna.replace(":", "").strip()
        try:
            return bytes.fromhex(h)[:NGFW_DEVICE_DNA_BYTES]
        except ValueError:
            return b""
    return b""


class Token:
    """
    A parsed FFN-LIC1 license token.

    Layout (little-endian), signed region = bytes[0:84]:
        0   8   magic "FFN-LIC1"
        8   4   version
       12  12   dna
       24   4   feature_id
       28   4   subfeature_id
       32   8   issued_unix_s
       40   8   expiry_unix_s
       48   4   flags
       52  16   signer_id (master == all-zero)
       68   4   sig_alg
       72  12   reserved
       84   ..  sig  (raw r||s for ECDSA)
    """

    __slots__ = (
        "raw",
        "payload",
        "magic",
        "version",
        "dna",
        "feature_id",
        "subfeature_id",
        "issued_unix_s",
        "expiry_unix_s",
        "flags",
        "signer_id",
        "sig_alg",
        "reserved",
        "sig",
    )

    def __init__(self, blob: bytes) -> None:
        if len(blob) < NGFW_LIC_PAYLOAD_BYTES:
            raise ValueError(
                f"token too short: {len(blob)} < {NGFW_LIC_PAYLOAD_BYTES}"
            )
        self.raw = bytes(blob)
        self.payload = self.raw[:NGFW_LIC_PAYLOAD_BYTES]
        self.sig = self.raw[NGFW_LIC_PAYLOAD_BYTES:]

        b = self.payload
        self.magic = b[0:8]
        self.version = struct.unpack_from("<I", b, 8)[0]
        self.dna = b[12:24]
        self.feature_id = struct.unpack_from("<I", b, 24)[0]
        self.subfeature_id = struct.unpack_from("<I", b, 28)[0]
        self.issued_unix_s = struct.unpack_from("<Q", b, 32)[0]
        self.expiry_unix_s = struct.unpack_from("<Q", b, 40)[0]
        self.flags = struct.unpack_from("<I", b, 48)[0]
        self.signer_id = b[52:68]
        self.sig_alg = struct.unpack_from("<I", b, 68)[0]
        self.reserved = b[72:84]

    # -- classmethods ------------------------------------------------------
    @classmethod
    def parse(cls, blob: bytes) -> "Token":
        return cls(blob)

    # -- predicates --------------------------------------------------------
    @property
    def dna_hex(self) -> str:
        return _dna_to_hex(self.dna)

    @property
    def is_master(self) -> bool:
        return self.signer_id == _MASTER_SIGNER_ZERO

    @property
    def magic_ok(self) -> bool:
        return self.magic == NGFW_LIC_MAGIC

    def expired(self, now: Optional[float] = None) -> bool:
        if not self.expiry_unix_s:
            return False  # 0 == perpetual
        if now is None:
            now = time.time()
        return self.expiry_unix_s < now

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return (
            f"<Token feat=0x{self.feature_id:x} dna={self.dna_hex} "
            f"signer={'master' if self.is_master else self.signer_id.hex()} "
            f"alg={self.sig_alg} exp={self.expiry_unix_s}>"
        )


# ---------------------------------------------------------------------------
# Master pubkey loading + signature verification
# ---------------------------------------------------------------------------
class _MasterKey:
    """Loaded master ECDSA-P384 public key + captured curve id."""

    def __init__(self, public_key, curve_id: int) -> None:
        self.public_key = public_key
        self.curve_id = curve_id


def load_master_pubkey(pubkey_path=MASTER_PUB) -> Optional[_MasterKey]:
    """
    Load the self-describing 144-byte master pubkey blob.
    byte0 = curve_id (must be NGFW_SIG_ALG_ECDSA_P384 == 4 for the P-384
    trust root); bytes[1:1+97] = uncompressed point (0x04 || X || Y).
    Returns None on any structural problem or if crypto is unavailable.
    """
    if not CRYPTO_OK:
        return None
    try:
        blob = Path(pubkey_path).read_bytes()
    except OSError:
        return None
    if len(blob) < NGFW_MASTER_PUBKEY_BLOB_BYTES:
        return None
    curve_id = blob[NGFW_MASTER_PUBKEY_CURVE_OFFSET]
    if curve_id != NGFW_SIG_ALG_ECDSA_P384:
        # Pass 1 host path only supports the P-384 master trust root.
        return None
    point = blob[
        NGFW_MASTER_PUBKEY_POINT_OFFSET : NGFW_MASTER_PUBKEY_POINT_OFFSET
        + NGFW_PUBKEY_BYTES_ECDSA_P384
    ]
    if len(point) != NGFW_PUBKEY_BYTES_ECDSA_P384 or point[0] != 0x04:
        return None
    try:
        pk = _ec.EllipticCurvePublicKey.from_encoded_point(_ec.SECP384R1(), point)
    except Exception:
        return None
    return _MasterKey(pk, curve_id)


def _verify_ecdsa_p384(master: "_MasterKey", payload: bytes, sig: bytes) -> bool:
    """Verify a raw r||s (96-byte) ECDSA-P384/SHA-384 signature over payload."""
    if not CRYPTO_OK:
        return False
    if len(sig) != NGFW_SIG_BYTES_ECDSA_P384:
        return False
    r = int.from_bytes(sig[:_P384_SCALAR_BYTES], "big")
    s = int.from_bytes(sig[_P384_SCALAR_BYTES : 2 * _P384_SCALAR_BYTES], "big")
    der = _encode_dss_signature(r, s)
    try:
        master.public_key.verify(der, payload, _ec.ECDSA(_hashes.SHA384()))
        return True
    except _InvalidSignature:
        return False
    except Exception:
        return False


def verify(token: "Token", live_dnas: List, pubkey_path=MASTER_PUB,
           now: Optional[float] = None) -> bool:
    """
    Verify a token against a candidate set of live DNAs.  Mirrors the C
    verifier's master-signer accept logic.

    Accept IFF:
      * magic == FFN-LIC1
      * signer_id is all-zero (master)          [vendor/Ed25519 = Pass-1 stub]
      * sig_alg == ECDSA-P384 and the P-384 master signature over bytes[0:84]
        is valid against the master pubkey blob
      * token.dna matches ANY candidate in ``live_dnas``
      * token is not expired

    Returns False (fail-closed) if `cryptography` is unavailable.
    """
    if not CRYPTO_OK:
        return False
    if not isinstance(token, Token):
        return False
    if not token.magic_ok:
        return False
    if token.version != NGFW_LIC_VERSION:
        return False

    # Vendor / Ed25519 path is not implemented host-side in Pass 1.
    if not token.is_master:
        return False
    if token.sig_alg != NGFW_SIG_ALG_ECDSA_P384:
        return False

    # DNA candidate match (any).
    cand = {_dna_from_any(d) for d in (live_dnas or [])}
    cand.discard(b"")
    if token.dna not in cand:
        return False

    if token.expired(now):
        return False

    master = load_master_pubkey(pubkey_path)
    if master is None:
        return False
    return _verify_ecdsa_p384(master, token.payload, token.sig)


# ---------------------------------------------------------------------------
# Host license store
# ---------------------------------------------------------------------------
class HostLicense:
    """
    Cardless host-side license store.

    Scans ``lic_dir`` for ``*.lic`` files, verifies each against the h1 host
    DNA (or an explicit override), caches accepted 84-byte payloads to
    ``cache_path``, and answers feature queries.
    """

    def __init__(
        self,
        lic_dir=LIC_DIR,
        pubkey_path=MASTER_PUB,
        cache_path=CACHE_PATH,
        host_identity: Optional[HostIdentity] = None,
        dna_override: Optional[List[str]] = None,
    ) -> None:
        self.lic_dir = Path(lic_dir)
        self.pubkey_path = Path(pubkey_path)
        self.cache_path = Path(cache_path)
        self.identity = host_identity or HostIdentity()
        # dna_override lets tests / callers inject candidate DNAs directly.
        self._dna_override = dna_override
        self._accepted: List[Token] = []
        self.reload()

    # -- candidate DNAs ----------------------------------------------------
    def _candidate_dnas(self) -> List[str]:
        if self._dna_override is not None:
            return list(self._dna_override)
        d = self.identity.dna_hex()
        return [d] if d else []

    # -- (re)scan ----------------------------------------------------------
    def reload(self) -> dict:
        """Re-scan the license dir, re-verify, and rewrite the cache.
        Returns a small summary dict."""
        candidates = self._candidate_dnas()
        accepted: List[Token] = []
        total = 0
        try:
            files = sorted(
                p for p in self.lic_dir.iterdir() if p.is_file() and p.suffix == ".lic"
            )
        except OSError:
            files = []
        for p in files:
            total += 1
            try:
                blob = p.read_bytes()
            except OSError:
                continue
            if len(blob) < NGFW_LIC_PAYLOAD_BYTES or blob[:8] != NGFW_LIC_MAGIC:
                continue
            try:
                tok = Token.parse(blob)
            except ValueError:
                continue
            if verify(tok, candidates, pubkey_path=self.pubkey_path):
                accepted.append(tok)
        self._accepted = accepted
        self._write_cache(accepted)
        return {"accepted": len(accepted), "total": total}

    def _write_cache(self, accepted: List[Token]) -> None:
        """Persist accepted 84-byte payloads (concatenated) best-effort."""
        try:
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            data = b"".join(t.payload for t in accepted)
            tmp = self.cache_path.with_suffix(self.cache_path.suffix + ".tmp")
            tmp.write_bytes(data)
            os.replace(tmp, self.cache_path)
        except OSError:
            pass  # cache is an optimization; never fatal

    # -- queries -----------------------------------------------------------
    def tier_gbps(self, now: Optional[float] = None) -> int:
        """Highest licensed (unexpired) capacity tier, in Gbps (0 = none)."""
        if now is None:
            now = time.time()
        best = 0
        for t in self._accepted:
            if t.expired(now):
                continue
            g = _TIER_GBPS.get(t.feature_id, 0)
            if g > best:
                best = g
        return best

    def base_ok(self, now: Optional[float] = None) -> bool:
        """Host base gate = unexpired BASE token AND a positive tier.
        Mirrors ngfw_app_bypass.c's LIC_NO_BASE reason, host-side."""
        if now is None:
            now = time.time()
        have_base = any(
            t.feature_id == NGFW_LIC_FEAT_BASE and not t.expired(now)
            for t in self._accepted
        )
        return have_base and self.tier_gbps(now) > 0

    def query(self, feature_id: int, now: Optional[float] = None) -> bool:
        """
        True if ``feature_id`` is licensed (accepted, unexpired) on this host.

        NGFW_LIC_FEAT_ACCEL (0x130) is NEVER granted host-side — it binds to
        card DNA and is only checkable with a card present.
        """
        if feature_id == NGFW_LIC_FEAT_ACCEL:
            return False
        if now is None:
            now = time.time()
        if feature_id == NGFW_LIC_FEAT_BASE:
            return self.base_ok(now)
        return any(
            t.feature_id == feature_id and not t.expired(now)
            for t in self._accepted
        )

    def features(self, now: Optional[float] = None) -> List[int]:
        """Sorted list of unexpired, accepted feature IDs."""
        if now is None:
            now = time.time()
        return sorted(
            {t.feature_id for t in self._accepted if not t.expired(now)}
        )

    def status(self) -> dict:
        now = time.time()
        expiries = [t.expiry_unix_s for t in self._accepted if t.expiry_unix_s]
        return {
            "base_ok": self.base_ok(now),
            "features": self.features(now),
            "tier_gbps": self.tier_gbps(now),
            "expiry": min(expiries) if expiries else 0,
            "dna": self.identity.dna_hex(),
            "accepted": len(self._accepted),
            "crypto_available": CRYPTO_OK,
        }

    def host_dna_info(self) -> dict:
        info = self.identity.info()
        # host_dna_info always reports the h1 source, even under dna_override.
        info["source"] = "host-h1"
        return info


# ---------------------------------------------------------------------------
# Selftest
# ---------------------------------------------------------------------------
def _build_payload(dna: bytes, feature_id: int, expiry: int = 0,
                   signer_id: bytes = _MASTER_SIGNER_ZERO,
                   sig_alg: int = NGFW_SIG_ALG_ECDSA_P384) -> bytes:
    """Assemble an 84-byte FFN-LIC1 signed region."""
    assert len(dna) == NGFW_DEVICE_DNA_BYTES
    assert len(signer_id) == NGFW_SIGNER_ID_BYTES
    b = bytearray(NGFW_LIC_PAYLOAD_BYTES)
    b[0:8] = NGFW_LIC_MAGIC
    struct.pack_into("<I", b, 8, NGFW_LIC_VERSION)
    b[12:24] = dna
    struct.pack_into("<I", b, 24, feature_id)
    struct.pack_into("<I", b, 28, 0)  # subfeature
    struct.pack_into("<Q", b, 32, int(time.time()))
    struct.pack_into("<Q", b, 40, expiry)
    struct.pack_into("<I", b, 48, 0)  # flags
    b[52:68] = signer_id
    struct.pack_into("<I", b, 68, sig_alg)
    # reserved[72:84] left zero
    return bytes(b)


def _p384_pub_blob(private_key) -> bytes:
    """Build the 144-byte master pubkey blob from a P-384 private key."""
    nums = private_key.public_key().public_numbers()
    x = nums.x.to_bytes(_P384_SCALAR_BYTES, "big")
    y = nums.y.to_bytes(_P384_SCALAR_BYTES, "big")
    point = b"\x04" + x + y  # 97 bytes
    blob = bytearray(NGFW_MASTER_PUBKEY_BLOB_BYTES)
    blob[NGFW_MASTER_PUBKEY_CURVE_OFFSET] = NGFW_SIG_ALG_ECDSA_P384
    blob[NGFW_MASTER_PUBKEY_POINT_OFFSET : NGFW_MASTER_PUBKEY_POINT_OFFSET + len(point)] = point
    return bytes(blob)


def _sign_p384(private_key, payload: bytes) -> bytes:
    """Sign payload, return raw r||s (96 bytes)."""
    der = private_key.sign(payload, _ec.ECDSA(_hashes.SHA384()))
    r, s = _decode_dss_signature(der)
    return r.to_bytes(_P384_SCALAR_BYTES, "big") + s.to_bytes(_P384_SCALAR_BYTES, "big")


def selftest() -> int:
    """
    Ephemeral end-to-end proof:
      1. generate a P-384 master key + write its 144-byte pubkey blob
      2. sign a synthetic FFN-LIC1 BASE token bound to this host's h1 DNA
         (or a fabricated DNA if no host identifiers are readable)
      3. assert verify() + HostLicense.query(BASE) pass
      4. assert a wrong-DNA token fails
    Returns 0 on success, non-zero on failure.
    """
    print("ffn_license selftest")
    print(f"  cryptography available: {CRYPTO_OK}"
          + ("" if CRYPTO_OK else f" ({CRYPTO_ERR})"))

    ident = HostIdentity()
    host_dna_hex = ident.dna_hex()
    print(f"  h1 host DNA: {host_dna_hex or '(unavailable on this host)'}")
    print(f"  h1 stream:   {ident.stream()}")

    if not CRYPTO_OK:
        print("  SKIP: cryptography not installed — verify path not exercised.")
        print("  (module imports + h1 identity OK)  -> SKIP")
        return 0

    import tempfile

    # Use the real host DNA when present; otherwise a deterministic fabricated
    # 12-byte DNA so the crypto path is still exercised on a dev box.
    dna = ident.dna_bytes() or bytes(range(1, 13))
    dna_hex = _dna_to_hex(dna)
    wrong_dna = bytes((b ^ 0xFF) for b in dna)

    priv = _ec.generate_private_key(_ec.SECP384R1())
    pub_blob = _p384_pub_blob(priv)

    ok = True
    with tempfile.TemporaryDirectory(prefix="ffn_lic_selftest_") as td:
        tdp = Path(td)
        pub_path = tdp / "master.p384.pub"
        pub_path.write_bytes(pub_blob)
        lic_dir = tdp / "licenses"
        lic_dir.mkdir()
        cache_path = tdp / "licenses.cache"

        # (a) good BASE token bound to our DNA
        base_payload = _build_payload(dna, NGFW_LIC_FEAT_BASE)
        base_tok = Token.parse(base_payload + _sign_p384(priv, base_payload))
        r = verify(base_tok, [dna_hex], pubkey_path=pub_path)
        print(f"  verify(BASE, correct dna)      = {r}  (expect True)")
        ok &= r is True

        # (b) tier token so base_ok() has a positive tier
        tier_payload = _build_payload(dna, NGFW_LIC_FEAT_TIER_10G)
        tier_tok_blob = tier_payload + _sign_p384(priv, tier_payload)
        r = verify(Token.parse(tier_tok_blob), [dna_hex], pubkey_path=pub_path)
        print(f"  verify(TIER_10G, correct dna)  = {r}  (expect True)")
        ok &= r is True

        # (c) wrong-DNA token must fail (signature valid, DNA mismatch)
        bad_payload = _build_payload(wrong_dna, NGFW_LIC_FEAT_BASE)
        bad_tok = Token.parse(bad_payload + _sign_p384(priv, bad_payload))
        r = verify(bad_tok, [dna_hex], pubkey_path=pub_path)
        print(f"  verify(BASE, wrong dna)        = {r}  (expect False)")
        ok &= r is False

        # (d) tampered signature must fail
        tampered = bytearray(base_tok.raw)
        tampered[-1] ^= 0xFF
        r = verify(Token.parse(bytes(tampered)), [dna_hex], pubkey_path=pub_path)
        print(f"  verify(BASE, bad signature)    = {r}  (expect False)")
        ok &= r is False

        # (e) full HostLicense store: write the two good tokens to disk
        (lic_dir / "base.lic").write_bytes(base_tok.raw)
        (lic_dir / "tier10.lic").write_bytes(tier_tok_blob)
        hl = HostLicense(
            lic_dir=lic_dir,
            pubkey_path=pub_path,
            cache_path=cache_path,
            dna_override=[dna_hex],
        )
        st = hl.status()
        print(f"  HostLicense.status()           = {st}")
        q_base = hl.query(NGFW_LIC_FEAT_BASE)
        q_tier = hl.query(NGFW_LIC_FEAT_TIER_10G)
        q_accel = hl.query(NGFW_LIC_FEAT_ACCEL)
        print(f"  query(BASE)  = {q_base}   (expect True)")
        print(f"  query(TIER_10G) = {q_tier} (expect True)")
        print(f"  query(ACCEL=0x130) = {q_accel} (expect False — host never grants)")
        ok &= q_base is True
        ok &= q_tier is True
        ok &= q_accel is False
        ok &= st["tier_gbps"] == 10
        ok &= NGFW_LIC_FEAT_BASE in st["features"]
        ok &= cache_path.exists() and cache_path.stat().st_size == 2 * NGFW_LIC_PAYLOAD_BYTES
        ok &= hl.host_dna_info()["source"] == "host-h1"

        # (f) a HostLicense whose candidate DNA does NOT match must reject
        hl2 = HostLicense(
            lic_dir=lic_dir,
            pubkey_path=pub_path,
            cache_path=cache_path,
            dna_override=[_dna_to_hex(wrong_dna)],
        )
        r = hl2.query(NGFW_LIC_FEAT_BASE)
        print(f"  HostLicense(wrong dna).query(BASE) = {r}  (expect False)")
        ok &= r is False

    print("  RESULT:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def _main(argv: List[str]) -> int:
    cmd = argv[1] if len(argv) > 1 else "status"
    if cmd == "selftest":
        return selftest()
    if cmd == "dna":
        ident = HostIdentity()
        print(ident.dna_hex() or "(unavailable)")
        print(ident.stream())
        return 0
    if cmd == "status":
        hl = HostLicense()
        import json
        print(json.dumps(hl.status(), indent=2))
        return 0
    print(f"usage: {argv[0]} [selftest|dna|status]")
    return 2


if __name__ == "__main__":
    import sys

    raise SystemExit(_main(sys.argv))
