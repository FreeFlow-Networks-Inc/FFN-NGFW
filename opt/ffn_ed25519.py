#!/usr/bin/env python3
"""ffn_ed25519.py -- dependency-free Ed25519 for FFN's signed payload updater.

Why this exists
---------------
FFN's updater originally signed manifests with HMAC-SHA256. That is fine for a
single box talking to its own build server, but FFN is *distributed*: the whole
point is that other people run it on reclaimed appliances. HMAC uses one shared
secret, so every image would have to ship the key that signs updates -- and
anyone holding an image could forge a payload for every other box. That is the
wrong trust model for a product handed to strangers.

Ed25519 fixes it: the build server keeps the private key, and images ship only
the public key. A stolen image lets you *verify* updates, never mint them.

The target boxes are minimal -- the PA-5220 under test has no `cryptography`
module and no reliable path to install one -- so verification cannot depend on a
third-party package. This is the standard reference algorithm (RFC 8032) in
plain Python, using extended coordinates so a verify costs tens of
milliseconds rather than seconds. It is checked against the RFC 8032 section
7.1 test vectors in selftest().

Only pure-Python integer arithmetic is used, so it runs anywhere Python does,
including the big-endian MIPS side if it is ever needed there.

    ffn_ed25519.py --selftest
    ffn_ed25519.py --keygen /etc/ffn-ngfw/update            # writes .key/.pub
"""
import hashlib
import os
import sys

# --- curve parameters (RFC 8032) ---------------------------------------------
Q = 2 ** 255 - 19
L = 2 ** 252 + 27742317777372353535851937790883648493
D = -121665 * pow(121666, Q - 2, Q) % Q
I = pow(2, (Q - 1) // 4, Q)


def _sha512(b):
    return hashlib.sha512(b).digest()


def _inv(x):
    return pow(x, Q - 2, Q)


def _xrecover(y):
    xx = (y * y - 1) * _inv(D * y * y + 1)
    x = pow(xx, (Q + 3) // 8, Q)
    if (x * x - xx) % Q != 0:
        x = (x * I) % Q
    if x % 2 != 0:
        x = Q - x
    return x


_By = 4 * _inv(5) % Q
_Bx = _xrecover(_By)
# base point in extended coordinates (X, Y, Z, T)
B_EXT = (_Bx % Q, _By % Q, 1, _Bx * _By % Q)


def _add(P, Q_):
    """Extended-coordinate point addition -- no modular inverse per step."""
    X1, Y1, Z1, T1 = P
    X2, Y2, Z2, T2 = Q_
    a = (Y1 - X1) * (Y2 - X2) % Q
    b = (Y1 + X1) * (Y2 + X2) % Q
    c = T1 * 2 * D * T2 % Q
    dd = Z1 * 2 * Z2 % Q
    e = b - a
    f = dd - c
    g = dd + c
    h = b + a
    return (e * f % Q, g * h % Q, f * g % Q, e * h % Q)


def _double(P):
    X1, Y1, Z1, T1 = P
    a = X1 * X1 % Q
    b = Y1 * Y1 % Q
    c = 2 * Z1 * Z1 % Q
    h = (a + b) % Q
    e = (h - (X1 + Y1) * (X1 + Y1)) % Q
    g = (a - b) % Q
    f = (c + g) % Q
    return (e * f % Q, g * h % Q, f * g % Q, e * h % Q)


def _scalarmult(P, e):
    """Left-to-right double-and-add. Not constant time -- verification only
    handles public data, and signing here is a build-server operation."""
    R = (0, 1, 1, 0)
    if e == 0:
        return R
    for bit in bin(e)[2:]:
        R = _double(R)
        if bit == "1":
            R = _add(R, P)
    return R


def _affine(P):
    X, Y, Z, _ = P
    zi = _inv(Z)
    return (X * zi % Q, Y * zi % Q)


def _encode_point(P):
    x, y = _affine(P)
    return ((y | ((x & 1) << 255))).to_bytes(32, "little")


def _decode_point(s):
    y = int.from_bytes(s, "little") & ~(1 << 255)
    sign = (s[31] >> 7) & 1
    x = _xrecover(y)
    if x & 1 != sign:
        x = Q - x
    P = (x, y, 1, x * y % Q)
    if not _on_curve(P):
        raise ValueError("point is not on the curve")
    return P


def _on_curve(P):
    x, y = _affine(P)
    return (-x * x + y * y - 1 - D * x * x * y * y) % Q == 0


def _clamp(h):
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a


# --- public API ---------------------------------------------------------------
def publickey(seed: bytes) -> bytes:
    """32-byte public key from a 32-byte private seed."""
    if len(seed) != 32:
        raise ValueError("seed must be 32 bytes")
    return _encode_point(_scalarmult(B_EXT, _clamp(_sha512(seed))))


def sign(msg: bytes, seed: bytes, pub: bytes = None) -> bytes:
    """64-byte signature. Used by the build server when publishing."""
    if len(seed) != 32:
        raise ValueError("seed must be 32 bytes")
    h = _sha512(seed)
    a = _clamp(h)
    if pub is None:
        pub = _encode_point(_scalarmult(B_EXT, a))
    r = int.from_bytes(_sha512(h[32:] + msg), "little") % L
    R = _encode_point(_scalarmult(B_EXT, r))
    k = int.from_bytes(_sha512(R + pub + msg), "little") % L
    s = (r + k * a) % L
    return R + s.to_bytes(32, "little")


def verify(msg: bytes, sig: bytes, pub: bytes) -> bool:
    """True only for a signature that is valid under `pub`. Never raises."""
    try:
        if len(sig) != 64 or len(pub) != 32:
            return False
        R = _decode_point(sig[:32])
        A = _decode_point(pub)
        s = int.from_bytes(sig[32:], "little")
        if s >= L:                      # reject non-canonical scalars
            return False
        k = int.from_bytes(_sha512(sig[:32] + pub + msg), "little") % L
        lhs = _scalarmult(B_EXT, s)
        rhs = _add(R, _scalarmult(A, k))
        return _affine(lhs) == _affine(rhs)
    except Exception:
        return False


def keygen(prefix):
    """Write <prefix>.key (private seed) and <prefix>.pub (public key), hex."""
    seed = os.urandom(32)
    pub = publickey(seed)
    kp, pp = prefix + ".key", prefix + ".pub"
    with open(kp, "w") as f:
        f.write(seed.hex() + "\n")
    os.chmod(kp, 0o600)
    with open(pp, "w") as f:
        f.write(pub.hex() + "\n")
    return kp, pp, pub.hex()


# --- selftest -----------------------------------------------------------------
# RFC 8032 section 7.1 test vectors.
VECTORS = [
    ("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
     "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
     "",
     "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
    ("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
     "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
     "72",
     "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
    ("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
     "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
     "af82",
     "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"),
]


def selftest():
    import time
    fails = []

    def chk(c, m):
        print(("  ok   " if c else "  FAIL ") + m)
        if not c:
            fails.append(m)

    for n, (sk, pk, msg, sig) in enumerate(VECTORS, 1):
        seed = bytes.fromhex(sk)
        m = bytes.fromhex(msg)
        chk(publickey(seed).hex() == pk, "RFC 8032 vector %d: public key" % n)
        chk(sign(m, seed).hex() == sig, "RFC 8032 vector %d: signature" % n)
        chk(verify(m, bytes.fromhex(sig), bytes.fromhex(pk)),
            "RFC 8032 vector %d: verify" % n)

    # negative cases -- these are the ones that matter for an updater
    seed = bytes.fromhex(VECTORS[2][0])
    pub = bytes.fromhex(VECTORS[2][1])
    msg = b"ffn payload manifest"
    sig = sign(msg, seed)
    chk(verify(msg, sig, pub), "round trip verifies")
    chk(not verify(b"ffn payload manifesT", sig, pub),
        "TAMPERED message is rejected")
    bad = bytearray(sig); bad[0] ^= 1
    chk(not verify(msg, bytes(bad), pub), "TAMPERED signature is rejected")
    otherpub = publickey(bytes.fromhex(VECTORS[0][0]))
    chk(not verify(msg, sig, otherpub), "WRONG public key is rejected")
    chk(not verify(msg, sig[:63], pub), "truncated signature is rejected")
    chk(not verify(msg, sig, pub[:31]), "truncated key is rejected")
    chk(not verify(msg, b"\x00" * 64, pub), "all-zero signature is rejected")
    # non-canonical S (S >= L) must not be accepted
    ncs = sig[:32] + (L + 1).to_bytes(32, "little")
    chk(not verify(msg, ncs, pub), "non-canonical scalar is rejected")

    k, p, ph = keygen("/tmp/ffn-ed-test")
    s2 = open(k).read().strip()
    chk(publickey(bytes.fromhex(s2)).hex() == ph, "keygen key pair is consistent")
    for f in (k, p):
        try:
            os.unlink(f)
        except Exception:
            pass

    t = time.time()
    verify(msg, sig, pub)
    print("  (verify takes %.0f ms)" % ((time.time() - t) * 1000))
    print("\n==== ffn_ed25519 selftest: %d failed ====" % len(fails))
    return 1 if fails else 0


if __name__ == "__main__":
    a = sys.argv[1:]
    if a and a[0] == "--keygen":
        pre = a[1] if len(a) > 1 else "./ffn-update"
        k, p, ph = keygen(pre)
        print("private seed -> %s   (keep on the build server ONLY)" % k)
        print("public key   -> %s   (ship this in the image)" % p)
        print("public key   =  %s" % ph)
        sys.exit(0)
    sys.exit(selftest())
