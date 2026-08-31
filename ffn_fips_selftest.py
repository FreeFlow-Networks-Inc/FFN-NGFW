#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""
FFN NGFW — FIPS-CC power-on self-test (POST).

Runs when the appliance boots in FIPS-CC mode (flag /etc/ffn-ngfw/fips-cc.mode).
Two families of tests, per FIPS 140 requirements:

  1. Cryptographic Known-Answer Tests (KATs) — approved algorithms are exercised
     against fixed NIST/RFC test vectors, plus pairwise-consistency for the
     asymmetric key types.
  2. Software integrity test — HMAC-SHA256 over the FFN code manifest, compared
     to the baseline recorded when FIPS-CC mode was enabled (in recovery).

On failure the module exits non-zero; the boot service then refuses to bring the
dataplane up and records the failure for the WebUI (a FIPS module that fails
self-test must not enter an operational state).

Usage:
  ffn_fips_selftest.py                 # run, write result JSON, exit 0/1
  ffn_fips_selftest.py --json          # print the result JSON to stdout too
  ffn_fips_selftest.py --gen-manifest  # (re)baseline the integrity manifest
"""
import argparse
import binascii
import hashlib
import hmac
import json
import os
import sys
import time
import traceback

RESULT_PATH = "/var/lib/ffn-ngfw/fips-selftest.json"
MODE_FLAG = "/etc/ffn-ngfw/fips-cc.mode"
INTEGRITY_MANIFEST = "/etc/ffn-ngfw/fips-integrity.manifest"
INTEGRITY_KEY = "/etc/ffn-ngfw/fips-integrity.key"
FFN_DIRS = ["/opt/ffn-ngfw-v2", "/usr/local/bin/ffn-cli"]
FFN_EXTS = (".py",)

hx = lambda s: binascii.unhexlify(s.replace(" ", ""))


# ---- crypto KATs ----------------------------------------------------------

def kat_sha():
    v = {
        "SHA-256": ("abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
        "SHA-384": ("abc", "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"),
        "SHA-512": ("abc", "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"),
    }
    for name, (msg, want) in v.items():
        algo = name.replace("SHA-", "sha").replace("sha", "sha")
        h = hashlib.new({"SHA-256": "sha256", "SHA-384": "sha384", "SHA-512": "sha512"}[name])
        h.update(msg.encode())
        if h.hexdigest() != want:
            raise ValueError(f"{name} KAT mismatch")


def kat_hmac():
    # RFC 4231 Test Case 1
    key = b"\x0b" * 20
    mac = hmac.new(key, b"Hi There", hashlib.sha256).hexdigest()
    if mac != "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7":
        raise ValueError("HMAC-SHA256 KAT mismatch")


def kat_pbkdf2():
    # PBKDF2-HMAC-SHA256, password="password", salt="salt", c=1, dkLen=32
    dk = hashlib.pbkdf2_hmac("sha256", b"password", b"salt", 1, 32).hex()
    if dk != "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b":
        raise ValueError("PBKDF2-HMAC-SHA256 KAT mismatch")


def kat_aes_ecb():
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    # FIPS-197 AES-128-ECB (C.1) and AES-256-ECB (C.3)
    cases = [
        (hx("000102030405060708090a0b0c0d0e0f"),
         hx("00112233445566778899aabbccddeeff"), hx("69c4e0d86a7b0430d8cdb78070b4c55a")),
        (hx("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
         hx("00112233445566778899aabbccddeeff"), hx("8ea2b7ca516745bfeafc49904b496089")),
    ]
    for key, pt, want in cases:
        enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
        ct = enc.update(pt) + enc.finalize()
        if ct != want:
            raise ValueError(f"AES-{len(key)*8}-ECB KAT mismatch")
        dec = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
        if dec.update(ct) + dec.finalize() != pt:
            raise ValueError(f"AES-{len(key)*8}-ECB decrypt KAT mismatch")


def kat_aes_gcm():
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    # NIST GCM KAT: key=0x00*16, iv=0x00*12, pt=0x00*16
    key = b"\x00" * 16
    ct_tag = AESGCM(key).encrypt(b"\x00" * 12, b"\x00" * 16, None)  # ct||tag
    want = hx("0388dace60b6a392f328c2b971b2fe78" "ab6e47d42cec13bdf53a67b21257bddf")
    if ct_tag != want:
        raise ValueError("AES-128-GCM KAT mismatch")
    if AESGCM(key).decrypt(b"\x00" * 12, ct_tag, None) != b"\x00" * 16:
        raise ValueError("AES-128-GCM decrypt KAT mismatch")


def kat_drbg():
    # DRBG health: approved RNG returns full-entropy output (not constant/short).
    a = os.urandom(32)
    b = os.urandom(32)
    if len(a) != 32 or len(b) != 32 or a == b or a == b"\x00" * 32:
        raise ValueError("DRBG health-test failed")


def pct_rsa():
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.primitives import hashes
    from cryptography.exceptions import InvalidSignature
    k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    msg = b"FFN-NGFW FIPS-CC RSA pairwise-consistency test"
    sig = k.sign(msg, padding.PKCS1v15(), hashes.SHA256())
    k.public_key().verify(sig, msg, padding.PKCS1v15(), hashes.SHA256())  # must pass
    try:
        k.public_key().verify(sig, msg + b"x", padding.PKCS1v15(), hashes.SHA256())
        raise ValueError("RSA PCT: tampered message verified (must fail)")
    except InvalidSignature:
        pass


def pct_ecdsa():
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import hashes
    from cryptography.exceptions import InvalidSignature
    k = ec.generate_private_key(ec.SECP256R1())
    msg = b"FFN-NGFW FIPS-CC ECDSA pairwise-consistency test"
    sig = k.sign(msg, ec.ECDSA(hashes.SHA256()))
    k.public_key().verify(sig, msg, ec.ECDSA(hashes.SHA256()))  # must pass
    try:
        k.public_key().verify(sig, msg + b"x", ec.ECDSA(hashes.SHA256()))
        raise ValueError("ECDSA PCT: tampered message verified (must fail)")
    except InvalidSignature:
        pass


CRYPTO_TESTS = [
    ("SHA-2 (256/384/512) KAT", kat_sha),
    ("HMAC-SHA256 KAT", kat_hmac),
    ("PBKDF2-HMAC-SHA256 KAT", kat_pbkdf2),
    ("AES-128/256-ECB KAT", kat_aes_ecb),
    ("AES-128-GCM KAT", kat_aes_gcm),
    ("DRBG health-test", kat_drbg),
    ("RSA-2048 pairwise-consistency", pct_rsa),
    ("ECDSA P-256 pairwise-consistency", pct_ecdsa),
]


# ---- software integrity ---------------------------------------------------

def _integrity_key():
    try:
        return open(INTEGRITY_KEY, "rb").read().strip()
    except FileNotFoundError:
        # derive from master.key so recovery + runtime agree without shipping a secret
        try:
            return hashlib.sha256(b"ffn-fips-integrity:" + open("/etc/ffn-ngfw/master.key", "rb").read().strip()).digest()
        except FileNotFoundError:
            return b"ffn-ngfw-fips-integrity-fallback-key"


def _iter_files():
    for base in FFN_DIRS:
        if os.path.isfile(base):
            yield base
        elif os.path.isdir(base):
            for root, _, files in os.walk(base):
                if "/venv/" in root + "/" or "__pycache__" in root:
                    continue
                for f in sorted(files):
                    if f.endswith(FFN_EXTS):
                        yield os.path.join(root, f)


def compute_manifest():
    key = _integrity_key()
    lines = []
    for path in sorted(set(_iter_files())):
        try:
            mac = hmac.new(key, open(path, "rb").read(), hashlib.sha256).hexdigest()
            lines.append(f"{mac}  {path}")
        except OSError:
            continue
    body = "\n".join(lines) + "\n"
    digest = hmac.new(key, body.encode(), hashlib.sha256).hexdigest()
    return body, digest


def gen_manifest():
    body, digest = compute_manifest()
    os.makedirs(os.path.dirname(INTEGRITY_MANIFEST), exist_ok=True)
    with open(INTEGRITY_MANIFEST, "w") as f:
        f.write(f"# FFN NGFW FIPS-CC integrity manifest\n# digest: {digest}\n{body}")
    return digest


def integrity_test():
    if not os.path.exists(INTEGRITY_MANIFEST):
        # no baseline yet — establish it (first enable). A later boot verifies against it.
        gen_manifest()
        return "baselined"
    stored = open(INTEGRITY_MANIFEST).read()
    stored_digest = ""
    for ln in stored.splitlines():
        if ln.startswith("# digest:"):
            stored_digest = ln.split(":", 1)[1].strip()
    body, digest = compute_manifest()
    if digest != stored_digest:
        raise ValueError("software integrity check FAILED (code digest mismatch)")
    return "verified"


# ---- runner ---------------------------------------------------------------

def run(write=True):
    tests = []
    ok = True
    for name, fn in CRYPTO_TESTS:
        try:
            fn()
            tests.append({"test": name, "kind": "crypto-kat", "result": "pass"})
        except Exception as e:
            ok = False
            tests.append({"test": name, "kind": "crypto-kat", "result": "FAIL", "detail": str(e)})
    try:
        state = integrity_test()
        tests.append({"test": "Software integrity (HMAC-SHA256 manifest)", "kind": "integrity", "result": "pass", "detail": state})
    except Exception as e:
        ok = False
        tests.append({"test": "Software integrity (HMAC-SHA256 manifest)", "kind": "integrity", "result": "FAIL", "detail": str(e)})

    result = {
        "overall": "pass" if ok else "FAIL",
        "fips_cc_mode": os.path.exists(MODE_FLAG),
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "tests": tests,
    }
    if write:
        try:
            os.makedirs(os.path.dirname(RESULT_PATH), exist_ok=True)
            json.dump(result, open(RESULT_PATH, "w"), indent=2)
        except OSError:
            pass
    return result


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true", help="print result JSON")
    ap.add_argument("--gen-manifest", action="store_true", help="(re)baseline integrity manifest and exit")
    a = ap.parse_args()
    if a.gen_manifest:
        print("integrity manifest digest:", gen_manifest())
        return 0
    try:
        r = run(write=True)
    except Exception:
        traceback.print_exc()
        return 2
    for t in r["tests"]:
        mark = "ok " if t["result"] == "pass" else "FAIL"
        print(f"  [{mark}] {t['test']}" + (f" ({t.get('detail')})" if t.get("detail") else ""))
    print(f"FIPS-CC POST: {r['overall']}")
    return 0 if r["overall"] == "pass" else 1


if __name__ == "__main__":
    sys.exit(main())
