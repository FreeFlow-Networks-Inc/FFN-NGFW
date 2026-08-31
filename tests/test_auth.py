#!/usr/bin/env python3
"""Regression test: a must-change-password login must be unable to do anything else.

Checks the thing that actually matters: that a must-change-password login cannot
be used to do anything except change the password. The old code returned a full
token and a polite flag, so this test would have failed on step 3.
"""
import os
import sys
import tempfile

d = tempfile.mkdtemp(prefix="ffnauth")
os.environ["FFN_DB_PATH"] = os.path.join(d, "config.db")
os.environ["FFN_CONFIG_DIR"] = os.path.join(d, "config")
os.environ["FFN_JWT_SECRET"] = "test-only-secret-not-a-real-one"
os.environ["FFN_ADMIN_INITIAL_PASSWORD"] = "SeedPw-123456"

# Import the app from the repository this test lives in, wherever that is.
_HERE = os.path.dirname(os.path.abspath(__file__))
for _cand in (os.path.join(_HERE, os.pardir),
              os.path.join(_HERE, os.pardir, "opt")):
    if os.path.isfile(os.path.join(_cand, "ffn_manager.py")):
        sys.path.insert(0, os.path.abspath(_cand))
        break
else:
    sys.exit("test_auth: cannot locate ffn_manager.py relative to %s" % _HERE)
import ffn_manager as m                                        # noqa: E402
from fastapi.testclient import TestClient                       # noqa: E402

fails = []


def check(name, cond, detail=""):
    print("  %-4s %s%s" % ("ok" if cond else "FAIL", name,
                           "" if cond else "  <- " + str(detail)))
    if not cond:
        fails.append(name)


with TestClient(m.app) as c:
    print("[1] the seeded password is NOT 'admin'")
    r = c.post("/api/auth/login", json={"username": "admin", "password": "admin"})
    check("admin/admin is rejected", r.status_code == 401, r.status_code)

    print("[2] login with the provisioned password works and flags the change")
    r = c.post("/api/auth/login",
               json={"username": "admin", "password": "SeedPw-123456"})
    check("login succeeds", r.status_code == 200, r.text[:200])
    body = r.json() if r.status_code == 200 else {}
    check("must_change_pw reported", body.get("must_change_pw") is True, body)
    tok = body.get("access_token", "")
    check("a token was issued", bool(tok))
    h = {"Authorization": "Bearer " + tok}

    print("[3] THE POINT: that token cannot reach a normal endpoint")
    r = c.get("/api/users", headers=h)
    check("/api/users is refused", r.status_code == 403, r.status_code)
    r = c.get("/api/system/fips", headers=h)
    check("/api/system/fips is refused", r.status_code == 403, r.status_code)

    print("[4] but it can reach exactly what it needs to")
    r = c.get("/api/auth/me", headers=h)
    check("/api/auth/me allowed", r.status_code == 200, r.status_code)

    print("[5] changing the password clears the restriction")
    r = c.post("/api/auth/change-password", headers=h,
               json={"current_password": "SeedPw-123456",
                     "new_password": "A-Better-Password-42"})
    check("change accepted", r.status_code == 200, r.text[:200])
    newtok = (r.json() or {}).get("access_token", "") if r.status_code == 200 else ""
    check("a full token is returned", bool(newtok))

    print("[6] the new token works everywhere")
    h2 = {"Authorization": "Bearer " + newtok}
    r = c.get("/api/users", headers=h2)
    check("/api/users now allowed", r.status_code == 200, r.status_code)

    print("[7] the old password no longer works")
    r = c.post("/api/auth/login",
               json={"username": "admin", "password": "SeedPw-123456"})
    check("old password rejected", r.status_code == 401, r.status_code)

    print("[8] and a fresh login is now unrestricted")
    r = c.post("/api/auth/login",
               json={"username": "admin", "password": "A-Better-Password-42"})
    check("login ok", r.status_code == 200, r.status_code)
    check("no change required", r.json().get("must_change_pw") is False, r.json())
    h3 = {"Authorization": "Bearer " + r.json()["access_token"]}
    check("full access", c.get("/api/users", headers=h3).status_code == 200)

print()
print("==== auth test: %d failed ====" % len(fails))
sys.exit(1 if fails else 0)
