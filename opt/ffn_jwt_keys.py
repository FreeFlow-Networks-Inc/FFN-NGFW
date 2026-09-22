#!/usr/bin/env python3
"""ffn_jwt_keys.py -- rotate the session-signing key without logging anyone out.

WHY A KEYRING AND NOT JUST A NEW SECRET

Tokens are signed HS256 and live JWT_EXPIRE_MINUTES (480 = 8 hours). Replacing
the one secret makes every token in existence fail verification at once, so
every logged-in administrator is thrown out mid-session the moment the timer
fires. ffn_manager._load_jwt_secret's own docstring already names that failure:

    an in-memory secret would silently invalidate every session on restart,
    which presents as random logouts rather than as a configuration error

A rotation that runs unattended must not reintroduce it deliberately. So the
keyring keeps two kinds of key:

    current    signs new tokens, and verifies
    retired    verifies ONLY, until every token it could have signed has expired

A retired key is dropped once `not_after` has passed, which is the retirement
moment plus the full token lifetime plus a margin. Between rotation and that
point both keys verify, so a token signed a minute before rotation keeps working
until it expires on its own schedule. Nobody is logged out; the change is
invisible.

THE ORDER MATTERS. Retire-then-sign, never sign-then-retire: the new key must be
in the file before anything signs with it, or a token can be issued whose key is
not yet persisted and does not survive a restart.

WHAT THIS IS NOT. It is not forward secrecy and not a response to a key already
in an attacker's hands. A leaked key stays usable until it is retired AND its
last token expires; if you know a key is compromised, rotate with
`--compromised`, which drops the old key immediately and does log everyone out.
That is the right trade when the alternative is honouring forged tokens.

USAGE

    ffn_jwt_keys.py status
    ffn_jwt_keys.py rotate [--compromised] [--lifetime-minutes N]
    ffn_jwt_keys.py init            # adopt an existing single secret
    ffn_jwt_keys.py selftest

The keyring is JSON at $FFN_JWT_KEYS_FILE, default /etc/ffn-ngfw/jwt.keys,
written 0600 by an atomic replace so a reader never sees a half-written file.
"""
import argparse
import json
import os
import secrets
import sys
import time

KEYS_FILE = os.environ.get("FFN_JWT_KEYS_FILE", "/etc/ffn-ngfw/jwt.keys")

# Must match ffn_manager.JWT_EXPIRE_MINUTES. Passed explicitly by the rotate
# command so the two cannot silently disagree; this is only the fallback.
DEFAULT_LIFETIME_MINUTES = 480

# Extra overlap beyond the token lifetime. Covers a clock that is not quite
# right and a token minted in the instant before the rotation wrote the file.
RETIRE_MARGIN_MINUTES = 60

VERSION = 1


def _now():
    return int(time.time())


def new_secret():
    return secrets.token_urlsafe(48)


def empty(now=None):
    now = _now() if now is None else now
    return {"version": VERSION,
            "current": {"secret": new_secret(), "created": now},
            "retired": []}


def load(path=None):
    """Read the keyring. Returns None when there is not one yet."""
    path = path or KEYS_FILE
    try:
        with open(path) as fh:
            doc = json.load(fh)
    except (OSError, ValueError):
        return None
    if not isinstance(doc, dict) or not isinstance(doc.get("current"), dict):
        return None
    if not doc["current"].get("secret"):
        return None
    doc.setdefault("retired", [])
    return doc


_CACHE = {"path": None, "stamp": None, "doc": None}


def load_cached(path=None):
    """load(), re-reading only when the file actually changes.

    This is called on every token verification, so it must not parse JSON each
    time -- and it must notice a rotation WITHOUT a restart, or the overlap
    window would not help: the manager would keep verifying against the keyring
    it read at import and reject tokens signed by the new key.

    One stat per call is the price. st_ino is in the stamp because rotation
    replaces the file by rename, so mtime and size alone can repeat.
    """
    path = path or KEYS_FILE
    try:
        st = os.stat(path)
        stamp = (st.st_mtime_ns, st.st_size, st.st_ino)
    except OSError:
        stamp = None
    if _CACHE["path"] == path and _CACHE["stamp"] == stamp:
        return _CACHE["doc"]
    doc = load(path) if stamp is not None else None
    _CACHE.update(path=path, stamp=stamp, doc=doc)
    return doc


def save(doc, path=None):
    """Atomic 0600 write. A torn keyring would lock every session out."""
    path = path or KEYS_FILE
    parent = os.path.dirname(path) or "."
    os.makedirs(parent, exist_ok=True)
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w") as fh:
            json.dump(doc, fh, indent=1)
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return path


def prune(doc, now=None):
    """Drop retired keys whose last possible token has expired."""
    now = _now() if now is None else now
    keep = [k for k in doc.get("retired", [])
            if isinstance(k, dict) and k.get("secret")
            and int(k.get("not_after", 0)) > now]
    dropped = len(doc.get("retired", [])) - len(keep)
    doc["retired"] = keep
    return dropped


def verification_secrets(doc, now=None):
    """Every secret a token may legitimately have been signed with.

    Current first: almost every token presented was signed with it, so the
    common case costs one verification attempt.
    """
    if not doc:
        return []
    now = _now() if now is None else now
    out = [doc["current"]["secret"]]
    for k in doc.get("retired", []):
        if isinstance(k, dict) and k.get("secret") and int(k.get("not_after", 0)) > now:
            out.append(k["secret"])
    return out


def signing_secret(doc):
    return doc["current"]["secret"] if doc else None


def rotate(doc, lifetime_minutes=DEFAULT_LIFETIME_MINUTES,
           margin_minutes=RETIRE_MARGIN_MINUTES, compromised=False, now=None):
    """Mint a new current key. Returns the new keyring.

    With compromised=True the outgoing key is discarded rather than retired, so
    anything it signed stops working immediately. That DOES log everyone out,
    which is the point.
    """
    now = _now() if now is None else now
    doc = dict(doc or empty(now))
    old = doc.get("current")
    doc["retired"] = list(doc.get("retired", []))
    if old and old.get("secret") and not compromised:
        doc["retired"].insert(0, {
            "secret": old["secret"],
            "retired": now,
            "not_after": now + int(lifetime_minutes + margin_minutes) * 60,
        })
    if compromised:
        doc["retired"] = []
    doc["current"] = {"secret": new_secret(), "created": now}
    doc["version"] = VERSION
    prune(doc, now)
    return doc


def adopt(existing_secret, now=None):
    """Build a keyring that keeps an already-issued secret as current.

    Used once, when migrating a box that has FFN_JWT_SECRET or jwt.secret: the
    sessions open at that moment stay valid, and the first scheduled rotation
    moves off the old key on the normal overlap schedule.
    """
    now = _now() if now is None else now
    return {"version": VERSION,
            "current": {"secret": existing_secret, "created": now, "adopted": True},
            "retired": []}


# ------------------------------------------------------------------- cli ----
def _fmt(ts):
    return time.strftime("%Y-%m-%d %H:%M:%SZ", time.gmtime(int(ts)))


def cmd_status(a):
    doc = load(a.file)
    if not doc:
        print("no keyring at %s" % a.file)
        print("the manager is still using its single secret; run `init` to adopt it")
        return 1
    now = _now()
    cur = doc["current"]
    print("keyring : %s" % a.file)
    print("current : created %s%s" % (_fmt(cur.get("created", 0)),
                                      "  (adopted)" if cur.get("adopted") else ""))
    live = verification_secrets(doc, now)
    print("verifies: %d key(s)" % len(live))
    for k in doc.get("retired", []):
        left = int(k.get("not_after", 0)) - now
        state = "expires in %d min" % (left // 60) if left > 0 else "EXPIRED (prune)"
        print("  retired %s  %s" % (_fmt(k.get("retired", 0)), state))
    return 0


def cmd_init(a):
    if load(a.file) and not a.force:
        print("keyring already exists at %s (use --force to replace)" % a.file)
        return 1
    existing = os.environ.get("FFN_JWT_SECRET")
    src = "FFN_JWT_SECRET"
    if not existing:
        secret_file = os.environ.get("FFN_JWT_SECRET_FILE", "/etc/ffn-ngfw/jwt.secret")
        try:
            with open(secret_file) as fh:
                existing = fh.read().strip()
            src = secret_file
        except OSError:
            existing = None
    if existing:
        doc = adopt(existing)
        print("adopted the existing secret from %s -- open sessions survive" % src)
    else:
        doc = empty()
        print("no existing secret found; generated a new one")
    save(doc, a.file)
    os.chmod(a.file, 0o600)
    print("wrote %s" % a.file)
    return 0


def cmd_rotate(a):
    doc = load(a.file)
    if not doc:
        print("no keyring at %s -- run `init` first" % a.file, file=sys.stderr)
        return 1
    doc = rotate(doc, lifetime_minutes=a.lifetime_minutes,
                 compromised=a.compromised)
    save(doc, a.file)
    if a.compromised:
        print("rotated, old key DISCARDED -- every session is now invalid")
    else:
        print("rotated; %d key(s) still verify, oldest for %d more minutes"
              % (len(verification_secrets(doc)),
                 max([(int(k["not_after"]) - _now()) // 60
                      for k in doc["retired"]] or [0])))
    return 0


def cmd_selftest(a):
    now = 1_000_000
    ring = empty(now)
    first = ring["current"]["secret"]

    ring = rotate(ring, lifetime_minutes=480, now=now)
    second = ring["current"]["secret"]
    assert second != first, "rotation must mint a new key"
    assert first in verification_secrets(ring, now), \
        "a token signed a moment ago must still verify"
    assert signing_secret(ring) == second

    # Just before the overlap ends the old key still verifies; just after, not.
    edge = now + (480 + 60) * 60
    assert first in verification_secrets(ring, edge - 1)
    assert first not in verification_secrets(ring, edge + 1)

    # Rotating twice inside one lifetime keeps both predecessors.
    ring2 = rotate(ring, lifetime_minutes=480, now=now + 60)
    live = verification_secrets(ring2, now + 60)
    assert first in live and second in live, live
    assert len(live) == 3, live

    # Compromised drops everything but the new key.
    ring3 = rotate(ring, lifetime_minutes=480, compromised=True, now=now + 60)
    live3 = verification_secrets(ring3, now + 60)
    assert len(live3) == 1 and first not in live3 and second not in live3

    # Pruning is by time, not by count.
    ring4 = rotate(empty(now), lifetime_minutes=1, now=now)
    assert len(verification_secrets(ring4, now)) == 2
    assert len(verification_secrets(ring4, now + (1 + 60) * 60 + 1)) == 1

    # adopt() keeps the old secret usable.
    ad = adopt("an-existing-secret", now)
    assert signing_secret(ad) == "an-existing-secret"

    print("selftest ok")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--file", default=KEYS_FILE)
    sub = ap.add_subparsers(dest="cmd")
    sub.add_parser("status").set_defaults(fn=cmd_status)
    p_init = sub.add_parser("init")
    p_init.add_argument("--force", action="store_true")
    p_init.set_defaults(fn=cmd_init)
    p_rot = sub.add_parser("rotate")
    p_rot.add_argument("--lifetime-minutes", type=int,
                       default=DEFAULT_LIFETIME_MINUTES,
                       help="token lifetime; must match JWT_EXPIRE_MINUTES")
    p_rot.add_argument("--compromised", action="store_true",
                       help="discard the old key now; logs everyone out")
    p_rot.set_defaults(fn=cmd_rotate)
    sub.add_parser("selftest").set_defaults(fn=cmd_selftest)
    a = ap.parse_args(argv)
    if not getattr(a, "fn", None):
        ap.print_help()
        return 2
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
