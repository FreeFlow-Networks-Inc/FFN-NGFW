#!/usr/bin/env python3
"""Gate the repository against image/PUBLISH-POLICY before anything is published.

Why this exists rather than another grep in a workflow file: the identity leak this
checks for got through because every gate in the build matched FILE NAMES while the
leak lived in file CONTENT, and because two separate ad-hoc scans disagreed about
what counted. The rule lives in PUBLISH-POLICY; this is the only thing that reads it.

It deliberately does NOT print matched text for credential rules. CI logs on a public
repository are public, so a scanner that echoes the secret it found in order to prove
it found one has leaked it a second time. Credential findings report the file, the
line and which rule fired. Identity findings do print the match, because a lab
address or NIC name is not a secret and seeing it is what makes the finding
actionable.

Usage:
    ffn-publish-check.py                # scan git-tracked files from the repo root
    ffn-publish-check.py --root DIR     # scan DIR (all files; use for an unpacked tree)
    ffn-publish-check.py --selftest     # no repo needed
Exit status: 0 clean, 1 findings, 2 usage/policy error.

No third-party imports: the appliance and the runners both have a bare python3.
"""

import argparse
import fnmatch
import os
import re
import subprocess
import sys
import tempfile

POLICY_NAME = "PUBLISH-POLICY"
MAX_BYTES = 4 * 1024 * 1024          # don't read big blobs looking for text patterns
TEXT_EXT_SKIP = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zst", ".gz", ".xz", ".zip",
    ".so", ".o", ".ko", ".bin", ".img", ".qcow2", ".pyc", ".woff", ".woff2", ".ttf",
}


class Policy(object):
    def __init__(self):
        self.deny_path = []
        self.allow_path = []
        self.deny_content = []
        self.deny_identity = []
        self.allow_identity = []      # list of (path_glob, compiled_regex_or_None)

    @classmethod
    def load(cls, path):
        p = cls()
        section = None
        buckets = {
            "deny-path": p.deny_path,
            "allow-path": p.allow_path,
            "deny-content": p.deny_content,
            "deny-identity": p.deny_identity,
        }
        with open(path, encoding="utf-8") as fh:
            for lineno, raw in enumerate(fh, 1):
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                if line.startswith("[") and line.endswith("]"):
                    section = line[1:-1]
                    continue
                if section is None:
                    raise ValueError("%s:%d: entry before any [section]" % (path, lineno))
                if section == "allow-identity":
                    if "::" not in line:
                        raise ValueError(
                            "%s:%d: allow-identity needs 'path-glob :: regex'" % (path, lineno))
                    glob, _, rx = line.partition("::")
                    glob, rx = glob.strip(), rx.strip()
                    p.allow_identity.append((glob, None if rx == ".*" else re.compile(rx)))
                elif section in ("deny-content", "deny-identity"):
                    try:
                        buckets[section].append((line, re.compile(line)))
                    except re.error as exc:
                        raise ValueError("%s:%d: bad regex (%s)" % (path, lineno, exc))
                elif section in buckets:
                    buckets[section].append(line)
                else:
                    raise ValueError("%s:%d: unknown section [%s]" % (path, lineno, section))
        return p

    def path_denied(self, relpath):
        """Return the deny-path glob that rejects relpath, or None."""
        for glob in self.allow_path:
            if fnmatch.fnmatch(relpath, glob) or fnmatch.fnmatch(os.path.basename(relpath), glob):
                return None
        for glob in self.deny_path:
            if fnmatch.fnmatch(relpath, glob) or fnmatch.fnmatch(os.path.basename(relpath), glob):
                return glob
        return None

    def identity_baselined(self, relpath, matched_text):
        for glob, rx in self.allow_identity:
            if not (fnmatch.fnmatch(relpath, glob)
                    or fnmatch.fnmatch(os.path.basename(relpath), glob)):
                continue
            if rx is None or rx.search(matched_text):
                return True
        return False


def tracked_files(root):
    """git-tracked files, or every file when this is not a git checkout."""
    try:
        out = subprocess.run(["git", "-C", root, "ls-files", "-z"],
                             capture_output=True, check=True).stdout
        names = [n.decode("utf-8", "replace") for n in out.split(b"\0") if n]
        if names:
            return names
    except (OSError, subprocess.CalledProcessError):
        pass
    names = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in (".git", "__pycache__")]
        for fn in filenames:
            names.append(os.path.relpath(os.path.join(dirpath, fn), root).replace(os.sep, "/"))
    return names


def readable_text(path):
    try:
        if os.path.getsize(path) > MAX_BYTES:
            return None
    except OSError:
        return None
    if os.path.splitext(path)[1].lower() in TEXT_EXT_SKIP:
        return None
    try:
        with open(path, "rb") as fh:
            blob = fh.read()
    except OSError:
        return None
    if b"\0" in blob[:8192]:
        return None
    return blob.decode("utf-8", "replace")


def scan(root, policy):
    """Return (findings, n_files). A finding is (severity, relpath, lineno, rule, shown)."""
    findings = []
    files = tracked_files(root)
    for rel in files:
        full = os.path.join(root, rel)
        if not os.path.isfile(full):
            continue

        glob = policy.path_denied(rel)
        if glob:
            findings.append(("DENY-PATH", rel, 0, glob, ""))
            continue

        text = readable_text(full)
        if text is None:
            continue

        for lineno, line in enumerate(text.splitlines(), 1):
            for pat, rx in policy.deny_content:
                if rx.search(line):
                    # Never echo the match: this may be a live credential.
                    findings.append(("DENY-CONTENT", rel, lineno, pat, "<redacted>"))
            for pat, rx in policy.deny_identity:
                m = rx.search(line)
                if m and not policy.identity_baselined(rel, m.group(0)):
                    findings.append(("DENY-IDENTITY", rel, lineno, pat, m.group(0)))
    return findings, len(files)


# --------------------------------------------------------------------------------
# selftest -- proves the rules bite, and proves the baseline suppresses
# --------------------------------------------------------------------------------
SELFTEST_POLICY = """
[deny-path]
*.key
*/shadow
[allow-path]
*.pub
[deny-content]
-----BEGIN [A-Z ]*PRIVATE KEY-----
(?:FFN_ROOT_PW)\\s*=\\s*["'][^"'$][^"']{5,}["']
[deny-identity]
\\b10\\.1\\.0\\.106\\b
[allow-identity]
docs/lab.md :: \\b10\\.1\\.0\\.106\\b
"""

def selftest():
    groups = failed = 0

    def check(name, cond):
        nonlocal groups, failed
        groups += 1
        if cond:
            print("  ok   %s" % name)
        else:
            print("  FAIL %s" % name)
            failed += 1

    with tempfile.TemporaryDirectory() as td:
        pol_path = os.path.join(td, POLICY_NAME)
        with open(pol_path, "w", encoding="utf-8") as fh:
            fh.write(SELFTEST_POLICY)
        pol = Policy.load(pol_path)

        def write(rel, body):
            p = os.path.join(td, rel)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "w", encoding="utf-8") as fh:
                fh.write(body)

        write("etc/server.key", "anything")
        write("etc/update.pub", "0" * 64)
        write("etc/shadow", "root:x:1::::::")
        write("src/a.py", 'KEY = """-----BEGIN OPENSSH PRIVATE KEY-----"""\n')
        write("image/config.sh", 'export FFN_ROOT_PW="${FFN_ROOT_PW:-}"\n')
        write("image/bad.sh", 'export FFN_ROOT_PW="Hunter2Hunter2"\n')
        write("docs/lab.md", "the build server is 10.1.0.106\n")
        write("opt/leak.py", "URL = 'https://10.1.0.106:8444'\n")

        f, n = scan(td, pol)
        by = {}
        for sev, rel, line, rule, shown in f:
            by.setdefault((sev, rel), []).append((line, rule, shown))

        check("deny-path catches *.key", ("DENY-PATH", "etc/server.key") in by)
        check("deny-path catches shadow", ("DENY-PATH", "etc/shadow") in by)
        check("allow-path exempts *.pub", ("DENY-PATH", "etc/update.pub") not in by)
        check("deny-content catches PEM private key", ("DENY-CONTENT", "src/a.py") in by)
        check("permitted ${VAR:-} form is NOT flagged",
              ("DENY-CONTENT", "image/config.sh") not in by)
        check("literal password IS flagged", ("DENY-CONTENT", "image/bad.sh") in by)
        check("credential findings are redacted",
              all(s == "<redacted>" for k, v in by.items() if k[0] == "DENY-CONTENT"
                  for _, _, s in v))
        check("baselined identity suppressed", ("DENY-IDENTITY", "docs/lab.md") not in by)
        check("new identity flagged", ("DENY-IDENTITY", "opt/leak.py") in by)
        check("identity findings show the match",
              any(s == "10.1.0.106" for k, v in by.items() if k[0] == "DENY-IDENTITY"
                  for _, _, s in v))
        check("scanned every file", n == 9)   # 8 fixtures + the policy file itself

    print("\n%d groups, %d failed" % (groups, failed))
    return 1 if failed else 0


def main():
    ap = argparse.ArgumentParser(description="gate the repo against image/PUBLISH-POLICY")
    ap.add_argument("--root", default=None, help="tree to scan (default: repo root)")
    ap.add_argument("--policy", default=None, help="policy file (default: <root>/image/PUBLISH-POLICY)")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()

    if args.selftest:
        return selftest()

    here = os.path.dirname(os.path.abspath(__file__))
    root = os.path.abspath(args.root) if args.root else os.path.dirname(here)
    policy_path = args.policy or os.path.join(root, "image", POLICY_NAME)
    if not os.path.isfile(policy_path):
        policy_path = os.path.join(here, POLICY_NAME)
    if not os.path.isfile(policy_path):
        sys.stderr.write("no %s found (looked in %s)\n" % (POLICY_NAME, policy_path))
        return 2

    try:
        policy = Policy.load(policy_path)
    except ValueError as exc:
        sys.stderr.write("policy error: %s\n" % exc)
        return 2

    findings, n = scan(root, policy)
    print("ffn-publish-check: %d files scanned against %s"
          % (n, os.path.relpath(policy_path, root)))

    if not findings:
        print("PASS: nothing in the tree violates the publication policy")
        return 0

    order = {"DENY-PATH": 0, "DENY-CONTENT": 1, "DENY-IDENTITY": 2}
    findings.sort(key=lambda f: (order.get(f[0], 9), f[1], f[2]))
    for sev, rel, lineno, rule, shown in findings:
        where = "%s:%d" % (rel, lineno) if lineno else rel
        extra = (" -- %s" % shown) if shown and shown != "<redacted>" else (
            " -- value withheld (CI logs are public)" if shown else "")
        print("  %-13s %s%s\n                rule: %s" % (sev, where, extra, rule))

    print("\nFAIL: %d finding(s). See image/%s for the rule and how to baseline an"
          " intentional pre-existing occurrence." % (len(findings), POLICY_NAME))
    return 1


if __name__ == "__main__":
    sys.exit(main())
