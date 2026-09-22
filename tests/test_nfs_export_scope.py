#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 FreeFlow Networks, Inc.
"""No committed NFS export may hand no_root_squash to more than one host.

.. warning::

    `image/provision.sh` wrote five exports at `127.1.0.0/16(rw,no_root_squash)`
    into EVERY freshly built appliance, under a comment reading "the client
    scoping below is what actually gates mounting". The scoping was the gate,
    and it was a /16.

That range contains the DP at 127.1.2.2, the exports are rw,no_root_squash, and
they include the CP's live root filesystems -- so the DP could mount and rewrite
the CP's root. The PCIe ingress filters do not close it: both ends deliberately
admit DP traffic addressed to the MP, because the CP has to route it, and
neither looks at protocol or port, so DP -> MP:2049 is permitted by design.

ffn-platform-pa5200's `tools/ffn_nfsd.sh` had already worked this out and
written it down. It did not stop three other files in that repository, or this
one, from handing out the /16 anyway -- which is the whole argument for a test
rather than a comment.

THE RULE. An export carrying `no_root_squash` must name exactly one client: a
bare IPv4 address, or one with an explicit /32. A shorter prefix, a wildcard or
a netgroup is rejected. no_root_squash means every UID on the client is trusted
as that UID on the server, root included, so the set of hosts allowed to mount
is the entire access control -- widening it by one bit doubles the number of
machines that own the filesystem.

`ro` is not an exemption. A read-only export of a root filesystem to a host that
should not see it is still a disclosure.

WHAT THIS DOES NOT CHECK. Whether the one named host is the *right* host -- that
needs the plane map, and getting it wrong is a functional bug that shows up
immediately as a failed mount. This checks the property that fails silently:
an export that works perfectly while also being reachable by machines nobody
considered.
"""
import os
import re
import subprocess
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.normpath(os.path.join(HERE, ".."))

SKIP_DIRS = {".git", ".github", "__pycache__"}
TEXT_SUFFIX = (".sh", ".py", ".conf", ".md", ".service", ".env", "")

# `/export/path  client(opt,opt)` -- an exports(5) line.
EXPORTS_LINE = re.compile(r"^\s*(/\S+)\s+(\S+?)\(([^)]*)\)", re.M)
# `exportfs -o opt,opt client:/path`, which in practice is written across three
# backslash-continued lines -- so this must cross newlines. An earlier version
# used [^\n]*? and silently matched nothing in the one file that has this form,
# which is why test_the_scanner_actually_matches_both_forms exists.
EXPORTFS_CMD = re.compile(
    r"exportfs\b[\s\S]{0,200}?-o\s+(\S+)[\s\\]+\"?([^\s\"':]+):(\S+?)\"?(?:\s|$)")

SINGLE_HOST = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}(?:/32)?$")


def interesting(name):
    if name.startswith("exports.") or name.endswith(".exports"):
        return True
    return os.path.splitext(name)[1] in TEXT_SUFFIX


def candidate_files():
    """Files COMMITTED TO THIS REPOSITORY -- deliberately not everything on disk.

    A filesystem walk audits whatever happens to be in the workspace --
    submodules, a sibling checkout a CI job dropped in, build output. Those
    findings may be real but they are not this repository's to fix, and a gate
    that fails on someone else's file is a gate people learn to ignore.

    `git ls-files` is the precise expression of what the docstring claims to
    check: the files this repository commits.
    """
    names = None
    try:
        out = subprocess.run(["git", "-C", REPO, "ls-files", "-z"],
                             stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                             check=True).stdout.decode("utf-8", "replace")
        names = [n for n in out.split("\0") if n]
    except (OSError, subprocess.CalledProcessError):
        names = None

    if names is not None:
        for rel in names:
            if interesting(os.path.basename(rel)):
                yield os.path.join(REPO, rel.replace("/", os.sep))
        return

    # No git (an exported tarball): fall back to a walk, and skip every dotted
    # directory so a nested checkout is still not mistaken for our own content.
    for root, dirs, files in os.walk(REPO):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".")]
        for name in files:
            if interesting(name):
                yield os.path.join(root, name)


def read(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return ""


def findings():
    """(relpath, client, options, where) for every too-wide export."""
    out = []
    for path in candidate_files():
        rel = os.path.relpath(path, REPO).replace(os.sep, "/")
        if rel == "tests/test_nfs_export_scope.py":
            continue                      # this file quotes the bad values
        text = read(path)
        if "no_root_squash" not in text:
            continue
        for mount, client, opts in EXPORTS_LINE.findall(text):
            if "no_root_squash" in opts and not SINGLE_HOST.match(client):
                out.append((rel, client, opts, mount))
        for opts, client, mount in EXPORTFS_CMD.findall(text):
            if "no_root_squash" in opts and not SINGLE_HOST.match(client):
                out.append((rel, client, opts, mount))
    return out


class ExportScope(unittest.TestCase):
    def test_no_root_squash_names_exactly_one_host(self):
        bad = findings()
        if bad:
            lines = ["%s: %s -> %s  (%s)" % (rel, mount, client, opts)
                     for rel, client, opts, mount in bad]
            self.fail(
                "no_root_squash exported to more than one host:\n  "
                + "\n  ".join(lines)
                + "\n\nno_root_squash trusts every UID on the client, root "
                  "included, so the client list is the entire access control. "
                  "Name the single host that mounts it.")

    def test_the_scanner_actually_matches_both_forms(self):
        """A scanner that silently matches nothing would pass forever."""
        exports_form = "/opt/dproot 127.1.0.0/16(rw,sync,no_root_squash,fsid=7)\n"
        self.assertEqual(
            EXPORTS_LINE.findall(exports_form),
            [("/opt/dproot", "127.1.0.0/16", "rw,sync,no_root_squash,fsid=7")])

        cmd_form = ('chroot "$C" /usr/sbin/exportfs \\\n'
                    '\t-o ro,sync,no_root_squash,no_subtree_check,fsid=9 \\\n'
                    '\t"127.1.0.0/16:$EXPORT" || exit 3\n')
        got = EXPORTFS_CMD.findall(cmd_form)
        self.assertEqual(len(got), 1, got)
        self.assertEqual(got[0][1], "127.1.0.0/16")

    def test_single_host_forms_accepted_and_wide_forms_rejected(self):
        for ok in ("127.1.1.2", "127.1.2.2", "10.0.0.1/32"):
            self.assertTrue(SINGLE_HOST.match(ok), ok)
        for bad in ("127.1.0.0/16", "127.1.1.0/24", "*", "*.lab", "10.0.0.0/8",
                    "@netgroup", "127.1.1.2/31"):
            self.assertFalse(SINGLE_HOST.match(bad), bad)

    def test_it_looks_at_the_files_that_actually_carry_exports(self):
        seen = {os.path.relpath(p, REPO).replace(os.sep, "/")
                for p in candidate_files()}
        for expect in ("image/provision.sh",):
            self.assertIn(expect, seen, "scanner would not have read %s" % expect)


if __name__ == "__main__":
    unittest.main(verbosity=2)
