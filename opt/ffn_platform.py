#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""ffn_platform.py -- list and select hardware platform submodules.

    ffn_platform.py list                what hardware is supported, with git URLs
    ffn_platform.py current             which platform is selected, if any
    ffn_platform.py select <name>       check out that platform's submodule
    ffn_platform.py deselect <name>     remove it again
    ffn_platform.py verify              registry vs. reality vs. platform.json
    ffn_platform.py selftest            registry-logic tests, no git needed

WHY A COMMAND RATHER THAN JUST DOCUMENTATION

Platforms are registered in `.gitmodules` with `update = none`, which is what
makes them opt-in: `git clone`, *including* `git clone --recursive`, skips them.
The consequence is that the obvious command does the wrong thing --

    git submodule update --init platform/pa5200        # prints "Skipping"

-- because `--checkout` is required to override `update = none`. That is a sharp
edge worth wrapping rather than documenting and hoping.

It also gives selection somewhere to check itself: that the platform is in the
registry, that its URL matches `.gitmodules`, and that the datapath policy the
registry advertises is the one the platform actually declares.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from typing import Dict, List, Optional, Tuple

REGISTRY = os.path.join("platform", "platforms.json")

def _repo_root() -> str:
    """The repository root, found from this script's location.

    Walks up looking for platform/platforms.json. Deriving it from __file__
    rather than defaulting to os.getcwd() means the tool works from any working
    directory -- and it has to, now that these scripts live in opt/ rather than
    at the root they describe.
    """
    here = os.path.dirname(os.path.abspath(__file__))
    d = here
    for _ in range(4):
        if os.path.isfile(os.path.join(d, "platform", "platforms.json")):
            return d
        parent = os.path.dirname(d)
        if parent == d:
            break
        d = parent
    return os.getcwd()          # last resort: behave as before

GITMODULES = ".gitmodules"
DECL = "platform.json"


# --------------------------------------------------------------------------
# Registry
# --------------------------------------------------------------------------

def load_registry(root: str = ".") -> List[Dict]:
    path = os.path.join(root, REGISTRY)
    try:
        with open(path) as fh:
            data = json.load(fh)
    except FileNotFoundError:
        raise SystemExit("ffn_platform: %s not found -- run from the repository "
                         "root, or pass --root" % path)
    except Exception as exc:
        raise SystemExit("ffn_platform: cannot parse %s: %s" % (path, exc))
    return [p for p in data.get("platforms", []) if p.get("name")]


def submodule_platforms(root: str = ".") -> List[Dict]:
    """Registry entries that are actual submodules (not the builtin generic)."""
    return [p for p in load_registry(root) if p.get("path")]


def find(root: str, name: str) -> Dict:
    for p in load_registry(root):
        if p["name"] == name:
            return p
    known = ", ".join(p["name"] for p in load_registry(root))
    raise SystemExit("ffn_platform: unknown platform %r. Known: %s"
                     % (name, known))


def gitmodules_urls(root: str = ".") -> Dict[str, str]:
    """path -> url, straight from .gitmodules. Empty when git is unavailable."""
    out: Dict[str, str] = {}
    try:
        txt = subprocess.check_output(
            ["git", "config", "-f", os.path.join(root, GITMODULES),
             "--get-regexp", r"^submodule\..*\.(path|url)$"],
            stderr=subprocess.DEVNULL).decode()
    except Exception:
        return out
    paths: Dict[str, str] = {}
    urls: Dict[str, str] = {}
    for line in txt.splitlines():
        if " " not in line:
            continue
        key, val = line.split(" ", 1)
        parts = key.split(".")
        if len(parts) < 3:
            continue
        sub = ".".join(parts[1:-1])
        if parts[-1] == "path":
            paths[sub] = val
        elif parts[-1] == "url":
            urls[sub] = val
    for sub, path in paths.items():
        if sub in urls:
            out[path] = urls[sub]
    return out


def is_selected(root: str, entry: Dict) -> bool:
    """A platform is selected when its submodule directory has content."""
    path = entry.get("path")
    if not path:
        return False
    full = os.path.join(root, path)
    try:
        return any(n != ".git" for n in os.listdir(full))
    except Exception:
        return False


def read_decl(root: str, entry: Dict) -> Optional[Dict]:
    path = entry.get("path")
    if not path:
        return None
    try:
        with open(os.path.join(root, path, DECL)) as fh:
            return json.load(fh)
    except Exception:
        return None


# --------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------

def cmd_list(root: str, as_json: bool = False) -> int:
    entries = load_registry(root)
    if as_json:
        for e in entries:
            e = dict(e)
            e["selected"] = is_selected(root, e)
        print(json.dumps(entries, indent=2))
        return 0

    print("Hardware platforms")
    print()
    for e in entries:
        sel = " [SELECTED]" if is_selected(root, e) else ""
        status = e.get("status", "?")
        mark = {"supported": "*", "planned": "-", "builtin": "="}.get(status, "?")
        print("  %s %-10s %s%s" % (mark, e["name"], e.get("hardware", ""), sel))
        if e.get("silicon") and e["silicon"] != "commodity":
            print("      silicon  : %s" % e["silicon"])
        print("      datapath : %s   cpu isolation: %s"
              % (e.get("datapath", "?"), e.get("cpu_isolation", "?")))
        if e.get("url"):
            print("      git      : %s" % e["url"])
        if e.get("notes"):
            print("      note     : %s" % e["notes"])
        if status == "planned":
            print("      STATUS   : planned -- not yet published, do not clone")
        print()
    print("  legend: * supported   - planned   = builtin (no submodule)")
    print()
    print("  select with: ffn_platform.py select <name>")
    return 0


def cmd_current(root: str) -> int:
    sel = [e for e in submodule_platforms(root) if is_selected(root, e)]
    if not sel:
        print("no platform selected -- running as generic hardware "
              "(DPDK datapath, isolation auto)")
        return 0
    for e in sel:
        decl = read_decl(root, e) or {}
        print("%s  (%s)" % (e["name"], e["path"]))
        print("  hardware : %s" % e.get("hardware", ""))
        print("  datapath : %s" % decl.get("datapath", e.get("datapath", "?")))
        print("  isolation: %s" % decl.get("cpu_isolation",
                                           e.get("cpu_isolation", "?")))
    if len(sel) > 1:
        print()
        print("WARNING: %d platforms are selected. One host is one platform; "
              "tooling that reads platform.json will refuse to guess." % len(sel))
        return 1
    return 0


def cmd_select(root: str, name: str) -> int:
    e = find(root, name)
    if not e.get("path"):
        print("%r is builtin -- it is what runs with no platform selected, so "
              "there is nothing to check out." % name)
        return 0
    if e.get("status") == "planned":
        print("%r is planned, not published: %s\nNothing to select yet."
              % (name, e.get("notes", "")), file=sys.stderr)
        return 2

    already = [o for o in submodule_platforms(root)
               if is_selected(root, o) and o["name"] != name]
    if already:
        print("already selected: %s. One host is one platform; deselect it "
              "first:\n  ffn_platform.py deselect %s"
              % (", ".join(o["name"] for o in already), already[0]["name"]),
              file=sys.stderr)
        return 2

    # `--checkout` is what overrides `update = none`; without it git reports
    # that it is skipping the submodule and leaves an empty directory.
    cmd = ["git", "submodule", "update", "--init", "--checkout", e["path"]]
    print("+ %s" % " ".join(cmd))
    rc = subprocess.call(cmd, cwd=root)
    if rc != 0:
        return rc
    if not is_selected(root, e):
        print("submodule reported success but %s is still empty" % e["path"],
              file=sys.stderr)
        return 1
    print()
    print("selected %s" % name)
    decl = read_decl(root, e)
    if decl:
        print("  datapath      : %s" % decl.get("datapath", "?"))
        print("  cpu isolation : %s" % decl.get("cpu_isolation", "?"))
        if decl.get("reason"):
            print("  reason        : %s" % decl["reason"])
    print()
    print("next: ffn_cpuisol.py show     # what this means for the kernel cmdline")
    return 0


def cmd_deselect(root: str, name: str) -> int:
    e = find(root, name)
    if not e.get("path"):
        print("%r is builtin; nothing to deselect." % name)
        return 0
    cmd = ["git", "submodule", "deinit", "-f", e["path"]]
    print("+ %s" % " ".join(cmd))
    return subprocess.call(cmd, cwd=root)


def cmd_verify(root: str) -> int:
    problems: List[str] = []
    entries = load_registry(root)
    gm = gitmodules_urls(root)

    for e in entries:
        path, url = e.get("path"), e.get("url")
        if not path:
            continue
        if e.get("status") == "planned":
            if path in gm:
                problems.append(
                    "%s is marked planned but is registered in .gitmodules -- "
                    "either publish it and mark it supported, or unregister it"
                    % e["name"])
            continue
        if path not in gm:
            problems.append("%s: %s is in the registry but not in .gitmodules"
                            % (e["name"], path))
        elif url and gm[path].rstrip("/") != url.rstrip("/"):
            problems.append("%s: URL mismatch\n    registry   : %s\n"
                            "    .gitmodules: %s" % (e["name"], url, gm[path]))
        # the registry advertises a policy; the platform declares the real one
        decl = read_decl(root, e)
        if decl:
            for key in ("datapath", "cpu_isolation"):
                if key in decl and key in e and decl[key] != e[key]:
                    problems.append(
                        "%s: registry says %s=%r but %s/%s declares %r. The "
                        "declaration wins at runtime, so the registry is "
                        "misleading." % (e["name"], key, e[key], path, DECL,
                                         decl[key]))

    for path in gm:
        if not any(x.get("path") == path for x in entries):
            problems.append("%s is a submodule but is not in the registry -- "
                            "add it to %s" % (path, REGISTRY))

    sel = [e for e in submodule_platforms(root) if is_selected(root, e)]
    if len(sel) > 1:
        problems.append("%d platforms selected at once: %s"
                        % (len(sel), ", ".join(e["name"] for e in sel)))

    if problems:
        for p in problems:
            print("PROBLEM: %s" % p)
        return 1
    print("OK: registry, .gitmodules and platform declarations agree")
    return 0


# --------------------------------------------------------------------------
# Selftest
# --------------------------------------------------------------------------

def selftest() -> int:
    import tempfile
    fails = []

    def check(name, cond, detail=""):
        print("  %-4s %s%s" % ("ok" if cond else "FAIL", name,
                               "" if cond else "  <- " + detail))
        if not cond:
            fails.append(name)

    root = tempfile.mkdtemp(prefix="ffnplat")
    os.makedirs(os.path.join(root, "platform", "demo"))
    reg = {"schema": 1, "platforms": [
        {"name": "demo", "path": "platform/demo", "url": "https://x/demo.git",
         "status": "supported", "hardware": "Demo", "datapath": "offload",
         "cpu_isolation": "none"},
        {"name": "later", "path": "platform/later", "url": "https://x/later.git",
         "status": "planned", "hardware": "Later"},
        {"name": "generic", "path": None, "url": None, "status": "builtin",
         "hardware": "Any x86-64", "datapath": "dpdk", "cpu_isolation": "auto"},
    ]}
    with open(os.path.join(root, "platform", "platforms.json"), "w") as fh:
        json.dump(reg, fh)

    print("[1] registry loads and separates submodules from builtin")
    check("3 entries", len(load_registry(root)) == 3)
    check("2 are submodules", len(submodule_platforms(root)) == 2)

    print("[2] selection is detected by directory content, not by config")
    demo = find(root, "demo")
    check("empty dir is not selected", is_selected(root, demo) is False)
    with open(os.path.join(root, "platform", "demo", "platform.json"), "w") as fh:
        json.dump({"platform": "demo", "datapath": "offload",
                   "cpu_isolation": "none"}, fh)
    check("populated dir is selected", is_selected(root, demo) is True)

    print("[3] the declaration is read back")
    d = read_decl(root, demo)
    check("datapath offload", (d or {}).get("datapath") == "offload")

    print("[4] a planned platform cannot be selected")
    rc = cmd_select(root, "later")
    check("select refuses", rc == 2)

    print("[5] builtin is a no-op rather than an error")
    check("select generic returns 0", cmd_select(root, "generic") == 0)

    print("[6] an unknown name is rejected")
    try:
        find(root, "nope")
        check("raises", False, "no SystemExit")
    except SystemExit:
        check("raises", True)

    print("[7] verify catches registry vs declaration drift")
    with open(os.path.join(root, "platform", "demo", "platform.json"), "w") as fh:
        json.dump({"platform": "demo", "datapath": "dpdk",
                   "cpu_isolation": "auto"}, fh)
    rc = cmd_verify(root)
    check("drift reported", rc == 1)

    print("\n==== ffn_platform selftest: %d failed ====" % len(fails))
    return 1 if fails else 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="list and select hardware platforms")
    ap.add_argument("cmd", choices=["list", "current", "select", "deselect",
                                    "verify", "selftest"])
    ap.add_argument("name", nargs="?")
    ap.add_argument("--root", default=None)
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    if a.root is None:
        a.root = _repo_root()

    if a.cmd == "selftest":
        return selftest()
    if a.cmd == "list":
        return cmd_list(a.root, a.json)
    if a.cmd == "current":
        return cmd_current(a.root)
    if a.cmd == "verify":
        return cmd_verify(a.root)
    if not a.name:
        print("%s needs a platform name (see: ffn_platform.py list)" % a.cmd,
              file=sys.stderr)
        return 2
    if a.cmd == "select":
        return cmd_select(a.root, a.name)
    return cmd_deselect(a.root, a.name)


if __name__ == "__main__":
    sys.exit(main())
