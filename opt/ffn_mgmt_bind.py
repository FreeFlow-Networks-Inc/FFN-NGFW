#!/usr/bin/env python3
"""Decide what address the management server should listen on.

The manager used to be started with a hardcoded `--host 0.0.0.0`, so the WebUI
and API answered on every interface the box had -- including data ports -- and
the only thing that could have narrowed it was an nftables rule. There was no
such rule: `nft list ruleset | grep -c 8443` returned 0 on a running appliance.

PAN-OS's model is the one being reproduced here, and it has two halves:

  * the dedicated management port always reaches the box's admin services;
  * any DATA interface reaches them only if an Interface Management Profile is
    attached to it and permits that service (Network > Network Profiles >
    Interface Mgmt), optionally restricted by Permitted IP.

FFN already implements the second half properly: ffn_config_bridge.py reads
`interface-mgmt-profiles` from net_resources, maps `permit_https` to tcp
443/8443, and ffn_bmfw.py emits per-interface nft accepts with `ip saddr`
restrictions behind a default drop. What was missing is that the listener
ignored all of it.

WHAT THIS RETURNS. One address, because that is what uvicorn's --host takes:

  * exactly one interface needs to reach the manager  -> that interface's IPv4
  * more than one does                                -> 0.0.0.0
  * nothing can be resolved                           -> 0.0.0.0

Widening to 0.0.0.0 is only defensible if something else narrows it, so that is
CHECKED rather than assumed -- see nft_enforces_input(). On the 5220 as found,
nothing did: `nft list ruleset` was empty and ffn-bmfw was inactive, so the
manager was answering on every interface with nothing in front of it. When that
is the case the resolver still binds wide, because refusing to start is worse,
but it says so in its reason string and its warning rather than reporting a
protection that is not there.

THE LAST CASE IS DELIBERATE AND IS NOT A BUG. A management server that refuses
to start because it could not resolve an address leaves an appliance with no
way in at all. Binding wide and logging loudly is recoverable; failing closed on
the management path is not.

THE BUG THAT MOTIVATES THE WHOLE RESOLUTION ORDER. A unit can carry a build-host
interface hint that DOES NOT EXIST on the deployed chassis. This illustrative
example uses placeholder interface names and a documentation address:

    # ip -br link show buildnic0
    Device "buildnic0" does not exist.
    # cat /etc/ffn-ngfw/mgmt.conf
    MGMT_IFACE=mgmt0
    MGMT_IP=192.0.2.10/24

Here buildnic0 is the BUILD HOST's NIC, harvested into the image. ffn_config_bridge's
_mgmt_ifaces() documents the same leak and was fixed for it; the systemd unit
was not. So `--host $FFN_MGMT_IFACE` taken at face value would have bound to
nothing and taken the appliance's management offline -- which is exactly the
failure this file exists to avoid. FFN_MGMT_IFACE is therefore treated as a
HINT that must be corroborated against /sys/class/net, never as truth.

Resolution order for the management interface, most trustworthy first:

  1. /etc/ffn-ngfw/mgmt.conf      MGMT_IFACE=, written by provision.sh on the
                                  real chassis from what was actually found
  2. /etc/ffn-ngfw/mgmt-ifaces    the provisioned list ffn_config_bridge reads
  3. $FFN_MGMT_IFACE              the unit's hint -- only if it exists
  4. the default-route interface  a floor, so the box cannot lock itself out

Step 4 is a last resort for the same reason ffn_config_bridge gives: on a
deployed firewall the default route often points out an untrusted port.
"""

import json
import os
import re
import subprocess
import sqlite3
import sys
from xml.etree import ElementTree as ET

DB = os.environ.get("FFN_DB_PATH", "/var/lib/ffn-ngfw/config-v2.db")
XML = os.path.join(os.environ.get("FFN_CONFIG_DIR", "/var/lib/ffn-ngfw/config"),
                   "running-config.xml")
MGMT_CONF = "/etc/ffn-ngfw/mgmt.conf"
MGMT_IFACES_FILE = "/etc/ffn-ngfw/mgmt-ifaces"

# The HTTPS keys an Interface Management Profile can carry. Only these matter
# here: a profile that permits ssh or ping on a data port says nothing about
# where the manager should listen. Kept deliberately in step with
# ffn_config_bridge.SVC2PORTS -- if that grows an https-bearing key, add it.
HTTPS_KEYS = ("permit_https",)


def _real_ifaces():
    try:
        return set(os.listdir("/sys/class/net"))
    except OSError:
        return set()


def _yes(v):
    return str(v).strip().lower() in ("yes", "true", "1", "on")


def _ipv4_of(iface):
    """First global IPv4 on an interface, or None.

    `ip` rather than a socket ioctl because an interface can carry several
    addresses and the ioctl only ever reports the first, which on a box with a
    secondary management address is not necessarily the one being asked about.
    """
    try:
        out = subprocess.run(["ip", "-4", "-o", "addr", "show", "dev", iface],
                             capture_output=True, text=True, timeout=5).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    m = re.search(r"\binet\s+(\d+\.\d+\.\d+\.\d+)/", out)
    return m.group(1) if m else None


def _mgmt_conf_iface():
    try:
        for ln in open(MGMT_CONF):
            ln = ln.split("#")[0].strip()
            if ln.startswith("MGMT_IFACE="):
                return ln.split("=", 1)[1].strip().strip('"').strip("'") or None
    except OSError:
        pass
    return None


def _provisioned_list():
    out = []
    try:
        for ln in open(MGMT_IFACES_FILE):
            ln = ln.split("#")[0].strip()
            if ln:
                out.append(ln)
    except OSError:
        pass
    return out


def _default_route_iface():
    try:
        for ln in list(open("/proc/net/route"))[1:]:
            p = ln.split()
            if len(p) > 2 and p[1] == "00000000":
                return p[0]
    except OSError:
        pass
    return None


def mgmt_iface(real=None):
    """(iface, why) for the dedicated management port, or (None, why)."""
    real = _real_ifaces() if real is None else real
    c = _mgmt_conf_iface()
    if c and c in real:
        return c, "mgmt.conf"
    if c:
        # Worth saying out loud rather than silently moving on: provision.sh
        # wrote it, so if it is gone the chassis changed under the config.
        pass
    for i in _provisioned_list():
        if i in real:
            return i, "mgmt-ifaces"
    env = (os.environ.get("FFN_MGMT_IFACE") or "").strip()
    if env and env in real:
        return env, "FFN_MGMT_IFACE"
    d = _default_route_iface()
    if d and d in real:
        return d, "default-route (last resort)"
    return None, "unresolved"


def _aliases():
    """PAN-OS interface name -> linux device, from the running config."""
    m = {}
    try:
        for e in ET.parse(XML).getroot().iter("interface-alias"):
            for en in e.findall("entry"):
                ln = en.findtext("linux-name")
                if ln:
                    m[en.get("name")] = ln
    except (OSError, ET.ParseError):
        pass
    return m


def https_profile_ifaces(real=None):
    """Data interfaces whose attached Interface Management Profile permits HTTPS.

    Same two sources ffn_config_bridge uses, and deliberately the same shape of
    query, so the listener and the firewall rules cannot disagree about which
    interfaces are supposed to serve the WebUI.
    """
    real = _real_ifaces() if real is None else real
    profs = {}
    try:
        con = sqlite3.connect("file:%s?mode=ro" % DB, uri=True)
        try:
            for name, cfg in con.execute(
                    "SELECT name,config FROM net_resources "
                    "WHERE kind='interface-mgmt-profiles'"):
                try:
                    profs[name] = json.loads(cfg or "{}")
                except ValueError:
                    profs[name] = {}
        finally:
            con.close()
    except sqlite3.Error:
        return []
    if not profs:
        return []

    al = _aliases()
    found = []
    try:
        root = ET.parse(XML).getroot()
    except (OSError, ET.ParseError):
        return []
    for eth in root.iter("ethernet"):
        for en in eth.findall("entry"):
            l3 = en.find("layer3")
            if l3 is None:
                continue
            pn = l3.findtext("interface-management-profile")
            if not pn or pn not in profs:
                continue
            if not any(_yes(profs[pn].get(k, "no")) for k in HTTPS_KEYS):
                continue
            dev = al.get(en.get("name"))
            if dev and dev in real and dev not in found:
                found.append(dev)
    return found


def cp_iface(real=None):
    """The PCIe transport to the control plane, if present.

    The CP reaches the MP's WebUI and API over this, not over the front panel --
    it is a virtual ethernet across PCIe (ffnnet0, 127.1.1.1/24). Binding only
    to the management port would cut that path, so it counts as a required
    listen address whenever the interface exists.

    Set FFN_MGR_CP_ACCESS=no to drop it, which is the right thing on a build
    with no control plane. It is included by default because the failure it
    prevents -- the CP silently losing its management path -- is quiet, while
    the cost of including it is only that the bind may widen to 0.0.0.0.
    """
    if not _yes(os.environ.get("FFN_MGR_CP_ACCESS", "yes")):
        return None
    real = _real_ifaces() if real is None else real
    for cand in ("ffnnet0", "pcicp0"):
        if cand in real:
            return cand
    return None


def nft_enforces_input():
    """Is there actually an nftables input chain that could restrict 8443?

    Asked rather than assumed, because widening the bind is only defensible if
    something else narrows it. On the 5220 as found, nothing did:

        # nft list ruleset | wc -l     -> 0
        # systemctl is-active ffn-bmfw -> inactive

    An empty ruleset with the manager on 0.0.0.0 means the WebUI and API answer
    on every interface the box has, with nothing in front of them. Reporting
    "nftables enforces which" in that state would be a claim this code cannot
    support, so it checks.

    Returns True only for a ruleset that has an input hook AND does not simply
    accept everything -- a chain with `policy accept` and no drop restricts
    nothing.
    """
    try:
        out = subprocess.run(["nft", "list", "ruleset"],
                             capture_output=True, text=True, timeout=10).stdout
    except (OSError, subprocess.SubprocessError):
        return False
    if "hook input" not in out:
        return False
    seg = out[out.index("hook input"):]
    return ("policy drop" in seg) or ("drop" in seg.split("}")[0])


def resolve():
    """(host, reason, detail) -- the address to hand uvicorn's --host."""
    override = (os.environ.get("FFN_MGR_HOST") or "").strip()
    if override:
        return override, "FFN_MGR_HOST override", {"override": override}

    real = _real_ifaces()
    wanted = []          # (iface, why)

    m, why = mgmt_iface(real)
    if m:
        wanted.append((m, "management port (%s)" % why))

    c = cp_iface(real)
    if c:
        wanted.append((c, "control plane over PCIe"))

    for d in https_profile_ifaces(real):
        if d not in [w[0] for w in wanted]:
            wanted.append((d, "interface-mgmt profile permits https"))

    addrs = []
    for iface, why in wanted:
        a = _ipv4_of(iface)
        if a and a not in addrs:
            addrs.append(a)

    detail = {
        "interfaces": [{"iface": i, "why": w, "ipv4": _ipv4_of(i)}
                       for i, w in wanted],
        "addresses": addrs,
    }

    if len(addrs) == 1:
        return addrs[0], "single interface serves the manager", detail

    if len(addrs) > 1:
        # uvicorn takes one --host, so serving two interfaces means binding
        # wide. That is only defensible if something else narrows it, so the
        # claim is checked rather than asserted.
        enforced = nft_enforces_input()
        detail["nft_enforcing"] = enforced
        if enforced:
            return "0.0.0.0", ("%d interfaces must serve the manager; the "
                               "nftables input chain enforces which"
                               % len(addrs)), detail
        detail["warning"] = (
            "bound wide with NO nftables input chain to restrict it -- the "
            "manager answers on every interface. Start ffn-bmfw, or set "
            "FFN_MGR_CP_ACCESS=no to bind only the management port (which "
            "costs the control plane its WebUI path over PCIe).")
        return "0.0.0.0", ("%d interfaces must serve the manager, but NOTHING "
                           "IS ENFORCING the distinction" % len(addrs)), detail

    return "0.0.0.0", "no interface address resolved -- binding wide rather " \
                      "than failing closed on the management path", detail


def main():
    args = sys.argv[1:]
    host, reason, detail = resolve()
    if "--json" in args:
        print(json.dumps({"host": host, "reason": reason, "detail": detail},
                         indent=2))
    elif "--explain" in args:
        print("host   : %s" % host)
        print("reason : %s" % reason)
        for e in detail.get("interfaces", []):
            print("  %-12s %-40s %s" % (e["iface"], e["why"],
                                        e["ipv4"] or "(no IPv4)"))
        if not detail.get("interfaces"):
            print("  (no candidate interfaces)")
        if "nft_enforcing" in detail:
            print("nft    : input chain %s"
                  % ("restricts traffic" if detail["nft_enforcing"]
                     else "ABSENT or accepts everything"))
        if detail.get("warning"):
            print("WARNING: %s" % detail["warning"])
    elif "--write" in args:
        path = args[args.index("--write") + 1]
        d = os.path.dirname(path)
        if d:
            os.makedirs(d, exist_ok=True)
        with open(path, "w") as f:
            f.write("FFN_MGR_HOST=%s\n" % host)
        sys.stderr.write("ffn-mgmt-bind: %s (%s)\n" % (host, reason))
    else:
        print(host)
    return 0


if __name__ == "__main__":
    sys.exit(main())
