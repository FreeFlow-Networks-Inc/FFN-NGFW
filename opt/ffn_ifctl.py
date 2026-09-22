#!/usr/bin/env python3
"""ffn_ifctl -- the DP command-ring port table. LEGACY, and not the appliance path.

This drives the port table of a DP application over the command/event ring. It
predates the MP/CP/DP control daemons, and on a PA-5200 it is NOT how interfaces
are configured: that goes through `ffn_planed.py` to the platform's own
controllers, which reach the OCTEON forwarder, the switch and the front-end ASIC.
Reading a result from here as evidence about a faceplate port is reading the
wrong backend -- the historical failure this header now exists to prevent.

What it is still good for: driving and inspecting a file-backed region, which is
how `dp_serve` runs the real C dispatch loop on a host for development.

    region in /etc/ffn-ngfw/dp-ports.json
      "file:/path"  -- file-backed region. This is the mode that works and the
                       one the tests use.
      "bar:PCI:N"   -- an Octeon BAR through the paged BAR1 window
                       (tools/ffn_octdram.py). Wired up, not qualified.

Two further honesties. The DP advertises `PORT_HW` in `dp_caps` only when it was
built with the chip accessors; without it the port table is tracked state and no
register is driven, so `hardware_applied` is False and nothing may be presented
as live. And this module carries no faceplate of its own: a plan comes from the
configuration file, because the port complement of a chassis belongs to that
chassis's platform module, not to a core tool that cannot see the hardware.
"""
import json
import os
import sys

sys.path.insert(0, "/opt/ffn-ngfw-v2")

try:
    import ffn_dpring as D
except ImportError:                                  # pragma: no cover
    D = None

CONF = "/etc/ffn-ngfw/dp-ports.json"

# Form factor -> a name an operator recognises. PAN numbers front-panel ports
# ethernet1/N, so FFN does the same for data ports.
DEFAULT_NAME = "ethernet1/%d"


def _load_conf():
    try:
        with open(CONF) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def _save_conf(c):
    tmp = CONF + ".tmp"
    with open(tmp, "w") as f:
        json.dump(c, f, indent=2, sort_keys=True)
        f.write("\n")
    os.replace(tmp, CONF)


class IfCtl:
    """Attach to a DP region and drive its port table."""

    def __init__(self, region=None):
        self.conf = _load_conf()
        self.region = region or self.conf.get("region") or ""
        self.ring = None
        self.error = None

    # -- attach ---------------------------------------------------------
    def __enter__(self):
        if D is None:
            self.error = "ffn_dpring not importable"
            return self
        if not self.region:
            self.error = ("no region configured; set \"region\" in %s to "
                          "file:<path> or bar:<pci>:<bar>" % CONF)
            return self
        try:
            if self.region.startswith("file:"):
                self.ring = D.DpRing.open_file(self.region[5:])
            elif self.region.startswith("bar:"):
                _k, pci, bar = self.region.split(":", 2)
                self.ring = D.DpRing.open_bar(pci, int(bar))
            else:
                self.error = "region must start with file: or bar:"
                return self
            self.ring.handshake()
        except (OSError, ValueError, D.DpError) as e:
            self.error = str(e)
            self.ring = None
        return self

    def __exit__(self, *a):
        if self.ring:
            self.ring.close()

    @property
    def ok(self):
        return self.ring is not None

    # -- status ---------------------------------------------------------
    def caps(self):
        if not self.ok:
            return {"available": False, "error": self.error}
        c = self.ring.caps()
        return {"available": True,
                "region": self.region,
                "caps": "0x%x" % c,
                "port_ctl": bool(c & D.CAP_PORT_CTL),
                "port_stats": bool(c & D.CAP_PORT_STATS),
                "hardware_applied": bool(c & D.CAP_PORT_HW)}

    def ports(self):
        """Port table as interface dicts in ffn_manager's shape, so the
        existing Devices > Setup > Interfaces page can render them next to
        the host NICs without a second code path."""
        if not self.ok:
            return []
        hw = bool(self.ring.caps() & D.CAP_PORT_HW)
        out = []
        for p in self.ring.ports():
            lp = p["lport"]
            name = (self.conf.get("names", {}).get(str(lp))
                    or DEFAULT_NAME % (lp + 1))
            lmac = ("bgx%d/%d %s" % (p["bgx"], p["lmac"], p["lmac_type"])
                    if p["has_lmac"] else "")
            out.append({
                # the fields the existing page already understands
                "name": name,
                "port": lp,
                "type": "octeon",
                "mac": "",
                "link_up": p["link_up"],
                "speed_gbps": round(p["speed_mbps"] / 1000.0, 1),
                "mtu": p["mtu"],
                "rx_bytes": 0, "tx_bytes": 0,
                "rx_packets": p["rx_pkts"], "tx_packets": p["tx_pkts"],
                "rx_drops": 0, "tx_drops": 0, "rx_errors": 0,
                # dataplane specifics the page can show as extra columns
                "form_factor": p["port_type"],
                "role": p["role"],
                "state": p["state"],
                "media": p["media"],
                "negotiation": p["neg"],
                "admin_up": p["admin_up"],
                "bridgeable": p["bridgeable"],
                "lmac": lmac,
                # never let the UI imply a port is live when nothing is driven
                "hardware_applied": hw,
            })
        return out

    # -- apply ----------------------------------------------------------
    def apply_port(self, lport, form_factor="SFP+", role="data",
                   speed_mbps=10000, mtu=1500, admin_up=False,
                   neg="autoneg", lmac_type=None, lane=0, phy=0xFF):
        """Push one port's configuration, then its admin state.

        Order matters and mirrors the DP's own rule: configure first, admin
        second. Configuration deliberately does not start a port.
        """
        if not self.ok:
            return {"ok": False, "error": self.error}
        c = self.ring.caps()
        if not c & D.CAP_PORT_CTL:
            return {"ok": False,
                    "error": "DP does not advertise PORT_CTL (caps=0x%x)" % c}
        try:
            self.ring.port_config(lport, form_factor, lmac_type=lmac_type,
                                  lane=lane, neg=neg, phy=phy,
                                  speed=speed_mbps, mtu=mtu, role=role)
            if admin_up:
                if not D.role_bridgeable(role):
                    return {"ok": False, "lport": lport,
                            "error": "role %r is not bridgeable; refusing "
                                     "admin-up" % role}
                self.ring.port_admin(lport, True)
        except D.DpError as e:
            return {"ok": False, "lport": lport, "error": str(e)}
        return {"ok": True, "lport": lport,
                "hardware_applied": bool(c & D.CAP_PORT_HW)}

    def apply_all(self, plan, settle=0.5):
        """Apply a list of {lport, form_factor, role, ...} dicts.

         counts commands accepted into the ring;  counts
        ports the DP actually created. Those are different things -- the ring
        is asynchronous, so a push succeeding says nothing about the DP having
        processed it. Reporting only the queue count is the same mistake as
        treating a mailbox ack as completion, so both are returned.
        """
        import time as _t
        results = [self.apply_port(**p) for p in plan]
        queued = sum(1 for r in results if r.get("ok"))
        if settle:
            _t.sleep(settle)
        want = {p["lport"] for p in plan}
        have = {p["lport"] for p in self.ring.ports()} if self.ok else set()
        return {"queued": queued,
                "confirmed": len(want & have),
                "missing": sorted(want - have),
                "failed": [r for r in results if not r.get("ok")],
                "results": results}

    def drain_events(self):
        return self.ring.drain() if self.ok else []


# ---------------------------------------------------------------- CLI ------
def _cmd_status(a):
    with IfCtl(_region(a)) as c:
        print(json.dumps(c.caps(), indent=2))
        return 0 if c.ok else 1


def _cmd_ports(a):
    with IfCtl(_region(a)) as c:
        if not c.ok:
            print("not available: %s" % c.error)
            return 1
        ps = c.ports()
        if not ps:
            print("no ports in the DP table")
            return 0
        hw = ps[0]["hardware_applied"]
        print("%-13s %-5s %-8s %-7s %-9s %-8s %-6s %-6s %s"
              % ("name", "port", "form", "role", "state", "media", "admin",
                 "link", "lmac"))
        for p in ps:
            print("%-13s %-5d %-8s %-7s %-9s %-8s %-6s %-6s %s"
                  % (p["name"], p["port"], p["form_factor"], p["role"],
                     p["state"], p["media"],
                     "up" if p["admin_up"] else "down",
                     "up" if p["link_up"] else "down", p["lmac"]))
        if not hw:
            print()
            print("NOTE: the DP does not advertise PORT_HW -- this table is "
                  "tracked state, not hardware. Nothing is being driven.")
        return 0


def _owned_elsewhere(a):
    """A plane daemon and this ring must not both own the same ports.

    A selected control daemon is the interface owner on that host. Applying here
    as well is the split-ownership failure the plane architecture warns about,
    and it is silent: both writers succeed and the survivor is whichever wrote
    last. Refuse by default and make overriding it deliberate.
    """
    socket = os.environ.get("FFN_PLANE_SOCKET", "")
    if not socket or "--force" in a:
        return False
    print("refusing: a control daemon is selected (FFN_PLANE_SOCKET=%s) and owns\n"
          "these interfaces. Configure them through it -- ffn_plane_network.py, or\n"
          "the Control Planes page. Pass --force only to drive a development\n"
          "region that no daemon is managing." % socket)
    return True


def _cmd_apply(a):
    """Apply the plan in the config file.

    There is deliberately no built-in plan. The one that used to live here
    described a per-Octeon PA-5220 complement that the chassis does not have,
    and a core tool that cannot see the hardware has no business asserting a
    faceplate. The platform module owns the port complement.
    """
    if _owned_elsewhere(a):
        return 1
    conf = _load_conf()
    plan = conf.get("plan")
    if not plan:
        print("no \"plan\" in %s. This tool has no default port complement: "
              "take the plan from the platform module for this chassis." % CONF)
        return 2
    with IfCtl(_region(a)) as c:
        if not c.ok:
            print("not available: %s" % c.error)
            return 1
        r = c.apply_all(plan)
        print(json.dumps({k: v for k, v in r.items() if k != "results"},
                         indent=2))
        return 0 if (not r["failed"] and not r["missing"]) else 1


def _region(a):
    if "--region" in a:
        try:
            return a[a.index("--region") + 1]
        except IndexError:
            pass
    return None


CMDS = {"status": _cmd_status, "ports": _cmd_ports, "apply": _cmd_apply}


def main():
    a = sys.argv[1:]
    if not a or a[0] not in CMDS:
        print(__doc__.strip().split("\n")[0])
        print()
        print("usage: ffn_ifctl.py {status|ports|apply} [--region file:PATH] [--force]")
        print()
        print("  status  region reachability and DP capabilities")
        print("  ports   the DP port table, in the WebUI's own shape")
        print("  apply   push the configured plan to the DP")
        print()
        print("  LEGACY. On an appliance the interface owner is the selected")
        print("  control daemon; use ffn_plane_network.py or the WebUI instead.")
        return 2
    return CMDS[a[0]](a[1:])


if __name__ == "__main__":
    sys.exit(main())
