#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""ffn_cpuisol.py -- hardware-driven CPU isolation and kernel command line.

Decides whether host CPU isolation is appropriate **at all**, and only then which
cores, then renders the kernel command line and optionally applies it via GRUB.

    ffn_cpuisol.py show        what the hardware is and what would be decided
    ffn_cpuisol.py plan        the decision, as JSON
    ffn_cpuisol.py cmdline     just the kernel arguments
    ffn_cpuisol.py diff        what applying would change (default, safe)
    ffn_cpuisol.py apply       write it, then regenerate the GRUB config
    ffn_cpuisol.py revert      remove FFN's tuning again
    ffn_cpuisol.py verify      compare the running kernel against the plan
    ffn_cpuisol.py selftest    decision-table tests, no hardware needed

THE DECISION, WHICH IS THE POINT OF THIS MODULE

FFN's default datapath is DPDK. A DPDK poll-mode driver spins at 100% on its
core by design and never yields; if the scheduler is free to preempt it, the
symptom is latency spikes and drops under load rather than an obvious error. So
on generic hardware the poll-mode cores are isolated from the scheduler
(`isolcpus`), taken out of the timer tick (`nohz_full`) and relieved of RCU
callbacks (`rcu_nocbs`).

On **specialised hardware that offloads forwarding, isolation is wrong.** When
packets are switched by dedicated silicon -- co-processors on the board, an
FPGA fabric, a SmartNIC running the datapath -- the host cores only ever run
the control plane. Isolating them removes cores from the scheduler for no gain,
and makes the management plane *less* responsive precisely when an operator most
wants it: during a traffic event. The right answer there is to isolate nothing.

A platform submodule declares which case it is in, so this is a property of the
hardware rather than a guess:

    platform/<name>/platform.json
        {"datapath": "offload", "cpu_isolation": "none", "reason": "..."}

With no platform selected, the default is generic DPDK hardware.

WHY THIS IS CAUTIOUS ABOUT WRITING

A bad kernel command line is a machine that does not come back. Every guard here
exists because its absence is a plausible outage:

  * never isolate CPU 0 -- kernel housekeeping and most IRQs land there
  * always leave at least two cores schedulable, or the box has no control plane
  * isolate SMT siblings together, since an isolated thread sharing a core with a
    schedulable one is still preempted at the hardware level
  * refuse when there are too few cores to split meaningfully
  * prefer a `/etc/default/grub.d` drop-in, which is removable, over editing the
    main file
  * back up before writing, validate after rendering, and default to `diff`

Read-only unless `apply`/`revert` is given, and those refuse without --yes.
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import re
import shutil
import subprocess
import sys
import time
from typing import Dict, List, Optional, Tuple

try:
    import ffn_hwdetect
except Exception:                                    # pragma: no cover
    ffn_hwdetect = None

# --------------------------------------------------------------------------
# Constants
# --------------------------------------------------------------------------

DROPIN_DIR = "/etc/default/grub.d"
DROPIN = os.path.join(DROPIN_DIR, "99-ffn-cpuisol.cfg")
GRUB_DEFAULT = "/etc/default/grub"
PLATFORM_DIR = "platform"

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

PLATFORM_DECL = "platform.json"

# Tokens this module owns. Anything matching these is removed before ours are
# inserted, so re-applying is idempotent instead of accumulating duplicates.
MANAGED_KEYS = ("isolcpus", "nohz_full", "rcu_nocbs", "irqaffinity",
                "default_hugepagesz", "hugepagesz", "hugepages",
                "intel_iommu", "amd_iommu", "iommu")

MIN_CORES_TO_ISOLATE = 4      # below this, splitting starves the control plane
MIN_SCHEDULABLE = 2           # cores that must remain for mgmt + ctrl

BANNER = "# Managed by ffn_cpuisol.py -- edits here are overwritten.\n"


# --------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------

def _read(path: str, default: str = "") -> str:
    try:
        with open(path) as fh:
            return fh.read().strip()
    except Exception:
        return default


def _have(tool: str) -> bool:
    return shutil.which(tool) is not None


def format_cpu_list(cores: List[int]) -> str:
    """Collapse [4,5,6,9] to '4-6,9'."""
    if not cores:
        return ""
    cores = sorted(set(cores))
    out, start, prev = [], cores[0], cores[0]
    for c in cores[1:]:
        if c == prev + 1:
            prev = c
            continue
        out.append(str(start) if start == prev else "%d-%d" % (start, prev))
        start = prev = c
    out.append(str(start) if start == prev else "%d-%d" % (start, prev))
    return ",".join(out)


def expand_cpu_list(spec: str) -> List[int]:
    """Expand '4-6,9' to [4,5,6,9]. Ignores flag tokens like 'managed_irq'."""
    cores: List[int] = []
    for part in (spec or "").split(","):
        part = part.strip()
        if not part or not re.match(r"^\d+(-\d+)?$", part):
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            if int(a) <= int(b):
                cores.extend(range(int(a), int(b) + 1))
        else:
            cores.append(int(part))
    return sorted(set(cores))


def smt_siblings() -> Dict[int, List[int]]:
    """cpu -> its thread siblings, from sysfs. Empty when sysfs is unavailable."""
    out: Dict[int, List[int]] = {}
    for path in glob.glob("/sys/devices/system/cpu/cpu[0-9]*/topology/"
                          "thread_siblings_list"):
        m = re.search(r"/cpu(\d+)/", path)
        if not m:
            continue
        out[int(m.group(1))] = expand_cpu_list(_read(path))
    return out


def numa_of_cpu(cpu: int) -> Optional[int]:
    for path in glob.glob("/sys/devices/system/node/node[0-9]*"):
        node = int(re.search(r"node(\d+)$", path).group(1))
        if cpu in expand_cpu_list(_read(os.path.join(path, "cpulist"))):
            return node
    return None


def numa_of_pci(pci: str) -> Optional[int]:
    if not pci:
        return None
    val = _read("/sys/bus/pci/devices/%s/numa_node" % pci)
    try:
        n = int(val)
        return n if n >= 0 else None
    except Exception:
        return None


# --------------------------------------------------------------------------
# Platform declaration
# --------------------------------------------------------------------------

DEFAULT_DECL = {
    "platform": "generic",
    "datapath": "dpdk",
    "cpu_isolation": "auto",
    "reason": "No platform selected: assuming generic hardware with a DPDK "
              "datapath, where the poll-mode cores benefit from isolation.",
}


def find_platform_decl(root: str = ".") -> Tuple[Dict, Optional[str]]:
    """Return (declaration, path). Falls back to the generic default.

    Looks for platform/<name>/platform.json. A platform whose submodule is not
    checked out simply is not found, which is correct: an unselected platform
    must not influence the host's kernel command line.
    """
    pattern = os.path.join(root, PLATFORM_DIR, "*", PLATFORM_DECL)
    found = sorted(glob.glob(pattern))
    if not found:
        return dict(DEFAULT_DECL), None
    if len(found) > 1:
        # Two selected platforms cannot both describe one host's datapath.
        raise SystemExit(
            "ffn_cpuisol: more than one platform is selected:\n  %s\n"
            "Deinit all but one: git submodule deinit -f platform/<name>"
            % "\n  ".join(found))
    path = found[0]
    try:
        with open(path) as fh:
            decl = json.load(fh)
    except Exception as exc:
        raise SystemExit("ffn_cpuisol: cannot read %s: %s" % (path, exc))
    merged = dict(DEFAULT_DECL)
    merged.update(decl)
    return merged, path


# --------------------------------------------------------------------------
# The decision
# --------------------------------------------------------------------------

class Plan:
    def __init__(self) -> None:
        self.isolate: bool = False
        self.cores: List[int] = []
        self.housekeeping: List[int] = []
        self.hugepages: Optional[Dict] = None
        self.iommu: List[str] = []
        self.reason: str = ""
        self.warnings: List[str] = []
        self.platform: str = "generic"
        self.datapath: str = "dpdk"
        self.decl_path: Optional[str] = None
        self.ncpu: int = 0

    def as_dict(self) -> Dict:
        return {
            "platform": self.platform,
            "datapath": self.datapath,
            "declaration": self.decl_path,
            "isolate": self.isolate,
            "isolated_cores": format_cpu_list(self.cores),
            "housekeeping_cores": format_cpu_list(self.housekeeping),
            "hugepages": self.hugepages,
            "iommu": self.iommu,
            "reason": self.reason,
            "warnings": self.warnings,
            "cmdline": render_cmdline(self),
        }


def physical_cores(ncpu: int, sibs: Dict[int, List[int]]) -> List[List[int]]:
    """Group logical CPUs into physical cores, in ascending order.

    With no sysfs topology every CPU is its own group, which is the right
    degradation: it just means no SMT pairing is applied.
    """
    groups: List[List[int]] = []
    seen: set = set()
    for c in range(ncpu):
        if c in seen:
            continue
        g = sorted(set(sibs.get(c, [c])) & set(range(ncpu))) or [c]
        seen.update(g)
        groups.append(g)
    return groups


def _pick_dpdk_cores(ncpu: int, sibs: Dict[int, List[int]],
                     prefer_node: Optional[int],
                     data_fraction: float = 0.5
                     ) -> Tuple[List[int], List[str]]:
    """Choose cores to isolate: whole physical cores, from the top, never CPU 0.

    Reasoning in PHYSICAL cores rather than logical CPUs is the whole trick. An
    isolated thread whose sibling stays schedulable is still preempted at the
    hardware level, so siblings have to move together -- but picking logical
    CPUs first and pulling siblings in afterwards doubles the set. On a 48-CPU
    /24-core host that isolated 46 of 48 and left the control plane with two.
    """
    warnings: List[str] = []
    groups = physical_cores(ncpu, sibs)

    # Never touch the physical core that owns CPU 0: kernel housekeeping and
    # most IRQ handling live there, and its sibling shares the same core.
    groups = [g for g in groups if 0 not in g]
    if not groups:
        return [], ["only one physical core is present; isolating nothing."]

    if prefer_node is not None:
        on_node = [g for g in groups if numa_of_cpu(g[0]) == prefer_node]
        if len(on_node) >= 2:
            groups = on_node
        elif on_node:
            warnings.append(
                "NIC is on NUMA node %d but only %d usable physical core(s) "
                "there; ignoring the NUMA preference rather than isolating a "
                "single core." % (prefer_node, len(on_node)))

    frac = min(max(data_fraction, 0.0), 0.9)
    n_groups = max(1, int(round(len(groups) * frac)))
    n_groups = min(n_groups, len(groups))
    chosen_groups = groups[-n_groups:]                 # the top physical cores
    chosen = sorted(c for g in chosen_groups for c in g)

    if any(len(g) > 1 for g in chosen_groups):
        warnings.append(
            "isolated %d whole physical core(s) (%d logical CPUs); SMT siblings "
            "move together because an isolated thread sharing a core with a "
            "schedulable one is still preempted."
            % (len(chosen_groups), len(chosen)))
    return chosen, warnings


def _plan_hugepages(mem_gb: float) -> Optional[Dict]:
    """1G pages sized from RAM. DPDK wants hugepages; 1G needs a boot arg."""
    if mem_gb < 8:
        return None                      # not enough RAM to carve 1G pages out
    count = max(2, min(int(mem_gb * 0.25), 64))
    return {"size": "1G", "count": count}


def decide(inv: Optional[Dict] = None, decl: Optional[Dict] = None,
           decl_path: Optional[str] = None, ncpu: Optional[int] = None,
           mem_gb: Optional[float] = None,
           sibs: Optional[Dict[int, List[int]]] = None,
           nic_node: Optional[int] = None) -> Plan:
    """Decide whether and how to isolate. Pure enough to unit-test."""
    p = Plan()
    decl = decl or dict(DEFAULT_DECL)
    p.platform = decl.get("platform", "generic")
    p.datapath = decl.get("datapath", "dpdk")
    p.decl_path = decl_path

    if ncpu is None:
        ncpu = (inv or {}).get("cpu", {}).get("cores_logical") or os.cpu_count() or 1
    p.ncpu = ncpu
    if mem_gb is None:
        mem_gb = float((inv or {}).get("memory", {}).get("total_gb") or 0)
    if sibs is None:
        sibs = smt_siblings()

    mode = str(decl.get("cpu_isolation", "auto")).lower()

    # ---- 1. the platform says isolation does not apply ------------------
    if mode == "none":
        p.isolate = False
        p.reason = decl.get("reason") or (
            "Platform %r declares cpu_isolation=none. Forwarding is offloaded, "
            "so host cores run only the control plane and isolating them would "
            "cost management responsiveness for no throughput gain."
            % p.platform)
        return p

    # ---- 2. the platform names the cores itself -------------------------
    if mode == "explicit":
        cores = expand_cpu_list(str(decl.get("isolate_cores", "")))
        if not cores:
            raise SystemExit(
                "ffn_cpuisol: %s sets cpu_isolation=explicit but no usable "
                "isolate_cores" % (decl_path or "platform declaration"))
        p.cores = cores
        p.isolate = True
        p.reason = decl.get("reason") or (
            "Platform %r pins the isolated set explicitly." % p.platform)

    # ---- 3. generic hardware: decide from the datapath ------------------
    else:
        if p.datapath == "offload":
            p.isolate = False
            p.reason = (
                "datapath=offload: forwarding does not run on host cores, so "
                "there is nothing whose preemption would drop packets.")
            return p
        if ncpu < MIN_CORES_TO_ISOLATE:
            p.isolate = False
            p.reason = (
                "only %d logical core(s): isolating any of them would leave too "
                "few for the management and control planes. DPDK will still run, "
                "sharing cores with the scheduler." % ncpu)
            return p
        frac = float(decl.get("data_fraction", 0.5))
        cores, warns = _pick_dpdk_cores(ncpu, sibs, nic_node, frac)
        p.cores = cores
        p.warnings.extend(warns)
        p.isolate = bool(cores)
        p.reason = (
            "datapath=dpdk on generic hardware: a poll-mode driver spins at "
            "100% and never yields, so its cores are isolated from the "
            "scheduler, the timer tick and RCU callbacks.")

    # ---- shared post-processing for the isolating cases -----------------
    p.cores = [c for c in sorted(set(p.cores)) if 0 <= c < ncpu]
    if 0 in p.cores:
        p.cores.remove(0)
        p.warnings.append("refused to isolate CPU 0: kernel housekeeping and "
                          "most IRQ handling land there.")
    p.housekeeping = [c for c in range(ncpu) if c not in p.cores]
    if len(p.housekeeping) < MIN_SCHEDULABLE:
        p.isolate = False
        p.cores = []
        p.housekeeping = list(range(ncpu))
        p.warnings.append(
            "plan would have left fewer than %d schedulable core(s); isolating "
            "nothing instead." % MIN_SCHEDULABLE)
        return p
    if not p.cores:
        p.isolate = False
        return p

    p.hugepages = _plan_hugepages(mem_gb)
    model = ((inv or {}).get("cpu", {}).get("model") or "").lower()
    if "amd" in model:
        p.iommu = ["amd_iommu=on", "iommu=pt"]
    else:
        p.iommu = ["intel_iommu=on", "iommu=pt"]
    return p


def render_cmdline(p: Plan) -> str:
    """The kernel arguments FFN manages, as one string."""
    if not p.isolate or not p.cores:
        return ""
    lst = format_cpu_list(p.cores)
    hk = format_cpu_list(p.housekeeping)
    toks = [
        # managed_irq keeps managed IRQs off the isolated set; domain stops the
        # scheduler load-balancing into it.
        "isolcpus=managed_irq,domain,%s" % lst,
        "nohz_full=%s" % lst,
        "rcu_nocbs=%s" % lst,
    ]
    if hk:
        toks.append("irqaffinity=%s" % hk)
    if p.hugepages:
        toks += ["default_hugepagesz=%s" % p.hugepages["size"],
                 "hugepagesz=%s" % p.hugepages["size"],
                 "hugepages=%d" % p.hugepages["count"]]
    toks += p.iommu
    return " ".join(toks)


# --------------------------------------------------------------------------
# Applying it
# --------------------------------------------------------------------------

def strip_managed(cmdline: str) -> str:
    """Remove tokens this module owns, so re-applying does not accumulate."""
    keep = []
    for tok in cmdline.split():
        key = tok.split("=", 1)[0]
        if key in MANAGED_KEYS:
            continue
        keep.append(tok)
    return " ".join(keep)


def grub_regen_command() -> Optional[List[str]]:
    for cmd, args in (("update-grub", []),
                      ("grub-mkconfig", ["-o", "/boot/grub/grub.cfg"]),
                      ("grub2-mkconfig", ["-o", "/boot/grub2/grub.cfg"])):
        if _have(cmd):
            return [cmd] + args
    return None


def dropin_supported() -> bool:
    """Debian/Ubuntu grub-mkconfig sources /etc/default/grub.d/*.cfg."""
    if os.path.isdir(DROPIN_DIR):
        return True
    for cand in ("/usr/sbin/grub-mkconfig", "/usr/sbin/update-grub",
                 "/usr/sbin/grub2-mkconfig"):
        if os.path.isfile(cand) and "grub.d" in _read(cand):
            return True
    return False


def render_dropin(p: Plan) -> str:
    args = render_cmdline(p)
    body = [BANNER,
            "# %s\n" % (p.reason.replace("\n", " ")),
            "#\n",
            "# Remove with: ffn_cpuisol.py revert --yes\n",
            "\n"]
    if not args:
        body.append("# No isolation applied on this hardware.\n")
    else:
        body.append('GRUB_CMDLINE_LINUX_DEFAULT="$GRUB_CMDLINE_LINUX_DEFAULT '
                    '%s"\n' % args)
    return "".join(body)


def current_effective() -> str:
    return _read("/proc/cmdline")


def plan_diff(p: Plan) -> str:
    """What applying would change, without changing it."""
    args = render_cmdline(p)
    lines = []
    if dropin_supported():
        lines.append("target: %s  (drop-in; the main grub file is untouched)"
                     % DROPIN)
        old = _read(DROPIN)
        if old:
            lines.append("--- current drop-in ---")
            lines += ["  " + l for l in old.splitlines()]
        else:
            lines.append("--- current drop-in --- (absent)")
        lines.append("--- proposed ---")
        lines += ["  " + l for l in render_dropin(p).rstrip().splitlines()]
    else:
        lines.append("target: %s  (no grub.d support detected)" % GRUB_DEFAULT)
        txt = _read(GRUB_DEFAULT)
        for var in ("GRUB_CMDLINE_LINUX_DEFAULT", "GRUB_CMDLINE_LINUX"):
            m = re.search(r'^%s="(.*)"$' % var, txt, re.M)
            if m:
                new = (strip_managed(m.group(1)) + " " + args).strip()
                lines.append("  - %s=\"%s\"" % (var, m.group(1)))
                lines.append("  + %s=\"%s\"" % (var, new))
                break
        else:
            lines.append("  (no GRUB_CMDLINE_LINUX* found -- refusing to guess)")
    lines.append("")
    lines.append("running kernel now: %s" % (current_effective() or "(unknown)"))
    return "\n".join(lines)


def apply(p: Plan, yes: bool = False, regen: bool = True) -> int:
    if not yes:
        print("refusing to write without --yes. Review with: "
              "ffn_cpuisol.py diff", file=sys.stderr)
        return 2
    if os.geteuid() != 0:
        print("must be root to write the boot configuration", file=sys.stderr)
        return 2

    stamp = time.strftime("%Y%m%d-%H%M%S")
    if dropin_supported():
        os.makedirs(DROPIN_DIR, exist_ok=True)
        if os.path.exists(DROPIN):
            shutil.copy2(DROPIN, "%s.bak-%s" % (DROPIN, stamp))
        with open(DROPIN, "w") as fh:
            fh.write(render_dropin(p))
        print("wrote %s" % DROPIN)
    else:
        txt = _read(GRUB_DEFAULT)
        if not txt:
            print("cannot read %s -- refusing" % GRUB_DEFAULT, file=sys.stderr)
            return 2
        shutil.copy2(GRUB_DEFAULT, "%s.bak-%s" % (GRUB_DEFAULT, stamp))
        args = render_cmdline(p)
        for var in ("GRUB_CMDLINE_LINUX_DEFAULT", "GRUB_CMDLINE_LINUX"):
            m = re.search(r'^%s="(.*)"$' % var, txt, re.M)
            if not m:
                continue
            new = (strip_managed(m.group(1)) + " " + args).strip()
            txt = txt[:m.start()] + '%s="%s"' % (var, new) + txt[m.end():]
            break
        else:
            print("no GRUB_CMDLINE_LINUX* in %s -- refusing to guess"
                  % GRUB_DEFAULT, file=sys.stderr)
            return 2
        with open(GRUB_DEFAULT, "w") as fh:
            fh.write(txt)
        print("wrote %s (backup: %s.bak-%s)"
              % (GRUB_DEFAULT, GRUB_DEFAULT, stamp))

    if not regen:
        print("skipped GRUB regeneration (--no-regen); changes take effect "
              "after you regenerate and reboot")
        return 0
    cmd = grub_regen_command()
    if not cmd:
        print("no update-grub/grub-mkconfig found; regenerate manually",
              file=sys.stderr)
        return 1
    print("running: %s" % " ".join(cmd))
    rc = subprocess.call(cmd)
    if rc != 0:
        print("GRUB regeneration failed (rc=%d). The backup is beside the file "
              "it replaced; do not reboot until this succeeds." % rc,
              file=sys.stderr)
        return rc
    print("done. Changes take effect on the next reboot.")
    return 0


def revert(yes: bool = False, regen: bool = True) -> int:
    if not yes:
        print("refusing to write without --yes", file=sys.stderr)
        return 2
    if os.geteuid() != 0:
        print("must be root", file=sys.stderr)
        return 2
    touched = False
    if os.path.exists(DROPIN):
        os.rename(DROPIN, "%s.removed-%s"
                  % (DROPIN, time.strftime("%Y%m%d-%H%M%S")))
        print("removed %s" % DROPIN)
        touched = True
    txt = _read(GRUB_DEFAULT)
    if txt:
        new_txt = txt
        for var in ("GRUB_CMDLINE_LINUX_DEFAULT", "GRUB_CMDLINE_LINUX"):
            m = re.search(r'^%s="(.*)"$' % var, new_txt, re.M)
            if not m:
                continue
            stripped = strip_managed(m.group(1))
            if stripped != m.group(1):
                new_txt = (new_txt[:m.start()] + '%s="%s"' % (var, stripped)
                           + new_txt[m.end():])
                touched = True
        if new_txt != txt:
            shutil.copy2(GRUB_DEFAULT, "%s.bak-%s"
                         % (GRUB_DEFAULT, time.strftime("%Y%m%d-%H%M%S")))
            with open(GRUB_DEFAULT, "w") as fh:
                fh.write(new_txt)
            print("stripped FFN tokens from %s" % GRUB_DEFAULT)
    if not touched:
        print("nothing to revert")
        return 0
    if regen:
        cmd = grub_regen_command()
        if cmd:
            return subprocess.call(cmd)
    return 0


def verify(p: Plan) -> List[str]:
    """Compare the running kernel against the plan."""
    out: List[str] = []
    running = current_effective()
    live_iso = []
    for tok in running.split():
        if tok.startswith("isolcpus="):
            live_iso = expand_cpu_list(tok.split("=", 1)[1])
    if p.isolate:
        if not live_iso:
            out.append("plan isolates %s but the running kernel isolates "
                       "nothing -- has it been applied and rebooted?"
                       % format_cpu_list(p.cores))
        elif sorted(live_iso) != sorted(p.cores):
            out.append("running isolcpus=%s differs from the plan (%s)"
                       % (format_cpu_list(live_iso), format_cpu_list(p.cores)))
    else:
        if live_iso:
            out.append("this hardware should isolate nothing, but the running "
                       "kernel isolates %s -- that is removing cores from the "
                       "scheduler for no benefit. Run: ffn_cpuisol.py revert "
                       "--yes" % format_cpu_list(live_iso))
    sysfs_iso = expand_cpu_list(_read("/sys/devices/system/cpu/isolated"))
    if p.isolate and sysfs_iso and sorted(sysfs_iso) != sorted(p.cores):
        out.append("sysfs reports isolated=%s" % format_cpu_list(sysfs_iso))
    return out


# --------------------------------------------------------------------------
# Selftest -- the decision table, no hardware required
# --------------------------------------------------------------------------

def selftest() -> int:
    fails = []

    def check(name, cond, detail=""):
        print("  %-4s %s%s" % ("ok" if cond else "FAIL", name,
                               "" if cond else "  <- " + detail))
        if not cond:
            fails.append(name)

    print("[1] specialised hardware isolates nothing")
    p = decide(decl={"platform": "pa5200", "datapath": "offload",
                     "cpu_isolation": "none", "reason": "offloaded"},
               ncpu=16, mem_gb=64, sibs={})
    check("isolate is False", p.isolate is False)
    check("no cores", p.cores == [])
    check("cmdline empty", render_cmdline(p) == "")

    print("[2] datapath=offload alone is enough, without cpu_isolation=none")
    p = decide(decl={"platform": "x", "datapath": "offload",
                     "cpu_isolation": "auto"}, ncpu=16, mem_gb=64, sibs={})
    check("isolate is False", p.isolate is False)

    print("[3] generic DPDK host isolates the top half, never CPU 0")
    p = decide(decl=None, ncpu=16, mem_gb=64, sibs={})
    check("isolates", p.isolate is True)
    check("0 not isolated", 0 not in p.cores, format_cpu_list(p.cores))
    check("leaves housekeeping", len(p.housekeeping) >= MIN_SCHEDULABLE)
    cl = render_cmdline(p)
    for need in ("isolcpus=managed_irq,domain,", "nohz_full=", "rcu_nocbs=",
                 "irqaffinity=", "iommu=pt"):
        check("cmdline has %s" % need, need in cl, cl)

    print("[4] too few cores: isolate nothing rather than starve the box")
    for n in (1, 2, 3):
        p = decide(decl=None, ncpu=n, mem_gb=8, sibs={})
        check("ncpu=%d does not isolate" % n, p.isolate is False)

    print("[5] SMT siblings are isolated together")
    sibs = {c: [c, c + 8] if c < 8 else [c - 8, c] for c in range(16)}
    p = decide(decl=None, ncpu=16, mem_gb=64, sibs=sibs)
    ok = all(all(s in p.cores for s in sibs[c] if s != 0) for c in p.cores)
    check("no split SMT core", ok, format_cpu_list(p.cores))

    print("[6] explicit cores are honoured and validated")
    p = decide(decl={"platform": "y", "cpu_isolation": "explicit",
                     "isolate_cores": "4-7"}, ncpu=8, mem_gb=32, sibs={})
    check("uses 4-7", p.cores == [4, 5, 6, 7], format_cpu_list(p.cores))
    p = decide(decl={"platform": "y", "cpu_isolation": "explicit",
                     "isolate_cores": "0-7"}, ncpu=8, mem_gb=32, sibs={})
    check("drops CPU 0 from an explicit set", 0 not in p.cores)
    check("warned about it", any("CPU 0" in w for w in p.warnings))

    print("[7] an explicit set that would starve the box is refused")
    p = decide(decl={"platform": "y", "cpu_isolation": "explicit",
                     "isolate_cores": "1-7"}, ncpu=8, mem_gb=32, sibs={})
    check("isolates nothing", p.isolate is False, format_cpu_list(p.cores))
    check("warned", any("schedulable" in w for w in p.warnings))

    print("[8] managed tokens are stripped, so re-apply is idempotent")
    before = "quiet splash isolcpus=managed_irq,domain,4-7 nohz_full=4-7 ro"
    after = strip_managed(before)
    check("keeps unmanaged", after == "quiet splash ro", after)

    print("[9] small-RAM hosts get no 1G hugepage args")
    p = decide(decl=None, ncpu=8, mem_gb=4, sibs={})
    check("no hugepages", p.hugepages is None)
    check("no hugepagesz in cmdline", "hugepagesz" not in render_cmdline(p))

    print("[10] AMD hosts get amd_iommu")
    p = decide(inv={"cpu": {"model": "AMD EPYC 7443P", "cores_logical": 16},
                    "memory": {"total_gb": 64}},
               decl=None, ncpu=16, mem_gb=64, sibs={})
    check("amd_iommu=on", "amd_iommu=on" in render_cmdline(p))

    print("[11] regression: a 48-CPU/24-core SMT host keeps a real control plane")
    sibs48 = {c: sorted({c, c + 24 if c < 24 else c - 24}) for c in range(48)}
    p = decide(decl=None, ncpu=48, mem_gb=128, sibs=sibs48)
    check("isolates", p.isolate is True)
    check("leaves more than 2 housekeeping cores", len(p.housekeeping) > 2,
          "housekeeping=%s" % format_cpu_list(p.housekeeping))
    check("isolates about half, not almost all", len(p.cores) <= 28,
          "isolated %d of 48" % len(p.cores))
    check("no split SMT core",
          all(all(s in p.cores for s in sibs48[c]) for c in p.cores),
          format_cpu_list(p.cores))
    check("CPU 0 and its sibling both schedulable",
          0 in p.housekeeping and 24 in p.housekeeping,
          format_cpu_list(p.housekeeping))

    print("\n==== ffn_cpuisol selftest: %d failed ====" % len(fails))
    return 1 if fails else 0


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def build_plan(root: str = ".") -> Plan:
    decl, path = find_platform_decl(root)
    inv = None
    nic_node = None
    if ffn_hwdetect is not None:
        try:
            inv = ffn_hwdetect.detect()
            # Prefer cores on the NUMA node of the fastest DPDK-capable NIC.
            best = None
            for n in inv.get("nics", []):
                pci = n.get("pci") or ""
                node = numa_of_pci(pci)
                if node is None:
                    continue
                spd = n.get("speed") or ""
                try:
                    mbps = int(re.sub(r"[^0-9]", "", spd) or 0)
                except Exception:
                    mbps = 0
                if best is None or mbps > best[0]:
                    best = (mbps, node)
            if best:
                nic_node = best[1]
        except Exception:
            inv = None
    return decide(inv=inv, decl=decl, decl_path=path, nic_node=nic_node)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="hardware-driven CPU isolation and kernel command line")
    ap.add_argument("cmd", choices=["show", "plan", "cmdline", "diff", "apply",
                                    "revert", "verify", "selftest"])
    ap.add_argument("--root", default=None,
                    help="repository root, for finding platform/*/platform.json")
    ap.add_argument("--yes", action="store_true", help="required by apply/revert")
    ap.add_argument("--no-regen", action="store_true",
                    help="do not run update-grub after writing")
    a = ap.parse_args(argv)
    if a.root is None:
        a.root = _repo_root()

    if a.cmd == "selftest":
        return selftest()
    if a.cmd == "revert":
        return revert(yes=a.yes, regen=not a.no_regen)

    p = build_plan(a.root)

    if a.cmd == "cmdline":
        print(render_cmdline(p))
        return 0
    if a.cmd == "plan":
        print(json.dumps(p.as_dict(), indent=2))
        return 0
    if a.cmd == "show":
        d = p.as_dict()
        print("platform      : %s (%s)" % (d["platform"],
                                           d["declaration"] or "no declaration"))
        print("datapath      : %s" % d["datapath"])
        print("logical cores : %d" % p.ncpu)
        print("isolate       : %s" % ("yes" if p.isolate else "no"))
        if p.isolate:
            print("  isolated    : %s" % d["isolated_cores"])
            print("  housekeeping: %s" % d["housekeeping_cores"])
            if p.hugepages:
                print("  hugepages   : %d x %s"
                      % (p.hugepages["count"], p.hugepages["size"]))
        print("reason        : %s" % p.reason)
        for w in p.warnings:
            print("warning       : %s" % w)
        print("cmdline       : %s" % (d["cmdline"] or "(none)"))
        return 0
    if a.cmd == "diff":
        print(plan_diff(p))
        return 0
    if a.cmd == "apply":
        return apply(p, yes=a.yes, regen=not a.no_regen)
    if a.cmd == "verify":
        w = verify(p)
        print("\n".join(w) if w else "OK: running kernel matches the plan")
        return 1 if w else 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
