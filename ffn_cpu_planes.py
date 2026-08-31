#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""
ffn_cpu_planes.py -- CPU plane / process splitting for the FFN NGFW.

PAN-OS-style separation of the Management Plane from the Data Plane, on a
generic bare-metal box. Cores are partitioned into planes; the data-plane
cores run the pinned NFQUEUE inspection workers (one per core / per vsys) and
are ideally isolated from the kernel scheduler (`isolcpus`) so packet
processing is never preempted by control-plane work.

    +-------------------- CPU cores --------------------+
    | mgmt: 0-1  | ctrl: 2-3 |     data: 4-11           |
    |  WebUI     |  daemons  |  pinned NFQUEUE workers  |
    |  config    |  routing  |  (isolcpus, SCHED_FIFO,  |
    |  API       |  logging  |   NIC IRQ affinity)      |
    +---------------------------------------------------+

Compatible with the existing platform:
  * reads /etc/ffn-ngfw/cpu-planes.conf  (FFN_MGMT_CORES / FFN_CTRL_CORES /
    FFN_DPDK_CORES; FFN_DPDK_CORES == the data plane here -- no DPDK required)
  * parses `isolcpus=managed_irq,domain,<list>` from /proc/cmdline

What the previous code lacked and this adds: the ACTIVE functions --
sched_setaffinity pinning, SCHED_FIFO for the data plane, NIC IRQ steering,
pinned worker spawn, plus planning (auto-split) and verification.

Linux-gated: the parsing / planning / config-generation logic is portable and
unit-tested anywhere; the pinning calls degrade to reported no-ops off Linux.

CLI:
    ffn_cpu_planes.py selftest
    ffn_cpu_planes.py show                    # current plane topology + affinity
    ffn_cpu_planes.py plan [--data-frac 0.5]  # auto-plan a split for this box
    ffn_cpu_planes.py conf                     # emit cpu-planes.conf
    ffn_cpu_planes.py grub                     # emit the isolcpus= kernel arg
    ffn_cpu_planes.py verify
"""

import argparse
import json
import logging
import os
import sys
from typing import Dict, List, Optional

logger = logging.getLogger("ffn-cpu-planes")

PLANE_MGMT = "mgmt"
PLANE_CTRL = "ctrl"
PLANE_DATA = "data"
PLANES = (PLANE_MGMT, PLANE_CTRL, PLANE_DATA)

# cpu-planes.conf keys <-> plane names (FFN_DPDK_CORES is the data plane).
CONF_KEY = {PLANE_MGMT: "FFN_MGMT_CORES", PLANE_CTRL: "FFN_CTRL_CORES",
            PLANE_DATA: "FFN_DPDK_CORES"}
CONF_ALIASES = {"FFN_DP_CORES": PLANE_DATA, "FFN_DATA_CORES": PLANE_DATA,
                "FFN_DATAPLANE_CORES": PLANE_DATA}

DEFAULT_CONF = "/etc/ffn-ngfw/cpu-planes.conf"

# os.sched_setaffinity/getaffinity + SCHED_FIFO exist on Linux only.
HAVE_SCHED = hasattr(os, "sched_setaffinity")
HAVE_RT = hasattr(os, "sched_setscheduler") and hasattr(os, "SCHED_FIFO")


# ===========================================================================
# CPU-list helpers (expand "0,2-5" <-> [0,2,3,4,5], and back)
# ===========================================================================
def expand_cpu_list(spec: str) -> List[int]:
    out: List[int] = []
    for part in (spec or "").split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            try:
                a, b = part.split("-", 1)
                out.extend(range(int(a), int(b) + 1))
            except ValueError:
                continue
        else:
            try:
                out.append(int(part))
            except ValueError:
                continue
    return sorted(set(out))


def format_cpu_list(cores: List[int]) -> str:
    """Compress [0,2,3,4,5,8] -> '0,2-5,8'."""
    cs = sorted(set(cores))
    if not cs:
        return ""
    ranges = []
    start = prev = cs[0]
    for c in cs[1:]:
        if c == prev + 1:
            prev = c
            continue
        ranges.append((start, prev))
        start = prev = c
    ranges.append((start, prev))
    return ",".join(str(a) if a == b else "%d-%d" % (a, b) for a, b in ranges)


# ===========================================================================
# System introspection (cmdline / isolcpus / topology)
# ===========================================================================
_ISOLCPUS_FLAGS = {"managed_irq", "domain", "nohz", "rcu"}


def parse_isolcpus(cmdline: str) -> List[int]:
    """Parse isolcpus= from a kernel cmdline string (flag tokens stripped)."""
    for tok in cmdline.split():
        if tok.startswith("isolcpus="):
            spec = tok.split("=", 1)[1]
            parts = [p for p in spec.split(",") if p not in _ISOLCPUS_FLAGS]
            return expand_cpu_list(",".join(parts))
    return []


def parse_nohz_full(cmdline: str) -> List[int]:
    for tok in cmdline.split():
        if tok.startswith("nohz_full="):
            return expand_cpu_list(tok.split("=", 1)[1])
    return []


def read_cmdline() -> str:
    try:
        with open("/proc/cmdline") as f:
            return f.read()
    except OSError:
        return ""


def cpu_count() -> int:
    return os.cpu_count() or 1


def parse_conf(text: str) -> Dict[str, List[int]]:
    """Parse cpu-planes.conf content into {plane: [cores]}."""
    planes: Dict[str, List[int]] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        k, v = k.strip(), v.strip().strip('"')
        plane = next((p for p, key in CONF_KEY.items() if key == k), None)
        if plane is None:
            plane = CONF_ALIASES.get(k)
        if plane:
            planes[plane] = expand_cpu_list(v)
    return planes


# ===========================================================================
# Planning: auto-split cores into planes
# ===========================================================================
def auto_plan(ncpu: int, *, data_frac: float = 0.5, mgmt: int = 1,
              ctrl: int = 1) -> Dict[str, List[int]]:
    """Split `ncpu` cores into mgmt / ctrl / data planes.

    Core 0 is always kept for the mgmt plane (kernel housekeeping / IRQs land
    there by convention). The data plane gets the top `data_frac` of the
    remaining cores (these are the ones you would also list in isolcpus).
    """
    cores = list(range(ncpu))
    if ncpu <= 2:
        # too few to split meaningfully: everything shares
        return {PLANE_MGMT: cores, PLANE_CTRL: cores, PLANE_DATA: cores}
    mgmt = max(1, mgmt)
    ctrl = max(1, ctrl)
    n_data = max(1, int(round((ncpu - mgmt - ctrl) * data_frac)))
    n_data = min(n_data, ncpu - mgmt - ctrl)
    data_cores = cores[ncpu - n_data:]                 # top cores
    front = cores[:ncpu - n_data]
    mgmt_cores = front[:mgmt]
    ctrl_cores = front[mgmt:mgmt + ctrl] or front[:1]
    # any leftover front cores fold into ctrl
    leftover = front[mgmt + ctrl:]
    ctrl_cores = sorted(set(ctrl_cores) | set(leftover))
    return {PLANE_MGMT: mgmt_cores, PLANE_CTRL: ctrl_cores, PLANE_DATA: data_cores}


# ===========================================================================
# The manager
# ===========================================================================
class CpuPlanes:
    """Owns the plane->cores map and applies it (affinity, RT, IRQ, workers)."""

    def __init__(self, planes: Dict[str, List[int]], *, isolated: Optional[List[int]] = None,
                 nohz_full: Optional[List[int]] = None):
        self.planes = {p: sorted(set(planes.get(p, []))) for p in PLANES}
        self.isolated = sorted(set(isolated or []))
        self.nohz_full = sorted(set(nohz_full or []))

    # -- constructors ------------------------------------------------------
    @classmethod
    def from_system(cls, conf_path: str = DEFAULT_CONF, *, ncpu: Optional[int] = None,
                    data_frac: float = 0.5) -> "CpuPlanes":
        """Build from cpu-planes.conf + isolcpus; auto-plan if no conf present."""
        n = ncpu or cpu_count()
        cmdline = read_cmdline()
        iso = parse_isolcpus(cmdline)
        nohz = parse_nohz_full(cmdline)
        planes = {}
        try:
            with open(conf_path) as f:
                planes = parse_conf(f.read())
        except OSError:
            pass
        if not any(planes.get(p) for p in PLANES):
            planes = auto_plan(n, data_frac=data_frac)
            # honour isolcpus as the data plane if it was set
            if iso:
                planes[PLANE_DATA] = iso
                nonio = [c for c in range(n) if c not in iso]
                planes[PLANE_MGMT] = nonio[:1] or [0]
                planes[PLANE_CTRL] = nonio[1:] or nonio[:1] or [0]
        return cls(planes, isolated=iso, nohz_full=nohz)

    @classmethod
    def auto(cls, ncpu: Optional[int] = None, *, data_frac: float = 0.5) -> "CpuPlanes":
        n = ncpu or cpu_count()
        return cls(auto_plan(n, data_frac=data_frac))

    # -- queries -----------------------------------------------------------
    def cores(self, plane: str) -> List[int]:
        return list(self.planes.get(plane, []))

    @property
    def data_cores(self) -> List[int]:
        return self.cores(PLANE_DATA)

    def plane_of(self, core: int) -> Optional[str]:
        for p in PLANES:
            if core in self.planes[p]:
                return p
        return None

    # -- pinning -----------------------------------------------------------
    def pin_to_cores(self, cores: List[int], pid: int = 0) -> bool:
        """os.sched_setaffinity(pid, cores). pid=0 = current thread."""
        if not HAVE_SCHED:
            logger.debug("sched_setaffinity unavailable; pin no-op (cores=%s)", cores)
            return False
        if not cores:
            return False
        try:
            os.sched_setaffinity(pid, set(cores))
            return True
        except OSError as e:
            logger.warning("pin pid=%d cores=%s failed: %s", pid, cores, e)
            return False

    def pin(self, plane: str, pid: int = 0) -> bool:
        """Pin a process/thread to a plane's cores."""
        return self.pin_to_cores(self.cores(plane), pid)

    def pin_core(self, core: int, pid: int = 0) -> bool:
        """Pin to a single core (used per data-plane worker)."""
        return self.pin_to_cores([core], pid)

    def affinity(self, pid: int = 0) -> List[int]:
        if not HAVE_SCHED:
            return []
        try:
            return sorted(os.sched_getaffinity(pid))
        except OSError:
            return []

    def set_realtime(self, prio: int = 50, pid: int = 0) -> bool:
        """Put a data-plane worker on SCHED_FIFO so it isn't preempted."""
        if not HAVE_RT:
            logger.debug("SCHED_FIFO unavailable; realtime no-op")
            return False
        try:
            param = os.sched_param(prio)
            os.sched_setscheduler(pid, os.SCHED_FIFO, param)
            return True
        except OSError as e:
            logger.warning("SCHED_FIFO prio=%d failed: %s (need CAP_SYS_NICE)", prio, e)
            return False

    # -- NIC IRQ steering --------------------------------------------------
    def nic_irqs(self, iface: str) -> List[int]:
        """Find the IRQ numbers a NIC uses (from /proc/interrupts)."""
        irqs = []
        try:
            with open("/proc/interrupts") as f:
                for line in f:
                    if iface in line and ":" in line:
                        head = line.split(":", 1)[0].strip()
                        if head.isdigit():
                            irqs.append(int(head))
        except OSError:
            pass
        return irqs

    def steer_irqs(self, iface: str, cores: Optional[List[int]] = None) -> List[int]:
        """Pin a NIC's IRQs to the data-plane cores (write smp_affinity_list).

        Returns the list of IRQs successfully steered. Needs root.
        """
        target = cores if cores is not None else self.data_cores
        done = []
        if not target:
            return done
        cl = format_cpu_list(target)
        for irq in self.nic_irqs(iface):
            path = "/proc/irq/%d/smp_affinity_list" % irq
            try:
                with open(path, "w") as f:
                    f.write(cl + "\n")
                done.append(irq)
            except OSError as e:
                logger.debug("steer irq %d -> %s failed: %s", irq, cl, e)
        return done

    # -- worker spawn ------------------------------------------------------
    def spawn_worker(self, core: int, target, args=(), *, name: Optional[str] = None,
                     realtime: bool = False, rt_prio: int = 50):
        """Spawn a process that pins itself to `core` then runs target(*args).

        Returns the multiprocessing.Process (already started). The child pins
        FIRST so all of target's work stays on the data-plane core.
        """
        import multiprocessing

        def _entry():
            self.pin_core(core)
            if realtime:
                self.set_realtime(rt_prio)
            target(*args)

        p = multiprocessing.Process(target=_entry, name=name or "ffn-dp-%d" % core,
                                    daemon=True)
        p.start()
        logger.info("spawned worker '%s' pinned to core %d (pid=%d)", p.name, core, p.pid)
        return p

    def assign_data_cores(self, n: int) -> List[int]:
        """Round-robin assign n workers across the data cores (one core each,
        wrapping if n > #data_cores). Used to place per-vsys dataplanes."""
        dc = self.data_cores or list(range(cpu_count()))
        return [dc[i % len(dc)] for i in range(n)]

    # -- reporting / config ------------------------------------------------
    def snapshot(self) -> dict:
        return {
            "ncpu": cpu_count(),
            "planes": {p: format_cpu_list(self.planes[p]) for p in PLANES},
            "plane_cores": {p: self.planes[p] for p in PLANES},
            "isolated": format_cpu_list(self.isolated),
            "nohz_full": format_cpu_list(self.nohz_full),
            "current_affinity": format_cpu_list(self.affinity()),
            "capabilities": {"sched_setaffinity": HAVE_SCHED, "sched_fifo": HAVE_RT},
            "warnings": self.verify(),
        }

    def verify(self) -> List[str]:
        w = []
        n = cpu_count()
        # plane overlaps
        for i, a in enumerate(PLANES):
            for b in PLANES[i + 1:]:
                ov = set(self.planes[a]) & set(self.planes[b])
                # mgmt/ctrl sharing is fine on small boxes; data must be exclusive
                if ov and PLANE_DATA in (a, b) and self.planes[a] != self.planes[b]:
                    w.append("plane %s and %s overlap on cores %s" %
                             (a, b, format_cpu_list(sorted(ov))))
        # out-of-range cores
        for p in PLANES:
            bad = [c for c in self.planes[p] if c >= n]
            if bad:
                w.append("plane %s lists cores %s >= ncpu(%d)" %
                         (p, format_cpu_list(bad), n))
        # data cores should be isolated for real determinism
        if self.isolated:
            not_iso = [c for c in self.data_cores if c not in self.isolated]
            if not_iso:
                w.append("data cores %s are NOT in isolcpus (%s) -> jitter risk"
                         % (format_cpu_list(not_iso), format_cpu_list(self.isolated)))
        elif self.data_cores and self.data_cores != list(range(n)):
            w.append("no isolcpus set; data cores %s share the kernel scheduler"
                     % format_cpu_list(self.data_cores))
        return w

    def render_conf(self) -> str:
        L = ["# /etc/ffn-ngfw/cpu-planes.conf -- generated by ffn_cpu_planes",
             "# FFN NGFW CPU plane split (mgmt/ctrl/data)."]
        for p in PLANES:
            L.append('%s="%s"' % (CONF_KEY[p], format_cpu_list(self.planes[p])))
        return "\n".join(L) + "\n"

    def grub_isolcpus(self) -> str:
        """Recommended kernel arg to isolate the data cores."""
        cl = format_cpu_list(self.data_cores)
        if not cl:
            return ""
        return "isolcpus=managed_irq,domain,%s nohz_full=%s rcu_nocbs=%s" % (cl, cl, cl)

    # -- DPDK EAL wiring (REWORK_CONTRACT §10) -----------------------------
    # The data plane cores ARE the DPDK lcores: ffn-dpdk-mp / the systemd unit
    # binds the symmetric-MP workers to these isolated cores so the EAL never
    # schedules a worker onto a mgmt/ctrl core. Pure string/int math -- no
    # Linux-only calls, importable + unit-testable on Windows.
    #
    # DPDK 22.11 EAL core options (only ONE of -c / -l / --lcores at a time):
    #   -c <hexmask>            bit i set => lcore i used
    #   -l <c1[-c2][,c3]...>    explicit core list
    #   --lcores '<l>@<cpu>,..' map DPDK lcore id -> physical cpu (@ omittable
    #                           when they are equal)
    # Ref: doc.dpdk.org/guides-22.11/linux_gsg/linux_eal_parameters.html

    def _eal_cores(self, cores: Optional[List[int]] = None) -> List[int]:
        """Cores to hand DPDK; defaults to the data plane."""
        return sorted(set(cores if cores is not None else self.data_cores))

    def eal_coremask(self, cores: Optional[List[int]] = None) -> str:
        """Hex coremask (``-c``) for the data-plane cores: bit i => lcore i."""
        mask = 0
        for c in self._eal_cores(cores):
            mask |= (1 << c)
        return "0x%x" % mask

    def eal_lcores_map(self, cores: Optional[List[int]] = None) -> str:
        """``--lcores`` map: compact DPDK lcore ids 0..N-1 pinned 1:1 onto the
        physical data cores (``0@<c0>,1@<c1>,...``). This keeps the EAL lcore id
        space dense while the workers still run on the isolated physical cpus."""
        return ",".join("%d@%d" % (i, c)
                        for i, c in enumerate(self._eal_cores(cores)))

    def eal_lcore_args(self, *, style: str = "list",
                       cores: Optional[List[int]] = None) -> List[str]:
        """EAL core-selection argv fragment for the data plane.

        style="list"     -> ["-l", "<c0>-<cN>"]      (default; readable)
        style="coremask" -> ["-c", "0x..."]
        style="map"      -> ["--lcores", "0@c0,1@c1,..."]  (dense lcore ids)

        Reflects self.data_cores (or an explicit `cores` override). Returns []
        when there are no data cores to bind.
        """
        cs = self._eal_cores(cores)
        if not cs:
            return []
        if style == "coremask":
            return ["-c", self.eal_coremask(cs)]
        if style == "map":
            return ["--lcores", self.eal_lcores_map(cs)]
        if style == "list":
            return ["-l", format_cpu_list(cs)]
        raise ValueError("unknown EAL lcore style: %r" % style)

    def dpdk_worker_map(self, nb_ports: int,
                        cores: Optional[List[int]] = None) -> Dict[int, dict]:
        """Map each data-plane core -> one symmetric-MP worker owning one queue
        pair per port (REWORK_CONTRACT §10).

        In DPDK symmetric-MP each secondary worker owns a single rx/tx queue
        index that is identical across every port; worker i drives queue i on
        all `nb_ports` ports. So N data cores => N workers => N queue pairs.

        Returns {physical_core: {
            "worker_index": i,       # 0..N-1, also the EAL lcore id under
                                     #   eal_lcores_map()
            "lcore": i,
            "rxq": i, "txq": i,      # queue-pair index (same on every port)
            "queues": [ {"port": p, "rx_queue": i, "tx_queue": i}
                        for p in range(nb_ports) ],
        }}.
        """
        if nb_ports < 0:
            raise ValueError("nb_ports must be >= 0")
        cs = self._eal_cores(cores)
        out: Dict[int, dict] = {}
        for i, core in enumerate(cs):
            out[core] = {
                "worker_index": i,
                "lcore": i,
                "rxq": i,
                "txq": i,
                "queues": [{"port": p, "rx_queue": i, "tx_queue": i}
                           for p in range(nb_ports)],
            }
        return out


# ===========================================================================
# Self-test -- portable (no root, works off-Linux)
# ===========================================================================
def selftest() -> int:
    print("ffn_cpu_planes selftest")

    # -- 1. cpu-list expand/compress round-trip ---------------------------
    assert expand_cpu_list("0,2-5,8") == [0, 2, 3, 4, 5, 8]
    assert format_cpu_list([0, 2, 3, 4, 5, 8]) == "0,2-5,8"
    assert format_cpu_list([4, 5, 6, 7, 8, 9, 10, 11]) == "4-11"
    assert expand_cpu_list(format_cpu_list([1, 3, 4, 5, 9])) == [1, 3, 4, 5, 9]
    print("  [ok] cpu-list expand/compress round-trip")

    # -- 2. isolcpus + nohz_full parsing (modern flag syntax) -------------
    cmd = "BOOT_IMAGE=/vmlinuz root=/dev/sda1 isolcpus=managed_irq,domain,4-11 nohz_full=4-11 quiet"
    assert parse_isolcpus(cmd) == [4, 5, 6, 7, 8, 9, 10, 11], parse_isolcpus(cmd)
    assert parse_nohz_full(cmd) == [4, 5, 6, 7, 8, 9, 10, 11]
    assert parse_isolcpus("no isolation here") == []
    print("  [ok] isolcpus/nohz_full cmdline parse (managed_irq,domain stripped)")

    # -- 3. auto-plan splits are disjoint + cover the data plane ----------
    pl = auto_plan(12, data_frac=0.5)
    assert pl[PLANE_MGMT] == [0], pl
    assert set(pl[PLANE_DATA]).isdisjoint(pl[PLANE_MGMT])
    assert set(pl[PLANE_DATA]).isdisjoint(pl[PLANE_CTRL])
    assert max(pl[PLANE_DATA]) == 11 and len(pl[PLANE_DATA]) == 5
    small = auto_plan(2)
    assert small[PLANE_DATA] == [0, 1]      # too few -> shared
    print("  [ok] auto_plan disjoint planes:", {k: format_cpu_list(v) for k, v in pl.items()})

    # -- 4. conf parse (FFN_*_CORES + aliases) ----------------------------
    conf = ('FFN_MGMT_CORES="0-1"\nFFN_CTRL_CORES="2,3"\nFFN_DPDK_CORES="4-11"\n'
            '# comment\nUNRELATED=x\n')
    p = parse_conf(conf)
    assert p[PLANE_MGMT] == [0, 1] and p[PLANE_CTRL] == [2, 3]
    assert p[PLANE_DATA] == list(range(4, 12))
    assert parse_conf('FFN_DP_CORES="6-7"')[PLANE_DATA] == [6, 7]   # alias
    print("  [ok] cpu-planes.conf parse (+ FFN_DP_CORES alias)")

    # -- 5. manager: construction, queries, worker assignment -------------
    cp = CpuPlanes(pl, isolated=[4, 5, 6, 7, 8, 9, 10, 11])
    assert cp.data_cores == [7, 8, 9, 10, 11]
    assert cp.plane_of(0) == PLANE_MGMT and cp.plane_of(11) == PLANE_DATA
    # round-robin core assignment for 8 vsys over 5 data cores wraps correctly
    assign = cp.assign_data_cores(8)
    assert assign == [7, 8, 9, 10, 11, 7, 8, 9], assign
    print("  [ok] manager queries + per-vsys core assignment:", assign)

    # -- 6. conf render round-trips; grub isolcpus names the data cores ---
    rendered = cp.render_conf()
    assert parse_conf(rendered)[PLANE_DATA] == cp.data_cores
    grub = cp.grub_isolcpus()
    assert "isolcpus=managed_irq,domain,7-11" in grub and "nohz_full=7-11" in grub
    print("  [ok] render_conf round-trip + grub:", grub)

    # -- 7. verify() flags a data core that isn't isolated ----------------
    bad = CpuPlanes({PLANE_MGMT: [0], PLANE_CTRL: [1], PLANE_DATA: [2, 3]},
                    isolated=[2])           # core 3 not isolated
    warns = bad.verify()
    assert any("NOT in isolcpus" in w for w in warns), warns
    print("  [ok] verify() catches non-isolated data core:", warns[0])

    # -- 8. actual pinning (Linux only) -----------------------------------
    if HAVE_SCHED:
        avail = sorted(os.sched_getaffinity(0))
        cp2 = CpuPlanes({PLANE_DATA: avail[:1]})
        if cp2.pin(PLANE_DATA):
            aff = cp2.affinity()
            assert aff == avail[:1], (aff, avail[:1])
            print("  [ok] sched_setaffinity pinned current -> core %s" % aff)
            cp2.pin_to_cores(avail)          # restore
        rt = CpuPlanes({}).set_realtime(10)
        print("  [%s] SCHED_FIFO attempt (needs CAP_SYS_NICE)" % ("ok" if rt else "info"))
    else:
        print("  [skip] sched_setaffinity unavailable on this OS (logic tested above)")

    # -- 8b. DPDK EAL wiring reflects the data plane (contract §10) --------
    # cp.data_cores == [7, 8, 9, 10, 11]
    assert cp.eal_coremask() == "0xf80", cp.eal_coremask()   # bits 7..11 set
    # default -l list must name exactly the data plane cores
    assert cp.eal_lcore_args() == ["-l", "7-11"], cp.eal_lcore_args()
    assert cp.eal_lcore_args()[1] == format_cpu_list(cp.data_cores)
    assert cp.eal_lcore_args(style="coremask") == ["-c", "0xf80"]
    assert cp.eal_lcore_args(style="map") == ["--lcores", "0@7,1@8,2@9,3@10,4@11"]
    # dpdk_worker_map: N data cores -> N workers -> N queue pairs, 1 pair/port
    nb_ports = 3
    wm = cp.dpdk_worker_map(nb_ports)
    assert list(wm) == cp.data_cores, list(wm)            # one worker per core
    assert len(wm) == len(cp.data_cores)                  # N workers
    qpairs = {(w["rxq"], w["txq"]) for w in wm.values()}
    assert len(qpairs) == len(cp.data_cores)              # N distinct queue pairs
    for i, core in enumerate(cp.data_cores):
        w = wm[core]
        assert w["worker_index"] == i and w["rxq"] == i and w["txq"] == i, w
        assert len(w["queues"]) == nb_ports               # one queue pair/port
        assert w["queues"][0] == {"port": 0, "rx_queue": i, "tx_queue": i}
        # every port carries this worker's single queue-pair index
        assert all(q["rx_queue"] == i and q["tx_queue"] == i
                   for q in w["queues"])
    # empty data plane -> no EAL binding args (portable no-op)
    assert CpuPlanes({}).eal_lcore_args() == []
    assert CpuPlanes({}).dpdk_worker_map(2) == {}
    print("  [ok] EAL wiring: coremask=%s args=%s workers=%d/%d qpairs"
          % (cp.eal_coremask(), cp.eal_lcore_args(), len(wm), len(qpairs)))

    # -- 9. snapshot shape ------------------------------------------------
    snap = cp.snapshot()
    assert set(snap["planes"]) == set(PLANES) and "capabilities" in snap
    print("  [ok] snapshot:", {"planes": snap["planes"], "isolated": snap["isolated"]})

    print("  all assertions passed")
    return 0


# ===========================================================================
# CLI
# ===========================================================================
def main(argv=None):
    ap = argparse.ArgumentParser(description="FFN NGFW CPU plane / proc-splitting")
    ap.add_argument("--conf", default=DEFAULT_CONF)
    ap.add_argument("--data-frac", type=float, default=0.5)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("selftest")
    sub.add_parser("show")
    sub.add_parser("plan")
    sub.add_parser("conf")
    sub.add_parser("grub")
    sub.add_parser("verify")
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    if args.cmd == "selftest":
        return selftest()

    if args.cmd == "plan":
        cp = CpuPlanes.auto(data_frac=args.data_frac)
    else:
        cp = CpuPlanes.from_system(args.conf, data_frac=args.data_frac)

    if args.cmd in ("show",):
        print(json.dumps(cp.snapshot(), indent=2))
    elif args.cmd == "plan":
        print(json.dumps(cp.snapshot(), indent=2))
    elif args.cmd == "conf":
        sys.stdout.write(cp.render_conf())
    elif args.cmd == "grub":
        print(cp.grub_isolcpus())
    elif args.cmd == "verify":
        w = cp.verify()
        print("\n".join(w) if w else "OK: no warnings")
        return 1 if w else 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
