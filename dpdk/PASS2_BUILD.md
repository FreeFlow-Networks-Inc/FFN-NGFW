# FFN-NGFW Pass-2 DPDK Data Plane -- Box Build & Bring-Up

Exact, ordered checklist to build and smoke-test the Pass-2 data plane on the
target box:

- **`ffn-fastpath-fwd`** -- standalone DPDK-primary fast path (single process,
  deterministic stdout; easiest for the pcap smoke test).
- **`ffn-dpdk-mp`** -- the symmetric-MP **zygote** primary (reserves shared
  `ffn_dpmem`, forks per-queue `--proc-type=secondary` workers, applies flatcc
  MP<->DP model/sig/policy hot-updates by flipping a double-buffered bank).
- **`ffn_hs_build`** -- the one libhs-gated Hyperscan DB serializer.

All deps are installed **side-by-side under `/opt`** -- do NOT rely on system
DPDK/flatcc. The Makefile bakes the `/opt` paths in; the service sets
`LD_LIBRARY_PATH` for them.

---

## 0. Prerequisites (already installed on the box)

| Component | Location / probe | Notes |
|---|---|---|
| DPDK **22.11** | prefix `/opt/dpdk-22.11`; `…/lib/x86_64-linux-gnu/pkgconfig/libdpdk.pc` | contract §10 target |
| flatcc | prefix `/opt/flatcc`; `bin/flatcc`, `include/`, `lib/libflatccrt.a` | C reader/builder codegen |
| Hyperscan | `pkg-config libhs` | OPTIONAL -- gated by `HAVE_HYPERSCAN` |
| C toolchain | `cc` (gcc/clang), C11 | `-std=gnu11 -O2 -g` |

Verify all of them in one shot:

```sh
cd sw/salvage/dpdk
make check
# prints libdpdk 22.11.x, libhs version (or "not found"), flatcc --version,
# and confirms /opt/flatcc/lib/libflatccrt.a exists. Non-zero exit == missing dep.
```

---

## 1. Environment

The Makefile already prepends the DPDK pkgconfig dir internally, so `make` needs
nothing exported. If you invoke `pkg-config`/`flatcc` by hand, mirror it:

```sh
export PKG_CONFIG_PATH=/opt/dpdk-22.11/lib/x86_64-linux-gnu/pkgconfig:$PKG_CONFIG_PATH
export LD_LIBRARY_PATH=/opt/dpdk-22.11/lib/x86_64-linux-gnu:$LD_LIBRARY_PATH

pkg-config --modversion libdpdk        # -> 22.11.x   (must succeed)
/opt/flatcc/bin/flatcc --version       # must succeed
```

`LD_LIBRARY_PATH` is required at RUN time: DPDK 22.11 lives under `/opt`, and its
PMDs (net_pcap, net_af_xdp, the NIC drivers) are auto-loaded shared objects from
that tree. The systemd unit sets this for you; a hand-run shell must export it.

---

## 2. Flatcc codegen + build

```sh
cd sw/salvage/dpdk

make codegen     # /opt/flatcc/bin/flatcc -a -o . ../ngfwd/ffn_mpdp.fbs
                 #   -> ffn_mpdp_reader.h  ffn_mpdp_builder.h  ffn_mpdp_verifier.h
                 #      ffn_mpdp_json_parser.h  ffn_mpdp_json_printer.h
                 #      flatbuffers_common_reader.h  flatbuffers_common_builder.h
make             # builds ffn-fastpath-fwd + ffn-dpdk-mp (+ ffn_hs_build if libhs)

# static-tables-only fast path (skips the DP-MP dpmem hot-swap path):
# make FFN_NO_DPMEM=1 ffn-fastpath-fwd
```

Notes:
- `flatcc -a` names the reader **`ffn_mpdp_reader.h`** (not `ffn_mpdp.h`); the
  builder/verifier `#include` it. `ffn_mpdp_consumer.c` already includes
  `ffn_mpdp_builder.h` + `ffn_mpdp_verifier.h`, i.e. the canonical `-a` names --
  no source edit was needed.
- The generated headers land in `.` and are found via `-I.` (which also lets
  `ffn_fastpath_fwd.c` find `ffn_dpmem.h`). Flatcc runtime headers come from
  `-I/opt/flatcc/include`; the runtime archive `/opt/flatcc/lib/libflatccrt.a`
  is linked into both DPDK binaries.
- The MP binary compiles `ffn_fastpath_fwd.c` a second time with
  `-Dmain=ffn_fastpath_fwd_standalone_main` so its `main()` does not collide with
  `ffn_dpdk_mp.c`'s. See **§9 Integration gaps** before relying on the MP
  worker path.

**Build objects / targets (for reference):**
- `ffn-fastpath-fwd` <- `ffn_fastpath_fwd.o` + `ffn_mpdp_consumer.o` + libflatccrt + libdpdk [+ libhs]
- `ffn-dpdk-mp` <- `ffn_dpdk_mp.o` + `ffn_fastpath_fwd.mp.o` + `ffn_mpdp_consumer.o` + libflatccrt + libdpdk [+ libhs], `-pthread`
- `ffn_hs_build` <- `ffn_hs_build.c` + libhs

---

## 3. Compile fast-path tables + Hyperscan DB

The fast path mmaps `ffn_fastpath.{policy,patmeta,avhash,strings}.bin` and
deserializes `ffn_fastpath.block.hsdb` from `--tables <dir>`. Build them from the
MP-side compiler, then serialize the Hyperscan DB (this is what carries EICAR):

```sh
python3 ../ngfwd/ffn_fastpath_compile.py build --out /var/lib/ffn-ngfw/fastpath --seed

# ffn_hs_build takes the fastpath DIR and writes ffn_fastpath.block.hsdb +
# ffn_fastpath.stream.hsdb into it (reads ffn_fastpath.hspat + .patmeta.bin):
./ffn_hs_build /var/lib/ffn-ngfw/fastpath

ls /var/lib/ffn-ngfw/fastpath/
#  ffn_fastpath.policy.bin  ffn_fastpath.patmeta.bin  ffn_fastpath.avhash.bin
#  ffn_fastpath.strings.bin  ffn_fastpath.block.hsdb   ffn_fastpath.stream.hsdb
```

> EICAR is dropped by the inline content scan, so the DROP smoke test below
> requires the `HAVE_HYPERSCAN` build **and** an EICAR pattern in
> `patmeta.bin`/`block.hsdb` with action RESET or DROP (the `--seed` set carries
> it). A build without libhs forwards EICAR (content scan compiled out).

---

## 4. Hugepages + NIC binding (vfio OR af_xdp)

```sh
# Hugepages: 1024 x 2 MiB = 2 GiB, mounted at /mnt/huge (matches the service).
echo 1024 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages
mkdir -p /mnt/huge
mountpoint -q /mnt/huge || mount -t hugetlbfs -o pagesize=2M nodev /mnt/huge
cat /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages   # > 0

# --- option A: vfio-pci (real NIC, best perf) ---
modprobe vfio-pci
/opt/dpdk-22.11/bin/dpdk-devbind.py --status
/opt/dpdk-22.11/bin/dpdk-devbind.py --bind=vfio-pci 0000:05:00.0
# (no IOMMU? echo 1 > /sys/module/vfio/parameters/enable_unsafe_noiommu_mode)

# --- option B: AF_XDP vdev (no rebind; kernel keeps the netdev) ---
# nothing to bind; pass --vdev=net_af_xdp0,iface=<nic> at run time. Needs the
# af_xdp PMD present in the /opt/dpdk-22.11 build (libbpf/libxdp).
```

The pcap smoke test (§6) needs no hugepage NIC at all -- it uses the `net_pcap`
vdev over files. You still want a few hugepages up for EAL init.

---

## 5. ASLR OFF -- why the zygote requires it

`ffn-dpdk-mp` (`--proc-type=primary`) seeds the AC/DFA tables, ML trees, and the
sig/policy double-buffer into a **shared** hugepage memzone (`ffn_dpmem`), then
forks per-queue workers. A serialized model (and DPDK's own internal shared
config) can embed **absolute pointers**; a forked/exec'd worker only keeps them
valid if the shared region maps at the **same virtual address** in every process
-- the layout must be deterministic. With ASLR on, each worker randomizes its
mmap base and those pointers dangle -> silent corruption.

```sh
sysctl -w kernel.randomize_va_space=0     # global ASLR off (the service does this)
# ffn-dpdk-mp ALSO self-enforces via personality(ADDR_NO_RANDOMIZE) + re-exec.
```

Restore with `sysctl -w kernel.randomize_va_space=2` when done (the unit does
this in `ExecStopPost`).

---

## 6. Smoke test A -- single-worker EICAR drop (pcap, no NIC)

Confirms parse -> policy -> Hyperscan content scan -> **DROP** end to end with
zero hardware. This is the exact command:

```sh
# Build an EICAR-carrying pcap (scapy shown; any tool works).
python3 - <<'PY'
from scapy.all import Ether, IP, TCP, Raw, wrpcap
eicar = rb'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
pkt = Ether()/IP(src="10.0.0.2",dst="10.0.0.9")/TCP(sport=1234,dport=80)/Raw(eicar)
wrpcap("in.pcap", [pkt]*4)
PY

# -l 1  -> one lcore; ffn_fastpath_fwd runs the worker inline (nworkers=0 path).
./ffn-fastpath-fwd -l 1 \
  --vdev=net_pcap0,rx_pcap=in.pcap,tx_pcap=out.pcap \
  -- --tables /var/lib/ffn-ngfw/fastpath

# PASS criteria (Ctrl-C to stop after the pcap drains):
#  * final "=== ffn_fastpath_fwd stats ===" shows THREATS >= 1 and dropped >= 1
#  * out.pcap has FEWER packets than in.pcap (EICAR packets were dropped)
tcpdump -r out.pcap 2>/dev/null | wc -l        # < 4
```

A clean packet (no EICAR) on the same 5-tuple must be **forwarded** (shows up in
`out.pcap`) -- proving the drop is on content, not on the flow.

---

## 7. Multi-lcore run

Give EAL more cores; `ffn_fastpath_fwd` launches one worker per non-main lcore,
each owning one RSS queue index across every port:

```sh
# 4 workers (lcores 2-5) + main lcore 1; one rx/tx queue per worker.
./ffn-fastpath-fwd -l 1-5 -a 0000:05:00.0 -a 0000:05:00.1 \
  -- --tables /var/lib/ffn-ngfw/fastpath [--offload]

# --offload enables the FP_PUNT_FPGA verdict path; without it a "punt" policy
# row degrades to software INSPECT.
```

The zygote/MP form (shared model, hot-swap) runs the same tables through
`ffn-dpdk-mp` -- normally via the service (§8), or by hand:

```sh
sysctl -w kernel.randomize_va_space=0
LD_LIBRARY_PATH=/opt/dpdk-22.11/lib/x86_64-linux-gnu \
./ffn-dpdk-mp -l 1-5 --proc-type=primary --file-prefix=ffn --huge-dir /mnt/huge \
  -a 0000:05:00.0 -- --tables /var/lib/ffn-ngfw/fastpath --nb-workers 4
```

---

## 8. Install + enable the service

```sh
install -Dm755 ffn-dpdk-mp        /opt/ffn-ngfw/dpdk/ffn-dpdk-mp
install -Dm755 ffn-fastpath-fwd   /opt/ffn-ngfw/dpdk/ffn-fastpath-fwd
install -Dm755 ffn_hs_build       /opt/ffn-ngfw/dpdk/ffn_hs_build
install -Dm644 PASS2_BUILD.md     /opt/ffn-ngfw/dpdk/PASS2_BUILD.md
install -Dm644 ffn-dpdk-fwd.service /etc/systemd/system/ffn-dpdk-fwd.service

# FFN_DPDK_CORES for the data plane (ffn_cpu_planes.py owns the CPU split):
ffn_cpu_planes.py conf > /etc/ffn-ngfw/cpu-planes.conf   # defines FFN_DPDK_CORES

systemctl daemon-reload
systemctl enable --now ffn-dpdk-fwd.service
systemctl status ffn-dpdk-fwd.service
journalctl -u ffn-dpdk-fwd -f
```

The unit replaces the old `ffn-dpdk-runtime` (DPDK 21.11). It reserves hugepages
(`nr_hugepages` + mount `/mnt/huge`), sets `kernel.randomize_va_space=0`, exports
`LD_LIBRARY_PATH=/opt/dpdk-22.11/lib/x86_64-linux-gnu`, and runs
`/opt/ffn-ngfw/dpdk/ffn-dpdk-mp -l ${FFN_DPDK_CORES} --proc-type=primary …`.

---

## 9. Integration gaps / box-only risks (READ before declaring done)

These are outside the three build files (Makefile / unit / this doc) and are
owned by the DP-MP / DP-FWD authors; the build wiring is ready for them:

1. **`ffn_mpdp_consumer.c` vs the committed `ffn_dpmem.h` (BLOCKER).**
   The consumer is written against a *richer* `struct ffn_dpmem_bank` (fields
   `ml_version`, `ml_kind`, `ml_features_version`, `ml_tree_blob/_len`,
   `ml_ngram_params/_len`, `policy`, `policy_n`) and helpers
   `ffn_dpmem_clone_active`, `ffn_dpmem_bank`, `ffn_dpmem_arena_dup`,
   `ffn_dpmem_arena_alloc`, `ffn_dpmem_publish`, `ffn_dpmem_threatintel_load`,
   `ffn_dpmem_sigverdict_apply`. The committed `ffn_dpmem.h` is the **slot/TLV**
   revision (`ffn_dpmem_bank_put/_clone/_flip`, `slot[]` dir) and provides none
   of those. Until DP-MP lands the matching `ffn_dpmem.h` (or the consumer is
   ported to the slot API), **`ffn_mpdp_consumer.c` will not compile**, which
   blocks BOTH binaries (both link it). Not fixable from the build files.

2. **MP worker path is not wired (`ffn_dp_worker_run`).**
   `ffn_dpdk_mp.c` calls `ffn_dp_worker_run(&args)` and ships a `__weak`
   forward-only fallback. `ffn_fastpath_fwd.c` exposes no strong
   `ffn_dp_worker_run` -- its real inspect worker is `static worker(void*)` with
   a different signature. So `ffn-dpdk-mp` links the MP TU's weak
   forward-only worker; the full inspect/verdict path does NOT run under the
   zygote yet. Linking `ffn_fastpath_fwd.mp.o` puts the code in the image but
   nothing calls it. Wiring it needs a source edit (a strong `ffn_dp_worker_run`
   adapting `struct ffn_dp_worker_args` -> the worker loop), owned by DP-FWD.

3. **Real FlatBuffers wire only.** `ffn_mpdp_apply()` rejects anything that is
   not a verifying FlatBuffers root. The MP side (`ffn_mpdp_wire.py`) must emit
   real FlatBuffers (its `flatbuffers`-runtime path), not the offline "FMDP"
   fallback frames, for live hot-updates to apply.

4. **PMD availability.** The pcap/af_xdp smoke tests assume `net_pcap` /
   `net_af_xdp` PMDs were built into `/opt/dpdk-22.11`. Confirm with
   `dpdk-testpmd --vdev=net_pcap0,... ` or check `/opt/dpdk-22.11/lib/.../dpdk/pmds-*`.

## 10. Gotchas

- **`libdpdk not found`** -> the `/opt/dpdk-22.11` pkgconfig dir is not on
  `PKG_CONFIG_PATH`. `make` prepends it automatically; a hand `pkg-config` call
  needs the export from §1.
- **flatcc headers not found** -> generated headers are stale/missing; run
  `make codegen` (or `make clean && make`). Runtime headers need
  `-I/opt/flatcc/include` (already in `CFLAGS`).
- **two `main` symbols linking `ffn-dpdk-mp`** -> only happens if the
  `-Dmain=ffn_fastpath_fwd_standalone_main` rename on `ffn_fastpath_fwd.mp.o` is
  removed. Keep it (§2).
- **worker memory corruption** -> ASLR still on, or workers launched with a
  different `--file-prefix` than the primary.
- **no hugepages** -> service `ExecStartPre` fails fast; run the §4 hugepage
  commands and re-check `nr_hugepages`.
- **old forwarder** -> `ffn_dpdk_fwd.c` (the Pass-1 KNI CPU-NIC forwarder) is
  NOT built here; KNI is deprecated in 22.11 / removed in 23.11.
