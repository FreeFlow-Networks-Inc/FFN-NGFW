# FFN-NGFW

A next-generation firewall for **ordinary x86-64 Linux**, with a DPDK datapath by
default and optional hardware platform support you select at clone time.

Nothing here requires special hardware. The dataplane, policy engine, signature
engines, management plane and console all build and run on a commodity box. FFN
detects the hardware it is given, tunes the host for it, and stays out of the way
of hardware that does not need tuning.

## Quickstart

    git clone https://github.com/FreeFlow-Networks-Inc/FFN-NGFW
    cd FFN-NGFW
    pip install -r requirements.txt
    ./ffn_hwdetect.py --brief          # what am I running on
    ./ffn_cpuisol.py show              # what FFN would tune, and why
    ./ffn_platform.py list             # hardware platforms available

Verified on a plain x86-64 host with no accelerator, no FPGA and no
co-processor, from a clean clone:

    cd dataplanes && make && make test
    ...
    ==== ffn_dp_oct test: 0 failed ====

That suite exercises the real code paths — policy classification, the flow
cache, cache invalidation on policy reload, fail-closed defaults, and packet I/O
through the backend — not stubs.

## Datapath

**DPDK is the default.** A DPDK poll-mode driver owns its core and spins,
which is what buys predictable forwarding latency, and it is why the host needs
tuning (below).

Two portable backends, no hard dependency on either:

| backend | where | use |
|---|---|---|
| **DPDK** (`dpdk/`) | any DPDK-capable NIC | the default fast path |
| **AF_PACKET** (`dataplanes/`) | any Linux interface, including a `veth` pair | reference and development; `make veth-test` |

Co-processor backends compile in only when asked for (`-DFFN_HAVE_CVMX`), and the
management plane degrades cleanly when no accelerator device is present rather
than refusing to start.

## Supported hardware

Three tiers, kept separate on purpose because they mean different things. The
first is "we have run it", the second is "FFN knows what this is", and the third
is "nothing here should care".

### Verified

Run end to end, from a clean clone:

| hardware | what was verified |
|---|---|
| generic x86-64 Linux, no accelerator | `dataplanes` builds and its test suite passes (`make test` → 0 failed): policy classification, flow cache, invalidation on policy reload, fail-closed defaults, packet I/O |
| PA-5200-series appliances | via the `pa5200` platform — see [platform/README.md](platform/README.md) |
| FFN VU9P FPGA accelerator card | via the `vu9p` platform (private; FFN's own gateware) |

### Recognised by autodetection

`ffn_hwdetect.py` identifies and classifies these specifically, which is what
lets `ffn_cpuisol.py` make sensible tuning decisions. **Recognised is not the
same as tested** — it means FFN knows what the device is, reads its NUMA node
and link speed, and will not mistake it for something else.

| class | vendor | detected via |
|---|---|---|
| 1/10/25/40 GbE NICs | Intel | `igb` (i210/i350), `ixgbe` (82599/X520/X540), `i40e` (X710/XL710), `ice` (E810) |
| 25/100 GbE NICs, SmartNICs | NVIDIA / Mellanox | `mlx5_core`, PCI vendor `15b3` (ConnectX family) |
| DPU | NVIDIA BlueField | PCI `15b3` + `/dev/rshim*`, `/dev/mst/*`, `tmfifo_net*`; firmware via `mlxfwmanager` |
| FPGA accelerators | Xilinx | PCI vendor `10ee` |
| FPGA accelerators | Intel / Altera | PCI vendor `1172` |
| Crypto offload | Intel QuickAssist (QAT) | PCI class `0b40` / device name |
| CPU crypto | Intel, AMD | CPUID flags: AES-NI, VAES, SHA-NI, PCLMULQDQ, AVX2, AVX-512 |
| Virtualisation | Intel, AMD | VT-x, AMD-V |

Onboard ASPEED and Matrox display controllers are deliberately classified as
BMC/VGA rather than as GPU accelerators — on a server they are the management
console's display, not something to schedule work on.

### Should work, not specifically enumerated

**Any NIC DPDK can bind.** FFN uses DPDK's own device layer rather than
maintaining a driver list, so a NIC bound through `vfio-pci`, `igb_uio` or
`uio_pci_generic` is surfaced as a DPDK-bound device and used, whether or not
FFN recognises the model. Devices bound to DPDK disappear from
`/sys/class/net`, so they are enumerated from PCI instead.

Likewise **any Linux interface** works with the AF_PACKET dataplane, including
`veth` pairs, VLANs, bonds and overlay interfaces — which is what makes the
forwarding path testable on a laptop.

If you run FFN on hardware not listed above, `ffn_hwdetect.py --json` is the
thing to send: it reports every NIC with its driver, PCI ID, link speed and NUMA
node, plus CPU topology and accelerators.

## Hardware autotuning

FFN detects CPUs, NUMA topology, NICs and accelerators, decides what the host
needs, and can write it to the kernel command line:

    ./ffn_cpuisol.py show          # the decision and the reasoning
    ./ffn_cpuisol.py diff          # exactly what applying would change
    sudo ./ffn_cpuisol.py apply --yes
    ./ffn_cpuisol.py verify        # running kernel vs. the plan
    sudo ./ffn_cpuisol.py revert --yes

On generic hardware with a DPDK datapath it isolates the poll-mode cores from
the scheduler (`isolcpus`), the timer tick (`nohz_full`) and RCU callbacks
(`rcu_nocbs`), pins IRQs to the housekeeping cores, and reserves 1 GB hugepages.

**On hardware that offloads forwarding it isolates nothing.** When packets are
switched by dedicated silicon, host cores only ever run the control plane;
isolating them removes cores from the scheduler for no gain and makes the
management plane *less* responsive exactly when an operator needs it — during a
traffic event. Platforms declare which case they are, so this is a property of
the hardware rather than a guess.

The writing side is deliberately timid, because a bad kernel command line is a
machine that does not come back:

  * `diff` is the default; `apply` and `revert` refuse without `--yes` and root
  * prefers a removable `/etc/default/grub.d` drop-in over editing the main file
  * backs up before writing, and refuses to reboot-break the box: never isolates
    CPU 0, always leaves at least two cores schedulable, and refuses when there
    are too few cores to split
  * isolates whole physical cores — an isolated thread whose SMT sibling stays
    schedulable is still preempted at the hardware level

`ffn_cpuisol.py selftest` runs the decision table with no hardware required.

## Hardware platforms

Platform support lives in separate repositories, listed in
[platform/platforms.json](platform/platforms.json) and browsable with:

    ./ffn_platform.py list
    ./ffn_platform.py select <name>
    ./ffn_platform.py current

Platforms are **opt-in**. They are registered in `.gitmodules` with
`update = none`, so `git clone` — *including* `git clone --recursive` — skips
them. A platform checkout is only meaningful on the hardware it describes; on
anything else it is bring-up code and register maps for absent hardware, which is
misleading rather than merely redundant. It also means a clone of the firewall can
never be broken by a platform repository being missing, renamed or inaccessible.

One platform is private: `vu9p` holds FFN's own FPGA gateware interface and
bitstream data, which is proprietary and carries no open-source grant. That is
precisely why platforms are opt-in — a public clone of this repository works
whether or not you can reach it, and this repository's GPL licence neither
extends to it nor is constrained by it. The management plane reaches the
accelerator through `/dev/ngfw0` ioctls rather than by linking its library, so
the two remain separate programs.

See [platform/README.md](platform/README.md) for the current list, what a
platform provides, and how to add one.

## Layout

    dataplanes/        portable dataplanes: policy engine, flow cache,
                       AF_PACKET backend, optional co-processor backends
    dpdk/              DPDK fast path and its multi-process plumbing
    static/            management console
    examples/          worked configuration examples
    tools/             host diagnostics
    platform/          hardware platform registry and opt-in submodules
    ffn_hwdetect.py    hardware, CPU, NUMA, NIC and accelerator autodetection
    ffn_cpuisol.py     CPU isolation decision and kernel command line
    ffn_cpu_planes.py  management / control / data plane core partitioning
    ffn_platform.py    list and select hardware platforms
    *.py               management plane: policy compiler, signature and threat
                       databases, detection engines, updater, sysd

## Building

The portable parts need only a C compiler and Python 3:

    cd dataplanes && make && make test      # dataplane and its test suite
    cd dpdk && make                        # needs DPDK headers
    pip install -r requirements.txt         # management plane

Platform components cross-compile to their own targets and document that
themselves.

## Why the code is written the way it is

The project exists to make capable appliances useful again after their vendor
support ends — machines with co-processors, accelerators, switch fabrics and
100G optics that become e-waste on a contract date, because the software that
drove them stops being available.

That gives the project one rule: **everything shipped is FFN's own code or
openly licensed.** No vendor code, binaries, firmware, or configuration is
redistributed. Where vendor firmware is needed to bring a board up, it is used
in place on the appliance the operator already owns and is never packaged.

The rule has teeth: `ffn_vendor.py` has a `check-clean` mode whose job is to
prove no vendor-supplied content has entered a build. Anything learned by
analysing a particular appliance is reference material about that hardware and
lives with its platform, never here.

## Status

Working: management plane, policy and signature engines, the portable dataplane
with its test suite, the DPDK forwarder, the console, hardware autodetection and
host autotuning.

Active project. Expect sharp edges, and expect the documentation to say where
something was wrong the first time — those notes are usually the useful ones.

## Licence

**GPL-2.0-or-later** ([COPYING](COPYING)) for FFN's own code.

28 files asserted this before publication, including all of `dataplanes/`, so it
is the licence the code was written under rather than one chosen afterwards.
Where `pyroute2` offers a choice of GPL-2.0-or-later or Apache-2.0, this project
elects the GPL branch.

Third-party obligations are in [THIRD-PARTY-NOTICES](THIRD-PARTY-NOTICES). Note
that `ffn_license.py` is FFN's entitlement module and has nothing to do with
copyright licensing.
