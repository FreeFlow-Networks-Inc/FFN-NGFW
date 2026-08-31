# FFN-NGFW

A next-generation firewall that runs on **ordinary Linux**, with optional
hardware platform support you select at clone time.

Nothing here requires special hardware. The dataplane, policy engine, signature
engines, management plane and console all build and run on a commodity x86 box.
Accelerators and specific appliances are handled by **platform submodules**,
which are opt-in — a platform is only useful on the hardware it describes, so it
is never pulled in by default.

## It really does run anywhere

Verified on a plain x86 Linux host with no accelerator, no FPGA and no
co-processor, from a clean clone of this repository:

    git clone https://github.com/FreeFlow-Networks-Inc/FFN-NGFW
    cd FFN-NGFW/octeon-dp
    make && make test
    ...
    ==== ffn_dp_oct test: 0 failed ====

That suite exercises the real code paths — policy classification, the flow
cache, cache invalidation on policy reload, fail-closed defaults, and packet I/O
through the backend — not stubs.

The dataplane has two portable backends and no hard dependency on either:

  * **AF_PACKET** (`octeon-dp/`) — the reference backend. Works on any Linux
    interface, including a `veth` pair (`make veth-test`), which makes the whole
    forwarding path testable on a laptop.
  * **DPDK** (`dpdk/`) — the userspace fast path, on any DPDK-capable NIC.

Co-processor support is compiled in only when asked for (`-DFFN_HAVE_CVMX`), and
the management plane degrades cleanly when no accelerator device is present
rather than refusing to start.

## Selecting a hardware platform

A plain clone gives you the portable firewall. Platform support is registered in
`.gitmodules` but marked `update = none`, so **even `git clone --recursive` skips
it** — you choose:

    git submodule update --init --checkout platform/pa5200

| platform | hardware | repository |
|---|---|---|
| `platform/pa5200` | Palo Alto PA-5200-series appliances (OCTEON CN73XX/CN78XX, FE100 FPGA, BCM88375) | [ffn-platform-pa5200](https://github.com/FreeFlow-Networks-Inc/ffn-platform-pa5200) |

See [platform/README.md](platform/README.md) for what a platform provides and
how to add one.

### Why opt-in rather than automatic

A PA-5200 platform checkout on a device that is not a PA-5200 is not merely
unnecessary, it is misleading: it ships boot orchestration, chassis models and
register maps for hardware that is not there. Making platforms explicit keeps
this repository honest about what it is — a firewall — and keeps the hardware
archaeology of any particular chassis out of it.

It also means `git clone` stays fast and self-contained, and a missing or
inaccessible platform repository can never break a clone of the firewall.

## Layout

    octeon-dp/         portable dataplane: policy engine, flow cache,
                       AF_PACKET backend, optional co-processor backends
    dpdk/              userspace fast path and its multi-process plumbing
    src/  libngfw/     accelerator device interface (optional at runtime)
    static/            management console
    examples/          worked configuration examples
    tools/             host diagnostics
    platform/          hardware platforms (opt-in submodules)
    *.py               management plane: policy compiler, signature and
                       threat databases, detection engines, updater, sysd

## Building

The portable parts need only a C compiler and Python 3:

    cd octeon-dp && make && make test      # dataplane + its test suite
    cd dpdk && make                        # needs DPDK headers
    pip install -r requirements.txt        # management plane

Platform components cross-compile to their own targets and document that
themselves; the PA-5200 platform builds big-endian MIPS64 and its `Makefile`s
have a `check` target that refuses a binary of the wrong endianness, linkage or
word size. A silently little-endian build there reads every shared control field
byte-reversed and presents as flaky hardware, so failing loudly is worth it.

## Where this came from

The first platform exists because PA-5200-series appliances are capable machines
— multiple co-processors, an FPGA, a switch fabric, 100G optics — that become
e-waste the day their support contract ends, purely because the software that
drove them stops being available. Writing the software from scratch makes the
hardware useful again.

That motivation shaped a rule the whole project follows: **everything shipped is
FFN's own code or openly licensed.** No vendor code, binaries, firmware, or
configuration is redistributed. Where vendor firmware is needed to bring a board
up, it is used in place on the appliance the operator already owns and is never
packaged.

The rule has teeth: `ffn_vendor.py` has a `check-clean` mode whose job is to
prove no vendor-supplied content has entered a build. Anything learned by
analysing an appliance is reference material about that hardware, and lives with
that platform rather than here.

## Status

Working: management plane, policy and signature engines, the portable dataplane
with its test suite, the DPDK forwarder, and the console.

The PA-5200 platform boots both co-processors under FFN-built kernels and
carries its own PCIe transports (128 Mbit/s, zero CRC failures under load). Its
switch-fabric bring-up is not done, so on that platform the transports are
management paths rather than the forwarding path.

Active project on unusual hardware. Expect sharp edges, and expect the
documentation to say where something was wrong the first time — those notes are
usually the useful ones.

## Licence

**GPL-2.0-or-later** ([COPYING](COPYING)) for FFN's own code.

28 files asserted this before publication, including all of `octeon-dp/`, so it
is the licence the code was written under rather than one chosen afterwards.
Where `pyroute2` offers a choice of GPL-2.0-or-later or Apache-2.0, this project
elects the GPL branch.

Third-party obligations are in [THIRD-PARTY-NOTICES](THIRD-PARTY-NOTICES).
Note that `ffn_license.py` is FFN's entitlement module and has nothing to do
with copyright licensing.
