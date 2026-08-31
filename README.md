# FFN-NGFW

A next-generation firewall built to run on **end-of-life Palo Alto Networks
PA-5200-series appliances**, using FFN's own code.

These appliances are capable machines — multiple OCTEON co-processors, an FPGA,
a Broadcom switch fabric, 100G optics — that become e-waste the day their
support contract ends, because the software that drives them stops being
available. This project is the software: enough of it, written from scratch, to
make the hardware useful again.

## Why the code is written the way it is

**Everything shipped is FFN's own code or openly licensed.** No vendor code,
binaries, firmware, or configuration is redistributed. Where vendor firmware is
needed to bring a board up, it is used **in place on the appliance the owner
already has** and is never packaged into anything this project distributes.

That rule shapes real engineering decisions rather than sitting in a README. It
is why the PCIe transports here are FFN's own protocol instead of a
reimplementation of the vendor's; why the OCTEON support is built against the
BSD-licensed parts of the vendor SDK; and why anything learned by analysing the
appliance lives in a separate reference repository rather than in this one.

## Repository layout

    octeon/            OCTEON co-processor bring-up and transports
      dpnet/           CP <-> DP virtual Ethernet over PCIe (FFN's own protocol)
      dpagent/         DP-side control/shell agent
      dpboot/          DP boot and DRAM tooling
      dproot/          DP root filesystem staging
      pcnet/           MP <-> CP virtual Ethernet over PCIe
      transport/       shared transport definitions
      patches/         kernel patches against the OCTEON SDK tree
    host-transport/    management-plane side of the PCIe transports
    tools/             operator tooling
    hw/                hardware reference material (git submodules, see below)

## Submodules: hardware reference material

Talking to this hardware means knowing things about it that are not publicly
documented. Those findings are **not** in this repository. They live in
hardware-specific reference repositories, wired in as submodules:

    hw/pa5220     PA-5220 (Gryphon): OCTEON CN73XX/CN78XX, FE100 FPGA, BCM88375

The split is deliberate and load-bearing:

- this repository stays what it claims to be — FFN's own code, under an
  open-source licence;
- reference material about a third party's hardware is a different kind of
  artifact, with different licensing and different distribution questions, and
  is versioned separately;
- someone reading the code can see the protocol FFN implements without wading
  through the archaeology that informed it, and vice versa.

Clone with submodules:

    git clone --recursive https://github.com/FreeFlow-Networks-Inc/FFN-NGFW

Submodules may be private. If you do not have access, the clone still succeeds
for the code — you will simply have an empty `hw/` directory, and anything that
needs a register offset will tell you which submodule it came from.

## Status

Working, on live hardware:

- **MP <-> CP transport** — virtual Ethernet over PCIe, rings in CP DRAM
  reached through the BAR1 window. Carries the CP's NFS root.
- **CP <-> DP transport** (`octeon/dpnet`) — the same idea one level down, rings
  in DP DRAM. 128 Mbit/s TCP, zero CRC failures and zero drops under load.
  See `octeon/dpnet/DPNET.md`.
- **DP bring-up** — 40 cores up under an FFN-built kernel, a control channel
  over PCIe, and a root filesystem staged across the same link.

Not yet done: the FE100 FPGA and BCM88375 switch fabric bring-up, which is what
turns this from a pair of reachable co-processors into a forwarding plane. The
transports above are management paths; they are not the data path.

This is an active project on unusual hardware. Expect sharp edges, and expect
the documentation to admit where something was wrong the first time — those
notes are usually the useful ones.

## Building

The OCTEON components cross-compile to **big-endian MIPS64**
(`mips64-linux-gnuabi64-gcc`). Each has a `Makefile` with a `check` target that
refuses a binary which is not big-endian, static and 64-bit — a silently
little-endian build reads every shared control field byte-reversed and presents
as flaky hardware, so it is worth failing loudly.

The management-plane components are Python 3. Note that the CP's userland runs
Python 2.7, so tooling that must run there is written for both.

## Licence

**GPL-2.0-or-later** ([COPYING](COPYING)) for FFN's own code in this repository.

Not an arbitrary pick: 28 files in this tree already asserted
`SPDX-License-Identifier: GPL-2.0-or-later` before publication, including every
file under `octeon-dp/`, so this is the licence the code was written under. The
one dissenting file (`src/ngfwd.c`, previously Apache-2.0) is relicensed to match
rather than leaving a mixed-licence program for someone else to reason about.
Where `pyroute2` offers a choice of GPL-2.0-or-later or Apache-2.0, this project
elects the GPL branch.

Third-party components retain their own licences; see
[THIRD-PARTY-NOTICES](THIRD-PARTY-NOTICES). Note that `ffn_license.py` is FFN's
entitlement module and has nothing to do with copyright licensing.

Hardware reference material in submodules documents third-party interfaces and
is not covered by this grant — see each submodule's own README.
