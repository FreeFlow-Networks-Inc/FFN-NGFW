# Hardware platforms

FFN-NGFW runs on ordinary x86-64 Linux without anything from this directory. A
*platform* adds support for one specific family of hardware: bringing up its
co-processors or accelerators, mapping its front panel, and telling FFN how that
hardware handles the datapath.

Platforms are **opt-in submodules**, registered in `.gitmodules` with
`update = none`, so `git clone` — *including* `git clone --recursive` —
deliberately skips them.

## The list

Machine-readable: [`platforms.json`](platforms.json). Browsable:

    ./ffn_platform.py list

| platform | hardware | datapath | CPU isolation | status | git |
|---|---|---|---|---|---|
| `generic` | any x86-64 Linux host, DPDK-capable or AF_PACKET NIC | dpdk | auto | builtin | — (no submodule) |
| `pa5200` | Palo Alto Networks PA-5200-series appliances | offload | none | supported | `https://github.com/FreeFlow-Networks-Inc/ffn-platform-pa5200.git` |
| `vu9p` | in-house VU9P FPGA accelerator card | offload | none | **planned** | `https://github.com/FreeFlow-Networks-Inc/FFN-NGFW-FPGA.git` |

`generic` is not a submodule — it is what FFN does with no platform selected.
`planned` means the URL is reserved but the repository is not published yet;
`ffn_platform.py select` refuses those rather than letting you clone a 404.

## Selecting one

    ./ffn_platform.py select pa5200
    ./ffn_platform.py current
    ./ffn_platform.py deselect pa5200

Or with git directly:

    git submodule update --init --checkout platform/pa5200

**`--checkout` is not optional.** It is what overrides `update = none`; without
it git reports that it is skipping the submodule and leaves an empty directory —
a failure that reads as a broken repository rather than a missing flag. That
sharp edge is why `ffn_platform.py` exists.

One host is one platform. `ffn_platform.py select` refuses to add a second while
one is checked out, because two declarations cannot both describe how one host's
datapath works.

## What a platform declares

Each platform ships `platform.json` at its root. FFN reads it to decide how to
tune the host:

```json
{
  "platform": "example",
  "datapath": "offload",
  "cpu_isolation": "none",
  "reason": "Forwarding runs on dedicated silicon, so host cores only carry the control plane."
}
```

| field | values | meaning |
|---|---|---|
| `datapath` | `dpdk` \| `afpacket` \| `offload` | where packets are actually forwarded |
| `cpu_isolation` | `auto` \| `none` \| `explicit` | whether host cores should be isolated |
| `isolate_cores` | e.g. `"8-15"` | required when `cpu_isolation` is `explicit` |
| `data_fraction` | 0.0–0.9 | share of physical cores to isolate under `auto` |
| `reason` | free text | shown by `ffn_cpuisol.py show`; say *why*, not *what* |

`cpu_isolation: none` is the important one. On hardware that offloads
forwarding, isolating host cores removes them from the scheduler for no
throughput gain and makes the management plane less responsive during a traffic
event — precisely when an operator needs it. Declaring `none` is how a platform
says "do not tune this host as if it were a software forwarder."

`ffn_cpuisol.py` reads this declaration, not the registry table above. The
registry duplicates the values so you can see them before cloning, and
`ffn_platform.py verify` checks the two still agree — so drift is reported
rather than quietly changing how a host is tuned.

## Why opt-in rather than automatic

A platform checkout is only meaningful on the hardware it describes. On anything
else it is bring-up code, chassis models and register maps for hardware that is
not present — misleading rather than merely redundant.

Keeping platforms explicit also means a clone of the firewall can never be broken
by a platform repository being missing, renamed, or inaccessible, and that an
unselected platform can never influence the host's kernel command line.

## What a platform is expected to provide

Nothing in the firewall build depends on a platform being present, so a platform
is additive rather than an interface to satisfy. In practice one provides some
mix of:

  * `platform.json` — the datapath and tuning declaration (the only required file)
  * bring-up: getting co-processors, FPGAs or fabrics from reset to running
  * a chassis model: which PCI device is which role, front-panel port mapping
  * transports: how the management plane reaches other processors on the board
  * host tooling: diagnostics and operator commands for that board

A platform follows the same rule as the rest of the project: everything it ships
is FFN's own code or openly licensed, and no vendor firmware, binaries or
configuration is redistributed. Material recovered by analysing a vendor's
hardware is reference material about that hardware — it belongs with the
platform, or in a separate reference repository, never in the firewall.

## Adding a platform

1. Create a repository, licensed compatibly (GPL-2.0-or-later matches the rest).
2. Give it a `platform.json` at its root.
3. Register it opt-in:

       git submodule add https://github.com/<org>/<repo>.git platform/<name>
       git config -f .gitmodules submodule.platform/<name>.update none

4. Add an entry to [`platforms.json`](platforms.json) and a row to the table
   above.
5. Check your work:

       ./ffn_platform.py verify
