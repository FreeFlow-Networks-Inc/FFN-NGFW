# Hardware platforms

FFN-NGFW runs on ordinary Linux without anything from this directory. A
*platform* adds support for one specific family of hardware: booting its
co-processors, driving its accelerators, mapping its front panel, and whatever
else that chassis needs.

Platforms are **opt-in submodules**. They are registered in `.gitmodules` with
`update = none`, which means `git clone` — including `git clone --recursive` —
deliberately skips them.

## Available platforms

| directory | hardware | repository |
|---|---|---|
| `pa5200` | Palo Alto PA-5200-series appliances: OCTEON CN73XX control plane, CN78XX data plane, FE100 FPGA, BCM88375 switch fabric | [ffn-platform-pa5200](https://github.com/FreeFlow-Networks-Inc/ffn-platform-pa5200) |

## Selecting one

    git submodule update --init --checkout platform/pa5200

`--checkout` is required because `update = none` is what makes the platform
opt-in; without it git will tell you it is skipping the submodule. To see what is
registered without fetching anything:

    git config -f .gitmodules --get-regexp '^submodule\..*\.path$'

To drop a platform again:

    git submodule deinit -f platform/pa5200

## Why this is not automatic

A platform checkout is only meaningful on the hardware it describes. On anything
else it is boot orchestration, chassis models and register maps for hardware that
is not present — dead weight at best, and actively misleading when someone reads
it as part of the firewall.

Keeping platforms explicit also means a clone of the firewall can never be broken
by a platform repository being missing, renamed, or inaccessible.

## What a platform is expected to provide

Nothing in the firewall build depends on a platform being present, so a platform
is additive rather than an interface to satisfy. In practice one provides some
mix of:

  * bring-up: getting co-processors, FPGAs or fabrics from reset to running
  * a chassis model: which PCI device is which role, front-panel port mapping
  * transports: how the management plane reaches the other processors
  * host tooling: diagnostics and operator commands for that board

A platform must follow the same rule as the rest of the project: everything it
ships is FFN's own code or openly licensed, and no vendor firmware, binaries or
configuration is redistributed. Material recovered by analysing a vendor's
hardware is reference material about that hardware — it belongs with the
platform, or in a separate reference repository, not in the firewall.

## Adding a platform

1. Create a repository for it, licensed compatibly (GPL-2.0-or-later matches the
   rest of the project).
2. Register it here, opt-in like the others:

       git submodule add https://github.com/<org>/<repo>.git platform/<name>
       git config -f .gitmodules submodule.platform/<name>.update none

3. Add a row to the table above, and to the one in the top-level README.
