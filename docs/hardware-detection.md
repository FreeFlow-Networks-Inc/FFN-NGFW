# Hardware detection

Run `python opt/ffn_hwdetect.py --brief` for a summary or use `--json` to capture
the complete inventory. In the console, open Hardware and choose **Re-detect**.
The authenticated `/api/system/hardware?refresh=1` endpoint returns the same
host inventory, enriched with the existing control-plane inventory when reachable.

Detection reads host information. It does not load drivers or bitstreams, bind
NICs, access PCI BARs, boot co-processors, select platforms, or change the kernel
command line. No optional utility is required for numeric PCI identification.

## Specialized hardware

| Hardware | Evidence used | Limits |
| --- | --- | --- |
| Xilinx and Altera PCI FPGA devices | Numeric vendor and class IDs from PCI sysfs | Reports an FPGA family, not an inferred VU9P model or a loaded FFN bitstream. PCI bridges are excluded. |
| SoC/platform FPGAs | Linux FPGA Manager `name`, `state`, and device association | Manager state describes the kernel manager; `operating` does not establish FFN forwarding readiness. |
| OCTEON host processors | CPU model and Cavium/Marvell OCTEON device-tree compatible strings | Works without a PCI endpoint or x86 DMI information. |
| OCTEON PCI devices | Known PCI device IDs, with local labels or OCTEON driver evidence for newer identities | Distinguishes processors, bridges, NVMe functions, and virtual functions. Unknown Cavium devices and ThunderX are not assumed to be OCTEON. |
| BlueField | Specific Mellanox BlueField PCI IDs; rshim/tmfifo provide weaker control-only evidence | Generic Mellanox NICs and MST alone are insufficient. Multiple functions are grouped by slot. |
| Other accelerators | PCI class and driver evidence for GPU, encryption, QAT and processing accelerators | A generic co-processor is not automatically called QAT. ASPEED/Matrox display devices remain BMC/VGA. |

`specialized.octeon` reports host-CPU evidence and observed PCI functions/slots.
It deliberately does not sum these into a chip count: one SoC can expose many
functions. `specialized.fpga` includes PCI and FPGA Manager observations; a
manager is merged into a PCI FPGA row when its device link establishes a match.
Uncorrelated observations remain separate. Arbitrary FPGA designs can use custom
PCI vendor IDs and no FPGA Manager; these remain in the raw PCI inventory until
an identification rule is added. Detection cannot identify every custom design.

`specialized.offload_ready` is `null`: readiness requires a separate platform
probe. Silicon behind an OCTEON control plane cannot be read from the host's PCI
bus. The manager retains the existing remote probe and labels those accelerator
rows `bus: control-plane`. The standalone detector reports only local evidence.

## Reliability and schema

Schema version 2 retains the established sections (`system`, `cpu`, `memory`,
`nics`, `dpu`, `accelerators`, `storage`, `hugepages`, `pci`, `tools`). New fields:

- `status`: `ok`, `partial`, or `unsupported` on non-Linux hosts.
- `probe_status`: per-section `ok`, `partial`, or `error`.
- `diagnostics`: section, source, status, and reason for missing/invalid probes.
- `pci.devices`: sorted BDF identities, class, driver, NUMA node, IOMMU group,
  SR-IOV PF/VF relationships and CPU locality. `identity_complete` distinguishes
  complete identities from unreadable or disappearing devices.
- CPU online/present/affinity-available IDs, SMT/core/die/socket topology, NUMA
  CPU lists, and common CPU flags. Unknown physical topology is marked as an
  estimate; instruction extensions are intersected across online CPUs.

`ok` means the requested probes completed, not that every optional property was
observable or that hardware is ready. Empty lists in a partial inventory do not
prove hardware absence. The console displays incomplete-inventory warnings.
NUMA `-1`, speed `0`, and IOMMU group `null` represent unavailable observations.
Legacy memory `total_gb` retains its previous calculation; `total_bytes` is exact.

Each `detect()` call uses one PCI snapshot. `lspci -Dnn` optionally supplies names;
numeric output is a fallback when PCI sysfs cannot be enumerated. Optional
commands run with a timeout and a fixed locale. Failure in one section preserves
the others. The detector has no cache; the manager caches for 30 seconds and runs
blocking probes outside its event loop. Remote enrichment does not mutate that
cached host snapshot.

Unbound PCI network devices and userspace-bound devices remain visible without a
Linux netdev. Multiple netdevs on one PCI function are preserved. VFIO/UIO binding
does not prove a running DPDK application. USB NICs do not inherit their USB host
controller's PCI identity. Virtual interfaces are labelled separately.

DPU control channels are host-level observations unless a device association is
known. The detector no longer assigns the first MST device's firmware to every
card: legacy per-device firmware dictionaries remain empty without a verified
association. Device presence does not establish BlueField operating mode.

CPU tuning reads `speed_mbps` and NUMA data from the inventory, preserves sparse
online CPU numbering, and refuses host-wide tuning from a restricted affinity
view or a non-Linux host.

## Hardware first, CPU assignment second

The sequence is **discover hardware → classify the main CPU's responsibility →
allocate CPU planes → generate isolation parameters**. Raw CPU facts are part of
discovery (needed to recognize an OCTEON host); allocation happens only after all
hardware probes finish. The inventory exposes `cpu_role` with evidence and a
reason, and `cpu.role` for simple consumers.

Recognized FPGA, OCTEON processors, DPU, co-processor, GPU, crypto/processing
accelerator, switch or front-end ASIC evidence assigns the main CPU the
**management** role. A selected offload platform makes the same assignment.
All online host CPUs remain management/housekeeping CPUs; the host data plane
gets no cores. BMC displays, bridges, auxiliary NVMe functions and unidentified
devices alone do not trigger this assignment. Incomplete hardware discovery
defers automatic partitioning with role `unknown`.

Both `ffn_cpuisol` and `CpuPlanes.from_system()`/`auto()` use this rule. Hardware
classification takes precedence over inherited explicit isolation or saved host
CPU splits. On management hosts they emit no host dataplane isolation, hugepage,
or IOMMU tuning, and do not allocate host dataplane workers. Generic hardware
continues to share its CPUs between management, control and the software data
plane. Supplying an explicit CPU count without an inventory to the CPU-plane
constructors remains a pure synthetic planning interface for tests.

This allocation policy does not activate an accelerator or attest forwarding
readiness. Running `isolcpus`/`nohz_full` settings are reported independently;
changing the planned role cannot remove restrictions from the running kernel.
Review `ffn_cpuisol.py diff` and correct the boot configuration before rebooting.
No boot configuration or live affinity is changed by discovery or planning.

## WebUI inventory

The Hardware page shows the collection time, probe diagnostics, CPU responsibility,
accelerator location and FPGA Manager state, NIC binding/SR-IOV details, and raw
PCI identities. The CPU-plane view distinguishes the detected role from running
isolation and warns when management CPUs still have isolation restrictions.

Network > Interfaces includes a detected-port inventory combining host NICs,
DPDK-bound PCI devices, live device interfaces, and chassis faceplate ports.
Unknown link states and speeds remain unknown. Host management interfaces on
chassis systems appear in discovery without becoming data-port configuration
rows. Re-detect ports requests a fresh host inventory; discovery does not create
configuration or assign zones. Late refresh responses cannot replace newer data.

## Extending and validating

Host access is isolated in `opt/ffn_hwprobe.py`. Pass `detect(probe=...)` to inject
a deterministic probe implementation; the fixture in `tests/test_hwdetect.py`
models procfs, sysfs, links, missing data, and optional commands without root.
Install `ffn_hwprobe.py` alongside `ffn_hwdetect.py` in the flat appliance layout.

Add narrowly scoped numeric IDs or evidence rules to the detector, cite their
source, and add a positive fixture plus a nearby negative case. Do not infer a
model, firmware state, or supported datapath from a vendor ID alone.

```sh
python tests/test_hwdetect.py
python tests/test_hardware_api.py     # requires requirements.txt + requirements-dev.txt
python opt/ffn_cpuisol.py selftest
node tests/test_hardware_ui.cjs
```

These checks are wired into CI. They exercise synthetic inventories and manager
integration; physical FPGA/OCTEON/BlueField validation still requires the devices.

## Identification references

- [Linux PCI sysfs interface](https://docs.kernel.org/PCI/sysfs-pci.html)
- [Linux mlx5 PCI identities](https://github.com/torvalds/linux/blob/master/drivers/net/ethernet/mellanox/mlx5/core/main.c)
- [PCI ID database: Cavium/OCTEON identities](https://github.com/pciutils/pciids/blob/master/pci.ids)
- [Linux LiquidIO OCTEON identities](https://github.com/torvalds/linux/blob/master/drivers/net/ethernet/cavium/liquidio/octeon_device.h)
- [Linux OCTEON device tree](https://github.com/torvalds/linux/blob/master/arch/mips/boot/dts/cavium-octeon/octeon_68xx.dts)
- [Linux FPGA Manager](https://docs.kernel.org/driver-api/fpga/fpga-mgr.html)

References checked on 2026-09-10. Classification rules are local and do not
download identifiers during detection.
