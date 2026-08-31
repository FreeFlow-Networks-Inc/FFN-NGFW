# Image build and installer

Builds a bootable FFN-NGFW appliance image, and installs it onto bare metal on
either firmware generation.

    ./build.sh                       # -> out/<ver>.qcow2 + rootfs/recovery tarballs
    sudo ./install-to-disk.sh --list # candidate disks, firmware, chosen scheme
    sudo ./install-to-disk.sh /dev/sdX

## Partition schemes

Both the image and the installer used to be MBR + legacy BIOS only, which simply
cannot boot on UEFI-only firmware — most hardware bought this decade. They are
now firmware-aware.

**The image** (`build.sh`, `IMG_SCHEME`):

| scheme | layout | boots on |
|---|---|---|
| `hybrid` *(default)* | GPT: bios_grub (1 MiB) + ESP (512 MiB) + root + recovery | UEFI **and** legacy BIOS |
| `mbr` | MBR: root + recovery | legacy BIOS only |

Hybrid is the default because a distributable image should not care what it
lands on. GRUB is installed twice — `i386-pc` into the bios_grub partition and
`x86_64-efi` into the ESP with `--removable`, which writes
`EFI/BOOT/BOOTX64.EFI` rather than an NVRAM entry. An NVRAM entry is impossible
to register at build time: there is no firmware present to register it with.

**The installer** (`install-to-disk.sh`, `--scheme auto|gpt|mbr`) picks from how
*this* boot happened, not from what the disk looks like:

| firmware | scheme | layout |
|---|---|---|
| UEFI | gpt | ESP (FAT32, 512 MiB) + root + recovery |
| BIOS | gpt | bios_grub (1 MiB) + root + recovery |
| BIOS | mbr | root + recovery |

`auto` chooses GPT when `/sys/firmware/efi` exists, otherwise MBR. That directory
only exists when the kernel booted *via* UEFI; finding an ESP on some disk proves
nothing about the current boot, and installing a UEFI bootloader from a BIOS boot
gives a machine that does not come up.

Legacy BIOS booting from GPT needs the 1 MiB `bios_grub` partition, because GPT
has no post-MBR gap for GRUB's core image and `grub-install` fails without it.

The recovery boot entry uses `search --no-floppy --label ffn-recovery` rather
than a hardcoded `(hd0,msdos2)`, so one entry is correct under every scheme and
survives the disk being moved to another controller.

## Installing from USB

`ffn-installer.service` runs `ffn-installer.sh` on the console at boot, gated on
`ConditionPathExists=/etc/ffn-installer-mode`. That file exists **only** on
installer media, so the menu can never appear on a running appliance even if the
unit is left enabled in the image. `ffn-installer.sh` refuses to run without it
as well, because the unit is not the only way to invoke a script.

Installer media carries:

    /etc/ffn-installer-mode          the marker
    /opt/ffn-installer/
        ffn-installer.sh             the menu
        install-to-disk.sh           the work
        <ver>-rootfs.tar.zst
        <ver>-recovery.tar.zst
        VERSION

The menu offers auto/GPT/MBR installs, a `--dry-run` rehearsal, a disk list, a
shell and reboot/poweroff. It is a plain numbered prompt on `/dev/console`, not a
TUI, because appliances are installed over a serial console or an IPMI text
redirect where there is no graphical display to fall back on.

**It never picks a disk for you.** An installer that helpfully chooses "the
biggest disk" and proceeds will eventually eat somebody's data array.

## Safety

The installer erases a disk, so:

  * **It refuses any disk hosting a mounted filesystem.** That is what stops you
    installing over the USB you booted from — the single easiest way to destroy
    an install halfway through. Verified: pointed at the disk holding `/`, it
    lists the mounts it found and exits 1.
  * A partition argument (`/dev/sda1`) is rejected with the parent disk named.
  * A disk smaller than the payload needs is refused rather than half-filled.
  * It prints what will be destroyed and requires the word `ERASE`. `--yes`
    skips that, for automated provisioning only.
  * `--dry-run` prints every command it would run and writes nothing.
  * 32-bit UEFI is refused outright rather than producing an unbootable disk.

## Who owns which kernel parameter

`ffn-hwtune.sh` and `opt/ffn_cpuisol.py` both used to write `isolcpus`,
`nohz_full`, `rcu_nocbs`, hugepages and IOMMU flags. Run in either order that
produces a command line with two `isolcpus=` tokens, or one silently erased —
and which the kernel honours is not something to build an appliance on.

One owner per concern now:

| owner | parameters |
|---|---|
| `opt/ffn_cpuisol.py` | `isolcpus`, `nohz_full`, `rcu_nocbs`, `irqaffinity`, hugepages, IOMMU |
| `ffn-hwtune.sh` | `console=` tokens only (serial baud is a chassis property) |

`ffn-hwtune.sh` now sets the console tokens via its own `grub.d` drop-in and
delegates the rest. It no longer rewrites the whole
`GRUB_CMDLINE_LINUX_DEFAULT` line, which used to destroy anything else
configured there.

## Files

| file | what |
|---|---|
| `build.sh` | builds the rootfs, recovery fs and the bootable image |
| `config.sh` | build knobs, including `IMG_SCHEME` and `IMG_ESP_MB` |
| `install-to-disk.sh` | bare-metal installer, GPT/UEFI + GPT/BIOS + MBR/BIOS |
| `ffn-installer.sh` | the boot-time installer menu |
| `ffn-installer.service` | runs the menu on installer media only |
| `ffn-firstboot.sh` / `.service` | per-machine provisioning: host keys, machine-id, TLS cert, JWT secret, NIC detection, disk grow |
| `ffn-hwtune.sh` | console tokens, then delegates CPU/memory tuning |
| `ffn-logvol.sh` / `.service` | log volume management |
| `ffn-recovery-menu.service` | recovery-partition menu |
| `ffn-fips-selftest.service` | FIPS self-test at boot |
| `ffn-pipeline.sh` | dataplane pipeline bring-up |
| `ffn_bbinstall.py` | busybox applet installer for the recovery root |
| `99-ffn-vendor.rules` | udev rules |

## Verified, and not

Verified on real hardware: `--list` correctly reports firmware and marks in-use
disks; the refusal of a mounted disk exits 1; the GPT/UEFI and MBR/BIOS
partition plans are correct under `--dry-run`.

**Not yet verified:** the `gpt-bios` path (GPT with `bios_grub`) follows the same
code path but has not been exercised on legacy-BIOS hardware, because firmware
mode is deliberately not overridable — a test hook there would be a way to
install the wrong bootloader. It needs a real BIOS machine or a SeaBIOS VM.
