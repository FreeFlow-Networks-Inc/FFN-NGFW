#!/usr/bin/env bash
# FFN NGFW bare-metal installer -- GPT/UEFI, GPT/BIOS and MBR/BIOS.
#
#   sudo ./install-to-disk.sh /dev/sdX                 # detect firmware, choose scheme
#   sudo ./install-to-disk.sh --scheme gpt /dev/nvme0n1
#   sudo ./install-to-disk.sh --list                   # candidate disks, then exit
#
# Expects <ver>-rootfs.tar.zst and <ver>-recovery.tar.zst beside this script.
# Lays down a main root plus a recovery/maintenance partition. First boot
# self-provisions; FIPS-CC is toggled only from the recovery side.
#
# WHY THREE LAYOUTS RATHER THAN ONE
#
# The previous installer did MBR + legacy BIOS only, so it simply could not
# install on a UEFI-only machine -- which is most hardware bought this decade.
# UEFI needs a GPT disk and a FAT32 EFI System Partition; legacy BIOS booting
# from GPT needs a 1 MiB bios_grub partition for GRUB's core image, because
# there is no post-MBR gap to embed it in. Those are different disks, not a flag.
#
#   gpt-uefi   p1 ESP (FAT32, 512M) | p2 root | p3 recovery
#   gpt-bios   p1 bios_grub (1M)    | p2 root | p3 recovery
#   mbr-bios                          p1 root | p2 recovery
#
# The recovery GRUB entry uses `search --label`, not a hardcoded (hd0,msdos2),
# so one entry is correct under every scheme and survives the disk being moved
# to another controller.
#
# SAFETY. This erases a disk, so:
#   * it refuses any disk that currently hosts a mounted filesystem, which is
#     what stops you installing over the USB you booted from -- the single
#     easiest way to destroy an install halfway through;
#   * it refuses a disk smaller than the payload needs;
#   * it prints what will be destroyed and requires the word ERASE;
#   * --list and --dry-run tell you what it would do and change nothing.
set -euo pipefail

SCHEME=auto
ASSUME_YES=0
DRY_RUN=0
DO_LIST=0
DISK=""

ESP_MB=512
ROOT_GB_MIN=9
RECOVERY_GB_MIN=2
# root + recovery + ESP + slack. Refuse rather than produce a wedged install.
MIN_DISK_GB=$(( ROOT_GB_MIN + RECOVERY_GB_MIN + 2 ))

HERE="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
ROOTFS_TAR=$(ls "$HERE"/*-rootfs.tar.zst 2>/dev/null | head -1 || true)
RECOVERY_TAR=$(ls "$HERE"/*-recovery.tar.zst 2>/dev/null | head -1 || true)

# Appliance chassis run their console at 9600; generic hardware at 115200.
FFN_SERIAL_BAUD="${FFN_SERIAL_BAUD:-115200}"

die(){ echo "ERROR: $*" >&2; exit 1; }
say(){ echo "-- $*"; }
run(){ if [ "$DRY_RUN" = 1 ]; then echo "   would run: $*"; else "$@"; fi; }

usage(){
	cat <<EOF
usage: $0 [options] /dev/sdX

  --scheme auto|gpt|mbr   partition scheme (default: auto)
                          auto = gpt when booted via UEFI, else mbr
  --list                  list candidate disks and exit
  --dry-run               print what would happen, change nothing
  --yes                   skip the ERASE prompt (for automated provisioning)
  -h, --help              this text

Environment:
  FFN_SERIAL_BAUD         console baud baked into the boot entries (default 115200;
                          PA-3200/PA-5200 chassis use 9600)
EOF
	exit "${1:-0}"
}

while [ $# -gt 0 ]; do
	case "$1" in
		--scheme) SCHEME="${2:-}"; shift 2 ;;
		--scheme=*) SCHEME="${1#*=}"; shift ;;
		--list) DO_LIST=1; shift ;;
		--dry-run) DRY_RUN=1; shift ;;
		--yes|-y) ASSUME_YES=1; shift ;;
		-h|--help) usage 0 ;;
		-*) die "unknown option $1 (try --help)" ;;
		*) [ -z "$DISK" ] || die "give exactly one disk"; DISK="$1"; shift ;;
	esac
done

case "$SCHEME" in auto|gpt|mbr) ;; *) die "--scheme must be auto, gpt or mbr" ;; esac

# ---------------------------------------------------------------------------
# Firmware mode
# ---------------------------------------------------------------------------
# The kernel only creates /sys/firmware/efi when it booted via UEFI. Presence of
# an ESP on some disk proves nothing about how THIS boot happened, and installing
# a UEFI bootloader from a BIOS boot gives a machine that does not come up.
if [ -d /sys/firmware/efi ]; then
	FIRMWARE=uefi
	EFI_BITS=$( [ -f /sys/firmware/efi/fw_platform_size ] && cat /sys/firmware/efi/fw_platform_size || echo 64 )
else
	FIRMWARE=bios
	EFI_BITS=0
fi
[ "$SCHEME" = auto ] && { [ "$FIRMWARE" = uefi ] && SCHEME=gpt || SCHEME=mbr; }

if [ "$SCHEME" = mbr ] && [ "$FIRMWARE" = uefi ]; then
	echo "WARNING: booted via UEFI but --scheme mbr was requested. The result will"
	echo "         only boot with legacy/CSM enabled in firmware setup." >&2
fi
if [ "$FIRMWARE" = uefi ] && [ "$EFI_BITS" = 32 ]; then
	die "32-bit UEFI is not supported (firmware reports fw_platform_size=32)"
fi

LAYOUT="${SCHEME}-${FIRMWARE}"
case "$LAYOUT" in
	gpt-uefi|gpt-bios|mbr-bios) ;;
	mbr-uefi) LAYOUT=mbr-bios ;;   # warned above; MBR implies legacy boot
	*) die "unsupported combination: scheme=$SCHEME firmware=$FIRMWARE" ;;
esac

# ---------------------------------------------------------------------------
# Which disks are safe to touch
# ---------------------------------------------------------------------------
# Any disk with a mounted filesystem is in use -- including the live medium this
# installer is running from. Installing onto it destroys the running system
# mid-copy, which is the classic USB-installer footgun.
busy_disks() {
	local src dev pk
	findmnt -rno SOURCE | sort -u | while read -r src; do
		case "$src" in /dev/*) ;; *) continue ;; esac
		dev="${src%%[*}"
		pk=$(lsblk -no PKNAME "$dev" 2>/dev/null | head -1 || true)
		[ -n "$pk" ] && echo "/dev/$pk" || echo "$dev"
	done | sort -u
}

BUSY="$(busy_disks || true)"

list_disks() {
	printf '%-14s %8s %-6s %-9s %s\n' DISK SIZE REMOV IN-USE MODEL
	local d name size rm model state
	for d in /sys/block/*; do
		name=$(basename "$d")
		case "$name" in loop*|ram*|sr*|fd*|dm-*|md*|zram*) continue ;; esac
		[ -r "$d/size" ] || continue
		size=$(( $(cat "$d/size") / 2097152 ))
		[ "$size" -gt 0 ] || continue
		rm=$( [ -r "$d/removable" ] && [ "$(cat "$d/removable")" = 1 ] && echo yes || echo no )
		model=$( [ -r "$d/device/model" ] && tr -d ' \n' < "$d/device/model" || echo "-" )
		state=$(echo "$BUSY" | grep -qx "/dev/$name" && echo IN-USE || echo free)
		printf '%-14s %7dG %-6s %-9s %s\n' "/dev/$name" "$size" "$rm" "$state" "$model"
	done
}

if [ "$DO_LIST" = 1 ]; then
	echo "firmware: $FIRMWARE   scheme would be: $SCHEME   layout: $LAYOUT"
	echo
	list_disks
	echo
	echo "IN-USE disks host a mounted filesystem and will be refused -- that"
	echo "includes the medium this installer booted from."
	exit 0
fi

[ "$(id -u)" = 0 ] || die "run as root"
[ -n "$DISK" ] || { echo "no disk given."; echo; list_disks; echo; usage 1; }
[ -b "$DISK" ] || die "$DISK is not a block device"

# Normalise a partition argument to its parent disk, so /dev/sda1 is caught.
PK=$(lsblk -no PKNAME "$DISK" 2>/dev/null | head -1 || true)
[ -n "$PK" ] && die "$DISK is a partition; give the whole disk (/dev/$PK)"

if echo "$BUSY" | grep -qx "$DISK"; then
	echo "REFUSING: $DISK currently hosts a mounted filesystem." >&2
	findmnt -rno TARGET,SOURCE | grep "$DISK" | sed 's/^/    /' >&2
	die "this is almost certainly the medium you booted from"
fi

DISK_GB=$(( $(cat "/sys/block/$(basename "$DISK")/size") / 2097152 ))
[ "$DISK_GB" -ge "$MIN_DISK_GB" ] || \
	die "$DISK is ${DISK_GB}G; need at least ${MIN_DISK_GB}G"

[ -f "$ROOTFS_TAR" ]   || die "no *-rootfs.tar.zst beside this script"
[ -f "$RECOVERY_TAR" ] || die "no *-recovery.tar.zst beside this script"
for t in zstd parted wipefs partprobe mkfs.ext4 grub-install; do
	command -v "$t" >/dev/null || die "missing tool: $t"
done
if [ "$LAYOUT" = gpt-uefi ]; then
	command -v mkfs.vfat >/dev/null || die "missing mkfs.vfat (apt install dosfstools)"
	command -v grub-install >/dev/null || die "missing grub-install"
	[ -d /usr/lib/grub/x86_64-efi ] || die "missing grub-efi-amd64-bin"
fi

# ---------------------------------------------------------------------------
# Confirm
# ---------------------------------------------------------------------------
echo
echo "firmware detected : $FIRMWARE"
echo "partition scheme  : $SCHEME   (layout: $LAYOUT)"
echo "target disk       : $DISK  (${DISK_GB}G)"
echo "payload           : $(basename "$ROOTFS_TAR")"
echo "                    $(basename "$RECOVERY_TAR")"
echo
echo "!!! EVERYTHING ON $DISK WILL BE DESTROYED:"
lsblk -o NAME,SIZE,FSTYPE,LABEL,MOUNTPOINT "$DISK" | sed 's/^/    /'
echo
if [ "$DRY_RUN" = 1 ]; then
	say "dry run: nothing will be written"
elif [ "$ASSUME_YES" != 1 ]; then
	read -rp "Type ERASE to continue: " a
	[ "$a" = "ERASE" ] || die "aborted"
fi

# ---------------------------------------------------------------------------
# Partition
# ---------------------------------------------------------------------------
say "partitioning $DISK as $LAYOUT"
run wipefs -a "$DISK"

case "$LAYOUT" in
gpt-uefi)
	run parted -s "$DISK" mklabel gpt
	run parted -s "$DISK" mkpart ESP fat32 1MiB "$((1 + ESP_MB))MiB"
	run parted -s "$DISK" set 1 esp on
	run parted -s "$DISK" mkpart ffn-root ext4 "$((1 + ESP_MB))MiB" "$((ROOT_GB_MIN))GiB"
	run parted -s "$DISK" mkpart ffn-recovery ext4 "$((ROOT_GB_MIN))GiB" 100%
	NESP=1; NROOT=2; NREC=3
	;;
gpt-bios)
	run parted -s "$DISK" mklabel gpt
	# 1 MiB unformatted partition for GRUB's core image: on GPT there is no
	# post-MBR gap to embed it in, and without this grub-install fails.
	run parted -s "$DISK" mkpart bios_grub 1MiB 2MiB
	run parted -s "$DISK" set 1 bios_grub on
	run parted -s "$DISK" mkpart ffn-root ext4 2MiB "$((ROOT_GB_MIN))GiB"
	run parted -s "$DISK" mkpart ffn-recovery ext4 "$((ROOT_GB_MIN))GiB" 100%
	NESP=0; NROOT=2; NREC=3
	;;
mbr-bios)
	run parted -s "$DISK" mklabel msdos
	run parted -s "$DISK" mkpart primary ext4 1MiB "$((ROOT_GB_MIN))GiB"
	run parted -s "$DISK" mkpart primary ext4 "$((ROOT_GB_MIN))GiB" 100%
	run parted -s "$DISK" set 1 boot on
	NESP=0; NROOT=1; NREC=2
	;;
esac

run partprobe "$DISK"
[ "$DRY_RUN" = 1 ] || sleep 2

# nvme0n1 partitions are nvme0n1p1; sda partitions are sda1.
partdev(){ local n="$1"; if [ -b "${DISK}${n}" ]; then echo "${DISK}${n}"; else echo "${DISK}p${n}"; fi; }
if [ "$DRY_RUN" = 1 ]; then
	P_ROOT="${DISK}<${NROOT}>"; P_REC="${DISK}<${NREC}>"
	[ "$NESP" != 0 ] && P_ESP="${DISK}<${NESP}>" || P_ESP=""
else
	P_ROOT=$(partdev "$NROOT"); P_REC=$(partdev "$NREC")
	[ "$NESP" != 0 ] && P_ESP=$(partdev "$NESP") || P_ESP=""
fi

say "creating filesystems"
[ -n "$P_ESP" ] && run mkfs.vfat -F 32 -n FFNESP "$P_ESP"
run mkfs.ext4 -q -F -L ffn-root     "$P_ROOT"
run mkfs.ext4 -q -F -L ffn-recovery "$P_REC"

if [ "$DRY_RUN" = 1 ]; then
	say "dry run complete -- no changes made"
	exit 0
fi

# ---------------------------------------------------------------------------
# Unpack
# ---------------------------------------------------------------------------
MNT=$(mktemp -d); MNT2=$(mktemp -d)
cleanup(){
	umount -R "$MNT/boot/efi" 2>/dev/null || true
	umount -R "$MNT/dev" "$MNT/sys" "$MNT/proc" 2>/dev/null || true
	umount "$MNT" "$MNT2" 2>/dev/null || true
	rmdir "$MNT" "$MNT2" 2>/dev/null || true
}
trap cleanup EXIT

say "extracting main root"
mount "$P_ROOT" "$MNT"
zstd -dc "$ROOTFS_TAR" | tar --numeric-owner --xattrs -C "$MNT" -xf -
say "extracting recovery"
mount "$P_REC" "$MNT2"
zstd -dc "$RECOVERY_TAR" | tar --numeric-owner --xattrs -C "$MNT2" -xf -

KVER=$(ls "$MNT/boot"/vmlinuz-* | sed 's#.*/vmlinuz-##' | sort -V | tail -1)
[ -n "$KVER" ] || die "no kernel found in the extracted root"

# fstab: label-based, so the disk can move controllers without editing anything.
{
	echo "# generated by install-to-disk.sh ($LAYOUT)"
	echo "LABEL=ffn-root  /  ext4  errors=remount-ro  0 1"
	[ -n "$P_ESP" ] && echo "LABEL=FFNESP  /boot/efi  vfat  umask=0077  0 1"
} > "$MNT/etc/fstab"

# Recovery entry via search --label rather than (hd0,msdosN): one entry that is
# correct under GPT and MBR alike, and still correct if the disk is moved.
cat > "$MNT/etc/grub.d/40_custom" <<EOF
#!/bin/sh
exec tail -n +3 \$0
menuentry 'FFN NGFW Recovery / Maintenance' --class ffn {
  search --no-floppy --label ffn-recovery --set root
  linux /boot/vmlinuz-$KVER root=LABEL=ffn-recovery ro console=tty0 console=ttyS0,${FFN_SERIAL_BAUD}n8
  initrd /boot/initrd.img-$KVER
}
EOF
chmod +x "$MNT/etc/grub.d/40_custom"
grep -q GRUB_DISABLE_OS_PROBER "$MNT/etc/default/grub" || \
	echo "GRUB_DISABLE_OS_PROBER=true" >> "$MNT/etc/default/grub"

# ---------------------------------------------------------------------------
# Bootloader
# ---------------------------------------------------------------------------
mount -t proc proc "$MNT/proc"
mount -t sysfs sys "$MNT/sys"
mount --rbind /dev "$MNT/dev"

case "$LAYOUT" in
gpt-uefi)
	say "installing GRUB (x86_64-efi)"
	mkdir -p "$MNT/boot/efi"
	mount "$P_ESP" "$MNT/boot/efi"
	mount --rbind /sys/firmware/efi/efivars "$MNT/sys/firmware/efi/efivars" 2>/dev/null || true
	chroot "$MNT" grub-install --target=x86_64-efi --efi-directory=/boot/efi \
		--bootloader-id=FFN --recheck
	# Also write the removable fallback path. Appliance firmware often fails to
	# persist an NVRAM boot entry, or gets cleared on battery loss; without
	# \EFI\BOOT\BOOTX64.EFI such a machine silently stops booting.
	mkdir -p "$MNT/boot/efi/EFI/BOOT"
	if [ -f "$MNT/boot/efi/EFI/FFN/grubx64.efi" ]; then
		cp "$MNT/boot/efi/EFI/FFN/grubx64.efi" "$MNT/boot/efi/EFI/BOOT/BOOTX64.EFI"
		say "wrote the removable-media fallback (EFI/BOOT/BOOTX64.EFI)"
	fi
	;;
gpt-bios|mbr-bios)
	say "installing GRUB (i386-pc)"
	MODS="part_gpt part_msdos ext2 biosdisk search search_label"
	grub-install --target=i386-pc --boot-directory="$MNT/boot" --modules="$MODS" "$DISK"
	;;
esac

chroot "$MNT" grub-mkconfig -o /boot/grub/grub.cfg

say "verifying the install has something to boot"
[ -f "$MNT/boot/grub/grub.cfg" ] || die "grub.cfg was not produced"
grep -q "ffn-recovery" "$MNT/boot/grub/grub.cfg" || \
	echo "WARNING: the recovery entry is missing from grub.cfg" >&2
if [ "$LAYOUT" = gpt-uefi ]; then
	[ -f "$MNT/boot/efi/EFI/BOOT/BOOTX64.EFI" ] || \
		echo "WARNING: no EFI/BOOT fallback; this disk may not boot on firmware that forgets NVRAM entries" >&2
fi

cleanup
trap - EXIT

cat <<EOF

DONE -- $LAYOUT on $DISK

  Normal boot  -> FFN NGFW. First boot self-provisions; the console prints the
                  generated admin password once, and the WebUI is on
                  https://<address>:8443
  Recovery     -> choose 'FFN NGFW Recovery / Maintenance' in GRUB to
                  enable/disable FIPS-CC (which wipes config).

Remove the installation medium and reboot.
EOF
