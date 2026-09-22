#!/usr/bin/env bash
# FFN NGFW bare-metal installer -- interactive.
#
#   sudo ./install-to-disk.sh                    # ask everything
#   sudo ./install-to-disk.sh /dev/sdX           # OS disk given, still asks about logs
#   sudo ./install-to-disk.sh /dev/sdX /dev/sdY  # OS mirror given, still asks about logs
#   FFN_ASSUME_YES=1 ... /dev/sdX                # non-interactive, no log volume
#
# Asks three things:
#   1. which disk(s) hold the OS       (single, or two for a RAID1 mirror)
#   2. which disk(s) hold /opt/ffn-logs (none, one, or two-plus)
#   3. RAID 1 or RAID 0 for the log volume
#
# Expects <ver>-rootfs.tar.zst + <ver>-recovery.tar.zst alongside this script.
# WIPES every disk selected. The OS disk gets two partitions: main root plus
# recovery/maintenance. First boot self-provisions; FIPS-CC is toggled only from
# the recovery partition.
#
# WHY RAID 0 IS OFFERED FOR LOGS BUT NOT FOR THE OS
#
# Logs are bulk, rewritable, and reproducible, so trading redundancy for space
# and write throughput is a legitimate choice -- that is what RAID 0 buys, and
# the appliance's two 1.8T spindles are there for exactly this.
#
# The OS volume is different, and not merely by preference:
#   * A stripe has NO redundancy, so it doubles the probability of losing the
#     box for a volume whose entire job is to survive a disk dying.
#   * A mirror member can still be read as an ordinary partition when the array
#     itself will not assemble, which has rescued a stranded box twice. A stripe
#     has no such property -- no single member contains a readable filesystem --
#     so early boot would depend on GRUB assembling the array correctly before
#     it can read /boot.
#
# METADATA VERSION: 1.2, not 1.0, and this was decided on hardware.
#
# 1.0 puts the superblock at the END of the member, which is what leaves ext4
# readable at offset 0 -- genuinely useful, and the property the rescue above
# relies on. But boot-testing a freshly imaged pair of SSDs in a PA-5220 showed
# that appliance's kernel rejecting EVERY 1.0 superblock: 8 members out of 8,
#     md: sda2 does not have a valid v1.0 superblock, not importing!
# while userspace read the same superblocks perfectly (magic a92b4efc, feature
# map 0x0, checksum correct) at exactly the offset the kernel would compute.
# Disks, partition sizes, whole-disk size, sector size and checksums were all
# ruled out; the cause is still unknown. 1.2 and 0.90 both assemble unattended
# on the same box. A layout that keeps a member readable is worthless if the
# array never comes up, so 1.2 it is.
# So the OS gets single-disk or RAID 1. If you genuinely want a striped OS, that
# is a different bootloader design, not a flag.
#
# Much of the partitioning and mirror logic here comes from
# install-to-disk.sh.raid1-proposed, including the metadata reasoning above, the
# size-from-the-smaller-disk rule for mismatched reclaimed SSDs, and the
# deliberately selective array teardown. Those were right; this adds the
# interactive selection and the log volume.
set -euo pipefail

HERE="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
ROOTFS_TAR=$(ls "$HERE"/*-rootfs.tar.zst 2>/dev/null | head -1) || true
RECOVERY_TAR=$(ls "$HERE"/*-recovery.tar.zst 2>/dev/null | head -1) || true
die(){ echo "ERROR: $*" >&2; exit 1; }

# Standalone installer: it does NOT source config.sh, so give the console baud
# its own default. Appliance chassis (PA-3200/PA-5200) run 9600:
#     sudo FFN_SERIAL_BAUD=9600 ./install-to-disk.sh
#   NOT `sudo -E`: many sudo builds are compiled without SETENV and print
#   "preserving the entire environment is not supported, '-E' is ignored",
#   so the variable silently never reaches the script. With FFN_ASSUME_YES
#   that means it drops into the interactive prompts instead and dies on a
#   closed stdin. Pass the assignments as sudo ARGUMENTS, as above.
FFN_SERIAL_BAUD="${FFN_SERIAL_BAUD:-115200}"
FFN_ASSUME_YES="${FFN_ASSUME_YES:-0}"

LOG_MD=/dev/md9          # matches the existing appliance convention
OS_LOG_DEV=""            # set when logs live on the OS disks rather than their own
LOG_MNT=/opt/ffn-logs
LOG_LABEL=ffn-logs

[ "$(id -u)" = 0 ] || die "run as root"
[ -f "$ROOTFS_TAR" ]   || die "rootfs tarball not found next to this script"
[ -f "$RECOVERY_TAR" ] || die "recovery tarball not found next to this script"
command -v zstd >/dev/null        || die "install zstd first (apt install zstd)"
command -v grub-install >/dev/null || die "install grub-pc-bin first"

# ---------------------------------------------------------------- helpers ----
pname(){ local p="${1}${2}"; [ -b "$p" ] || p="${1}p${2}"; echo "$p"; }

# The disk the live environment itself is running from must never be offered.
# Wiping it mid-install is unrecoverable, and it is an easy mistake to make when
# the USB enumerates as /dev/sda.
live_disk(){
	local src
	src=$(findmnt -no SOURCE / 2>/dev/null || true)
	[ -n "$src" ] || return 0
	lsblk -no PKNAME "$src" 2>/dev/null | head -1
}

candidates(){
	local live; live=$(live_disk)
	lsblk -dno NAME,SIZE,MODEL --sort NAME 2>/dev/null | while read -r n s m; do
		case "$n" in loop*|sr*|ram*|zram*|md*|dm-*) continue;; esac
		[ -n "$live" ] && [ "$n" = "$live" ] && continue
		printf '%s\t%s\t%s\n' "$n" "$s" "${m:-unknown}"
	done
}

show_candidates(){
	local i=1
	printf '   %-3s %-12s %-9s %s\n' "#" "DEVICE" "SIZE" "MODEL"
	candidates | while read -r n s m; do
		printf '   %-3s /dev/%-7s %-9s %s\n' "$i" "$n" "$s" "$m"
		i=$((i+1))
	done
}

nth_disk(){ candidates | sed -n "${1}p" | cut -f1; }
ndisks(){ candidates | wc -l; }

# Resolve a user answer like "1" or "1 3" or "/dev/sdb" into device paths.
resolve(){
	local out=() tok
	for tok in $1; do
		if [ -b "$tok" ]; then out+=("$tok")
		elif [ -b "/dev/$tok" ]; then out+=("/dev/$tok")
		else
			local n; n=$(nth_disk "$tok" 2>/dev/null || true)
			[ -n "$n" ] || die "not a disk or menu number: $tok"
			out+=("/dev/$n")
		fi
	done
	printf '%s\n' "${out[@]}"
}

# ---------------------------------------------------- 1. the OS disk(s) ------
OS_DISKS=()
if [ $# -ge 1 ]; then
	while [ $# -gt 0 ]; do OS_DISKS+=("$1"); shift; done
else
	[ "$(ndisks)" -gt 0 ] || die "no candidate disks found"
	echo
	echo "=== 1. Where should the OS go? ==="
	echo "Two partitions are created: main root (9 GiB) and recovery/maintenance."
	echo "Give ONE disk for a single-disk install, or TWO for a RAID 1 mirror."
	echo "(RAID 0 is not offered for the OS -- see the comment at the top of this script.)"
	echo
	show_candidates
	echo
	read -rp "OS disk(s) [e.g. 1  or  1 2]: " ans
	[ -n "$ans" ] || die "no OS disk selected"
	mapfile -t OS_DISKS < <(resolve "$ans")
fi
[ "${#OS_DISKS[@]}" -ge 1 ] && [ "${#OS_DISKS[@]}" -le 2 ] \
	|| die "OS takes one disk, or two for a mirror (got ${#OS_DISKS[@]})"
for d in "${OS_DISKS[@]}"; do [ -b "$d" ] || die "not a block device: $d"; done
OS_RAID=0; [ "${#OS_DISKS[@]}" = 2 ] && OS_RAID=1
[ "$OS_RAID" = 1 ] && { command -v mdadm >/dev/null || die "install mdadm first (apt install mdadm)"; }

# ------------------------------------------------- 2/3. the log volume -------
LOG_DISKS=(); LOG_LEVEL=""
if [ "$FFN_ASSUME_YES" = 1 ]; then
	echo "-- FFN_ASSUME_YES: skipping the log volume --"
else
	echo
	echo "=== 2. Where should the log files go? ($LOG_MNT) ==="
	echo "Leave EMPTY to keep logs on the OS disk. Otherwise pick the disk(s) to"
	echo "dedicate to $LOG_MNT -- typically the large spindles, not the OS SSD."
	echo
	# Numbering MUST match the OS menu above: resolve() maps a menu number
	# against the FULL candidate list, so renumbering a filtered list here would
	# make "1" mean a different disk in each prompt. Show every candidate with
	# the same number and mark the ones already claimed, rather than removing
	# them and shifting everything up.
	printf '   %-3s %-12s %-9s %s\n' "#" "DEVICE" "SIZE" "MODEL"
	i=1; avail=0
	while read -r n s m; do
		[ -n "$n" ] || continue
		taken=""
		for o in "${OS_DISKS[@]}"; do
			[ "/dev/$n" = "$o" ] && taken="   <- OS"
		done
		[ -z "$taken" ] && avail=$((avail+1))
		printf '   %-3s /dev/%-7s %-9s %s%s\n' "$i" "$n" "$s" "$m" "$taken"
		i=$((i+1))
	done < <(candidates)
	[ "$avail" -gt 0 ] || echo "   (no disks left after the OS selection)"
	echo
	read -rp "Log disk(s) [e.g. 3 4], or EMPTY for none: " lans
	if [ -n "${lans// /}" ]; then
		# resolve against the FULL candidate list so menu numbers stay stable
		mapfile -t LOG_DISKS < <(resolve "$lans")
		for d in "${LOG_DISKS[@]}"; do
			[ -b "$d" ] || die "not a block device: $d"
			for o in "${OS_DISKS[@]}"; do
				[ "$d" = "$o" ] && die "$d is already the OS disk -- pick different disks for logs"
			done
		done
		if [ "${#LOG_DISKS[@]}" -ge 2 ]; then
			command -v mdadm >/dev/null || die "install mdadm first (apt install mdadm)"
			echo
			echo "=== 3. RAID level for $LOG_MNT across ${#LOG_DISKS[@]} disks ==="
			echo "  1) RAID 1  mirror  -- survives a disk failure, usable capacity = smallest disk"
			echo "  0) RAID 0  stripe  -- capacity and write throughput of all disks, NO redundancy"
			echo "                        (one disk dies and the whole log volume is gone)"
			echo
			read -rp "RAID level for logs [1/0]: " rl
			case "$rl" in
				1) LOG_LEVEL=1 ;;
				0) LOG_LEVEL=0 ;;
				*) die "answer 1 or 0" ;;
			esac
		fi
	fi
fi

# ------------------------------------------------------------- confirm -------
echo
echo "================ PLAN ================"
if [ "$OS_RAID" = 1 ]; then
	echo " OS   : RAID 1 mirror across ${OS_DISKS[*]}  (md0=root, md1=recovery)"
else
	echo " OS   : single disk ${OS_DISKS[*]}  (2 partitions: root + recovery)"
fi
if [ "${#LOG_DISKS[@]}" = 0 ]; then
	echo " LOGS : on the OS disk (no dedicated volume)"
elif [ "${#LOG_DISKS[@]}" = 1 ]; then
	echo " LOGS : single disk ${LOG_DISKS[*]} -> $LOG_MNT"
else
	echo " LOGS : RAID $LOG_LEVEL across ${LOG_DISKS[*]} -> $LOG_MD -> $LOG_MNT"
fi
echo " Serial console baud: $FFN_SERIAL_BAUD"
echo "======================================"
echo
echo "!!! This ERASES: ${OS_DISKS[*]} ${LOG_DISKS[*]:-}"
lsblk "${OS_DISKS[@]}" ${LOG_DISKS[@]:+"${LOG_DISKS[@]}"}
if [ "$FFN_ASSUME_YES" != 1 ]; then
	read -rp "Type ERASE to continue: " a; [ "$a" = "ERASE" ] || die "aborted"
fi

# Stop only arrays with a member on a disk we are about to touch. "mdadm --stop
# --scan" would stop EVERY array on the system, which on a box with an existing
# log mirror assembled would tear that down too -- not something an installer
# aimed at specific disks has any business doing.
stop_arrays_on(){
	# Stopping an array is not enough on its own: udev's INCREMENTAL ASSEMBLY
	# re-creates it from the surviving superblocks within moments, so a single
	# pass races udev and partitioning then dies with
	#   wipefs: error: /dev/sdX: probing initialization failed: Device or resource busy
	# Observed on a re-image of disks that already carried our own arrays.
	# So: stop, then zero the members' superblocks (leaving udev nothing to
	# assemble FROM), then re-check, up to a few rounds. Zeroing is safe here
	# because every caller passes disks the operator has already confirmed for
	# erasure -- this runs after the ERASE prompt.
	local d base md p round left mdname mp
	for round in 1 2 3 4 5; do
		left=0
		for d in "$@"; do
			base=$(basename "$d")
			for md in /sys/block/md*; do
				[ -d "$md" ] || continue
				if ls "$md"/slaves 2>/dev/null | grep -q "^${base}[0-9p]*$"; then
					mdname=$(basename "$md")
					# An array with a MOUNTED filesystem will not stop, and a
					# previous failed run leaves its mktemp mount behind -- which
					# presents as an unstoppable array for no visible reason.
					# Release it first; these disks are already confirmed for erasure.
					for mp in $(awk -v dv="/dev/$mdname" '$1==dv{print $2}' /proc/self/mounts); do
						echo "-- releasing $mp (mounted from /dev/$mdname) --"
						umount "$mp" 2>/dev/null || umount -l "$mp" 2>/dev/null || true
					done
					echo "-- stopping /dev/$mdname (member on $d) --"
					mdadm --stop "/dev/$mdname" >/dev/null 2>&1 || true
					left=1
				fi
			done
		done
		[ "$left" = 0 ] && return 0
		for d in "$@"; do
			for p in "$d"[0-9]* "${d}p"[0-9]*; do
				[ -b "$p" ] && { mdadm --zero-superblock "$p" >/dev/null 2>&1 || true; }
			done
		done
		sleep 1
	done
	# Last resort: say so rather than let partitioning fail with a confusing
	# "resource busy" several steps later.
	for d in "$@"; do
		base=$(basename "$d")
		for md in /sys/block/md*; do
			[ -d "$md" ] || continue
			ls "$md"/slaves 2>/dev/null | grep -q "^${base}[0-9p]*$" 				&& die "cannot release /dev/$(basename "$md") from $d; stop it by hand and re-run"
		done
	done
}

# Partition numbers, named once so the shift from the old msdos layout cannot
# be got wrong in one place and not another. p1 is the BIOS boot partition.
# MBR: four primaries, exactly what the layout needs, and no bios_grub
# partition because MBR keeps the post-MBR gap that core.img embeds into.
OS_P_ROOT=1
OS_P_RECOVERY=2
OS_P_NFS=3
OS_P_LOGS=4

# Fixed sizes, not proportions. Root matches the image build's
# IMG_P1_END so a disk installed here and one installed from the image
# agree; recovery is a maintenance environment and 8 GiB is ample; the
# remainder becomes mirrored NFS space for the OCTEON planes rather than
# being absorbed by recovery.
OS_ROOT_END_MIB=81920      # 80 GiB
OS_RECOVERY_END_MIB=90112  # +8 GiB
# NFS gets a fixed 32 GiB rather than the remainder. The planes' roots are
# ~80 MB trees, so 32 GiB is room to install into both many times over, and
# log space is the scarcer resource once the chassis 2 TB log pair is absent.
OS_NFS_END_MIB=122880      # +32 GiB
NFS_MNT=/opt/ffn-nfs
NFS_LABEL=ffn-nfs

part_os(){   # $1 = disk, $2 = root end, $3 = recovery end, $4 = nfs end, $5 = logs end ("" = none)
	wipefs -a "$1"
	# MBR with metadata 0.90 and partition type 0xfd -- the combination the
	# KERNEL assembles by itself, before any userspace runs.
	#
	# That is not a style preference. On this chassis 1.2 arrays built by two
	# different mdadm versions were BOTH refused at boot ("does not have a valid
	# v1.2 superblock, not importing!") while the appliance own PAN-OS log pair
	# -- MBR, 0.90, 0xfd -- assembled unattended on the very same boot. In-kernel
	# autodetect needs no mdadm, no mdadm.conf, no initramfs assembly and no udev
	# incremental claim, which removes every moving part that failed here.
	#
	# No bios_grub partition: MBR keeps the ~1 MiB post-MBR gap that core.img is
	# embedded into, which frees a primary. Four primaries is exactly the layout
	# -- root, recovery, nfs, logs -- so no extended partition is needed either.
	#
	# 0.90 also puts the superblock at the END of the member with data at offset
	# 0, so each half still mounts as a plain ext4 partition when the array will
	# not start. That rescue route is not theoretical: it is how a stranded box
	# was recovered twice.
	parted -s "$1" mklabel msdos
	parted -s "$1" mkpart primary ext4 1MiB "$2"
	parted -s "$1" mkpart primary ext4 "$2" "$3"
	# The remainder: mirrored NFS space for the OCTEON control and data plane
	# root filesystems. Their own initramfs is RAM-backed, so anything they
	# install has to live on the host's disk to survive a reboot.
	parted -s "$1" mkpart primary ext4 "$3" "$4"
	# Logs, when no dedicated log disks were chosen. Without the chassis 2 TB
	# pair there is no array for ffn-logvol.sh to discover, and logs would
	# otherwise fill the root filesystem.
	if [ -n "${5:-}" ]; then
		parted -s "$1" mkpart primary ext4 "$4" "$5"
	fi
	if [ "$OS_RAID" = 1 ]; then
		# On an msdos label "raid on" is partition type 0xfd, Linux raid
		# autodetect. That type is what the kernel scans for at boot, and with
		# 0.90 metadata it is what makes the array appear with no userspace
		# involved at all.
		parted -s "$1" set $OS_P_ROOT raid on
		parted -s "$1" set $OS_P_RECOVERY raid on
		parted -s "$1" set $OS_P_NFS raid on
		[ -n "${5:-}" ] && parted -s "$1" set $OS_P_LOGS raid on
	fi
	# Active flag on the first primary. Separate byte from the partition type so
	# it coexists with 0xfd; some BIOSes refuse an MBR disk without it.
	parted -s "$1" set $OS_P_ROOT boot on
	partprobe "$1"; sleep 2
}

# --------------------------------------------------------- OS partitions -----
stop_arrays_on "${OS_DISKS[@]}"
if [ "$OS_RAID" = 1 ]; then
	for d in "${OS_DISKS[@]}"; do
		# Zero EVERY member we are about to build on, and the whole disk too.
		# This used to clear only p2 and p3, so a stale superblock on p4, p5 or
		# the raw device survived an install and could be auto-assembled later
		# as a foreign array claiming space we had just partitioned. Reclaimed
		# SSDs arrive carrying someone else's metadata; assume nothing.
		for n in $OS_P_ROOT $OS_P_RECOVERY $OS_P_NFS $OS_P_LOGS; do
			mdadm --zero-superblock "$(pname "$d" "$n")" >/dev/null 2>&1 || true
		done
		mdadm --zero-superblock "$d" >/dev/null 2>&1 || true
	done
	# Identical explicit sizes derived from the SMALLER disk. The two SSDs in a
	# reclaimed chassis are usually different models and differ by a few MB;
	# "100%" would build mismatched members, mdadm would size the array to the
	# smaller one anyway, and a later swap for a slightly smaller disk would
	# fail. 64MiB of slack at the end leaves room for exactly that swap.
	SMALL=""
	for d in "${OS_DISKS[@]}"; do
		s=$(blockdev --getsize64 "$d")
		[ -z "$SMALL" ] && SMALL=$s
		[ "$s" -lt "$SMALL" ] && SMALL=$s
	done
	USABLE_MIB=$(( SMALL / 1048576 - 64 ))
	# Need root + recovery + something worth having for the planes.
	[ "$USABLE_MIB" -gt $(( OS_RECOVERY_END_MIB + 4096 )) ] \
		|| die "OS disks too small: ${USABLE_MIB}MiB usable, need > $(( OS_RECOVERY_END_MIB + 4096 ))MiB"
	echo "-- partitioning ${OS_DISKS[*]} (GPT, RAID members; ${USABLE_MIB}MiB usable) --"
	# Only carve an on-disk log volume when no dedicated log disks were chosen,
	# so nothing ever competes for the ffn-logs label.
	if [ "${#LOG_DISKS[@]}" -eq 0 ]; then
		OS_LOG_ARG="${USABLE_MIB}MiB"; NFS_END="${OS_NFS_END_MIB}MiB"
		echo "   root ${OS_ROOT_END_MIB}MiB / recovery $(( OS_RECOVERY_END_MIB - OS_ROOT_END_MIB ))MiB / nfs $(( OS_NFS_END_MIB - OS_RECOVERY_END_MIB ))MiB / logs $(( USABLE_MIB - OS_NFS_END_MIB ))MiB"
	else
		OS_LOG_ARG=""; NFS_END="${USABLE_MIB}MiB"
		echo "   root ${OS_ROOT_END_MIB}MiB / recovery $(( OS_RECOVERY_END_MIB - OS_ROOT_END_MIB ))MiB / nfs $(( USABLE_MIB - OS_RECOVERY_END_MIB ))MiB (logs on dedicated disks)"
	fi
	for d in "${OS_DISKS[@]}"; do
		part_os "$d" "${OS_ROOT_END_MIB}MiB" "${OS_RECOVERY_END_MIB}MiB" "$NFS_END" "$OS_LOG_ARG"
	done
	echo "-- creating OS mirrors (metadata 0.90, kernel-autodetectable) --"
	mdadm --create --run --verbose /dev/md0 --level=1 --raid-devices=2 \
	      --metadata=0.90 \
	      "$(pname "${OS_DISKS[0]}" $OS_P_ROOT)" "$(pname "${OS_DISKS[1]}" $OS_P_ROOT)"
	mdadm --create --run --verbose /dev/md1 --level=1 --raid-devices=2 \
	      --metadata=0.90 \
	      "$(pname "${OS_DISKS[0]}" $OS_P_RECOVERY)" "$(pname "${OS_DISKS[1]}" $OS_P_RECOVERY)"
	mdadm --create --run --verbose /dev/md2 --level=1 --raid-devices=2 \
	      --metadata=0.90 \
	      "$(pname "${OS_DISKS[0]}" $OS_P_NFS)" "$(pname "${OS_DISKS[1]}" $OS_P_NFS)"
	if [ -n "$OS_LOG_ARG" ]; then
		mdadm --create --run --verbose /dev/md3 --level=1 --raid-devices=2 \
		      --metadata=0.90 \
		      "$(pname "${OS_DISKS[0]}" $OS_P_LOGS)" "$(pname "${OS_DISKS[1]}" $OS_P_LOGS)"
		OS_LOG_DEV=/dev/md3
	fi
	P1=/dev/md0; P2=/dev/md1; P3=/dev/md2
else
	echo "-- partitioning ${OS_DISKS[0]} (GPT: bios_grub + root + recovery + nfs) --"
	if [ "${#LOG_DISKS[@]}" -eq 0 ]; then
		part_os "${OS_DISKS[0]}" "${OS_ROOT_END_MIB}MiB" "${OS_RECOVERY_END_MIB}MiB" "${OS_NFS_END_MIB}MiB" 100%
		OS_LOG_DEV=$(pname "${OS_DISKS[0]}" $OS_P_LOGS)
	else
		part_os "${OS_DISKS[0]}" "${OS_ROOT_END_MIB}MiB" "${OS_RECOVERY_END_MIB}MiB" 100% ""
	fi
	P1=$(pname "${OS_DISKS[0]}" $OS_P_ROOT)
	P2=$(pname "${OS_DISKS[0]}" $OS_P_RECOVERY)
	P3=$(pname "${OS_DISKS[0]}" $OS_P_NFS)
fi

# The filesystems this creates are read by the PAYLOAD's userspace, not by this
# host's. e2fsprogs 1.47 turns on orphan_file and metadata_csum_seed by default;
# jammy's e2fsck 1.46 refuses a filesystem carrying them --
#     /dev/md0 has unsupported feature(s): FEATURE_C12
#     e2fsck: Get a newer version of e2fsck!
# -- and the boot stops at "The root filesystem requires a manual fsck". The
# kernel mounts it perfectly well; it is the checker that is too old, which is
# why this surfaces at first boot rather than at install time.
#
# Same class of bug as the image build's, where the consumer was the image's own
# GRUB instead. Probed rather than written flat: `-O ^orphan_file` is itself an
# error on an e2fsprogs that predates the feature.
EXT4_OFF=""
_probe=$(mktemp); truncate -s 16M "$_probe"
for _f in orphan_file metadata_csum_seed; do
	if mkfs.ext4 -q -F -O "^$_f" "$_probe" >/dev/null 2>&1; then
		EXT4_OFF="${EXT4_OFF:+$EXT4_OFF,}^$_f"
	fi
done
rm -f "$_probe"
if [ -n "$EXT4_OFF" ]; then
	echo "-- ext4: disabling $EXT4_OFF (unreadable by the payload's e2fsck) --"
	EXT4_OFF="-O $EXT4_OFF"
fi
mkfs.ext4 -q -F $EXT4_OFF -L ffn-root     "$P1"
mkfs.ext4 -q -F $EXT4_OFF -L ffn-recovery "$P2"
mkfs.ext4 -q -F $EXT4_OFF -L "$NFS_LABEL"  "$P3"
[ -n "${OS_LOG_DEV:-}" ] && mkfs.ext4 -q -F $EXT4_OFF -L "$LOG_LABEL" "$OS_LOG_DEV"

# ---------------------------------------------------------- log volume -------
LOG_DEV=""
if [ "${#LOG_DISKS[@]}" -ge 1 ]; then
	stop_arrays_on "${LOG_DISKS[@]}"
	for d in "${LOG_DISKS[@]}"; do
		wipefs -a "$d" >/dev/null 2>&1 || true
		mdadm --zero-superblock "$d" >/dev/null 2>&1 || true
		parted -s "$d" mklabel msdos
		# One whole-disk partition. GPT because these are typically multi-TB
		# spindles, where MBR cannot address the full device.
		parted -s "$d" mkpart primary ext4 1MiB 100%
		[ "${#LOG_DISKS[@]}" -ge 2 ] && parted -s "$d" set 1 raid on
		partprobe "$d"; sleep 2
		mdadm --zero-superblock "$(pname "$d" 1)" >/dev/null 2>&1 || true
	done
	if [ "${#LOG_DISKS[@]}" = 1 ]; then
		LOG_DEV=$(pname "${LOG_DISKS[0]}" 1)
		echo "-- log volume: single disk $LOG_DEV --"
	else
		members=(); for d in "${LOG_DISKS[@]}"; do members+=("$(pname "$d" 1)"); done
		echo "-- creating log array $LOG_MD (RAID $LOG_LEVEL across ${#members[@]} members) --"
		# metadata 1.2 is fine here, unlike the OS mirror: nothing needs to read
		# a member as a bare filesystem before the array is assembled, because
		# the log volume is mounted by fstab long after the initramfs is done.
		mdadm --create --run --verbose "$LOG_MD" --level="$LOG_LEVEL" \
		      --raid-devices="${#members[@]}" --metadata=0.90 \
		      "${members[@]}"
		LOG_DEV="$LOG_MD"
	fi
	mkfs.ext4 -q -F $EXT4_OFF -L "$LOG_LABEL" "$LOG_DEV"
fi

# ------------------------------------------------------------- extract -------
MNT=$(mktemp -d); MNT2=$(mktemp -d)
echo "-- extracting main root --"; mount "$P1" "$MNT";  zstd -dc "$ROOTFS_TAR"   | tar --numeric-owner --xattrs -C "$MNT"  -xf -
echo "-- extracting recovery --";  mount "$P2" "$MNT2"; zstd -dc "$RECOVERY_TAR" | tar --numeric-owner --xattrs -C "$MNT2" -xf -

# fstab: mount the log volume by LABEL, which survives the array being renumbered
# (md9 -> md127 is the classic surprise when a foreign homehost is seen).
if [ -n "$LOG_DEV" ]; then
	mkdir -p "$MNT$LOG_MNT"
	grep -q "$LOG_MNT" "$MNT/etc/fstab" 2>/dev/null \
		|| echo "LABEL=$LOG_LABEL  $LOG_MNT  ext4  defaults,noatime,nofail  0  2" >> "$MNT/etc/fstab"
	echo "-- fstab: LABEL=$LOG_LABEL -> $LOG_MNT (nofail, so a missing log volume never blocks boot) --"
fi

# NFS space for the OCTEON planes. Mounted by LABEL with nofail: an absent
# volume must never stop the firewall booting, the same reasoning as the log
# volume. cproot/ and dproot/ are created now so the export config and
# ffn-nfsroot.sh have somewhere to point on first boot.
mkdir -p "$MNT$NFS_MNT"
grep -q "$NFS_MNT" "$MNT/etc/fstab" 2>/dev/null \
	|| echo "LABEL=$NFS_LABEL  $NFS_MNT  ext4  defaults,noatime,nofail  0  2" >> "$MNT/etc/fstab"
NFSTMP=$(mktemp -d)
mount "$P3" "$NFSTMP" && { mkdir -p "$NFSTMP/cproot" "$NFSTMP/dproot"; umount "$NFSTMP"; }
rmdir "$NFSTMP" 2>/dev/null || true
echo "-- fstab: LABEL=$NFS_LABEL -> $NFS_MNT (cproot/ + dproot/ created) --"

# Log volume on the OS disks. Mounted by LABEL with nofail, same as the
# others: a missing log volume must never stop the firewall booting.
if [ -n "${OS_LOG_DEV:-}" ]; then
	mkdir -p "$MNT$LOG_MNT"
	grep -q "$LOG_MNT" "$MNT/etc/fstab" 2>/dev/null \
		|| echo "LABEL=$LOG_LABEL  $LOG_MNT  ext4  defaults,noatime,nofail  0  2" >> "$MNT/etc/fstab"
	echo "-- fstab: LABEL=$LOG_LABEL -> $LOG_MNT (on the OS mirror; no chassis log array present) --"
fi

echo "-- installing GRUB (main + recovery entries) --"
KVER=$(ls "$MNT/boot"/vmlinuz-* | sed 's#.*/vmlinuz-##' | sort | tail -1)
# Locate recovery by LABEL rather than a hardcoded (hd0,msdos2): under RAID the
# recovery mirror is not on hd0 in any fixed sense, and search also survives a
# disk being pulled or the BIOS renumbering drives.
cat > "$MNT/etc/grub.d/40_custom" <<EOF
#!/bin/sh
exec tail -n +3 \$0
menuentry 'FFN NGFW Recovery / Maintenance' --class ffn {
  search --no-floppy --label --set=root ffn-recovery
  linux /boot/vmlinuz-$KVER root=LABEL=ffn-recovery ro console=tty0 console=ttyS0,${FFN_SERIAL_BAUD}n8
  initrd /boot/initrd.img-$KVER
}
EOF
chmod +x "$MNT/etc/grub.d/40_custom"
grep -q GRUB_DISABLE_OS_PROBER "$MNT/etc/default/grub" || echo "GRUB_DISABLE_OS_PROBER=true" >> "$MNT/etc/default/grub"

# GRUB repaints the whole menu on every countdown tick. At 9600 baud that is
# ~2 seconds per tick, which is what makes an appliance console crawl. countdown
# prints one line per second instead, and the menu is still one keypress away so
# the recovery entry stays reachable. 'quiet' is deliberately NOT added -- this
# box has no video, so boot progress on serial is the only progress there is,
# and verify-image.sh checks for exactly that.
grep -q '^GRUB_TIMEOUT_STYLE=' "$MNT/etc/default/grub" \
	|| echo 'GRUB_TIMEOUT_STYLE=countdown' >> "$MNT/etc/default/grub"

# --make-rslave is not optional. Without it the rbind is a SHARED mount, so the
# recursive `umount -l` in the cleanup below propagates back to the host and
# unmounts the BUILD MACHINE's /dev/pts. The symptom is remote: every later
# login on the build host fails to allocate a PTY, long after the build that
# did it has exited, and nothing points at the build. Observed doing exactly
# that. Slave propagation keeps unmounts inside the chroot.
mount -t proc proc "$MNT/proc"; mount -t sysfs sys "$MNT/sys"; mount --rbind /dev "$MNT/dev"; mount --make-rslave "$MNT/dev"

# Any array that has to be assembled before or during boot must be described
# inside the image. For the OS mirror the initramfs needs it to mount root at
# all; the log array does not, but recording it keeps md9 from being assembled
# as md127 under a foreign homehost.
# NOTE the grouping: || and && are equal precedence and left-associative in
# bash, so without the braces this reads (OS_RAID || LOG_DEV) && LOG_DISKS>=2 --
# which would SKIP mdadm.conf for an OS mirror with no log array, leaving an
# initramfs that cannot assemble root. Unbootable box.
if [ "$OS_RAID" = 1 ] || { [ -n "$LOG_DEV" ] && [ "${#LOG_DISKS[@]}" -ge 2 ]; }; then
	mkdir -p "$MNT/etc/mdadm"
	{ echo "HOMEHOST <ignore>"; mdadm --detail --scan; } > "$MNT/etc/mdadm/mdadm.conf"
	echo "-- wrote /etc/mdadm/mdadm.conf --"
fi
if [ "$OS_RAID" = 1 ]; then
	chroot "$MNT" sh -c 'command -v update-initramfs >/dev/null' \
		|| die "target image has no update-initramfs; cannot build a RAID-capable initrd"
	# A degraded array is the exact case a mirror exists for, and Ubuntu's
	# initramfs REFUSES to start one unless told to. Without this a single
	# failed disk drops the appliance to an (initramfs) prompt instead of
	# booting, which defeats the entire point of mirroring root. Observed
	# twice on real hardware, both times with perfectly valid metadata.
	mkdir -p "$MNT/etc/initramfs-tools/conf.d"
	echo "BOOT_DEGRADED=true" > "$MNT/etc/initramfs-tools/conf.d/mdadm"
	echo "-- BOOT_DEGRADED=true (boots on one leg rather than halting) --"
	chroot "$MNT" update-initramfs -u -k all
	# core.img must read a 0.90 superblock member before the initrd exists, and
	# GRUB goes on BOTH disks so the box still boots with either one pulled.
	# That is the entire point of the mirror.
	for d in "${OS_DISKS[@]}"; do
		grub-install --target=i386-pc --modules="mdraid09 part_msdos ext2" \
		             --boot-directory="$MNT/boot" "$d"
	done
else
	grub-install --target=i386-pc --boot-directory="$MNT/boot" "${OS_DISKS[0]}"
fi

chroot "$MNT" grub-mkconfig -o /boot/grub/grub.cfg
# Cleanup must never fail the install. Everything above has already been
# written and synced; a busy mountpoint here is a transient reference held by a
# helper that update-initramfs or grub-mkconfig spawned, not a problem with the
# result. Previously `umount "$MNT" "$MNT2"` had no `|| true`, so set -e turned
# a tidy-up hiccup into exit 32 on a completed install -- which reads as "the
# install failed" and invites redoing it or discarding a good disk.
unmount_tree(){   # $1 = mountpoint to release, deepest first
	local mp="$1" i sub
	[ -n "$mp" ] || return 0
	# Deepest-first, so /dev/pts and /dev/shm go before /dev, and /dev before $MNT.
	for sub in $(mount | awk -v m="$mp" '$3 ~ "^"m {print $3}' | sort -r); do
		for i in 1 2 3; do
			umount "$sub" 2>/dev/null && break
			sleep 1
		done
		# Still held: detach lazily. The filesystem goes once the last
		# descriptor closes, which is fine -- our writes are already done.
		mountpoint -q "$sub" && umount -l "$sub" 2>/dev/null
	done
	return 0
}
sync
unmount_tree "$MNT"
unmount_tree "$MNT2"
rmdir "$MNT" "$MNT2" 2>/dev/null || true

# ------------------------------------------------ verify the arrays ----------
# Declaring success without this is how a box that cannot assemble its own
# root reaches a rack. Stop every array we built and re-assemble it from the
# on-disk metadata ALONE -- exactly what the initramfs must do at boot, with
# none of our mdadm.conf in play yet.
if [ "$OS_RAID" = 1 ]; then
	echo
	echo "-- verifying the arrays cold-assemble from on-disk metadata --"
	sync
	# Check IDENTITY, never device paths. An array reassembled by scan comes back
	# under whatever minor is free -- md0 becomes md124, md1 becomes md125 and so
	# on -- which is the same "md9 -> md127" renumbering noted further up. A
	# path-based check reports a perfectly healthy mirror as a failure.
	VERIFY_UUIDS=$(mdadm --detail --scan 2>/dev/null | sed -n 's/.*UUID=\([^ ]*\).*/\1/p' | sort -u)
	[ -n "$VERIFY_UUIDS" ] || die "no arrays to verify, yet OS_RAID=1"
	# Assemble against the ARRAY lines we just recorded, NOT whatever
	# /etc/mdadm/mdadm.conf this environment happens to have. Two reasons:
	# the arrays are named ffn:<name>, so a host whose hostname is not "ffn"
	# treats them as foreign and --scan skips them; and when this installer is
	# run inside the payload root (the way to make mdadm/mkfs/grub match the
	# image), the conf in scope is the payload's, which has no ARRAY lines at
	# all. Either way the check reported FAIL on four perfectly good arrays.
	# Explicit UUID lines make homehost irrelevant.
	VERIFY_CONF=$(mktemp)
	mdadm --detail --scan > "$VERIFY_CONF" 2>/dev/null || true
	for m in /dev/md*; do
		[ -b "$m" ] && { mdadm --stop "$m" >/dev/null 2>&1 || true; }
	done
	# Stopping an array frees its members, and udev reacts by running
	# `mdadm --incremental` on each one. That re-claims the very partitions this
	# check is about to assemble, so a single immediate attempt races it and the
	# check reports FAIL on a healthy mirror -- which it did, twice, and a false
	# FAIL here is worse than no check at all: it tells an operator the disks are
	# bad when they are fine. Settle first, then retry before believing it.
	# --run so a legitimately degraded array still counts as assembled.
	command -v udevadm >/dev/null 2>&1 && udevadm settle --timeout=30 >/dev/null 2>&1 || true
	BACK=""
	for _try in 1 2 3 4 5; do
		mdadm --assemble --scan --run --config="$VERIFY_CONF" >/dev/null 2>&1 || true
		sleep 2
		BACK=$(mdadm --detail --scan 2>/dev/null | sed -n 's/.*UUID=\([^ ]*\).*/\1/p' | sort -u)
		missing=0
		for u in $VERIFY_UUIDS; do echo "$BACK" | grep -qx "$u" || missing=1; done
		[ "$missing" = 0 ] && break
		command -v udevadm >/dev/null 2>&1 && udevadm settle --timeout=10 >/dev/null 2>&1 || true
	done
	rm -f "$VERIFY_CONF"
	VERIFY_FAIL=0
	for u in $VERIFY_UUIDS; do
		if echo "$BACK" | grep -qx "$u"; then
			echo "   OK   array $u re-assembled"
		else
			echo "   FAIL array $u did NOT re-assemble from its own metadata"
			VERIFY_FAIL=1
		fi
	done
	# The labels are what fstab and the initramfs actually search for, so prove
	# those resolve too -- an assembled array with an unreadable filesystem would
	# still strand the box.
	for l in ffn-root ffn-recovery "$NFS_LABEL"; do
		d=$(blkid -L "$l" 2>/dev/null)
		case "$d" in
			/dev/md*) echo "   OK   LABEL=$l -> $d" ;;
			*)        echo "   FAIL LABEL=$l did not resolve to an md device (got: ${d:-nothing})"
			          VERIFY_FAIL=1 ;;
		esac
	done
	if [ "$VERIFY_FAIL" = 1 ]; then
		echo
		echo "REFUSING to report success: an array or label cannot be recovered from"
		echo "the metadata now on disk, so this box would stop at an initramfs prompt."
		echo "Collect before re-running:"
		echo "  mdadm --examine <each member>"
		echo "  blockdev --getsz <each member>"
		cat /proc/mdstat
		exit 1
	fi
	echo "-- all arrays verified (identity + labels; minors may renumber, that is fine) --"
fi

echo
echo "DONE. Reboot into the appliance."
echo "  Normal boot  -> FFN NGFW (first boot self-provisions; WebUI https://<dhcp-ip>:8443)."
echo "  Recovery     -> pick 'FFN NGFW Recovery / Maintenance' in GRUB to enable/disable FIPS-CC (wipes config)."
if [ "$OS_RAID" = 1 ]; then
	echo "  OS RAID1     -> /dev/md0 = ffn-root, /dev/md1 = ffn-recovery, GRUB on both disks."
fi
if [ "${#LOG_DISKS[@]}" -ge 2 ]; then
	echo "  LOG RAID$LOG_LEVEL   -> $LOG_MD = $LOG_LABEL mounted at $LOG_MNT"
	[ "$LOG_LEVEL" = 0 ] && echo "                  NOTE: RAID 0 has no redundancy -- one disk lost is all logs lost."
elif [ "${#LOG_DISKS[@]}" = 1 ]; then
	echo "  LOGS         -> $LOG_DEV mounted at $LOG_MNT"
fi
if [ "$OS_RAID" = 1 ] || [ "${#LOG_DISKS[@]}" -ge 2 ]; then
	echo "  Sync runs in the background after boot. Check: cat /proc/mdstat"
	cat /proc/mdstat
fi
