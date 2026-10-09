#!/usr/bin/env bash
# FFN NGFW installer front-end, run automatically when booted from install media.
#
# Started by ffn-installer.service, which is gated on /etc/ffn-installer-mode --
# a file that exists ONLY on installer media. A normal installed system never
# has it, so this can never appear on a running appliance.
#
# WHY THIS IS THIN
#
# install-to-disk.sh is interactive and does the real work: it enumerates the
# candidate disks itself, excludes the medium this was booted from, asks which
# disks hold the OS (single or a RAID 1 mirror) and which hold the logs (none,
# one, or a mirror/stripe), prints exactly what it will destroy and requires the
# word ERASE. Duplicating any of that here would mean two places that could
# disagree about which disk is about to be wiped.
#
# It used to be thicker, passing --list/--scheme/--dry-run. Those belonged to an
# earlier single-disk installer; the RAID-aware one this medium carries has no
# such flags, so every menu entry that used them would have failed.
#
# It also does not require a network, a mouse, or a graphical console:
# appliances are installed over a serial console or IPMI text redirect, so this
# is a plain numbered menu on stdin.
set -uo pipefail

MARKER=/etc/ffn-installer-mode
PAYLOAD_DIR="${FFN_PAYLOAD_DIR:-/opt/ffn-installer}"
INSTALLER="$PAYLOAD_DIR/install-to-disk.sh"

have(){ command -v "$1" >/dev/null 2>&1; }
pause(){ echo; read -rp "Press Enter to continue... " _ || true; }

banner() {
	clear 2>/dev/null || true
	local fw="legacy BIOS"
	[ -d /sys/firmware/efi ] && fw="UEFI"
	cat <<EOF
================================================================
 FFN NGFW  --  installer
================================================================
 firmware   : $fw
 payload    : $PAYLOAD_DIR
 version    : $(cat "$PAYLOAD_DIR/VERSION" 2>/dev/null || echo "unknown")

 Nothing is written until you choose disks and type ERASE.
================================================================
EOF
}

require_payload() {
	if [ ! -x "$INSTALLER" ]; then
		echo "ERROR: $INSTALLER is missing or not executable."
		echo "This medium does not carry a usable payload."
		return 1
	fi
	if ! ls "$PAYLOAD_DIR"/*-rootfs.tar.zst >/dev/null 2>&1; then
		echo "ERROR: no *-rootfs.tar.zst in $PAYLOAD_DIR."
		return 1
	fi
	return 0
}

show_disks() {
	echo
	# Display only. The installer's own list is the one that decides anything;
	# this is here so an operator can look without starting an install.
	lsblk -d -o NAME,SIZE,MODEL,TRAN 2>/dev/null || cat /proc/partitions
	echo
	echo "The medium you booted from is excluded from the installer's list."
}

main_menu() {
	while :; do
		banner
		cat <<'EOF'
  1) Install FFN-NGFW   (choose OS and log disks, RAID layout, then type ERASE)
  2) Show disks
  3) Shell
  4) Reboot
  5) Power off
EOF
		echo
		read -rp "choice> " c || { echo; continue; }
		case "${c:-}" in
			1) require_payload && "$INSTALLER" ; pause ;;
			2) show_disks ; pause ;;
			3) echo "Type 'exit' to return to this menu."
			   ${SHELL:-/bin/bash} -l || true ;;
			4) echo "rebooting..."; sleep 1
			   have systemctl && systemctl reboot || reboot ;;
			5) echo "powering off..."; sleep 1
			   have systemctl && systemctl poweroff || poweroff ;;
			*) echo "not a choice."; sleep 1 ;;
		esac
	done
}

# Refuse to run outside installer media. Belt and braces: the systemd unit is
# already conditioned on this file, but this script may also be run by hand and
# the consequence of getting it wrong is an installer menu on a live firewall.
if [ ! -e "$MARKER" ]; then
	echo "$0: refusing to run -- $MARKER does not exist, so this is not"
	echo "installer media. Create it deliberately if that is really what you want."
	exit 2
fi

if [ "$(id -u)" != 0 ]; then
	echo "$0: must run as root (it partitions disks)"
	exit 2
fi

main_menu
