#!/usr/bin/env bash
# FFN NGFW installer front-end, run automatically when booted from install media.
#
# Started by ffn-installer.service, which is gated on /etc/ffn-installer-mode --
# a file that exists ONLY on installer media. A normal installed system never
# has it, so this can never appear on a running appliance.
#
# WHAT THIS DOES NOT DO
#
# It does not pick a disk, and it does not install anything on its own. An
# installer that helpfully chooses "the biggest disk" and gets on with it will
# eventually eat somebody's data array. Every destructive step here needs a
# disk named explicitly and the word ERASE typed, both enforced by
# install-to-disk.sh rather than by this menu.
#
# It also does not require a network, a mouse, or a graphical console: appliances
# are installed over a serial console or IPMI text redirect, so this is a plain
# numbered menu on stdin.
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

 Nothing is written until you choose a disk and confirm.
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

do_install() {
	local scheme="$1"
	echo
	"$INSTALLER" --list || return 1
	echo
	echo "Disks marked IN-USE are refused: that includes this installer medium."
	echo "Enter the target disk (e.g. /dev/sda, /dev/nvme0n1), or blank to cancel."
	read -rp "target> " d || return 1
	[ -n "${d:-}" ] || { echo "cancelled."; return 0; }
	echo
	# install-to-disk.sh does the real validation, the ERASE prompt and the work.
	"$INSTALLER" --scheme "$scheme" "$d"
}

do_dry_run() {
	echo
	"$INSTALLER" --list || return 1
	echo
	read -rp "disk to rehearse against> " d || return 1
	[ -n "${d:-}" ] || return 0
	"$INSTALLER" --dry-run "$d"
}

main_menu() {
	while :; do
		banner
		cat <<'EOF'
  1) Install  (detect firmware, choose GPT or MBR automatically)
  2) Install  -- force GPT   (UEFI, or BIOS with a bios_grub partition)
  3) Install  -- force MBR   (legacy BIOS only)
  4) Rehearse an install (--dry-run; changes nothing)
  5) Show disks
  6) Shell
  7) Reboot
  8) Power off
EOF
		echo
		read -rp "choice> " c || { echo; continue; }
		case "${c:-}" in
			1) require_payload && do_install auto ; pause ;;
			2) require_payload && do_install gpt  ; pause ;;
			3) require_payload && do_install mbr  ; pause ;;
			4) require_payload && do_dry_run      ; pause ;;
			5) require_payload && "$INSTALLER" --list ; pause ;;
			6) echo "Type 'exit' to return to this menu."
			   ${SHELL:-/bin/bash} -l || true ;;
			7) echo "rebooting..."; sleep 1
			   have systemctl && systemctl reboot || reboot ;;
			8) echo "powering off..."; sleep 1
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
