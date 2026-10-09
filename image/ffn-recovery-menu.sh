#!/usr/bin/env bash
# FFN NGFW Recovery / Maintenance menu — runs ONLY on the recovery partition.
# Mounts the main root (LABEL=ffn-root) and can toggle FIPS-CC mode or factory-reset.
# Enabling/disabling FIPS-CC ZEROIZES the configuration (FIPS requirement).
#
# Interactive:  ffn-recovery-menu.sh
# Scripted:     ffn-recovery-menu.sh <enable-fips|disable-fips|factory-reset|selftest|status>
set -uo pipefail
MAIN_LABEL="ffn-root"
M=/mnt/main
C="\033[1;36m"; G="\033[1;32m"; Y="\033[1;33m"; R="\033[1;31m"; Z="\033[0m"

mount_main() {
  mkdir -p "$M"
  mountpoint -q "$M" && return 0
  local dev; dev=$(blkid -L "$MAIN_LABEL" 2>/dev/null)
  [ -z "$dev" ] && dev=$(findfs LABEL="$MAIN_LABEL" 2>/dev/null)
  [ -z "$dev" ] && { echo -e "${R}Cannot find main root (LABEL=$MAIN_LABEL)${Z}"; return 1; }
  mount "$dev" "$M" || { echo -e "${R}mount $dev failed${Z}"; return 1; }
}
umount_main() { mountpoint -q "$M" && umount "$M"; }

zeroize_config() {
  echo -e "${Y}Zeroizing configuration and cryptographic material on the main root...${Z}"
  rm -f  "$M"/var/lib/ffn-ngfw/config-v2.db "$M"/var/lib/ffn-ngfw/config.db
  rm -f  "$M"/var/lib/ffn-ngfw/config/running-config.xml "$M"/var/lib/ffn-ngfw/config/candidate-config.xml "$M"/var/lib/ffn-ngfw/config/last-applied.xml
  rm -rf "$M"/var/lib/ffn-ngfw/config/history/* "$M"/var/lib/ffn-ngfw/config/snapshots/* 2>/dev/null
  # zeroize CSPs — regenerated fresh by first-boot
  rm -f  "$M"/etc/ffn-ngfw/master.key "$M"/etc/ffn-ngfw/tls/server.key "$M"/etc/ffn-ngfw/tls/server.crt
  rm -f  "$M"/etc/ffn-ngfw/fips-integrity.manifest "$M"/etc/ffn-ngfw/fips-integrity.key
  rm -f  "$M"/etc/systemd/system/ffn-manager-v2.service.d/20-jwt.conf
  rm -f  "$M"/var/lib/ffn-ngfw/fips-selftest.json
  # restore the factory running-config skeleton if we baked one
  if [ -f "$M"/etc/ffn-ngfw/factory/running-config.xml ]; then
    mkdir -p "$M"/var/lib/ffn-ngfw/config
    cp "$M"/etc/ffn-ngfw/factory/running-config.xml "$M"/var/lib/ffn-ngfw/config/running-config.xml
  fi
  # force first-boot to re-provision (fresh host keys, TLS, secrets, admin/admin)
  rm -f  "$M"/var/lib/ffn-ngfw/.firstboot-done
}

do_enable_fips() {
  mount_main || return 1
  zeroize_config
  echo "enabled" > "$M"/etc/ffn-ngfw/fips-cc.mode
  sync; umount_main
  echo -e "${G}FIPS-CC mode ENABLED. Configuration zeroized. Reboot into normal mode to run the power-on self-tests.${Z}"
}
do_disable_fips() {
  mount_main || return 1
  zeroize_config
  rm -f "$M"/etc/ffn-ngfw/fips-cc.mode
  sync; umount_main
  echo -e "${G}FIPS-CC mode DISABLED. Configuration zeroized.${Z}"
}
do_factory_reset() {
  mount_main || return 1
  zeroize_config              # keeps current FIPS-CC flag
  sync; umount_main
  echo -e "${G}Configuration factory-reset (FIPS-CC mode unchanged).${Z}"
}
do_selftest() {
  mount_main || return 1
  echo -e "${C}Running FIPS-CC self-test against the main root...${Z}"
  for f in proc sys dev; do mount --rbind /$f "$M/$f" 2>/dev/null; done
  chroot "$M" /opt/ffn-ngfw-v2/venv/bin/python3 /opt/ffn-ngfw-v2/ffn_fips_selftest.py 2>&1 | sed 's/^/  /'
  for f in dev sys proc; do umount -lR "$M/$f" 2>/dev/null; done
  umount_main
}
do_status() {
  mount_main || return 1
  local m="disabled"; [ -f "$M"/etc/ffn-ngfw/fips-cc.mode ] && m="ENABLED"
  echo -e "  FIPS-CC mode on main root: ${C}$m${Z}"
  umount_main
}

action() {
  case "$1" in
    enable-fips)   do_enable_fips ;;
    disable-fips)  do_disable_fips ;;
    factory-reset) do_factory_reset ;;
    selftest)      do_selftest ;;
    status)        do_status ;;
    *) echo "unknown action: $1"; return 2 ;;
  esac
}

# non-interactive: kernel cmdline (ffn.recovery.action=) or an explicit arg
CMDACT=$(sed -n 's/.*ffn\.recovery\.action=\([a-z-]*\).*/\1/p' /proc/cmdline 2>/dev/null)
if [ "${1:-}" != "" ]; then action "$1"; exit $?; fi
if [ -n "$CMDACT" ]; then echo -e "${Y}cmdline action: $CMDACT${Z}"; action "$CMDACT"; echo "Rebooting in 5s..."; sleep 5; reboot; fi

# interactive menu
while true; do
  echo -e "\n${C}================ FFN NGFW Recovery / Maintenance ================${Z}"
  do_status 2>/dev/null
  cat <<MENU
  1) Enable FIPS-CC mode         (ZEROIZES config, then reboot)
  2) Disable FIPS-CC mode        (ZEROIZES config)
  3) Factory reset configuration (ZEROIZES config, keep FIPS state)
  4) Run FIPS-CC self-test
  5) Reboot into normal mode
  6) Recovery shell (bash)
MENU
  read -rp "Select [1-6]: " ch
  case "$ch" in
    1) read -rp "Type ZEROIZE to confirm: " a; [ "$a" = ZEROIZE ] && { do_enable_fips; echo "Rebooting..."; sleep 3; reboot; } ;;
    2) read -rp "Type ZEROIZE to confirm: " a; [ "$a" = ZEROIZE ] && { do_disable_fips; echo "Rebooting..."; sleep 3; reboot; } ;;
    3) read -rp "Type ZEROIZE to confirm: " a; [ "$a" = ZEROIZE ] && do_factory_reset ;;
    4) do_selftest ;;
    5) reboot ;;
    6) echo "Type 'exit' to return to the menu."; bash ;;
    *) echo "invalid choice" ;;
  esac
done
