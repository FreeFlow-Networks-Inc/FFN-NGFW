#!/usr/bin/env bash
# ffn-vendor-autoimport.sh <block-device-name>
#
# Fired by udev when a removable partition appears. Mounts it READ-ONLY, looks
# for vendor firmware belonging to THIS chassis, imports it, and unmounts.
#
# If you own a Palo Alto appliance you own its firmware, and carrying it on a
# USB stick is a perfectly ordinary thing to do. This makes that work: plug the
# stick in and FFN picks the firmware up by itself.
#
# Deliberate limits, because this runs automatically on media we did not write:
#   * mounted ro,nodev,nosuid,noexec -- nothing on the stick can execute
#   * only a partition whose firmware matches THIS chassis is imported; a
#     PA-3200 bitstream on a PA-5200 is refused, not loaded
#   * artifacts must match the vendor's own SHA-256 manifest
#   * a stick with no vendor content is ignored silently, so ordinary USB use
#     is unaffected
#   * loading is separate from importing and is governed by vendor.conf
#
# The manifest proves integrity, not authenticity (see ffn_vendor.py). Set
# autoload=no in /etc/ffn-ngfw/vendor.conf if you want to confirm by hand.
set -uo pipefail

DEV="${1:-}"
[ -n "$DEV" ] || exit 0
NODE="/dev/$DEV"
[ -b "$NODE" ] || exit 0

CONF=/etc/ffn-ngfw/vendor.conf
VENDOR=/opt/ffn-ngfw-v2/ffn_vendor.py
[ -x "$VENDOR" ] || exit 0

get(){ sed -n "s/^$1=//p" "$CONF" 2>/dev/null | tail -1; }
AUTOIMPORT="$(get autoimport)"; AUTOIMPORT="${AUTOIMPORT:-yes}"
AUTOLOAD="$(get autoload)";     AUTOLOAD="${AUTOLOAD:-yes}"
[ "$AUTOIMPORT" = "yes" ] || exit 0

log(){ logger -t ffn-vendor-auto "$*"; echo "$*"; }

MNT="/run/ffn-vendor/$DEV"
mkdir -p "$MNT"
cleanup(){ umount "$MNT" 2>/dev/null; rmdir "$MNT" 2>/dev/null; }
trap cleanup EXIT

# ext filesystems that were not cleanly unmounted refuse a read-only mount
# unless the journal replay is skipped; try plain ro first, then ro,noload.
if ! mount -o ro,nodev,nosuid,noexec "$NODE" "$MNT" 2>/dev/null; then
  mount -o ro,noload,nodev,nosuid,noexec "$NODE" "$MNT" 2>/dev/null || exit 0
fi

# Quietly ignore ordinary media: only speak up if there is vendor content.
if ! python3 "$VENDOR" scan --source "$MNT" >/tmp/ffn-vendor-scan.$$ 2>&1; then
  rm -f /tmp/ffn-vendor-scan.$$
  exit 0
fi

log "vendor firmware detected on $DEV"
sed 's/^/  /' /tmp/ffn-vendor-scan.$$ | logger -t ffn-vendor-auto
rm -f /tmp/ffn-vendor-scan.$$

if python3 "$VENDOR" import --source "$MNT" 2>&1 | logger -t ffn-vendor-auto; then
  log "imported firmware from $DEV"
  if [ "$AUTOLOAD" = "yes" ]; then
    python3 "$VENDOR" load 2>&1 | logger -t ffn-vendor-auto
  else
    log "autoload=no -- staged only; run 'ffn_vendor.py load' to apply"
  fi
else
  log "import refused for $DEV (platform mismatch or failed integrity check)"
fi
