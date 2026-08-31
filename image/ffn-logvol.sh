#!/usr/bin/env bash
# ffn-logvol.sh -- find and mount the chassis's internal log volume.
#
# A PA-5200 ships two internal 2 TB drives as a RAID1 pair carrying PAN-OS's
# 'Log' volume. On a reclaimed box those drives are still there and still
# perfectly good, so FFN uses them for its own logs instead of filling the
# 24 GB system partition.
#
# The array UUID differs on every chassis, so nothing is baked into the image:
# this DISCOVERS the array at boot. Runs once, early, and is designed to be a
# no-op on any box that has no such array.
#
# TWO TRAPS THIS HANDLES
#
#  1. PAN's arrays use md metadata v0.90, which lives near the END of the
#     device. When the member partition spans almost the whole disk, the
#     superblock is visible through BOTH /dev/sdX and /dev/sdX1, and mdadm
#     refuses to choose -- it assembles one member as a spare and leaves the
#     array inactive. Restricting DEVICE to partitions fixes it.
#  2. `mount` refuses a device blkid has typed as linux_raid_member, so the
#     filesystem type is given explicitly when mounting a bare member.
#
# It must never break boot: every failure path exits 0, because a missing log
# disk is not a reason to lose a firewall.
set -uo pipefail

MNT="${FFN_LOG_MNT:-/opt/ffn-logs}"
BIND="${FFN_LOG_BIND:-/var/log/ffn-ngfw}"
CONF=/etc/mdadm/mdadm.conf

log() { echo "[ffn-logvol] $*"; logger -t ffn-logvol "$*" 2>/dev/null || true; }

# Already mounted (e.g. by fstab)? Nothing to do.
if mountpoint -q "$MNT"; then
    log "$MNT already mounted"
    exit 0
fi

command -v mdadm >/dev/null 2>&1 || { log "mdadm absent; skipping"; exit 0; }

# --- trap 1: only ever consider partitions as array members ----------------
mkdir -p "$(dirname "$CONF")"
if ! grep -q '^DEVICE' "$CONF" 2>/dev/null; then
    sed -i '1i DEVICE /dev/sd?1' "$CONF" 2>/dev/null \
        || echo 'DEVICE /dev/sd?1' > "$CONF"
    log "restricted mdadm DEVICE to partitions (v0.90 whole-disk alias)"
fi

# --- find candidate members ------------------------------------------------
members=()
for p in /dev/sd?1; do
    [ -b "$p" ] || continue
    if [ "$(blkid -s TYPE -o value "$p" 2>/dev/null)" = "linux_raid_member" ]; then
        members+=("$p")
    fi
done
if [ "${#members[@]}" -lt 2 ]; then
    log "fewer than two raid members found; nothing to assemble"
    exit 0
fi

# Group by array UUID and take the first complete pair.
declare -A byuuid
for p in "${members[@]}"; do
    u="$(mdadm --examine "$p" 2>/dev/null | awk '/UUID :/{print $3; exit}')"
    [ -n "$u" ] || continue
    byuuid["$u"]="${byuuid[$u]:-} $p"
done

for u in "${!byuuid[@]}"; do
    set -- ${byuuid[$u]}
    [ "$#" -ge 2 ] || continue
    log "assembling array $u from $*"
    # Assemble with both members NAMED -- --scan is what gets confused by the
    # whole-disk alias.
    if ! mdadm --assemble --run /dev/md9 "$@" >/dev/null 2>&1; then
        # Perhaps already assembled under another name; find it.
        dev="$(lsblk -lno NAME,TYPE | awk '$2=="raid1"{print "/dev/"$1; exit}')"
        [ -n "$dev" ] || { log "assemble failed for $u"; continue; }
    else
        dev=/dev/md9
    fi

    # Persist the array so the next boot finds it without us.
    grep -q "$u" "$CONF" 2>/dev/null || \
        echo "ARRAY $dev UUID=$u" >> "$CONF"

    mkdir -p "$MNT"
    if mount "$dev" "$MNT" 2>/dev/null; then
        log "mounted $dev at $MNT"
    else
        log "could not mount $dev; leaving it assembled"
        exit 0
    fi

    # --- lay out FFN's log areas, preserving anything already there --------
    mkdir -p "$MNT/ffn-ngfw" "$MNT/traffic" "$MNT/threat" "$MNT/journal"
    # A PAN log database found here belongs to whoever owned the box before.
    # Move it aside rather than deleting it.
    if [ -d "$MNT/logdb" ] && [ ! -d "$MNT/panos-logdb.preserved" ]; then
        mv -n "$MNT/logdb" "$MNT/panos-logdb.preserved" 2>/dev/null \
            && log "preserved the previous owner's PAN logdb"
    fi

    # --- bind FFN's log directory onto the array --------------------------
    if [ -d "$BIND" ] && ! mountpoint -q "$BIND"; then
        cp -a "$BIND/." "$MNT/ffn-ngfw/" 2>/dev/null || true
        mount --bind "$MNT/ffn-ngfw" "$BIND" 2>/dev/null \
            && log "bound $BIND -> $MNT/ffn-ngfw"
    fi

    df -h "$MNT" | tail -1 | while read -r _ size used _ pct _; do
        log "log volume ready: $size total, $used used ($pct)"
    done
    exit 0
done

log "no complete raid pair assembled"
exit 0
