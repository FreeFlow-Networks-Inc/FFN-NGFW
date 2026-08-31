#!/usr/bin/env bash
# FFN NGFW reproducible appliance image builder. Run as root ON a jammy amd64 host.
# Produces: out/<ver>-rootfs.tar.zst + <ver>-recovery.tar.zst + install-to-disk.sh (bare metal),
# and out/<ver>.qcow2 (VM) — a 2-partition image: main root + recovery/maintenance partition.
set -euo pipefail
HERE="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
source "$HERE/config.sh"
mkdir -p "$BUILD_ROOT" "$OUT"
LOG="$BUILD_ROOT/build.log"; exec > >(tee -a "$LOG") 2>&1
VERSION="ffn-ngfw-$(date -u +%Y%m%d-%H%M)"
FFN_RESUME="${FFN_RESUME:-0}"     # reuse existing rootfs + external sources (skip debootstrap/DPDK download)
unset RESUME 2>/dev/null || true  # avoid leaking into initramfs-tools' RESUME (hibernation) var
RECOVERY="$BUILD_ROOT/recovery"
stage(){ echo -e "\n\033[1;35m========== $* ==========\033[0m"; }

# --- SAFETY: never rm a tree while /dev/proc/sys are bind-mounted under it. ---
mounts_under(){ mount | grep -F "$1" | wc -l; }
safe_umount_tree(){ local d="$1" i m; [ -e "$d" ] || return 0
  for i in 1 2 3 4 5; do
    [ "$(mounts_under "$d")" = 0 ] && return 0
    mount | awk '{print $3}' | grep -F "$d" | awk '{print length, $0}' | sort -rn | cut -d' ' -f2- \
      | while read -r m; do umount -l "$m" 2>/dev/null; done
    sleep 1
  done
  [ "$(mounts_under "$d")" = 0 ]; }
safe_wipe(){ local d="$1"; [ -d "$d" ] || return 0
  if ! safe_umount_tree "$d"; then echo "FATAL: mounts remain under $d — refusing rm:"; mount | grep -F "$d"; exit 1; fi
  rm --one-file-system -rf "$d"; }

cleanup(){ set +e; safe_umount_tree "$ROOTFS"; [ -n "${MNT:-}" ] && safe_umount_tree "$MNT"; [ -n "${MNT2:-}" ] && safe_umount_tree "$MNT2"
  [ -n "${LOOP:-}" ] && losetup -d "$LOOP" 2>/dev/null; [ -n "${MNT:-}" ] && rmdir "$MNT" 2>/dev/null; [ -n "${MNT2:-}" ] && rmdir "$MNT2" 2>/dev/null; }
trap cleanup EXIT

# ---------------------------------------------------------------- 0. host tooling
stage "0. host build tooling"
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends debootstrap qemu-utils grub-pc-bin grub2-common \
  parted dosfstools e2fsprogs xz-utils zstd wget ca-certificates rsync git cloud-guest-utils

# ---------------------------------------------------------------- 1. payload
stage "1. assemble payload"
mkdir -p "$PAYLOAD/units"
# FFN code + units + scripts.
# Normally harvested from a LIVE FFN box (/opt/ffn-ngfw-v2, /etc/ffn-ngfw, units).
# FFN_PRESEED=1 instead uses a payload staged ahead of time, so the image can be
# built on any Linux host without the appliance being up:
#     FFN_PRESEED=1 BUILD_ROOT=/mnt/clones/ffn-build sudo -E ./build.sh
if [ "${FFN_PRESEED:-0}" = 1 ]; then
  echo "PRESEED: using pre-staged payload in $PAYLOAD (no live box harvest)"
  miss=0
  for f in opt-ffn-ngfw-v2.tgz opt-ffn-ngfw-v1.tgz etc-ffn-ngfw.tgz varlib-seed.tgz ffn-cli; do
    if [ ! -s "$PAYLOAD/$f" ]; then echo "  MISSING $PAYLOAD/$f"; miss=1; fi
  done
  if [ ! -d "$PAYLOAD/units" ] || [ -z "$(ls -A "$PAYLOAD/units" 2>/dev/null)" ]; then
    echo "  MISSING $PAYLOAD/units/*.service"; miss=1
  fi
  [ "$miss" = 1 ] && { echo "PRESEED payload incomplete — aborting"; exit 1; }
  ls -la "$PAYLOAD" | sed "s/^/    /"
else
# FFN code + units + scripts — ALWAYS refreshed (cheap, and this is what changes between runs)
  tar czf "$PAYLOAD/opt-ffn-ngfw-v2.tgz" -C /opt --exclude=venv --exclude=__pycache__ --exclude='*.pyc' ffn-ngfw-v2
  tar czf "$PAYLOAD/opt-ffn-ngfw-v1.tgz" -C /opt --exclude=venv --exclude=__pycache__ --exclude='*.pyc' ffn-ngfw
  cp /usr/local/bin/ffn-cli "$PAYLOAD/ffn-cli"
  tar czf "$PAYLOAD/etc-ffn-ngfw.tgz" -C /etc --exclude='*.key' --exclude=master.key --exclude='ffn-ngfw/tls' ffn-ngfw

  # The updater's PUBLIC key ships in the image; the private seed must not.
  # FFN is handed to strangers, so an image that carried signing material would
  # let anyone holding one mint updates for every other appliance.
  if [ -s /etc/ffn-ngfw/update-sign.pub ]; then
    cp /etc/ffn-ngfw/update-sign.pub "$PAYLOAD/update.pub"
    echo "  update.pub staged ($(cat /etc/ffn-ngfw/update-sign.pub))"
  else
    echo "  WARNING: no /etc/ffn-ngfw/update-sign.pub — the image will not be able"
    echo "           to verify updates. Generate one with:"
    echo "           ffn_ed25519.py --keygen /etc/ffn-ngfw/update-sign"
  fi

  # Hard stop: never let signing material into a distributed payload.
  if tar tzf "$PAYLOAD/etc-ffn-ngfw.tgz" | grep -Eq '(update-sign\.key|update\.key|master\.key|\.pem$)'; then
    echo "ABORT: private key material found in etc-ffn-ngfw.tgz"
    tar tzf "$PAYLOAD/etc-ffn-ngfw.tgz" | grep -E '(update-sign\.key|update\.key|master\.key|\.pem$)' | sed 's/^/    /'
    exit 1
  fi
  if tar tzf "$PAYLOAD/opt-ffn-ngfw-v2.tgz" | grep -Eq 'update-sign\.key'; then
    echo "ABORT: signing seed found in opt-ffn-ngfw-v2.tgz"; exit 1
  fi

  # A menu item that goes nowhere, or a button calling a function nobody
  # defined, throws only when a user presses it -- so it survives every
  # page-load test. Vendor product names presented as FFN features are
  # caught here too.
  if [ -x /opt/ffn-ngfw-v2/ffn_uiaudit.py ]; then
    echo "  auditing WebUI for dead ends and vendor naming..."
    if ! python3 /opt/ffn-ngfw-v2/ffn_uiaudit.py /opt/ffn-ngfw-v2/static/index.html; then
      echo "ABORT: WebUI audit found actionable problems"
      exit 1
    fi
  fi

  # The WebUI is one big inline script: a syntax error blanks the entire UI and
  # is invisible in the served HTML. Refuse to build an image with a broken one.
  if [ -x /opt/ffn-ngfw-v2/ffn_jscheck.py ]; then
    echo "  checking WebUI JavaScript..."
    if ! python3 /opt/ffn-ngfw-v2/ffn_jscheck.py /opt/ffn-ngfw-v2/static/index.html; then
      echo "ABORT: WebUI JavaScript has structural errors — fix before building"
      exit 1
    fi
  fi
  # NOTE: config-v2.db holds the WebUI USER TABLE (admin password hash). Shipping the
# build host's copy would give every reclaimed appliance the same known credential,
# so it is excluded explicitly (the directory pattern alone does NOT match the file).
tar czf "$PAYLOAD/varlib-seed.tgz" -C /var/lib \
    --exclude='ffn-ngfw/security.db' --exclude='ffn-ngfw/config/history/*' \
    --exclude='ffn-ngfw/config/snapshots/*' --exclude='ffn-ngfw/config-v2' --exclude='ffn-ngfw/config-v2.db' \
    --exclude='ffn-ngfw/config-v2.db-wal' --exclude='ffn-ngfw/config-v2.db-shm' --exclude='ffn-ngfw/vendor' --exclude='ffn-ngfw/vendor/*' ffn-ngfw
  # Stage the log-volume discovery service. provision.sh looks for these in
  # /payload, so without this step the chassis log RAID is never picked up
  # and FFN quietly fills the 24GB system partition instead.
  for f in ffn-logvol.sh ffn-logvol.service; do
    [ -f "$HERE/$f" ] && cp "$HERE/$f" "$PAYLOAD/$f"
  done

  # Stage the vendor-autodetect MECHANISM (not any firmware).
  for f in 99-ffn-vendor.rules ffn-vendor-autoimport@.service vendor.conf; do
    [ -f "$HERE/$f" ] && cp "$HERE/$f" "$PAYLOAD/$f"
  done

  # Vendor firmware belongs to the owner of the box it came from. It may be
  # used in place there; packaging it would be redistributing it.
  if [ -x /opt/ffn-ngfw-v2/ffn_vendor.py ]; then
    for t in "$PAYLOAD"/varlib-seed.tgz "$PAYLOAD"/opt-ffn-ngfw-v2.tgz "$PAYLOAD"/etc-ffn-ngfw.tgz; do
      [ -f "$t" ] || continue
      if ! python3 /opt/ffn-ngfw-v2/ffn_vendor.py check-clean "$t"; then
        echo "ABORT: vendor firmware in $t -- it must not be packaged"
        exit 1
      fi
    done
  fi

  rm -rf "$PAYLOAD/units"; mkdir -p "$PAYLOAD/units"
  for u in ffn-manager-v2 ffn-configd ffn-controld ffn-dpdk-fwd ffn-bmfw ffn-sysd ffn-satd ffn-watchdogd; do
    for base in /etc/systemd/system /lib/systemd/system; do
      [ -f "$base/$u.service" ] && cp "$base/$u.service" "$PAYLOAD/units/"
      [ -d "$base/$u.service.d" ] && cp -a "$base/$u.service.d" "$PAYLOAD/units/"
    done
  done
  for t in ffn-license-monitor.timer ffn-sigdb-update.timer ffn-license-monitor.service ffn-sigdb-update.service ffn-license-fetch.service; do
    for base in /etc/systemd/system /lib/systemd/system; do [ -f "$base/$t" ] && cp "$base/$t" "$PAYLOAD/units/"; done
  done
fi
cp "$HERE/config.sh" "$HERE/provision.sh" "$HERE/ffn-firstboot.sh" "$HERE/ffn-hwtune.sh" \
   "$HERE/ffn-selftest.sh" "$HERE/ffn-firstboot.service" "$HERE/ffn-selftest.service" \
   "$HERE/ffn-fips-selftest.service" "$HERE/ffn-recovery-menu.sh" "$HERE/ffn-recovery-menu.service" \
   "$HERE/requirements-v1.frozen" "$HERE/requirements-v2.frozen" "$PAYLOAD/"
# pinned external sources — slow; skip on resume
if [ "$FFN_RESUME" = 1 ] && [ -f "$PAYLOAD/dpdk-src.tar.xz" ] && [ -f "$PAYLOAD/flatcc-src.tar.gz" ]; then
  echo "RESUME: reusing DPDK + flatcc sources"
else
  echo "downloading DPDK ${DPDK_VER}..."; wget -qO "$PAYLOAD/dpdk-src.tar.xz" "$DPDK_URL"
  rm -rf "$BUILD_ROOT/flatcc-src"; git clone --quiet --depth 1 --branch "$FLATCC_REF" "$FLATCC_GIT" "$BUILD_ROOT/flatcc-src"
  tar czf "$PAYLOAD/flatcc-src.tar.gz" -C "$BUILD_ROOT" flatcc-src; rm -rf "$BUILD_ROOT/flatcc-src"
  wget -qO- 'https://raw.githubusercontent.com/zerotier/ZeroTierOne/master/doc/contact%40zerotier.com.gpg' 2>/dev/null | gpg --dearmor > "$PAYLOAD/zerotier.gpg" 2>/dev/null || rm -f "$PAYLOAD/zerotier.gpg"
fi
echo "payload size: $(du -sh "$PAYLOAD" | cut -f1)"

# ---------------------------------------------------------------- 2. debootstrap
stage "2. debootstrap ${FFN_RELEASE}/${FFN_ARCH}"
if [ "$FFN_RESUME" = 1 ] && [ -x "$ROOTFS/usr/bin/apt-get" ]; then
  echo "RESUME: reusing existing rootfs at $ROOTFS (skipping debootstrap)"
else
  safe_wipe "$ROOTFS"; mkdir -p "$ROOTFS"
  debootstrap --arch="$FFN_ARCH" --variant=minbase \
    --include=systemd-sysv,apt-utils,ca-certificates,gnupg,locales "$FFN_RELEASE" "$ROOTFS" "$FFN_MIRROR"
fi

# ---------------------------------------------------------------- 3. chroot provision (main root)
stage "3. chroot provision (main root)"
rm -f "$ROOTFS/etc/resolv.conf"; cat /etc/resolv.conf > "$ROOTFS/etc/resolv.conf"
cp "$HERE/config.sh" "$ROOTFS/config.sh"
cp "$HERE/provision.sh" "$ROOTFS/provision.sh"; chmod +x "$ROOTFS/provision.sh"
# The model profile has to exist INSIDE the chroot too: provision.sh sources
# /config.sh, which re-sources $FFN_PROFILE, and a host path is meaningless there.
if [ -n "${FFN_PROFILE:-}" ] && [ -f "${FFN_PROFILE}" ]; then
  cp "$FFN_PROFILE" "$ROOTFS/profile.conf"

  # A profile may ship its own factory running-config alongside it. Without
  # this, the factory default is whatever the /etc + /var/lib harvest picked
  # up off the BUILD HOST: its hostname, its NIC names, its IP addresses.
  FACTORY_XML="${FFN_PROFILE%.conf}.running-config.xml"
  if [ -f "$FACTORY_XML" ]; then
    cp "$FACTORY_XML" "$ROOTFS/factory-running-config.xml"
    echo "  model factory config staged: $(basename "$FACTORY_XML")"
  fi
  export FFN_PROFILE=/profile.conf
  echo "  model profile staged: ${FFN_MODEL:-?}"
fi
mkdir -p "$ROOTFS/payload"; cp -a "$PAYLOAD/." "$ROOTFS/payload/"
mount -t proc proc "$ROOTFS/proc"; mount -t sysfs sys "$ROOTFS/sys"; mount --rbind /dev "$ROOTFS/dev"
chroot "$ROOTFS" /provision.sh
safe_umount_tree "$ROOTFS"
rm -f "$ROOTFS/config.sh" "$ROOTFS/provision.sh" "$ROOTFS/profile.conf" "$ROOTFS/factory-running-config.xml"; rm -rf "$ROOTFS/payload"
rm -f "$ROOTFS/etc/resolv.conf"; ln -sf /run/systemd/resolve/stub-resolv.conf "$ROOTFS/etc/resolv.conf" 2>/dev/null || true

# ---------------------------------------------------------------- 3.5 recovery rootfs
stage "3.5 build recovery / maintenance rootfs"
safe_wipe "$RECOVERY"; mkdir -p "$RECOVERY"
rsync -aHAX --numeric-ids "$ROOTFS"/ "$RECOVERY"/
# recovery runs NO firewall stack — mask everything but the maintenance menu (mask = symlink to /dev/null)
for u in ffn-configd ffn-controld ffn-manager-v2 ffn-bmfw ffn-dpdk-fwd ffn-fips-selftest \
         ffn-firstboot ffn-selftest frr zerotier-one ssh ffn-license-monitor.timer ffn-sigdb-update.timer; do
  ln -sf /dev/null "$RECOVERY/etc/systemd/system/$u"
  case "$u" in *.timer) : ;; *) ln -sf /dev/null "$RECOVERY/etc/systemd/system/$u.service" 2>/dev/null || true ;; esac
done
# enable the recovery menu on the console
mkdir -p "$RECOVERY/etc/systemd/system/multi-user.target.wants"
ln -sf /etc/systemd/system/ffn-recovery-menu.service "$RECOVERY/etc/systemd/system/multi-user.target.wants/ffn-recovery-menu.service"
printf 'LABEL=%s / ext4 errors=remount-ro 0 1\n' "$IMG_LABEL_RECOVERY" > "$RECOVERY/etc/fstab"
echo "ffn-ngfw-recovery" > "$RECOVERY/etc/hostname"

# ---------------------------------------------------------------- 4. bare-metal artifacts
stage "4. package bare-metal rootfs tarballs"
tar --numeric-owner --xattrs -C "$ROOTFS"   -cf - . | zstd -T0 -12 -o "$OUT/$VERSION-rootfs.tar.zst" -f
tar --numeric-owner --xattrs -C "$RECOVERY" -cf - . | zstd -T0 -12 -o "$OUT/$VERSION-recovery.tar.zst" -f
cp "$HERE/install-to-disk.sh" "$OUT/"; chmod +x "$OUT/install-to-disk.sh"

# ---------------------------------------------------------------- 5. qcow2 (2 partitions)
stage "5. build bootable qcow2 (main + recovery partitions)"
RAW="$BUILD_ROOT/$VERSION.raw"
modprobe loop 2>/dev/null || true
[ -e /dev/loop-control ] || mknod -m660 /dev/loop-control c 10 237 2>/dev/null || true
for i in 0 1 2 3 4 5 6 7; do [ -e "/dev/loop$i" ] || mknod -m660 "/dev/loop$i" b 7 "$i" 2>/dev/null || true; done
qemu-img create -f raw "$RAW" "${IMG_SIZE_GB}G"

# IMG_SCHEME=hybrid (default) lays down GPT with BOTH a bios_grub partition and
# an ESP, so one image boots on UEFI and on legacy BIOS. The old MBR-only layout
# could not boot UEFI-only firmware at all. IMG_SCHEME=mbr is kept for firmware
# too old to read GPT.
IMG_SCHEME="${IMG_SCHEME:-hybrid}"
IMG_ESP_MB="${IMG_ESP_MB:-512}"

case "$IMG_SCHEME" in
hybrid)
  ESP_END=$(( 2 + IMG_ESP_MB ))
  parted -s "$RAW" mklabel gpt
  # 1 MiB unformatted, for GRUB's core image: GPT has no post-MBR gap to embed
  # it in, and grub-install i386-pc fails without this.
  parted -s "$RAW" mkpart bios_grub 1MiB 2MiB
  parted -s "$RAW" set 1 bios_grub on
  parted -s "$RAW" mkpart ESP fat32 2MiB "${ESP_END}MiB"
  parted -s "$RAW" set 2 esp on
  parted -s "$RAW" mkpart "$IMG_LABEL_ROOT"     ext4 "${ESP_END}MiB" "$IMG_P1_END"
  parted -s "$RAW" mkpart "$IMG_LABEL_RECOVERY" ext4 "$IMG_P1_END" 100%
  P_ESP=2; P_ROOT=3; P_REC=4
  ;;
mbr)
  parted -s "$RAW" mklabel msdos
  parted -s "$RAW" mkpart primary ext4 1MiB "$IMG_P1_END"
  parted -s "$RAW" mkpart primary ext4 "$IMG_P1_END" 100%
  parted -s "$RAW" set 1 boot on
  P_ESP=0; P_ROOT=1; P_REC=2
  ;;
*) echo "IMG_SCHEME must be hybrid or mbr (got: $IMG_SCHEME)" >&2; exit 1 ;;
esac

LOOP=$(losetup --find --show --partscan "$RAW")
[ "$P_ESP" != 0 ] && mkfs.vfat -F 32 -n FFNESP "${LOOP}p${P_ESP}" >/dev/null
mkfs.ext4 -q -L "$IMG_LABEL_ROOT"     "${LOOP}p${P_ROOT}"
mkfs.ext4 -q -L "$IMG_LABEL_RECOVERY" "${LOOP}p${P_REC}"
MNT=$(mktemp -d); MNT2=$(mktemp -d)
mount "${LOOP}p${P_ROOT}" "$MNT";  tar -C "$ROOTFS"   -cf - . | tar --xattrs -C "$MNT"  -xf -
mount "${LOOP}p${P_REC}"  "$MNT2"; tar -C "$RECOVERY" -cf - . | tar --xattrs -C "$MNT2" -xf -
# GRUB on the main partition, with a manual recovery menu entry (root=partition 2)
KVER=$(ls "$MNT/boot"/vmlinuz-* 2>/dev/null | sed 's#.*/vmlinuz-##' | sort | tail -1)
cat > "$MNT/etc/grub.d/40_custom" <<EOF
#!/bin/sh
exec tail -n +3 \$0
menuentry 'FFN NGFW Recovery / Maintenance' --class ffn {
  search --no-floppy --label $IMG_LABEL_RECOVERY --set root
  linux /boot/vmlinuz-$KVER root=LABEL=$IMG_LABEL_RECOVERY ro console=tty0 console=ttyS0,${FFN_SERIAL_BAUD}n8
  initrd /boot/initrd.img-$KVER
}
EOF
chmod +x "$MNT/etc/grub.d/40_custom"
echo "GRUB_DISABLE_OS_PROBER=true" >> "$MNT/etc/default/grub"
mount -t proc proc "$MNT/proc"; mount -t sysfs sys "$MNT/sys"; mount --rbind /dev "$MNT/dev"
# Install GRUB for every firmware this image may land on. part_gpt and
# search_label are in the module list because the recovery entry now finds its
# partition by label rather than by a hardcoded (hd0,msdosN).
GRUB_MODS="part_gpt part_msdos ext2 biosdisk search search_label"
grub-install --target=i386-pc --boot-directory="$MNT/boot" --modules="$GRUB_MODS" "$LOOP"
if [ "$P_ESP" != 0 ]; then
  mkdir -p "$MNT/boot/efi"
  mount "${LOOP}p${P_ESP}" "$MNT/boot/efi"
  # --removable writes EFI/BOOT/BOOTX64.EFI rather than an NVRAM entry, which is
  # the only thing that works for an image: there is no firmware present at
  # build time to register a boot entry with.
  chroot "$MNT" grub-install --target=x86_64-efi --efi-directory=/boot/efi \
      --bootloader-id=FFN --removable --recheck
  echo "LABEL=FFNESP  /boot/efi  vfat  umask=0077  0 1" >> "$MNT/etc/fstab"
  umount "$MNT/boot/efi"
fi
chroot "$MNT" grub-mkconfig -o /boot/grub/grub.cfg
safe_umount_tree "$MNT"; safe_umount_tree "$MNT2"
rmdir "$MNT" "$MNT2"; MNT=""; MNT2=""
losetup -d "$LOOP"; LOOP=""
qemu-img convert -f raw -O qcow2 -c "$RAW" "$OUT/$VERSION.qcow2"
rm -f "$RAW"

# ---------------------------------------------------------------- 6. manifest
stage "6. checksums + manifest"
( cd "$OUT" && sha256sum "$VERSION"* install-to-disk.sh > SHA256SUMS.txt )
echo "$VERSION" > "$OUT/VERSION"
ls -la "$OUT"
echo -e "\n\033[1;32mBUILD COMPLETE: $VERSION\033[0m"
echo "  bare-metal: $OUT/$VERSION-rootfs.tar.zst + $VERSION-recovery.tar.zst + install-to-disk.sh"
echo "  vm image  : $OUT/$VERSION.qcow2  (main + recovery partitions)"
