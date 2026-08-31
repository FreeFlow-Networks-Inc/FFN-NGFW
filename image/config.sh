#!/usr/bin/env bash
# FFN NGFW reproducible appliance image — build configuration.
# Sourced by build.sh (host) and provision.sh (chroot).

set -euo pipefail

# --- target OS ---
export FFN_RELEASE="jammy"          # Ubuntu 22.04 LTS (matches the dev box)
export FFN_ARCH="amd64"
export FFN_MIRROR="http://archive.ubuntu.com/ubuntu"
export FFN_HOSTNAME="ffn-ngfw"
export FFN_KERNEL_META="linux-generic-hwe-22.04"   # 6.8 HWE kernel like the box

# --- versions of custom deps (pinned = reproducible) ---
export DPDK_VER="22.11.4"                                  # 22.11 LTS; FFN links librte_*.so.23
export DPDK_URL="https://fast.dpdk.org/rel/dpdk-${DPDK_VER}.tar.xz"
export DPDK_PREFIX="/opt/dpdk-22.11"
export FLATCC_GIT="https://github.com/dvidelabs/flatcc.git"
export FLATCC_REF="v0.6.1"
export FLATCC_PREFIX="/opt/flatcc"

# --- image geometry ---
export IMG_SIZE_GB="${IMG_SIZE_GB:-32}"             # qcow2/raw virtual size (thin; two roots: main + recovery)
export IMG_LABEL_ROOT="ffn-root"
export IMG_LABEL_RECOVERY="ffn-recovery"
export IMG_P1_END="${IMG_P1_END:-24GiB}"            # main root partition end; recovery = 9GiB..100%

# --- build/output locations (on the build host) ---
# Overridable so the build can run on a disk with room (e.g. an attached
# volume) instead of a small root filesystem:
#     BUILD_ROOT=/mnt/clones/ffn-build sudo -E ./build.sh
export BUILD_ROOT="${BUILD_ROOT:-/root/ffn-image-build}"
export ROOTFS="${BUILD_ROOT}/rootfs"
export PAYLOAD="${BUILD_ROOT}/payload"      # FFN tarballs staged here
export OUT="${BUILD_ROOT}/out"              # final artifacts land here

# --- appliance package set (LEAN — no desktop/cups/fonts, unlike the dev box) ---
# base system + admin tooling
export PKGS_BASE="systemd-sysv init dbus udev kmod netplan.io iproute2 iputils-ping \
isc-dhcp-client openssh-server ca-certificates curl wget gnupg sudo less nano vim-tiny \
bash-completion htop jq sqlite3 pciutils usbutils ethtool lldpd locales tzdata cron \
libpam-systemd rsync cloud-guest-utils openssl"
# firewall + routing dataplane deps (runtime)
# mdadm brings up the chassis log RAID (see ffn-logvol.sh). Without it a
# reclaimed PA-5200's two internal 2TB log drives stay invisible and FFN
# fills the 24GB system partition instead.
export PKGS_STORAGE="mdadm"

export PKGS_NET="nftables iptables ipset conntrack bridge-utils ifenslave frr frr-pythontools \
libnetfilter-queue1 libnfnetlink0 libhyperscan5 libnuma1 libpcap0.8 libbpf0 libmnl0 \
# nfs-kernel-server: the OCTEON planes NFS-root from the MP SSD over PCIC,
# which is what makes the control plane editable in place.
nfs-kernel-server nfs-common"
# build deps (DPDK/flatcc/venv wheels + FFN C components); kept so runtime HS/pattern compile works
export PKGS_BUILD="build-essential meson ninja-build cmake git pkg-config python3-pyelftools \
libnuma-dev libpcap-dev libbpf-dev libelf-dev libssl-dev libmnl-dev \
libnetfilter-queue-dev libnfnetlink-dev libhyperscan-dev zlib1g-dev"
# python management plane
export PKGS_PY="python3 python3-venv python3-dev python3-pip"
# boot
export PKGS_BOOT="${FFN_KERNEL_META} initramfs-tools grub-pc-bin grub-common"

# --- SAFE default kernel cmdline (generic; ffn-hwtune tunes per-CPU on first boot) ---
# NOTE: the dev box uses isolcpus=12-47 hugepages=2048 for a 48-thread Xeon. That is
# hardware-specific and would break a smaller CPU, so the image ships a conservative
# default and ffn-hwtune.sh recomputes it on first boot from the actual core count.
export GRUB_CMDLINE_DEFAULT="intel_iommu=on iommu=pt default_hugepagesz=2M hugepagesz=2M hugepages=512 transparent_hugepage=never"

# --- admin gateway (mirrors what we wired on the live box) ---
export FFN_CLI="/usr/local/bin/ffn-cli"
export ADMIN_USER="admin"

# --- serial console baud ---------------------------------------------------
# 115200 is the sane default for generic x86 and QEMU. Palo Alto appliances
# (PA-3200/PA-5200 and friends) run their console at 9600 8N1 and their BIOS
# serial redirection is configured to match, so an image built at 115200 emits
# garbage on that hardware and looks like a failure to boot when it is only a
# baud mismatch. Build a 9600 image for those chassis:
#     FFN_SERIAL_BAUD=9600 sudo -E ./build.sh
export FFN_SERIAL_BAUD="${FFN_SERIAL_BAUD:-115200}"

# --- console / SSH access -------------------------------------------------
# The image used to ship with no root password and no authorized_keys, which
# made local login impossible (admin/admin is the WebUI account, not a Unix
# one). Set at build time:
#     FFN_ROOT_PW='...' FFN_SSH_PUBKEY="$(cat ~/.ssh/id_ed25519.pub)" ./build.sh
# Leaving FFN_ROOT_PW empty keeps the accounts locked (previous behaviour).
export FFN_ROOT_PW="${FFN_ROOT_PW:-}"
export FFN_SSH_PUBKEY="${FFN_SSH_PUBKEY:-}"

# --- FFN payload updater ------------------------------------------------------
# Where appliances built from this image look for signed updates. The image
# carries only the ed25519 PUBLIC key (staged from /etc/ffn-ngfw/update-sign.pub);
# the private seed stays on this build server and is never packaged.
FFN_UPDATE_URL="${FFN_UPDATE_URL:-https://10.1.0.106:8444}"

# --- model profile -------------------------------------------------------------
# A profile (profiles/<model>.conf) is sourced LAST so its values win over the
# generic defaults above. set -a exports everything it defines, so provision.sh
# (which sources this file inside the chroot) sees the model's knobs too.
if [ -n "${FFN_PROFILE:-}" ] && [ -f "${FFN_PROFILE}" ]; then
  set -a; . "${FFN_PROFILE}"; set +a
  echo "[config] model profile: ${FFN_MODEL:-?} (${FFN_PROFILE})"
fi

# ---- image partition scheme ------------------------------------------------
# hybrid (default) = GPT with a bios_grub partition AND an ESP, so one image
#                    boots on UEFI and on legacy BIOS.
# mbr              = the old MBR layout, for firmware too old to read GPT.
: "${IMG_SCHEME:=hybrid}"
: "${IMG_ESP_MB:=512}"
