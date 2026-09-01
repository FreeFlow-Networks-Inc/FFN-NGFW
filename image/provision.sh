#!/usr/bin/env bash
# Runs INSIDE the chroot (called by build.sh). Turns a bare debootstrap rootfs
# into the FFN NGFW appliance: deps, custom builds, FFN install, services.
set -euo pipefail
source /config.sh
export DEBIAN_FRONTEND=noninteractive
log(){ echo -e "\n\033[1;36m[provision] $*\033[0m"; }

log "hostname / locale / timezone"
echo "$FFN_HOSTNAME" > /etc/hostname
printf '127.0.0.1\tlocalhost\n127.0.1.1\t%s\n' "$FFN_HOSTNAME" > /etc/hosts
ln -sf /usr/share/zoneinfo/UTC /etc/localtime
sed -i 's/# en_US.UTF-8/en_US.UTF-8/' /etc/locale.gen || true
locale-gen en_US.UTF-8 || true

log "apt sources (main/universe/multiverse + updates + security)"
cat > /etc/apt/sources.list <<EOF
deb ${FFN_MIRROR} ${FFN_RELEASE} main universe multiverse restricted
deb ${FFN_MIRROR} ${FFN_RELEASE}-updates main universe multiverse restricted
deb ${FFN_MIRROR} ${FFN_RELEASE}-security main universe multiverse restricted
EOF
apt-get update

log "install base + net + python + build + boot packages"
apt-get install -y --no-install-recommends $PKGS_BASE
apt-get install -y --no-install-recommends $PKGS_NET
apt-get install -y --no-install-recommends $PKGS_STORAGE
apt-get install -y --no-install-recommends $PKGS_PY
apt-get install -y --no-install-recommends $PKGS_BUILD
apt-get install -y $PKGS_BOOT     # kernel/grub: allow recommends (firmware etc.)

log "ZeroTier (official repo)"
if [ -f /payload/zerotier.gpg ]; then
  install -m644 /payload/zerotier.gpg /usr/share/keyrings/zerotier.gpg
  echo "deb [signed-by=/usr/share/keyrings/zerotier.gpg] https://download.zerotier.com/debian/${FFN_RELEASE} ${FFN_RELEASE} main" \
    > /etc/apt/sources.list.d/zerotier.list
  apt-get update && apt-get install -y zerotier-one || echo "WARN: zerotier install failed (non-fatal)"
else
  echo "WARN: no zerotier key in payload; skipping (install later)"
fi

log "build DPDK ${DPDK_VER} -> ${DPDK_PREFIX} (af_xdp vdev, lean driver set)"
if [ -e "${DPDK_PREFIX}/lib/x86_64-linux-gnu/librte_eal.so.23" ]; then
  echo "DPDK already present -> skipping build (idempotent resume)"
else
  cd /tmp && rm -rf dpdk-* && tar xf /payload/dpdk-src.tar.xz && cd dpdk-*/
  meson setup build --prefix="${DPDK_PREFIX}" -Dplatform=generic \
    -Denable_drivers='net/af_xdp,net/ring,net/null' \
    -Dtests=false -Denable_kmods=false -Dexamples='' -Ddisable_libs=''
  ninja -C build
  ninja -C build install
  cd / && rm -rf /tmp/dpdk-*
fi
echo "${DPDK_PREFIX}/lib/x86_64-linux-gnu" > /etc/ld.so.conf.d/dpdk.conf
ldconfig

log "build flatcc ${FLATCC_REF} -> ${FLATCC_PREFIX} (build-time dep; non-fatal)"
if [ -e "${FLATCC_PREFIX}/bin/flatcc" ]; then
  echo "flatcc already present -> skipping"
elif [ -f /payload/flatcc-src.tar.gz ]; then
  ( set -e
    cd /tmp && rm -rf flatcc-src && tar xf /payload/flatcc-src.tar.gz && cd flatcc-src
    cmake -S . -B build -DFLATCC_TEST=off >/dev/null
    cmake --build build -j"$(nproc)" >/dev/null
    mkdir -p "${FLATCC_PREFIX}"
    # flatcc emits artifacts in-tree (./bin ./lib) with headers in ./include — no `install` target
    for d in bin lib include; do [ -d "$d" ] && cp -a "$d" "${FLATCC_PREFIX}/"; done
    cd / && rm -rf /tmp/flatcc-src
  ) || echo "WARN: flatcc build failed (non-fatal — runtime uses pre-generated wire code)"
else
  echo "WARN: no flatcc source in payload; skipping"
fi

log "install FFN code from payload"
tar xzf /payload/opt-ffn-ngfw-v2.tgz -C /opt
tar xzf /payload/opt-ffn-ngfw-v1.tgz -C /opt 2>/dev/null || true
install -m755 /payload/ffn-cli /usr/local/bin/ffn-cli
tar xzf /payload/etc-ffn-ngfw.tgz -C /etc

# --- FFN payload updater: public verification key only ------------------------
# The build server keeps the ed25519 private seed. Shipping only the public key
# means a copy of this image can verify updates but can never forge one, which
# is what makes FFN safe to hand to someone else with their reclaimed hardware.
mkdir -p /etc/ffn-ngfw
if [ -s /payload/update.pub ]; then
  install -m644 /payload/update.pub /etc/ffn-ngfw/update.pub
  echo "  update verification key installed: $(cat /etc/ffn-ngfw/update.pub)"
else
  echo "  NOTE: no update.pub in payload — this image cannot verify updates"
fi
# Belt and braces: if any private key material slipped through, delete it here.
rm -f /etc/ffn-ngfw/update-sign.key /etc/ffn-ngfw/update.key
if [ -n "${FFN_UPDATE_URL:-}" ]; then
  echo "url=$FFN_UPDATE_URL" > /etc/ffn-ngfw/update-server.conf
  echo "  update server: $FFN_UPDATE_URL"
fi
mkdir -p /var/lib/ffn-ngfw
tar xzf /payload/varlib-seed.tgz -C /var/lib
# dataplane binaries (prebuilt FFN artifacts; rebuildable from repo sw/salvage/dpdk)
mkdir -p /opt/ffn-ngfw-v2/dpdk
for b in ffn-dpdk-mp ffn-fastpath-fwd ffn_hs_build; do
  [ -f "/opt/ffn-ngfw-v2/dpdk/$b" ] && chmod +x "/opt/ffn-ngfw-v2/dpdk/$b" || true
done

log "python venvs from FROZEN requirements (exact reproduction of the working venvs)"
# v2 mgmt API (ffn-manager-v2). Frozen set incl. python-multipart (FastAPI upload) + netfilterqueue.
python3 -m venv /opt/ffn-ngfw-v2/venv
/opt/ffn-ngfw-v2/venv/bin/pip install --no-cache-dir --upgrade pip wheel >/dev/null
/opt/ffn-ngfw-v2/venv/bin/pip install --no-cache-dir -r /payload/requirements-v2.frozen
# v1 venv — ffn-configd / ffn-controld run from /opt/ffn-ngfw/venv (lxml/pyinotify/pyroute2). ALWAYS build it.
python3 -m venv /opt/ffn-ngfw/venv
/opt/ffn-ngfw/venv/bin/pip install --no-cache-dir --upgrade pip wheel >/dev/null
/opt/ffn-ngfw/venv/bin/pip install --no-cache-dir -r /payload/requirements-v1.frozen

log "systemd units (faithful copies pulled from the reference box)"
cp -a /payload/units/*.service /etc/systemd/system/ 2>/dev/null || true
cp -a /payload/units/*.timer   /etc/systemd/system/ 2>/dev/null || true
cp -a /payload/units/*.d       /etc/systemd/system/ 2>/dev/null || true

log "service group + admin gateway account (ffn-cli login shell, key-only) + sudoers"
groupadd -f ffn-mgmt   # ffn-controld chowns its socket to this group (FFN_CONTROLD_GROUP)
grep -qxF "$FFN_CLI" /etc/shells || echo "$FFN_CLI" >> /etc/shells
if ! id "$ADMIN_USER" >/dev/null 2>&1; then
  useradd -m -s "$FFN_CLI" -c "FFN NGFW admin (CLI gateway)" "$ADMIN_USER"
fi
install -d -m700 -o "$ADMIN_USER" -g "$ADMIN_USER" "/home/$ADMIN_USER/.ssh"
cat > /etc/sudoers.d/ffn-admin-shell <<EOF
# escape target for 'request system shell' / 'maint shell' (gated in-band by ffn-cli)
${ADMIN_USER} ALL=(root) NOPASSWD: /bin/bash, /bin/bash --login, /bin/bash -l
Defaults:${ADMIN_USER} !requiretty
EOF
chmod 440 /etc/sudoers.d/ffn-admin-shell

log "console + SSH credentials"
# Without this the image has no usable local login at all: root is locked by
# debootstrap and the admin account is key-only with an empty .ssh.
if [ -n "${FFN_ROOT_PW:-}" ]; then
  echo "root:${FFN_ROOT_PW}" | chpasswd
  echo "${ADMIN_USER}:${FFN_ROOT_PW}" | chpasswd
  # Expire both immediately. FFN_ROOT_PW is a SETUP credential, not a standing
  # one: one value is baked into an image that many appliances are built from, so
  # without this every deployment shares a root password forever. Expiring it
  # keeps first console login possible -- the reason FFN_ROOT_PW exists -- while
  # forcing a change before the account is usable for anything else.
  chage -d 0 root || true
  chage -d 0 "${ADMIN_USER}" || true
  echo "  set password for root + ${ADMIN_USER} (expired: must be changed at first login)"
else
  echo "  WARNING: FFN_ROOT_PW empty -- no console login will be possible"
fi
if [ -n "${FFN_SSH_PUBKEY:-}" ]; then
  install -d -m700 /root/.ssh
  echo "${FFN_SSH_PUBKEY}" > /root/.ssh/authorized_keys
  chmod 600 /root/.ssh/authorized_keys
  install -d -m700 -o "$ADMIN_USER" -g "$ADMIN_USER" "/home/$ADMIN_USER/.ssh"
  echo "${FFN_SSH_PUBKEY}" > "/home/$ADMIN_USER/.ssh/authorized_keys"
  chmod 600 "/home/$ADMIN_USER/.ssh/authorized_keys"
  chown "$ADMIN_USER:$ADMIN_USER" "/home/$ADMIN_USER/.ssh/authorized_keys"
  echo "  installed authorized_keys for root + ${ADMIN_USER}"
else
  echo "  WARNING: FFN_SSH_PUBKEY empty -- no key-based SSH"
fi
mkdir -p /var/log/ffn-ngfw; chmod 1777 /var/log/ffn-ngfw

log "first-boot + hw-tune + selftest + FIPS + recovery services"
install -m755 /payload/ffn-firstboot.sh /usr/local/sbin/ffn-firstboot.sh
install -m755 /payload/ffn-hwtune.sh     /usr/local/sbin/ffn-hwtune.sh
install -m755 /payload/ffn-selftest.sh    /usr/local/sbin/ffn-selftest.sh
cp -a /payload/ffn-firstboot.service /etc/systemd/system/
cp -a /payload/ffn-selftest.service  /etc/systemd/system/
# FIPS-CC power-on self-test (runs when /etc/ffn-ngfw/fips-cc.mode exists) + dataplane gating
cp -a /payload/ffn-fips-selftest.service /etc/systemd/system/
mkdir -p /etc/systemd/system/ffn-dpdk-fwd.service.d
cat > /etc/systemd/system/ffn-dpdk-fwd.service.d/20-fips.conf <<EOF
[Unit]
After=ffn-fips-selftest.service
Requires=ffn-fips-selftest.service
EOF
# factory config skeleton restored by recovery-mode zeroize
mkdir -p /etc/ffn-ngfw/factory
# The model's own factory config outranks anything the harvest brought in.
# varlib-seed.tgz and etc-ffn-ngfw.tgz are tarred off the BUILD HOST, so
# without this the image ships the builder's hostname, its interface-alias
# map and its IP addresses -- which is how a PA-5220 image came to carry
# the build host's own NIC name and IP address as its factory defaults.
if [ -f /factory-running-config.xml ]; then
  install -m644 /factory-running-config.xml /etc/ffn-ngfw/factory/running-config.xml
  mkdir -p /var/lib/ffn-ngfw/config
  for f in running-config.xml last-applied.xml candidate-config.xml; do
    install -m644 /factory-running-config.xml "/var/lib/ffn-ngfw/config/$f"
  done
  echo "  factory config: model-specific (harvested build-host config discarded)"
elif [ -f /var/lib/ffn-ngfw/config/running-config.xml ]; then
  cp /var/lib/ffn-ngfw/config/running-config.xml /etc/ffn-ngfw/factory/running-config.xml
  echo "  WARNING: no profiles/${FFN_MODEL}.running-config.xml -- this image"
  echo "           inherits the BUILD HOST identity as its factory default"
fi

# ---- NFS root for the OCTEON planes ---------------------------------------
# The CP and DP take their rootfs from the MP's SSD over PCIC. Exports are
# scoped to the PCIC subnet only; NFS must never be reachable from the
# management network.
mkdir -p /opt/dpfs /opt/var.cp /opt/var.dp0 /opt/var.dp1 /opt/var.dp2
cat > /etc/exports <<'EOF'
# FFN: NFS root for the OCTEON control/data planes.
# Restricted to the CP/DP address space, as PAN-OS does. NFS must never be
# reachable from the management network -- rpc.nfsd binds 0.0.0.0:2049 and
# rpcbind 0.0.0.0:111, so the nft ruleset must refuse 111/2049 on every mgmt
# interface. The client scoping below is what actually gates mounting.
/opt/dpfs    127.1.0.0/16(rw,sync,no_root_squash,no_subtree_check)
/opt/var.cp  127.1.0.0/16(rw,sync,no_root_squash,no_subtree_check)
/opt/var.dp0 127.1.0.0/16(rw,sync,no_root_squash,no_subtree_check)
/opt/var.dp1 127.1.0.0/16(rw,sync,no_root_squash,no_subtree_check)
/opt/var.dp2 127.1.0.0/16(rw,sync,no_root_squash,no_subtree_check)
EOF
# Pin nfsd to the PCIC subnet. Not a substitute for the firewall rule -- if the
# PCIC interface is absent at boot nfsd falls back to all addresses, which is
# exactly why the nft rule above is required as well.
mkdir -p /etc/nfs.conf.d
cat > /etc/nfs.conf.d/10-ffn-pcic.conf <<'EOF'
[nfsd]
host=127.1.1.1
EOF
systemctl enable nfs-server 2>/dev/null || true

# Management/control interfaces, for ffn_config_bridge.py. These used to be a
# hardcoded list inside that script, so the nft INPUT accept rule named the
# build host's NIC and ssh on this chassis' real mgmt port was dropped.
mkdir -p /etc/ffn-ngfw
{
  echo "# Interfaces permitted to reach FFN's own admin services (ssh/https)."
  echo "# Written by provision.sh from profiles/${FFN_MODEL}.conf. One per line."
  for i in ${FFN_MGMT_IFACE:-} ${FFN_HA1_A:-} ${FFN_HA1_B:-}; do echo "$i"; done
} > /etc/ffn-ngfw/mgmt-ifaces

# ---- keep the PCIC interface's driver-assigned name ------------------------
# systemd's predictable naming would rename pcicp0 to enp1s0f0. The bus-derived
# name says where the PCIe endpoint sits; pcicp0 says which plane is on the far
# end, which is what matters when there are two PCIC hops (MP<->CP, CP<->DP) to
# tell apart in a rule or a capture.
mkdir -p /etc/systemd/network
cat > /etc/systemd/network/10-ffn-pcic.link <<'EOF'
[Match]
Driver=ffn_pcic

[Link]
NamePolicy=keep
EOF
# recovery/maintenance menu (activated only on the recovery partition, but shipped in both)
install -m755 /payload/ffn-recovery-menu.sh /usr/local/sbin/ffn-recovery-menu.sh
cp -a /payload/ffn-recovery-menu.service /etc/systemd/system/

log "enable services (auto-load on boot)"
systemctl enable systemd-networkd systemd-resolved 2>/dev/null || true  # deterministic networking
systemctl enable ssh
systemctl enable ffn-firstboot.service
# ffn-sysd first (the state bus other daemons publish to); ffn-watchdogd early
# so a chassis watchdog cannot reset us mid-boot; ffn-satd stays inert unless
# /etc/ffn-ngfw/satellite.json enables it.
for u in ffn-sysd ffn-watchdogd ffn-satd ffn-configd ffn-controld ffn-manager-v2 ffn-bmfw ffn-dpdk-fwd frr zerotier-one \
         ffn-license-monitor.timer ffn-sigdb-update.timer ffn-selftest.service ffn-fips-selftest.service; do
  systemctl enable "$u" 2>/dev/null && echo "  enabled $u" || echo "  (skip $u — unit absent)"
done

log "GRUB defaults + serial console (for headless/qemu) + initramfs"
cat > /etc/default/grub <<EOF
GRUB_DEFAULT=0
GRUB_TIMEOUT=3
GRUB_DISTRIBUTOR="FFN NGFW"
GRUB_CMDLINE_LINUX_DEFAULT="${GRUB_CMDLINE_DEFAULT} console=tty0 console=ttyS0,${FFN_SERIAL_BAUD:-115200}n8"
GRUB_CMDLINE_LINUX=""
GRUB_TERMINAL="console serial"
GRUB_SERIAL_COMMAND="serial --speed=${FFN_SERIAL_BAUD:-115200} --unit=0"
EOF
# Persist the console baud so ffn-hwtune cannot revert it on first boot.
# provision.sh runs INSIDE the chroot, so this path is absolute.
mkdir -p /etc/ffn-ngfw
echo "${FFN_SERIAL_BAUD:-115200}" > /etc/ffn-ngfw/serial-baud
# fstab uses a label; the packager sets the same label on the root fs
cat > /etc/fstab <<EOF
LABEL=${IMG_LABEL_ROOT} /   ext4  errors=remount-ro  0 1
EOF
update-initramfs -c -k all

# --- model dataplane ----------------------------------------------------------
# Built from FFN's own sources inside the chroot, and the unit is GENERATED from
# the model profile rather than harvested from one particular box, so the ports a
# given model uses live in exactly one place (profiles/<model>.conf).
if [ -n "${FFN_DP_PORTS:-}" ] && [ -d /opt/ffn-ngfw-v2/octeon-dp ]; then
  log "dataplane (${FFN_DP_MODE:-afpacket}) for ${FFN_MODEL:-generic}: ${FFN_DP_PORTS}"
  if make -C /opt/ffn-ngfw-v2/octeon-dp ffn_dp_afpacket >/tmp/dpbuild.log 2>&1; then
    install -m755 /opt/ffn-ngfw-v2/octeon-dp/ffn_dp_afpacket /usr/local/sbin/ffn_dp_afpacket
    echo "  built /usr/local/sbin/ffn_dp_afpacket"
  else
    echo "  WARNING: dataplane build FAILED — image will have no forwarder"
    tail -15 /tmp/dpbuild.log | sed 's/^/    /'
  fi

  # starter policy: management reachable, everything else denied by default
  if [ -x /opt/ffn-ngfw-v2/octeon-dp/mkpolicy.py ]; then
    python3 /opt/ffn-ngfw-v2/octeon-dp/mkpolicy.py \
        -o /etc/ffn-ngfw/dataplane-policy.bin \
        "allow tcp any any:443" "allow tcp any any:22" "allow udp any any:53" \
        >/dev/null 2>&1 && echo "  wrote /etc/ffn-ngfw/dataplane-policy.bin" \
      || echo "  WARNING: could not generate dataplane policy"
  fi

  _dpargs=""; _dpup=""
  for _p in $FFN_DP_PORTS; do
    _dpargs="$_dpargs -i $_p"
    _dpup="$_dpup
ExecStartPre=-/sbin/ip link set $_p up"
  done
  cat > /etc/systemd/system/ffn-dp-afpacket.service <<UNIT
[Unit]
Description=FFN dataplane (AF_PACKET bump-in-the-wire) — ${FFN_MODEL:-generic}
After=network-online.target ffn-sysd.service
Wants=ffn-sysd.service
# Ports come from the model profile. Forwards once transceivers/link are
# present; idles harmlessly until then.
[Service]
Type=simple${_dpup}
ExecStart=/usr/local/sbin/ffn_dp_afpacket${_dpargs} \
          -p /etc/ffn-ngfw/dataplane-policy.bin -d drop -v 1 -P -s 60
Restart=always
RestartSec=5
[Install]
WantedBy=multi-user.target
UNIT
  systemctl enable ffn-dp-afpacket.service 2>/dev/null \
    && echo "  enabled ffn-dp-afpacket ($FFN_DP_PORTS)" || true
fi

# --- owner-supplied vendor firmware (autodetect) -------------------------------
# Someone reclaiming their own appliance owns the firmware that shipped on it.
# These pieces let them plug a stick in and have FFN pick it up. The firmware
# itself is NEVER packaged -- only the mechanism is.
if [ -f /payload/99-ffn-vendor.rules ]; then
  install -m644 /payload/99-ffn-vendor.rules /etc/udev/rules.d/99-ffn-vendor.rules
  install -m644 /payload/ffn-vendor-autoimport@.service /etc/systemd/system/
  [ -f /etc/ffn-ngfw/vendor.conf ] || install -m644 /payload/vendor.conf /etc/ffn-ngfw/vendor.conf
  echo "  vendor firmware autodetect installed (udev + template unit)"
fi
# Belt and braces: an image must never carry vendor firmware.
rm -rf /var/lib/ffn-ngfw/vendor

# --- pin the management port -------------------------------------------
# Three identical I210s sit on the front panel: one management, two HA
# control. Alphabetical or carrier-order detection can land on an HA port,
# which loses the box. Writing the profile's choice here is what makes
# FFN_MGMT_IFACE mean anything.
if [ -n "${FFN_MGMT_IFACE:-}" ]; then
  mkdir -p /etc/ffn-ngfw
  {
    echo "# Written by provision.sh from the model profile."
    echo "iface=${FFN_MGMT_IFACE}"
    [ -n "${FFN_MGMT_IP:-}"  ] && echo "address=${FFN_MGMT_IP}"
    [ -n "${FFN_MGMT_GW:-}"  ] && echo "gateway=${FFN_MGMT_GW}"
    [ -n "${FFN_MGMT_DNS:-}" ] && echo "dns=${FFN_MGMT_DNS}"
    # Recorded so HA setup does not have to guess which ports these are.
    [ -n "${FFN_HA1_A:-}" ] && echo "ha1_a=${FFN_HA1_A}"
    [ -n "${FFN_HA1_B:-}" ] && echo "ha1_b=${FFN_HA1_B}"
  } > /etc/ffn-ngfw/mgmt.conf
  echo "  mgmt port pinned: ${FFN_MGMT_IFACE}"
fi

# --- chassis log volume ------------------------------------------------
# A PA-5200 carries two internal 2TB drives as a RAID1 holding PAN-OS's
# 'Log' volume. They are still good on a reclaimed box, so FFN uses them
# for its own logs rather than filling the 24GB system partition. The
# array UUID differs per chassis, so it is DISCOVERED at boot rather than
# baked into the image.
if [ -f /payload/ffn-logvol.sh ]; then
  install -m755 /payload/ffn-logvol.sh /usr/local/sbin/ffn-logvol.sh
  install -m644 /payload/ffn-logvol.service /etc/systemd/system/
  systemctl enable ffn-logvol.service 2>/dev/null \
    && echo "  log-volume discovery enabled" || true
fi

# --- OCTEON generation ----------------------------------------------------
# The C dataplane reads this to choose its backend rather than inferring the
# generation from the PCI id, which is only a pci.ids database label.
if [ -n "${FFN_OCTEON_GEN:-}" ]; then
  mkdir -p /etc/ffn-ngfw
  echo "$FFN_OCTEON_GEN" > /etc/ffn-ngfw/octeon-gen
  echo "  octeon generation pinned: $FFN_OCTEON_GEN"
fi

# --- offload NPU bind ----------------------------------------------------------
# Hand the Octeon to vfio-pci at boot so FFN can map its BARs. Harmless on a
# chassis that has no such device.
if [ -n "${FFN_OCTEON_IDS:-}" ]; then
  echo "vfio-pci" > /etc/modules-load.d/ffn-vfio.conf
  echo "options vfio-pci ids=${FFN_OCTEON_IDS}" > /etc/modprobe.d/ffn-vfio.conf
  echo "  vfio-pci pinned to ${FFN_OCTEON_IDS}"
fi

log "strip per-appliance identity"
# openssh-server generates host keys when it is installed IN THE CHROOT,
# so they would ship inside the image and every appliance built from it
# would present the same SSH host identity -- indistinguishable from a
# man-in-the-middle, and a warning every operator would learn to ignore.
# Remove them and regenerate on first start. ssh-keygen -A only creates
# what is missing, so it is idempotent.
rm -f /etc/ssh/ssh_host_*
mkdir -p /etc/systemd/system/ssh.service.d
cat > /etc/systemd/system/ssh.service.d/10-ffn-hostkeys.conf <<'UNIT'
[Service]
# Generate this appliance's own host keys before sshd starts.
ExecStartPre=-/usr/bin/ssh-keygen -A
UNIT
echo "  ssh host keys removed; regenerated per appliance at first start"

log "slim apt caches"
apt-get clean; rm -rf /var/lib/apt/lists/*

log "provision complete"
