#!/usr/bin/env bash
# FFN NGFW first-boot provisioning — runs ONCE before the FFN services start.
# Makes a generic image unique + self-configuring (keys, secrets, NICs, disk).
set -uo pipefail
export DEBIAN_FRONTEND=noninteractive PATH=/usr/sbin:/usr/bin:/sbin:/bin
STAMP=/var/lib/ffn-ngfw/.firstboot-done
LOG=/var/log/ffn-ngfw/firstboot.log
mkdir -p /var/log/ffn-ngfw
exec > >(tee -a "$LOG") 2>&1
echo "=== ffn-firstboot $(date -u +%FT%TZ) ==="
[ -f "$STAMP" ] && { echo "already provisioned; exiting"; exit 0; }

echo "-- regenerate SSH host keys --"
rm -f /etc/ssh/ssh_host_*; ssh-keygen -A >/dev/null 2>&1 || true

echo "-- fresh machine-id --"
rm -f /etc/machine-id /var/lib/dbus/machine-id
systemd-machine-id-setup 2>/dev/null || true

echo "-- WebUI TLS cert (self-signed) --"
if [ ! -s /etc/ffn-ngfw/tls/server.crt ] || [ ! -s /etc/ffn-ngfw/tls/server.key ]; then
  rm -f /etc/ffn-ngfw/tls/server.crt /etc/ffn-ngfw/tls/server.key
  mkdir -p /etc/ffn-ngfw/tls
  openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
    -keyout /etc/ffn-ngfw/tls/server.key -out /etc/ffn-ngfw/tls/server.crt \
    -subj "/CN=$(hostname)" -addext "subjectAltName=DNS:$(hostname),IP:127.0.0.1" 2>/dev/null
  chmod 600 /etc/ffn-ngfw/tls/server.key
  cp /etc/ffn-ngfw/tls/server.crt /usr/local/share/ca-certificates/ffn-ngfw.crt 2>/dev/null && update-ca-certificates >/dev/null 2>&1 || true
fi

echo "-- master.key (HMAC escape) --"
[ -s /etc/ffn-ngfw/master.key ] || { head -c 32 /dev/urandom | base64 > /etc/ffn-ngfw/master.key; chmod 600 /etc/ffn-ngfw/master.key; }

echo "-- per-machine JWT secret --"   # no default ships any more; this
                                  # pins one per machine regardless
mkdir -p /etc/systemd/system/ffn-manager-v2.service.d
if [ ! -f /etc/systemd/system/ffn-manager-v2.service.d/20-jwt.conf ]; then
  printf '[Service]\nEnvironment=FFN_JWT_SECRET=%s\n' "$(head -c 32 /dev/urandom | base64)" \
    > /etc/systemd/system/ffn-manager-v2.service.d/20-jwt.conf
fi

echo "-- NIC detection --"
mapfile -t NICS < <(ls /sys/class/net | grep -vE '^(lo|docker|veth|zt|tmfifo|dummy|tap)')
echo "   found: ${NICS[*]:-none}"
MGMT="${NICS[0]:-}"; DATA="${NICS[1]:-}"
if [ -n "$MGMT" ]; then
  echo "   mgmt=$MGMT via DHCP"
  cat > /etc/netplan/01-ffn.yaml <<EOF
network:
  version: 2
  renderer: networkd
  ethernets:
    $MGMT:
      dhcp4: true
      dhcp6: false
EOF
  chmod 600 /etc/netplan/01-ffn.yaml
  netplan generate 2>/dev/null || true
fi

echo "-- reconcile firewall mgmt-allow to the detected NIC (image ships dev-box eno1np0) --"
# ffn-bmfw's input chain is 'policy drop' + mgmt-allow on eno1np0/ztbtov4b2k. On any box
# whose mgmt NIC differs, that would lock out SSH/WebUI. Add the detected NIC to the allow.
if [ -n "$MGMT" ] && [ -f /etc/ffn-ngfw/ffn-bmfw.nft ]; then
  case "$MGMT" in
    eno1np0|ztbtov4b2k) echo "   mgmt NIC already in allow-list ($MGMT)";;
    *) sed -i "s/\"eno1np0\", \"ztbtov4b2k\"/\"$MGMT\", \"eno1np0\", \"ztbtov4b2k\"/g" /etc/ffn-ngfw/ffn-bmfw.nft \
         && echo "   added $MGMT to firewall mgmt-allow";;
  esac
fi

echo "-- control-plane CPU pinning + dataplane placement (hardware-dependent) --"
CORES=$(nproc)
# The cpu-plane drop-ins pin ffn-configd/controld to CPUAffinity=4-11 — valid only on
# appliance-class CPUs. On smaller machines those cores don't exist and the services
# crash-loop (sched_setaffinity EINVAL), so strip the pinning below the appliance spec.
if [ "$CORES" -lt 16 ]; then
  rm -f /etc/systemd/system/ffn-configd.service.d/10-cpu-plane.conf \
        /etc/systemd/system/ffn-controld.service.d/10-cpu-plane.conf 2>/dev/null || true
  echo "   removed control-plane CPUAffinity pinning (only ${CORES} cores)"
fi
if [ "$CORES" -ge 16 ] && [ -n "$DATA" ]; then
  # dedicate the last two cores to the DP; bind the detected data NIC
  C1=$((CORES-2)); C2=$((CORES-1))
  systemctl unmask ffn-dpdk-fwd.service 2>/dev/null || true
  mkdir -p /etc/systemd/system/ffn-dpdk-fwd.service.d
  cat > /etc/systemd/system/ffn-dpdk-fwd.service.d/10-iface.conf <<EOF
[Service]
ExecStart=
ExecStart=/opt/ffn-ngfw-v2/dpdk/ffn-dpdk-mp -l ${C1}-${C2} --file-prefix=ffndp --vdev=net_af_xdp0,iface=${DATA} -- --tables /var/lib/ffn-ngfw/fastpath
EOF
  echo "   dataplane: cores ${C1}-${C2}, data iface ${DATA}"
else
  systemctl disable ffn-dpdk-fwd.service 2>/dev/null || true
  systemctl mask ffn-dpdk-fwd.service 2>/dev/null || true
  echo "   dataplane DISABLED/masked (need >=16 cores + a dedicated data NIC; have ${CORES} cores, data='${DATA:-none}'). Management plane runs normally."
fi

echo "-- grow root filesystem to fill disk --"
ROOTDEV=$(findmnt -no SOURCE /); DISK=$(lsblk -no PKNAME "$ROOTDEV" 2>/dev/null | head -1)
if [ -n "${DISK:-}" ]; then
  PARTNUM=$(echo "$ROOTDEV" | grep -oE '[0-9]+$')
  command -v growpart >/dev/null 2>&1 && growpart "/dev/$DISK" "$PARTNUM" 2>/dev/null || true
  resize2fs "$ROOTDEV" 2>/dev/null || true
fi

echo "-- recompute kernel tuning for this CPU (takes effect next boot) --"
/usr/local/sbin/ffn-hwtune.sh || true

systemctl daemon-reload
touch "$STAMP"
echo "=== firstboot done; FFN services will now start ==="
