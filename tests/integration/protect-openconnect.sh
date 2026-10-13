#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
# End-to-end check of the FFN Protect gateway with a real GlobalProtect client
# (OpenConnect, --protocol=gp) in network namespaces on a Linux build host.
#
#   ffn-protect-gw      10.77.0.1/24 on p9  (daemon + worker, tunnel.1 = 10.200.0.1/24, 10.99.0.1 on lo)
#   ffn-protect-client  10.77.0.2/24 on c9  (openconnect)
#
# Proves: portal prelogin and configuration, gateway login, ESP tunnel
# (client pings the gateway's tunnel address and a network behind it through
# the tunnel), then the SSL-tunnel fallback with ESP disabled.
#
#   sudo tests/integration/protect-openconnect.sh <ffn-protect-tunnel binary> [work dir]
set -eu
WORKER=${1:?worker binary}
WORK=${2:-/tmp/ffn-protect-it}
HERE=$(cd "$(dirname "$0")/../.." && pwd)
DAEMON=$HERE/opt/ffn_protect_gateway.py
VPNC=$(ls /usr/share/vpnc-scripts/vpnc-script /etc/vpnc/vpnc-script 2>/dev/null | head -1)
[ -n "$VPNC" ] || { echo 'vpnc-script not found (install vpnc-scripts)'; exit 2; }
command -v openconnect >/dev/null || { echo 'openconnect not found'; exit 2; }
PASSWORD=it-$(head -c 6 /dev/urandom | od -An -tx1 | tr -d ' \n')

cleanup() {
    set +e
    for pid in "$WORK/oc.pid" "$WORK/oc2.pid"; do [ -f "$pid" ] && kill "$(cat "$pid")" 2>/dev/null; done
    [ -f "$WORK/daemon.pid" ] && kill "$(cat "$WORK/daemon.pid")" 2>/dev/null
    sleep 1
    ip netns del ffn-protect-gw 2>/dev/null
    ip netns del ffn-protect-client 2>/dev/null
}
trap cleanup EXIT
cleanup
rm -rf "$WORK"; mkdir -p "$WORK/run"; chmod 700 "$WORK/run"

ip netns add ffn-protect-gw
ip netns add ffn-protect-client
ip link add p9 netns ffn-protect-gw type veth peer name c9 netns ffn-protect-client
ip -n ffn-protect-gw addr add 10.77.0.1/24 dev p9
ip -n ffn-protect-gw addr add 10.99.0.1/24 dev lo
ip -n ffn-protect-gw link set lo up
ip -n ffn-protect-gw link set p9 up
ip -n ffn-protect-client addr add 10.77.0.2/24 dev c9
ip -n ffn-protect-client link set lo up
ip -n ffn-protect-client link set c9 up
ip netns exec ffn-protect-gw sysctl -qw net.ipv4.ip_forward=1

openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 2 -subj /CN=10.77.0.1 -addext subjectAltName=IP:10.77.0.1 \
    -keyout "$WORK/key.pem" -out "$WORK/cert.pem" 2>/dev/null
PIN=$(openssl x509 -in "$WORK/cert.pem" -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64)
PHASH=$(printf '%s\n' "$PASSWORD" | python3 "$DAEMON" phash)
python3 - "$WORK" "$PHASH" <<'PY'
import json, sys
work, phash = sys.argv[1], sys.argv[2]
cert, key = open(work + '/cert.pem').read(), open(work + '/key.pem').read()
intent = dict(revision=1, configuration='integration', protect=dict(
    certificates=dict(gw=dict(certificate=cert, private_key=key, chain='')),
    users=dict(alice=dict(phash=phash)),
    auth_profiles=dict(users=dict(method='local', timeout=5)),
    portals=dict(main=dict(interface='p9', address='10.77.0.1', certificate='gw', auth_profile='users', login_lifetime=3600,
                           connect_method='user-logon', gateways=[dict(name='10.77.0.1', priority=1, description='it')], root_ca='')),
    gateways=dict(main=dict(interface='p9', address='10.77.0.1', certificate='gw', auth_profile='users', tunnel='tunnel.1',
                            tunnel_address='10.200.0.1/24', pools=[['10.200.0.10', '10.200.0.20']], dns=['10.99.0.1'], dns_suffix=['it.example'],
                            access_routes=['10.99.0.0/24', '10.200.0.0/24'], exclude_routes=[], tunnel_mode='esp-ssl', crypto='aes-128-cbc',
                            idle_timeout=600, login_lifetime=3600, mtu=1400, hip=False))))
json.dump(intent, open(work + '/intent.json', 'w'))
PY

FFN_PROTECT_INTENT=$WORK/intent.json FFN_PROTECT_RUN=$WORK/run FFN_PROTECT_WORKER=$WORKER FFN_PROTECT_OWNER_ROWS=$WORK/run \
    ip netns exec ffn-protect-gw python3 "$DAEMON" serve >"$WORK/daemon.log" 2>&1 &
echo $! >"$WORK/daemon.pid"
for i in $(seq 1 50); do
    grep -q 'listening on 10.77.0.1' "$WORK/daemon.log" 2>/dev/null && break
    sleep 0.2
done
grep -q 'listening on 10.77.0.1' "$WORK/daemon.log" || { echo 'daemon did not listen'; cat "$WORK/daemon.log"; exit 1; }
ip -n ffn-protect-gw -br link show tunnel.1 || { echo 'tunnel device missing'; cat "$WORK/daemon.log"; exit 1; }

connect() {   # $1 pid file, rest: extra openconnect options
    local pidfile=$1; shift
    printf '%s\n' "$PASSWORD" | ip netns exec ffn-protect-client openconnect --protocol=gp --servercert "pin-sha256:$PIN" \
        --user alice --passwd-on-stdin --script "$VPNC" --background --pid-file "$pidfile" --interface vpn0 "$@" https://10.77.0.1 \
        >"$WORK/openconnect.log" 2>&1
    for i in $(seq 1 50); do
        ip -n ffn-protect-client -br addr show vpn0 2>/dev/null | grep -q '10.200.0.' && return 0
        sleep 0.2
    done
    echo 'client tunnel did not come up'; cat "$WORK/openconnect.log"; return 1
}
mode() {
    python3 - "$WORK/run/status.json" <<'PY'
import json, sys
status = json.load(open(sys.argv[1]))
print(','.join('%s:%s' % (s['user'], s['mode']) for s in status['sessions']))
PY
}

echo '== ESP tunnel'
connect "$WORK/oc.pid"
sleep 3   # the client probes ESP before it switches from the SSL tunnel
ip netns exec ffn-protect-client ping -c 3 -W 2 10.200.0.1 >/dev/null && echo 'ping gateway tunnel address: ok'
ip netns exec ffn-protect-client ping -c 3 -W 2 10.99.0.1 >/dev/null && echo 'ping network behind the gateway: ok'
echo "session modes: $(mode)"
mode | grep -q 'alice:esp' || { echo 'expected an ESP session'; cat "$WORK/openconnect.log"; exit 1; }
kill "$(cat "$WORK/oc.pid")"; rm -f "$WORK/oc.pid"; sleep 2

echo '== SSL tunnel (ESP disabled on the client)'
connect "$WORK/oc2.pid" --no-dtls
ip netns exec ffn-protect-client ping -c 3 -W 2 10.200.0.1 >/dev/null && echo 'ping gateway tunnel address: ok'
ip netns exec ffn-protect-client ping -c 3 -W 2 10.99.0.1 >/dev/null && echo 'ping network behind the gateway: ok'
echo "session modes: $(mode)"
mode | grep -q 'alice:ssl' || { echo 'expected an SSL session'; cat "$WORK/openconnect.log"; exit 1; }
kill "$(cat "$WORK/oc2.pid")"; rm -f "$WORK/oc2.pid"; sleep 2
echo "== daemon log"
grep 'protect:' "$WORK/daemon.log" | tail -12
echo 'PASS'
