#!/bin/bash
# End-to-end test of the AF_PACKET dataplane over veth pairs.
#
#   sender ns  --[ffnA1|ffnA0]--  FFN dataplane  --[ffnB0|ffnB1]--  receiver ns
#
# The forwarder bridges ffnA0 <-> ffnB0 (bump-in-the-wire). We inject frames on
# ffnA1 and watch ffnB1: a policy-allowed flow must arrive, a policy-denied flow
# must NOT. That exercises real kernel networking through the whole path:
# AF_PACKET rx -> parse -> classify -> flow cache -> verdict -> AF_PACKET tx.
#
# Requires root. Cleans up after itself.
set -u
FAIL=0
ok(){   echo "  ok   $1"; }
bad(){  echo "  FAIL $1"; FAIL=$((FAIL+1)); }

cleanup() {
  [ -n "${DP_PID:-}" ] && kill "$DP_PID" 2>/dev/null
  ip netns del ffnsnd 2>/dev/null
  ip netns del ffnrcv 2>/dev/null
  ip link del ffnA0 2>/dev/null
  ip link del ffnB0 2>/dev/null
  rm -f /tmp/ffn_veth_pol.bin /tmp/ffn_rcv.txt /tmp/ffn_dp.log
}
trap cleanup EXIT
cleanup 2>/dev/null

echo "== 1. build the topology =="
ip link add ffnA0 type veth peer name ffnA1 || { echo "veth create failed"; exit 1; }
ip link add ffnB0 type veth peer name ffnB1 || { echo "veth create failed"; exit 1; }
ip netns add ffnsnd
ip netns add ffnrcv
ip link set ffnA1 netns ffnsnd
ip link set ffnB1 netns ffnrcv
ip link set ffnA0 up
ip link set ffnB0 up
ip netns exec ffnsnd ip link set ffnA1 up
ip netns exec ffnrcv ip link set ffnB1 up
# static neighbours so nothing depends on ARP crossing the firewall
ip netns exec ffnsnd ip addr add 10.77.0.1/24 dev ffnA1
ip netns exec ffnrcv ip addr add 10.77.0.2/24 dev ffnB1
ok "veth pairs + namespaces created (ffnA0/ffnB0 are the dataplane ports)"

echo "== 2. build a policy: allow tcp/443, drop tcp/4444 =="
python3 - <<'PY'
import struct
def row(sip,smask,dip,dmask,spl,sph,dpl,dph,proto,vsys,act,flags,egr,rid):
    def nbo(v): return struct.unpack("<I", struct.pack(">I", v))[0]
    return struct.pack("<IIIIHHHHBBBBHH", nbo(sip),nbo(smask),nbo(dip),nbo(dmask),
                       spl,sph,dpl,dph,proto,vsys,act,flags,egr,rid)
def ip(a,b,c,d): return (a<<24)|(b<<16)|(c<<8)|d
FORWARD, DROP = 0, 3
rows = [
    # allow 10.77.0.0/24 -> any tcp/443  (egress 0xFFFF = "the other port")
    row(ip(10,77,0,0), ip(255,255,255,0), 0,0, 0,65535, 443,443, 6,1, FORWARD,0, 0xFFFF, 901),
    # explicitly drop tcp/4444
    row(0,0, 0,0, 0,65535, 4444,4444, 6,1, DROP,0, 0xFFFF, 902),
]
body = b"".join(rows)
hdr = struct.pack("<4sHHIQIIII", b"FPPO", 1, 0x40, len(rows), 0, 0, 32, len(rows), 0)
open("/tmp/ffn_veth_pol.bin","wb").write(hdr+body)
print("  policy.bin: %d rules, %d bytes" % (len(rows), len(hdr+body)))
PY
[ -s /tmp/ffn_veth_pol.bin ] && ok "policy.bin generated" || bad "policy.bin generation"

echo "== 3. start the dataplane on ffnA0 <-> ffnB0 =="
./ffn_dp_afpacket -i ffnA0 -i ffnB0 -p /tmp/ffn_veth_pol.bin -d drop -v 1 \
    > /tmp/ffn_dp.log 2>&1 &
DP_PID=$!
sleep 1.5
if kill -0 "$DP_PID" 2>/dev/null; then
  ok "dataplane running (pid $DP_PID)"
  grep -q 'policy: 2 rule' /tmp/ffn_dp.log && ok "policy loaded (2 rules)" \
      || bad "policy not reported loaded"
else
  bad "dataplane died"; sed 's/^/    /' /tmp/ffn_dp.log
fi

echo "== 4. listen on the far side, inject traffic on the near side =="
# receiver: capture ethernet frames arriving on ffnB1
ip netns exec ffnrcv timeout 8 python3 - > /tmp/ffn_rcv.txt 2>/dev/null <<'PY' &
import socket, struct, sys
# ETH_P_ALL must be in NETWORK byte order for AF_PACKET, hence htons().
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
s.bind(("ffnB1", 0))
s.settimeout(7)
seen = []
try:
    while True:
        f = s.recv(2048)
        if len(f) < 38 or f[12:14] != b"\x08\x00":
            continue
        ihl = (f[14] & 0x0f) * 4
        l4 = 14 + ihl
        if f[23] != 6:            # tcp only
            continue
        dport = struct.unpack("!H", f[l4+2:l4+4])[0]
        seen.append(dport)
        print("GOT dport=%d" % dport, flush=True)
except Exception:
    pass
PY
RCV_PID=$!
sleep 1

# sender: two flows -- one allowed (443), one denied (4444)
ip netns exec ffnsnd python3 - <<'PY'
import socket, struct, time
def frame(dport):
    eth = b"\x02\x00\x00\x00\x00\x02" + b"\x02\x00\x00\x00\x00\x01" + b"\x08\x00"
    ip  = bytearray(20)
    ip[0]=0x45; ip[8]=64; ip[9]=6
    ip[2:4] = struct.pack("!H", 40)
    ip[12:16] = bytes([10,77,0,1]); ip[16:20] = bytes([10,77,0,2])
    tcp = bytearray(20)
    tcp[0:2] = struct.pack("!H", 50000); tcp[2:4] = struct.pack("!H", dport)
    tcp[12] = 0x50; tcp[13] = 0x02
    return bytes(eth)+bytes(ip)+bytes(tcp)
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
s.bind(("ffnA1", 0))
for i in range(5):
    s.send(frame(443));   time.sleep(0.05)
    s.send(frame(4444));  time.sleep(0.05)
print("  sent 5x tcp/443 (allow) + 5x tcp/4444 (deny)")
PY
sleep 3
wait $RCV_PID 2>/dev/null

echo "== 5. results =="
# grep -c already prints 0 and exits 1 when there are no matches, so a
# `|| echo 0` fallback would emit "0\n0" and break the arithmetic below.
GOT443=$(grep -c 'dport=443'  /tmp/ffn_rcv.txt 2>/dev/null); GOT443=${GOT443:-0}
GOT4444=$(grep -c 'dport=4444' /tmp/ffn_rcv.txt 2>/dev/null); GOT4444=${GOT4444:-0}
echo "  frames arriving on the far side: tcp/443=$GOT443  tcp/4444=$GOT4444"
[ "$GOT443"  -gt 0 ] && ok "ALLOWED flow (tcp/443) was forwarded through the dataplane" \
                     || bad "allowed flow did not arrive"
[ "$GOT4444" -eq 0 ] && ok "DENIED flow (tcp/4444) was dropped by policy" \
                     || bad "denied flow leaked ($GOT4444 frames)"

kill "$DP_PID" 2>/dev/null
sleep 0.7
echo "== 6. dataplane counters =="
sed -n '/--- final ---/,$p' /tmp/ffn_dp.log | sed 's/^/  /'
grep -qE 'fwd=[1-9]' /tmp/ffn_dp.log && ok "forward counter non-zero" || bad "no forwards counted"
grep -qE 'drop=[1-9]' /tmp/ffn_dp.log && ok "drop counter non-zero"    || bad "no drops counted"
grep -qE 'cache_hit=[1-9]' /tmp/ffn_dp.log && ok "flow cache served repeat packets" \
    || echo "  note: no cache hits (few packets)"

echo
echo "==== veth end-to-end: $FAIL failed ===="
exit $((FAIL>0))
