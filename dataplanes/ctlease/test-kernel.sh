#!/bin/sh
# Isolated conntrack/control test; no hardware access or packet transmission.
set -eu
cd "$(dirname "$0")"
ns="ffn-ctlease-test-$$"
test ! -d /sys/module/ffn_ctlease
loaded=0
cleanup() {
    ip netns del "$ns" 2>/dev/null || true
    if [ "$loaded" = 1 ]; then rmmod ffn_ctlease; fi
}
trap cleanup EXIT INT TERM
insmod ./ffn_ctlease.ko
loaded=1
ip netns add "$ns"
ip netns exec "$ns" sysctl -qw net.netfilter.nf_conntrack_acct=1
ip netns exec "$ns" nft add table inet ctlease_test
ip netns exec "$ns" nft add chain inet ctlease_test labels
ip netns exec "$ns" nft add rule inet ctlease_test labels ct label set 1
ip netns exec "$ns" env FFN_CTLEASE_ISOLATED_TEST=yes python3 ./test_ctlease.py
