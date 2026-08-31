#!/usr/bin/env python3
"""Generate policy.bin for the FFN dataplane (fp_policy_ent / "FPPO", 32B rows).
Same ABI ffn_fastpath_compile.py emits, so one policy format serves every backend.

  ./mkpolicy.py out.bin  "allow tcp any any:443"  "drop tcp any any:4444"  ...
Grammar:  <allow|inspect|drop|local> <tcp|udp|any> <src|any> <dst|any>[:port]
"""
import struct, sys
FWD, INSPECT, PUNT, DROP, LOCAL = 0, 1, 2, 3, 4
ACT = {"allow": FWD, "forward": FWD, "inspect": INSPECT, "drop": DROP, "local": LOCAL}
PROTO = {"tcp": 6, "udp": 17, "any": 0}

def cidr(t):
    if t in ("any", "0.0.0.0/0"):
        return 0, 0
    net, _, bits = t.partition("/")
    bits = int(bits or 32)
    o = [int(x) for x in net.split(".")]
    ip = (o[0] << 24) | (o[1] << 16) | (o[2] << 8) | o[3]
    mask = ((1 << bits) - 1) << (32 - bits) & 0xFFFFFFFF
    return ip, mask

def be(v):                      # IPv4 fields are network-order bytes in the row
    return struct.unpack("<I", struct.pack(">I", v))[0]

rows = []
for rid, spec in enumerate(sys.argv[2:], start=1):
    p = spec.split()
    act, proto, src, dst = ACT[p[0]], PROTO[p[1]], p[2], p[3]
    dport = 0
    if ":" in dst:
        dst, _, dp = dst.partition(":")
        dport = int(dp)
    sip, smask = cidr(src); dip, dmask = cidr(dst)
    dlo, dhi = (dport, dport) if dport else (0, 65535)
    rows.append(struct.pack("<IIIIHHHHBBBBHH", be(sip), be(smask), be(dip), be(dmask),
                            0, 65535, dlo, dhi, proto, 1, act, 0, 0xFFFF, rid))
body = b"".join(rows)
hdr = struct.pack("<4sHHIQIIII", b"FPPO", 1, 0x40, len(rows), 0, 0, 32, len(rows), 0)
open(sys.argv[1], "wb").write(hdr + body)
print("wrote %s: %d rule(s), %d bytes" % (sys.argv[1], len(rows), len(hdr + body)))
