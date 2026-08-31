#!/usr/bin/env python3
"""ffn_dpring -- the MP side of the FFN dataplane control ring.

This is the piece that was missing: the DP has had a command ring since ABI
v1, but nothing on the management plane could drive it.

Wire format is ffn_dp_abi.h, ABI v2. Everything multi-byte is little-endian,
including on the big-endian MIPS target -- the DP's ld_le*/st_le* accessors
exist precisely so the host does not have to byte-swap.

    0x0000  header, 64 bytes
    0x0040  CMD ring   MP -> DP
    0x1040  EVT ring   DP -> MP
    0x2040  stats
    0x3000  port table, 32 entries x 64 bytes   (v2)
    0x4000  policy bank 0   (4 MiB)
    0x404000 policy bank 1

Rings are single-producer/single-consumer with monotonic 32-bit head/tail;
the MP owns CMD's head and EVT's tail, the DP owns the opposite ends. That is
why no locking appears here -- adding any would be a sign of a
misunderstanding, not of safety.

Port model reference: PAN's own port layer on the 5220
(/opt/dpfs/usr/local/lib64/brdagent/cp/libports.so). Four lifecycle states
rather than a boolean, negotiation mode and media presence as separate axes.

Where the region lives: Octeon DRAM, reached through the BAR1 window. Host
access to that window still needs SPEM0_BAR1_INDEX programming, which is
unresolved -- so `open_bar()` is expected to fail on real hardware today.
`open_file()` works now and is what the tests and the simulator use.
"""
import mmap
import os
import struct
import sys
import time

ABI_MAGIC = b"FFNDP\0"
ABI_VER = 2

OFF_HDR = 0x0000
OFF_CMD_RING = 0x0040
OFF_EVT_RING = 0x1040
OFF_STATS = 0x2040
OFF_PORTS = 0x3000
OFF_BANK0 = 0x4000
BANK_SIZE = 0x400000

RING_DESCS = 64
DESC_SIZE = 32
RING_HDR_SZ = 16

PORT_ENTRY_SZ = 64
MAX_PORTS = 32

# ---- capability bits ----
CAP_PORT_CTL = 1 << 0
CAP_PORT_STATS = 1 << 1
CAP_PORT_HW = 1 << 2

# ---- opcodes (must track ffn_dp_abi.h) ----
CMD_NOP, CMD_PING, CMD_SET_BANK, CMD_GET_STATS, CMD_SET_DEFAULT, \
    CMD_FLUSH_FLOWS, CMD_SHUTDOWN, CMD_PORT_ENUM, CMD_PORT_CONFIG, \
    CMD_PORT_ADMIN, CMD_PORT_STATS = range(11)

EVT_NONE, EVT_PONG, EVT_READY, EVT_STATS, EVT_ERROR, EVT_FLOW_DROP, \
    EVT_PORT_INFO, EVT_PORT_LINK, EVT_PORT_STATS = range(9)

EVT_NAME = {EVT_PONG: "PONG", EVT_READY: "READY", EVT_STATS: "STATS",
            EVT_ERROR: "ERROR", EVT_FLOW_DROP: "FLOW_DROP",
            EVT_PORT_INFO: "PORT_INFO", EVT_PORT_LINK: "PORT_LINK",
            EVT_PORT_STATS: "PORT_STATS"}

# ---- port enums, mirroring PAN's BRD_PORT_TYPE_* ----
PORT_TYPE = {0: "none", 1: "RJ45", 2: "SFP", 3: "SFP+", 4: "QSFP+",
             5: "QSFP28", 6: "XFP", 7: "HA", 8: "internal", 9: "uplink",
             10: "ghost"}
PORT_TYPE_ID = {v.lower(): k for k, v in PORT_TYPE.items()}

PORT_STATE = {0: "reset", 1: "powerdown", 2: "startup", 3: "run"}
PORT_NEG = {0: "autoneg", 1: "forced"}
PORT_MEDIA = {0: "unknown", 1: "absent", 2: "present", 3: "nopop",
              4: "invalid"}

# BGX LMAC_TYPE [10:8]
LMAC_TYPE = {0: "SGMII", 1: "XAUI", 2: "RXAUI", 3: "10G-R", 4: "40G-R",
             5: "QSGMII", 6: "RGMII", 7: "reserved"}

# Port ROLE -- a separate axis from form factor, mirroring PAN_IFHW_TYPE_*.
# HSCI = High Speed Chassis Interconnect, the HA2/HA3 high-speed link. It is
# 40 G Ethernet on a QSFP+ cage, NOT Interlaken: this chip has no ilk* CSRs
# and every live GSERn_CFG has the ILA bit clear.
PORT_ROLE = {0: "data", 1: "HA", 2: "HSCI", 3: "mgmt", 4: "internal",
             5: "AE", 6: "loopback"}
PORT_ROLE_ID = {v.lower(): k for k, v in PORT_ROLE.items()}
BRIDGEABLE_ROLES = {0, 5}          # data, AE


def role_bridgeable(role):
    """Only data and AE ports may carry inspected traffic."""
    if isinstance(role, str):
        role = PORT_ROLE_ID.get(role.lower(), -1)
    return role in BRIDGEABLE_ROLES


F_HAS_LMAC = 1 << 0
F_MGMT = 1 << 1
F_VALID = 1 << 7

# Sensible LMAC_TYPE per form factor, from the 5220's complement.
DEFAULT_LMAC_TYPE = {1: 0, 2: 0, 3: 3, 4: 4, 5: 4, 6: 3, 7: 0, 8: 3}


class DpError(Exception):
    pass


def _pack_cfg(port_type, lmac_type, lane, neg, phy, flags, role=0):
    return ((port_type & 0xFF) | ((lmac_type & 0x7) << 8) |
            ((lane & 0xFF) << 16) | ((neg & 0xFF) << 24) |
            ((phy & 0xFF) << 32) | ((flags & 0xFF) << 40) |
            ((role & 0xFF) << 48))


def _pack_a2(speed, mtu):
    return (speed & 0xFFFFFFFF) | ((mtu & 0xFFFF) << 32)


def _unpack_state(w):
    return {"port_type": PORT_TYPE.get(w & 0xFF, "?"),
            "state": PORT_STATE.get((w >> 8) & 0xFF, "?"),
            "neg": PORT_NEG.get((w >> 16) & 0xFF, "?"),
            "media": PORT_MEDIA.get((w >> 24) & 0xFF, "?"),
            "admin_up": bool((w >> 32) & 1),
            "link_up": bool((w >> 33) & 1),
            "flags": (w >> 40) & 0xFF,
            "role": PORT_ROLE.get((w >> 48) & 0xFF, "?")}


class DpRing:
    """MP-side client for one DP shared region."""

    def __init__(self, mm):
        self.mm = mm

    # ---- construction -------------------------------------------------
    @classmethod
    def open_file(cls, path, size=None):
        fd = os.open(path, os.O_RDWR)
        if size is None:
            size = max(os.fstat(fd).st_size, OFF_BANK0 + 65536)
        mm = mmap.mmap(fd, size, mmap.MAP_SHARED,
                       mmap.PROT_READ | mmap.PROT_WRITE)
        os.close(fd)
        return cls(mm)

    @classmethod
    def open_bar(cls, pci="0000:01:00.0", bar=2, offset=0, size=None):
        """Attach through a PCI BAR window.

        Expected to fail today: the region sits in Octeon DRAM behind the
        BAR1 index register, and host programming of SPEM0_BAR1_INDEX is not
        yet solved (see tools/ffn_octdram.py). Kept so the call site is ready.
        """
        path = "/sys/bus/pci/devices/%s/resource%d" % (pci, bar)
        if not os.path.exists(path):
            raise DpError("no such BAR: %s" % path)
        fd = os.open(path, os.O_RDWR | getattr(os, "O_SYNC", 0))
        try:
            if size is None:
                size = OFF_BANK0 + 65536
            mm = mmap.mmap(fd, size, mmap.MAP_SHARED,
                           mmap.PROT_READ | mmap.PROT_WRITE, offset=offset)
        finally:
            os.close(fd)
        return cls(mm)

    # ---- header -------------------------------------------------------
    def header(self):
        b = self.mm[OFF_HDR:OFF_HDR + 64]
        return {"magic": b[0:6],
                "abi_version": struct.unpack_from("<H", b, 6)[0],
                "dp_state": struct.unpack_from("<I", b, 8)[0],
                "host_state": struct.unpack_from("<I", b, 12)[0],
                "dp_heartbeat": struct.unpack_from("<Q", b, 16)[0],
                "host_heartbeat": struct.unpack_from("<Q", b, 24)[0],
                "active_bank": struct.unpack_from("<I", b, 32)[0],
                "default_dec": struct.unpack_from("<I", b, 36)[0],
                "dp_caps": struct.unpack_from("<I", b, 40)[0],
                "dp_error": struct.unpack_from("<I", b, 44)[0]}

    def handshake(self):
        """Verify magic and version. Refuses rather than guessing."""
        h = self.header()
        if h["magic"] != ABI_MAGIC:
            raise DpError("bad magic %r -- not an FFN DP region" % h["magic"])
        if h["abi_version"] != ABI_VER:
            raise DpError("ABI version %d, this client speaks %d"
                          % (h["abi_version"], ABI_VER))
        return h

    def caps(self):
        return self.header()["dp_caps"]

    def require_port_ctl(self):
        c = self.caps()
        if not c & CAP_PORT_CTL:
            raise DpError("this DP image does not advertise PORT_CTL "
                          "(dp_caps=0x%x) -- refusing to send port commands"
                          % c)
        return c

    # ---- rings --------------------------------------------------------
    def _ring_head(self, base):
        return struct.unpack_from("<I", self.mm, base)[0]

    def _ring_tail(self, base):
        return struct.unpack_from("<I", self.mm, base + 4)[0]

    def _set_head(self, base, v):
        struct.pack_into("<I", self.mm, base, v & 0xFFFFFFFF)

    def _set_tail(self, base, v):
        struct.pack_into("<I", self.mm, base + 4, v & 0xFFFFFFFF)

    def _desc(self, base, idx):
        return base + RING_HDR_SZ + (idx % RING_DESCS) * DESC_SIZE

    def push(self, opcode, a0=0, a1=0, a2=0, flags=0):
        """Enqueue a command. Returns False if the ring is full."""
        base = OFF_CMD_RING
        head, tail = self._ring_head(base), self._ring_tail(base)
        if (head - tail) & 0xFFFFFFFF >= RING_DESCS:
            return False
        o = self._desc(base, head)
        struct.pack_into("<HHIQQQ", self.mm, o, opcode & 0xFFFF,
                         flags & 0xFFFF, head & 0xFFFFFFFF, a0, a1, a2)
        self._set_head(base, head + 1)
        return True

    def pop_event(self):
        """Dequeue one event, or None."""
        base = OFF_EVT_RING
        head, tail = self._ring_head(base), self._ring_tail(base)
        if head == tail:
            return None
        o = self._desc(base, tail)
        op, flags, seq, a0, a1, a2 = struct.unpack_from("<HHIQQQ", self.mm, o)
        self._set_tail(base, tail + 1)
        return {"op": op, "name": EVT_NAME.get(op, "op%d" % op),
                "flags": flags, "seq": seq, "a0": a0, "a1": a1, "a2": a2}

    def drain(self, limit=256):
        out = []
        while len(out) < limit:
            e = self.pop_event()
            if e is None:
                break
            out.append(e)
        return out

    def wait_event(self, op, timeout=2.0, interval=0.01):
        """Wait for a specific event, returning it and any others seen."""
        deadline = time.monotonic() + timeout
        others = []
        while time.monotonic() < deadline:
            e = self.pop_event()
            if e is None:
                time.sleep(interval)
                continue
            if e["op"] == op:
                return e, others
            others.append(e)
        return None, others

    # ---- port table ---------------------------------------------------
    def port_raw(self, i):
        o = OFF_PORTS + (i % MAX_PORTS) * PORT_ENTRY_SZ
        return self.mm[o:o + PORT_ENTRY_SZ]

    def port(self, i):
        b = self.port_raw(i)
        flags = b[15]
        if not flags & F_VALID:
            return None
        # name[16] sits at offset 24, after speed_mbps[4] and mtu[4]
        name = bytes(b[24:40]).split(b"\0")[0].decode("ascii", "replace")
        return {"lport": struct.unpack_from("<H", b, 0)[0],
                "pport": struct.unpack_from("<H", b, 2)[0],
                "bgx": b[4], "lmac": b[5],
                "port_type": PORT_TYPE.get(b[6], "?"),
                "lmac_type": LMAC_TYPE.get(b[7], "?"),
                "lane_to_sds": b[8],
                "state": PORT_STATE.get(b[9], "?"),
                "neg": PORT_NEG.get(b[10], "?"),
                "media": PORT_MEDIA.get(b[11], "?"),
                "admin_up": bool(b[12]), "link_up": bool(b[13]),
                "phy_addr": b[14], "flags": flags,
                "has_lmac": bool(flags & F_HAS_LMAC),
                "mgmt": bool(flags & F_MGMT),
                "speed_mbps": struct.unpack_from("<I", b, 16)[0],
                "mtu": struct.unpack_from("<I", b, 20)[0],
                "name": name,
                "rx_pkts": struct.unpack_from("<Q", b, 40)[0],
                "tx_pkts": struct.unpack_from("<Q", b, 48)[0],
                "role": PORT_ROLE.get(b[56], "?"),
                "bridgeable": role_bridgeable(b[56])}

    def ports(self):
        return [p for p in (self.port(i) for i in range(MAX_PORTS))
                if p is not None]

    # ---- high level ---------------------------------------------------
    def ping(self, token=0xC0FFEE):
        self.push(CMD_PING, token)
        e, _ = self.wait_event(EVT_PONG)
        return e is not None and e["a0"] == token

    def port_config(self, lport, port_type, lmac_type=None, lane=0,
                    neg="autoneg", phy=0xFF, speed=0, mtu=1500,
                    has_lmac=True, mgmt=False, role="data"):
        self.require_port_ctl()
        if isinstance(port_type, str):
            t = PORT_TYPE_ID.get(port_type.lower())
            if t is None:
                raise DpError("unknown port type %r; known: %s"
                              % (port_type,
                                 ", ".join(sorted(PORT_TYPE_ID))))
            port_type = t
        if lmac_type is None:
            lmac_type = DEFAULT_LMAC_TYPE.get(port_type, 0)
        neg_id = {"autoneg": 0, "forced": 1}.get(neg)
        if neg_id is None:
            raise DpError("neg must be 'autoneg' or 'forced'")
        flags = (F_HAS_LMAC if has_lmac else 0) | (F_MGMT if mgmt else 0)
        if isinstance(role, str):
            rid = PORT_ROLE_ID.get(role.lower())
            if rid is None:
                raise DpError("unknown role %r; known: %s"
                              % (role, ", ".join(sorted(PORT_ROLE_ID))))
        else:
            rid = role
        cfg = _pack_cfg(port_type, lmac_type, lane, neg_id, phy, flags, rid)
        if not self.push(CMD_PORT_CONFIG, lport, cfg, _pack_a2(speed, mtu)):
            raise DpError("command ring full")
        return True

    def port_admin(self, lport, up):
        self.require_port_ctl()
        if not self.push(CMD_PORT_ADMIN, lport, 1 if up else 0):
            raise DpError("command ring full")
        return True

    def port_enum(self):
        self.require_port_ctl()
        self.push(CMD_PORT_ENUM)
        return True

    def close(self):
        self.mm.close()


def _fmt_ports(ports):
    if not ports:
        return "  (no ports configured)"
    w = ["  %-4s %-9s %-9s %-7s %-10s %-8s %-6s %-6s %s"
         % ("port", "type", "role", "lmac", "state", "media", "admin", "link",
            "speed")]
    for p in ports:
        lm = ("bgx%d/%d %s" % (p["bgx"], p["lmac"], p["lmac_type"])
              if p["has_lmac"] else "-")
        w.append("  %-4d %-9s %-9s %-7s %-10s %-8s %-6s %-6s %d%s"
                 % (p["lport"], p["port_type"], p["role"], lm, p["state"],
                    p["media"], "up" if p["admin_up"] else "down",
                    "up" if p["link_up"] else "down", p["speed_mbps"],
                    "" if p["bridgeable"] else "  [not bridgeable]"))
    return "\n".join(w)



def _selftest():
    """Validate the wire format from the MP side, with no DP present.

    The point is to catch a disagreement with ffn_dp_abi.h here, rather than
    against live silicon where a field at the wrong offset looks like a
    hardware fault. This caught exactly one real bug: name[16] was being read
    at offset 40 instead of 24.
    """
    import tempfile
    fails = []

    def chk(c, m):
        print(("  ok   " if c else "  FAIL ") + m)
        if not c:
            fails.append(m)

    # ---- layout invariants must agree with the C header ----
    chk(OFF_PORTS + MAX_PORTS * PORT_ENTRY_SZ <= OFF_BANK0,
        "port table fits before bank0")
    chk(RING_HDR_SZ + RING_DESCS * DESC_SIZE <= OFF_EVT_RING - OFF_CMD_RING,
        "cmd ring fits in its slot")
    chk(DESC_SIZE == struct.calcsize("<HHIQQQ"), "descriptor is 32 bytes")
    chk(PORT_ENTRY_SZ == 64, "port entry is 64 bytes")
    chk(CMD_PORT_CONFIG == 8 and CMD_PORT_ADMIN == 9,
        "port opcodes follow SHUTDOWN in ABI order")
    chk(EVT_PORT_INFO == 6 and EVT_PORT_STATS == 8,
        "port events follow FLOW_DROP in ABI order")

    path = os.path.join(tempfile.mkdtemp(), "region.bin")
    with open(path, "wb") as f:
        f.write(bytes(OFF_BANK0 + 65536))
    r = DpRing.open_file(path)
    try:
        # ---- handshake must refuse an unformatted region ----
        try:
            r.handshake()
            chk(False, "handshake should refuse a zeroed region")
        except DpError as e:
            chk("magic" in str(e), "handshake refuses a zeroed region")

        struct.pack_into("<6sH", r.mm, OFF_HDR, ABI_MAGIC, ABI_VER)
        struct.pack_into("<I", r.mm, OFF_HDR + 40,
                         CAP_PORT_CTL | CAP_PORT_STATS)
        chk(r.handshake()["abi_version"] == 2, "handshake accepts v2")

        # ---- a version mismatch is refused, not tolerated ----
        struct.pack_into("<H", r.mm, OFF_HDR + 6, 99)
        try:
            r.handshake()
            chk(False, "version mismatch should be refused")
        except DpError as e:
            chk("ABI version" in str(e), "version mismatch is refused")
        struct.pack_into("<H", r.mm, OFF_HDR + 6, ABI_VER)

        # ---- capability gating ----
        chk(r.require_port_ctl() & CAP_PORT_CTL, "PORT_CTL gate passes")
        struct.pack_into("<I", r.mm, OFF_HDR + 40, 0)
        try:
            r.port_admin(0, True)
            chk(False, "should refuse without PORT_CTL")
        except DpError as e:
            chk("PORT_CTL" in str(e),
                "port commands refused when the DP lacks PORT_CTL")
        struct.pack_into("<I", r.mm, OFF_HDR + 40, CAP_PORT_CTL)

        # ---- descriptor encoding is what the C side reads ----
        chk(r.push(CMD_PORT_CONFIG, 3, 0x1122334455, 0x66778899),
            "push a PORT_CONFIG")
        o = OFF_CMD_RING + RING_HDR_SZ
        op, fl, seq, a0, a1, a2 = struct.unpack_from("<HHIQQQ", r.mm, o)
        chk(op == CMD_PORT_CONFIG and a0 == 3 and a1 == 0x1122334455
            and a2 == 0x66778899, "descriptor round-trips through the ring")
        chk(struct.unpack_from("<I", r.mm, OFF_CMD_RING)[0] == 1,
            "cmd head advanced to 1")

        # ---- a full ring is reported, never silently dropped ----
        for _ in range(RING_DESCS):
            r.push(CMD_NOP)
        chk(r.push(CMD_NOP) is False, "a full ring reports False")

        # ---- packing matches the C macros ----
        w = _pack_cfg(3, 3, 0x00, 1, 0xFF, F_HAS_LMAC)
        chk((w & 0xFF) == 3 and ((w >> 8) & 7) == 3
            and ((w >> 24) & 0xFF) == 1 and ((w >> 32) & 0xFF) == 0xFF,
            "cfg word packs type/lmac_type/neg/phy")
        a2w = _pack_a2(10000, 9216)
        chk((a2w & 0xFFFFFFFF) == 10000 and ((a2w >> 32) & 0xFFFF) == 9216,
            "a2 packs speed and mtu")
        chk(DEFAULT_LMAC_TYPE[3] == 3 and DEFAULT_LMAC_TYPE[4] == 4,
            "SFP+ defaults to 10G-R and QSFP+ to 40G-R")

        # ---- port entry decode, at the C struct's offsets ----
        po = OFF_PORTS
        struct.pack_into("<HH", r.mm, po, 5, 11)
        for off, val in ((4, 2), (5, 1), (6, 3), (7, 3), (8, 0x01), (9, 3),
                         (10, 1), (11, 2), (12, 1), (13, 1), (14, 0xFF),
                         (15, F_VALID | F_HAS_LMAC)):
            r.mm[po + off] = val
        struct.pack_into("<I", r.mm, po + 16, 10000)
        struct.pack_into("<I", r.mm, po + 20, 9216)
        nm = "ethernet1/1".encode()
        r.mm[po + 24:po + 40] = nm + bytes(16 - len(nm))
        struct.pack_into("<Q", r.mm, po + 40, 1234)
        struct.pack_into("<Q", r.mm, po + 48, 5678)

        p = r.port(0)
        chk(p is not None, "a valid entry decodes")
        chk(p["lport"] == 5 and p["pport"] == 11, "lport/pport decode")
        chk(p["port_type"] == "SFP+" and p["lmac_type"] == "10G-R",
            "form factor and LMAC type decode")
        chk(p["bgx"] == 2 and p["lmac"] == 1 and p["has_lmac"],
            "bgx/lmac decode")
        chk(p["state"] == "run" and p["neg"] == "forced"
            and p["media"] == "present", "state/neg/media decode")
        chk(p["speed_mbps"] == 10000 and p["mtu"] == 9216,
            "speed and mtu decode")
        chk(p["name"] == "ethernet1/1", "name decodes at offset 24")
        chk(p["rx_pkts"] == 1234 and p["tx_pkts"] == 5678,
            "counters decode at 40/48")
        chk(len(r.ports()) == 1, "only valid entries are listed")

        r.mm[po + 15] = F_HAS_LMAC
        chk(r.port(0) is None and r.ports() == [],
            "an entry without F_VALID is ignored")

        # ---- event decode ----
        eo = OFF_EVT_RING
        struct.pack_into("<HHIQQQ", r.mm, eo + RING_HDR_SZ,
                         EVT_PORT_LINK, 0, 0, 5, 1, 2)
        struct.pack_into("<I", r.mm, eo, 1)
        e = r.pop_event()
        chk(e is not None and e["name"] == "PORT_LINK" and e["a0"] == 5,
            "event decodes and the tail advances")
        chk(r.pop_event() is None, "event ring drains")

        # ---- unknown port type refused rather than coerced ----
        struct.pack_into("<I", r.mm, OFF_HDR + 40, CAP_PORT_CTL)
        try:
            r.port_config(0, "banana")
            chk(False, "an unknown port type should be refused")
        except DpError as e:
            chk("unknown port type" in str(e),
                "an unknown port type is refused")
    finally:
        r.close()

    print("")
    print("==== ffn_dpring selftest: %d failed ====" % len(fails))
    return 1 if fails else 0


def main():
    a = sys.argv[1:]
    if "--selftest" in a:
        return _selftest()
    if not a or "--help" in a:
        print(__doc__.strip().split("\n")[0])
        print()
        print("usage: ffn_dpring.py --file <region> [--ports] [--ping]")
        print("       ffn_dpring.py --bar [--pci B:D.F] [--ports]")
        return 0
    try:
        if "--file" in a:
            r = DpRing.open_file(a[a.index("--file") + 1])
        else:
            pci = a[a.index("--pci") + 1] if "--pci" in a else "0000:01:00.0"
            r = DpRing.open_bar(pci)
    except (OSError, DpError) as e:
        print("cannot attach: %s" % e)
        return 1

    try:
        h = r.handshake()
        caps = h["dp_caps"]
        print("region OK: ABI v%d  dp_state=%d  active_bank=%d  caps=0x%x"
              % (h["abi_version"], h["dp_state"], h["active_bank"], caps))
        print("  PORT_CTL=%s PORT_STATS=%s PORT_HW=%s"
              % (bool(caps & CAP_PORT_CTL), bool(caps & CAP_PORT_STATS),
                 bool(caps & CAP_PORT_HW)))
        if not caps & CAP_PORT_HW:
            print("  NOTE: PORT_HW is not advertised -- the DP tracks port "
                  "state but drives no registers (needs CVMX).")
        if "--ping" in a:
            print("ping: %s" % ("ok" if r.ping() else "no PONG"))
        if "--ports" in a:
            print()
            print(_fmt_ports(r.ports()))
    except DpError as e:
        print("handshake failed: %s" % e)
        return 1
    finally:
        r.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
