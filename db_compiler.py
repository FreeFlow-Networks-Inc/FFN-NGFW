#!/usr/bin/env python3
"""
db_compiler.py -- Universal database compiler for the FFN-NGFW-FPGA.

Compiles text-format database files into binary table images and loads
them into the FPGA over /dev/ngfw0 (BRAM via TBL_WRITE / IP_CFG_WRITE,
DDR4 via DDR_WRITE).

Supports all 15 database types used by the 31-engine NGFW pipeline:
  BRAM:  appid, zones, ddos_pps, policy, app_policy, qos
  DDR4:  threats, url, geoip, blocklist, dns_blocklist,
         malware_hashes, file_magic, tls_fingerprints, spyware_iocs

Usage:
  db_compiler.py compile  <type> <input.txt> [--output out.bin]
  db_compiler.py load     <type> <input.txt> [--vsys N]
  db_compiler.py update   <type> <input.txt> [--vsys N]
  db_compiler.py list
"""

import argparse
import ctypes
import hashlib
import ipaddress
import json
import os
import struct
import sys
import time
import zlib
from pathlib import Path

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

NGFW_DEV_PATH = os.getenv("FFN_NGFW_DEV", "/dev/ngfw0")
DB_META_PATH = os.getenv("FFN_DB_META", "/var/lib/ffn-ngfw/db_meta.json")

# Binary file header: magic(4) + version(2) + db_type(2) + entry_count(4) +
#                     timestamp(8) + checksum(4) + reserved(8) = 32 bytes
BIN_MAGIC = b"FFND"
BIN_VERSION = 2
BIN_HEADER_SIZE = 32

# ioctl constants -- these match the kernel driver definitions in ngfw_regs.h
# _IOW('N', 0x03, struct ngfw_tbl_write)   -> 16 bytes payload
# _IOW('N', 0x09, struct ngfw_ddr_xfer)    -> 32 bytes payload
# _IOW('N', 0x10, struct ngfw_ip_cfg_write) -> 16 bytes payload
NGFW_IOC_MAGIC = ord("N")

def _iow(nr, size):
    """Compute linux _IOW ioctl number: direction=1 (write), type='N'."""
    return (1 << 30) | (size << 16) | (NGFW_IOC_MAGIC << 8) | nr

def _iowr(nr, size):
    """Compute linux _IOWR ioctl number."""
    return (3 << 30) | (size << 16) | (NGFW_IOC_MAGIC << 8) | nr

# struct ngfw_tbl_write { u8 table_id; u16 index; u64 data; } = 11 padded->16
SIZEOF_TBL_WRITE = 16
NGFW_IOC_TBL_WRITE = _iow(0x03, SIZEOF_TBL_WRITE)

# struct ngfw_ip_cfg_write { u8 table_id; u16 addr; u32 data; u32 data_hi; } = 16
SIZEOF_IP_CFG_WRITE = 16
NGFW_IOC_IP_CFG_WRITE = _iow(0x10, SIZEOF_IP_CFG_WRITE)

# struct ngfw_ddr_xfer { u32 region; u64 offset; u64 length; ptr buf; } = 32
SIZEOF_DDR_XFER = 32
NGFW_IOC_DDR_WRITE = _iow(0x09, SIZEOF_DDR_XFER)

# FPGA table IDs from ngfw_regs.h
NGFW_TBL_DDOS_ZONE_MAP   = 0x00
NGFW_TBL_DDOS_THRESHOLDS = 0x01
NGFW_TBL_DDOS_IP_BLOCKLIST = 0x02
NGFW_TBL_DDOS_GEOIP      = 0x03
NGFW_TBL_DDOS_SYN_SEED   = 0x04
NGFW_TBL_SEC_POLICY       = 0x05
NGFW_TBL_APPID            = 0x06
NGFW_TBL_CID_THREAT       = 0x07
NGFW_TBL_CID_URL          = 0x08
NGFW_TBL_CID_SPYWARE      = 0x09
NGFW_TBL_USER_POLICY      = 0x0A
NGFW_TBL_APP_POLICY       = 0x0B
NGFW_TBL_CID_FILE_MASK    = 0x0C
NGFW_TBL_RATE_LIMITER      = 0x0D
NGFW_TBL_SESSION_INSERT    = 0x0E
NGFW_TBL_BLOOM_PROGRAM     = 0x0F

# IP config bus table IDs (>= 0x10) -- used with NGFW_IOC_IP_CFG_WRITE
NGFW_TBL_DPI_BRAM          = 0x10
NGFW_TBL_URL_BLOOM         = 0x12
NGFW_TBL_DNS_BLOOM         = 0x13
NGFW_TBL_DLP_ENGINE        = 0x14   # DLP data-pattern table
NGFW_TBL_TCAM_POLICY       = 0x1A

# DDR4 region IDs from enum ngfw_ddr_region
NGFW_RGN_GEOIP     = 6
NGFW_RGN_BLOCKLIST = 7
NGFW_RGN_URL       = 8
NGFW_RGN_THREATS   = 10
NGFW_RGN_MALWARE   = 11
NGFW_RGN_FILEMAGIC = 12
NGFW_RGN_TLSFP     = 13
NGFW_RGN_DNSBL     = 14
NGFW_RGN_SPYWARE   = 15

# Bloom filter parameters
BLOOM_FILTER_BITS = 65536   # 8 KB bloom filter per engine
BLOOM_NUM_HASHES  = 3       # k=3

# Protocol name -> number
PROTO_MAP = {
    "any": 0, "tcp": 6, "udp": 17, "icmp": 1, "gre": 47,
    "esp": 50, "ah": 51, "sctp": 132,
}

# ---------------------------------------------------------------------------
# FPGA device handle
# ---------------------------------------------------------------------------

class FPGADevice:
    """Thin wrapper for /dev/ngfw0 ioctl calls via ctypes."""

    def __init__(self, dev_path=NGFW_DEV_PATH):
        self._fd = None
        self._sim = False
        self._dev_path = dev_path
        try:
            self._fd = os.open(dev_path, os.O_RDWR)
        except OSError:
            self._sim = True

    def close(self):
        if self._fd is not None:
            os.close(self._fd)
            self._fd = None

    def _ioctl(self, cmd, buf):
        if self._sim:
            return buf
        import fcntl
        return fcntl.ioctl(self._fd, cmd, buf)

    def tbl_write(self, table_id, index, data):
        """Write a single BRAM table entry (tables 0x00-0x0F)."""
        # Pack: u8 table_id, u8 pad, u16 index, u32 pad, u64 data
        buf = struct.pack("<BBHIQ", table_id, 0, index & 0xFFFF, 0, data & 0xFFFFFFFFFFFFFFFF)
        self._ioctl(NGFW_IOC_TBL_WRITE, buf)

    def ip_cfg_write(self, table_id, addr, data_lo, data_hi=0):
        """Write via the IP config bus (tables >= 0x10)."""
        buf = struct.pack("<BBHII", table_id, 0, addr & 0xFFFF, data_lo & 0xFFFFFFFF, data_hi & 0xFFFFFFFF)
        self._ioctl(NGFW_IOC_IP_CFG_WRITE, buf)

    def ddr_write(self, region, offset, data_bytes):
        """Write a block of bytes into a DDR4 region."""
        length = len(data_bytes)
        # Allocate a ctypes buffer so we can pass a real pointer
        cbuf = ctypes.create_string_buffer(data_bytes)
        ptr_val = ctypes.addressof(cbuf)
        # struct ngfw_ddr_xfer: u32 region, u32 pad, u64 offset, u64 length, u64 ptr
        xfer = struct.pack("<IIQQq", region, 0, offset, length, ptr_val)
        self._ioctl(NGFW_IOC_DDR_WRITE, xfer)
        # keep cbuf alive through the ioctl
        del cbuf

    def bloom_set_bit(self, bloom_table_id, bit_index):
        """Set a single bit in a BRAM-based bloom filter."""
        word_idx = bit_index // 64
        bit_pos = bit_index % 64
        data = 1 << bit_pos
        self.tbl_write(NGFW_TBL_BLOOM_PROGRAM, word_idx, data)

    @property
    def sim_mode(self):
        return self._sim


# ---------------------------------------------------------------------------
# Metadata store
# ---------------------------------------------------------------------------

def _load_meta():
    try:
        with open(DB_META_PATH, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

def _save_meta(meta):
    os.makedirs(os.path.dirname(DB_META_PATH), exist_ok=True)
    with open(DB_META_PATH, "w") as f:
        json.dump(meta, f, indent=2)

def _update_meta(db_type, entry_count, checksum, file_path, vsys=0):
    meta = _load_meta()
    key = f"{db_type}:vsys{vsys}"
    meta[key] = {
        "type": db_type,
        "vsys": vsys,
        "entry_count": entry_count,
        "checksum": checksum,
        "file_path": str(file_path),
        "last_loaded": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    _save_meta(meta)

# ---------------------------------------------------------------------------
# Binary format helpers
# ---------------------------------------------------------------------------

def _make_header(db_type_id, entry_count, payload_crc):
    """Build a 32-byte binary file header."""
    ts = int(time.time())
    hdr = struct.pack(
        "<4sHHIQI8s",
        BIN_MAGIC,           # 4 bytes magic
        BIN_VERSION,         # 2 bytes version
        db_type_id & 0xFFFF, # 2 bytes type
        entry_count,         # 4 bytes count
        ts,                  # 8 bytes unix timestamp
        payload_crc,         # 4 bytes CRC32
        b"\x00" * 8,         # 8 bytes reserved
    )
    return hdr

def _crc32(data):
    return zlib.crc32(data) & 0xFFFFFFFF

def _bloom_hashes(value_bytes, num_bits=BLOOM_FILTER_BITS):
    """Return BLOOM_NUM_HASHES bit positions for a value."""
    h1 = _crc32(value_bytes)
    h2 = _crc32(value_bytes + b"\x01")
    positions = []
    for i in range(BLOOM_NUM_HASHES):
        pos = (h1 + i * h2) % num_bits
        positions.append(pos)
    return positions

def _fnv1a_64(data):
    """FNV-1a 64-bit hash."""
    h = 0xCBF29CE484222325
    for b in data:
        h ^= b
        h = (h * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    return h

def _ip_to_int(ip_str):
    return int(ipaddress.ip_address(ip_str.strip()))

def _net_to_int(cidr_str):
    net = ipaddress.ip_network(cidr_str.strip(), strict=False)
    return int(net.network_address), net.prefixlen

def _parse_lines(path):
    """Yield non-empty, non-comment lines from a text file."""
    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                yield line

# ---------------------------------------------------------------------------
# Database type registry
# ---------------------------------------------------------------------------

DB_TYPE_IDS = {
    "appid":            1,
    "zones":            2,
    "ddos_pps":         3,
    "policy":           4,
    "app_policy":       5,
    "qos":              6,
    "threats":          7,
    "url":              8,
    "geoip":            9,
    "blocklist":       10,
    "dns_blocklist":   11,
    "malware_hashes":  12,
    "file_magic":      13,
    "tls_fingerprints":14,
    "spyware_iocs":    15,
    "dlp":             16,
}

# ---------------------------------------------------------------------------
# Compilers -- each returns (entries_list, binary_payload)
# entries_list: list of (index, data_64) for BRAM or raw bytes for DDR4
# ---------------------------------------------------------------------------

def compile_appid(path):
    """App-ID: <proto> <port_low>-<port_high> <app_id> <app_name>"""
    entries = []
    for line in _parse_lines(path):
        parts = line.split()
        if len(parts) < 4:
            continue
        proto_str = parts[0]
        port_range = parts[1]
        app_id = int(parts[2])
        # app_name = parts[3]  -- stored only for reference
        proto_num = PROTO_MAP.get(proto_str.lower(), 0)

        if "-" in port_range:
            lo, hi = port_range.split("-")
            lo, hi = int(lo), int(hi)
        else:
            lo = hi = int(port_range)

        for port in range(lo, min(hi + 1, lo + 64)):
            # Index: { proto[7:0], port[15:0] } hashed to 16-bit
            idx = ((proto_num & 0xFF) << 8) ^ (port & 0xFFFF)
            idx = idx & 0xFFFF
            # Data: [15:0]=app_id, [16]=valid, [23:17]=proto
            data = (1 << 16) | ((proto_num & 0x7F) << 17) | (app_id & 0xFFFF)
            entries.append((idx, data))

    payload = b"".join(struct.pack("<HQ", idx, d) for idx, d in entries)
    return entries, payload


def compile_zones(path):
    """Zones: <zone_id> <port> <vlan> <name>"""
    entries = []
    for line in _parse_lines(path):
        parts = line.split()
        if len(parts) < 4:
            continue
        zone_id = int(parts[0]) & 0xFF
        port = int(parts[1]) & 3
        vlan = int(parts[2]) & 0xFFF
        # Key = { port[1:0], vlan_id[11:0] } = 14-bit index
        key = (port << 12) | vlan
        # Data: [8]=valid, [7:0]=zone_id
        data = (1 << 8) | zone_id
        entries.append((key, data))

    payload = b"".join(struct.pack("<HQ", idx, d) for idx, d in entries)
    return entries, payload


def compile_ddos_pps(path):
    """DDoS PPS thresholds: <zone_id> <threshold>"""
    entries = []
    for line in _parse_lines(path):
        parts = line.split()
        if len(parts) < 2:
            continue
        zone_id = int(parts[0]) & 0xFF
        threshold = int(parts[1])
        # Data: [31:0]=threshold, [32]=valid
        data = (1 << 32) | (threshold & 0xFFFFFFFF)
        entries.append((zone_id, data))

    payload = b"".join(struct.pack("<HQ", idx, d) for idx, d in entries)
    return entries, payload


def compile_policy(path):
    """Security policy:
    <id> <src_cidr> <dst_cidr> <proto> <sport_range> <dport_range> <action>
    """
    entries = []
    for line in _parse_lines(path):
        parts = line.split()
        if len(parts) < 7:
            continue
        rule_id = int(parts[0])
        src_ip, src_pfx = _net_to_int(parts[1])
        dst_ip, dst_pfx = _net_to_int(parts[2])
        proto_str = parts[3]
        sport_range = parts[4]
        dport_range = parts[5]
        action = parts[6]

        proto_num = PROTO_MAP.get(proto_str.lower(), 0)
        sp_lo, sp_hi = (0, 65535)
        if "-" in sport_range:
            sp_lo, sp_hi = [int(x) for x in sport_range.split("-")]
        dp_lo, dp_hi = (0, 65535)
        if "-" in dport_range:
            dp_lo, dp_hi = [int(x) for x in dport_range.split("-")]

        action_val = {"allow": 1, "permit": 1, "deny": 0, "log": 2, "punt": 3}.get(
            action.lower(), 0
        )
        # TCAM entry: encode as two 64-bit words (match + mask)
        # Word 0 (match): src_ip[31:0] in high bits, dst_ip[31:0] in low
        match_word = ((src_ip & 0xFFFFFFFF) << 32) | (dst_ip & 0xFFFFFFFF)
        # Word 1 (action/meta):
        #   [63]=valid, [62:61]=action, [60:56]=src_pfx, [55:51]=dst_pfx,
        #   [50:43]=proto, [42:27]=dp_lo, [26:11]=sp_lo, [10:3]=dp_hi>>8,
        #   [2:0]=rule_id lower bits (for priority ordering)
        meta = (1 << 63)
        meta |= (action_val & 0x3) << 61
        meta |= (src_pfx & 0x1F) << 56
        meta |= (dst_pfx & 0x1F) << 51
        meta |= (proto_num & 0xFF) << 43
        meta |= (dp_lo & 0xFFFF) << 27
        meta |= (sp_lo & 0xFFFF) << 11
        meta |= (dp_hi >> 8) & 0x7FF

        # Two entries per rule: index N = match, index N+1 = meta
        base_idx = len(entries) // 2
        entries.append((base_idx * 2, match_word))
        entries.append((base_idx * 2 + 1, meta))

    payload = b"".join(struct.pack("<HQ", idx, d) for idx, d in entries)
    return entries, payload


def compile_app_policy(path):
    """Application policy: <app_id> <action> <log_level> <max_bps>"""
    entries = []
    for line in _parse_lines(path):
        parts = line.split()
        if len(parts) < 4:
            continue
        app_id = int(parts[0])
        action = parts[1]
        log_level = int(parts[2])
        max_bps = int(parts[3])

        action_val = {"allow": 1, "permit": 1, "deny": 0, "log": 2, "punt": 3}.get(
            action.lower(), 0
        )
        # Data: [63]=valid, [62:61]=action, [60:59]=log_level,
        #       [58:27]=max_bps(scaled to KB/s), [15:0]=app_id
        bps_scaled = (max_bps // 1000) & 0xFFFFFFFF
        data = (1 << 63)
        data |= (action_val & 0x3) << 61
        data |= (log_level & 0x3) << 59
        data |= (bps_scaled & 0xFFFFFFFF) << 27
        data |= app_id & 0xFFFF
        entries.append((app_id & 0xFFFF, data))

    payload = b"".join(struct.pack("<HQ", idx, d) for idx, d in entries)
    return entries, payload


def compile_qos(path):
    """QoS weights: <port> <queue> <weight>"""
    entries = []
    for line in _parse_lines(path):
        parts = line.split()
        if len(parts) < 3:
            continue
        port = int(parts[0]) & 0x3
        queue = int(parts[1]) & 0x7
        weight = int(parts[2]) & 0xFF

        # Index: { port[1:0], queue[2:0] } = 5-bit key
        idx = (port << 3) | queue
        # Data: [8]=valid, [7:0]=weight
        data = (1 << 8) | weight
        entries.append((idx, data))

    payload = b"".join(struct.pack("<HQ", idx, d) for idx, d in entries)
    return entries, payload


def compile_threats(path):
    """Threat signatures: <sig_id> <pattern_hex> <severity> <name>
    Produces DDR4 binary + BRAM bloom filter entries.
    """
    ddr_entries = []
    bloom_bits = set()
    for line in _parse_lines(path):
        parts = line.split(None, 3)
        if len(parts) < 3:
            continue
        sig_id = int(parts[0])
        pattern_hex = parts[1]
        severity = int(parts[2])

        # Normalize: pad odd-length hex to even, truncate to 4 bytes for
        # the FPGA 32-bit fast-match engine
        if len(pattern_hex) % 2:
            pattern_hex = pattern_hex + "0"
        pattern_bytes = bytes.fromhex(pattern_hex[:8])  # first 4 bytes
        pattern_val = int.from_bytes(pattern_bytes.ljust(4, b"\x00"),
                                     "big") & 0xFFFFFFFF

        # DDR4 entry: 8 bytes = sig_id(2) + severity(1) + flags(1) + pattern(4)
        entry = struct.pack("<HBBI", sig_id, severity, 0x01, pattern_val)
        ddr_entries.append(entry)

        # Bloom filter bits for the DPI BRAM
        for pos in _bloom_hashes(pattern_bytes):
            bloom_bits.add(pos)

    payload = b"".join(ddr_entries)
    return (ddr_entries, bloom_bits), payload


def compile_url(path):
    """URL categories: <url_pattern>
    Produces DDR4 hash table + BRAM bloom filter entries.
    """
    ddr_entries = []
    bloom_bits = set()

    # Category detection from the file or from URL patterns
    cat_map = {
        "malicious": 3, "evil": 3, "malware": 3, "ransomware": 3,
        "phishing": 4, "fake": 4, "verify": 4, "secure-login": 4,
        "tor": 6, "vpn": 6, "proxy": 6, "hidemyass": 6,
        "coinhive": 10, "crypto": 10, "webmine": 10, "minero": 10,
        "authedmine": 10,
        "doubleclick": 9, "adservice": 9, "googletag": 9,
        "google-analytics": 9, "googlesyndication": 9, "facebook.com/tr": 9,
        "adult": 1,
        "gambling": 2,
        "youtube": 8, "netflix": 8, "disney": 8, "hulu": 8, "twitch": 8,
        "facebook": 7, "twitter": 7, "instagram": 7, "tiktok": 7,
        "linkedin": 7, "snapchat": 7,
        "microsoft": 100, "windowsupdate": 100, "google.com": 100,
        "apple.com": 100, "ubuntu": 100, "redhat": 100, "github": 100,
        "gitlab": 100, "stackoverflow": 100,
    }

    for line in _parse_lines(path):
        url = line.strip()
        # Determine category
        cat_id = 0
        for key, cid in cat_map.items():
            if key in url.lower():
                cat_id = cid
                break

        url_bytes = url.encode("utf-8")
        url_hash = _fnv1a_64(url_bytes)
        md5_hash = hashlib.md5(url_bytes).digest()
        md5_32 = struct.unpack("<I", md5_hash[:4])[0]

        # DDR4 entry: 8 bytes = hash_lo(4) + cat(1) + flags(1) + md5_check(2)
        entry = struct.pack(
            "<IBBH",
            url_hash & 0xFFFFFFFF,
            cat_id & 0xFF,
            0x01,  # valid flag
            md5_32 & 0xFFFF,
        )
        ddr_entries.append(entry)

        # Bloom filter bits
        for pos in _bloom_hashes(url_bytes):
            bloom_bits.add(pos)

    payload = b"".join(ddr_entries)
    return (ddr_entries, bloom_bits), payload


def compile_geoip(path):
    """GeoIP: <CIDR> <country_code>
    Produces DDR4 binary.
    """
    ddr_entries = []
    for line in _parse_lines(path):
        parts = line.split()
        if len(parts) < 2:
            continue
        cidr = parts[0]
        cc = parts[1].strip()[:2].upper()

        net = ipaddress.ip_network(cidr, strict=False)
        ip_int = int(net.network_address)
        pfx = net.prefixlen
        cc_val = (ord(cc[0]) << 8) | ord(cc[1]) if len(cc) == 2 else 0

        # DDR4 entry: 8 bytes = ip(4) + pfx(1) + cc(2) + flags(1)
        entry = struct.pack("<IBHB", ip_int, pfx, cc_val, 0x01)
        ddr_entries.append(entry)

    payload = b"".join(ddr_entries)
    return ddr_entries, payload


def compile_blocklist(path):
    """IP blocklist: one IPv4 per line.
    Produces DDR4 binary + BRAM bloom filter entries.
    """
    ddr_entries = []
    bloom_bits = set()
    for line in _parse_lines(path):
        ip_str = line.split()[0]
        ip_int = _ip_to_int(ip_str)

        # DDR4 entry: 16 bytes = ip(4) + timestamp(4) + reason_hash(4) + flags(4)
        ts = int(time.time()) & 0xFFFFFFFF
        entry = struct.pack("<IIII", ip_int, ts, 0, 0x00000001)
        ddr_entries.append(entry)

        # Bloom filter
        ip_bytes = struct.pack(">I", ip_int)
        for pos in _bloom_hashes(ip_bytes):
            bloom_bits.add(pos)

    payload = b"".join(ddr_entries)
    return (ddr_entries, bloom_bits), payload


def compile_dns_blocklist(path):
    """DNS blocklist: one domain per line.
    Produces DDR4 binary + BRAM bloom filter entries.
    """
    ddr_entries = []
    bloom_bits = set()
    for line in _parse_lines(path):
        domain = line.strip().lower()
        domain_bytes = domain.encode("utf-8")
        fnv_hash = _fnv1a_64(domain_bytes)

        # DDR4 entry: 12 bytes = hash_lo(4) + hash_hi(4) + flags(4)
        entry = struct.pack(
            "<III",
            fnv_hash & 0xFFFFFFFF,
            (fnv_hash >> 32) & 0xFFFFFFFF,
            0x00000001,  # valid
        )
        ddr_entries.append(entry)

        # Bloom filter
        for pos in _bloom_hashes(domain_bytes):
            bloom_bits.add(pos)

    payload = b"".join(ddr_entries)
    return (ddr_entries, bloom_bits), payload


def compile_malware_hashes(path):
    """Malware SHA-256 hashes: <sha256_hex> [<name>]
    Produces DDR4 binary.
    """
    ddr_entries = []
    for line in _parse_lines(path):
        parts = line.split(None, 1)
        if not parts:
            continue
        sha_hex = parts[0].strip()
        if len(sha_hex) != 64:
            continue
        sha_bytes = bytes.fromhex(sha_hex)

        # DDR4 entry: 32 bytes = sha256(32)
        ddr_entries.append(sha_bytes)

    payload = b"".join(ddr_entries)
    return ddr_entries, payload


def compile_file_magic(path):
    """File magic: <magic_hex_8bytes> <category> <action>
    Produces DDR4 binary.
    """
    ddr_entries = []
    for line in _parse_lines(path):
        parts = line.split()
        if len(parts) < 3:
            continue
        magic_hex = parts[0].replace("_", "")
        category = int(parts[1])
        action_str = parts[2]
        action_val = {"allow": 0, "log": 1, "deny": 2, "punt": 3}.get(
            action_str.lower(), 0
        )

        # Pad or truncate to 8 bytes
        magic_bytes = bytes.fromhex(magic_hex)[:8].ljust(8, b"\x00")

        # DDR4 entry: 12 bytes = magic(8) + category(1) + action(1) + flags(2)
        entry = magic_bytes + struct.pack("<BBH", category, action_val, 0x0001)
        ddr_entries.append(entry)

    payload = b"".join(ddr_entries)
    return ddr_entries, payload


def compile_tls_fingerprints(path):
    """TLS (JA3) fingerprints: <ja3_md5_hex> <category> <name>
    Produces DDR4 binary.
    """
    ddr_entries = []
    for line in _parse_lines(path):
        parts = line.split(None, 2)
        if len(parts) < 3:
            continue
        ja3_hex = parts[0].strip()
        category = int(parts[1])
        # name = parts[2]

        if len(ja3_hex) != 32:
            continue
        ja3_bytes = bytes.fromhex(ja3_hex)

        # DDR4 entry: 20 bytes = ja3(16) + category(1) + flags(1) + reserved(2)
        entry = ja3_bytes + struct.pack("<BBH", category, 0x01, 0)
        ddr_entries.append(entry)

    payload = b"".join(ddr_entries)
    return ddr_entries, payload


def compile_spyware_iocs(path):
    """Spyware IOCs: <type> <value> <family> <action>
    Produces DDR4 binary.
    """
    IOC_TYPE_MAP = {"ip": 1, "domain": 2, "sni": 3, "uri": 4,
                    "ja3": 5, "useragent": 6}

    ddr_entries = []
    for line in _parse_lines(path):
        parts = line.split(None, 3)
        if len(parts) < 4:
            continue
        ioc_type_str = parts[0].strip().lower()
        ioc_value = parts[1].strip()
        # family = parts[2]
        action_str = parts[3].strip().lower()

        ioc_type = IOC_TYPE_MAP.get(ioc_type_str, 0)
        action_val = {"deny": 2, "log": 1, "allow": 0}.get(action_str, 1)

        value_bytes = ioc_value.encode("utf-8")
        value_hash = _fnv1a_64(value_bytes)

        # DDR4 entry: 16 bytes = hash(8) + type(1) + action(1) + flags(1)
        #              + value_len(1) + value_prefix(4)
        prefix = value_bytes[:4].ljust(4, b"\x00")
        entry = struct.pack(
            "<QBBBB",
            value_hash,
            ioc_type,
            action_val,
            0x01,  # valid
            min(len(value_bytes), 255),
        ) + prefix
        ddr_entries.append(entry)

    payload = b"".join(ddr_entries)
    return ddr_entries, payload


# ---------------------------------------------------------------------------
# Compiler dispatch
# ---------------------------------------------------------------------------

# DLP (Data Loss Prevention) codes. Built-in data identifiers run as dedicated
# FPGA format detectors (e.g. credit_card = Luhn-checked PAN); keyword / regex
# are matched by the content engine (DPI Aho-Corasick / regex) and referenced
# by a fingerprint. Action BLOCKS the transfer so the data can't leave.
DLP_DETECTOR  = {"credit_card": 1, "ssn": 2, "api_key": 3, "email": 4,
                 "keyword": 8, "regex": 9, "custom": 10}
DLP_BUILTIN   = {"credit_card", "ssn", "api_key", "email"}
DLP_ACTION    = {"alert": 0, "log": 1, "block": 2, "quarantine": 3}
DLP_DIRECTION = {"egress": 1, "ingress": 2, "both": 3}
DLP_SEVERITY  = {"low": 1, "medium": 2, "high": 3}


def compile_dlp(path):
    """DLP rules -> DLP_ENGINE (table 0x14, IP-cfg bus).

    Data Loss Prevention detects sensitive data (PII / PCI / secrets) in flow
    CONTENT and acts to keep it from leaving the network. Each rule is a POLICY
    descriptor the DLP engine applies to the content-inspection result:
      * built-in identifiers (credit_card -> Luhn-checked PAN, ssn, api_key,
        email) run as dedicated FPGA detectors -- no pattern bytes needed;
      * keyword / regex rules are matched by the content engine (DPI
        Aho-Corasick / regex); the literal pattern must ALSO be installed there
        (via the DPI pattern path) and this descriptor references it by
        fingerprint while carrying the policy (direction / threshold / action).

    Text format, tab-separated (trailing fields optional):
        <name>\\t<type>\\t<pattern>\\t<action>[\\t<severity>\\t<direction>\\t<threshold>]
    Defaults: severity=medium, direction=egress, threshold=1.

    64-bit descriptor word:
        [63:32] pattern fingerprint (fnv32 of pattern; 0 for built-in detectors)
        [31:24] detector id
        [23:16] threshold  (min match count in a flow to trigger)
        [15:12] direction  (1=egress 2=ingress 3=both)
        [11: 8] severity   (1=low 2=med 3=high)
        [ 7: 4] action     (0=alert 1=log 2=block 3=quarantine)
        [ 3: 0] flags (bit0 = valid)
    """
    entries = []
    for idx, line in enumerate(_parse_lines(path)):
        parts = line.split("\t")
        if len(parts) < 4:
            parts = line.split(None, 3)
        if len(parts) < 4:
            continue
        dtype     = parts[1].strip().lower()
        pattern   = parts[2]
        action    = parts[3].strip().lower()
        severity  = parts[4].strip().lower() if len(parts) > 4 else "medium"
        direction = parts[5].strip().lower() if len(parts) > 5 else "egress"
        try:
            threshold = max(1, min(255, int(parts[6]))) if len(parts) > 6 else 1
        except ValueError:
            threshold = 1
        det = DLP_DETECTOR.get(dtype, DLP_DETECTOR["custom"])
        fp = 0 if dtype in DLP_BUILTIN else (_fnv1a_64(pattern.encode("utf-8")) & 0xFFFFFFFF)
        word = ((fp & 0xFFFFFFFF) << 32) \
             | ((det & 0xFF) << 24) \
             | ((threshold & 0xFF) << 16) \
             | ((DLP_DIRECTION.get(direction, 1) & 0xF) << 12) \
             | ((DLP_SEVERITY.get(severity, 2) & 0xF) << 8) \
             | ((DLP_ACTION.get(action, 2) & 0xF) << 4) \
             | 0x1
        entries.append((idx, word))
    payload = b"".join(struct.pack("<IQ", i, d) for i, d in entries)
    return entries, payload


COMPILERS = {
    "appid":            compile_appid,
    "zones":            compile_zones,
    "ddos_pps":         compile_ddos_pps,
    "policy":           compile_policy,
    "app_policy":       compile_app_policy,
    "qos":              compile_qos,
    "threats":          compile_threats,
    "url":              compile_url,
    "geoip":            compile_geoip,
    "blocklist":        compile_blocklist,
    "dns_blocklist":    compile_dns_blocklist,
    "malware_hashes":   compile_malware_hashes,
    "file_magic":       compile_file_magic,
    "tls_fingerprints": compile_tls_fingerprints,
    "spyware_iocs":     compile_spyware_iocs,
    "dlp":              compile_dlp,
}

# Which DB types target BRAM (loaded via TBL_WRITE / IP_CFG_WRITE)
BRAM_TYPES = {
    "appid":      NGFW_TBL_APPID,
    "zones":      NGFW_TBL_DDOS_ZONE_MAP,
    "ddos_pps":   NGFW_TBL_DDOS_THRESHOLDS,
    "policy":     NGFW_TBL_TCAM_POLICY,
    "app_policy": NGFW_TBL_APP_POLICY,
    "qos":        NGFW_TBL_RATE_LIMITER,
    "dlp":        NGFW_TBL_DLP_ENGINE,
}

# Which DB types go to DDR4 regions
DDR4_TYPES = {
    "threats":          NGFW_RGN_THREATS,
    "url":              NGFW_RGN_URL,
    "geoip":            NGFW_RGN_GEOIP,
    "blocklist":        NGFW_RGN_BLOCKLIST,
    "dns_blocklist":    NGFW_RGN_DNSBL,
    "malware_hashes":   NGFW_RGN_MALWARE,
    "file_magic":       NGFW_RGN_FILEMAGIC,
    "tls_fingerprints": NGFW_RGN_TLSFP,
    "spyware_iocs":     NGFW_RGN_SPYWARE,
}

# Which DB types additionally program a BRAM bloom filter
BLOOM_TYPES = {
    "threats":       NGFW_TBL_DPI_BRAM,
    "url":           NGFW_TBL_URL_BLOOM,
    "blocklist":     NGFW_TBL_DDOS_IP_BLOCKLIST,
    "dns_blocklist": NGFW_TBL_DNS_BLOOM,
}

# Which BRAM tables require IP_CFG_WRITE (table_id >= 0x10)
IP_CFG_TABLES = {NGFW_TBL_TCAM_POLICY, NGFW_TBL_DPI_BRAM,
                 NGFW_TBL_URL_BLOOM, NGFW_TBL_DNS_BLOOM, NGFW_TBL_DLP_ENGINE}


# ---------------------------------------------------------------------------
# Load logic
# ---------------------------------------------------------------------------

def _load_bram_entries(dev, db_type, entries, vsys=0):
    """Push compiled entries into FPGA BRAM tables."""
    tbl_id = BRAM_TYPES[db_type]

    # For VSYS overrides on policy tables, shift table ID
    if vsys > 0 and db_type == "policy":
        tbl_id = NGFW_TBL_TCAM_POLICY  # same TCAM, but offset entries
        idx_offset = vsys * 256  # per-VSYS rule space
    else:
        idx_offset = 0

    for idx, data in entries:
        adjusted_idx = idx + idx_offset
        if tbl_id in IP_CFG_TABLES:
            dev.ip_cfg_write(tbl_id, adjusted_idx,
                             data & 0xFFFFFFFF,
                             (data >> 32) & 0xFFFFFFFF)
        else:
            dev.tbl_write(tbl_id, adjusted_idx, data)


def _load_ddr4_payload(dev, db_type, payload, vsys=0):
    """Write compiled binary payload to DDR4 via QDMA DMA."""
    region = DDR4_TYPES[db_type]
    offset = 0

    # Per-VSYS: append after the global data (simple offset scheme)
    if vsys > 0:
        # Each VSYS gets a 40KB slot in the VSYS_POLICY region
        # For other DB types, we overlay at a VSYS-specific offset
        offset = vsys * 40960

    # Write in 4MB chunks (DMA transfer size limit)
    chunk_size = 4 * 1024 * 1024
    pos = 0
    while pos < len(payload):
        chunk = payload[pos : pos + chunk_size]
        dev.ddr_write(region, offset + pos, chunk)
        pos += len(chunk)


def _load_bloom_filter(dev, db_type, bloom_bits):
    """Program bloom filter bits into BRAM."""
    if db_type not in BLOOM_TYPES:
        return
    bloom_tbl = BLOOM_TYPES[db_type]
    # Collect bits into 64-bit words and write them
    words = {}
    for bit_pos in bloom_bits:
        word_idx = bit_pos // 64
        bit_offset = bit_pos % 64
        words.setdefault(word_idx, 0)
        words[word_idx] |= 1 << bit_offset

    for word_idx, data in sorted(words.items()):
        if bloom_tbl in IP_CFG_TABLES:
            dev.ip_cfg_write(bloom_tbl, word_idx,
                             data & 0xFFFFFFFF,
                             (data >> 32) & 0xFFFFFFFF)
        else:
            dev.tbl_write(NGFW_TBL_BLOOM_PROGRAM, word_idx, data)


def do_compile(db_type, input_path, output_path=None):
    """Compile a text database to binary format."""
    if db_type not in COMPILERS:
        print(f"Error: unknown database type '{db_type}'", file=sys.stderr)
        print(f"Valid types: {', '.join(sorted(COMPILERS.keys()))}", file=sys.stderr)
        return None, None, 1

    compiler = COMPILERS[db_type]
    result, payload = compiler(input_path)

    # Count entries
    if isinstance(result, tuple) and len(result) == 2:
        # (entries_or_ddr, bloom_bits)
        entry_list = result[0]
    else:
        entry_list = result
    entry_count = len(entry_list)

    crc = _crc32(payload)
    header = _make_header(DB_TYPE_IDS[db_type], entry_count, crc)
    binary = header + payload

    if output_path:
        with open(output_path, "wb") as f:
            f.write(binary)
        print(f"[{db_type}] Compiled {entry_count} entries -> "
              f"{output_path} ({len(binary)} bytes, CRC32=0x{crc:08X})")
    else:
        print(f"[{db_type}] Compiled {entry_count} entries "
              f"({len(binary)} bytes, CRC32=0x{crc:08X})")

    return result, payload, 0


def do_load(db_type, input_path, vsys=0):
    """Compile and load a database into the FPGA."""
    result, payload, rc = do_compile(db_type, input_path)
    if rc != 0:
        return rc

    dev = FPGADevice()
    try:
        if db_type in BRAM_TYPES:
            if isinstance(result, tuple):
                entries = result[0]
            else:
                entries = result
            _load_bram_entries(dev, db_type, entries, vsys)
            mode_str = "BRAM"
        elif db_type in DDR4_TYPES:
            _load_ddr4_payload(dev, db_type, payload, vsys)
            mode_str = "DDR4"
        else:
            print(f"Error: no load target for type '{db_type}'", file=sys.stderr)
            return 1

        # Program bloom filter if applicable
        if db_type in BLOOM_TYPES:
            if isinstance(result, tuple) and len(result) == 2:
                bloom_bits = result[1]
                _load_bloom_filter(dev, db_type, bloom_bits)
                mode_str += " + bloom"

        entry_count = len(result[0]) if isinstance(result, tuple) else len(result)
        crc_val = _crc32(payload)
        _update_meta(db_type, entry_count, f"0x{crc_val:08X}", input_path, vsys)

        sim_note = " (simulation)" if dev.sim_mode else ""
        print(f"[{db_type}] Loaded {entry_count} entries -> FPGA {mode_str} "
              f"(vsys={vsys}){sim_note}")
    finally:
        dev.close()
    return 0


def do_update(db_type, input_path, vsys=0):
    """Incremental update: compile new entries and append/merge."""
    # For BRAM types, an update is the same as a full load (overwrite entries)
    # For DDR4 types, we append new entries after existing data
    meta = _load_meta()
    key = f"{db_type}:vsys{vsys}"
    existing = meta.get(key, {})
    existing_count = existing.get("entry_count", 0)

    result, payload, rc = do_compile(db_type, input_path)
    if rc != 0:
        return rc

    dev = FPGADevice()
    try:
        if db_type in BRAM_TYPES:
            entries = result[0] if isinstance(result, tuple) else result
            _load_bram_entries(dev, db_type, entries, vsys)
            new_count = len(entries)
        elif db_type in DDR4_TYPES:
            # Append after existing entries
            entry_size = len(payload) // max(
                len(result[0]) if isinstance(result, tuple) else len(result), 1
            ) if payload else 1
            offset = existing_count * entry_size
            region = DDR4_TYPES[db_type]
            chunk_size = 4 * 1024 * 1024
            pos = 0
            while pos < len(payload):
                chunk = payload[pos : pos + chunk_size]
                dev.ddr_write(region, offset + pos, chunk)
                pos += len(chunk)

            if db_type in BLOOM_TYPES and isinstance(result, tuple):
                _load_bloom_filter(dev, db_type, result[1])

            new_count = len(result[0]) if isinstance(result, tuple) else len(result)
        else:
            print(f"Error: no update target for '{db_type}'", file=sys.stderr)
            return 1

        total = existing_count + new_count
        crc_val = _crc32(payload)
        _update_meta(db_type, total, f"0x{crc_val:08X}", input_path, vsys)

        sim_note = " (simulation)" if dev.sim_mode else ""
        print(f"[{db_type}] Updated: +{new_count} entries (total={total}, "
              f"vsys={vsys}){sim_note}")
    finally:
        dev.close()
    return 0


def do_list():
    """List all loaded databases and their metadata."""
    meta = _load_meta()
    if not meta:
        print("No databases loaded yet.")
        print(f"Available types: {', '.join(sorted(COMPILERS.keys()))}")
        return 0

    fmt = "  {:<20s} {:>8s}  {:>12s}  {:<20s}  {}"
    print("Loaded databases:")
    print(fmt.format("Type", "Entries", "Checksum", "Last loaded", "File"))
    print("  " + "-" * 85)
    for key in sorted(meta.keys()):
        info = meta[key]
        print(fmt.format(
            key,
            str(info.get("entry_count", "?")),
            info.get("checksum", "?"),
            info.get("last_loaded", "?"),
            info.get("file_path", "?"),
        ))
    return 0


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="FFN NGFW Database Compiler",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"Supported database types:\n  "
               + "\n  ".join(sorted(COMPILERS.keys())),
    )
    sub = parser.add_subparsers(dest="command")

    # compile
    p_compile = sub.add_parser("compile", help="Compile text DB to binary")
    p_compile.add_argument("type", choices=sorted(COMPILERS.keys()))
    p_compile.add_argument("input", help="Input text file")
    p_compile.add_argument("--output", "-o", help="Output binary file")

    # load
    p_load = sub.add_parser("load", help="Compile + load into FPGA")
    p_load.add_argument("type", choices=sorted(COMPILERS.keys()))
    p_load.add_argument("input", help="Input text file")
    p_load.add_argument("--vsys", type=int, default=0,
                        help="VSYS ID for per-tenant override")

    # update
    p_update = sub.add_parser("update", help="Incremental update (append)")
    p_update.add_argument("type", choices=sorted(COMPILERS.keys()))
    p_update.add_argument("input", help="Input text file with new entries")
    p_update.add_argument("--vsys", type=int, default=0,
                          help="VSYS ID for per-tenant override")

    # list
    sub.add_parser("list", help="Show loaded databases")

    # Backwards compat: positional <type> <input> <output> (old interface)
    # Check before argparse runs, since it would reject the legacy syntax.
    if len(sys.argv) == 4 and sys.argv[1] in COMPILERS:
        db_type = sys.argv[1]
        in_path = sys.argv[2]
        out_path = sys.argv[3]
        _, _, rc = do_compile(db_type, in_path, out_path)
        sys.exit(rc)

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        sys.exit(1)

    if args.command == "compile":
        output = args.output
        if not output:
            output = Path(args.input).stem + ".bin"
        _, _, rc = do_compile(args.type, args.input, output)
        sys.exit(rc)

    elif args.command == "load":
        rc = do_load(args.type, args.input, vsys=args.vsys)
        sys.exit(rc)

    elif args.command == "update":
        rc = do_update(args.type, args.input, vsys=args.vsys)
        sys.exit(rc)

    elif args.command == "list":
        sys.exit(do_list())


if __name__ == "__main__":
    main()
