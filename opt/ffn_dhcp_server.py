#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""FFN DHCPv4 server for the dataplane's routed interfaces.

The committed `network/dhcp/interface/entry/server` configuration is compiled
on the MP into one intent per dataplane device (p5, ae1.69, ...) and applied
here through the `dhcp` plane resource. The daemon serves each device from a
raw socket in the ffn-data namespace, filtered in the kernel to DHCP (and ARP
replies while probing), so it sees clients before the per-interface management
tables that gate the host's own services, and answers clients that have no
address yet by building the whole frame itself.

Leases live under /var/lib/ffn/dhcp-server/<device>.json; the daemon publishes
its view at /run/ffn-dhcp-server/status.json for the console and the
convergence check. Relayed requests (giaddr set) are counted and ignored: the
server is authoritative for its own subnet only.

Control, JSON on stdin and stdout, run by the MP through the plane channel:

    status     the applied intent (integer revision), the daemon's view, leases
    validate   check an intent without applying it
    apply      replace the intent at the given revision; the daemon reloads
    serve      the daemon (systemd: ip netns exec ffn-data ... serve)
"""
import ipaddress
import json
import os
import random
import re
import signal
import struct
import sys
import time
from pathlib import Path

INTENT = Path('/etc/ffn/dhcp-server.json')
RUN = Path('/run/ffn-dhcp-server')
LEASES = Path('/var/lib/ffn/dhcp-server')
BOOT_ID = Path('/proc/sys/kernel/random/boot_id')
DEVICE = re.compile(r'(p[1-9][0-9]{0,3}|ae[1-9][0-9]{0,2})(\.[1-9][0-9]{0,3})?\Z')
MAC = re.compile(r'([0-9a-f]{2}:){5}[0-9a-f]{2}\Z')
DOMAIN = re.compile(r'(?=.{1,253}\Z)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*\Z', re.I)
OPTION_LISTS = ('dns', 'ntp', 'wins')
MAX_POOL = 65536
MAX_SERVERS = 64
MIN_LEASE, MAX_LEASE = 60, 400 * 86400
OFFER_SECONDS = 60        # an offer the client never requested
DECLINE_SECONDS = 600     # declined by a client, or answered an ARP probe
STATUS_LEASES = 1024
INFINITE = 0xFFFFFFFF
ETH_P_IP, ETH_P_ARP, ETH_P_ALL = 0x0800, 0x0806, 0x0003
DISCOVER, OFFER, REQUEST, DECLINE, ACK, NAK, RELEASE, INFORM = 1, 2, 3, 4, 5, 6, 7, 8
NAMES = {DISCOVER: 'discover', OFFER: 'offer', REQUEST: 'request', DECLINE: 'decline', ACK: 'ack', NAK: 'nak',
         RELEASE: 'release', INFORM: 'inform'}
CLIENT_MESSAGES = (DISCOVER, REQUEST, DECLINE, RELEASE, INFORM)
MAGIC = b'\x63\x82\x53\x63'
BROADCAST_MAC = b'\xff' * 6
SO_ATTACH_FILTER = 26
SIOCGIFHWADDR = 0x8927


# ------------------------------------------------------------------ intent
def _ip4(value, what):
    try:
        address = ipaddress.IPv4Address(value)
    except (ValueError, TypeError):
        raise ValueError('%s must be an IPv4 address' % what)
    if address.is_multicast or address.is_unspecified or address.is_loopback:
        raise ValueError('%s must be a unicast IPv4 address' % what)
    return address


def validate_server(device, spec):
    """Normalise one device's intent or raise ValueError naming the fault."""
    if not isinstance(device, str) or not DEVICE.fullmatch(device):
        raise ValueError('unsupported dataplane device name')
    if not isinstance(spec, dict) or set(spec) - {'interface', 'address', 'pools', 'reserved', 'lease', 'probe', 'options'}:
        raise ValueError(device + ': unknown server field')
    if not isinstance(spec.get('interface'), str) or not spec['interface']:
        raise ValueError(device + ': interface name required')
    try:
        address = ipaddress.IPv4Interface(spec.get('address'))
    except (ValueError, TypeError):
        raise ValueError(device + ': address must be an IPv4 interface address')
    if address.network.prefixlen > 30 or address.ip.is_loopback or address.ip.is_multicast:
        raise ValueError(device + ': address must leave room for clients')
    network = address.network
    hosts = (int(network.network_address) + 1, int(network.broadcast_address) - 1)
    pools, total = [], 0
    if not isinstance(spec.get('pools', []), list) or len(spec.get('pools', [])) > 32:
        raise ValueError(device + ': pools must be a list of at most 32 ranges')
    for item in spec.get('pools', []):
        if not isinstance(item, list) or len(item) != 2:
            raise ValueError(device + ': each pool is a [first, last] pair')
        first, last = (_ip4(v, device + ': pool address') for v in item)
        if int(first) > int(last):
            raise ValueError(device + ': pool first address exceeds its last')
        if not (hosts[0] <= int(first) and int(last) <= hosts[1]):
            raise ValueError(device + ': pool %s-%s is outside %s' % (first, last, network))
        if int(first) <= int(address.ip) <= int(last):
            raise ValueError(device + ': pool contains the interface address')
        pools.append((int(first), int(last)))
        total += int(last) - int(first) + 1
    pools.sort()
    for (a, b), (c, _) in zip(pools, pools[1:]):
        if c <= b:
            raise ValueError(device + ': pools overlap')
    if total > MAX_POOL:
        raise ValueError(device + ': pools exceed %d addresses' % MAX_POOL)
    reserved = {}
    if not isinstance(spec.get('reserved', {}), dict) or len(spec.get('reserved', {})) > 4096:
        raise ValueError(device + ': reserved must map at most 4096 MAC addresses')
    for mac, ip in spec.get('reserved', {}).items():
        if not isinstance(mac, str) or not MAC.fullmatch(mac.lower()):
            raise ValueError(device + ': reservation MAC must be six colon-separated octets')
        target = _ip4(ip, device + ': reservation')
        if target not in network or not hosts[0] <= int(target) <= hosts[1] or target == address.ip:
            raise ValueError(device + ': reservation %s is not a client address on %s' % (target, network))
        if mac.lower() in reserved or str(target) in reserved.values():
            raise ValueError(device + ': reservations must be unique')
        reserved[mac.lower()] = str(target)
    if not pools and not reserved:
        raise ValueError(device + ': a pool or a reservation is required')
    lease = spec.get('lease')
    if lease is not None and (type(lease) is not int or not MIN_LEASE <= lease <= MAX_LEASE):
        raise ValueError(device + ': lease must be %d..%d seconds or null for unlimited' % (MIN_LEASE, MAX_LEASE))
    if type(spec.get('probe', False)) is not bool:
        raise ValueError(device + ': probe must be true or false')
    options = spec.get('options', {})
    if not isinstance(options, dict) or set(options) - {'gateway', 'subnet_mask', 'domain', *OPTION_LISTS}:
        raise ValueError(device + ': unknown option')
    normalised = {}
    if options.get('gateway'):
        normalised['gateway'] = str(_ip4(options['gateway'], device + ': gateway'))
    if options.get('subnet_mask'):
        try:
            mask = ipaddress.IPv4Network('0.0.0.0/' + str(options['subnet_mask']))
        except (ValueError, TypeError):
            raise ValueError(device + ': subnet mask is not a valid netmask')
        normalised['subnet_mask'] = str(mask.netmask)
    for name in OPTION_LISTS:
        values = options.get(name, [])
        if not isinstance(values, list) or len(values) > 4:
            raise ValueError(device + ': %s takes at most four addresses' % name)
        if values:
            normalised[name] = [str(_ip4(v, device + ': ' + name)) for v in values]
    if options.get('domain'):
        if not isinstance(options['domain'], str) or not DOMAIN.fullmatch(options['domain']):
            raise ValueError(device + ': domain is not a valid DNS name')
        normalised['domain'] = options['domain']
    return dict(interface=spec['interface'], address=str(address), pools=[[str(ipaddress.IPv4Address(a)), str(ipaddress.IPv4Address(b))] for a, b in pools],
                reserved=reserved, lease=lease, probe=bool(spec.get('probe', False)), options=normalised)


def validate_intent(intent):
    if not isinstance(intent, dict) or not isinstance(intent.get('servers'), dict):
        raise ValueError('intent needs a servers object')
    if len(intent['servers']) > MAX_SERVERS:
        raise ValueError('at most %d DHCP servers' % MAX_SERVERS)
    configuration = intent.get('configuration')
    if configuration is not None and (not isinstance(configuration, str) or not re.fullmatch(r'[0-9a-f]{64}', configuration)):
        raise ValueError('configuration must be a SHA-256 digest')
    servers = {device: validate_server(device, spec) for device, spec in sorted(intent['servers'].items())}
    return dict(schema=1, configuration=configuration, servers=servers)


# ------------------------------------------------------------------ codec
def checksum(data):
    if len(data) % 2:
        data += b'\0'
    total = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def parse(frame):
    """Ethernet/IPv4/UDP/DHCP request -> dict, or None for anything else."""
    if len(frame) < 14 + 20 + 8 + 240:
        return None
    if frame[12:14] != b'\x08\x00':
        return None
    ihl = (frame[14] & 0x0F) * 4
    if ihl < 20 or frame[23] != 17 or (struct.unpack('!H', frame[20:22])[0] & 0x1FFF):
        return None
    ip_len = struct.unpack('!H', frame[16:18])[0]
    udp = 14 + ihl
    if udp + 8 > len(frame):
        return None
    sport, dport, udp_len = struct.unpack('!HHH', frame[udp:udp + 6])
    if dport != 67:
        return None
    end = min(len(frame), 14 + ip_len, udp + udp_len)
    data = frame[udp + 8:end]
    if len(data) < 240 or data[236:240] != MAGIC:
        return None
    op, htype, hlen, hops, xid, secs, flags = struct.unpack('!BBBBIHH', data[:12])
    if op != 1 or htype != 1 or hlen != 6:
        return None
    options, i = {}, 240
    while i < len(data):
        tag = data[i]
        if tag == 0:
            i += 1
            continue
        if tag == 255:
            break
        if i + 1 >= len(data):
            break
        length = data[i + 1]
        value = data[i + 2:i + 2 + length]
        if len(value) < length:
            break
        options.setdefault(tag, value)
        i += 2 + length
    if options.get(53, b'') not in (bytes([t]) for t in CLIENT_MESSAGES):
        return None
    return dict(src_mac=frame[6:12], dst_mac=frame[:6], src_ip=frame[26:30], xid=xid, secs=secs, flags=flags,
                ciaddr=data[12:16], yiaddr=data[16:20], giaddr=data[24:28], chaddr=data[28:34],
                type=options[53][0], options=options, sport=sport)


def option(tag, value):
    return bytes([tag, len(value)]) + value


def build(reply, message, server_ip, server_mac, yiaddr, options, dst_mac, dst_ip):
    """A complete frame for `reply` to `message`; options is the encoded option bytes."""
    lease_fields = struct.pack('!BBBBIHH', 2, 1, 6, 0, message['xid'], 0, message['flags'])
    body = (lease_fields + (message['ciaddr'] if reply != NAK else bytes(4)) + yiaddr + bytes(4) + message['giaddr']
            + message['chaddr'] + bytes(10) + bytes(64) + bytes(128) + MAGIC + option(53, bytes([reply]))
            + option(54, server_ip) + options + b'\xff')
    if len(body) < 300:
        body += bytes(300 - len(body))
    udp = struct.pack('!HHHH', 67, 68 if message['sport'] != 67 else 67, 8 + len(body), 0) + body
    pseudo = server_ip + dst_ip + struct.pack('!BBH', 0, 17, len(udp))
    udp = udp[:6] + struct.pack('!H', checksum(pseudo + udp) or 0xFFFF) + udp[8:]
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), random.randrange(65536), 0, 64, 17, 0, server_ip, dst_ip)
    ip = ip[:10] + struct.pack('!H', checksum(ip)) + ip[12:]
    return dst_mac + server_mac + b'\x08\x00' + ip + udp


# ------------------------------------------------------------------ leases
def atomic(path, value):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + '.tmp')
    with open(temp, 'w', opener=lambda p, flags: os.open(p, flags, 0o600)) as handle:
        json.dump(value, handle)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temp, path)


class Leases:
    """One device's bindings: ip -> row; durable, re-read at start."""

    def __init__(self, path, device):
        self.path, self.device, self.rows = Path(path), device, {}
        try:
            value = json.loads(self.path.read_text())
            if value.get('schema') == 1 and value.get('device') == device and isinstance(value.get('rows'), dict):
                self.rows = {ip: row for ip, row in value['rows'].items() if isinstance(row, dict) and row.get('state') in ('offered', 'bound', 'declined')}
        except (OSError, ValueError, AttributeError):
            pass

    def save(self):
        atomic(self.path, dict(schema=1, device=self.device, rows=self.rows))

    def expire(self, now):
        stale = [ip for ip, row in self.rows.items() if row.get('expires') is not None and row['expires'] <= now]
        for ip in stale:
            del self.rows[ip]
        return bool(stale)

    def held_by(self, key):
        for ip, row in self.rows.items():
            if row.get('key') == key and row['state'] in ('offered', 'bound'):
                return ip, row
        return None, None


# ------------------------------------------------------------------ server
class Server:
    """Protocol state for one device. handle() is pure apart from the lease file."""

    def __init__(self, device, spec, leases, clock=time.time, probe=None, log=None):
        self.device, self.spec, self.leases = device, spec, leases
        self.clock, self.probe, self.log = clock, probe or (lambda ip: False), log or (lambda *a: None)
        self.address = ipaddress.IPv4Interface(spec['address'])
        self.network = self.address.network
        self.server_ip = self.address.ip.packed
        self.mac = None
        self.pools = [(int(ipaddress.IPv4Address(a)), int(ipaddress.IPv4Address(b))) for a, b in spec['pools']]
        self.reserved = {mac: ip for mac, ip in spec['reserved'].items()}
        self.reserved_ips = set(self.reserved.values())
        self.counters = {name: 0 for name in ('discover', 'offer', 'request', 'ack', 'nak', 'decline', 'release', 'inform',
                                              'relayed', 'exhausted', 'other_server', 'ignored', 'conflict')}
        self.last_event = None

    # -- allocation ------------------------------------------------------
    def in_pool(self, ip):
        value = int(ipaddress.IPv4Address(ip))
        return any(a <= value <= b for a, b in self.pools)

    def candidates(self):
        for a, b in self.pools:
            for value in range(a, b + 1):
                ip = str(ipaddress.IPv4Address(value))
                if ip not in self.reserved_ips:
                    yield ip

    def allocate(self, key, mac, requested, now):
        """The address to offer `key`, or None when nothing is free."""
        if mac in self.reserved:
            return self.reserved[mac]
        held, row = self.leases.held_by(key)
        if held:
            return held
        wanted = [requested] if requested and self.in_pool(requested) and requested not in self.reserved_ips else []
        for ip in wanted + list(self.candidates()):
            row = self.leases.rows.get(ip)
            if row is not None and row.get('key') != key:
                continue
            if self.spec['probe'] and self.probe(ip):
                self.counters['conflict'] += 1
                self.leases.rows[ip] = dict(state='declined', key=None, mac=None, hostname='', since=now, expires=now + DECLINE_SECONDS)
                continue
            return ip
        return None

    def bind(self, ip, key, mac, hostname, now, state):
        if state == 'bound' and self.spec['lease'] is None:
            expires = None
        elif state == 'bound':
            expires = now + self.spec['lease']
        else:
            expires = now + OFFER_SECONDS
        self.leases.rows[ip] = dict(state=state, key=key, mac=mac, hostname=hostname, since=now, expires=expires)
        self.leases.save()

    def release(self, ip, key):
        row = self.leases.rows.get(ip)
        if row is not None and row.get('key') == key:
            del self.leases.rows[ip]
            self.leases.save()
            return True
        return False

    # -- replies ---------------------------------------------------------
    def lease_options(self, lease=True):
        out = b''
        seconds = self.spec['lease']
        if lease:
            out += option(51, struct.pack('!I', INFINITE if seconds is None else seconds))
            if seconds is not None:
                out += option(58, struct.pack('!I', seconds // 2)) + option(59, struct.pack('!I', seconds * 7 // 8))
        opts = self.spec['options']
        mask = ipaddress.IPv4Address(opts.get('subnet_mask', str(self.network.netmask)))
        out += option(1, mask.packed)
        out += option(28, self.network.broadcast_address.packed)
        out += option(3, ipaddress.IPv4Address(opts.get('gateway', str(self.address.ip))).packed)
        for tag, name in ((6, 'dns'), (42, 'ntp'), (44, 'wins')):
            if opts.get(name):
                out += option(tag, b''.join(ipaddress.IPv4Address(v).packed for v in opts[name]))
        if opts.get('domain'):
            out += option(15, opts['domain'].encode())
        return out

    def reply(self, kind, message, yiaddr, options):
        """Address the reply as RFC 2131 section 4.1 requires, then build the frame."""
        if kind == NAK or (message['flags'] & 0x8000 and message['ciaddr'] == bytes(4)):
            dst_mac, dst_ip = BROADCAST_MAC, b'\xff\xff\xff\xff'
        elif message['ciaddr'] != bytes(4):
            dst_mac, dst_ip = message['src_mac'], message['ciaddr']
        else:
            dst_mac, dst_ip = message['chaddr'], yiaddr
        if 61 in message['options'] and kind != NAK:
            options += option(61, message['options'][61])
        return build(kind, message, self.server_ip, self.mac, yiaddr, options, dst_mac, dst_ip)

    def nak(self, message, reason):
        self.counters['nak'] += 1
        return [self.reply(NAK, message, bytes(4), option(56, reason.encode()[:64]))]

    def handle(self, frame, now=None):
        """Frames to send in answer to one received frame."""
        now = self.clock() if now is None else now
        message = parse(frame)
        if message is None:
            return []
        if self.leases.expire(now):
            self.leases.save()
        kind = message['type']
        self.counters[NAMES[kind]] += 1
        self.last_event = now
        if message['giaddr'] != bytes(4):
            self.counters['relayed'] += 1
            return []
        mac = ':'.join('%02x' % b for b in message['chaddr'])
        key = ('id:' + message['options'][61].hex()) if message['options'].get(61) else ('mac:' + mac)
        hostname = message['options'].get(12, b'').decode('utf-8', 'replace')[:64]
        requested = message['options'].get(50)
        requested = str(ipaddress.IPv4Address(requested)) if requested and len(requested) == 4 else None
        ciaddr = str(ipaddress.IPv4Address(message['ciaddr'])) if message['ciaddr'] != bytes(4) else None
        if kind == DISCOVER:
            ip = self.allocate(key, mac, requested, now)
            if ip is None:
                self.counters['exhausted'] += 1
                self.log('%s: pool exhausted for %s' % (self.device, mac))
                return []
            self.bind(ip, key, mac, hostname, now, 'offered')
            self.counters['offer'] += 1
            return [self.reply(OFFER, message, ipaddress.IPv4Address(ip).packed, self.lease_options())]
        if kind == REQUEST:
            server = message['options'].get(54)
            if server is not None:
                if server != self.server_ip:
                    held, row = self.leases.held_by(key)
                    if held and row['state'] == 'offered':
                        self.release(held, key)
                    self.counters['other_server'] += 1
                    return []
                target = requested
                if target is None or not self.offered_to(target, key, mac):
                    return self.nak(message, 'requested address was not offered')
            elif requested is not None:                       # INIT-REBOOT
                if ipaddress.IPv4Address(requested) not in self.network:
                    return self.nak(message, 'wrong network')
                target = requested
                if not self.offered_to(target, key, mac, bound_only=True):
                    return self.nak(message, 'address is not leased to this client')
            elif ciaddr is not None:                          # RENEWING / REBINDING
                target = ciaddr
                if ipaddress.IPv4Address(target) not in self.network or not self.offered_to(target, key, mac, bound_only=True):
                    return self.nak(message, 'lease is not held by this client')
            else:
                self.counters['ignored'] += 1
                return []
            self.bind(target, key, mac, hostname, now, 'bound')
            self.counters['ack'] += 1
            return [self.reply(ACK, message, ipaddress.IPv4Address(target).packed, self.lease_options())]
        if kind == DECLINE:
            if requested and self.in_pool(requested):
                self.leases.rows[requested] = dict(state='declined', key=None, mac=mac, hostname='', since=now, expires=now + DECLINE_SECONDS)
                self.leases.save()
                self.log('%s: %s declined %s' % (self.device, mac, requested))
            return []
        if kind == RELEASE:
            if ciaddr:
                self.release(ciaddr, key)
            return []
        if kind == INFORM:
            if ciaddr is None:
                self.counters['ignored'] += 1
                return []
            self.counters['ack'] += 1
            return [self.reply(ACK, message, bytes(4), self.lease_options(lease=False))]
        return []

    def offered_to(self, ip, key, mac, bound_only=False):
        """Is `ip` the client's reservation, or a binding (offer or lease) held by it?"""
        if self.reserved.get(mac) == ip:
            return True
        if ip in self.reserved_ips:
            return False
        row = self.leases.rows.get(ip)
        if row is None or row.get('key') != key:
            return False
        return row['state'] == 'bound' or (not bound_only and row['state'] == 'offered')

    def summary(self, now):
        states = {'bound': 0, 'offered': 0, 'declined': 0}
        rows = []
        for ip, row in sorted(self.leases.rows.items(), key=lambda kv: int(ipaddress.IPv4Address(kv[0]))):
            states[row['state']] = states.get(row['state'], 0) + 1
            if len(rows) < STATUS_LEASES:
                rows.append(dict(ip=ip, mac=row.get('mac'), hostname=row.get('hostname', ''), state=row['state'],
                                 since=row.get('since'), expires=row.get('expires')))
        return dict(interface=self.spec['interface'], address=str(self.address), pool_size=sum(b - a + 1 for a, b in self.pools),
                    reserved=len(self.reserved), lease=self.spec['lease'], counters=dict(self.counters),
                    last_event=self.last_event, leases=rows, **states)


# ------------------------------------------------------------------ daemon
def bpf_program(probe):
    """Classic BPF: UDP to port 67 in unfragmented IPv4, plus ARP replies while probing."""
    instructions = [
        (0x28, 0, 0, 12),                       # ethertype
        (0x15, 0, 2, ETH_P_ARP) if probe else (0x15, 11, 2, ETH_P_ARP),
        (0x28, 0, 0, 20),                       # ARP opcode
        (0x15, 8, 9, 2),                        # reply -> accept
        (0x15, 0, 8, ETH_P_IP),
        (0x30, 0, 0, 23),                       # protocol
        (0x15, 0, 6, 17),
        (0x28, 0, 0, 20),                       # flags/fragment offset
        (0x45, 4, 0, 0x1FFF),
        (0xB1, 0, 0, 14),                       # x = header length
        (0x48, 0, 0, 16),                       # udp destination port
        (0x15, 0, 1, 67),
        (0x06, 0, 0, 65535),
        (0x06, 0, 0, 0),
    ]
    return b''.join(struct.pack('HBBI', *row) for row in instructions), len(instructions)


def device_addresses(device, run=None):
    import subprocess
    run = run or (lambda argv: subprocess.run(argv, capture_output=True, text=True, timeout=10).stdout)
    try:
        rows = json.loads(run(['ip', '-j', 'addr', 'show', 'dev', device]) or '[]')
    except (OSError, ValueError, subprocess.SubprocessError):
        return None
    if not rows:
        return None
    return [a['local'] + '/' + str(a['prefixlen']) for a in rows[0].get('addr_info', []) if a.get('family') == 'inet']


class Instance:
    """One served device: the socket, the server and its state for the status file."""

    def __init__(self, device, spec, log):
        self.device, self.spec, self.log = device, spec, log
        self.server = Server(device, spec, Leases(LEASES / (device + '.json'), device), probe=self.probe, log=log)
        self.sock = None
        self.state, self.detail = 'starting', ''
        self.pending = []

    def open(self):
        import ctypes
        import fcntl
        import socket
        addresses = device_addresses(self.device)
        if addresses is None:
            self.state, self.detail = 'interface-absent', 'no such device in the dataplane namespace'
            return False
        if self.spec['address'] not in addresses:
            self.state, self.detail = 'address-missing', 'device carries %s, not %s' % (', '.join(addresses) or 'no IPv4 address', self.spec['address'])
            return False
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        try:
            program, count = bpf_program(self.spec['probe'])
            buffer = ctypes.create_string_buffer(program)
            sock.setsockopt(socket.SOL_SOCKET, SO_ATTACH_FILTER, struct.pack('HP', count, ctypes.addressof(buffer)))
            sock.bind((self.device, ETH_P_ALL))
            info = fcntl.ioctl(sock.fileno(), SIOCGIFHWADDR, struct.pack('256s', self.device.encode()))
            self.server.mac = info[18:24]
            sock.setblocking(False)
        except OSError as error:
            sock.close()
            self.state, self.detail = 'error', str(error)[:200]
            return False
        self.sock = sock
        self.state, self.detail = 'serving', ''
        self.log('%s: serving %s from %s' % (self.device, self.spec['address'], ':'.join('%02x' % b for b in self.server.mac)))
        return True

    def close(self):
        if self.sock is not None:
            self.sock.close()
            self.sock = None
        self.state, self.detail = 'stopped', ''

    def receive(self):
        """Handle every frame the kernel queued; replies go straight back out."""
        frames = list(self.pending)
        self.pending = []
        while True:
            try:
                frames.append(self.sock.recv(65535))
            except BlockingIOError:
                break
            except OSError as error:
                self.state, self.detail = 'error', str(error)[:200]
                return
        for frame in frames:
            if frame[12:14] == b'\x08\x06':
                continue
            try:
                for reply in self.server.handle(frame):
                    self.sock.send(reply)
            except OSError as error:
                self.log('%s: send failed: %s' % (self.device, error))
            except Exception as error:   # a malformed frame must never stop the server
                self.log('%s: %s' % (self.device, error))

    def probe(self, ip):
        """ARP for `ip`; True when something answers within the wait."""
        import select
        target = ipaddress.IPv4Address(ip).packed
        request = (BROADCAST_MAC + self.server.mac + b'\x08\x06' + struct.pack('!HHBBH', 1, ETH_P_IP, 6, 4, 1)
                   + self.server.mac + self.server.server_ip + bytes(6) + target)
        try:
            self.sock.send(request)
        except OSError:
            return False
        deadline = time.monotonic() + 0.3
        while True:
            wait = deadline - time.monotonic()
            if wait <= 0:
                return False
            if not select.select([self.sock], [], [], wait)[0]:
                return False
            try:
                frame = self.sock.recv(65535)
            except OSError:
                return False
            if frame[12:14] == b'\x08\x06' and len(frame) >= 42 and frame[20:22] == b'\x00\x02' and frame[28:32] == target:
                return True
            if frame[12:14] == b'\x08\x00':
                self.pending.append(frame)

    def status(self, now):
        return dict(state=self.state, detail=self.detail, mac=':'.join('%02x' % b for b in self.server.mac) if self.server.mac else None,
                    **self.server.summary(now))


def read_intent(path=None):
    try:
        value = json.loads(Path(INTENT if path is None else path).read_text())
    except (OSError, ValueError):
        return dict(schema=1, revision=0, configuration=None, servers={})
    if not isinstance(value, dict) or value.get('schema') != 1 or type(value.get('revision')) is not int:
        return dict(schema=1, revision=0, configuration=None, servers={})
    return value


class Daemon:
    def __init__(self, log=None):
        self.log = log or (lambda line: print(line, flush=True))
        self.instances = {}
        self.revision, self.configuration = None, None
        self.reload_requested = True
        self.process_start = None

    def reload(self):
        intent = read_intent()
        try:
            servers = validate_intent(intent)['servers']
        except ValueError as error:
            self.log('intent rejected: ' + str(error))
            servers = {}
        for device in list(self.instances):
            if device not in servers or servers[device] != self.instances[device].spec:
                self.instances.pop(device).close()
                self.log(device + ': stopped')
        for device, spec in servers.items():
            if device not in self.instances:
                self.instances[device] = Instance(device, spec, self.log)
        self.revision, self.configuration = intent['revision'], intent.get('configuration')
        self.reload_requested = False

    def publish(self):
        now = time.time()
        atomic(RUN / 'status.json', dict(schema=1, boot_id=boot_id(), pid=os.getpid(), process_start=self.process_start,
                                         monotonic=time.monotonic(), time=now, revision=self.revision, configuration=self.configuration,
                                         servers={device: inst.status(now) for device, inst in sorted(self.instances.items())}))

    def serve(self):
        import select
        RUN.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.process_start = process_start(os.getpid())
        (RUN / 'pid').write_text(str(os.getpid()) + '\n')
        signal.signal(signal.SIGHUP, lambda *a: setattr(self, 'reload_requested', True))
        stop = []
        signal.signal(signal.SIGTERM, lambda *a: stop.append(True))
        next_publish, next_open = 0.0, 0.0
        while not stop:
            if self.reload_requested:
                self.reload()
                self.publish()
                next_open = 0.0
            now = time.monotonic()
            if now >= next_open:
                for inst in self.instances.values():
                    if inst.sock is None:
                        inst.open()
                next_open = now + 5
            sockets = {inst.sock: inst for inst in self.instances.values() if inst.sock is not None}
            try:
                ready = select.select(list(sockets), [], [], 1.0)[0]
            except InterruptedError:
                ready = []
            for sock in ready:
                sockets[sock].receive()
            if ready or time.monotonic() >= next_publish:
                self.publish()
                next_publish = time.monotonic() + 5
        for inst in self.instances.values():
            inst.close()
        self.publish()


def boot_id():
    try:
        return BOOT_ID.read_text().strip()
    except OSError:
        return None


def process_start(pid):
    try:
        return Path('/proc/%d/stat' % pid).read_text().rsplit(') ', 1)[1].split()[19]
    except (OSError, IndexError):
        return None


# ------------------------------------------------------------------ control
def running_status():
    try:
        value = json.loads((RUN / 'status.json').read_text())
    except (OSError, ValueError):
        return None
    if not isinstance(value, dict) or value.get('schema') != 1 or value.get('boot_id') != boot_id():
        return None
    try:
        if process_start(value['pid']) != value['process_start']:
            return None
    except (KeyError, TypeError):
        return None
    return value


def status():
    intent = read_intent()
    return dict(config=dict(revision=intent['revision'], configuration=intent.get('configuration'), servers=intent.get('servers', {})),
                boot_id=boot_id(), running=running_status())


def apply(request, clock=time.time):
    if not isinstance(request, dict) or set(request) - {'revision', 'servers', 'configuration'}:
        raise ValueError('apply takes revision, servers and configuration')
    current = read_intent()
    if type(request.get('revision')) is not int or request['revision'] != current['revision']:
        raise ValueError('revision conflict; refresh status')
    intent = validate_intent(request)
    intent.update(revision=current['revision'] + 1, applied_at=clock())
    atomic(INTENT, intent)
    signalled = False
    try:
        pid = int((RUN / 'pid').read_text().strip())
        os.kill(pid, signal.SIGHUP)
        signalled = True
    except (OSError, ValueError):
        pass
    deadline = time.monotonic() + 5
    while signalled and time.monotonic() < deadline:
        running = running_status()
        if running and running.get('revision') == intent['revision']:
            break
        time.sleep(0.2)
    return status()


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    action = argv[0] if argv else 'status'
    if action == 'serve':
        Daemon().serve()
        return 0
    if action not in ('status', 'validate', 'apply'):
        raise SystemExit('usage: ffn_dhcp_server.py status|validate|apply|serve')
    try:
        if action == 'status':
            result = status()
        else:
            data = sys.stdin.buffer.read((1 << 20) + 1)
            if len(data) > (1 << 20):
                raise ValueError('request exceeds 1 MiB')
            request = json.loads(data) if data.strip() else {}
            if action == 'validate':
                validate_intent(request)
                result = dict(validated=True, servers=sorted(request.get('servers', {})))
            else:
                result = apply(request)
    except (ValueError, OSError) as error:
        print(json.dumps({'error': str(error)[:512]}))
        return 2
    print(json.dumps(result))
    return 0


if __name__ == '__main__':
    sys.exit(main())
