# SPDX-License-Identifier: GPL-2.0-or-later
"""Strict conntrack event decoding and durable Security session accounting.

Netlink headers use the kernel's native byte order. Tuple addresses, ports,
IDs and counters use network order. Labels written by nftables use its native
128-bit bitmask encoding, verified by packet tests on MIPS64eb.
"""
import ipaddress
import json
import socket
import sqlite3
import struct
import sys
import time


class EventError(ValueError):
    pass


def attributes(raw, byteorder=sys.byteorder, padding=()):
    fmt = '<HH' if byteorder == 'little' else '>HH'
    result = {}
    offset = 0
    while offset < len(raw):
        if len(raw) - offset < 4:
            raise EventError('Truncated netlink attribute')
        size, kind = struct.unpack_from(fmt, raw, offset)
        if size < 4 or offset + size > len(raw):
            raise EventError('Invalid netlink attribute length')
        kind &= 0x3fff
        if kind in padding and size==4:
            offset += 4
            continue
        if kind in result:
            raise EventError('Duplicate netlink attribute')
        result[kind] = raw[offset + 4:offset + size]
        offset += (size + 3) & ~3
    if offset != len(raw):
        raise EventError('Truncated netlink attribute padding')
    return result


def integer(raw, size):
    if len(raw) != size:
        raise EventError('Invalid conntrack scalar length')
    return int.from_bytes(raw, 'big')


def tuple_data(raw, byteorder):
    data = attributes(raw, byteorder)
    ip = attributes(data[1], byteorder)
    proto = attributes(data[2], byteorder)
    result = dict(source=str(ipaddress.IPv4Address(ip[1])),
                  destination=str(ipaddress.IPv4Address(ip[2])),
                  protocol=integer(proto[1], 1))
    for kind, field, size in ((2, 'source_port', 2), (3, 'destination_port', 2),
                              (4, 'icmp_id', 2), (5, 'icmp_type', 1), (6, 'icmp_code', 1)):
        if kind in proto:
            result[field] = integer(proto[kind], size)
    return result


def decode(raw, byteorder=sys.byteorder):
    """Decode every message in one datagram; malformed/lost events are fatal."""
    fmt = '<IHHII' if byteorder == 'little' else '>IHHII'
    offset = 0
    result = []
    while offset < len(raw):
        if len(raw) - offset < 16:
            raise EventError('Truncated netlink header')
        size, kind, flags, sequence, sender = struct.unpack_from(fmt, raw, offset)
        if size < 16 or offset + size > len(raw):
            raise EventError('Invalid netlink message length')
        body = raw[offset + 16:offset + size]
        offset += (size + 3) & ~3
        if kind == 4:
            raise EventError('Conntrack event stream overrun')
        if kind == 2:
            if len(body) < 4 or int.from_bytes(body[:4], byteorder, signed=True):
                raise EventError('Conntrack netlink error')
            continue
        if kind not in (0x100, 0x102):
            continue
        if len(body) < 4:
            raise EventError('Truncated nfgenmsg')
        if body[0] != socket.AF_INET:
            continue
        try:
            data = attributes(body[4:], byteorder)
            label = data.get(22, b'')
            if len(label) not in (0, 16):
                raise EventError('Invalid conntrack label size')
            labels = int.from_bytes(label, byteorder)
            # DESTROY need not include CTA_LABELS. The durable NEW record
            # supplies its token, keyed by boot + CT ID + original tuple.
            counters = {}
            for key, direction in ((9, 'original'), (10, 'reply')):
                if key in data:
                    nested = attributes(data[key], byteorder, padding=(5,))
                    counters[direction] = dict(packets=integer(nested[1], 8),
                                               bytes=integer(nested[2], 8))
            result.append(dict(event='end' if kind == 0x102 else 'start' if flags & 0x600 else 'update',
                               id=integer(data[12], 4), token=labels >> 1 if labels & 1 else None,
                               original=tuple_data(data[1], byteorder),
                               reply=tuple_data(data[2], byteorder), counters=counters))
        except (KeyError, ValueError, struct.error) as error:
            raise EventError('Malformed owned conntrack event: ' + str(error)) from error
    if offset != len(raw):
        raise EventError('Truncated netlink message padding')
    return result


def subscribe():
    stream = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 12)
    try:
        stream.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
        # Subscribe to NEW, UPDATE and DESTROY. Do not set NETLINK_NO_ENOBUFS:
        # loss must stop renewal of the forwarding lease.
        stream.bind((0, 7))
        stream.setblocking(False)
        return stream
    except BaseException:
        stream.close()
        raise


def receive(stream):
    raw, ancillary, flags, sender = stream.recvmsg(1024 * 1024)
    if flags & socket.MSG_TRUNC or sender[0] != 0:
        raise EventError('Truncated or non-kernel conntrack event')
    return decode(raw)


class Journal:
    """Archive immutable rule generations before admitting their first packet."""
    def __init__(self, path, boot):
        self.boot = boot
        self.db = sqlite3.connect(path)
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.execute('PRAGMA synchronous=FULL')
        self.db.executescript('''
            CREATE TABLE IF NOT EXISTS rules(token INTEGER PRIMARY KEY, metadata TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS sessions(identity TEXT PRIMARY KEY, token INTEGER NOT NULL,
                started REAL, updated REAL NOT NULL, data TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY, observed REAL NOT NULL,
                kind TEXT NOT NULL, token INTEGER NOT NULL, data TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS health(id INTEGER PRIMARY KEY CHECK(id=1), fault TEXT);
        ''')

    def register(self, rules):
        with self.db:
            for token, metadata in rules.items():
                raw = json.dumps(metadata, sort_keys=True)
                old = self.db.execute('SELECT metadata FROM rules WHERE token=?', (int(token),)).fetchone()
                if old and old[0] != raw:
                    raise EventError('A Security session token cannot be reused')
                self.db.execute('INSERT OR IGNORE INTO rules VALUES(?,?)', (int(token), raw))

    def record(self, row, now=None):
        now = time.time() if now is None else now
        identity = json.dumps([self.boot, row['id'], row['original']], sort_keys=True)
        old = self.db.execute('SELECT started,token FROM sessions WHERE identity=?', (identity,)).fetchone()
        if row['token'] is None:
            if not old:return
            row=dict(row,token=old[1])
        found = self.db.execute('SELECT metadata FROM rules WHERE token=?', (row['token'],)).fetchone()
        if not found:
            raise EventError('No durable rule generation for owned conntrack event')
        rule = json.loads(found[0])
        if old and old[1] != row['token']:
            raise EventError('Session changed its Security rule identity')
        first_admission=not old and row['event'] in ('start','update')
        started = old[0] if old else now if first_admission else None
        event = dict(row, boot_id=self.boot, rule=rule, started=started, ended=now if row['event']=='end' else None,
                     duration_seconds=max(0,now-started) if started is not None and row['event']=='end' else None)
        with self.db:
            if row['event'] == 'end':
                if rule['logging']['end'] and set(row['counters']) != {'original', 'reply'}:
                    raise EventError('Session-end accounting counters are missing')
                self.db.execute('DELETE FROM sessions WHERE identity=?', (identity,))
            else:
                self.db.execute('INSERT OR REPLACE INTO sessions VALUES(?,?,?,?,?)',
                                (identity, row['token'], started, now, json.dumps(event)))
            if (row['event'] == 'end' and rule['logging']['end'] or
                    first_admission and rule['logging']['start']):
                if first_admission:event=dict(event,event='start')
                self.db.execute('INSERT INTO events(observed,kind,token,data) VALUES(?,?,?,?)',
                                (now, event['event'], row['token'], json.dumps(event)))

    def fault(self, reason):
        with self.db:
            self.db.execute('INSERT OR REPLACE INTO health VALUES(1,?)', (str(reason),))

    def recover_boot(self):
        """A new kernel lost its old conntracks; preserve that loss explicitly."""
        with self.db:
            for identity,token,raw in self.db.execute('SELECT identity,token,data FROM sessions').fetchall():
                if json.loads(identity)[0]==self.boot:continue
                record=json.loads(raw)
                record.update(event='interrupted',reason='dataplane-boot-changed',ended=None,
                              duration_seconds=None,counters_complete=False)
                if record['rule']['logging']['end']:
                    self.db.execute('INSERT INTO events(observed,kind,token,data) VALUES(?,?,?,?)',
                                    (time.time(),'interrupted',token,json.dumps(record)))
                self.db.execute('DELETE FROM sessions WHERE identity=?',(identity,))

    def fault_reason(self):
        row = self.db.execute('SELECT fault FROM health WHERE id=1').fetchone()
        return row[0] if row else None

    def recent(self, limit=100):
        return [json.loads(row[0]) for row in self.db.execute(
            'SELECT data FROM events ORDER BY id DESC LIMIT ?', (min(100, max(1, limit)),))]

    def close(self):
        self.db.close()
