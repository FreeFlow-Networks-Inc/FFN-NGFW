"""Privileged, isolated netns tests. Netlink/ioctl control only; no packets.

Run through test-kernel.sh. Never run in an appliance's production namespace.
"""
import ctypes as C
import errno
import fcntl
import json
import os
from pathlib import Path
import socket
import struct as S
import subprocess
import time
import unittest
from ffn_ctlease import Bind, Update, tuple_abi, Lease


def attr(kind, data):
    raw = S.pack('HH', len(data) + 4, kind) + data
    return raw + bytes((-len(raw)) % 4)


def attrs(raw):
    result = {}
    while len(raw) >= 4:
        length, kind = S.unpack_from('HH', raw)
        assert 4 <= length <= len(raw)
        result[kind & 0x3fff] = raw[4:length]
        raw = raw[(length + 3) & ~3:]
    return result


ORIGINAL = ('192.0.2.10', '198.51.100.20', 42001, 443)
REPLY = ('198.51.100.20', '203.0.113.30', 443, 52001)


def tuple_wire(values):
    src, dst, sport, dport = values
    ip = attr(1, socket.inet_aton(src)) + attr(2, socket.inet_aton(dst))
    proto = attr(1, b'\x11') + attr(2, S.pack('!H', sport)) + attr(3, S.pack('!H', dport))
    return attr(0x8001, ip) + attr(0x8002, proto)


def netlink(command, extra=b'', create=False):
    payload = bytes([socket.AF_INET, 0, 0, 0]) + attr(0x8001, tuple_wire(ORIGINAL)) + extra
    flags = 1 | 4 | (0x400 | 0x200 if create else 0)
    msg = S.pack('IHHII', len(payload) + 16, 0x100 | command, flags, 1, 0) + payload
    replies = []
    with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 12) as sock:
        sock.settimeout(3)
        sock.sendto(msg, (0, 0))
        while True:
            raw = sock.recv(65536)
            while len(raw) >= 16:
                length, kind, _, _, _ = S.unpack_from('IHHII', raw)
                body = raw[16:length]
                if kind == 2:
                    error = S.unpack_from('i', body)[0]
                    if error: raise OSError(-error, os.strerror(-error))
                    return replies
                replies.append(attrs(body[4:]))
                raw = raw[(length + 3) & ~3:]


def create(timeout=10, status=6):
    extra = attr(0x8002, tuple_wire(REPLY)) + attr(7, S.pack('!I', timeout))
    extra += attr(3, S.pack('!I', status | 8)) + attr(8, S.pack('!I', 27))
    netlink(0, extra, True)
    netlink(0, attr(22, b'\x01' + bytes(15)))


def snapshot():
    value = netlink(1)[0]
    counters = []
    for direction in (9, 10):
        fields = attrs(value[direction])
        counters.append(tuple(S.unpack('!Q', fields[key])[0] for key in (1, 2)))
    return value, counters


def identity(timeout=60):
    value, _ = snapshot()
    bind = Bind(version=1, id=S.unpack('!I', value[12])[0], timeout=timeout,
                protocol=17, mark=27, original=tuple_abi(ORIGINAL), reply=tuple_abi(REPLY))
    bind.labels[:] = value[22]
    bind.ethernet[:] = (14, 18)
    return bind


def ioctl(fd, number, data):
    # Generic ioctl encoding is architecture-dependent (MIPS uses 3 direction
    # bits and WRITE=4). Derive commands from a compiled native ABI helper.
    fcntl.ioctl(fd, COMMANDS[number], bytes(data))


class LeaseTests(unittest.TestCase):
    def setUp(self):
        create()
        self.fds = []

    def tearDown(self):
        for fd in self.fds: os.close(fd)
        try: netlink(2)
        except OSError as exc:
            if exc.errno != errno.ENOENT: raise

    def open(self):
        fd = os.open('/dev/ffn-ctlease', os.O_RDWR | os.O_CLOEXEC)
        self.fds.append(fd)
        return fd

    def bound(self):
        fd = self.open()
        ioctl(fd, 0, identity())
        return fd

    def error(self, expected, fd, op, arg):
        with self.assertRaises(OSError) as caught: ioctl(fd, op, arg)
        self.assertEqual(caught.exception.errno, expected)

    def test_refresh_account_and_replay(self):
        fd = self.bound()
        update = Update(sequence=1, packets=(4, 2), octets=(400, 240), active=3)
        ioctl(fd, 1, update)
        value, counters = snapshot()
        self.assertEqual(counters, [(4, 344), (2, 204)])
        self.assertGreaterEqual(S.unpack('!I', value[7])[0], 58)
        self.error(errno.EINVAL, fd, 1, update)
        self.assertEqual(snapshot()[1], counters)

    def test_deleted_tuple_not_reused(self):
        fd = self.bound()
        netlink(2)
        create()
        self.error(errno.ESTALE, fd, 1, Update(sequence=1, packets=(1, 0), octets=(100, 0), active=1))
        self.assertEqual(snapshot()[1], [(0, 0), (0, 0)])
        self.assertLessEqual(S.unpack('!I', snapshot()[0][7])[0], 10)
        # A genuinely new object can acquire its own exclusive lease.
        self.bound()

    def test_duplicate_owner(self):
        self.bound()
        self.error(errno.EBUSY, self.open(), 0, identity())

    def test_identity_guards(self):
        for field in ('id', 'mark', 'labels', 'reply'):
            bind = identity()
            if field == 'labels': bind.labels[0] ^= 2
            elif field == 'reply': bind.reply.destination_port[0] ^= 1
            else: setattr(bind, field, getattr(bind, field) ^ 1)
            self.error(errno.ESTALE, self.open(), 0, bind)

    def test_unsupported_tcp_and_unassured(self):
        bind = identity(); bind.protocol = 6
        self.error(errno.EOPNOTSUPP, self.open(), 0, bind)
        netlink(2); create(status=0)
        self.error(errno.EOPNOTSUPP, self.open(), 0, identity())

    def test_reason_without_activity_does_not_refresh(self):
        fd = self.bound()
        ioctl(fd, 1, Update(sequence=1, packets=(1, 0), octets=(100, 0)))
        self.assertLessEqual(S.unpack('!I', snapshot()[0][7])[0], 10)
        self.assertEqual(snapshot()[1], [(1, 86), (0, 0)])

    def test_bad_counters_do_not_mutate(self):
        fd = self.bound()
        for update in (Update(sequence=1, packets=(1, 0), octets=(1, 0)),
                       Update(sequence=1, packets=(0, 0), octets=(100, 0)),
                       Update(sequence=1, packets=(1, 0), octets=(100, 0), active=2),
                       Update(sequence=1, packets=(1, 0), octets=(99999, 0))):
            self.error(errno.EINVAL, fd, 1, update)
        self.assertEqual(snapshot()[1], [(0, 0), (0, 0)])

    def test_close_releases_claim_but_preserves_connection(self):
        fd = self.bound(); os.close(fd); self.fds.remove(fd)
        self.bound()
        self.assertEqual(snapshot()[1], [(0, 0), (0, 0)])

    def test_rebind_rejected(self):
        fd = self.bound()
        self.error(errno.EALREADY, fd, 0, identity())

    def test_mark_change_invalidates(self):
        fd = self.bound()
        netlink(0, attr(8, S.pack('!I', 28)))
        self.error(errno.ESTALE, fd, 1, Update(sequence=1, packets=(1, 0), octets=(100, 0), active=1))
        self.assertEqual(snapshot()[1], [(0, 0), (0, 0)])
        netlink(0, attr(8, S.pack('!I', 27)))
        self.error(errno.ESTALE, fd, 1, Update(sequence=1, packets=(1, 0), octets=(100, 0), active=1))

    def test_label_change_invalidates(self):
        fd = self.bound()
        netlink(0, attr(22, b'\x02' + bytes(15)))
        self.error(errno.ESTALE, fd, 1, Update(sequence=1, packets=(1, 0), octets=(100, 0), active=1))
        self.assertEqual(snapshot()[1], [(0, 0), (0, 0)])

    def test_sequence_gap(self):
        fd = self.bound()
        self.error(errno.EINVAL, fd, 1, Update(sequence=2, packets=(1, 0), octets=(100, 0), active=1))
        self.assertEqual(snapshot()[1], [(0, 0), (0, 0)])

    def test_namespace_crossing(self):
        fd = self.bound()
        child = os.fork()
        if child == 0:
            try:
                libc = C.CDLL(None, use_errno=True)
                if libc.unshare(0x40000000) != 0: os._exit(2)
                self.error(errno.EPERM, fd, 1, Update(sequence=1, packets=(1, 0), octets=(100, 0), active=1))
            except BaseException: os._exit(3)
            os._exit(0)
        _, status = os.waitpid(child, 0)
        self.assertEqual(status, 0)
        self.assertEqual(snapshot()[1], [(0, 0), (0, 0)])

    def test_timeout_never_shortened(self):
        fd = self.bound()
        netlink(0, attr(7, S.pack('!I', 120)))
        ioctl(fd, 1, Update(sequence=1, packets=(1, 0), octets=(100, 0), active=1))
        self.assertGreaterEqual(S.unpack('!I', snapshot()[0][7])[0], 118)

    def test_expired_connection(self):
        fd = self.bound()
        netlink(0, attr(7, S.pack('!I', 1)))
        time.sleep(1.1)
        self.error(errno.ESTALE, fd, 1, Update(sequence=1, packets=(1, 0), octets=(100, 0), active=1))

    def test_native_check_does_not_refresh_or_account(self):
        lease=Lease(identity(),str(Path(__file__).with_name('libffn-ctlease.so')))
        try:
            lease.check()
            self.assertEqual(snapshot()[1],[(0,0),(0,0)])
            self.assertLessEqual(S.unpack('!I',snapshot()[0][7])[0],10)
            lease.update(1,(1,0),(100,0),0)
            lease.check()
            self.assertEqual(snapshot()[1],[(1,86),(0,0)])
        finally:lease.close()

    def test_native_idle_delete_and_recreate_invalidates(self):
        lease=Lease(identity(),str(Path(__file__).with_name('libffn-ctlease.so')))
        try:
            netlink(2);create()
            with self.assertRaises(OSError) as caught:lease.check()
            self.assertEqual(caught.exception.errno,errno.ESTALE)
            self.assertEqual(snapshot()[1],[(0,0),(0,0)])
        finally:lease.close()

    def test_native_idle_expiry_invalidates(self):
        lease=Lease(identity(),str(Path(__file__).with_name('libffn-ctlease.so')))
        try:
            netlink(0,attr(7,S.pack('!I',1)));time.sleep(1.1)
            with self.assertRaises(OSError) as caught:lease.check()
            self.assertEqual(caught.exception.errno,errno.ESTALE)
        finally:lease.close()

    def test_idle_label_change_is_sticky(self):
        lease=Lease(identity(),str(Path(__file__).with_name('libffn-ctlease.so')))
        try:
            netlink(0,attr(22,b'\x02'+bytes(15)))
            with self.assertRaises(OSError):lease.check()
            netlink(0,attr(22,b'\x01'+bytes(15)))
            with self.assertRaises(OSError):lease.check()
        finally:lease.close()

    def test_unbound_and_argument_checks(self):
        fd=self.open()
        with self.assertRaises(OSError) as caught:fcntl.ioctl(fd,COMMANDS[2],0)
        self.assertEqual(caught.exception.errno,errno.ENOTCONN)
        fd=self.bound()
        with self.assertRaises(OSError) as caught:fcntl.ioctl(fd,COMMANDS[2],1)
        self.assertEqual(caught.exception.errno,errno.EINVAL)


if __name__ == '__main__':
    assert os.environ.get('FFN_CTLEASE_ISOLATED_TEST') == 'yes'
    assert os.readlink('/proc/self/ns/net') != os.readlink('/proc/1/ns/net')
    # Some ip implementations do not remount sysfs for netns exec.
    assert {name for _, name in socket.if_nameindex()} <= {'lo', 'sit0'}
    links = json.loads(subprocess.check_output(['ip', '-j', 'link', 'show'], text=True))
    assert all('UP' not in item['flags'] and item['link_type'] in ('loopback', 'sit') for item in links)
    assert C.sizeof(Bind) == 72 and C.sizeof(Update) == 48
    COMMANDS = [int(v) for v in subprocess.check_output([str(Path(__file__).with_name('ctlease-abi'))], text=True).split()]
    unittest.main(verbosity=2)
