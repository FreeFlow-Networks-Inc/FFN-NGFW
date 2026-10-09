"""Control binding for the native identity-bound conntrack lease.

Only the trusted session coordinator may open one, before hardware admission.
Call close only after acknowledged hardware withdrawal. No packet I/O here.
"""
import ctypes as C
import os
import socket
import struct


class Tuple(C.Structure):
    _fields_ = [('source', C.c_ubyte * 4), ('destination', C.c_ubyte * 4),
                ('source_port', C.c_ubyte * 2), ('destination_port', C.c_ubyte * 2)]


class Bind(C.Structure):
    _fields_ = [('version', C.c_uint32), ('id', C.c_uint32), ('timeout', C.c_uint32),
                ('protocol', C.c_uint32), ('zone', C.c_uint16), ('reserved', C.c_uint16),
                ('mark', C.c_uint32), ('labels', C.c_ubyte * 16),
                ('original', Tuple), ('reply', Tuple), ('ethernet', C.c_uint16 * 2),
                ('reserved2', C.c_uint32)]


class Update(C.Structure):
    _fields_ = [('sequence', C.c_uint64), ('packets', C.c_uint64 * 2),
                ('octets', C.c_uint64 * 2), ('active', C.c_uint32), ('reserved', C.c_uint32)]


def tuple_abi(values):
    src, dst, sport, dport = values
    return Tuple.from_buffer_copy(socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack('!HH', sport, dport))


def tuple_values(value):
    return (socket.inet_ntoa(bytes(value.source)), socket.inet_ntoa(bytes(value.destination)),
            int.from_bytes(bytes(value.source_port), 'big'), int.from_bytes(bytes(value.destination_port), 'big'))


class Lease:
    def __init__(self, identity, library='/usr/lib/ffn/libffn-ctlease.so'):
        if not isinstance(identity, Bind): raise TypeError('native Bind identity required')
        if C.sizeof(Bind) != 72 or C.sizeof(Update) != 48: raise RuntimeError('unsupported native ABI')
        self.fd = -1
        self.original,self.reply=tuple_values(identity.original),tuple_values(identity.reply)
        self.protocol=identity.protocol
        self.library = C.CDLL(library)
        self.library.ffn_ctlease_open.argtypes = [C.POINTER(Bind)]
        self.library.ffn_ctlease_open.restype = C.c_int
        self.library.ffn_ctlease_update.argtypes = [C.c_int, C.POINTER(Update)]
        self.library.ffn_ctlease_update.restype = C.c_int
        self.library.ffn_ctlease_check.argtypes = [C.c_int]
        self.library.ffn_ctlease_check.restype = C.c_int
        self.library.ffn_ctlease_close.argtypes = [C.c_int]
        self.library.ffn_ctlease_close.restype = None
        result = self.library.ffn_ctlease_open(C.byref(identity))
        if result < 0: raise OSError(-result, os.strerror(-result))
        self.fd = result

    def update(self, sequence, packets, octets, active_mask):
        values = (sequence, *packets, *octets)
        if len(packets) != 2 or len(octets) != 2 or any(type(v) is not int or not 0 <= v < 2**64 for v in values):
            raise ValueError('invalid accounting update')
        if type(active_mask) is not int or not 0 <= active_mask <= 3: raise ValueError('invalid activity mask')
        if self.fd < 0: raise RuntimeError('lease closed')
        update = Update(sequence=sequence, packets=packets, octets=octets, active=active_mask)
        result = self.library.ffn_ctlease_update(self.fd, C.byref(update))
        if result < 0: raise OSError(-result, os.strerror(-result))

    def check(self):
        """Validate an idle connection without changing counters or timeout."""
        if self.fd < 0: raise RuntimeError('lease closed')
        result = self.library.ffn_ctlease_check(self.fd)
        if result < 0: raise OSError(-result, os.strerror(-result))

    def close(self):
        if self.fd >= 0:
            self.library.ffn_ctlease_close(self.fd)
            self.fd = -1
