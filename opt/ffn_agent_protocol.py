# SPDX-License-Identifier: GPL-2.0-or-later
"""Bounded agent reports over an authenticated, persistent stdio transport."""
import json
import sys
import time
import uuid

LIMIT = 262144


def frame(value):
    raw = json.dumps(value, separators=(',', ':'), allow_nan=False).encode() + b'\n'
    if len(raw) > LIMIT:
        raise ValueError('agent frame too large')
    return raw


def parse(raw):
    if len(raw) > LIMIT or not raw.endswith(b'\n'):
        raise ValueError('incomplete or oversized agent frame')
    result = json.loads(raw, parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite number')))
    if not isinstance(result, dict):
        raise ValueError('agent object required')
    return result


def canonical(value):
    if not isinstance(value, str) or str(uuid.UUID(value)) != value:
        raise ValueError('canonical UUID required')
    return value


def serve(provider, role, platform, source=None, sink=None):
    """One challenge per fresh observation; no commands or write operations."""
    source = source or sys.stdin.buffer
    sink = sink or sys.stdout.buffer
    instance = str(uuid.uuid4())
    sequence = 0
    while True:
        raw = source.readline(LIMIT + 1)
        if not raw:
            return
        request = parse(raw)
        if (set(request) != {'v', 'nonce', 'op'} or type(request['v']) is not int
                or request['v'] != 1 or request['op'] != 'observe'):
            raise ValueError('invalid observation request')
        nonce = canonical(request['nonce'])
        report = provider()
        if not isinstance(report, dict) or type(report.get('ready')) is not bool:
            raise ValueError('invalid provider report')
        boot = canonical(report['boot_id'])
        sequence += 1
        sink.write(frame({'v': 1, 'nonce': nonce, 'role': role, 'platform': platform,
                         'instance': instance, 'boot_id': boot, 'sequence': sequence,
                         'observed_at': time.time(), 'report': report}))
        sink.flush()


def validate(reply, nonce, role, platform, previous=None):
    if (set(reply) != {'v', 'nonce', 'role', 'platform', 'instance', 'boot_id',
                      'sequence', 'observed_at', 'report'} or type(reply['v']) is not int
            or reply['v'] != 1 or reply['nonce'] != nonce or reply['role'] != role
            or reply['platform'] != platform or type(reply['sequence']) is not int
            or reply['sequence'] < 1 or not isinstance(reply['report'], dict)
            or type(reply['report'].get('ready')) is not bool
            or reply['report'].get('boot_id') != reply['boot_id']):
        raise ValueError('agent identity or challenge mismatch')
    canonical(reply['instance']); canonical(reply['boot_id'])
    if previous and (reply['instance'] != previous['instance']
                     or reply['boot_id'] != previous['boot_id']
                     or reply['sequence'] != previous['sequence'] + 1):
        raise ValueError('agent restarted or replayed a report within the channel')
    return reply
