"""Real Linux route/neighbor observations in a disposable, isolated namespace."""
import os
from pathlib import Path
import subprocess
import sys
import time
import uuid


def run(*args):
    return subprocess.check_output(args, text=True, stderr=subprocess.STDOUT, timeout=10)


def inside():
    import fcntl
    import struct
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'opt'))
    import ffn_l3_offload as l3
    descriptors = []
    try:
        for name, address in [('lan', '192.0.2.1/24'), ('wan', '203.0.113.2/24')]:
            fd = os.open('/dev/net/tun', os.O_RDWR); descriptors.append(fd)
            fcntl.ioctl(fd, 0x400454ca, struct.pack('16sH', name.encode(), 0x1002))
            run('ip', 'link', 'set', name, 'alias', 'ffn-test:' + name)
            run('ip', 'link', 'set', name, 'up')
            run('ip', 'address', 'add', address, 'dev', name)
        run('ip', 'route', 'add', 'default', 'via', '203.0.113.1', 'dev', 'wan')
        for dev, address, mac in [('lan', '192.0.2.5', '02:00:00:00:00:05'),
                                  ('wan', '203.0.113.1', '02:00:00:00:00:07')]:
            run('ip', 'neigh', 'replace', address, 'lladdr', mac, 'nud', 'permanent', 'dev', dev)
        state = l3.snapshot(time.monotonic() + 5)
        bindings = {p['ifname']: dict(device=p['ifname'], index=p['ifindex'], alias=p['ifalias'])
                    for p in state['links'] if p['ifname'] in ('lan', 'wan')}
        session = dict(software_candidate=True, rule={'interface_pairs': [['lan', 'wan']]},
                       original={'source': '192.0.2.5'}, translated={'destination': '198.51.100.2'})
        result = l3.plan(session, bindings, state)
        assert result['available'], result
        assert result['directions'][0]['next_hop'] == '203.0.113.1'
        assert result['directions'][1]['destination_mac'] == '02:00:00:00:00:05'
        assert not result['hardware_admission']
        run('ip', 'neigh', 'del', '203.0.113.1', 'dev', 'wan')
        changed = l3.snapshot(time.monotonic() + 5)
        assert l3.fingerprint(changed) != l3.fingerprint(state)
        assert not l3.plan(session, bindings, changed)['available']
        print('PASS: real TAP routes, two-way next hops, neighbor withdrawal; no hardware admission')
    finally:
        for fd in descriptors: os.close(fd)


def main():
    namespace = 'ffn-l3-' + uuid.uuid4().hex[:8]
    run('ip', 'netns', 'add', namespace)
    try:
        print(run('ip', 'netns', 'exec', namespace, sys.executable, str(Path(__file__).resolve()), '--inside'))
    finally:
        run('ip', 'netns', 'delete', namespace)


if __name__ == '__main__':
    inside() if sys.argv[1:] == ['--inside'] else main()
