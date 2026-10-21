"""Opt-in root integration test: a plain physical TAP is remade with multi_queue, keeping its MAC, addresses and routes.

Only a disposable namespace named after this process is used; the engine's
state files live in a temporary directory.
"""
import json
from pathlib import Path
import subprocess as S
import sys
import tempfile
import uuid
sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'opt'))
import ffn_linux_network as net


def main():
    token = uuid.uuid4().hex[:8]
    ns = 'ffn-test-' + token
    def run(*args): return S.run(args, check=True, capture_output=True, text=True).stdout
    def link(name): return json.loads(run('ip', '-n', ns, '-d', '-j', 'link', 'show', 'dev', name))[0]
    def routes(family): return json.loads(run('ip', '-n', ns, family, '-j', 'route', 'show', 'table', 'all'))
    made = False
    try:
        with tempfile.TemporaryDirectory() as temp:
            net.NS = ns; net.PORT_BACKEND = 'tap'
            net.STATE = Path(temp)/'network.json'; net.OVERLAY_STATE = Path(temp)/'overlay.json'
            cfg = {'revision': 0, 'ports': {'p1': {'mode': 'l3', 'addresses': ['192.0.2.1/24']}, 'p2': {'mode': 'disabled'}},
                   'routes': [{'dst': '198.51.100.0/24', 'via': '192.0.2.2', 'dev': 'p1'}]}
            net.save(cfg); net.start(cfg); made = True
            assert net.tap_multiqueue('p1') is True and net.tap_multiqueue('p2') is True, 'boot-time TAPs lack multi_queue'
            identity = json.loads(net.STATE.with_name('port-macs.json').read_text())['p1']
            assert link('p1')['address'] == identity
            # What an older engine left: a plain TAP with the remembered MAC, the port's address, another owner's
            # address, the engine's static route and a route another owner put in its own table.
            run('ip', '-n', ns, 'link', 'delete', 'dev', 'p1')
            run('ip', '-n', ns, 'tuntap', 'add', 'dev', 'p1', 'mode', 'tap')
            run('ip', '-n', ns, 'link', 'set', 'p1', 'address', identity, 'up')
            run('ip', '-n', ns, 'address', 'add', '192.0.2.1/24', 'dev', 'p1')
            run('ip', '-n', ns, 'address', 'add', '192.0.2.9/24', 'dev', 'p1')
            run('ip', '-n', ns, 'route', 'add', '198.51.100.0/24', 'via', '192.0.2.2', 'dev', 'p1', 'metric', '100', 'proto', 'static')
            run('ip', '-n', ns, 'route', 'add', '203.0.113.0/24', 'via', '192.0.2.3', 'dev', 'p1', 'table', '101')
            run('ip', '-n', ns, '-6', 'route', 'add', '2001:db8::/32', 'dev', 'p1', 'metric', '1024', 'proto', 'static')
            old_index = link('p1')['ifindex']
            assert net.tap_multiqueue('p1') is False
            report = net.reconcile_taps(cfg)
            assert report['p1'] == {'remade': True, 'routes_restored': 3, 'addresses_restored': 1}, report
            assert report['p2'] == {'remade': False, 'reason': 'multi_queue'}, report
            new = link('p1')
            assert new['ifindex'] != old_index and new['linkinfo']['info_data']['multi_queue'] is True, new
            assert new['address'] == identity, 'MAC identity lost: %s' % new['address']
            assert 'UP' in new['flags']
            addresses = {a['local'] + '/' + str(a['prefixlen']) for row in json.loads(run('ip', '-n', ns, '-j', 'address', 'show', 'dev', 'p1'))
                         for a in row['addr_info'] if a['family'] == 'inet'}
            assert addresses == {'192.0.2.1/24', '192.0.2.9/24'}, addresses
            # iproute2 prints no protocol for a boot route and the table id as a string.
            v4 = {(r.get('dst'), r.get('gateway'), r.get('dev'), r.get('metric'), r.get('protocol'), str(r.get('table'))) for r in routes('-4')}
            assert ('198.51.100.0/24', '192.0.2.2', 'p1', 100, 'static', 'None') in v4, v4
            assert ('203.0.113.0/24', '192.0.2.3', 'p1', None, None, '101') in v4, v4
            assert ('192.0.2.0/24', None, 'p1', None, 'kernel', 'None') in v4, v4
            v6 = {(r.get('dst'), r.get('dev'), r.get('metric'), r.get('protocol')) for r in routes('-6')}
            assert ('2001:db8::/32', 'p1', 1024, 'static') in v6, v6
            assert net.reconcile_taps(cfg) == {'p1': {'remade': False, 'reason': 'multi_queue'}, 'p2': {'remade': False, 'reason': 'multi_queue'}}
            assert link('p1')['ifindex'] == new['ifindex'], 'a device that takes queues was remade again'
            # A queue of the new device opens as a queue: what the packet owner's lanes need.
            run('ip', '-n', ns, 'link', 'delete', 'dev', 'p2')
            assert net.reconcile_taps(cfg, only=['p2'])['p2'] == {'remade': False, 'created': True, 'reason': 'device was missing'}
            assert net.tap_multiqueue('p2') is True
            print('TAP backend: multi_queue creation, one-time remake keeping MAC, addresses and routes, and recreation of a missing device passed')
    finally:
        if made:
            S.run(['ip', 'netns', 'delete', ns], check=True)


if __name__ == '__main__': main()
