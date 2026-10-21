"""Physical TAPs take queues: made with multi_queue, and a plain one is remade once, keeping what was on it."""
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'opt'))
import ffn_linux_network as net

PLAIN = [{'ifindex': 8, 'ifname': 'p5', 'address': 'b2:bd:5a:dd:09:6a',
          'linkinfo': {'info_kind': 'tun', 'info_data': {'type': 'tap', 'multi_queue': False, 'persist': True}}}]
QUEUED = [{'ifindex': 41, 'ifname': 'p5', 'address': '02:00:00:00:00:41',
           'linkinfo': {'info_kind': 'tun', 'info_data': {'type': 'tap', 'multi_queue': True, 'persist': True}}}]
ROUTES4 = [{'dst': 'default', 'gateway': '152.193.185.9', 'dev': 'p5', 'protocol': 'static', 'metric': 100, 'flags': []},
           {'dst': '152.193.185.8/29', 'dev': 'p5', 'protocol': 'kernel', 'scope': 'link', 'prefsrc': '152.193.185.10', 'flags': []},
           {'dst': '10.9.0.0/16', 'gateway': '152.193.185.12', 'dev': 'p5', 'table': 101, 'protocol': 'boot', 'flags': ['onlink']},
           {'dst': '10.1.0.0/22', 'dev': 'ae1.69', 'protocol': 'kernel', 'scope': 'link', 'prefsrc': '10.1.0.1', 'flags': []},
           {'type': 'local', 'dst': '152.193.185.10', 'dev': 'p5', 'table': 'local', 'protocol': 'kernel', 'scope': 'host', 'flags': []},
           {'dst': '10.8.0.0/24', 'protocol': 'static', 'flags': [], 'nexthops': [
               {'gateway': '152.193.185.9', 'dev': 'p5', 'weight': 1, 'flags': []}, {'gateway': '10.1.0.2', 'dev': 'ae1.69', 'weight': 1, 'flags': []}]}]
ROUTES6 = [{'dst': 'fe80::/64', 'dev': 'p5', 'protocol': 'kernel', 'metric': 256, 'flags': [], 'pref': 'medium'},
           {'dst': '2001:db8::/32', 'gateway': 'fe80::1', 'dev': 'p5', 'protocol': 'static', 'metric': 1024, 'flags': [], 'pref': 'medium'},
           {'dst': '2001:db8:1::/48', 'gateway': 'fe80::2', 'dev': 'p5', 'protocol': 'ra', 'metric': 1024, 'expires': 1700, 'flags': [], 'pref': 'medium'}]
ADDRESSES = [{'ifname': 'p5', 'addr_info': [
    {'family': 'inet', 'local': '152.193.185.10', 'prefixlen': 29, 'scope': 'global'},
    {'family': 'inet', 'local': '152.193.185.11', 'prefixlen': 29, 'scope': 'global'},
    {'family': 'inet6', 'local': 'fe80::b0bd:5aff:fedd:96a', 'prefixlen': 64, 'scope': 'link'}]}]
SETTINGS = {'mode': 'l3', 'addresses': ['152.193.185.10/29']}


class Kernel:
    """Answers the engine's queries as iproute2 would, before and after the remake, and records writes."""
    def __init__(self, multiqueue=False):
        self.calls = []; self.link = QUEUED if multiqueue else PLAIN; self.deleted = False

    def ip(self, *args):
        self.calls.append(args)
        if args[:2] == ('-d', '-j') and args[2:5] == ('link', 'show', 'dev'):
            if self.deleted: raise RuntimeError('Cannot find device')
            return json.dumps(self.link)
        if args[:4] == ('-j', 'link', 'show', 'dev'): return json.dumps(self.link)
        if args == ('-j', 'link'): return json.dumps([] if self.deleted else self.link)
        if args[:2] == ('-4', '-j'): return json.dumps(ROUTES4)
        if args[:2] == ('-6', '-j'): return json.dumps(ROUTES6)
        if args[:4] == ('-j', 'address', 'show', 'dev'): return json.dumps(ADDRESSES)
        if args[:2] == ('link', 'delete'): self.deleted = True
        return ''

    def run(self, *args):
        self.calls.append(args)
        if 'tuntap' in args and 'add' in args:
            self.deleted = False; self.link = QUEUED
        return ''


class TapQueueTests(unittest.TestCase):
    def setUp(self):
        overlay = patch.object(net, 'OVERLAY_STATE'); overlay.start().exists.return_value = False; self.addCleanup(overlay.stop)
        identity = patch.object(net, 'remember_tap_mac', return_value='b2:bd:5a:dd:09:6a'); identity.start(); self.addCleanup(identity.stop)
        exists = patch.object(net, 'exists', return_value=True); exists.start(); self.addCleanup(exists.stop)

    def test_physical_tap_is_created_with_multi_queue(self):
        kernel = Kernel(multiqueue=True)
        with patch.object(net, 'ip', side_effect=kernel.ip), patch.object(net, 'run', side_effect=kernel.run):
            net.configure_port('p5', SETTINGS, create=True)
        self.assertIn(('ip', 'netns', 'exec', net.NS, 'ip', 'tuntap', 'add', 'dev', 'p5', 'mode', 'tap', 'multi_queue'), kernel.calls)

    def test_route_arguments_round_trip(self):
        self.assertEqual(net.route_arguments('-4', ROUTES4[0]),
                         ['-4', 'route', 'replace', 'default', 'via', '152.193.185.9', 'dev', 'p5', 'metric', '100', 'proto', 'static'])
        self.assertEqual(net.route_arguments('-4', ROUTES4[2]),
                         ['-4', 'route', 'replace', '10.9.0.0/16', 'via', '152.193.185.12', 'dev', 'p5', 'onlink', 'table', '101', 'proto', 'boot'])
        self.assertEqual(net.route_arguments('-4', ROUTES4[5]),
                         ['-4', 'route', 'replace', '10.8.0.0/24', 'nexthop', 'via', '152.193.185.9', 'dev', 'p5', 'weight', '1',
                          'nexthop', 'via', '10.1.0.2', 'dev', 'ae1.69', 'weight', '1', 'proto', 'static'])
        self.assertEqual(net.route_arguments('-6', ROUTES6[1]),
                         ['-6', 'route', 'replace', '2001:db8::/32', 'via', 'fe80::1', 'dev', 'p5', 'metric', '1024', 'proto', 'static', 'pref', 'medium'])
        self.assertEqual(net.route_arguments('-4', {'type': 'blackhole', 'dst': '10.0.0.0/8', 'protocol': 'static', 'flags': []}),
                         ['-4', 'route', 'replace', 'blackhole', '10.0.0.0/8', 'proto', 'static'])

    def test_owners_routes_are_kept_and_the_kernels_are_not(self):
        kernel = Kernel()
        with patch.object(net, 'ip', side_effect=kernel.ip):
            kept = net.device_routes('p5')
        self.assertEqual([(f, r['dst']) for f, r in kept], [('-4', 'default'), ('-4', '10.9.0.0/16'), ('-4', '10.8.0.0/24'), ('-6', '2001:db8::/32')])
        with patch.object(net, 'ip', side_effect=kernel.ip):
            self.assertEqual(net.extra_addresses('p5', SETTINGS), ['152.193.185.11/29'])

    def test_plain_tap_is_remade_once_with_identity_addresses_and_routes(self):
        kernel = Kernel()
        with patch.object(net, 'ip', side_effect=kernel.ip), patch.object(net, 'run', side_effect=kernel.run):
            report = net.reconcile_taps({'revision': 3, 'ports': {'p5': SETTINGS, 'p3': {'mode': 'disabled'}}}, only=['p5'])
        self.assertEqual(report, {'p5': {'remade': True, 'routes_restored': 4, 'addresses_restored': 1}})
        calls = kernel.calls
        delete = calls.index(('link', 'delete', 'dev', 'p5'))
        create = calls.index(('ip', 'netns', 'exec', net.NS, 'ip', 'tuntap', 'add', 'dev', 'p5', 'mode', 'tap', 'multi_queue'))
        identity = calls.index(('link', 'set', 'p5', 'address', 'b2:bd:5a:dd:09:6a'))
        own = calls.index(('address', 'add', '152.193.185.10/29', 'dev', 'p5'))
        up = calls.index(('link', 'set', 'p5', 'up'))
        extra = calls.index(('address', 'replace', '152.193.185.11/29', 'dev', 'p5'))
        default = calls.index(('-4', 'route', 'replace', 'default', 'via', '152.193.185.9', 'dev', 'p5', 'metric', '100', 'proto', 'static'))
        # Snapshot before the delete; identity before the link comes up; addresses before routes.
        self.assertLess(max(i for i, c in enumerate(calls) if c[:2] in (('-4', '-j'), ('-6', '-j')) or c[:3] == ('-j', 'address', 'show')), delete)
        self.assertLess(delete, create); self.assertLess(create, identity); self.assertLess(identity, up)
        self.assertLess(up, extra); self.assertLess(extra, default)
        self.assertFalse(any(c[:3] == ('-4', 'route', 'replace') and c[3] == '152.193.185.8/29' for c in calls), 'kernel route re-added')
        self.assertFalse(any(c[:3] == ('-6', 'route', 'replace') and c[3] == '2001:db8:1::/48' for c in calls), 'expiring RA route re-added')
        # Once: the device now takes queues, so a second pass changes nothing.
        before = len(kernel.calls)
        with patch.object(net, 'ip', side_effect=kernel.ip), patch.object(net, 'run', side_effect=kernel.run):
            report = net.reconcile_taps({'revision': 3, 'ports': {'p5': SETTINGS}})
        self.assertEqual(report, {'p5': {'remade': False, 'reason': 'multi_queue'}})
        self.assertFalse(any(c[:2] in (('link', 'delete'), ('address', 'replace')) or 'tuntap' in c for c in kernel.calls[before:]))

    def test_underlay_and_foreign_devices_are_left_alone_and_a_missing_tap_is_made(self):
        kernel = Kernel()
        with patch.object(net.OVERLAY_STATE, 'exists', return_value=True), \
             patch.object(net.OVERLAY_STATE, 'read_text', return_value=json.dumps({'links': {'ov1': {'underlay': 'p5'}}})), \
             patch.object(net, 'ip', side_effect=kernel.ip), patch.object(net, 'run', side_effect=kernel.run):
            report = net.reconcile_taps({'revision': 3, 'ports': {'p5': SETTINGS}})
        self.assertFalse(report['p5']['remade']); self.assertIn('underlay', report['p5']['reason'])
        self.assertFalse(any(c[:2] == ('link', 'delete') for c in kernel.calls))
        kernel = Kernel(); kernel.deleted = True
        with patch.object(net, 'ip', side_effect=kernel.ip), patch.object(net, 'run', side_effect=kernel.run):
            report = net.reconcile_taps({'revision': 3, 'ports': {'p5': SETTINGS}})
        self.assertEqual(report['p5'], {'remade': False, 'created': True, 'reason': 'device was missing'})
        self.assertIn(('ip', 'netns', 'exec', net.NS, 'ip', 'tuntap', 'add', 'dev', 'p5', 'mode', 'tap', 'multi_queue'), kernel.calls)
        with patch.object(net, 'PORT_BACKEND', 'native'), patch.object(net, 'ip') as ip:
            self.assertEqual(net.reconcile_taps({'revision': 3, 'ports': {'p5': SETTINGS}}), {})
        ip.assert_not_called()


if __name__ == '__main__': unittest.main()
