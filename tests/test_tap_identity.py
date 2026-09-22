"""TAP recreation retains the appliance's own MAC; native NICs stay untouched."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'opt'))
import ffn_linux_network as net


class IdentityTests(unittest.TestCase):
    def setUp(self):
        folder=tempfile.TemporaryDirectory();self.addCleanup(folder.cleanup)
        item=patch.object(net,'STATE',Path(folder.name)/'network.json');item.start();self.addCleanup(item.stop)

    def test_persisted_identity_survives_recreation_and_ports_are_distinct(self):
        self.assertEqual(net.remember_tap_mac('p1','02:00:00:00:00:01'),'02:00:00:00:00:01')
        self.assertEqual(net.remember_tap_mac('p1','02:00:00:00:00:02'),'02:00:00:00:00:01')
        self.assertEqual(net.remember_tap_mac('p2','02:00:00:00:00:02'),'02:00:00:00:00:02')
        self.assertEqual(len(json.loads(net.STATE.with_name('port-macs.json').read_text())),2)

    def test_recreated_tap_uses_saved_mac_before_becoming_active(self):
        net.remember_tap_mac('p1','02:00:00:00:00:01');calls=[]
        def ip(*args):
            calls.append(args)
            return json.dumps([{'address':'02:00:00:00:00:02'}])
        with patch.object(net,'ip',side_effect=ip),patch.object(net,'run'):
            net.configure_port('p1',{'mode':'l3','addresses':[]},create=True)
        self.assertLess(calls.index(('link','set','p1','address','02:00:00:00:00:01')),calls.index(('link','set','p1','up')))

    def test_existing_mac_drift_is_rejected_before_link_changes(self):
        net.remember_tap_mac('p1','02:00:00:00:00:01')
        with patch.object(net,'ip',return_value='[{"address":"02:00:00:00:00:02"}]') as ip:
            with self.assertRaisesRegex(RuntimeError,'MAC changed'):net.configure_port('p1',{'mode':'disabled'})
        self.assertEqual(ip.call_count,1)

    def test_native_interfaces_do_not_acquire_synthetic_identities(self):
        with patch.object(net,'PORT_BACKEND','native'),patch.object(net,'ip',return_value='[{}]'),patch.object(net,'remember_tap_mac') as remember:
            net.configure_port('eth0',{'mode':'disabled'})
        remember.assert_not_called()

    def test_invalid_multicast_and_corrupt_identity_are_rejected(self):
        for value in ('00:00:00:00:00:00','01:00:00:00:00:01','not-a-mac'):
            with self.assertRaises(ValueError):net.remember_tap_mac('p1',value)
        net.STATE.with_name('port-macs.json').write_text('{"p1":"broken"}')
        with self.assertRaises(ValueError):net.remember_tap_mac('p1','02:00:00:00:00:01')


if __name__=='__main__':unittest.main()
