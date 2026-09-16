import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'opt'))
from ffn_vr_interfaces import inventory, validate_route


class Interfaces(unittest.TestCase):
    def setUp(self):
        self.rows = inventory({'ethernet':[
            {'name':'ethernet1/1','mode':'layer3','ip_addresses':['192.0.2.2/24'],'sub_interfaces':['ethernet1/1.100']},
            {'name':'ethernet1/2','mode':'layer2'},
            {'name':'ethernet1/3','mode':'aggregate-group'}],
            'aggregate-ethernet':[{'name':'ae1','mode':'layer3'}],
            'loopback':[{'name':'loopback','mode':'layer3','sub_interfaces':['loopback.1']}]},
            [{'name':'tenant','interfaces':['eth8']}], {'ethernet1/1.100':'eth8'})
        self.route = {'dest_cidr':'0.0.0.0/0','next_hop':'192.0.2.1','dev':'ethernet1/1','metric':100}

    def test_catalog_uses_configured_l3_and_normalizes_membership(self):
        self.assertEqual({r['name'] for r in self.rows},{'ethernet1/1','ethernet1/1.100','ae1','loopback.1'})
        self.assertEqual(next(r for r in self.rows if r['name']=='ethernet1/1.100')['virtual_router'],'tenant')

    def test_valid_default_route_and_onlink(self):
        self.assertEqual(validate_route(self.route,'default',self.rows),self.route)
        self.assertEqual(validate_route(self.route|{'next_hop':''},'default',self.rows)['dev'],'ethernet1/1')

    def test_unknown_non_l3_and_other_router_are_rejected(self):
        for dev in ('management0','ethernet1/2','ethernet1/1.100','eth8'):
            with self.assertRaises(ValueError):validate_route(self.route|{'dev':dev},'default',self.rows)

    def test_family_prefix_and_metric_validation(self):
        for change in ({'next_hop':'::1'},{'dest_cidr':'192.0.2.3/24'},{'metric':-1},{'metric':2**32},{'metric':True},{'dev':None,'next_hop':''}):
            with self.assertRaises(ValueError):validate_route(self.route|change,'default',self.rows)
        validate_route(self.route|{'dest_cidr':'::/0','next_hop':'2001:db8::1'},'default',self.rows)


if __name__=='__main__':unittest.main()
