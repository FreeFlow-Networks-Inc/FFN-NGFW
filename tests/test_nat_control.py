import copy
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch,AsyncMock
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'opt'))
from ffn_nat_control import NatGateway,NatError,reconcile
from ffn_nat_policy import compile_policy
from test_nat_policy import configuration


class NatControlTests(unittest.IsolatedAsyncioTestCase):
    async def test_commit_only_plan_and_dp_acknowledgments(self):
        with tempfile.TemporaryDirectory() as temp:
            xml=configuration();Path(temp,'running-config.xml').write_bytes(xml)
            plan=compile_policy(xml)['plan'];planes=AsyncMock()
            async def request(args):
                r=args['request'];result={'available':True,'revision':7} if r['action']=='status' else {'applied':True,'revision':8,'digest':'test'}
                return {'ok':True,'result':result,'trace':['mp','cp','dp'],'state':'applied'}
            planes.request.side_effect=request;gateway=NatGateway(planes,temp)
            with patch('ffn_nat_control.commissioned',return_value=True):
                with self.assertRaisesRegex(NatError,'committed'):await gateway.apply({'plan':{'version':1,'rules':[]}})
                planes.request.assert_not_called()
                result=await gateway.apply({'plan':plan});self.assertTrue(result['applied'])
                self.assertEqual(planes.request.call_args.args[0]['request']['payload'],{'revision':7,'plan':plan})

    async def test_unavailable_dp_cannot_apply(self):
        with tempfile.TemporaryDirectory() as temp:
            Path(temp,'running-config.xml').write_bytes(configuration());gateway=NatGateway(AsyncMock(),temp)
            gateway.worker=AsyncMock(return_value={'available':False,'error':'kernel missing'})
            with patch('ffn_nat_control.commissioned',return_value=True):
                with self.assertRaisesRegex(NatError,'kernel missing'):await gateway.apply({'plan':compile_policy(configuration())['plan']})
                self.assertEqual(gateway.worker.call_count,1)


if __name__=='__main__':unittest.main()
