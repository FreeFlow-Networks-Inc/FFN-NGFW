import asyncio
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'opt'))
from ffn_security_control import projection, SecurityGateway, NatError
from test_policy_plan import configuration


class SecurityControlTests(unittest.TestCase):
    def test_projection_excludes_credentials_and_is_idempotent(self):
        xml=configuration('security',{'action':'allow'}).replace(b'<config>',b'<config><mgt-config><password>secret</password></mgt-config>')
        projected=projection(xml)
        self.assertNotIn('secret',projected);self.assertNotIn('DO-NOT-EXPOSE',projected)
        self.assertEqual(projected,projection(projected));self.assertIn('ethernet1/1',projected)

    def test_apply_rejects_candidate_or_direct_rule_payload(self):
        async def test():
            with tempfile.TemporaryDirectory() as directory:
                Path(directory,'running-config.xml').write_bytes(configuration('security',{'action':'drop','log-end':'no'}))
                g=SecurityGateway(None,directory)
                with patch('ffn_security_control.commissioned',return_value=True):
                    with self.assertRaises(NatError):await g.apply({'xml':projection(configuration('security',{'action':'allow'}))})
        asyncio.run(test())

    def test_install_boundaries_idempotent_and_reject_unknown_layout(self):
        path=Path(__file__).resolve().parents[1]/'image/install-security.py'
        spec=importlib.util.spec_from_file_location('install_security',path);mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
        code='''def demo():
        self.nat = NatGateway(self.planes, os.getenv('FFN_CONFIG_DIR','/var/lib/ffn-ngfw/config'))
        handlers={
            "nat/apply":                self.nat.apply,
        }
'''
        merged=mod.merge_control(code);self.assertEqual(merged,mod.merge_control(merged))
        with self.assertRaises(ValueError):mod.merge_control('pass\n')
        code='''def demo():
        changes={}
        # FFN NAT is reconciled as one ordered rulebase, including deletions.
        pass
'''
        merged=mod.merge_configd(code);self.assertEqual(merged,mod.merge_configd(merged))
        self.assertIn('.rulebase.security.',merged)


if __name__=='__main__':unittest.main()
