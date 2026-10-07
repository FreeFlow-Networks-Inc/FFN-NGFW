"""A new dataplane kernel lifetime is a restore, not a drift, in prepare()."""
import sys
from pathlib import Path
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'opt'))
import ffn_security_runtime as runtime

XML='<policy/>'
BINDINGS={'ethernet1/1':{'device':'p1','index':4}}


def saved_state(boot_id):
    return dict(version=1,revision=4,token_generation=1,xml=XML,digest='d',bindings=BINDINGS,
                tables=[['inet','ffn_policy_gate'],['inet','ffn_security'],['ip','ffn_nat']],kernel_digest='k-saved',
                boot_id=boot_id,nat=dict(revision=5,digest='n',plan={'rules':[]},script='s'))


class RestoreTests(unittest.TestCase):
    def prepare(self,old,names,replay=False,revision=4):
        """Run prepare() against a kernel whose tables are `names` and whose
        fingerprint never matches the saved record; report what the NAT layer
        was told about restoring."""
        seen={}
        def nat_prepare(request,allow_restore=False,*,validation_network=None):
            seen['allow_restore']=allow_restore
            return dict(revision=5,digest='n'),None,None
        patches=[patch.object(runtime,'saved',return_value=old),patch.object(runtime,'boot',return_value='boot-now'),
                 patch.object(runtime,'health'),patch.object(runtime,'bindings',return_value=(BINDINGS,{})),
                 patch.object(runtime,'inventory',return_value={'nftables':[]}),patch.object(runtime,'guard_scripts',return_value={}),
                 patch.object(runtime,'ownership'),patch.object(runtime,'compile_policy',return_value={'valid':True,'plan':{'rules':[]}}),
                 patch.object(runtime,'tokens_for',return_value=({},{})),patch.object(runtime,'render',return_value={'script':'sec','digest':'d'}),
                 patch.object(runtime,'digest',return_value='n'),patch.object(runtime,'table_names',return_value=names),
                 patch.object(runtime,'fingerprint',return_value='k-live'),patch.object(runtime,'gate',return_value='gate'),
                 patch.object(runtime.nat,'run',return_value='[]'),patch.object(runtime.nat,'saved',return_value={'revision':5}),
                 patch.object(runtime.nat,'prepare',side_effect=nat_prepare),patch.object(runtime.nat,'render',return_value='natscript'),
                 patch.object(runtime.nat,'nft')]
        for item in patches:item.start();self.addCleanup(item.stop)
        try:return runtime.prepare({'revision':revision,'xml':XML},replay=replay),seen
        finally:
            for item in patches:item.stop()

    def test_new_kernel_lifetime_without_tables_is_a_restore(self):
        (old,state,batch,_),seen=self.prepare(saved_state('boot-before'),set())
        self.assertTrue(seen['allow_restore'])
        self.assertEqual(state['boot_id'],'boot-now')
        self.assertIn(('inet','ffn_security'),state['tables'])
        self.assertEqual(batch,'gatesecnatscript')

    def test_new_kernel_lifetime_with_a_foreign_security_table_is_still_drift(self):
        with self.assertRaisesRegex(runtime.NatError,'Security table drift'):
            self.prepare(saved_state('boot-before'),{('inet','ffn_security')})

    def test_same_kernel_lifetime_keeps_the_drift_guard(self):
        with self.assertRaisesRegex(runtime.NatError,'Security table drift'):
            self.prepare(saved_state('boot-now'),set())

    def test_replay_and_first_apply_are_unchanged(self):
        _,seen=self.prepare(saved_state('boot-now'),set(),replay=True)
        self.assertTrue(seen['allow_restore'])
        _,seen=self.prepare(None,set(),revision=0)
        self.assertFalse(seen['allow_restore'])
        self.assertFalse(runtime.kernel_lifetime_changed(None,'boot-now'))
        self.assertTrue(runtime.kernel_lifetime_changed({'boot_id':'x'},'boot-now'))


if __name__=='__main__':unittest.main()
