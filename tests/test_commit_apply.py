import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'opt'))
from ffn_commit_apply import ApplyCycle, ordered_paths, STAGES


class Status:
    def __init__(self):self.errors=[];self.validation_errors=[]


class CommitTests(unittest.TestCase):
    def test_orders_definitions_parents_units_zones_routes_and_rules(self):
        paths=['d.rulebase.security.rule','d.network.virtual-router.route','d.zone.z',
               'd.network.interface.aggregate-ethernet.a.units.u.ip',
               'd.network.interface.ethernet.e.aggregate-group','d.network.interface.aggregate-ethernet.a',
               'd.network.profiles.interface-management-profile.p']
        self.assertEqual(ordered_paths({p:{'kind':'added'} for p in paths}),list(reversed(paths)))
        self.assertEqual(ordered_paths({p:{'kind':'removed'} for p in paths}),paths)

    def test_failure_stops_dependencies_and_checkpoint(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'running';path.write_bytes(b'new');last=Path(temp)/'last';last.write_bytes(b'old')
            status=Status();cycle=ApplyCycle(path,status);cycle.advance('validation');cycle.advance('interfaces-and-routes')
            status.errors.append('interface settings rejected')
            with self.assertRaises(RuntimeError):cycle.advance('system-settings')
            with self.assertRaises(RuntimeError):cycle.checkpoint(last)
            cycle.finish();self.assertEqual(cycle.steps[-1]['state'],'failed');self.assertEqual(last.read_bytes(),b'old')

    def test_changed_running_generation_never_advances_checkpoint(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'running';path.write_bytes(b'new');last=Path(temp)/'last';last.write_bytes(b'old')
            cycle=ApplyCycle(path,Status())
            for stage in STAGES[:-1]:cycle.advance(stage)
            path.write_bytes(b'concurrent commit')
            with self.assertRaises(RuntimeError):cycle.checkpoint(last)
            self.assertEqual(last.read_bytes(),b'old')

    @unittest.skipUnless(hasattr(__import__('os'),'O_DIRECTORY'),'POSIX durable checkpoint')
    def test_success_checkpoints_exact_generation(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'running';path.write_bytes(b'new');last=Path(temp)/'last'
            cycle=ApplyCycle(path,Status())
            for stage in STAGES[:-1]:cycle.advance(stage)
            cycle.checkpoint(last);cycle.finish()
            self.assertEqual(last.read_bytes(),b'new');self.assertEqual([r['state'] for r in cycle.steps],['verified']*5)

    def test_no_skipping_dependency_phase(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'running';path.write_bytes(b'new')
            cycle=ApplyCycle(path,Status());cycle.advance('validation')
            with self.assertRaises(RuntimeError):cycle.advance('security-and-nat')


ENGINE='''class ApplyStatus:
    def __init__(self):
        self.errors=[];self.validation_errors=[];self.overall='in-progress'
    def fail(self,*args):self.errors.append(args)
    def finish(self):
        self.overall='failed' if self.errors else 'applied'
    def write(self):
        self.output={
            "overall": self.overall,
        }

class ConfigEngine:
    def apply(self):
        status = ApplyStatus()
        changes = requested.copy()
        # FFN selected platform reconciliation
        platform(status)
        if status.errors:
            status.finish();status.write();return status
        if not changes:
            reconcile_nat(RUNNING_CONFIG, status)
            status.finish();status.write();return status
        # 6. Dispatch
        for xpath in sorted(changes):
            dispatch(xpath,status)
        if not status.errors and not status.validation_errors:
            reconcile_nat(RUNNING_CONFIG, status)
        try:
            import shutil
            if not status.errors and not status.validation_errors:
                shutil.copy2(RUNNING_CONFIG, LAST_APPLIED)
        except Exception as exc:
            logger.warning("Failed to update last-applied: %s", exc)
        status.finish();status.write();return status
'''


@unittest.skipUnless(sys.platform!='win32','POSIX configd locking')
class InstallerTests(unittest.TestCase):
    def test_actual_installer_orders_replay_failure_and_generation_fence(self):
        import runpy
        merge=runpy.run_path(str(ROOT/'image/install-commit-order.py'))['merge']
        installed=merge(ENGINE);self.assertEqual(merge(installed),installed)
        for scenario in ('success','unchanged','platform-failed','policy-failed','changed'):
            with self.subTest(scenario=scenario),tempfile.TemporaryDirectory() as temp:
                running=Path(temp)/'running';running.write_bytes(b'new');last=Path(temp)/'last';last.write_bytes(b'old')
                calls=[]
                def platform(status):
                    calls.append('platform')
                    if scenario=='platform-failed':status.fail('interface','sdk','rejected')
                    if scenario=='changed':running.write_bytes(b'newer')
                def policy(path,status):
                    calls.append('policy')
                    if scenario=='policy-failed':status.fail('policy','dp','not acknowledged')
                scope=dict(RUNNING_CONFIG=running,LAST_APPLIED=last,platform=platform,reconcile_nat=policy,
                           requested={} if scenario=='unchanged' else {'system':{}},
                           dispatch=lambda p,s:calls.append(p),logger=SimpleNamespace(warning=lambda *a:None))
                exec(compile(installed,'configd_fixture','exec'),scope)
                result=scope['ConfigEngine']().apply()
                good=scenario in ('success','unchanged')
                self.assertEqual(last.read_bytes(),b'new' if good else b'old')
                self.assertEqual(bool(result.errors),not good)
                if good:self.assertEqual([p['state'] for p in result.output['phases']],['verified']*5)
                else:self.assertNotEqual(result.output['phases'][-1]['state'],'verified')
                if scenario in ('platform-failed','changed'):self.assertEqual(calls,['platform'])


if __name__=='__main__':unittest.main()
