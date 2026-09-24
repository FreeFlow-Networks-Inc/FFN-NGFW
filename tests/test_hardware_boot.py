import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'opt'))
import ffn_hardware_boot as boot


class Clock:
    now = 0
    def clock(self): return self.now
    def sleep(self, seconds): self.now += seconds


class Services:
    def __init__(self):
        self.started = []
        self.states = {}
        self.failure = None
    def show(self, step):
        return {'LoadState':'loaded', 'ActiveState':self.states.get(step['id'], 'inactive')}
    def start(self, step):
        self.started.append(step['id'])
        if self.failure == step['id']:
            raise TimeoutError('uncertain start')
        self.states[step['id']] = 'active'


class BootTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.path = self.root / 'state.json'
        self.profile = {'schema':1, 'platform':'demo',
            'match':{'architectures':['x86_64'], 'products':['Demo'], 'pci_required':{'177d:9700':1}},
            'steps':[
                {'id':'boot', 'plane':'mp', 'unit':'demo-boot.service', 'timeout':5},
                {'id':'bcm', 'plane':'cp', 'unit':'demo-bcm.service', 'timeout':5, 'after':['boot']},
                {'id':'agent', 'plane':'dp', 'unit':'demo-agent.service', 'timeout':5, 'after':['bcm']}],
            'acknowledgments':{'cp':['bcm.available'], 'dp':['boot.ready']}}
        self.profile_path = self.root / 'boot.json'
        self.profile_path.write_text(json.dumps(self.profile))
        self.config = {'schema':1, 'platforms':[{'profile':str(self.profile_path.resolve())}]}
        self.inventory = {'system':{'os':'Linux','arch':'x86_64','product':'Demo'},
            'pci':{'available':True,'source':'sysfs','devices':[
                {'address':'0000:01:00.0','vendor_id':'177d','device_id':'9700','identity_complete':True}]}}
        self.control = {'agents':{role:{'role':role,'fresh':True,'connected':True,
            'age_seconds':0,'stale_after_seconds':30,
            'last_observation':{'platform':'demo','boot_id':role+'-boot',
                'report':{'ready':True,'boot_id':role+'-boot','bcm':{'available':True},'boot':{'ready':True}}}}
            for role in ('cp','dp')}}
        self.services = Services()
        self.clock = Clock()

    def run_boot(self, bid='mp-boot'):
        return boot.orchestrate(self.config,self.inventory,bid,self.path,self.services,
                                lambda:self.control,self.clock.clock,self.clock.sleep)

    def test_detection_is_on_mp_and_exact(self):
        self.assertTrue(boot.matches(self.profile, self.inventory))
        for field, value in [('arch','mips64'),('os','Windows'),('product','Other')]:
            inv = copy.deepcopy(self.inventory)
            inv['system'][field] = value
            self.assertFalse(boot.matches(self.profile, inv))
        self.inventory['pci']['source'] = 'lspci'
        self.assertFalse(boot.matches(self.profile,self.inventory))

    def test_enrollment_still_requires_matching_pci_and_fingerprint(self):
        self.inventory['system']['product'] = 'Unlabelled board'
        identity = boot.fingerprint(self.inventory)
        self.assertTrue(boot.matches(self.profile,self.inventory,identity))
        self.inventory['pci']['devices'][0]['device_id'] = 'ffff'
        self.assertFalse(boot.matches(self.profile,self.inventory,identity))

    def test_ambiguous_no_writes(self):
        self.config['platforms'] *= 2
        with self.assertRaisesRegex(ValueError,'Ambiguous'):
            self.run_boot()
        self.assertEqual(self.services.started,[])
        self.assertEqual(json.loads(self.path.read_text())['phase'],'failed')

    def test_dependency_and_no_command_injection(self):
        self.profile['steps'][0]['after'] = ['bcm']
        with self.assertRaises(ValueError): boot.validate_profile(self.profile)
        self.profile['steps'][0].pop('after')
        self.profile['steps'][0]['unit'] = 'bad; reboot.service'
        with self.assertRaises(ValueError): boot.validate_profile(self.profile)

    def test_ordered_start_and_idempotent_second_run(self):
        state = self.run_boot()
        self.assertEqual(self.services.started,['boot','bcm','agent'])
        self.assertTrue(state['hardware_ready'])
        self.assertFalse(state['forwarding_verified'])
        self.assertEqual(self.run_boot(),state)
        self.assertEqual(self.services.started,['boot','bcm','agent'])

    def test_active_owners_never_restarted(self):
        self.services.states = dict(boot='active',bcm='active',agent='active')
        self.assertEqual(self.run_boot()['phase'],'ready')
        self.assertEqual(self.services.started,[])

    def test_uncertain_start_is_never_replayed(self):
        self.services.failure = 'bcm'
        with self.assertRaises(TimeoutError): self.run_boot()
        self.assertEqual(json.loads(self.path.read_text())['steps']['bcm']['state'],'start-submitted')
        with self.assertRaisesRegex(RuntimeError,'already attempted'): self.run_boot()
        self.assertEqual(self.services.started,['boot','bcm'])

    def test_new_mp_boot_allows_new_start(self):
        self.services.failure = 'bcm'
        with self.assertRaises(TimeoutError): self.run_boot()
        self.services.failure = None
        self.assertEqual(self.run_boot('new-mp-boot')['phase'],'ready')

    def test_stale_and_missing_hardware_ack_do_not_pass(self):
        for field, value in [('fresh',False),('connected',False),('age_seconds',90),('age_seconds',float('nan'))]:
            control = copy.deepcopy(self.control)
            control['agents']['cp'][field] = value
            self.assertTrue(boot.acknowledgments(self.profile,control)[1])
        self.control['agents']['cp']['last_observation']['report']['bcm']['available'] = False
        self.clock.sleep = lambda seconds: setattr(self.clock, 'now', self.clock.now + 61)
        with self.assertRaisesRegex(RuntimeError,'did not acknowledge'): self.run_boot()
        self.assertFalse(json.loads(self.path.read_text())['hardware_ready'])

    def test_restarted_dp_invalidates_ready_without_reset(self):
        self.run_boot()
        sample = self.control['agents']['dp']['last_observation']
        sample['boot_id'] = sample['report']['boot_id'] = 'new-dp-boot'
        self.assertEqual(self.run_boot()['phase'],'degraded')
        self.assertEqual(self.services.started,['boot','bcm','agent'])
        mp = self.root / 'mp-id'
        mp.write_text('mp-boot')
        self.assertFalse(boot.status(self.control,self.path,mp)['hardware_ready'])
        mp.write_text('next-boot')
        self.assertEqual(boot.status(self.control,self.path,mp)['phase'],'stale')

    def test_generic_and_unknown_specialized_never_start_owners(self):
        self.inventory['pci']['devices'] = []
        self.assertEqual(self.run_boot()['phase'],'generic')
        self.inventory['accelerators'] = [{'kind':'unknown'}]
        self.assertEqual(self.run_boot()['phase'],'unsupported')
        self.assertEqual(self.services.started,[])

    def test_completed_oneshot_is_not_an_inactive_daemon(self):
        observed = dict(ActiveState='inactive',Type='oneshot',Result='success',ExecMainStatus='0',
                        ExecMainExitTimestampMonotonic='123')
        self.assertTrue(boot.service_ready(observed))
        observed['ExecMainExitTimestampMonotonic'] = '0'
        self.assertFalse(boot.service_ready(observed))

    def test_profile_change_cannot_replay_boot(self):
        self.run_boot()
        self.profile['steps'][0]['unit'] = 'different.service'
        self.profile_path.write_text(json.dumps(self.profile))
        with self.assertRaisesRegex(RuntimeError,'already attempted'): self.run_boot()

    def test_identity_loss_preserves_start_fence(self):
        self.services.failure = 'bcm'
        with self.assertRaises(TimeoutError): self.run_boot()
        self.inventory['system']['product'] = 'Other'
        self.run_boot()
        self.inventory['system']['product'] = 'Demo'
        with self.assertRaisesRegex(RuntimeError,'already attempted'): self.run_boot()


if __name__ == '__main__':
    unittest.main()
