import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'opt'))
import ffn_alerts as alerts


def subsystem(ident, state, summary='', plane='dp', details=()):
    return dict(id=ident, plane=plane, state=state, summary=summary or ident, details=list(details))


def report(*subsystems, boots=None, overall=None):
    states = [s['state'] for s in subsystems]
    return dict(schema=1, overall=overall or max(states, key=lambda s: {'converged': 0, 'unavailable': 1, 'pending': 2, 'drift': 3, 'failed': 4}[s]) if states else 'converged',
                generation='abc123', processor_boots=boots or {'cp': 'cp-1', 'dp': 'dp-1'}, subsystems=list(subsystems))


class Recorder(alerts.Outputs):
    def __init__(self, config=None):
        super().__init__(config, log=lambda text: self.lines.append(text), mailer=self.mail, poster=self.webhook)
        self.lines, self.mails, self.posts = [], [], []

    def mail(self, settings, event, text):
        self.mails.append((settings['to'], event['event'], event['id']))

    def webhook(self, url, event, text):
        self.posts.append((url, event['event']))

    @staticmethod
    def syslog(event, text):
        pass


class Evaluation(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.paths = dict(state_path=root / 'state.json', events_path=root / 'events.jsonl', view_path=root / 'alerts.json',
                          config_path=root / 'missing.json')
        self.clock = 1000.0

    def run_once(self, rep, units=None, outputs=None, advance=120):
        self.clock += advance
        return alerts.evaluate(report=rep, now=self.clock, units=units or {}, outputs=outputs or Recorder(), **self.paths)

    def test_a_failure_is_raised_after_two_evaluations_and_cleared_once(self):
        out = Recorder()
        bad = report(subsystem('dhcp-server', 'failed', '3 of 3 DHCP server(s) not serving', details=['ae1.69: error (Network is down)']))
        first = self.run_once(bad, outputs=out)
        self.assertEqual(first['active'], [])
        self.assertEqual(first['pending'], ['subsystem:dhcp-server'])
        self.assertEqual(out.lines, [])
        second = self.run_once(bad, outputs=out)
        self.assertEqual([a['id'] for a in second['active']], ['subsystem:dhcp-server'])
        self.assertEqual(second['active'][0]['severity'], 'critical')
        self.assertEqual(second['active'][0]['since'], self.clock)
        self.assertEqual(len(out.lines), 1)
        self.assertIn('ALERT raised [critical] subsystem:dhcp-server (dp): 3 of 3 DHCP server(s) not serving -- ae1.69', out.lines[0])
        good = report(subsystem('dhcp-server', 'converged', 'serving'))
        third = self.run_once(good, outputs=out)
        self.assertEqual(third['active'], [])
        self.assertTrue(out.lines[-1].startswith('ALERT cleared [critical] subsystem:dhcp-server'), out.lines[-1])
        events = [json.loads(l) for l in self.paths['events_path'].read_text().splitlines()]
        self.assertEqual([(e['event'], e['id']) for e in events], [('raised', 'subsystem:dhcp-server'), ('cleared', 'subsystem:dhcp-server')])
        self.assertEqual(events[1]['duration'], 120)

    def test_a_transient_unavailable_check_never_raises(self):
        out = Recorder()
        self.run_once(report(subsystem('faceplate', 'unavailable', 'plane timeout', plane='cp')), outputs=out)
        view = self.run_once(report(subsystem('faceplate', 'converged')), outputs=out)
        self.assertEqual((view['active'], view['pending'], out.lines), ([], [], []))

    def test_severity_and_ordering(self):
        rep = report(subsystem('faceplate', 'drift', 'port 5 differs', plane='cp'), subsystem('security-runtime', 'failed', 'collector down'),
                     subsystem('aggregates', 'unavailable', 'no answer'))
        self.run_once(rep)
        view = self.run_once(rep)
        self.assertEqual([(a['id'], a['severity']) for a in view['active']],
                         [('subsystem:security-runtime', 'critical'), ('subsystem:aggregates', 'warning'), ('subsystem:faceplate', 'warning')])

    def test_a_withdrawn_tracked_route_pages_and_the_route_link_feed_is_watched(self):
        # 2026-10-20: both default routes withdrawn for fifteen minutes, and no page because no check said so.
        out = Recorder()
        bad = report(subsystem('tracked-routes', 'failed', '2 tracked route(s) withdrawn: hardware link observation stale on the dataplane',
                               details=['0.0.0.0/0 via 184.187.55.65 dev p1: withdrawn (hardware-link-observation-stale)']))
        self.run_once(bad, outputs=out)
        view = self.run_once(bad, outputs=out)
        self.assertEqual([(a['id'], a['severity'], a['plane']) for a in view['active']], [('subsystem:tracked-routes', 'critical', 'dp')])
        self.assertIn('ffn-route-link-feed.service', alerts.WATCHED_UNITS)
        down = {'ffn-route-link-feed.service': dict(restarts=0, active='failed', result='exit-code')}
        self.run_once(report(), units=down, outputs=out)
        view = self.run_once(report(), units=down, outputs=out)
        self.assertEqual([a['id'] for a in view['active']], ['unit-failed:ffn-route-link-feed.service'])

    def test_unit_failure_and_flapping_are_conditions(self):
        out = Recorder()
        quiet = {'ffn-fe100-session-feed.service': dict(restarts=10, active='active', result='success')}
        self.run_once(report(), units=quiet, outputs=out)
        looping = {'ffn-fe100-session-feed.service': dict(restarts=27, active='activating', result='exit-code'),
                   'ffn-lifecycle-reconcile.service': dict(restarts=0, active='failed', result='exit-code')}
        self.run_once(report(), units=looping, outputs=out)
        view = self.run_once(report(), units=dict(looping, **{'ffn-fe100-session-feed.service': dict(restarts=44, active='activating', result='exit-code')}), outputs=out)
        ids = sorted(a['id'] for a in view['active'])
        self.assertEqual(ids, ['unit-failed:ffn-lifecycle-reconcile.service', 'unit-flapping:ffn-fe100-session-feed.service'])
        self.assertIn('restarted 17 times since the last evaluation', next(a['summary'] for a in view['active'] if a['id'].startswith('unit-flapping')))
        calm = {'ffn-fe100-session-feed.service': dict(restarts=44, active='active', result='success'),
                'ffn-lifecycle-reconcile.service': dict(restarts=0, active='inactive', result='success')}
        view = self.run_once(report(), units=calm, outputs=out)
        self.assertEqual(view['active'], [])
        self.assertEqual(sum(1 for l in out.lines if l.startswith('ALERT cleared')), 2)

    def test_a_processor_reboot_is_a_single_event(self):
        out = Recorder()
        self.run_once(report(boots={'cp': 'cp-1', 'dp': 'dp-1'}), outputs=out)
        view = self.run_once(report(boots={'cp': 'cp-1', 'dp': 'dp-2'}), outputs=out)
        self.assertEqual([(e['event'], e['id'], e['severity']) for e in view['events']], [('event', 'processor-rebooted:dp', 'critical')])
        self.assertEqual(view['active'], [])
        again = self.run_once(report(boots={'cp': 'cp-1', 'dp': 'dp-2'}), outputs=out)
        self.assertEqual(again['events'], [])
        self.assertEqual(len(out.lines), 1)

    def test_configured_outputs_receive_transitions_and_their_failures_do_not_stop_the_evaluation(self):
        out = Recorder({'email': {'host': 'smtp.example', 'from': 'a@b', 'to': ['ops@b']}, 'webhook': 'https://hook.example/x'})
        bad = report(subsystem('security-runtime', 'failed', 'collector down'))
        self.run_once(bad, outputs=out)
        self.run_once(bad, outputs=out)
        self.assertEqual(out.mails, [(['ops@b'], 'raised', 'subsystem:security-runtime')])
        self.assertEqual(out.posts, [('https://hook.example/x', 'raised')])
        broken = Recorder({'webhook': 'https://hook.example/x'})
        def failing(url, event, text):
            raise OSError('connection refused')
        broken.poster = failing
        view = self.run_once(report(subsystem('security-runtime', 'converged')), outputs=broken)
        self.assertEqual(view['active'], [])
        self.assertEqual(broken.failures, ['webhook: connection refused'])
        self.assertTrue(any('output failed' in l for l in broken.lines))

    def test_events_log_is_bounded_and_status_reads_the_view(self):
        rows = [dict(at=i, event='raised', id='x%d' % i, severity='warning', summary='s') for i in range(600)]
        kept = alerts.append_events(self.paths['events_path'], rows, kept=500)
        self.assertEqual(len(kept), 500)
        self.assertEqual(json.loads(kept[0])['id'], 'x100')
        self.run_once(report(subsystem('dhcp-server', 'failed', 'down')))
        self.run_once(report(subsystem('dhcp-server', 'failed', 'down')))
        view = alerts.status(view_path=self.paths['view_path'], events_path=self.paths['events_path'], clock=lambda: self.clock + 30)
        self.assertEqual((view['age_seconds'], view['stale'], [a['id'] for a in view['active']]), (30, False, ['subsystem:dhcp-server']))
        self.assertEqual(view['recent'][0]['id'], 'subsystem:dhcp-server')
        stale = alerts.status(view_path=self.paths['view_path'], events_path=self.paths['events_path'], clock=lambda: self.clock + 3600)
        self.assertTrue(stale['stale'])
        self.assertTrue(alerts.status(view_path=Path(self.tmp.name) / 'absent.json')['stale'])

    def test_unit_states_parse_systemctl_blocks(self):
        def run(argv, **kwargs):
            class R:
                stdout = 'Id=a.service\nNRestarts=3\nActiveState=active\nResult=success\n\nId=b.service\nNRestarts=x\nActiveState=failed\nResult=exit-code\n'
            return R()
        self.assertEqual(alerts.unit_states(('a.service', 'b.service'), run=run),
                         {'a.service': dict(restarts=3, active='active', result='success'),
                          'b.service': dict(restarts=0, active='failed', result='exit-code')})


class Api(unittest.TestCase):
    def test_routes_serve_the_view_and_request_an_evaluation(self):
        try:
            from fastapi import FastAPI
            from fastapi.testclient import TestClient
        except ImportError:
            self.skipTest('fastapi not installed')
        tmp = tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup)
        view = Path(tmp.name) / 'alerts.json'
        alerts.atomic(view, dict(schema=1, evaluated_at=1.0, overall='failed', active=[dict(id='subsystem:x', severity='critical', summary='x')], pending=[]))
        app = FastAPI(); calls = []
        def run(argv, **kwargs):
            calls.append(argv)
            class R: returncode, stderr = 0, ''
            return R()
        async def audit(user, action, detail): calls.append(('audit', action))
        def admin(user):
            if user.get('role') != 'admin':
                from fastapi import HTTPException
                raise HTTPException(403, 'admin only')
        user = {'username': 'ops', 'role': 'admin'}
        alerts.install(app, lambda: user, admin, audit, run=run)
        from unittest.mock import patch
        with patch.object(alerts, 'VIEW', view):
            client = TestClient(app)
            got = client.get('/api/alerts').json()
            self.assertEqual([a['id'] for a in got['active']], ['subsystem:x'])
            self.assertTrue(got['stale'])
            self.assertEqual(client.post('/api/alerts/evaluate').json(), dict(status='requested', unit='ffn-alerts.service'))
            self.assertEqual(calls[0], ['systemctl', 'start', '--no-block', 'ffn-alerts.service'])
            user['role'] = 'viewer'
            self.assertEqual(client.post('/api/alerts/evaluate').status_code, 403)


if __name__ == '__main__':
    unittest.main()
