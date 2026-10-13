#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Alerts: what the convergence check and unit health find, turned into raised
and cleared events that reach someone.

The Boot & Convergence page reported "3 of 3 DHCP servers not serving" for
three days in October 2026 and nobody saw it, because a page has to be
opened. This module runs from ffn-alerts.timer every two minutes on the MP,
compares the current assessment with the last one, and on every transition
writes a journal line (syslog identifier ffn-alert), appends an event to a
bounded log, publishes the active alerts for the console's dashboard and
header badge, and, when /etc/ffn-ngfw/alerts.json configures them, sends an
email and posts a webhook.

A condition is raised only after it has been seen in two consecutive
evaluations, so a single slow plane request does not page anyone, and it is
cleared the first time it is absent. Processor reboots are one-off events,
not standing conditions: a changed CP or DP boot identity is reported once.

Conditions, in order of severity:
  subsystem:<id>      a convergence subsystem failed (critical), drifted or
                      could not be checked (warning)
  unit-failed:<unit>  a watched MP unit is in the failed state (critical)
  unit-flapping:<u>   a watched unit restarted three or more times between
                      two evaluations (warning)
"""
import json
import os
import subprocess
import sys
import time
from pathlib import Path

STATE_DIR = Path('/var/lib/ffn-ngfw/alerts')
STATE = STATE_DIR / 'state.json'
EVENTS = STATE_DIR / 'events.jsonl'
VIEW = Path('/run/ffn-ngfw/alerts.json')
CONFIG = Path('/etc/ffn-ngfw/alerts.json')
UNIT = 'ffn-alerts.service'
SEVERITY = {'failed': 'critical', 'drift': 'warning', 'unavailable': 'warning'}
CONFIRMATIONS = 2
EVENTS_KEPT = 500
RECENT_SHOWN = 30
RESTART_FLAP = 3
WATCHED_UNITS = ('ffn-fe100-session-feed.service', 'ffn-aggregate@ae1.service', 'ffn-controld.service',
                 'ffn-managementd.service', 'ffn-manager-v2.service', 'ffn-plane@mp.service',
                 'ffn-lifecycle-reconcile.service', 'ffn-interface-service-tunnel.service')
RANK = {'critical': 2, 'warning': 1, 'info': 0}


def read_json(path, default):
    try:
        value = json.loads(Path(path).read_text(encoding='utf-8'))
    except (OSError, ValueError):
        return default
    return value if isinstance(value, dict) else default


def atomic(path, value):
    path = Path(path)
    path.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + '.tmp')
    temp.write_text(json.dumps(value, sort_keys=True) + '\n', encoding='utf-8')
    os.chmod(temp, 0o640)
    temp.replace(path)


def unit_states(units=WATCHED_UNITS, run=subprocess.run):
    """NRestarts, ActiveState and Result per watched unit; a unit systemd cannot describe is left out."""
    try:
        raw = run(['systemctl', 'show', *units, '--property=Id,NRestarts,ActiveState,Result'],
                  capture_output=True, text=True, timeout=20).stdout
    except (OSError, subprocess.SubprocessError):
        return {}
    result = {}
    for block in raw.strip().split('\n\n'):
        fields = dict(line.split('=', 1) for line in block.splitlines() if '=' in line)
        unit = fields.get('Id')
        if not unit:
            continue
        try:
            restarts = int(fields.get('NRestarts', '0'))
        except ValueError:
            restarts = 0
        result[unit] = dict(restarts=restarts, active=fields.get('ActiveState', 'unknown'), result=fields.get('Result', ''))
    return result


def conditions(report, units, previous_units):
    """Everything that is wrong right now, keyed so the same trouble keeps the same identity."""
    found = {}
    for s in (report or {}).get('subsystems') or []:
        severity = SEVERITY.get(s.get('state'))
        if severity:
            found['subsystem:' + s['id']] = dict(severity=severity, plane=s.get('plane'), source='convergence',
                                               summary=s.get('summary') or s['id'], details=list(s.get('details') or [])[:8],
                                               state=s.get('state'))
    for unit, now in (units or {}).items():
        before = (previous_units or {}).get(unit) or {}
        if now.get('active') == 'failed':
            found['unit-failed:' + unit] = dict(severity='critical', plane='mp', source='systemd', state='failed',
                                                summary='%s is failed (%s)' % (unit, now.get('result') or 'exit'), details=[])
        delta = now.get('restarts', 0) - before.get('restarts', now.get('restarts', 0))
        if delta >= RESTART_FLAP:
            found['unit-flapping:' + unit] = dict(severity='warning', plane='mp', source='systemd', state='flapping',
                                                  summary='%s restarted %d times since the last evaluation' % (unit, delta), details=[])
    return found


def processor_events(report, previous):
    """A CP or DP boot identity that changed since the last evaluation is one event, reported once."""
    boots = (report or {}).get('processor_boots') or {}
    events = []
    if isinstance(previous, dict):
        for role in sorted(set(boots) | set(previous)):
            if previous.get(role) and boots.get(role) and previous[role] != boots[role]:
                events.append(dict(kind='processor-rebooted', severity='critical', plane=role, source='lifecycle',
                                   summary='%s processor booted again (boot %s)' % (role.upper(), str(boots[role])[:8]), details=[]))
    return events, boots


def line(event):
    label = {'raised': 'ALERT raised', 'cleared': 'ALERT cleared', 'event': 'ALERT event'}[event['event']]
    text = '%s [%s] %s (%s): %s' % (label, event['severity'], event['id'], event.get('plane') or '-', event['summary'])
    if event.get('details'):
        text += ' -- ' + '; '.join(str(d) for d in event['details'][:3])
    return text


class Outputs:
    """Where an event goes: the journal always, email and a webhook when configured."""

    def __init__(self, config=None, log=None, mailer=None, poster=None):
        self.config = config or {}
        self.log = log or (lambda text: print(text, flush=True))
        self.mailer, self.poster = mailer or self.send_mail, poster or self.post
        self.failures = []

    def emit(self, event):
        text = line(event)
        self.log(text)
        self.syslog(event, text)
        for name, target in (('email', self.mailer), ('webhook', self.poster)):
            if self.config.get(name):
                try:
                    target(self.config[name], event, text)
                except Exception as error:   # an output that fails must not stop the others or the evaluation
                    self.failures.append('%s: %s' % (name, str(error)[:120]))
                    self.log('alert %s output failed: %s' % (name, str(error)[:120]))

    @staticmethod
    def syslog(event, text):
        try:
            import syslog
        except ImportError:
            return
        priority = {'critical': syslog.LOG_CRIT, 'warning': syslog.LOG_WARNING}.get(event['severity'], syslog.LOG_NOTICE)
        if event['event'] == 'cleared':
            priority = syslog.LOG_NOTICE
        syslog.openlog('ffn-alert', 0, syslog.LOG_DAEMON)
        syslog.syslog(priority, text)

    @staticmethod
    def send_mail(settings, event, text):
        import smtplib
        from email.message import EmailMessage
        message = EmailMessage()
        message['Subject'] = '[FFN NGFW] ' + text[:120]
        message['From'] = settings['from']
        message['To'] = ', '.join(settings['to'])
        message.set_content(text + '\n\n' + json.dumps(event, indent=2, sort_keys=True) + '\n')
        with smtplib.SMTP(settings['host'], int(settings.get('port', 587)), timeout=20) as smtp:
            if settings.get('starttls', True):
                smtp.starttls()
            if settings.get('username'):
                password = Path(settings['password_file']).read_text(encoding='utf-8').strip()
                smtp.login(settings['username'], password)
            smtp.send_message(message)

    @staticmethod
    def post(url, event, text):
        import urllib.request
        body = json.dumps(dict(event, text=text)).encode()
        request = urllib.request.Request(url, data=body, headers={'Content-Type': 'application/json'}, method='POST')
        with urllib.request.urlopen(request, timeout=20) as response:
            response.read(1)


def append_events(path, events, kept=EVENTS_KEPT):
    path = Path(path)
    path.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
    try:
        existing = [l for l in path.read_text(encoding='utf-8').splitlines() if l.strip()]
    except OSError:
        existing = []
    lines = (existing + [json.dumps(e, sort_keys=True) for e in events])[-kept:]
    temp = path.with_suffix('.tmp')
    temp.write_text('\n'.join(lines) + ('\n' if lines else ''), encoding='utf-8')
    os.chmod(temp, 0o640)
    temp.replace(path)
    return lines


def recent_events(path=EVENTS, count=RECENT_SHOWN):
    try:
        rows = [l for l in Path(path).read_text(encoding='utf-8').splitlines() if l.strip()]
    except OSError:
        return []
    out = []
    for row in rows[-count:]:
        try:
            out.append(json.loads(row))
        except ValueError:
            continue
    return list(reversed(out))


def live_convergence_report(no_planes=False):
    """The convergence module lives beside this file in a repository checkout and under
    /usr/local/lib/ffn on an appliance; the controld client it needs sits in /opt/ffn-ngfw."""
    for extra in (Path(__file__).resolve().parent, Path('/usr/local/lib/ffn'), Path('/opt/ffn-ngfw')):
        if str(extra) not in sys.path:
            sys.path.append(str(extra))
    from ffn_convergence import live_report
    return live_report(no_planes=no_planes)


def evaluate(report=None, now=None, state_path=STATE, events_path=EVENTS, view_path=VIEW, config_path=CONFIG,
             units=None, outputs=None):
    """One evaluation: compare with the last state, emit transitions, publish the view."""
    now = time.time() if now is None else now
    if report is None:
        report = live_convergence_report()
    if units is None:
        units = unit_states()
    outputs = outputs or Outputs(read_json(config_path, {}))
    state = read_json(state_path, {})
    if state.get('schema') != 1:
        state = dict(schema=1, conditions={}, units={}, processor_boots=None, evaluations=0)
    seen = conditions(report, units, state.get('units') or {})
    events = []
    held = state.get('conditions') or {}
    for ident, cond in seen.items():
        entry = held.get(ident)
        if entry is None:
            entry = dict(cond, first=now, count=0, raised=False)
            held[ident] = entry
        else:
            entry.update(cond)
        entry['count'] = entry.get('count', 0) + 1
        entry['last'] = now
        if not entry['raised'] and entry['count'] >= CONFIRMATIONS:
            entry['raised'], entry['since'] = True, now
            events.append(dict(at=now, event='raised', id=ident, severity=entry['severity'], plane=entry.get('plane'),
                               summary=entry['summary'], details=entry.get('details') or [], source=entry.get('source')))
    for ident in list(held):
        if ident not in seen:
            entry = held.pop(ident)
            if entry.get('raised'):
                events.append(dict(at=now, event='cleared', id=ident, severity=entry['severity'], plane=entry.get('plane'),
                                   summary=entry['summary'], details=[], source=entry.get('source'),
                                   duration=round(now - entry.get('since', now))))
    one_offs, boots = processor_events(report, state.get('processor_boots'))
    for item in one_offs:
        events.append(dict(at=now, event='event', id=item['kind'] + ':' + str(item.get('plane')), **{k: v for k, v in item.items() if k != 'kind'}))
    for event in events:
        outputs.emit(event)
    if events:
        append_events(events_path, events)
    state.update(conditions=held, units=units, processor_boots=boots or state.get('processor_boots'),
                 evaluated_at=now, evaluations=state.get('evaluations', 0) + 1,
                 overall=(report or {}).get('overall'), output_failures=outputs.failures)
    atomic(state_path, state)
    active = sorted((dict(entry, id=ident) for ident, entry in held.items() if entry.get('raised')),
                    key=lambda e: (-RANK.get(e['severity'], 0), e.get('since', 0), e['id']))
    view = dict(schema=1, evaluated_at=now, overall=(report or {}).get('overall'), generation=(report or {}).get('generation'),
                active=[{k: e.get(k) for k in ('id', 'severity', 'plane', 'source', 'state', 'summary', 'details', 'since', 'first')} for e in active],
                pending=sorted(ident for ident, entry in held.items() if not entry.get('raised')),
                events=[dict(e) for e in events], output_failures=outputs.failures)
    atomic(view_path, view)
    return view


def status(view_path=None, events_path=None, clock=time.time):
    view_path = VIEW if view_path is None else view_path
    events_path = EVENTS if events_path is None else events_path
    view = read_json(view_path, {})
    age = None if not view.get('evaluated_at') else max(0, clock() - view['evaluated_at'])
    return dict(schema=1, evaluated_at=view.get('evaluated_at'), age_seconds=age, stale=age is None or age > 600,
                overall=view.get('overall'), generation=view.get('generation'), active=view.get('active') or [],
                pending=view.get('pending') or [], recent=recent_events(events_path), output_failures=view.get('output_failures') or [])


def install(app, current_user, require_admin, audit, run=subprocess.run):
    """The console's view: active alerts for the dashboard and header, a trigger for an evaluation now."""
    from fastapi import Depends, HTTPException

    @app.get('/api/alerts')
    async def alerts_view(user: dict = Depends(current_user)):
        return status()

    @app.post('/api/alerts/evaluate')
    async def alerts_evaluate(user: dict = Depends(current_user)):
        require_admin(user)
        try:
            result = run(['systemctl', 'start', '--no-block', UNIT], capture_output=True, text=True, timeout=10)
        except (OSError, subprocess.SubprocessError) as error:
            raise HTTPException(503, 'Alert evaluation could not be started: %s' % str(error)[:120])
        if result.returncode:
            raise HTTPException(503, 'Alert evaluation could not be started: %s' % (result.stderr or '').strip()[:120])
        await audit(user, 'alerts.evaluate', 'requested')
        return dict(status='requested', unit=UNIT)


def main(argv=None):
    import argparse
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('action', choices=('evaluate', 'status'))
    parser.add_argument('--no-planes', action='store_true', help='evaluate from the local files only (no plane requests)')
    args = parser.parse_args(argv)
    if args.action == 'status':
        print(json.dumps(status(), indent=2, sort_keys=True))
        return 0
    view = evaluate(report=live_convergence_report(no_planes=args.no_planes))
    print('alerts: %d active, %d raised or cleared this evaluation, overall %s' % (
        len(view['active']), len(view['events']), view.get('overall')), flush=True)
    return 0


if __name__ == '__main__':
    sys.exit(main())
