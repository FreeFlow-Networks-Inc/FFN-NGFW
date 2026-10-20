# Alerts

The Boot & Convergence page told the truth for three days in October 2026
("3 of 3 DHCP servers not serving: Network is down") and nobody saw it,
because a page has to be opened. `opt/ffn_alerts.py` turns what that check
and the watched management units find into raised and cleared events that
reach someone without a page being open.

## What runs

`ffn-alerts.timer` runs `ffn-alerts.service` every two minutes on the MP.
Each evaluation takes the live convergence report (the same collection the
`ffn-convergence` command and the console page use), the `NRestarts`,
`ActiveState` and `Result` of the watched units, and compares them with the
previous evaluation in `/var/lib/ffn-ngfw/alerts/state.json`.

| Condition | Severity | Raised when |
| --- | --- | --- |
| `subsystem:<id>` | critical / warning | a convergence subsystem is `failed` (critical), `drift` or `unavailable` (warning) |
| `unit-failed:<unit>` | critical | a watched unit is in systemd's failed state |
| `unit-flapping:<unit>` | warning | a watched unit restarted three or more times between two evaluations |
| `processor-rebooted:<cp\|dp>` | critical, one event | a processor's boot identity changed since the last evaluation |

A condition is raised only after it has been seen in two consecutive
evaluations (about four minutes), so a single slow plane request never
pages anyone; it is cleared the first time it is absent, with the duration
it stood. A processor reboot is reported once and never stands.

`subsystem:tracked-routes` is the one that would have paged on 2026-10-20,
when both default routes were withdrawn for fifteen minutes because the MP's
route-link feed had been stopped with the control daemon by a patch install:
the selected platform reports each link-tracked route's installed/reason from
the dataplane, `failed` when a route is withdrawn for a stale link observation,
and `ffn-route-link-feed.service` is a watched unit. The convergence page's
reapply restarts that feed before it replays the configuration.

## Where an event goes

* The journal, always: syslog identifier `ffn-alert`, priority `crit` or
  `warning` for a raise and `notice` for a clear. `journalctl -t ffn-alert`
  is the history on the box; a remote syslog target receives it with the
  rest of the journal.
* `/var/lib/ffn-ngfw/alerts/events.jsonl`, the last 500 events.
* `/run/ffn-ngfw/alerts.json`, the active alerts, read by `GET /api/alerts`
  for the dashboard card and the header badge. The badge polls once a
  minute and shows the count; the card lists each alert with its severity,
  plane, summary, details and age, and says when the evaluation itself is
  stale (older than ten minutes), which is an alert about the alerting.
* Email and a webhook when `/etc/ffn-ngfw/alerts.json` configures them:

```json
{
  "email": {"host": "smtp.example.net", "port": 587, "starttls": true,
            "from": "ngfw@example.net", "to": ["ops@example.net"],
            "username": "ngfw", "password_file": "/etc/ffn-ngfw/alerts-smtp.secret"},
  "webhook": "https://hooks.example.net/ffn"
}
```

The password lives only in the named file (mode 0600); the configuration
file holds no secret. An output that fails is logged and does not stop the
others or the evaluation.

## By hand

```
ffn_alerts.py status            # the current view and the recent events
systemctl start ffn-alerts      # evaluate now (also POST /api/alerts/evaluate)
journalctl -t ffn-alert -n 50   # the transitions on this box
```
