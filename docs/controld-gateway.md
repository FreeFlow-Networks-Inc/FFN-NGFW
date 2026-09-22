# Controld control gateway

`ffn-controld` is the MP entry point for selected platform operations. There is
no second `ffn-masterd` service. The request path is:

Console deployments now use [local daemon RPC and FFN database-backed SSH
authentication](CONSOLE-DAEMON.md). The CLI reuses its SSH session identity;
the web listener and CLI share one management backend and commit owner.

```text
WebUI / authenticated FFN-CLI -> controld -> journaled MP plane worker
configd platform applier     -> controld -> journaled MP plane worker
                                              -> CP / DP / BCM / FE100 owners
CP / DP agents              -> persistent observation channels -> controld
```

Configuration storage and candidate commits remain owned by the configuration
manager and configd. Controld dispatches runtime application through the existing
plane worker. Original request IDs, revision checks, resource locks, durable
intent, unknown outcomes and recovery lookups survive the gateway. A lost reply
never causes an automatic retry. The worker's socket is internal; API clients
cannot supply its path or an executable.

Set `FFN_CONTROL_GATEWAY=controld` on the WebUI manager and provide its
`FFN_PLANE_SOCKET` selection. Once enabled, loss of controld fails the request;
the frontend cannot silently fall back to the worker. The legacy transport is
retained for installations that have not selected the gateway.

The root-owned `/etc/ffn/controld.json` selects an absolute `worker_socket` and
up to four agents. Each agent specifies a fixed `argv`, `role` (`cp` or `dp`),
`platform`, and integer `interval`, `timeout`, `stale_after` values in seconds.
Expiry must exceed the interval plus observation timeout. For a CPU-only local
worker, `agents` can be empty; the core has no PA5200 addresses or hardware probes.
The PA5200 module provides its own SSH channel installer and observation code.

Each authenticated channel exchanges a new UUID challenge for each observation.
Reports carry a channel instance, boot UUID, increasing sequence and bounded JSON.
The receiver rejects replay, identity changes, truncated data and oversized frames.
Freshness uses MP monotonic time, independent of CP/DP wall-clock differences.
Disconnect or expiry makes `ready` false. Historical data is labelled
`last_observation`; it never authorizes a hardware write. Reconnect has bounded
backoff and affects the observation channel only.

API and CLI access:

- `GET /api/system/control`: owner, CP/DP freshness and last reports.
- `GET /api/system/control/events`: bounded connection and request outcomes;
  configuration payloads are excluded.
- `POST /api/system/planes`: the existing revisioned plane request envelope.
- Local clients: `ControldClient.control_status()`, `control_events()` and
  `plane_request(request)`; mutations preserve the supplied request UUID.
- Selected PA5200 CLI: `show platform control`, `show platform agents`,
  `show platform fe100`, `show platform control-events`.

The HTTP endpoints require administrator access. The local Unix socket uses the
existing `ffn-mgmt` authorization boundary. SSH private keys are supplied to
controld through a systemd credential, with home-directory protection retained.

`image/install-control-gateway.sh` installs the versioned core sources and adds
the API mount to compatible older managers, backing up existing files under
`/var/backups/ffn`. The image builder also overlays these tracked
sources, so images do not inherit an arbitrary harvested controld version.
Platform channel activation is a separate step. No hardware is commissioned or
rebooted by installing the gateway.

Validation includes a real Unix-socket gateway/worker exchange, durable replay
without a second apply, persistent subprocess reports, wrong identity and replay
rejection, stale readiness, API authorization, unknown outcomes and no fallback.
Run `python3 tests/test_control_gateway.py` on Linux for all transport tests.
