# Unauthenticated routes in the manager API

Found 2026-09-06 while fixing the WebUI controls. **Three action endpoints are
fixed; ~46 read endpoints are not.** This file is the working list.

## The exposure, measured

The manager binds `0.0.0.0:8443` and there is **no** iptables or nftables rule
for that port:

```
LISTEN 0 2048 0.0.0.0:8443 0.0.0.0:* users:(("uvicorn",...))
iptables -S | grep -c 8443   ->  0
nft list ruleset | grep -c 8443 -> 0
```

A **different host on the network** then fetched the live firewall rulebase with
no credentials:

```
RE-VM -> MP:8443 /api/policy/rules : 200
{"rules":[{"id":9,"name":"allow-lab-mgmt-eno1np0","src_ip":"0.0.0.0/0", ...
```

## It is an omission, not a policy

`Depends(get_current_user)` guards **126 of 189** routes. Auth is the
established pattern; these routes simply do not use it. Of 51 unguarded routes,
two are legitimately public — `GET /` and `POST /api/auth/login`.

## Fixed

| route | before | after |
|---|---|---|
| `POST /api/system/updates/install` | 200 | **401** |
| `POST /api/system/updates/check` | 200 | **401** |
| `POST /api/ml/score` | 200 | **401** |

`updates/install` was the worst of the set: it downloads and verifies a payload,
and its request model carries an `insecure` flag that appends `--insecure`, so
an anonymous caller could request an install with signature checking relaxed.
Writing to the inactive A/B root limits the damage; it does not excuse it.

These three were also the *safest* to change: each is called only from
`static/index.html` via its `api()` helper, which already sends
`Authorization: Bearer`. No internal or machine caller exists.

## Not fixed — needs a decision, not a bulk edit

Adding a guard to these blind risks locking an operator out of their own
firewall: several are plausibly fetched by the UI **before** login (a dashboard
that paints before authentication, a login page showing system identity). Each
needs checking against the UI's pre-login path.

Ordered by what they disclose.

**Policy and traffic**
```
GET /api/policy/rules                      the live rulebase
GET /api/logs/security  /api/logs/traffic  /api/logs/system
GET /api/monitor/sessions
GET /api/dashboard/sessions  /threats  /throughput  /ddos
```

**Network topology**
```
GET /api/network/arp
GET /api/network/virtual-routers
GET /api/network/virtual-routers/{name}/routes  /fib  /neighbors
GET /api/system/interfaces
```

**Host and platform inventory**
```
GET /api/system/status      hostname, uptime, CPU model, memory
GET /api/system/hardware  /resources  /fpga  /cpu-planes  /copp
GET /api/system/updates
GET /api/octeon/bringup
GET /api/dataplane/status  /api/dataplane/offload
GET /api/mpdp/status  /api/mpdp/telemetry
```

**Licensing identity**
```
GET /api/license/dna  /api/license/dna.txt  /api/license/audit  /api/license/status
```

**Engines, ML, plugins**
```
GET /api/engines  /api/engines/emulator  /api/engines/{name}/stats
GET /api/ml/status
GET /api/sigdb/status
GET /api/crucible/status
GET /api/plugins
```

## Two cheap mitigations, independent of the code

Either one shrinks the exposure without touching a route:

1. **Bind to the management interface** rather than `0.0.0.0`. The unit already
   sets `FFN_MGMT_IFACE=eno1np0`; uvicorn's `--host` does not follow it.
2. **Filter 8443** to the management network. There is currently no rule at all.

## A related trap worth knowing

The UI's `api()` helper does:

```js
if (r.status === 404) return null;
```

so a missing endpoint renders as an **empty panel**, not an error. That is why
`/api/crucible/status` being absent from the deployed manager went unnoticed —
the Crucible panel simply looked idle. Any control that looks blank rather than
broken should be checked against `/openapi.json`.
