# Unauthenticated routes in the manager API

Found 2026-09-06 while fixing the WebUI controls. The HTTP routes were closed the
same day. A follow-up review on 2026-09-10 found that the earlier count omitted
the live-log WebSocket; that endpoint now authenticates before starting a log
reader or sending any logs.

`/api/logs/live` accepts a WebSocket connection, then requires a first JSON frame
of `{"token":"<access_token>"}` within five seconds. Invalid, expired, deleted-user
and password-change-only sessions close with code 1008. The browser sends the
token in a frame so credentials do not enter URL/access logs. Both live-log
controls in the console use this protocol. Disconnecting also stops and reaps
the journal reader even when no new logs are arriving.

HTTP requests and new log streams resolve the current account role and forced
password-change flag from the user database, rather than trusting stale role
claims for the token's full lifetime. These checks happen at WebSocket
authentication; an already-open stream is not periodically reauthenticated.

The original HTTP-only counts were:

    before   189 routes, 129 guarded, 60 open
    after    190 routes, 188 guarded,  2 open

The two that stay open, and why they must:

| route | why |
|---|---|
| `GET /` | serves the WebUI. Guard it and there is no way to reach the login page to authenticate in the first place. |
| `POST /api/auth/login` | is how a token is obtained. |

## The exposure, as measured before the fix

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

It was an omission rather than a policy: `Depends(get_current_user)` already
guarded 129 of 189 routes. Auth was the established pattern; these routes simply
did not use it.

## What was actually open

An earlier version of this file said "three action endpoints, ~46 reads". Both
halves were wrong, and the corrections are the interesting part.

**Four more state-changing endpoints were open** than the three already fixed
(`POST /api/system/updates/install`, `/check`, `/api/ml/score`):

```
PUT  /api/system/updates/server      repoints the update server
POST /api/vendor/scan
POST /api/vendor/import
POST /api/vendor/forget
```

`updates/server` is the one worth staring at. An anonymous caller could aim the
appliance's update source at a host of their choosing — and `updates/install`
carried an `insecure` flag that relaxes signature checking. Signing
([[ffn-update-trust-model]]) is what stops that becoming code execution, which
is precisely why the trust model is not optional.

**And `/openapi.json` was open, which no audit of the source would have found.**
FastAPI registers it internally, not through an `@app.get` decorator, so it does
not appear in any scan that walks the decorators — including the one used here.
Measured against the running manager:

```
GET /openapi.json  ->  200, 136256 bytes, 157 paths disclosed
GET /docs          ->  200
```

That is a complete map of the API — every path, parameter and request model.
Guarding 58 handlers while publishing their full description would have been
theatre.

## How it was done

`Depends(get_current_user)` appended to each handler's signature — the same
idiom the other 129 routes already used, so nothing new was introduced.

The edit was driven from an **AST parse**, not a regex: whether a handler is
guarded is a property of its signature, and these signatures span multiple lines
and carry defaults with their own parentheses (`limit: int = Query(100,
le=1000)`). A line-oriented match gets that wrong in both directions.

Appending is always safe here because the new parameter has a default, so it
can never precede a non-default one; where a handler has a keyword-only marker
it simply becomes another keyword-only with a default.

Two checks before trusting it:

* **no name collisions** — any handler already taking something called `user`
  would have been reported and skipped rather than silently shadowed. None were.
* **no internal callers** — a handler invoked directly from elsewhere in the
  module would now receive a `Depends` object instead of a dict. Searched every
  guarded handler name for call sites that are not its own `def`: **zero**.
  Every one is reached only through the router.

`/openapi.json` was handled separately: `docs_url`, `redoc_url` and
`openapi_url` are now all `None` so FastAPI registers none of its built-ins, and
`/openapi.json` is re-registered behind the same guard. `/docs` and `/redoc` are
not restored — they are browser UIs whose only job is to fetch and render the
spec, and a browser opening them cannot send an `Authorization` header, so
behind bearer auth they could only ever render an empty shell.

## Why this was safe to do in bulk, having previously not been

The earlier note said this needed "a decision, not a bulk edit", because
guarding blind risked locking an operator out of their own firewall. That
concern turned out to be unfounded, and the evidence is what changed:

* **the WebUI makes no API call before login.** `static/index.html:8885` gates
  the entire application on `if (token)`, and its `api()` helper always sends
  the bearer when one is set.
* **`ffn_updated.py:291` already tolerates it**: `api = r.status in (200, 401,
  403)   # answering at all is the point`.
* **`ffn-selftest.sh` was the only caller that demanded exactly 200.** It polls
  `/api/system/status` for 120 s at boot, so guarding that route would have made
  a healthy appliance fail its own selftest after sixty retries — which reads as
  a boot problem, not an auth change. Fixed first, in image-build `763b7bf`.

## Still open, and not addressed here

**CORS is configured wide.** `ffn_manager.py` sets `allow_origins=["*"]` with
`allow_credentials=True`. Guarding the routes shrinks what that can reach — a
cross-origin read now gets 401 rather than data — and this deployment keeps its
token in `localStorage` rather than a cookie, so a browser will not attach
credentials automatically. I did not verify Starlette's exact behaviour for
wildcard-plus-credentials (it is not installed outside the manager's venv), so
treat this as a configuration worth reviewing rather than a characterised hole.

**Two cheap mitigations remain worthwhile**, independent of the code, because
authentication is not the same as reachability:

1. **Bind to the management interface** rather than `0.0.0.0`. The unit already
   sets `FFN_MGMT_IFACE=eno1np0`; uvicorn's `--host` does not follow it.
2. **Filter 8443** to the management network. There is still no rule at all.

**This is the repo, not the appliance.** `/opt/ffn-ngfw-v2/` on the MP still
runs the older manager and is unaffected until it is deployed.

## A related trap worth knowing

The UI's `api()` helper does:

```js
if (r.status === 404) return null;
```

so a missing endpoint renders as an **empty panel**, not an error. That is why
`/api/crucible/status` being absent from the deployed manager went unnoticed —
the Crucible panel simply looked idle. Any control that looks blank rather than
broken should be checked against `/openapi.json`, which now needs a token.
