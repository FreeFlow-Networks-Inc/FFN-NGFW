# QoS interface configuration

Network > QoS & Bandwidth now stages interface-to-profile attachments through
the same `ffn-controld` policy controller used by the authenticated API and CLI.
The previous page targeted a retired SQL resource endpoint and displayed fixed
sample class names and bandwidths. It now shows the configured eight-class
profile, calculated budgets, and explicit activation status.

Each attachment selects a configured physical or aggregate Layer 2/3 data
interface, QoS profile, positive egress maximum in Mbps, default class 1–8, and
requested enabled state. Management interfaces, aggregate members, and
unconfigured interfaces are excluded. Default class 4 is configurable. New
attachments are disabled.

The effective maximum is the smaller of the interface limit and the profile
maximum; a zero profile maximum inherits the interface limit. A zero class
maximum inherits the effective maximum. Profile guarantees, each class limit,
and the sum of class guarantees must fit that budget. Class guarantees use
decimal arithmetic. No hardware link capacity or enforcement is inferred from
these configured values.

OK saves only the candidate. Cancel saves nothing. Running views are read only.
Stale revisions, foreign locks, missing profiles, duplicate attachments and
unsupported imported fields prevent a write. Referenced profiles cannot be
deleted, and a profile edit cannot invalidate an attachment's budget. The plan
view reports invalid imported or dangling references instead of inventing data.

The MP controller stores attachments under
`devices/entry/network/qos/interface/entry[@name=<logical-interface>]`, with
`profile`, `enabled`, `max-mbps` and `default-class` fields. Core configuration
owns this schema; platform modules will resolve logical interfaces to queues.

```
show policies qos-interfaces
show policies qos-interfaces running
request policies qos-interface add ethernet1/1 profile=wan max-mbps=100 default-class=4 enabled=no
request policies qos-interface edit ethernet1/1 max-mbps=200
request policies qos-interface remove ethernet1/1
```

The shared endpoint is `GET/POST /api/config/qos/interfaces`. Mutations require
an administrative role and the candidate revision returned by GET.

This completes the configuration linkage, **not scheduler enforcement**.
Enabled attachments are rejected by the common Commit/configd policy guard
until a scheduler provider exists. Queue counters and applied-state claims are
not synthesized. Classification rules and profiles remain subject to their
existing provider checks. A future provider must validate actual link capacity,
resolve the PA-5220/CPU queue mapping, program all eight classes, and return a
generation-specific acknowledgment before activation can be enabled.
