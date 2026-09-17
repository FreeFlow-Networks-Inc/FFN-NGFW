# Policy configuration from WebUI and FFN-CLI

NAT, QoS, PBF and Decryption use the same controld-owned candidate XML. Saving
with **OK** stages a change; **Cancel** leaves configuration unchanged. The
running view is read only. Commit retains its normal compiler/provider checks.

## WebUI

* NAT selects either a translated address or an interface address for dynamic
  IP-and-port translation. Inapplicable source fields are hidden and removed from
  the submitted rule. Destination translation supports address and port values.
* PBF displays egress and next-hop fields only for Forward. Changing to Discard
  or No PBF clears those forwarding fields when the edit is confirmed.
* Decryption displays inspection type only for Decrypt, and server certificate
  only for inbound inspection. Profiles remain selectable for No Decrypt checks.
* NAT/PBF interface selectors contain configured Layer 3 interfaces and units.
  Layer 2 and unconfigured ports are excluded.
* QoS profiles are under Network > Network Profiles > QoS Profile and the QoS
  policy's **Manage profiles** button. All eight classes have priority, maximum
  and guaranteed Mbps controls. Invalid totals and guarantees are rejected.
* Decryption profiles are under Objects > Decryption Profiles and the Decryption
  policy's **Manage profiles** button. This initial profile editor supports TLS
  version bounds, forward-proxy checks and No Decryption certificate checks.

The profile controls use the concepts in the official
[QoS profile help](https://docs.paloaltonetworks.com/ngfw/help/12-1/network/network-network-profiles/network-network-profiles-qos)
and [Decryption profile help](https://docs.paloaltonetworks.com/ngfw/help/12-1/objects/objects-decryption-profile).
FFN stores its own structured profile schema; this is not a promise of arbitrary
PAN-OS XML import compatibility. Unsupported imported fields stay read only.

## CLI without JSON

These examples require the referenced zones/interfaces to exist. New and cloned
rules start disabled. They are staged, not automatically committed or applied.

```
request policies nat add outbound from=trust to=untrust source=192.0.2.0/24 source-type=dynamic-ip-and-port source-interface=ethernet1/2
request policies qos add priority-web source=192.0.2.0/24 class=2
request policies pbf add alternate-uplink action=forward egress-interface=ethernet1/2 next-hop=198.51.100.1
request policies profiles decryption add tls-strict min-version=tls1-2 max-version=tls1-3
request policies decryption add inspect-tls action=decrypt type=ssl-forward-proxy profile=tls-strict

request policies profiles qos add wan-profile max-mbps=100 guaranteed-mbps=20 class1.priority=real-time class1.guaranteed-mbps=20
request policies profiles qos edit wan-profile class2.priority=high class2.max-mbps=50
show policies profiles qos vsys1 candidate
show policies profiles decryption vsys1 running

request policies nat edit outbound description="Internet source translation"
request policies nat clone outbound outbound-copy
request policies nat before outbound-copy outbound
request policies nat after outbound-copy outbound
request policies nat enable outbound
request policies nat disable outbound-copy
request policies nat remove outbound-copy
```

Append `scope=vsys2` for another virtual system. List fields accept comma-separated
values. Quote names or values containing spaces. The commands read the current
candidate revision, send the mutation through the authenticated API, and reject
concurrent changes instead of retrying over them. Existing JSON commands remain
available for automation that manages explicit revision tokens.

QoS profiles are device-wide; Decryption profiles are local to the selected
virtual system. A referenced profile cannot be deleted. Renaming an existing
profile is deliberately unsupported; create a new one and update references.

## Ownership, upgrades and runtime limits

QoS profiles are stored under `network/profiles/qos-profile`. Their FFN fields
are `aggregate-bandwidth/{max-mbps,guaranteed-mbps}` and
`classes/entry[@name='class1'…'class8']/{priority,max-mbps,guaranteed-mbps}`.
Decryption profiles are under the selected VSYS `profiles/decryption` subtree.

The legacy SQL resource synchronizer no longer rewrites the QoS rulebase or its
profiles at Commit. Legacy `network-resources/qos-policies` and `qos-profiles`
requests return the new endpoint location. Existing SQL rows are retained;
installations with old SQL definitions must review/export them before migrating
to the new editors. They are not silently converted to the new schema.

Profile definitions do not commission an engine or attach a scheduler to an
interface. QoS shaping, PBF route enforcement, and TLS/SSH inspection remain
blocked until their corresponding runtime providers are implemented. NAT keeps
its existing commissioned dataplane provider and acknowledgment path. No rule
editor or CLI convenience command bypasses these checks.

Tests: `test_policy_workflows.py`, `test_policy_config.py`,
`test_policies_browser.cjs`, and `test_console_ui.cjs` cover staging, running
isolation, conditional fields, profile validation, auth/locks, reference
protection, CLI operations, and legacy-sync ownership.
