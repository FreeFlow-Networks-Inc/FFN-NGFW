# NAT, QoS, PBF and Decryption implementation status

All four rulebases now have a control-daemon compiler, resolved policy preview,
and first-match packet tester shared by the WebUI and FFN-CLI. These are
diagnostics against candidate or running XML, not runtime apply acknowledgments.
They do not change configuration, send packets, or acquire a configuration lock.
Normal rule edits still stage candidate changes for Commit.

## Supported planning

The compiler resolves static IPv4 address objects/groups, address ranges,
TCP/UDP services/groups, and static application groups. It preserves rule order,
virtual-system scope, no-NAT exceptions, PBF no-policy-routing exceptions, and
no-decrypt exceptions. Disabled rules are excluded. Imported settings that cannot
be interpreted safely block compilation instead of being silently dropped.

The intended actions are:

* NAT: the existing compiler's static SNAT, dynamic IP-and-port SNAT, interface
  masquerade and destination address/port translations.
* QoS: assignment to class 1–8. Classification does not by itself impose a rate.
* PBF: forward through a configured Layer 3 interface/IPv4 next hop, discard,
  or fall back to ordinary routing.
* Decryption: no-decrypt, TLS forward proxy, TLS inbound inspection with a
  referenced server certificate, or SSH proxy. Plans contain certificate names,
  never private keys or certificate contents.

Packet tests require IPv4 addresses, configured source/destination zones and
protocol. Ports, application identity, user identity and egress interface may
also be supplied. Missing context produces an indeterminate result if an earlier
rule could match. It must never cause a later rule to be selected. Application
and user inputs are hypothetical values; the test performs no live App-ID,
User-ID, route lookup, TLS interception or certificate validation. Each rulebase
is tested independently at its lookup stage. For NAT use original addresses and
the original route's destination zone/interface.

## Runtime boundary

NAT retains its existing commissioned Linux nftables provider and MP → CP → DP
apply path. The NAT translation preview now displays per-rule initial-packet
counters only when the kernel table and saved generation agree with the selected
plan. These counters describe the first packet processed by a NAT connection
rule, **not total session packets or bytes**. A new plan generation resets them.
Unavailable or mismatched telemetry is not displayed as zero usage.

QoS, PBF and Decryption remain blocked for activation until their runtime
providers exist. Their commit errors now also include specific compilation errors
or engine requirements. The next runtime work is:

* QoS: an acknowledged classifier/scheduler with per-egress class-to-queue and
  bandwidth-profile bindings, including the PA-5200 forwarding path.
* PBF: policy routes, reachable next-hop validation, return-path handling and
  integration with NAT's destination-zone lookup. The current NAT runtime rejects
  policy routing and VRFs; enabling PBF alone would not resolve that conflict.
* Decryption: an inspection proxy, session steering, certificate/key provisioning,
  trust validation and profile enforcement. A stored decrypt rule is not an
  operational TLS interception engine.

## API and CLI

Authenticated read operations go through `policy/request` on `ffn-controld`:

```
GET /api/config/policies/qos/preview?scope=vsys1&source=candidate
POST /api/config/policies/qos/test?scope=vsys1&source=running
{"packet":{"source":"192.0.2.10","destination":"198.51.100.20","from_zone":"trust","to_zone":"untrust","protocol":"tcp","destination_port":443}}
```

```
show policies preview qos vsys1 candidate
show policies preview pbf vsys1 running
show policies preview decryption vsys1 candidate
request policies qos test '{"source":"192.0.2.10","destination":"198.51.100.20","from_zone":"trust","to_zone":"untrust","protocol":"tcp","destination_port":443}' vsys1 candidate
```

The preview response includes a configuration revision, deterministic plan digest,
expanded matches, intended actions, blockers and runtime requirements. All test
results explicitly carry `simulation: true` and `applied: false`.

## Validation

Run `tests/test_policy_plan.py`, `tests/test_policy_config.py`,
`tests/test_nat_policy.py`, `tests/test_nat_control.py`, and
`tests/test_policies_browser.cjs`. The planner uses only Python's standard library
and the shared policy modules; it does not depend on host endianness or an x86
packet library. Native MIPS64eb validation is separate from enforcement testing.
