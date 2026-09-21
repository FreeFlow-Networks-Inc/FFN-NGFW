# Security policy planning and execution

Security XML is the shared candidate configuration for WebUI and CLI. Saving a
rule does not activate it. As of this implementation, Security has an ordered
plan compiler and read-only match diagnostics, but no commissioned execution
provider. Commit must remain blocked for enabled Security rules.

The WebUI Security workspace exposes **Preview policy plan** and **Test policy
match**. The same operations are available through the existing control daemon:

```text
show policies preview security vsys1 candidate
request policies security test {"source":"192.0.2.10","destination":"198.51.100.10","from_zone":"trust","to_zone":"untrust","protocol":"tcp","destination_port":443} vsys1 candidate
```

Replace the example zones with configured zone names. No packets are sent.
Authenticated read-only users can run these diagnostics; mutations still require
an administrator and use the candidate/Commit workflow.

The plan preserves universal/intrazone/interzone semantics, source and destination
objects, service objects, user/device/application predicates, actions, profiles,
ICMP responses and logging requests. Unknown XML and unresolved objects stop
evaluation. Missing identity data and application-default service resolution are
indeterminate, never a wildcard match. Implicit intrazone allow/interzone deny
results describe policy intent, not observed dataplane behavior.

Execution still needs all of the following before commissioning:

- Ordered stateful enforcement and readback tied to the committed revision.
- Verified zone/interface bindings derived from each platform's active owners,
  including aggregate parents and VLAN units.
- Atomic coordination with aggregate transit guards and NAT, including rollback
  and restart recovery without resetting LACP.
- Enforcement of every requested action/profile/identity predicate, with explicit
  rejection of unsupported capabilities.
- Session logging and log forwarding when requested; packet counters alone cannot
  satisfy session-end logging.

The current PA5200 aggregate path has a default-deny transit guard. Its legacy
NAT binding file contains physical VIF mappings and does not automatically include
aggregate VLANs. Merely adding a Security provider selection file, removing the
guard or accepting a syntactically valid plan would not establish enforcement.

Validation: Security matching tests cover ordering, disabled rules, zone types,
implicit rules, unknown fields, missing identity and application-default. The
existing policy/API tests and authorization matrix also pass. On the appliance,
the candidate rule compiled and matched through the control daemon while Commit
remained blocked. Candidate and running configuration hashes were unchanged.
