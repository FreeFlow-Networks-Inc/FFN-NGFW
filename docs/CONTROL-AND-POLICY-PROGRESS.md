# Control and policy implementation — 2026-09-21

## Deployed and verified

- Browser and console authentication now enforce the same write-role boundary.
  Admin and superuser may mutate; operator and read-only may inspect, run the
  read-only policy match tests, and change their own password. Tests exercise
  every registered core mutation through both identity paths. Hardware extension
  handlers retain their existing administrator checks.
- Configuration edit locks use SQLite transactions and durable leases. Competing
  processes cannot both acquire a lock. Management and control daemon restarts
  preserve the current holder and timeout. Administrator override remains audited.
- Three dynamic destination NAT selectors are implemented: round-robin, source
  IP hash, and source/destination IP hash. Statically resolved address objects,
  groups, ranges and subnets expand to a bounded pool of at most 256 addresses.
  FQDN/dynamic-group resolution is not implemented. Hash seeds remain stable
  across replay. Existing connections retain their conntrack translation.
- The NAT editor reads support from the current dataplane, and Commit continues
  to validate the proposed rules before applying them. Merely saving a definition
  does not enable it. Rule simulation displays translated pools correctly.
- Matching MIPS64eb nft_numgen, nft_hash, sch_htb, sch_fq_codel and cls_fw modules
  were built from the commissioned tree, checked against the running kernel
  configuration, loaded, and configured for boot-time loading. No kernel image
  replacement or appliance reboot was required.
- Native OCTEON disposable-namespace tests passed for ICMP source NAT, static
  source NAT, TCP/UDP destination NAT, combined translations, first-match no-NAT
  exceptions, counters, removal and replay. New distribution tests passed with
  two backend addresses, translated UDP ports and existing-connection affinity.
- Native scheduler tests also passed: all eight HTB classes carried marked UDP
  packets through FQ-CoDel and reported class byte counters. This verifies the
  scheduler primitives, not QoS rule/profile activation through Commit.
- The LACP owner was restarted in a bounded test. It automatically recovered
  with a new acknowledgement token, matching configuration, its subinterface,
  and both 40G members distributing. Recovery exceeded the initial 50-second
  test window; no full CP/DP reboot recovery was tested.

No operator candidate/running XML was changed during deployment. The currently
committed XML contains no enabled NAT, QoS, PBF or Decryption rules; the tests
do not demonstrate production internet transit.

## Implemented internally, not admitted to production

The PA5200 platform has a tested `SessionLifecycle` component for FE100 owners:
monotonic heartbeat/idle/maximum-lifetime expiry, explicit close, ordered producer
events, producer restart fencing, capacity bounds, and exact-owned-entry cleanup.
Policy/binding/qualification changes drain sessions. It is not a public admission
API and is not connected to a production evaluator. It must not be described as
live FE100 offload. The existing automatic FE100 recovery timer remains active.

## Remaining implementation and qualification

- Connect a trusted live session evaluator to FE100, including direction-specific
  zone/routing metadata and current policy/route/neighbor generation. Qualify
  simultaneous bidirectional forwarding before enabling admissions. Hardware NAT
  and inspection bypass remain unsupported.
- Implement persistent source-IP/port bindings, IP-modulo and least-sessions
  destination allocation. These modes remain explicitly blocked at activation.
- Connect QoS classification and egress scheduling, PBF with return-path/NAT
  integration, and TLS/SSH decryption with certificate/profile enforcement.
  Installing their kernel prerequisites does not enable these policy providers.
- Finish the candidate/Commit migration for legacy operational write handlers;
  this change fixes authorization but does not convert every older immediate
  operation into a staged setting.
- Restore/requalify the WAN packet path in the current CP/DP lifetime. The live
  WAN state belongs to an earlier hardware epoch, its BCM WAN queue count is zero,
  and the DP WAN netdevice is down. Do not attribute this to a disconnected modem
  or reuse stale qualification as readiness. Preserve the working aggregate path.
- Run actual upstream transit, deny/profile enforcement and full reboot tests
  once those paths and policies are commissioned.

References for distribution semantics and kernel expressions:
[PAN-OS destination distribution](https://docs.paloaltonetworks.com/ngfw/networking/nat/configure-nat/configure-destination-nat-using-dynamic-ip-addresses),
[nftables reference](https://netfilter.org/projects/nftables/manpage.html).
