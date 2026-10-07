# NAT64 and NPTv6

Policies > NAT offers IPv4, NAT64 and NPTv6 modes. Prefixes and pools accept
literal addresses or current shared/vsys address objects. OK stages candidate
XML through controld; Cancel discards the editor. The console CLI uses the same
schema and validation. No customer prefix, address pool or route is installed
by this feature. New rules start disabled.

NAT64 uses `nat64-prefix` and `nat64-pool`. Source matching is IPv6; destination
Any is narrowed to the translation prefix. The pool contains explicit unicast
IPv4 hosts or a static group of such hosts. NPTv6 uses
`nptv6-internal-prefix` and `nptv6-external-prefix`; Source is Any or the effective
internal prefix, Destination and Service are Any. IPv4 translation options are
incompatible with these modes. Wrong-family objects, host bits in prefixes,
unsupported lengths and overlapping NPTv6 prefixes are rejected.

Example CLI syntax, using documentation-only addresses:

```text
request policies nat add v6-egress nat-type=nat64 nat64-prefix=2001:db8:64::/96 nat64-pool=192.0.2.10 from=inside to=outside
request policies nat add prefix-map nat-type=nptv6 nptv6-internal-prefix=fd01:203:405::/48 nptv6-external-prefix=2001:db8:1::/48 from=inside to=outside
```

Use existing zone names and assigned prefixes. These commands stage disabled
rules; they do not configure a translator, DNS64, routes or interfaces.

## Implemented primitives

`ffn_ipv6_translation.py` implements [RFC 6052](https://www.rfc-editor.org/rfc/rfc6052)
address embedding/extraction for all six prefix lengths, reserved-u validation
and the well-known-prefix non-global-destination restriction. A bounded NAT64
packet oracle translates already selected TCP/UDP and ICMP echo tuples in both
directions, recalculating checksums and decrementing TTL/hop limit. It is not
a stateful translator or an allocator. Unsupported extensions, fragmentation
and ICMP errors are rejected.

NPTv6 mapping follows [RFC 6296](https://www.rfc-editor.org/rfc/rfc6296), including
zero extension of unequal prefixes, checksum adjustment, and the first usable
IID word for prefixes longer than /48. Unmapped subnets and all-ones IIDs are
rejected. The all-ones interpretation follows the algorithm and reported
[erratum 8757](https://www.rfc-editor.org/errata/eid8757), which remains reported,
not verified. A bounded base-header oracle covers outbound, inbound and hairpin
mapping; payload and transport checksums remain unchanged. It deliberately
rejects extensions and ICMP errors rather than silently mishandling quoted
inner headers.

Tests cover published address examples, all 65,535 reversible /48 subnet values,
unequal prefixes, reserved identifiers, TCP/UDP/echo rewrites, checksum errors,
configuration round trips, CLI mode changes and prevention of runtime writes.

## Runtime boundary

IPv4 plans retain version 1 and their existing digest. Plans containing IPv6
translations use version 2. The DP validates their structure but refuses
activation before nftables, routes or interfaces are changed. A successful
compile or simulation is not an enforcement acknowledgment. Preview and the
editor show the current provider's reason for unavailable translation modes.

The deployed Linux provider currently implements IPv4 NAT only. NAT64 needs
an integrated stateful translator (including binding/session accounting,
ICMP errors, PMTU and fragments); NPTv6 needs IPv6 forwarding, hairpin and ICMP
embedded-header handling. Both need coordinated IPv6 Security enforcement,
interface/route validation, transactional apply, restart recovery and packet
qualification. Jool executable/module discovery is read-only and does not
commission it. Merely loading a module must not authorize traffic.

The PA-5200 FE100 adapter separately reports NAT64 and NPTv6 as unqualified.
The audited VER=3 flag alone does not establish IPv6 key layouts, native actions
or safe forwarding. IPv4-only encoders continue rejecting cross-family tuples.
Existing IPv4 Internet traffic stays on its commissioned provider.
