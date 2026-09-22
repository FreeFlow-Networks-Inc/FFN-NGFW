# Dataplane NAT and local interface services

NAT rules edited in WebUI or FFN-CLI remain candidate changes until Commit.
The compiler resolves address/service objects and static groups, preserves
first-match order, and rejects unsupported enabled rules before activation.
Controld sends the committed plan through the MP execution worker to the
selected dataplane. Configd records the dataplane acknowledgment and digest.

The Linux provider supports IPv4 masquerade, single-address dynamic IP/port
source NAT, host-to-host static source NAT, TCP/UDP destination port translation,
combined source/destination NAT, and ordered no-NAT exceptions. These are
software conntrack/nftables operations. They do not grant Security-policy
permission, implement FE100 hardware NAT, or implement address pools, IPv6 NAT,
dynamic IP without port translation, policy routing, or active VRFs/ECMP.
Existing conntrack sessions retain their translation until they expire.

The provider owns only `ip ffn_nat` in the isolated `ffn-data` namespace. It
checks kernel support, interface mappings, revision, table ownership and drift
before replacing that table atomically. Failed persistence attempts restore
the previous table. A saved configuration can be restored by `ffn-nat.service`.

Commissioning requires a root-owned `/etc/ffn/nat-provider.json` on the MP:

```json
{"provider":"linux-nftables","commit":true}
```

The dataplane requires a root-owned `/etc/ffn/nat-interfaces.json` mapping
logical names to existing owned Linux interfaces. Do not derive this map from
untrusted interface names. Install the runtime and required kernel modules
before selecting the provider. `image/install-nat.py` narrowly merges existing
daemon code and keeps backups; it does not restart services or select a provider.

Operational readback is available through the WebUI NAT translation preview,
`show policies nat-preview`, `show policies nat-tools`, and the authenticated
`/api/config/nat/preview` and `/api/system/dataplane-tools` endpoints.

Interface management profiles govern **local input to the interface's own
addresses**. Their Ping/service permissions and permitted-source lists are
independent of zone membership and transit Security rules. The DP network
owner installs the local-input rules before assigning the address. Profile-only
changes preserve the interface state and its routes. Both PAN-style `ping`
and legacy `permit_ping` fields are supported; conflicting fields or missing
profile references are rejected. A profile permits traffic to a listener; it
does not create SSH/HTTPS/SNMP services in the dataplane namespace.

Validation includes real MIPS64eb namespace packet tests for NAT and for Ping
with a drop-all transit chain, no zone, source restrictions, profile revocation,
and destination-address ownership. The native tool audit checks ELF class,
endianness and machine type as well as version execution. Some utilities use
native BusyBox applets, reported explicitly by the audit.
