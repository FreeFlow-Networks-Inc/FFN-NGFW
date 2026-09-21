# Security policy planning and execution

WebUI and CLI share candidate XML and the controld Commit boundary. Saving a
rule stages it. The selected `linux-stateful-nftables` provider validates the
effective candidate, then configd applies only committed running XML through
controld and its journaled execution worker.

## Supported enforcement

The initial provider supports ordered IPv4 allow/drop rules, universal,
intrazone and interzone types, zone/interface bindings, address/service objects,
and local session-start/end logging for allowed traffic. Intrazone allow and
interzone deny remain implicit. Both directions are checked against current
policy; replies additionally require the original direction's conntrack grant.
INPUT/OUTPUT are separate from transit Security policy.

Application/identity matches, inspection profiles, reset/reject/ICMP-response
actions, logging denied packets, external log forwarding and IPv6 are rejected
at validation. Application-default is not treated as service any. Unsupported
features remain blocked; selecting the provider never bypasses these checks.

## Coordinated activation and recovery

`ffn_security_runtime.py` applies Security, NAT, the platform's acknowledged
aggregate guards and a closed forwarding gate in one nftables transaction.
Logical interfaces resolve from commissioned physical mappings and fresh
platform owner evidence. Security rules use current numeric interface IDs.
No addresses, VLANs, zones or aggregate members are compiled into the code.

An eight-second kernel lease admits transit only while the supervisor verifies
the stored generation, current bindings, kernel readback and event collector.
The collector renews it each second. A stopped/hung supervisor loses its lease;
stream loss or logging failures hold transit closed. Apply failures restore the
previous kernel generation with a closed gate. Failed or ambiguous rollback is
latched as a fault. NAT cannot be changed through its standalone worker after
coordinated ownership is established.

Binding changes and DP boot replay recompile the stored policy only after all
required owners are available. The PA5200 aggregate owner always starts with
its default-deny guard. Policy reconciliation exchanges that guard only when
the new owner is acknowledged, without restarting LACP. A new DP boot records
old sessions as interrupted, with incomplete counters explicitly identified.
A same-boot collector crash with active sessions, or event-stream loss, requires
explicit event-gap reconciliation; it does not silently claim complete logs.

## Session records

`ffn_session_events.py` consumes kernel NEW/UPDATE/DESTROY events. Immutable rule
generation metadata is durable before traffic is admitted. A record includes
the original and reply tuples (including NAT), rule identity, observed first
admission time, end observation and actual original/reply packet/byte counters.
Missing kernel timestamps are not invented. DESTROY messages can omit labels;
the durable session identity supplies the rule token. Native byte order and
alignment padding are tested on MIPS64eb; synthetic fixtures also cover little
endian. Numeric nftables conntrack labels name bit positions, including zero.

Records live in `/var/lib/ffn/security-sessions.db` on the DP. The collector uses
SQLite durable transactions. External log forwarding, retention management and
bulk WebUI log browsing are separate capabilities, not claimed by this provider.
An administrator can inspect recorded events read-only on the DP:

```sh
python3 - <<'PY'
import json, sqlite3
db = sqlite3.connect('file:/var/lib/ffn/security-sessions.db?mode=ro', uri=True)
for (row,) in db.execute('SELECT data FROM events ORDER BY id DESC LIMIT 20'):
    print(json.dumps(json.loads(row), indent=2))
PY
```

## Installation and qualification

Install core code with `image/install-security.py dp` and `... mp`; these
installers do not select a provider. Install the platform guard/binding adapter
and Security worker transport before starting `ffn-security-runtime.service`.
The DP requires the matching conntrack events/netlink/labels/accounting and
nftables kernel features. Native CPU worker configuration exposes the same
resource, with platform code used only when explicitly selected.

After qualification, MP selection is the root-owned
`/etc/ffn/security-provider.json` with
`{"provider":"linux-stateful-nftables","commit":true}`. Commissioning must
initialize the provider from running XML and verify its supervised acknowledgment.
Removing that selection is not a rollback procedure: the DP gate deliberately
continues to protect transit until an explicit, verified migration occurs.

Native OCTEON tests cover allow/reply, an existing ungranted conntrack reply,
unsolicited reverse traffic, ordered drops, revocation, service matching, NAT
translation, durable session-end counters, interface-local input, collector
lease expiry, invalid-generation rejection, persistence rollback and binding
loss/recovery. Candidate validation on the appliance passed through controld;
commissioning left candidate and running XML unchanged.

Read-only plan/match diagnostics remain available:

```text
show policies preview security vsys1 candidate
request policies security test {"source":"192.0.2.10","destination":"198.51.100.10","from_zone":"trust","to_zone":"untrust","protocol":"tcp","destination_port":443} vsys1 candidate
request policies commit-validate
```

Use configured zone names and addresses for your environment. Plan matching
does not send traffic or prove physical WAN readiness.
