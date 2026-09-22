# Dataplane session collector

The coordinated Security/NAT provider enforces supported policies in the
dataplane kernel. Its forwarding lease requires a current session collector,
matching interface owners, the stored policy generation and verified nftables
readback. These checks do not commission FE100 hardware session offload.

The collector drains conntrack netlink events on a separate thread so policy
and interface readback cannot stop reception. Events are committed in bounded
batches using SQLite WAL with FULL synchronous durability. Socket loss remains
detectable; NETLINK_NO_ENOBUFS is never enabled. The actual receive buffer size,
collector heartbeat and reconciliation count are included in Security health.

On startup or a recoverable event gap, forwarding closes before a fresh socket
subscribes and dumps the kernel's IPv4 conntracks. Multicast events received
during the dump are replayed in order. Interrupted, incomplete, oversized or
undrained dumps cannot reopen traffic. Known durable rule identities must match
every recovered grant. The supervisor independently revalidates policy and
interface ownership before renewing forwarding. Conntracks, NAT mappings,
packet owners and LACP are not flushed or restarted by reconciliation.

Surviving sessions retain known start times. Sessions discovered only during
recovery have an unknown start time. A disappeared session with end logging
enabled produces an `interrupted` record with incomplete counters and no
fabricated end time. Recovered records retain `event_gap` through their later
end event. Malformed events, unknown rule identities, database errors and
unconfirmed policy rollback remain fail-closed; automatic recovery does not
clear these faults.

Validation includes endian-independent decoder/journal tests and the native
Security/NAT namespace suite on MIPS64: restart with live sessions, injected
ENOBUFS, a 2,000-packet burst, lease expiry, policy revocation, interface-owner
loss and persistence rollback. Native namespace tests require root and operate
on temporary namespaces, without changing the live firewall configuration.
