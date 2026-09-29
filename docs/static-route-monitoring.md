# Static route eligibility and path monitoring

Static routes are desired configuration. Distinct metrics allow multiple routes
to the same destination; Linux prefers the lowest metric among installed routes.
The route owner withdraws ineligible routes while retaining their configuration.
It never reconfigures aggregate members or restarts LACP.

PA5200 configd marks static routes for link tracking. The MP obtains actual
faceplate link observations through controld and renews a DP-local 60-second
lease. A live TAP descriptor alone is insufficient. Aggregates additionally need
a distributing member with a current physical link. Unknown or expired hardware
observations withhold the route. CPU-only backends use native netdevice carrier.

A gateway outside the interface prefix is retained as configured but withheld
with `gateway-outside-interface-prefix`. The explicit on-link option permits
ISP-supplied /32 plus directly reachable gateway arrangements; it is never
inferred from an address or enabled automatically.

Each route can enable IPv4 ICMP path monitoring with up to four explicit targets,
an interval, timeout, failure/recovery round thresholds, and an any/all target
failure condition. Targets must lie within the route destination. IPv6 path
monitoring is rejected until an NDP/ICMPv6 probe provider is implemented.

Probes run in the data namespace and send Ethernet/ARP/ICMP through the selected
interface and next hop. They do not follow another default route, change the
kernel route table, or use management internet. This allows a withdrawn path to
recover without a backup path answering its probes. Replies must match a random
nonce, source/destination addresses and valid IP/ICMP checksums. Monitoring starts
withheld until the recovery threshold is met. Probe rounds are bounded and
scheduled oldest-first; configured intervals are minimum intervals under load.

`ffn-static-routes.service` shares the network configuration lock. Its stop hook
withdraws managed routes; systemd restarts the owner on failure. Results from a
configuration that changed during a probe are discarded. Link observations and
monitor state are boot-scoped. Hardware FE100 session invalidation must continue
to consume route-change events before production hardware admission is enabled.

The route dialog stages these settings with OK/Cancel. Commit applies them.
The PA5200 console uses the same daemon-backed APIs:

```
show platform routes default
request platform route default new '{"dest_cidr":"0.0.0.0/0","dev":"ethernet1/1","next_hop":"192.0.2.1","metric":100,"path_monitor":{"enabled":true,"targets":["198.51.100.1"],"interval":5,"timeout":1,"failure_count":3,"recovery_count":3,"failure_condition":"all"}}'
```

Use a numeric route ID instead of `new` to edit an existing route. These commands
stage candidate changes only. `show platform network` exposes the DP route and
monitor observations; the WebUI labels unavailable runtime evidence explicitly.
