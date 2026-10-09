# VRRP configuration and runtime boundary

Network > VRRP and `show/request policies vrrp` share the authenticated MP
management/controld path. OK and CLI edits modify candidate XML only, under
configuration locking and revision checks. Running configuration is read-only.
No customer address, interface, VRID, or ISP preference is built into the code.

Two modes are represented:

- **Participation:** VRRPv3 multicast, IPv4 or IPv6, a configured Layer 3 data
  interface (including aggregate subinterfaces), VRID, backup priority 1–254,
  advertisement interval, preemption, virtual addresses and tracked interfaces.
  VIPs may reference local/shared IP/netmask objects. Compilation resolves the
  current object value without replacing the stored reference. VIPs must be
  distinct from the permanent address and share its subnet and prefix.
- **Passthrough:** IPv4, IPv6 or both, confined to an existing Layer 2 VLAN domain
  with at least two eligible interfaces in the selected virtual system. This
  does not create a bridge, join ISP circuits, or authorize routed forwarding.

Per RFC 9568, the plan identifies protocol 112, destination 224.0.0.18 or
ff02::12, and TTL/Hop Limit 255. Those constants describe the protocol, not
customer configuration. Advertisements must never be routed.

## Current availability

Configuration, deterministic plans, WebUI, CLI and commit guards are implemented.
**Neither mode is activated by this patch.** All entries start disabled. An
enabled entry blocks Commit/configd before runtime changes because an election
and scoped forwarding provider has not yet been commissioned. A valid plan does
not mean a router is Master, a VIP exists, or BCM/FE100 is forwarding VRRP.
Malformed imported settings also block Commit, even when disabled.

Before commissioning a provider, verify:

1. Committed logical-interface to DP attachment, bridge and VLAN identity; no
   carrier requirement for storing configuration, and fault state if a tracked
   attachment becomes unavailable at runtime.
2. Backup/Master election, preemption, withdrawal, restart and peer-failure
   recovery; real VIP/virtual-MAC ownership, GARP/NA, and duplicate-IP prevention.
3. Interface management-profile protection on VIP/VMAC devices. Protocol 112
   acceptance must be explicitly scoped and must not expose other local services.
4. L2 passthrough across the same bridge/VLAN only, protocol/destination/hop-limit
   checks, and negative tests for different VLANs, ISP links and routed paths.
5. MP→CP→DP revision/boot acknowledgements, stale-owner fencing and readback.
   VIP/NAT/session ownership must be synchronized or withdrawn on failover.

Address-owner priority 255, unicast peers, virtual wires, sync groups and
script-based tracking are not exposed. ISP health and default-route preference
remain separate Virtual Router settings; VRRP does not choose between ISPs.

## Console examples

Use actual configured names and objects in place of the placeholders:

```text
show policies vrrp candidate scope=vsys1
request policies vrrp add gateway interface=<data-interface> virtual_addresses=<VIP-object> vrid=<id>
request policies vrrp add advertisements mode=passthrough domain=<VLAN-domain> family=both
request policies vrrp edit gateway priority=150 preempt=yes
request policies vrrp remove advertisements
```

`image/install-policies-ui.py` includes the code, navigation and console handler;
normal build/provision and plane installers include the shared commit dependency.
No runtime services or configuration are changed by the installer itself.

Reference: https://www.rfc-editor.org/rfc/rfc9568.html
