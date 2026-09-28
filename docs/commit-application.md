# Configuration application

Candidate validation resolves configured interfaces and address objects, including
physical interfaces, aggregates and units. An administratively disabled or
disconnected port can be referenced. DHCP does not need a lease to install a
masquerade rule. Unknown interfaces, invalid objects and unsupported policies
remain errors. Preview bindings are never used to forward packets.

Configd applies a generation in this order:

1. XML, object and policy validation.
2. Platform interfaces, parents, units, management profiles and routes, with
   provider readback before proceeding.
3. Remaining system settings in dependency order. Deletions precede additions,
   with consumers removed before their definitions.
4. Coordinated Security/NAT installation and dataplane acknowledgment.
5. Durable last-applied checkpoint of exactly the verified XML generation.

The apply status exposes `commit_generation` and `phases`. Failure stops dependent
stages. Concurrent running-config changes invalidate the acknowledgment. A replay
with no remaining generic changes still verifies policy and writes the checkpoint.
CLI and WebUI receive the same configd result through controld. Distribution to
other plane agents is held when configd reports failure or an uncertain result.

This is ordered reconciliation, not an all-resource atomic rollback. Successful
interface changes can precede a later failure; the report retains those results
and the previous last-applied checkpoint. Reapply reconciles the committed intent.

Install the selected platform and Security/NAT hooks first, then run
`python3 image/install-commit-order.py /opt/ffn-ngfw/ffn_configd.py`.
The Security installer also installs the ordering hook on engines that already
have platform reconciliation. Installation does not itself commit the candidate.

Operational carrier, LACP selection, DHCP lease and hardware flow qualification
remain separate observations. An accepted configuration is not a claim that a
disconnected cable forwards packets. Runtime owner identity and settings readback
are still required before reporting applied configuration.
