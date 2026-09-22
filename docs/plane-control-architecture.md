# Common MP / CP / DP control architecture

FFN-NGFW owns the management API, configuration definitions, control protocol,
transaction journal, and Linux network engine. Platform submodules own physical
device mappings, bring-up, capabilities and hardware-specific UI. No network
command, executable path, CPU assignment or PCI register address comes from an
HTTP caller.

```mermaid
flowchart LR
  UI[WebUI / API] --> MP[MP daemon: durable intent and outcomes]
  MP -->|Pinned SSH / Unix RPC| CP[CP daemon: platform hardware control]
  CP --> NIF[Platform NIF link adapter]
  CP -->|Pinned SSH / Unix RPC| DP[DP daemon: validate and apply]
  MP -->|CPU-only: local Unix RPC| DP
  DP --> L[Shared Linux L2 / L3 engine]
  L --> TAP[OCTEON TAP / platform fabric]
  L --> NIC[Provisioned native host NICs]
```

## Responsibilities and current scope

* **MP:** authenticated administration, candidate XML, audit, runtime requests,
  durable submitted intent and returned configuration. The WebUI shows which
  nodes handled a request. Hardware-bearing hosts retain management CPU roles.
* **CP:** dispatches platform-owned resources locally and relays network requests
  to the DP. PA-5200 NIF activation uses the commissioned FE100 link service;
  CP physical link observations do not imply forwarding or policy readiness.
* **DP:** validates dependencies and revisions, serializes changes, journals the
  intent before execution, applies L2/L3 configuration, and returns the result.
  Runtime controller state is persisted for the existing boot replay mechanism.
* **CPU-only deployment:** MP and DP are separate daemons on one host; an extra
  CP process is optional. Native NICs must already be provisioned into the data
  namespace. Neither runtime apply nor autodetection moves a management NIC.

The shared engine implements disabled/L2/L3 interfaces, VLAN membership and
PVIDs, IPv4/IPv6 addresses, VRFs, static routes, ECMP and policy routing. These
match useful interface/routing concepts documented in Palo Alto's
[interface guide](https://docs.paloaltonetworks.com/ngfw/networking/configure-interfaces)
and [virtual router guide](https://docs.paloaltonetworks.com/ngfw/networking/configure-virtual-routers).
This is an FFN implementation, not a claim to reproduce proprietary internals.

## Protocol and recovery

Protocol v1 uses bounded newline-delimited JSON over root-only Unix sockets.
Remote hops invoke the fixed `ffn_planed.py call` client using pinned SSH host
keys and node-local credentials. The payload is passed on stdin; there is no
remote shell interpolation of configuration. Relays and daemons persist across
requests, while remote SSH subprocesses currently run per request. No new TCP
listener or unauthenticated management channel is introduced.

An envelope has exactly `v`, canonical UUID `id`, `resource`, `action`, and
object `payload`. Actions are status, validate, apply, lookup, result, resolve
and inventory. Apply/validate include the controller's current integer revision.
Controllers are allowlisted in root-administered node configuration. A CP may
handle `nif` locally while forwarding `network` to its DP.

The resource vocabulary belongs to the node configuration, not to the core.
`inventory`, on the reserved resource name `planes`, returns the node's role,
the resources it offers, the actions permitted on each, the budget each
controller call is given, and any request IDs currently blocking a resource. A
node with a peer asks it and nests the answer; a peer that does not reply --
including one predating this action -- is reported unreachable rather than
omitted, because silence about a downstream node must not read as a node with
nothing on it. Controller argv is never returned: a caller does not need the
executable path, and returning it would turn reading a description into reading
a map of the box. A platform therefore adds resources by installing its own node
configuration, and the core WebUI and CLI address them with no core change.

Controller budgets are per resource and action, declared as `timeouts` in the
node configuration and defaulting to 90 s for apply and 20 s otherwise. They are
checked when the daemon is constructed -- so `install-plane-node.sh` refuses a
bad one -- against the resource's own configured commands and against the
response ladder: controller at most 110 s, relayed peer 120 s, client wait
125 s, socket read 130 s. A controller allowed to outlive its caller produces an
unknown outcome nobody observed, which is the state this protocol exists to make
rare and recoverable. A controller killed before its own shorter deadline
destroys the bounded answer it was about to return, which is what the defaults
did to a platform whose status call is allowed 25 s and whose route lookup is
allowed 90 s.

Every apply stores its intent before dispatch. Repeating an identical UUID does
not blindly re-execute a leaf operation; changing the content of that UUID is
rejected. A leaf that crashes or loses its controller outcome retains an unknown
record and rejects new writes to that resource. Relays retain the original
request and can retry delivery of the same UUID, allowing the leaf to return its
durable result. Journals contain configuration and must remain root-only.

Read a result with `payload: {"request_id":"<original UUID>"}`. For an unknown
leaf outcome, inspect live configuration, repair any partial runtime changes,
and explicitly resolve using `payload: {"request_id":"<original UUID>",
"observed_revision":N}`. Resolve checks that revision again, records
**reconciled**, and never claims the interrupted operation succeeded or replays
it. A failed route/port rollback may need repair; revision equality alone is
not proof of healthy forwarding. Audit and request IDs provide the evidence
needed to follow that recovery.

The blocking request ID does not have to have been kept. `inventory` reports it
per resource, which is what lets a different session recover an apply it did not
issue -- previously the daemon implemented resolve and nothing in the core could
send it, so an interrupted apply blocked its resource until someone assembled
the envelope by hand. `ffn_plane_network.py result --recover UUID` reads the
stored outcome; `resolve --recover UUID --observed-revision N` records the
reconciliation. The Control Planes page offers the same pair, and makes the
operator enter the revision rather than filling it in from the observation it is
supposed to confirm.

## Installation and selection

Install Python 3 with sqlite3, iproute2 and the platform's kernel/network
dependencies on the participating nodes. Run
`image/install-plane-node.sh ROLE CONFIG.json` on each node from the core tree.
It installs code, the service template and role configuration; it does not start
services or change interfaces. Use platform-provided MP/CP/DP configurations,
or `config/planes/cpu-mp.json` and `cpu-dp.json` on a CPU-only host.

For a native backend, provisioning must create `ffn-data`, place and name its
owned interfaces `p1` through `p4096`, and supply `/etc/ffn/network.json` before
initializing the engine with `ffn_linux_network.py apply --backend native`.
This explicit initialization sets up the bridge, forwarding and configured
interfaces. Existing namespaces/bridges must not be adopted blindly. Runtime
patches cannot add unprovisioned native interfaces, and automatic native namespace
teardown is refused. Boot-time namespace provisioning and replay must be ordered
before the DP control service in the image's platform/host profile.

Start the DP, then CP if present, then MP daemons with `ffn-plane@ROLE.service`.
Set `FFN_PLANE_SOCKET=/run/ffn-plane-mp/control.sock` in the manager's local
systemd environment and restart the manager. The core Control Planes page then
appears. POST `/api/system/planes` is admin-only and accepts the protocol envelope.
Validate, review the returned proposal, then apply. `GET` on the same path is
admin-only too and returns the description; the page lists the resources it
finds there, so a provider's resources reach the operator without the core
naming any of them. The provider's existing network WebUI also uses the MP
daemon when this selection is present. A provider page that wants one resource
only calls `window.ffnPlanes.render(parent, resource, seed)`, supplying its own
editor template rather than relying on the core knowing its schema.

## Performance boundary and remaining work

Control messages never carry packets. Native Linux forwarding can use NIC queues
and kernel parallelism; the new daemons do not implement a packet worker scheduler
or tune RSS/IRQ/NUMA affinity. A high-core deployment should provision management
and dataplane CPU sets based on discovery, NIC NUMA locality and the selected
packet engine. No core-count or throughput gain is asserted by these changes.

The PA-5200 packet path is no longer only the commissioned four-port software
relay through the MP. The platform adapter's routed virtual interfaces have been
physically qualified on one faceplate pair: exact L2, IPv4 and IPv6 forwarding in
both directions, VLAN isolation, MAC rewrite, TTL and hop-limit handling, ARP and
IPv6 neighbour discovery, and refusal to reassign an interface that saved routes
or policies depend on. FE100 front egress with a live session has passed on that
same pair. None of that is a throughput result: it is bounded sequential tests at
MTU 1500 on one pair.

What remains before the appliance is exploited: the other faceplate ports,
hardware tables and queues at scale, production FE100 session admission --
including concurrent policy-pair admission and continuous invalidation for every
direct controller writer -- cold-boot replay of routes that depend on adapter
interfaces, and line-rate inspection. NIF service activation completes none of
those, and NIF disable is intentionally unsupported by the current commissioned
adapter. A qualified pair is evidence about a pair.

Runtime network updates remain separate from XML commit. A future commit adapter
must compile the candidate into per-provider operations and coordinate rollback
across routing, NIF and security policy. This implementation provides per-resource
validation and recovery, not distributed two-phase commit. Legacy config agents
must not simultaneously own the same interfaces during migration.

## Verification

`test_planes.py` exercises three-plane and CPU-only paths, revision/UUID rejection,
lost replies, restart replay and explicit recovery. It also covers description:
that a node reports its own resources, actions, budgets and blocked request IDs,
that controller paths stay out of that answer, that the reserved `planes`
resource cannot be driven, that a relay nests its peer or reports it unreachable,
and that a configured budget reaches the controller while one outside the ladder
or naming an unconfigured operation is refused when the daemon is constructed.
`test_plane_sockets.py` runs real Unix sockets and subprocess relays with an
inert backend, and walks one description through all three nodes. API and WebUI
tests cover permissions, validation and retention of the request ID after
failures; the WebUI test drives resource discovery, a resource change, and a
reconciliation that refuses to proceed without an observed revision and never
replays the interrupted apply.
`test_linux_network.py` covers dependency checks and rollback. The opt-in root
`test_network_namespace.py` sends packets through disposable native veth interfaces
and removes only the namespaces it created; it never uses physical interfaces.
