# Identity-bound hardware accounting

`ffn_ctlease.ko` pins one existing, assured IPv4 UDP or established TCP conntrack
object to a file descriptor. `libffn-ctlease.so` performs the native ioctls; `ffn_ctlease.py` is
the control-plane binding. None of these components creates connections,
allocates NAT, forwards packets, installs hardware flows, or enables offload.

Linux's conntrack netlink timeout update selects a connection by tuple and zone;
it does not condition the update on `CTA_ID`. Checking an ID in userspace before
a tuple update therefore cannot prevent refreshing a replacement connection.
The module retains the actual object and rejects dying or expired objects.
It matches both tuples, zone, numeric netlink ID, mark, and all 16 label bytes.
`CTA_ID` is an opaque hash cast to network order by the kernel, so the module
matches the value returned by a normal big-endian netlink decoder on both
little-endian hosts and big-endian OCTEON.

Only one file may own accounting for a given object. Updates have contiguous
per-lease sequence numbers and bounded, validated directional packet/octet
deltas. Ethernet header bytes (14 or 18, explicitly configured per direction)
are subtracted before updating Linux's L3 byte counters. An activity mask
controls timeout refresh separately from accounting, and refresh never shortens
the existing timeout. Detected identity changes latch the lease invalid.
The read-only check ioctl also detects idle deletion, expiry and label changes
without synthesizing traffic or extending the timeout. The coordinator calls
it when there are no new hardware deltas.

The device is mode 0600, requires `CAP_NET_ADMIN` in the bound network
namespace, and rejects use after crossing into another namespace. It requires
kernel conntrack accounting, marks, and labels. Helper sessions, fixed timeouts,
sequence-adjusted sessions and existing kernel/hardware offload are unsupported.

## TCP

A flow the hardware carries is invisible to the kernel: conntrack's TCP window
tracking goes stale and, on hand-back, every segment is `ct state invalid`
(the PA-5220 stalled a session for five minutes this way on 2026-10-19). The
lease does what `nf_flow_table` does for its own offloaded flows:

* bind requires an established, assured object and marks both directions
  `IP_CT_TCP_FLAG_BE_LIBERAL`; the timeout bound is the established default
  (432000 s) rather than UDP's 300 s, so a leased flow never expires sooner
  than it would in software;
* release zeroes both directions' `td_maxwin`, so the windows are re-learned
  from the next segments; the liberal flags stay, as in the kernel's own
  teardown fixup, so segments reordered across the hand-back are not invalid;
* a FIN or RST that reaches the kernel moves the state off ESTABLISHED, and the
  next update or check returns `ESTALE`: the owner must withdraw the hardware
  flow. Making such segments reach the kernel (a hardware exception for TCP
  control flags, or acknowledged withdrawal) is the owner's job; the module
  cannot see packets.

## Integration order

1. The trusted policy/session owner validates the software verdict, NAT binding,
   route, neighbor, interface, policy generation, and hardware generation.
2. Bind the kernel lease and register fresh directional hardware flow IDs before
   installing either direction. Labels must already represent the active policy
   generation; this module never invents a verdict or label.
3. Feed decoded native counter deltas through the single accounting owner.
   Receiver loss, stale accounting, or an ioctl failure must stop admission and
   withdraw both hardware directions. Never retry an ambiguous accounting write.
4. Acknowledge hardware withdrawal before closing the lease or reclaiming IDs
   and NAT/path resources. A separate controller watchdog must withdraw traffic
   if the accounting process dies. Closing a descriptor does **not** remove FE100
   entries. Policy/route mutations must be ordered behind acknowledged withdrawal;
   mark/label checks alone are not an atomic policy-revocation mechanism.

There is deliberately no autoload or production-enable service here.

## Build and verification

```sh
make KDIR=/path/to/exact/prepared/kernel
make client
# Module must match the running kernel; requires root, iproute2, nftables, Python.
make test
```

For OCTEON, build with the exact appliance kernel's `ARCH=mips` and
`CROSS_COMPILE` settings, then cross-compile the client with the MIPS64 big-endian
compiler. Never load a module built against a different kernel release/config.

`test-kernel.sh` refuses an already loaded module, creates a disposable network
namespace without connected interfaces, creates only test conntrack objects,
and removes the namespace/module afterward. Tests cover identity rejection,
delete/recreate, expiry, replay/gaps, duplicate ownership, label/mark changes,
namespace crossing, byte accounting, reason-without-activity, and timeout bounds,
on a UDP object and again on an established TCP object, plus TCP's liberal
windows, established-only binding and FIN/RST invalidation. The UDP suite passed
on Linux 6.8 and the PA-5220's Linux 6.18.49 MIPS64 kernel; the CI `integration`
job runs the whole suite against the runner's kernel on every change.
These are lifecycle tests, not production forwarding qualification.
