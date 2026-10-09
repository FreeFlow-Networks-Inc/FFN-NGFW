# DHCP server on selected interfaces

The appliance serves DHCPv4 on the routed interfaces the operator selects.
The configuration is PAN-OS-shaped and lives in the candidate like every
other network setting; a commit carries it to the dataplane, which serves it
from the interface's own address. Nothing is served until a commit.

## Configuration

Network > DHCP in the console, or the API behind it:

| Endpoint | Purpose |
| --- | --- |
| `GET /api/config/dhcp?source=candidate` | servers in the candidate, with the layer3 interfaces that can host one |
| `PUT /api/config/dhcp` | add or replace the server on one interface (revision-checked) |
| `DELETE /api/config/dhcp/{interface}?revision=` | remove it |
| `GET /api/dhcp/status` | the committed servers joined with the dataplane daemon's view and leases |

The XML, under `devices/entry/network`:

```xml
<dhcp><interface><entry name="ae1.69"><server>
  <mode>enabled</mode><probe-ip>no</probe-ip>
  <ip-pool><member>10.1.0.100-10.1.0.199</member></ip-pool>
  <reserved><entry name="10.1.0.50"><mac>02:11:22:33:44:99</mac><description>printer</description></entry></reserved>
  <option>
    <lease><timeout>1440</timeout></lease>            <!-- minutes, or <unlimited/> -->
    <dns><primary>1.1.1.1</primary><secondary>8.8.8.8</secondary></dns>
    <dns-suffix>lan</dns-suffix>                      <!-- gateway, subnet-mask, ntp, wins likewise -->
  </option>
</server></entry></interface></dhcp>
```

Rules, checked when the candidate is saved and again by the dataplane:

* the interface is `ethernet1/N`, `aeN` or a subinterface of one, layer3, with
  a static IPv4 address; the first address is the server address and its
  network bounds every pool and reservation. A DHCP-client interface cannot
  serve;
* pools are first-last ranges (or single addresses) inside that network, not
  overlapping and not containing the interface address, at most 65536
  addresses; reservations are unique MAC-to-address pairs in the network;
* the lease is 1 to 1,000,000 minutes or unlimited; gateway and mask default
  to the interface address and prefix; DNS, NTP and WINS take up to two
  addresses each; `probe-ip` ARPs for an address before offering it.

## How it reaches the dataplane

`opt/ffn_dhcp_intent.py` compiles the committed tree into one intent per
dataplane device (`ethernet1/5` is `p5`, `ae1.69` keeps its name). The
platform provider that configd runs on every commit and on boot
(`configd_applier.reconcile_dhcp` on the PA-5200) sends it through the `dhcp`
plane resource, revision-fenced like the network patches, and reads it back.
The dataplane keeps the applied intent at `/etc/ffn/dhcp-server.json`.

`opt/ffn_dhcp_server.py` is the daemon (`ffn-dhcp-server.service`, in the
`ffn-data` namespace). One instance per device, from a raw socket filtered in
the kernel to UDP/67 (and ARP replies while probing): the server sees clients
before the per-interface management tables, which gate only the host's own
services, and answers clients that have no address yet by building the frame
itself. Replies follow RFC 2131 section 4.1 (unicast to `ciaddr`, broadcast
when the client asks, otherwise unicast to the client's MAC); INIT-REBOOT,
renew, rebind, decline, release and inform are handled; relayed requests
(`giaddr`) are counted and ignored, since the server is authoritative for its
own subnet only. Leases persist in `/var/lib/ffn/dhcp-server/<device>.json`;
the daemon's view is published at `/run/ffn-dhcp-server/status.json`, which
is what the console and the convergence check (`dhcp-server` subsystem) read.

The daemon's own validation is the configuration module's validation: a
candidate that saves is an intent that applies.

## Operating it

```sh
# on the dataplane
python3 /usr/local/lib/ffn/ffn_dhcp_server.py status        # applied intent, daemon view, leases
systemctl reload ffn-dhcp-server.service                     # re-read the intent (the apply does this)
# on the MP
ffn-dhcp status                                              # the same, over the management connection
ffn-convergence                                              # dhcp-server: serving / pending / drift
```

A server that is committed but reads `interface-absent` or `address-missing`
on the dataplane is pending: the device or its address has not appeared yet
(an aggregate's subinterface after boot, an interface being re-addressed).
