# Service routes and the management interfaces

PAN-OS parity for how the firewall's own traffic leaves the box, on a chassis
whose management plane (MP) is a separate computer from the dataplane (DP).

## The management port (Device > Setup > Interfaces)

The MP's external ports (MGT, HA1-A, HA1-B, AUX-1, AUX-2) are configured
under Device > Setup > Interfaces, PAN-OS style, and nowhere else: address
mode (static, DHCP, disabled), address and gateway, DNS servers, MTU, and for
the MGT port the **permitted services** (HTTPS, SSH, ping, SNMP) and
**permitted source addresses**. The candidate stores them under
`deviceconfig/system/mp-interfaces/entry[@name=MGT]`:

```
mode static|dhcp|disabled, address, gateway, dns/member, mtu, description
services/member      https | ssh | ping | snmp   (MGT only; empty = HTTPS and SSH)
permitted-ip/member  10.0.0.0/8 ...               (MGT only; empty = any source)
```

The platform's `mp-interfaces` resource applies the addressing through
systemd-networkd on commit; the MP host firewall (`ffn_bmfw`, fed by
`ffn_config_bridge`) emits the MGT port's input rule from the permitted
services and sources, replacing the blanket management accept for that
port. With the MGT port on an out-of-band network (DHCP from it), the
management plane reaches DNS, NTP and the update server through MGT, which
is PAN-OS's default.

## Service routes (Device > Setup > Services > Service Route Configuration)

A service route sends one of the firewall's own services through a faceplate
interface with that interface's address instead of through MGT:

| Service | Ports |
| --- | --- |
| dns | udp/53, tcp/53 |
| ntp | udp/123 |
| updates (FFN updates, HTTPS) | tcp/443 |
| email | tcp/25, 465, 587 |
| syslog | udp/514, tcp/514, tcp/6514 |
| ldap | tcp/389, 636 |
| radius | udp/1812, 1813 |
| snmp-trap | udp/162 |

Committed tree (PAN-OS shape): `deviceconfig/system/route/service/entry[@name]/source/{interface, address}`;
`interface` is a layer3 faceplate interface (`ethernet1/N`, `aeN`,
subinterfaces), `address` one of its static IPv4 addresses (default: the
first). `opt/ffn_service_routes.py` compiles the tree, validates it with the
dataplane's own rules, and installs it.

### The path a routed service takes

```
MP  127.1.1.1 ffnnet0 --PCIe--> CP 127.1.1.2 / 127.1.2.1 ffndp0 --PCIe--> DP root 127.1.2.2
    ip rule: ipproto/dport -> table 100 (default via the CP)      CP: ffn-service-route-forward.service
                                                                   forwards 127.1.1.1's traffic to the DP
DP root: ip rule from 127.1.1.1 iif ffndp0 -> table 100 (default via svcrt1)
         veth svcrt0 127.1.3.1 <-> svcrt1 127.1.3.2 (forwarding namespace)
ffn-data: ip rule from 127.1.1.1 ipproto/dport -> table per egress interface (default via that interface's gateway)
          nft ip ffn_service_routes postrouting: ip saddr 127.1.1.1 oifname <dev> snat to <address>
          security policy: traffic on svcrt1 from 127.1.1.1 is granted both ways (firewall-originated)
          replies: 127.1.1.0/24 via svcrt0 -> DP root -> 127.1.1.0/24 via the CP -> MP
```

Only the configured ports are routed; everything else the MP sends keeps
using MGT. The exemption in the security policy is the same treatment
PAN-OS gives MP service traffic: it is not transit and no rule is needed.

### Pieces

- `opt/ffn_service_routes.py`: tree compile (`compile_intent`), intent rules
  (`validate_intent`), the DP installer (`apply`, `boot`, `status`), the MP
  rules (`mp-apply`, `mp-status`, `mp-boot`).
- `opt/ffn_config_service_routes.py`, `static/service-routes.js`: console
  API and card.
- `opt/ffn_security_nft.py` + `opt/ffn_security_runtime.py`: the host-link
  exemption, read from `/run/ffn-service-routes/status.json`; a change in it
  replays the policy at once.
- Units: `systemd/ffn-service-routes.service` (DP, re-installs the stored
  intent after a boot or a network-owner restart), `image/ffn-service-routes-mp.service`
  (MP, re-installs the MP rules), and the platform's
  `ffn-service-route-forward.service` (CP forwarding).
- Platform (`ffn-platform-pa5200`): the `service-routes` plane resource
  (status/validate/apply on both MP and DP), `reconcile_service_routes` in
  the applier, the CP unit, overlay and image entries.
- Convergence subsystem `service-routes`.

## Limits

IPv4 only. Service routes do not move the console's own listener; the
manager still answers on the management interfaces and on data interfaces
whose management profile permits HTTPS. The internal path shares the PCIe
transport with the control channel; routed services are management
traffic, not bulk transfer.
