# FFN Protect gateway

Remote-access VPN on FFN that real GlobalProtect clients can use, and in a
later phase PAN-OS satellite firewalls. Own code throughout: the client
protocol is implemented from its public description (the OpenConnect project
documents the endpoints, the XML bodies, the ESP keying and the SSL-tunnel
framing from the client side); no vendor binary, package or file is involved.
PAN-OS portal and gateway configuration maps onto FFN's `global-protect`
configuration nodes so an existing PAN-OS deployment can be re-pointed.

## Where it runs

Everything that touches packets runs on the dataplane in the forwarding
namespace, on the WAN interface addresses the configuration names:

| Part | Language | Role |
| --- | --- | --- |
| `opt/ffn_protect_gateway.py` (installed as `/usr/local/lib/ffn/ffn_protect_gateway.py`, unit `ffn-protect-gateway.service`) | Python, standard library only (the DP has no crypto module) | portal and gateway HTTPS endpoints, authentication, sessions, IP pool, HIP, the SSL-tunnel framing, and the C worker's control socket |
| `ffn-protect-tunnel` (`octeon/native/ffn_protect_tunnel.c` in the platform repository) | C with the DP's OpenSSL 3 | owns the tunnel device, terminates ESP-in-UDP on 4501 for every session (AES-128/256-CBC, HMAC-SHA1-96, a 64-entry anti-replay window, per-direction keys, NAT traversal), and moves packets for SSL-tunnel sessions to and from the Python side over socket pairs |

One gateway owns one tunnel device, named exactly as the configured tunnel
unit (`tunnel.1`), so the security policy zones it like any other interface:
the gateway publishes an owner row (`/run/ffn-protect-<gateway>-status.json`,
refreshed every second) that the platform's binding discovery reads
(`protect_bindings` in `ffn_platform_policy_bindings.py`), and the compiled
policy addresses the device by that name. ESP and SSL sessions share the
device, which is why ESP is terminated by the worker rather than by the
kernel: a kernel XFRM interface could not carry the SSL sessions, and two
devices per logical interface would have changed every consumer of the
bindings. The tunnel device appears once, when the daemon starts the
gateway, and survives reloads; the policy replays once when the binding
appears.

The kernel answers the client's keepalive probes (an ICMP echo to the
gateway's tunnel address) because the tunnel device carries that address;
nothing special is needed for them.

## Protocol, as served

Portal (`/global-protect/`): `prelogin.esp` announces the authentication
method; `getconfig.esp` authenticates and returns the agent configuration
(`<policy>`: gateway list with priorities, the trusted root certificates to
install, agent settings) and the portal user cookie, which later gateway
logins accept in place of the password. Gateway (`/ssl-vpn/`): `login.esp`
authenticates and returns the auth cookie in the positional `<jnlp>`
argument list the clients index; `getconfig.esp` assigns the tunnel address,
DNS, split-tunnel routes and the ESP parameters (SPIs, keys, algorithms, UDP
port 4501); `hipreportcheck.esp` and `hipreport.esp` take the host
information report when the gateway asks for one; `logout.esp` ends the
session. `GET /ssl-tunnel-connect.sslvpn` with the auth cookie upgrades the
connection to the SSL tunnel: the gateway answers with the twelve raw bytes
`START_TUNNEL`, after which each packet is a 16-byte header (magic
`0x1a2b3c4d`, ethertype, length, a fixed trailer) followed by the IP packet,
in both directions; a frame with ethertype 0 is a keepalive and is echoed.

ESP: standard RFC 4303 ESP carried in UDP 4501, no IKE: the gateway
generates the SPIs and distinct keys per direction in `getconfig.esp`.
Offered algorithms are `aes-128-cbc` and `aes-256-cbc` with `sha1` (96-bit
ICV), which every GlobalProtect client and OpenConnect accept; a client that
offers neither gets the SSL tunnel only. The worker learns the client's
public address and port from the first authenticated packet, so clients
behind NAT work, and it ignores the one-byte NAT keepalives.

Authentication backends, selected per portal and gateway by an
authentication profile: local users (PBKDF2-SHA256 hashes compiled into the
intent, never plain), LDAP simple bind as the user over TLS (an own BER
encoder for the bind request, a bind DN template instead of a stored service
account), RADIUS PAP, and in phase 2 SAML. Failed attempts are limited per
source address and per user (ten in five minutes). Login refusals go to the
daemon's journal with the user name and source, never the password.

## Configuration

FFN-native schema in PAN-OS shape:

```
vsys/entry/global-protect/global-protect-portal/entry[@name]
  portal-config/local-address/{interface, ip/ipv4}   (a layer3 dataplane interface and one of its static addresses)
  portal-config/certificate                          (shared/certificate name)
  portal-config/client-auth/entry/authentication-profile
  portal-config/login-lifetime                       (seconds)
  client-config/connect-method                       user-logon | on-demand | pre-logon
  client-config/gateways/external/list/entry[@name=host]/{priority, description}
  client-config/root-ca/member                       (certificates the agent installs)
vsys/entry/global-protect/global-protect-gateway/entry[@name]
  local-address/{interface, ip/ipv4}, certificate, client-auth/entry/authentication-profile
  tunnel-interface                                   (a tunnel unit; its first IPv4 address is the gateway's)
  remote-user-tunnel-configs/entry/{ip-pool/member, dns/member, dns-suffix/member,
                                    split-tunneling/{access-route, exclude-access-route}/member}
  ipsec-crypto  aes-128-cbc | aes-256-cbc | none (SSL only)
  idle-timeout, login-lifetime (seconds), mtu, hip-collection yes|no
shared/certificate/entry[@name]/{public-key, private-key, chain}
shared/authentication-profile/entry[@name]/method/{local-database | ldap/server-profile | radius/server-profile}, allow-list/member
shared/server-profile/ldap/entry[@name]/{server/entry/{address,port}, ssl, verify-server-certificate, bind-dn-template, ca, timeout}
shared/server-profile/radius/entry[@name]/{server/entry/{ip-address,port}, secret, timeout}
shared/local-user-database/user/entry[@name]/phash
network/interface/tunnel/entry[@name='tunnel']/units/entry[@name='tunnel.N']/ip/entry[@name='a.b.c.d/n']
```

The console pages (FFN Protect > Portals, Gateways) edit all of it through
`/api/config/protect/...` (`opt/ffn_config_protect.py`): the gateway editor
creates the tunnel unit with the gateway, certificates are uploaded as PEM
or generated self-signed, local users are hashed on save. Private keys,
hashes and shared secrets live in the candidate configuration and are
reported by the API only as present.

Two more things the operator sets:

- The WAN interface's **interface management profile** must permit the
  `FFN Protect` service (443/tcp and 4501/udp to the interface's addresses);
  the per-device input table on the dataplane drops everything else to the
  box. The dataplane's interface relay, which serves permitted management
  ports on interface addresses, leaves the pairs the committed Protect intent
  claims to the daemon (`protect_listeners` in `ffn_interface_services.py`).
- The tunnel unit goes into a **zone** on the Zones page; security rules
  between that zone and the others decide what remote users reach, and NAT
  rules whether they leave through the WAN.

The commit path compiles the tree (`opt/ffn_protect_intent.py`) to
`/etc/ffn/protect.json` on the DP through the platform's `protect` plane
resource (status, validate, apply; `reconcile_protect` in the platform
applier), the same path the DHCP server uses; the readback compares digests
so the secrets never travel back. The daemon reloads on SIGHUP, keeps
sessions on gateways whose data-path settings did not change, and reports
every listener, gateway and session in `/run/ffn-protect/status.json`, which
`protect status` returns redacted. The convergence check `protect-gateway`
compares the committed tree with the applied digest and the daemon's
listeners and gateways; alerts follow from it.

## Tests

- `tests/test_protect_gateway.py`: credentials, BER and the directory bind
  against a fake on the loopback, RADIUS PAP against a fake, the limits, the
  pool, the tunnel framing, the XML the clients index, the intent rules.
- `tests/test_protect_intent.py`: tree to intent, faults per entry.
- `tests/test_protect_ui.cjs`: the console pages and editors.
- `tests/integration/protect-openconnect.sh`: a real client (OpenConnect,
  `--protocol=gp`) in network namespaces on a Linux host: portal, login,
  ESP tunnel and the SSL fallback, with pings through the tunnel.
- platform: `make test` in `octeon/native` runs the worker's ESP unit test;
  `test_policy_bindings.py` covers the tunnel binding.

## Phases

1. Client protocol: portal, gateway, ESP and SSL tunnels, local/LDAP/RADIUS
   authentication, HIP accepted and recorded, console pages and status,
   convergence. Verified with OpenConnect, then with the GlobalProtect agent
   against the appliance.
2. SAML single sign-on for the portal and gateway (the portal is the
   service provider: `prelogin.esp` returns the request, the IdP posts the
   assertion to `/SAML20/SP/ACS`, the assertion's XML signature is verified
   with the DP's `openssl` tool after exclusive canonicalisation, and the
   client receives its prelogin cookie).
3. Satellite firewalls (large-scale VPN): the portal enrolment and
   certificate issuance the PAN-OS satellite daemon expects, then IPsec with
   certificates and route publication to the satellites. The satellite side
   of the protocol is not publicly documented; it is established from the
   behaviour of a PAN-OS satellite and the clone on the RE VM before any
   code is written.

## Limits in phase 1

No clientless VPN, no MDM, no IPv6 tunnel addresses, no client certificate
authentication, single-threaded worker (adequate for tens of users; the C
data path is where throughput work goes next). A worker restart drops its
sessions; clients reconnect with their still-valid cookies.
