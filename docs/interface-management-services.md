# Interface management service access

An interface management profile applies to traffic addressed to that interface,
independently of its transit zone and security policy. Saving a profile or binding
stages the candidate; Commit applies its nftables INPUT filter and publishes the
applied service permissions. No profile means no management services. Permitted
IP prefixes apply to both the filter and service relay. Ping remains local.

On appliances with a separate management plane, `ffn-interface-services` binds
TCP/UDP listeners to the applied interface addresses and devices in `ffn-data`.
It relays allowed requests through a root-only Unix socket provided by the
platform's authenticated transport. PA5200 uses an MP-supervised, host-key-pinned
SSH reverse socket through the commissioned CP/DP channel. It reconnects after
transport or processor restart. It does not route transit traffic through the MP.

HTTPS/TLS and SSH bytes pass unchanged to the existing MP services; normal
authentication remains required. The MP application sees a loopback connection;
the DP service status records the last client source. This is not a replacement
for source-preserving access logs. Removing a service, address or profile, or
changing permitted sources, closes its active sessions within the one-second
reconciliation interval; new requests recheck applied permissions immediately.

The default HTTPS provider is the FFN listener on loopback port 8443, exposed on
profile ports 443 and 8443. Other services use their conventional MP loopback
ports. `/etc/ffn/interface-services.json` may override or disable providers:

```json
{"tcp/443":{"host":"127.0.0.1","port":8443},"tcp/23":null}
```

Only known profile services and loopback destinations are accepted. TCP and UDP
requests are bounded to 256 concurrent operations. UDP replies are associated
with the originating client; the relay waits up to three seconds for a response.
Enabling SNMP, User-ID or response pages does not create those service backends.
Their daemons and their own application configuration must also be enabled.

Network > Network Profiles > Interface Management shows applied listener and
provider availability on supported appliances. `show platform interface-services`
reads the same observations through the console control daemon. A listening MP
socket is readiness evidence, not proof of application authentication or a
successful SNMP response. Status is boot-fenced and marked stale after ten seconds.

The image overlay includes the frontend, profile enforcement and service unit.
The PA5200 control-channel installer provisions the MP tunnel using the existing
plane-agent credential; no customer address or credential is embedded in code.
Before reconnecting SSH, the tunnel removes a stale, owned Unix socket only
after confirming that no listener accepts connections. Active listeners,
non-socket paths and symlinks are preserved. This allows a control-daemon restart
to restore interface management access without restarting the dataplane.
For live upgrades, the platform also reads boot-qualified, acknowledged aggregate
runtime profiles, allowing profile changes without restarting the LACP worker.
Rollout must deploy all static assets referenced by `index.html` as one set.

Run `sudo python3 tests/test_interface_services.py` on Linux for isolated TCP/UDP,
source restriction, permission revocation and transport failure tests. These
tests create and remove their own network namespace and never use `ffn-data`.
