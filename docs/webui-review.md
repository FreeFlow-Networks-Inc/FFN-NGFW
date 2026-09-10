# WebUI review and reorganization

This review covers the top navigation, sidebar destinations, renderer dispatch,
inline controls, configuration workflows, runtime dashboards, and shared resource
editors in `static/index.html`. Source inspection is broader than functional
validation: the tests below exercise the changed workflows, not every feature on
a running firewall.

## Changes

| Area | Finding | Result |
| --- | --- | --- |
| Navigation | Duplicate ACC definition, software destinations, and colliding policy/network QoS IDs | One menu owner per destination; distinct QoS route; legacy software/QoS/log-settings links resolve to their canonical pages |
| Navigation | Long flat menus, non-keyboard sidebar items | Search across all tabs, collapsible sections, native buttons, visible focus, active-page semantics, last-page memory per tab |
| Layout | Narrow windows clipped the header and main content | Wrapped top navigation, bounded content, responsive grids, scrolling tables |
| Dashboard | Heatmap repeated the detailed DDoS page; charts retained old canvases | Summary links to detail; destroy charts when navigating; throughput view fetches only throughput; late dashboard responses cannot write into another page |
| Hardware | Hardware, health, and offload were split across Dashboard and Device | Device owns hardware inventory, health and runtime. Network owns detected/configured interface ports |
| Initialization | DHCP registration ran before the resource registry existed | Registry initialized before first use; a whole-script regression test detects declaration-order failures |
| General settings | Many fields had no persistence; saving one panel sent empty values for fields on other panels | Five supported fields load from candidate; save sends only changed keys; failed requests retain edits; admin authorization enforced on server |
| Configuration | Operations tab duplicated working commit controls with alert-only buttons and invented snapshot rows | Configuration & Backups uses existing commit/history/lock workflows, real running snapshots, restore-to-candidate, delete and XML export |
| Addresses/services | Fabricated objects and groups; Add Address never saved | Read actual candidate/running XML with shared/vsys scope; explicit read-only view; no invented objects |
| Content | Check Now bumped a local database revision; database actions displayed alerts | Content Status reads actual signature counts/revision; downloads use existing package workflow |
| URL lists | Allow list ignored; additive block entries submitted without awaited results | Remove ignored allow-list field; additive label, sequential requests and partial-failure feedback; require admin and verify durable writes |
| Signatures | Toggle changed appearance only and always appeared enabled | Read-only reported state; missing state says Not reported |
| Resource editors | Arrays/objects bypassed HTML escaping; API failures appeared empty; required fields ignored | Escape all value types, distinguish failure from empty data, validate required fields, check create/update/delete responses |
| Syslog | Duplicate page always said no servers and offered unsaved retention settings | One server-profile editor |
| Support | Fake diagnostic downloads and incorrect issue repository | Link to existing diagnostics/system health and correct repository |
| Incomplete features | NAT/decryption/SD-WAN policy, access-domain, TLS service-profile, master-key and recommendation pages implied implementation | Removed from ordinary navigation; direct routes explicitly report unavailable. Existing runtime features are not disabled |
| ML | Retrain/upload controls reported progress without implementing a usable workflow | Remove these controls; preserve scoring and existing model-update/status workflows |

## Configuration behavior

General Settings reads `GET /api/system/setup`, which returns candidate values.
`POST /api/system/setup` remains a candidate update requiring a separate commit.
Only changed fields are submitted, including an intentional empty field when the
operator clears it. Read failures leave the form disabled.

Snapshots copy the **running** XML. Restore replaces the candidate XML; it does
not apply a configuration or restart any service. The UI confirms replacement of
an existing named snapshot and destructive restore/delete actions. The server
enforces admin/superuser roles for snapshot mutations and rejects restore while
another administrator owns the configuration lock. These are existing file
formats and APIs, with new UI integration and authorization checks.

Generic network-resource definitions are stored in SQLite by the existing API.
Their persistence is not proof that a runtime backend has consumed them. The
editor now says so. It does not label these writes as candidate XML commits.

## Remaining implementation work

1. Implement runtime adapters, validation and applied-state reporting for stored
   network/device resource kinds; persistent CRUD alone must not be marketed as
   active DHCP, VPN, AAA, certificate or policy enforcement.
2. Implement NAT, decryption and SD-WAN policy editing against actual runtime
   backends before restoring their navigation entries.
3. Add validated address/service object editing and verify policy references and
   deletion dependencies before enabling mutation of those objects.
4. Implement real remote signature-feed retrieval/verification, model training,
   manual weight upload and master-key lifecycle before exposing action controls.
5. Replace remaining legacy API helper callers with explicit error states and
   cancel/guard stale responses throughout long-running monitoring pages. The new
   workflows use strict errors; this is not a claim that every legacy page does.
6. Unify resource storage with the candidate/commit model where required and
   audit authorization across legacy mutation routes. This change tightens only
   the mutations it directly exposes or repairs.

## Verification

- Whole-script execution and navigation uniqueness, cross-tab search, aliases,
  per-tab memory, escaping, request errors and partial setup saves in
  `tests/test_console_ui.cjs`.
- Candidate settings round trip, read-only rejection, snapshot lifecycle and
  configuration-lock conflict in `tests/test_console_api.py`, using temporary
  files and database; no live networking actions.
- Existing hardware, patch and extension renderer tests, authentication and
  management security regressions, JavaScript syntax and WebUI audits.
- Browser fixture review of configuration/backups, loaded general settings,
  global search and XML address inventory, including a narrow desktop viewport.
- Publication policy and whitespace checks.

No appliance deployment, packet-forwarding validation or live configuration
commit was performed. This branch builds on the signed patch-management work.

## Current navigation inventory

### Dashboard (4)

Overview (`dash-overview`), Throughput (`dash-throughput`), Sessions (`dash-sessions`), DDoS Heatmap (`dash-ddos`).

### Monitor (5)

Traffic (`traffic`), Threat (`threat`), URL Filtering (`url-filtering`), System (`system-logs`), Session Browser (`session-browser`).

### Acc (4)

ACC Dashboard (`acc-dashboard`), ML Inference (`ml-inference`), Crucible (`crucible`), IoT Devices (`iot-devices`).

### Policy (2)

Security (`security`), DDoS Protection (`ddos-protection`).

### Objects (7)

Addresses (`addresses`), Services (`services`), Applications (`applications`), Threat Signatures (`threat-sigs`), URL Categories (`url-categories`), Databases (`databases`), Security Profiles (`security-profiles`).

### Network (33)

Interfaces (`interfaces`), Zones (`zones`), VLANs (`vlan`), Virtual Wires (`virtual-wires`), Virtual Routers (`routing`), IPSec Tunnels (`ipsec-vpn`), GRE Tunnels (`gre-tunnels`), VXLAN Tunnels (`vxlan-tunnels`), DHCP (`dhcp`), DNS Proxy (`dns-proxy`), Portals (`fp-portals`), Gateways (`fp-gateways`), MDM (`fp-mdm`), Clientless Apps (`fp-clientless-apps`), Clientless App Groups (`fp-clientless-app-groups`), DHCP Profile (`fp-dhcp-profile`), Wireguard (`zt-wireguard`), ZeroTier (`zt-zerotier`), Tailscale (`zt-tailscale`), ZScaler (`zt-zscaler`), QoS & Bandwidth (`network-qos`), LLDP (`lldp`), FFN Protect IPSec Crypto (`np-fp-ipsec-crypto`), IKE Gateways (`np-ike-gateways`), IPSec Crypto (`np-ipsec-crypto`), IKE Crypto (`np-ike-crypto`), Monitor (`np-monitor`), Interface Mgmt (`np-interface-mgmt`), Zone Protection (`np-zone-protection`), QoS Profile (`np-qos-profile`), LLDP Profile (`np-lldp-profile`), BFD Profile (`np-bfd-profile`), SD-WAN Interface Profile (`sdwan-iface-profile`).

### Device (53)

General Settings (`setup`), Configuration & Backups (`config-audit`), Hardware Inventory (`dash-hardware`), System Health (`dash-system`), Dataplane Offload (`dash-offload`), Dataplane & Engines (`dataplane-engines`), High Availability (`ha`), FIPS-CC Mode (`fips-cc`), Password Profiles (`pw-profiles`), Administrators (`administrators`), Admin Roles (`admin-roles`), Authentication Profile (`auth-profile`), Authentication Sequence (`auth-sequence`), User Identification (`user-id`), DHCP Log Ingestion (`iot-dhcp-ingest`), Data Redistribution (`data-redistribution`), Cloud Redistribution (`cloud-redistribution`), Device Quarantine (`device-quarantine`), VM Info Sources (`vm-info-sources`), Vendor Firmware (`vendor-fw`), Troubleshooting (`troubleshooting`), Virtual Systems (`virtual-systems`), Shared Gateways (`shared-gateways`), Certificates (`certificates`), Certificate Profile (`cert-profile`), OCSP Responder (`ocsp`), SCEP (`scep`), SSL Decryption Exclusion (`ssl-exclusion`), SSH Service Profile (`ssh-profile`), Response Pages (`response-pages`), CoPP (`copp`), SNMP Trap (`sp-snmp`), Syslog (`sp-syslog`), Email (`sp-email`), HTTP (`sp-http`), Netflow (`sp-netflow`), RADIUS (`sp-radius`), SCP (`sp-scp`), TACACS+ (`sp-tacacs`), LDAP (`sp-ldap`), Kerberos (`sp-kerberos`), SAML IdP (`sp-saml`), DNS (`sp-dns`), MFA (`sp-mfa`), Users (`local-users`), User Groups (`local-groups`), Scheduled Log Export (`sched-log-export`), Software & Patches (`device-updates`), SSLVPN Client (`sslvpn-client`), Content Status (`dynamic-updates`), Plugins (`plugins`), Licenses (`licenses`), Support (`support`).
