# Security rule configuration

Policies > Security edits candidate XML through `ffn-controld`. OK stages an
edit; Cancel discards the dialog changes; Commit validates activation. FFN-CLI
uses the same API, schema, object choices and validation. New rules are disabled.

The editor includes Name, Description, Tags, Universal/Intrazone/Interzone type,
source zones/addresses/users/devices, destination zones/addresses/devices,
applications, services, action, profiles, logging and read-only usage.

Actions are Allow, Deny, Drop, Reset Client, Reset Server and Reset Both Client
and Server. Send ICMP Unreachable is available for blocking actions and is
rejected with Allow. Intrazone rules select the source zone and leave destination
zone as `any`; the rule type specifies same-zone matching.

## Profiles and logging

`profile-mode` selects `none`, `group` or `profiles`. It is an API/editor selector,
inferred from XML rather than persisted as an extra XML node. Group and individual
profiles are mutually exclusive. Choosing None removes assignments on OK.
Switching modes within an open dialog retains values until OK or Cancel.

| Settings key | XML path below the rule | Definition inventory |
| --- | --- | --- |
| `profile-group` | `profile-setting/group/member` | `profile-group` |
| `antivirus` | `profile-setting/profiles/virus/member` | `profiles/virus` |
| `vulnerability` | `profile-setting/profiles/vulnerability/member` | `profiles/vulnerability` |
| `anti-spyware` | `profile-setting/profiles/spyware/member` | `profiles/spyware` |
| `url-filtering` | `profile-setting/profiles/url-filtering/member` | `profiles/url-filtering` |
| `file-blocking` | `profile-setting/profiles/file-blocking/member` | `profiles/file-blocking` |
| `data-filtering` | `profile-setting/profiles/data-filtering/member` | `profiles/data-filtering` |
| `crucible-analysis` | `profile-setting/profiles/crucible-analysis/member` | `profiles/crucible-analysis` |
| `log-setting` | `log-setting` | `log-settings/profiles` |

Selectors discover named definitions in the selected virtual system and shared
configuration. Unknown references are rejected. Profile definitions must already
exist; assigning a profile does not provision or commission its engine. Earlier
FFN scalar group assignments remain readable/editable and are upgraded to member
XML on an explicit edit. Unsupported imported structures remain read only.

`log-start` and `log-end` choose session-start and session-end logging. `log-setting`
selects the log forwarding profile; an empty value means none. `source-device`
and `destination-device` reference Objects > Devices; `source-user` accepts user
matching values. These matches require the relevant runtime identity services.

## Usage and activation

Hit Count, Last Hit and First Hit are read only. The current XML Security provider
is not commissioned, so usage is explicitly unavailable, with null API values.
Stored legacy SQL counters have no verified dataplane observation identity or
timestamp and are not displayed as live measurements. Usage is not written to
candidate XML or copied on clone.

The unified list retains legacy fast-path rules and immutable implicit defaults.
Legacy rules keep their existing limited editor and enforcement path. New XML
rules support the complete configuration above, but enabling them still blocks
Commit until the Security compiler and acknowledged dataplane apply are
commissioned. Saving settings does not claim enforcement of profiles, identity,
logging or reset/ICMP behavior.

Use `show policies security` to inspect the schema and revision. Create/update
through `request policies security <create|update> <JSON>` with `revision` and a
`rule` containing `name`, `description`, `enabled`, and `settings`. Usage fields
are rejected in mutation payloads. Configuration remains unchanged on validation
failure or a stale revision.
