# Policies workspace and shared control contract

Policies contains Security, NAT, QoS, Policy Based Forwarding, Decryption,
Tunnel Inspection, Application Override, Authentication, DoS Protection and
SD-WAN. All ten have tabbed editors, scoped candidate/running views, search,
clone, move, enable/disable and delete. Configured object, zone, interface and
profile choices are resolved from the same XML used by Objects and Network.

## One owner for new XML rule operations

WebUI and authenticated FFN-CLI use `/api/config/policies/{kind}`. The manager
checks administrator privileges and its configuration lock, then calls
`policy/request` on controld. `PolicyController` validates the revision,
fields and references and atomically replaces candidate XML. An unavailable
daemon returns an error; the API never writes a fallback database.

Rules live under the local device's `vsys/entry/rulebase/{kind}/rules`.
Reordering changes the actual XML entry order. ConfigManager diff includes
rule order, so a move alone is a pending change and can be committed.

CLI examples:

```
show policies security vsys1 candidate
show policies nat vsys1 running
show policies status candidate
request policies security toggle '{"revision":"<revision-from-show>","name":"branch-rule","enabled":false}' vsys1
request policies security move '{"revision":"<revision-from-show>","name":"branch-rule","position":1}' vsys1
```

`create` and `update` take a `rule` containing `name`, `description`, `enabled`
and typed `settings`. `show policies <kind>` returns the schema, available
references and revision. New and cloned rules start disabled in the WebUI.
Use the existing CLI `commit` or WebUI Commit after reviewing changes.

## Activation is deliberately separate from storage

NAT has a compiler and an opt-in, commissioned nftables runtime provider.
QoS, PBF and Decryption have resolved policy previews and packet-match tests;
their enforcement engines are not yet connected. See [policy planning](policy-planning.md)
for their capabilities, CLI commands and runtime requirements. Enabled XML rules
without a commissioned provider are **blocked at commit**, including rules
imported by generic CLI/API config operations.
ConfigManager validates the effective full or partial commit before replacing
running XML. Configd validates again before any local or platform side effect;
its dry-run mode uses the same guard. The UI and CLI display the same blockers
from controld and never report a stored rule as dataplane-applied.

Disabled definitions may be stored and committed. **Policies > Security** shows
XML and SQL fast-path rules in one table, with Policy Source identifying their
storage. The candidate/running selector applies to XML; fast-path rows show
stored SQL policy in both views and are read only in the running view. This is
an inventory, not a combined execution order: each compiler retains its own
ordering. Same-named rows in different stores remain distinct. No rules are
migrated, cleared, or applied by combining the display.
Implicit defaults are always visible, including during searches, and all fields
are read only. Their API protection includes descriptions and default entries
imported into XML. Virtual-system filtering retains global system defaults.
The existing DoS engine controls remain accessible separately. Full control
unification still requires migration of that SQL rulebase plus commissioned
runtime compilers and CP/DP acknowledgments for each policy kind.

Imported rules with unknown XML fields are read only. Edits cannot silently
discard them. Profile-dependent policy types require existing configured
profiles; this change does not invent placeholder profiles or a vendor App-ID
dictionary.

## Installation and tests

`python image/install-policies-ui.py` narrowly merges the manager, controld,
configd, CLI and frontend and retains a timestamped code backup. It does not
commit configurations or restart services. Validate the existing running policy
report before restarting controld, configd and manager. No reboot or BCM/CP/DP
restart is required.

Run `tests/test_policy_config.py`, `tests/test_partial_commit.py`,
`tests/test_policy_barrier.py`, and `tests/test_control_gateway.py` with the
runtime Python dependencies. `node tests/test_policies_browser.cjs` uses a
loopback fixture and Playwright to exercise all ten policy editors against the
real controller and API. It accepts the same `TEST_PYTHON`, `TEST_BROWSER` and
optional `TEST_SCREENSHOT` overrides as the Objects browser tests.

Reference: [PAN-OS 12.1 Policies help](https://docs.paloaltonetworks.com/ngfw/help/12-1/policies).
