# PAN-OS 12.1 frontend alignment

The FFN console now uses a compact light shell, separate header and tab strip,
Dashboard / ACC / Monitor / Policies / Objects / Network / Device tab order,
left navigation tree, bordered tables, compact forms, and shared dialog styling.
Selected hardware extensions inherit these styles through the existing CSS
variables and shared components. FFN branding remains explicit.

The Interfaces page puts configuration first, with expandable hardware inventory
and kernel aggregate diagnostics. Config History and Tasks live in the footer.
Tasks reads /api/config/apply-status and preserves partial failures, per-setting
errors, validation failures, and missing-state errors. Commit confirmation only
reports successful application when configd returns applied without errors.
A saved XML version alone is not treated as successful runtime application.

Reference: https://docs.paloaltonetworks.com/ngfw/help/12-1/web-interface-basics
Reference: https://docs.paloaltonetworks.com/ngfw/help/12-1/web-interface-basics/commit-changes

This is frontend alignment, not a claim of pixel-exact reproduction or PAN-OS
feature parity. Exact comparison still needs reference screenshots from the
requested 12.1 build. Existing backend capability gates and unsupported-state
messages are retained. Task Manager exposes the latest configd run; it is not
an archive of all daemon jobs.

Verification: full console script execution, navigation, hardware and extension
renderer regressions, patch and plane UI tests, task error/escaping tests, commit
partial-failure handling, and browser review of Device, Interfaces, and Tasks.

## Setup and interface workflows

Device > Setup groups Management (hostname/timezone), Services (DNS/NTP), and
Operations (existing configuration/snapshot actions). In-page tab changes retain
unsaved field values. The redundant Configuration & Backups sidebar entry is
removed; its existing direct route remains available. Tabs support arrow keys,
Home/End, accessible names and selected states.

The interface dialog separates Config from Advanced link/LLDP settings, keeps
field values when switching tabs, and uses one action row. Saving leaves success
or failure visible. Unchanged virtual-router membership does not trigger a write;
failed inventory lookup disables membership editing. A virtual-router write
failure after a candidate save is explicitly partial, preserves the original
assignment baseline, and remains retryable. Concurrent duplicate saves are
blocked while the request is pending. VR assignments still use the existing
immediate runtime API; the interface candidate itself requires commit.

Verified with fixture browser interactions and regressions for retained edits,
unchanged VR writes, partial save failure, and candidate/commit state reporting.
The appliance deployment changes static frontend files only; no configuration
commit, service restart, or reboot is performed.
