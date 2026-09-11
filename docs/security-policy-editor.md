# Security-policy editor improvements

The policy editor preserves name, interface constraints, virtual-system ID and
enabled state. Rules can be cloned (clones start disabled), filtered, enabled,
disabled and edited. Immutable defaults expose description editing only. Failed
writes retain the dialog and its input. API writes require administrator role.
Source/destination zone and application controls that never submitted data are
removed; the table now shows the stored interface conditions and tenant ID.

These rules use the existing policy database, not candidate XML. Saving or
cloning a rule is not proof of dataplane application. This change does not add
zone-aware or application-aware enforcement.

Validation rejects malformed IPs, invalid protocols, port ranges and actions.
The fast-path compiler validates every enabled rule before writing its output.
IPv6, interface constraints and Reset have no equivalent in its current binary
format, so those conditions stop compilation instead of being silently widened
or treated as Allow. A rejected compile leaves the prior binary in place.
Disabled rules remain excluded. Stored unsupported conditions can be inspected
and disabled; they must be resolved before a successful fast-path compile.

Verification: six isolated API/compiler tests cover persistence, permissions,
immutable rules, malformed conditions and preserving the compiled binary on
failure; UI tests cover escaped rows, field preservation, disabled cloning and
failed saves. Browser fixture review verifies the rule table and clone dialog.
The appliance deployment reads the authenticated API and checks existing rule
compatibility; it does not change rules, compile a policy or commit config.
