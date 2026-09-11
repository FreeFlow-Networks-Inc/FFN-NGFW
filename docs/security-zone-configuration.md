# Security-zone configuration workflow

Network > Zones reads its interface choices from the zone API, independently of
whether the Interfaces page has been opened. Candidate and running views are
separate; running is read-only. The editor retains existing unresolved members,
log settings and unrelated imported zone fields. Type changes replace the old
network type rather than leaving two types in XML.

Zone writes require administrator permissions, the current candidate revision,
and an available configuration lock. Validation rejects duplicate names,
incorrect interface types, duplicate/cross-zone membership and interface
ownership in another virtual system. Policy references block zone deletion.
Errors preserve the editor. No request commits configuration automatically.

The API accepts POST/PUT bodies with a required revision from GET, and DELETE
requires the same revision query parameter. Older clients must refresh their
zone inventory and supply that revision. The URL family remains
/api/vsys/{vsys}/zones. GET additionally accepts source=candidate or running.

Current limitation: configd's ZoneApplier records/skips zone reconciliation;
it does not program zone-based policy enforcement. The UI explicitly reports
this. User-ID and profile references are stored configuration, not a claim of
active dataplane enforcement. External/tunnel zone membership editing is not
implemented. This does not add full PAN-OS feature parity.

Validation: eight tests execute the actual manager route functions against an
isolated configuration manager; they cover permissions, locks, conflicts,
create/update/delete, field preservation, source views, membership and policy
references. Console tests cover direct zone entry, choice loading, escaping and
failure states. Browser fixture review verifies the table and populated editor.

Commit feedback now keeps skipped configd settings visible and does not report
unconditional apply success when any setting was skipped. Image verification
also requires the zone backend module and shared console stylesheet.
