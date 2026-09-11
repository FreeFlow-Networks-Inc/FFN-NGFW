# VLAN subinterface configuration

Network > Interfaces now offers Edit for VLAN subinterfaces, in addition to Add
and Delete. Interface IDs (1–9999) are separate from VLAN tags (1–4094). A parent
must already be configured as Layer 2 or Layer 3; the child inherits that mode.
Layer 3 fields include IPv4/IPv6 CIDRs, MTU, management profile and comment.
Layer 2 editing excludes those Layer 3 fields. A virtual-system selector controls
where the child is imported.

Writes replace managed fields in one candidate XML save, including removing old
addresses and cleared optional values. Existing TCP MSS settings are preserved.
Other unsupported imported settings remain read-only. Administrator permission,
configuration lock, current revision, unique tags and valid address/MTU values
are required. References from zones, virtual routers and other member lists
block deletion. A successful delete also removes the virtual-system import.

API: GET /api/config/subinterfaces?parent=...&vsys=...&source=candidate|running;
POST creates, PUT updates, and DELETE accepts parent, unit, vsys and revision.
POST/PUT bodies require revision, parent, unit, tag and mode. Legacy POST and
DELETE /api/interfaces/subinterface route aliases now use this validated
contract; callers must supply unit and revision. The exact DELETE route is
registered before the generic interface path so it cannot be shadowed.

No operation automatically commits or changes live forwarding. The generic
configd has Linux subinterface handling, but PA-5220 platform reconciliation
does not yet implement physical faceplate VLAN subinterfaces. Hardware apply
results must be checked in Tasks; this update does not claim PA-5220 VLAN
forwarding is operational.

Validation: eight new subinterface API tests plus the existing eight zone tests;
UI regression for independent unit/tag values, update method, retained edits and
stale revision errors; browser fixture review of the populated editor and a
rejected save. Deployment verifies authenticated candidate/running API reads and
served frontend assets without committing or modifying appliance configuration.
