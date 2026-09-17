# VLAN subinterface configuration

Network > Interfaces now offers Edit for VLAN subinterfaces, in addition to Add
and Delete. Interface IDs (1–9999) are separate from VLAN tags (1–4094). A parent
must already be configured as Layer 2 or Layer 3; the child inherits that mode.
The movable editor has Configuration, IPv4, IPv6 and Advanced tabs for Layer 3.
Each address has its own add/remove row; validation brings hidden invalid fields
into view. Advanced settings include an optional MTU and a candidate management
profile selector. Configuration includes comment, security zone and virtual
router. Layer 2 offers its compatible zone and VLAN membership instead.
Virtual-system scope follows the selected interface and appears in the heading.
Mode, physical link state and speed follow the parent.

OK replaces managed fields and memberships in one candidate XML save, including
removing old addresses and cleared optional values, then closes the editor and
refreshes the pending-commit indicator. Cancel makes no writes. Failed or stale
saves retain the form and its edits. Existing TCP MSS settings are preserved.
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

Listing includes mode-compatible zone, virtual-router, VLAN and management
profile choices from the same XML snapshot/revision as the interface. Optional
`zone`, `virtual_router` and `vlan` fields preserve membership when omitted;
an empty string clears it. Unknown or incompatible selections are rejected
without saving any part of the request. Existing unresolved management profiles
can be retained or cleared, but cannot be newly assigned. Duplicate router/zone
memberships require repair before editing. Unrelated object settings survive.
Router selection here stages XML membership; it does not write the legacy SQL
router store or call the immediate router APIs.

No operation automatically commits or changes live forwarding. The generic
configd has Linux subinterface handling, but PA-5220 platform reconciliation
does not yet implement physical faceplate VLAN subinterfaces. Hardware apply
results must be checked in Tasks; this update does not claim PA-5220 VLAN
forwarding is operational.

Validation: `tests/test_config_subinterfaces.py` covers candidate-only edits,
membership validation and preservation, permissions, locks and revision checks.
`tests/test_subinterface_browser.cjs` covers tabs, address rows, atomic request
payloads, read-only controls, hidden-field validation, Cancel and retained edits
after a rejected save. Deployment verifies candidate/running API reads and
served frontend assets without committing or modifying appliance configuration.
