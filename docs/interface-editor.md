# Physical and aggregate interface editor

Network > Interfaces uses the same movable, tabbed editor layout as subinterfaces.
Configuration contains the interface type, comment, compatible security zone,
virtual router or Layer 2 VLAN, aggregate membership and aggregate bond options.
IPv4 contains static address rows or DHCP client settings, including the default
route metric. IPv6 has separate static address rows. Advanced contains MTU,
management profile, physical speed/duplex, admin state and LLDP options.
Aggregate speed and duplex are configured on its physical members.

The new GET/PUT `/api/config/interfaces` API loads the interface and choices from
one candidate XML snapshot. PUT requires its revision and administrator access,
honors configuration locks, validates references and addresses, and performs one
candidate save. OK closes after confirmation and refreshes the Commit indicator.
Cancel makes no writes; failed requests keep the edits for review. The editor
does not call immediate virtual-router, link-control or commit APIs. Named router
choices use candidate XML; the legacy SQL router store remains separate.

Parent edits preserve subinterface units, TCP MSS, LACP and other unedited XML.
Mode changes are rejected if they would discard subinterfaces or additional
imported mode settings, or invalidate a static-route interface reference.
Unconfigured interfaces default to None and a disabled link. Opening Add Aggregate
does not insert a temporary entry into the interface inventory.

DHCP currently replaces all static interface addresses; the IPv6 editor is hidden
while DHCP is selected. Switching back to Static before saving retains entered
rows. Additional imported IPv6 options are preserved. Runtime support remains
platform-dependent; inspect Commit/Tasks results. This editor does not implement
PA-5220 VLAN subinterface forwarding or qualify new dataplane features.

Coverage: `test_config_interfaces.py`, `test_interface_defaults_browser.cjs`,
existing subinterface, link-settings, aggregate and modal-layer tests. Live browser
checks exercise current WAN/aggregate settings, drag, themes and Cancel with API
writes blocked. Deployment does not commit configuration or restart the dataplane.
