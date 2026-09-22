# Virtual Router interface inventory and static-route editing

The Virtual Router dialogs use `/api/network/virtual-router-interfaces`, built
from the same candidate interface configuration used by Network > Interfaces.
It includes configured Layer 3 Ethernet, aggregate, VLAN, loopback, tunnel and
Layer 3 subinterfaces. Management-host NIC discovery is not used as the list
of firewall ports. Legacy Linux aliases are recognized when reading saved
membership or route selections.

The current default-router model uses Layer 3 interfaces not assigned to a
named router. Its editor shows those effective members without trying to
enslave them to a Linux VRF called `default`. Named-router selectors identify
interfaces already assigned elsewhere. Unknown saved selections remain visible
instead of silently disappearing when inventory changes or a request fails.

Static routes can be added, edited in place and deleted from the Routing
dialog. Editing retains the route ID. Backend validation checks the network
prefix, next-hop address family, interface existence, router ownership and
metric range. Route writes require an administrator. A failed inventory load
prevents the route form from saving an accidentally cleared interface.

This update preserves the existing SQL router/route store. Saving a route is
not evidence that it is installed in the dataplane. On systems with a selected
hardware extension, router and route configuration saves do not create MP
kernel VRFs or send route additions to MP FRR. Platform dataplane activation
and synchronization with committed configuration remain separate integration
work; the editor states that distinction explicitly.

`image/install-vr-ui.py --target /opt/ffn-ngfw-v2` merges only the changed API
functions, router dialogs and assets into a live manager, with backups. It does
not replace configuration databases or running/candidate XML. Restart the
manager after installation and refresh the browser. No appliance reboot is
required.

Regression coverage: `tests/test_vr_interfaces.py`, `tests/test_vr_route_api.py`,
`tests/test_vr_ui.cjs` and `tests/test_console_ui.cjs`. The appliance rollout
also checks the authenticated inventory API, an invalid edit, asset delivery
and preservation of the existing default route.
