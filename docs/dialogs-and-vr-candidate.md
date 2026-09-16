# Dialogs and Virtual Router candidate edits

Dialogs stack in opening order, including the static-route editor opened from
the Virtual Router window. Drag a dialog by its title bar. Its position is
clamped to the viewport and resets when it closes. Only the top dialog receives
keyboard input or backdrop clicks; Escape closes that dialog and returns focus
to its opener. Background pages cannot scroll or receive input while a dialog
is open. Dynamically created policy and object dialogs use the same layer stack.

Virtual Router settings, routing settings, member assignments, and static-route
CRUD now write the candidate XML. OK stages the current editor's values; Cancel
or Escape does not submit them. Confirming a child route editor stages that
route separately; canceling its parent does not undo an already confirmed route.
Use Revert in the Commit window to discard staged configuration globally.

The existing routes in the legacy SQL store remain available as a read-only
migration source. The first VR edit imports those definitions into the candidate
alongside existing canonical XML, including when the factory template already
contains an empty default router. Existing XML values take precedence. No GET
migrates files; no editor writes SQL, invokes FRR, or changes the kernel. A marker
prevents deleted candidate routes from reappearing from the migration source.
Route IDs remain stable across edits and deletions.

Staged routes use `network/virtual-router/entry/routing-table/ip/static-route`.
FFN router metadata and extended routing options are preserved with the router.
Commit makes the configuration eligible for the existing configd/platform apply
pipeline; its apply report remains authoritative. This change does not commission
new routing protocol engines or establish dataplane forwarding readiness.

Install with `python3 image/install-dialogs.py --manager /opt/ffn-ngfw-v2`.
It merges the affected functions, copies the dialog assets and candidate helper,
and backs up replaced code. Restart the manager to load the Python change and
refresh the browser for the UI changes. No firewall reboot or BCM restart is
required. Deployment does not commit or modify the operator's configuration.
