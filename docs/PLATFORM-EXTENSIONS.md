# Management platform extensions

The core is https://github.com/FreeFlow-Networks-Inc/FFN-NGFW. Hardware
controls belong in independently installed platform repositories. The core
provides authentication, role checks, audit persistence, extension discovery
and a WebUI registration hook; it contains no PA-5220 controller code.

## Selection and removal

`FFN_PLATFORM_EXTENSION` selects one absolute, locally administered directory.
Unset is the default: no platform code imports, routes, asset mounts or hardware
probes occur through this extension system. A checked-out submodule or installed
command alone does not enable anything. Selection changes require manager restart.

An extension contains `extension.json` (`id`, `label`, `api_version: 1`),
`control.py` and `static/ui.js`. The Python module exports
`router(current_user, require_admin, record_audit)` returning an APIRouter.
It must not perform discovery or hardware writes at import time. Extensions
are trusted administrator-installed code running with the manager's privileges.
The HTTP API cannot install, select or supply a filesystem path for an extension.

The core serves authenticated `GET /api/system/extensions`, returning disabled,
enabled, or unavailable. Failure to load an explicitly selected extension is
logged and leaves the core available. Selected static assets are public like
the existing WebUI bundle; they contain no device data or credentials. All
hardware API routes must require the supplied authentication dependency.

The browser loads only scripts advertised by that endpoint. An extension calls
`window.ffnExtensions.register(id, label, render)` and uses
`window.ffnExtensions.request(path, options)` for checked authenticated requests.
The page is added to Dashboard only after registration. No PA-specific identifiers
or requests appear in the core WebUI.

## PA-5220 integration analysis

The current core manager is a FastAPI monolith with a single asyncio worker,
SQLite audit/users, bearer authentication and an XML candidate/commit system.
`ffn_ifctl.py` targets an earlier MP/DP command-ring port table. Existing BCM
endpoints target `ffn-bcmd`. Neither interface controls the new Debian namespace
forwarder. Treating those older paths as live forwarding would report success
against the wrong backend.

The optional `ffn-platform-pa5200/management` extension instead invokes the
installed MP controllers: `ffn-network`, `ffn-overlay`, `ffn-inspection`,
`ffn-thermal`, and the pinned `ffn-cp` management path. Linux routing and interface
configuration execute on the DP; CPLD and cooling access execute on the CP.
The manager does not take ownership of ASIC registers or copy vendor SDKs.

All mutations require admin/superuser, use fixed command vectors and JSON stdin,
and audit operation/revision/outcome without logging configuration payloads.
Blocking process IO is asynchronous and bounded. Existing controllers enforce
revision conflicts, field validation, persistence and rollback. An interrupted
SSH command can leave an unknown remote outcome; the API requires a status
refresh before retrying, and the UI disables stale editors after submission.

Configuration currently applies immediately through those controllers. It is
explicitly separate from XML candidate/commit; no fake XML commit integration
is claimed. Completing that integration requires a transactional prepare/apply/
rollback contract spanning network, overlay and inspection policy, including
port/VRF dependencies. Production FRR neighbor management, MACsec key management,
OVS/OVN lifecycle, hardware flow/session offload and broader physical port support
remain separate integration work. Current offload claims stay qualified.

Existing legacy platform discovery/BCM endpoints predate this extension system;
this change does not convert or remove them. The new controls have explicit opt-in
semantics and no fallback to the legacy hardware command paths.

## Checks

`python -m unittest discover -s tests -p test_extensions.py` verifies disabled
zero-import behavior, authentication, selected assets and missing-package recovery.
Platform API and UI tests live with their implementation in the platform repo.
Run `ffn_jscheck.py` and `ffn_uiaudit.py` against the core HTML after UI changes.
