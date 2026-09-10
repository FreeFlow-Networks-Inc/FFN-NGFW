# Repository review — 2026-09-10

This pass focused on management-plane authentication, live-log lifecycle, and
CI reliability. It is not a complete security or hardware certification.

## Repository synchronization

Fetched origin and pulled the tracked `add-image-build-submodule` branch with
`--ff-only`. It was already current with its upstream, with four additional local
commits. Created `codex/repository-hardening` and merged `origin/main` at
`b2dddf4`, incorporating the upstream python-jose 3.4.0 update. The pre-existing
edit to `image-build/payload/ffn-cli` was preserved.

## Changes

| Finding | Improvement |
| --- | --- |
| The live-log WebSocket accepted anonymous clients and spawned `journalctl`. | Require a valid, unrestricted bearer token in the first frame within five seconds, before accessing logs or starting a process. Updated both console clients. |
| HTTP authentication trusted token roles and did not check whether an account still existed. | Resolve current roles and forced-password-change state from SQLite on each authenticated request and new stream. Reject deleted accounts and tokens missing expiry or subject. |
| A disconnected client could leave a log reader blocked on a quiet journal. | Wait for disconnect concurrently with log output, cancel pending reads and reap the reader. |
| CI compared Crucible's signing implementation before fetching its submodule. | Fetch the pinned public submodule before reading its files. |

Existing custom WebSocket clients must adopt the first-frame authentication
protocol documented in `UNAUTHENTICATED-ROUTES.md`. Each authentication now adds
one SQLite account lookup; throughput under appliance load has not been measured.

## Validation

- `python tests/test_auth.py`: passes, including existing password-change tests,
  role demotion, forced password change, account deletion, malformed/expired/
  missing WebSocket credentials, authentication timeout, authorized streaming,
  and cleanup after disconnect from a quiet journal.
- `python opt/ffn_jscheck.py static/index.html`: zero problems.
- Python compilation of the changed manager and test: passes.
- Publication scanner selftest: 11 groups, zero failures.
- `git diff --check`: passes.

Tests ran in an isolated Python 3.12 virtual environment on Windows, using the
repository's runtime and test requirements. The log-stream tests mock
`journalctl`; they exercise the real WebSocket route and authentication code.
Linux dataplane builds, DPDK, live journalctl, appliance images, FPGA/OCTEON
hardware, and the full GitHub Actions workflow were not executed on this host.

## Remaining priorities

1. **Enforce a complete role policy.** Several mutating handlers, including
   `policy_add`, use `get_current_user` without a role check. Reading a current
   role does not itself prevent a read-only user from changing policy. Define
   allowed operations for each role and enforce them centrally with route tests.
2. **Render log content as text.** System-log rendering interpolates `l.message`
   into `innerHTML`. Log content should not be interpreted as markup. Audit other
   API-derived HTML interpolation at the same time.
3. **Add explicit session revocation.** Password changes do not revoke existing
   full-access tokens. Account lookup is keyed by username, so recreating a
   deleted username can also revive its unexpired tokens. Use immutable account
   identity and a session version, and revalidate long-lived WebSocket sessions.
4. **Exercise Linux integration in CI.** Keep the existing portable dataplane
   suite, and add live stream disconnect tests against a real subprocess and a
   defined dependency-update policy. Hardware claims still require appliance
   validation.

No appliance was deployed or reconfigured during this review.
