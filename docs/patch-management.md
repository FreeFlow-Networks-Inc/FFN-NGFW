# Code patch management

Device > Software and Software Updates open Patch Management. The previous image
and content updater remains under **Full image / content updates**.

1. Set an HTTPS update server and provision its Ed25519 public key at
   `/etc/ffn-ngfw/update.pub`.
2. **Check for patches** verifies the release manifest and displays its version,
   notes and SHA-256. No code is installed.
3. **Download and validate** stages the selected release. Review the added,
   replaced and deleted files and required dependencies.
4. **Install staged patch** revalidates the signature, hashes, exact installed
   baseline, dependencies and space. It journals backups, stops management
   services, applies files, and restarts previously active services. An independent
   systemd worker survives the manager's restart; the page polls persisted status.
5. **Roll back latest patch** restores saved files and the previous patch version.
   Local changes block rollback. Failed installations attempt automatic restoration.
   After power loss or failed restoration, **Recover interrupted operation** resumes
   restoration once the original worker is no longer active.

Actions require admin or superuser; authenticated viewers can inspect status.
The latest 50 jobs record the requesting user, times and result. Only one patch
operation can run at once. The full software updater shares its lock; a full
software replacement invalidates patch staging and rollback records.

## Build and publish

Use two clean release trees: the exact previous version and the next version.
The builder accepts repository trees (`opt/*.py`, `static/**`) or flat installed
trees (`*.py`, `static/**`). Python modules map to the appliance's flat layout.

```sh
python3 opt/ffn_patch.py build --base /srv/releases/previous \
  --source /srv/releases/next --version 2026.09.10.1 \
  --require defusedxml==0.7.1 --output /srv/patches/ffn-2026.09.10.1.tgz

python3 opt/ffn_payload.py publish --dir /srv/ffn-updates --kind patch \
  --file /srv/patches/ffn-2026.09.10.1.tgz --version 2026.09.10.1 \
  --seed /secure/update-sign.key --notes "Hardware discovery and WebUI fixes"
```

Serve `/srv/ffn-updates` over HTTPS with a trusted certificate. The private seed
stays on the publisher. Patches refuse HMAC, unsigned metadata, HTTP and redirects
away from HTTPS. Downloaded and expanded packages are limited to 128 MiB and
4096 regular-file members. Traversal, archive links, undeclared files and Python
syntax errors are rejected. This workflow never pulls unsigned GitHub code onto
a running appliance.

Patches change Python modules and WebUI assets only. Configuration, secrets,
virtual environments, kernel modules, FPGA bitstreams, OS packages and install
hooks are excluded. Declared Python distributions must already be installed at
their required versions; patching does not run pip. Use full images for other
components or updates requiring data migrations.

## Bootstrap and recovery

Initially deploy `ffn_patch.py`, `ffn_patch_api.py`, the updated manager/UI and
`ffn_payload.py` together, plus runtime requirements including `defusedxml`.
An appliance without this patch manager cannot bootstrap it through the new UI.

The installation is `/opt/ffn-ngfw-v2`; private state, staged packages and backups
live in `/var/lib/ffn-ngfw/patches`. Backups are retained on disk; only the latest
journal supports one-step rollback. Administrators can archive obsolete backups,
but must preserve the directory referenced by `journal.json`.

The worker controls `ffn-manager-v2`, `ffn-configd` and `ffn-controld` units that
were active before installation. The manager must already be active. Validation
checks syntax, dependencies and service startup; it does not certify forwarding
or physical FPGA/OCTEON behavior. No reboot or explicit dataplane restart occurs.

If the WebUI does not return, use the appliance console and its runtime Python:

```sh
/opt/ffn-ngfw-v2/venv/bin/python /opt/ffn-ngfw-v2/ffn_patch.py status
/opt/ffn-ngfw-v2/venv/bin/python /opt/ffn-ngfw-v2/ffn_patch.py recover
journalctl -u 'ffn-patch-*'
```

`FFN_PATCH_ROOT` and `FFN_PATCH_STATE` are administrator-controlled overrides,
never API parameters. State must remain outside the code installation and must
not be writable by untrusted users. Recovery restores code, not application data.

## Validation

`tests/test_patches.py` covers signatures, tampering, baseline drift, dependencies,
install/rollback, service failure, simulated power loss, damaged backups, archive
attacks, transport policy and locking. API and renderer tests cover permissions,
job submission and displayed state. CI mocks systemd and needs no root privileges.
A real Linux appliance smoke test is required before production rollout.
