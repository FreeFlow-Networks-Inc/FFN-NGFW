# Signed patch repository

Run the serving process separately from the publisher. Keep existing image and
content servers separate when they hold legacy releases. Only reviewed code
patches belong in this repository; development Debian packages and CP/DP image
candidates do not use the code-patch format.

## Server setup

Use a dedicated system account `ffn-patches` with no login shell. Install a
versioned copy of this tool and `opt/ffn_update_server.py`, `ffn_payload.py`,
`ffn_ed25519.py`, `ffn_patch.py`, and `ffn_vendor.py`, preserving repository paths.
The publisher needs Python 3.10+. Serving uses Python's standard library.

Install `ffn-patch-server.service` and supply the following administrator-owned
`/etc/ffn-patch-server/server.conf`; replace the example host and paths for your
deployment. The server does not read this as shell code.

```ini
FFN_PATCH_SERVER=/srv/ffn-build-server/services/patch-server/opt/ffn_update_server.py
FFN_PATCH_PUBLISHED=/srv/ffn-build-server/published/patches
FFN_PATCH_BIND=0.0.0.0
FFN_PATCH_PORT=8445
FFN_PATCH_HOST=updates.example.com
FFN_PATCH_CERT=/etc/ffn-patch-server/server.crt
FFN_PATCH_TLS_KEY=/etc/ffn-patch-server/server.key
FFN_PATCH_PUBLIC_KEY=/etc/ffn-patch-server/update.pub
```

Use a TLS certificate whose SAN matches the configured DNS name or IP address.
Clients must trust its issuing CA. Keep its private key readable only by root
and the service group (0640); keep the Ed25519 signing seed root-only (0600),
outside both the served directory and the service's accessible credentials.
An existing signing identity should be retained when moving a repository.
The service is read-only, unprivileged, resource-limited, and has no upload API.
Administer publications over SSH; do not expose it directly to the Internet
without your usual authenticated reverse proxy and network controls.

Allow the chosen TCP port on the build host's management interface in both its
active and persistent input firewall rules. On hosts running FFN, preserve it
in the `mgmt_tcp_ports` configuration used to regenerate the host ruleset.
Check from a separate machine as well as locally; a loopback download does not
test the input firewall. Do not flush the host's ruleset to expose the service.

The service exposes its console at `/`, a signed `/manifest.json`, and only the
payload named by that manifest. `/api/status` verifies the signature, and
`/api/clients` records recent requests in memory. Check-ins are request activity,
not proof of successful appliance installation. This view resets on restart.

## Publish

Build against the **exact installed code baseline**, following
[patch-management.md](../../docs/patch-management.md). Validate release behavior
before promotion. Then run the publisher as the administrator holding the seed:

```sh
python3 tools/build-server/patch_repository.py \
  --dir /srv/ffn-build-server/published/patches \
  --public-key /etc/ffn-patch-server/update.pub publish \
  --seed /etc/ffn-ngfw/update-sign.key \
  --file /srv/ffn-build-server/artifacts/approved-patch.tgz \
  --notes 'Reviewed changes for the documented baseline'
```

The publisher checks archive limits, Python syntax, member hashes, allowed code
paths, and vendor-artifact exclusions. It writes a content-addressed payload
before atomically replacing the Ed25519-signed manifest. Concurrent publishers
are locked; repeating the same publication preserves its timestamp. Previous
catalogs remain in a non-served `.history` directory. Old payloads are retained
on disk, but the server exposes only the currently listed one. A client racing
a publication can safely retry its check/download.

Use `--import-manifest /path/to/old/manifest.json` with `publish` to migrate an
already published patch. The original manifest must verify under the same key,
the archive must match it, and the publication timestamp is preserved. This
imports only the patch entry, not old full images or software bundles.

```sh
python3 tools/build-server/patch_repository.py \
  --dir /srv/ffn-build-server/published/patches \
  --public-key /etc/ffn-patch-server/update.pub verify
systemctl enable --now ffn-patch-server
journalctl -u ffn-patch-server
```

## Enroll a firewall

Transfer the CA certificate and Ed25519 **public** key through an authenticated
administrative channel. Compare their fingerprints with the server. Never copy
the CA private key, TLS private key or signing seed onto the firewall. Preserve
an already-installed matching signing key; a mismatch needs a deliberate trust
rotation, not a blind overwrite.

On an Ubuntu management plane, install a private issuing CA under
`/usr/local/share/ca-certificates/ffn-patch-server.crt` and run
`update-ca-certificates`. Install the verified signing public key as
`/etc/ffn-ngfw/update.pub`. Set the HTTPS URL under **Device > Software > Patch
Management**, or in `/etc/ffn-ngfw/update-server.conf` as `url=https://HOST:8445`.
Keep TLS verification enabled.

Use **Check for patches**, then **Download and validate**. Installation remains
an explicit administrator action. Baseline/dependency mismatches must be resolved
with an appropriate release, never by disabling the checks. This server setup
does not install patches, restart dataplanes, or reboot appliances.

Back up signing material separately and encrypt it. Monitor certificate expiry
and renew the leaf certificate under the same trusted CA, then restart only
`ffn-patch-server`. Back up the manifest and its referenced archive together.
