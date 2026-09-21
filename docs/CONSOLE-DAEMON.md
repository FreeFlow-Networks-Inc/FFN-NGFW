# Console ownership and administrator authentication

The console uses local JSON RPC over `/run/ffn-ngfw/console.sock`, owned by
`ffn-controld`. It does not contact HTTPS, load WebUI pages, or fall back to
the web listener. The CLI's existing operation names remain compatible;
`/api/...` strings are identifiers carried inside RPC, not network requests.

```text
SSH / console -> ffn-cli -> controld console socket -> ffn-managementd
Browser      -> web listener -> controld console socket -> ffn-managementd
                                                        |
                      one authentication/configuration/commit owner
                                                        |
                     controld -> configd / CP / DP / hardware owners
```

`ffn-managementd` runs the shared management handlers without a TCP listener
or static-file service. Its private Unix socket is root-only. The web process
forwards HTTP management operations and does not execute a second set of
candidate/commit handlers. Its startup skips database/alias initialization.
WebSocket log observation remains in the web process and is read-only.

The console-facing socket accepts only management operations, never the
legacy privileged `plane/request`, raw register, or shell-command protocol.
Protected web operations retain bearer authentication. Console operations
use `SO_PEERCRED`: the control daemon obtains the calling UID from the kernel,
and passes it over the private backend connection. No client-supplied user,
role, environment username, or forwarded identity header grants privileges.

## SSH identities and permissions

The FFN administrator database remains authoritative for passwords and roles.
The SSH PAM helper checks credentials through controld against that database.
After successful SSH authentication, the CLI does not ask for another login.
Every operation resolves the peer UID and rechecks the current database role,
so account deletion, demotion, and forced password changes remain effective.
Forced password changes prompt in the CLI before normal control operations.

Database-only users receive a password-free NSS identity containing a stable
UID, the `ffn-console` group, a home directory and the restricted CLI shell.
They are not added to `/etc/passwd` or `/etc/shadow`. The extrausers export
contains no password hashes. A durable `console_identities` table prevents
UID reuse after account deletion. Existing local accounts already using
`ffn-cli`, such as an older appliance's admin account, retain their UID and
use FFN password verification for SSH. Other Linux accounts retain their
existing authentication stack.

UID 0 receives the full `superuser` control role even without an FFN database
entry. Linux root SSH authentication is unchanged. Non-root CLI users cannot
enter the old operating-system maintenance escape. SSH forwarding and user
RC execution are disabled for the `ffn-console` group.

New FFN accounts use SSH-safe names and cannot take over Linux system
accounts. Configuration changes continue to stage in candidate and require
Commit. The IPC migration itself never commits firewall configuration.

## Installation

From the core checkout on MP, with the management service running:

```sh
python3 image/install-console-ipc.py
apt-get install libnss-extrausers
python3 image/install-console-auth.py --database /path/to/the/appliance/config.db
```

Use the deployed `FFN_DB_PATH` for the database argument. The IPC installer
copies the service's existing FFN environment to a root-readable backend
environment file, preserving the configured database, JWT signing key and
platform selection. It merges the installed shell and manager rather than
replacing them with an older checkout. Backups reside in `/var/backups/ffn`.
The web listener is stopped briefly while ownership transfers to the backend.
No CP/DP reset, port reconfiguration, or firewall reboot is needed.

The auth installer validates `sshd -t` before reloading SSH; it preserves root
and existing sessions. Reconnect existing FFN-CLI sessions to load the new
transport. Backend unavailability returns an error, with no HTTP fallback or
automatic replay of an uncertain mutation. Console JSON messages are bounded.
The root-owned web gateway streams uploads/downloads through controld in
64 KiB chunks, preserving larger file transfers without buffering the whole
transfer in the control daemon. Unprivileged console clients cannot open this
gateway stream or use it to inherit root identity.

The core installer is independent of hardware family. Platform extensions
continue to provide their command vocabulary and implementation through the
same authenticated operation adapter.

## Validation performed

- Protocol/identity tests reject spoofed UID fields and headers, unauthorized
  access, stale/deleted accounts, forced-password bypass, and legacy privileged
  commands on the console socket.
- A 17 MiB streaming upload and binary response passed through real local
  sockets; the console and browser transport use the same backend owner.
- A temporary FFN-only administrator successfully logged in over real SSH and
  ran FE100 status with the web listener stopped, using one password prompt.
  A wrong password was rejected; subsequent demotion enforced read-only access.
  The temporary account and home were removed after testing.
- Root and the existing admin account both used the real installed CLI through
  controld. Root required no FFN database account or second login.
- A console-acquired commit lock was visible to the web client, which received
  a conflict when attempting to acquire it. Cleanup released the lock, and
  candidate/running XML hashes stayed unchanged.

NSS metadata follows the [GNU libc NSS interface](https://sourceware.org/glibc/manual/latest/html_node/NSS-Modules-Interface.html)
using [extrausers](https://packages.debian.org/bookworm/libnss-extrausers).
SSH credential checks use the [Linux-PAM pam_exec interface](https://github.com/linux-pam/linux-pam/blob/master/modules/pam_exec/pam_exec.c).
