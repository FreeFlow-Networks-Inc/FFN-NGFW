#!/bin/sh
# Install one plane's code/configuration. Starting it is an explicit rollout step.
set -eu
role=${1:?usage: install-plane-node.sh mp|cp|dp CONFIG.json}
config=${2:?configuration file required}
case "$role" in mp|cp|dp) ;; *) echo 'invalid plane role' >&2; exit 2 ;; esac
test "$(id -u)" = 0
root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
PYTHONPATH="$root/opt" python3 - "$role" "$config" <<'PY'
import json, sys
from ffn_planed import Plane
with open(sys.argv[2]) as stream:
    cfg=json.load(stream)
if cfg.get('role') != sys.argv[1]: raise SystemExit('role/config mismatch')
Plane(cfg, ':memory:').db.close()
PY
install -d -m 0755 /usr/local/lib/ffn
install -d -m 0700 /etc/ffn/planes
install -m 0644 "$root/opt/ffn_planed.py" "$root/opt/ffn_linux_network.py" /usr/local/lib/ffn/
install -m 0600 "$config" "/etc/ffn/planes/$role.json"
install -m 0644 "$root/systemd/ffn-plane@.service" /etc/systemd/system/
systemctl daemon-reload
echo "Installed $role. Verify transports and backend prerequisites, then start ffn-plane@$role."
