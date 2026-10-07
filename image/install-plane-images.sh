#!/bin/sh
# MP only. Install staged-image fetching; do not change processor boot selection.
set -eu
platform=${1:?usage: install-plane-images.sh SELECTED_PLATFORM_DIRECTORY}
root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
test "$(id -u)" = 0
test -r "$platform/plane-images.json"
PYTHONPATH="$root/opt" python3 - "$platform" <<'PY'
import json, sys
from pathlib import Path
from ffn_plane_images import validate_lock
directory = Path(sys.argv[1])
lock = json.loads((directory / 'plane-images.json').read_text())
validate_lock(lock)
if lock['platform'] != json.loads((directory / 'platform.json').read_text())['platform']:
    raise SystemExit('Selected platform/image lock mismatch')
PY
install -d -m 0755 /usr/local/lib/ffn /etc/ffn-ngfw
install -m 0644 "$root/opt/ffn_plane_images.py" /usr/local/lib/ffn/ffn_plane_images.py
install -m 0644 "$root/systemd/ffn-plane-images.service" /etc/systemd/system/ffn-plane-images.service
install -m 0644 "$platform/plane-images.json" /etc/ffn-ngfw/plane-images.json.new
mv /etc/ffn-ngfw/plane-images.json.new /etc/ffn-ngfw/plane-images.json
systemctl daemon-reload
systemctl enable ffn-plane-images.service
systemctl start --no-block ffn-plane-images.service
echo 'MP image staging enabled. See journalctl -u ffn-plane-images; boot selection is unchanged.'
