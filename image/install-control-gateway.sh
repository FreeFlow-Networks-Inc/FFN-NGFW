#!/bin/sh
# Install versioned controld code; activation is a separate rollout step.
set -eu
test "$(id -u)" = 0
root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
test -d /opt/ffn-ngfw
test -d /opt/ffn-ngfw-v2
backup="/var/backups/ffn/control-gateway-$(date +%s)-$$"
deploy() {
    if [ -e "$2" ]; then
        mkdir -p "$(dirname -- "$backup$2")"
        cp -p "$2" "$backup$2"
    fi
    install -m 0644 "$1" "$2"
}
install -d -m 0755 /usr/local/lib/ffn
for dir in /opt/ffn-ngfw /opt/ffn-ngfw-v2 /usr/local/lib/ffn; do
    for name in ffn_control_plane.py ffn_hardware_boot.py ffn_agent_protocol.py ffn_agent_resources.py ffn_controld_client.py ffn_planed.py ffn_policy_config.py ffn_policy_plan.py ffn_policy_profiles.py ffn_qos_config.py ffn_nat_policy.py ffn_ipv6_translation.py; do
        deploy "$root/opt/$name" "$dir/$name"
    done
done
deploy "$root/opt/ffn_controld.py" /opt/ffn-ngfw/ffn_controld.py
deploy "$root/opt/ffn_plane_api.py" /opt/ffn-ngfw-v2/ffn_plane_api.py
python3 "$root/image/install-control-api.py"
echo "Previous control files: $backup"
echo 'Installed controld. Select /etc/ffn/controld.json and FFN_CONTROL_GATEWAY=controld before activating the gateway.'
