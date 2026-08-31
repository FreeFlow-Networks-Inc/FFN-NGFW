#!/usr/bin/env bash
# Set the platform console tokens on the kernel cmdline, then hand CPU/memory
# tuning to opt/ffn_cpuisol.py. Effective on the next boot.
#
# WHY THIS SCRIPT NO LONGER DECIDES ANYTHING ITSELF
#
# It used to compute isolcpus/nohz_full/rcu_nocbs/hugepages/iommu on its own and
# write them with:
#
#     sed -i "s|^GRUB_CMDLINE_LINUX_DEFAULT=.*|...=\"${CMD}\"|" /etc/default/grub
#
# That is two separate problems once ffn_cpuisol.py exists:
#
#   1. Both wrote the same kernel parameters. ffn_cpuisol.py appends via a
#      /etc/default/grub.d drop-in; this overwrote the whole line in the main
#      file. Run in either order you get a cmdline with TWO isolcpus= tokens, or
#      one silently erased -- and which one the kernel honours is not something
#      to build an appliance on.
#
#   2. They disagreed on policy. This script isolated the upper half of the
#      LOGICAL cpus whenever nproc >= 16, which splits SMT pairs (an isolated
#      thread whose sibling stays schedulable is still preempted), and it had no
#      concept of hardware that offloads forwarding -- so on an appliance whose
#      packets never touch host cores it would isolate cores for no benefit.
#      ffn_cpuisol.py reasons in whole physical cores and reads the platform's
#      own datapath declaration.
#
# So: one owner per concern. ffn_cpuisol.py owns isolation, hugepages and IOMMU.
# This script owns the console tokens, because serial baud is a property of the
# chassis and nothing to do with CPU topology.
set -uo pipefail

CPUISOL="${FFN_CPUISOL:-/opt/ffn_cpuisol.py}"
DROPIN_DIR=/etc/default/grub.d
CONSOLE_DROPIN="$DROPIN_DIR/10-ffn-console.cfg"
GRUB_DEFAULT=/etc/default/grub

# Serial baud is platform-specific -- PA-3200/PA-5200 chassis run 9600. The
# image build persists it so re-tuning on first boot cannot revert to 115200.
BAUD=115200
[ -r /etc/ffn-ngfw/serial-baud ] && BAUD="$(cat /etc/ffn-ngfw/serial-baud)"
CONSOLE_TOKENS="console=tty0 console=ttyS0,${BAUD}n8"

say(){ echo "ffn-hwtune: $*"; }

# ---------------------------------------------------------------- console ----
if [ -d "$DROPIN_DIR" ] || grep -qs "grub.d" /usr/sbin/grub-mkconfig 2>/dev/null; then
	mkdir -p "$DROPIN_DIR"
	cat > "$CONSOLE_DROPIN" <<EOF
# Managed by ffn-hwtune.sh -- console only. CPU isolation, hugepages and IOMMU
# are owned by ffn_cpuisol.py, which appends its own drop-in.
GRUB_CMDLINE_LINUX_DEFAULT="\$GRUB_CMDLINE_LINUX_DEFAULT ${CONSOLE_TOKENS}"
EOF
	say "console tokens -> $CONSOLE_DROPIN (baud ${BAUD})"
	REGEN_NEEDED=1
else
	# No grub.d on this distro. Replace only the console tokens inside the
	# existing line -- never rewrite the whole line, which is what used to
	# destroy anything else configured there.
	if [ -w "$GRUB_DEFAULT" ]; then
		cur=$(sed -n 's|^GRUB_CMDLINE_LINUX_DEFAULT="\(.*\)"$|\1|p' "$GRUB_DEFAULT" | head -1)
		stripped=$(echo " $cur " | sed -E 's/ console=[^ ]*//g; s/^ *//; s/ *$//')
		new="$stripped $CONSOLE_TOKENS"
		sed -i "s|^GRUB_CMDLINE_LINUX_DEFAULT=.*|GRUB_CMDLINE_LINUX_DEFAULT=\"${new}\"|" "$GRUB_DEFAULT"
		say "console tokens merged into $GRUB_DEFAULT (baud ${BAUD})"
		REGEN_NEEDED=1
	else
		say "cannot write $GRUB_DEFAULT; console tokens not set"
		REGEN_NEEDED=0
	fi
fi

# ------------------------------------------------------------- cpu / memory --
# ffn_cpuisol.py decides whether isolation is appropriate at all, picks whole
# physical cores, sizes hugepages, and regenerates GRUB itself.
if [ -x "$CPUISOL" ]; then
	say "delegating CPU/memory tuning to $CPUISOL"
	"$CPUISOL" show || true
	if "$CPUISOL" apply --yes; then
		say "kernel tuning applied; effective next boot"
		exit 0
	fi
	say "WARNING: $CPUISOL apply failed; console tokens are still set"
else
	say "NOTE: $CPUISOL not found -- console tokens set, but no CPU isolation,"
	say "      hugepage or IOMMU tuning was applied. Install the management"
	say "      plane, or run ffn_cpuisol.py by hand."
fi

# cpuisol normally regenerates GRUB; do it here if it did not run.
if [ "${REGEN_NEEDED:-0}" = 1 ]; then
	command -v update-grub >/dev/null 2>&1 && update-grub >/dev/null 2>&1 \
		|| grub-mkconfig -o /boot/grub/grub.cfg >/dev/null 2>&1 || true
	say "GRUB config regenerated"
fi
