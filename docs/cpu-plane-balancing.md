# Automatic CPU plane allocation

Hardware classification runs before CPU allocation. On a CPU-only host, the
default policy reserves `max(1, physical_cores // 8)` physical cores each for
management (MP) and control (CP). Dataplane (DP) workers get all remaining cores.
SMT siblings stay in the same pool; the lowest online core stays in MP.

| Physical cores | MP | CP | DP |
| --- | --- | --- | --- |
| 4 | 1 | 1 | 2 |
| 8 | 1 | 1 | 6 |
| 16 | 2 | 2 | 12 |
| 32 | 4 | 4 | 24 |
| 64 | 8 | 8 | 48 |

With fewer than four physical cores the planes share CPUs and no automatic
isolation is proposed. Specialized/offload hardware keeps host CPUs assigned to
management. Restricted process affinity prevents host-wide boot tuning.

`ffn_cpuisol.py plan` includes the MP/CP/DP map. Its default isolated CPU set
matches `ffn_cpu_planes.py --auto grub`: DP alone receives `isolcpus`,
`nohz_full`, and `rcu_nocbs`. MP and CP stay schedulable. The allocation policy
does not benchmark workload demand or tune NUMA placement dynamically.

Generate a proposed runtime map with `ffn_cpu_planes.py --auto conf` and inspect
boot changes with `ffn_cpuisol.py diff`. Apply boot changes through the existing
`ffn_cpuisol.py apply --yes` workflow during a maintenance window; kernel
isolation takes effect after reboot. Install the matching generated CPU map in
`/etc/ffn-ngfw/cpu-planes.conf` when adopting a new allocation, then restart its
consumers. Generating a plan alone does not migrate running processes.

Saved CPU maps and existing kernel isolation remain authoritative for active
runtime reporting. Explicit platform core/fraction declarations retain their
existing behavior; the balanced policy is the generic default. Separate control
daemons still require service affinity configuration to bind their processes;
CPU allocation alone does not pin every service on the host.
