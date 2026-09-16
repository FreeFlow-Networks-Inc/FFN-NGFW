# Plane CPU telemetry

The dashboard reads `/api/system/plane-usage`. The manager obtains CP and DP
observations from `ffn-controld` (`state/control`); it does not contact remote
hardware itself. Each configured observation agent is selected by its `cp` or
`dp` role, not its name. Agent reports expose `report.host_resources`:

- `cores`, `per_core`, and `cpu_percent`: Linux logical CPU IDs and busy percentages.
- `sample_seconds`: elapsed monotonic time between two observations.
- `state`: `sampling`, `available`, or `unavailable`.
- `memory_bytes`, `memory_total_bytes`, `memory_percent`: host memory usage.

The persistent agent transport samples `/proc/stat` on its own host after each
health observation. CPU usage excludes idle and I/O wait; guest counters are not
counted twice. The first observation, reboot, counter regression, or newly online
core requires another sample. Failed CPU reads clear the sampling baseline.
This is Linux CPU accounting, not FE100 occupancy, engine utilization, or proof
of successful forwarding. Agent health readiness is independent of CPU load.

Controld reports freshness using its local monotonic receive time. Disconnected,
expired, missing, or incompatible reports produce unknown utilization, never a
fallback to management processor usage. The dashboard clears expired readings
even if its next HTTP request stalls. With multiple agents of the same role,
the aggregate is weighted equally by logical core and requires all agents;
per-core labels include the agent name.

When remote agents are selected, the management processor's local cores appear
under Management Plane. When controld confirms there are no remote agents, the
existing local CPU allocation supplies all three planes. An unavailable
controller leaves CP/DP unknown until topology can be confirmed. Local memory
figures are approximate process RSS, while remote memory figures cover the host;
the UI labels this distinction.

Install `ffn_agent_resources.py` alongside `ffn_agent_protocol.py` on every
selected agent host (`/usr/local/lib/ffn` for PA-5200). Install the updated
`ffn_control_plane.py` and resource helper beside controld and the manager.
Reconnect the observation streams to load the sampler; the first usable sample
arrives on the second observation. Packet engines and the BCM service need no
restart. No CPU affinity, boot parameters, interface settings, or configuration
data are changed by telemetry.
