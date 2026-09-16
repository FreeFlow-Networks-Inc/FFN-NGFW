# SPDX-License-Identifier: GPL-2.0-or-later
"""Linux host CPU telemetry carried by the selected CP/DP observation agents.

This measures kernel CPU accounting, not accelerator occupancy or forwarding
readiness. Only the persistent agent samples counters; readers never trigger
commands on a plane or change its affinity.
"""
import math
from pathlib import Path
import time


class ResourceSampler:
    def __init__(self, root='/proc', clock=time.monotonic):
        self.root = Path(root)
        self.clock = clock
        self.previous = None

    def sample(self, boot_id):
        result = {'state': 'unavailable', 'scope': 'linux-host',
                  'cores': [], 'per_core': {}, 'cpu_percent': None,
                  'sample_seconds': None, 'memory_bytes': None,
                  'memory_total_bytes': None, 'memory_percent': None}
        try:
            counters = {}
            for line in (self.root / 'stat').read_text().splitlines():
                fields = line.split()
                if fields and fields[0].startswith('cpu') and fields[0][3:].isdigit():
                    values = tuple(int(n) for n in fields[1:9])
                    if len(values) < 4 or any(n < 0 for n in values):
                        raise ValueError('invalid CPU counters')
                    counters[int(fields[0][3:])] = values
            if not counters:
                raise ValueError('no CPU counters')
            now = self.clock()
            previous = self.previous
            self.previous = (boot_id, now, counters)
            window = now - previous[1] if previous and previous[0] == boot_id else 0
            usage = {}
            for core, values in sorted(counters.items()):
                old = previous[2].get(core) if previous and window > 0 else None
                delta = [a - b for a, b in zip(values, old)] if old and len(old) == len(values) else []
                total = sum(delta)
                idle = delta[3] + (delta[4] if len(delta) > 4 else 0) if delta else 0
                usage[str(core)] = (round(100 * (total - idle) / total, 1)
                                    if delta and min(delta) >= 0 and total > 0 else None)
            valid = all(v is not None for v in usage.values())
            result.update(cores=sorted(counters), per_core=usage,
                          state='available' if valid else 'sampling',
                          sample_seconds=round(window, 3) if window > 0 else None,
                          cpu_percent=round(sum(usage.values()) / len(usage), 1) if valid else None)
        except (OSError, ValueError):
            self.previous = None
        try:
            mem = {}
            for line in (self.root / 'meminfo').read_text().splitlines():
                key, rest = line.split(':', 1)
                mem[key] = int(rest.split()[0]) * 1024
            total = mem['MemTotal']
            available = mem.get('MemAvailable', sum(mem.get(k, 0) for k in
                                ('MemFree', 'Buffers', 'Cached', 'SReclaimable')) - mem.get('Shmem', 0))
            used = total - max(0, min(total, available))
            if total > 0:
                result.update(memory_bytes=used, memory_total_bytes=total,
                              memory_percent=round(100 * used / total, 2))
        except (OSError, ValueError, KeyError, IndexError):
            pass
        return result


def _number(value, maximum=None):
    return (type(value) in (int, float) and math.isfinite(value) and value >= 0
            and (maximum is None or value <= maximum))


def agent_plane_usage(status, role):
    """Project only resource fields, never exposing privileged agent reports.

    Every selected agent must have a fresh, complete sample for the aggregate.
    Core IDs are qualified when a role has multiple agents to avoid collisions.
    """
    selected = {name: a for name, a in (status or {}).get('agents', {}).items() if a.get('role') == role}
    result = {'source': 'agent', 'state': 'unavailable', 'fresh': False,
              'cores': [], 'per_core': {}, 'cpu_percent': None,
              'memory_bytes': None, 'memory_percent': None, 'memory_scope': 'host',
              'age_seconds': None, 'expires_in_seconds': 0, 'sample_seconds': None,
              'agents': []}
    if not selected:
        return result
    states, ages, expiry, windows, memories = [], [], [], [], []
    for name, agent in sorted(selected.items()):
        observation = agent.get('last_observation') or {}
        resources = (observation.get('report') or {}).get('host_resources') or {}
        fresh = agent.get('fresh') is True and agent.get('connected') is True
        age = agent.get('age_seconds')
        ttl = agent.get('stale_after_seconds')
        if not _number(age) or not _number(ttl) or age >= ttl:
            fresh = False
        state = resources.get('state', 'unavailable') if fresh else 'stale'
        cores = resources.get('cores', [])
        usage = resources.get('per_core', {})
        valid = (isinstance(cores, list) and 0 < len(cores) <= 4096
                 and all(type(c) is int and c >= 0 for c in cores)
                 and len(set(cores)) == len(cores) and isinstance(usage, dict))
        if not valid:
            cores, state = [], 'unavailable' if fresh else 'stale'
        if state == 'available' and not all(_number(usage.get(str(c)), 100) for c in cores):
            state = 'unavailable'
        if state not in ('available', 'sampling', 'stale'):
            state = 'unavailable'
        for core in cores:
            key = str(core) if len(selected) == 1 else name + ':' + str(core)
            result['cores'].append(core if len(selected) == 1 else key)
            result['per_core'][key] = usage[str(core)] if state == 'available' else None
        states.append(state)
        if _number(age):
            ages.append(age)
        expiry.append(max(0, ttl - age) if fresh else 0)
        window = resources.get('sample_seconds')
        if _number(window):
            windows.append(window)
        used, total = resources.get('memory_bytes'), resources.get('memory_total_bytes')
        if fresh and _number(used) and _number(total) and total > 0 and used <= total:
            memories.append((used, total))
        result['agents'].append({'name': name, 'state': state, 'fresh': fresh,
                                 'age_seconds': age if _number(age) else None})
    state = ('stale' if 'stale' in states else 'unavailable' if 'unavailable' in states
             else 'sampling' if 'sampling' in states else 'available')
    result.update(state=state, fresh=all(a['fresh'] for a in result['agents']),
                  age_seconds=max(ages) if ages else None,
                  expires_in_seconds=min(expiry), sample_seconds=max(windows) if windows else None)
    if state == 'available' and result['per_core']:
        result['cpu_percent'] = round(sum(result['per_core'].values()) / len(result['per_core']), 1)
    if len(memories) == len(selected):
        result['memory_bytes'] = sum(m[0] for m in memories)
        result['memory_percent'] = round(100 * result['memory_bytes'] / sum(m[1] for m in memories), 2)
    return result
