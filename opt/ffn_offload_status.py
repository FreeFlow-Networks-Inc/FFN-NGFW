# SPDX-License-Identifier: GPL-2.0-or-later
"""Merge controld's authenticated agent observations into hardware inventory."""
from copy import deepcopy


def with_dp_acknowledgement(inventory, agents):
    info = deepcopy(inventory)
    agent = (agents or {}).get('agents', {}).get('dp', {})
    observation = agent.get('last_observation') or {}
    report = observation.get('report') or {}
    if (not info.get('present') or agent.get('connected') is not True
            or agent.get('fresh') is not True or observation.get('role') != 'dp'
            or observation.get('platform') != 'pa5200' or report.get('octeon') is not True
            or report.get('role') != 'dataplane'
            or not observation.get('boot_id')
            or observation['boot_id'] != report.get('boot_id')):
        return info
    ready = agent.get('ready') is True and report.get('ready') is True
    dp = info.setdefault('dp', {})
    dp.update(present=True, running=True, agent_acknowledged=True, ready=ready,
              boot_id=observation['boot_id'], cpu_count=report.get('cpu_count'),
              host_resources=report.get('host_resources'),
              packet_io=report.get('packet_io'),
              forwarding_verified=report.get('forwarding_verified') is True,
              liveness='native agent ready' if ready else 'agent answering; runtime not ready')
    if not dp.get('model'):
        dp['model'] = 'OCTEON dataplane'
    info['boot_state'] = 'DP agent ready' if ready else 'DP agent answering; runtime not ready'
    return info
