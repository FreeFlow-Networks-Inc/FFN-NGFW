"""Counter deltas with explicit warm-up, reset and observation-gap handling."""
import time


class PortTraffic:
    def __init__(self): self.previous = None

    def sample(self, observation):
        now = observation['sample_monotonic']
        old = self.previous
        self.previous = observation
        dt = now - old['sample_monotonic'] if old else 0
        valid = old and old.get('boot_id') == observation.get('boot_id') and 0.1 < dt < 30
        previous = {p['name']:p for p in old['ports']} if valid else {}
        ports = []
        for port in observation['ports']:
            row = dict(port, rx_gbps=None, tx_gbps=None, rx_pps=None, tx_pps=None, state='warming')
            before = previous.get(port['name'], {})
            for suffix, factor, field in [('packets_total',1,'pps'), ('bytes_total',8e-9,'gbps')]:
                for direction in ('rx','tx'):
                    key = direction+'_'+suffix
                    current, prev = port.get(key), before.get(key)
                    if type(current) is int and type(prev) is int and current >= prev:
                        row[direction+'_'+field] = (current-prev)*factor/dt
            field = 'pps' if observation.get('unit') == 'pps' else 'gbps'
            if all(row[k+'_'+field] is not None for k in ('rx','tx')): row['state'] = 'available'
            ports.append(row)
        return dict(timestamp=time.time(), ports=ports, unit=observation.get('unit','Gbps'),
                    source=observation.get('source','Data ports'), available=True)
