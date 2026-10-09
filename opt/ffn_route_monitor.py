"""Static-route path monitor configuration and hysteresis (no runtime I/O)."""
import ipaddress

DEFAULT = dict(enabled=False, targets=[], interval=5, timeout=1, failure_count=3,
               recovery_count=3, failure_condition='all')


def validate(value, destination=None):
    if value is None: value = {}
    if not isinstance(value, dict) or set(value)-set(DEFAULT):
        raise ValueError('Unknown path monitoring setting')
    result = dict(DEFAULT, **value)
    if type(result['enabled']) is not bool: raise ValueError('Path monitoring enabled must be boolean')
    for key, low, high in [('interval',1,300),('timeout',1,10),('failure_count',1,20),('recovery_count',1,20)]:
        if type(result[key]) is not int or not low <= result[key] <= high:
            raise ValueError(key+' is outside the supported range')
    if result['timeout'] > result['interval']: raise ValueError('Probe timeout must not exceed interval')
    if result['failure_condition'] not in ('any','all'): raise ValueError('Failure condition must be any or all')
    targets = result['targets']
    if (not isinstance(targets,list) or any(not isinstance(t,str) for t in targets)
            or len(targets)>4 or len(targets)!=len(set(targets))):
        raise ValueError('Use up to four distinct monitoring targets')
    for target in targets:
        if not isinstance(target,str): raise ValueError('Monitor target must be an IP address')
        address=ipaddress.ip_address(target)
        if address.version!=4 or address.is_multicast or address.is_unspecified or address.is_loopback:
            raise ValueError('This path monitor requires unicast IPv4 targets')
        if destination and address not in ipaddress.ip_network(destination):
            raise ValueError('Monitor target must be inside the route destination')
    if result['enabled'] and not targets: raise ValueError('Enabled path monitoring requires at least one target')
    return result


def advance(previous, results, settings):
    """Count complete probe rounds; unknown startup is withheld until recovery."""
    if not results or any(type(v) is not bool for v in results): raise ValueError('Complete probe round required')
    failed=any(not v for v in results) if settings['failure_condition']=='any' else all(not v for v in results)
    failures=previous.get('failures',0)+1 if failed else 0
    successes=0 if failed else previous.get('successes',0)+1
    healthy=previous.get('healthy',False)
    if failures>=settings['failure_count']: healthy=False
    if successes>=settings['recovery_count']: healthy=True
    return dict(healthy=healthy, failures=failures, successes=successes, targets=results)
