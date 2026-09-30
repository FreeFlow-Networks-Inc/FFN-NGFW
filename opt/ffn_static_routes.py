"""Reconcile link-qualified static routes without modifying desired configuration."""
import fcntl
import hashlib
import importlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from ffn_route_monitor import validate, advance

STATE=Path('/run/ffn-static-routes.json')


def key(route):
    return hashlib.sha256(json.dumps(route,sort_keys=True).encode()).hexdigest()


def boot(): return Path('/proc/sys/kernel/random/boot_id').read_text().strip()


def load():
    try:
        value=json.loads(STATE.read_text())
        return value if value['boot']==boot() else {'routes':{}}
    except (OSError,ValueError,KeyError): return {'routes':{}}


def save(value):
    temp=STATE.with_suffix('.tmp');temp.write_text(json.dumps(value));temp.chmod(0o600);temp.replace(STATE)


def base_reason(net, route):
    import ipaddress
    if route.get('type')=='blackhole': return None
    dev=route['dev'];rows=json.loads(net.ip('-j','address','show','dev',dev))
    if len(rows)!=1: return 'interface-missing'
    row=rows[0]
    if not {'UP','LOWER_UP'}<=set(row.get('flags',[])): return 'link-down'
    provider=getattr(net,'route_link',None)
    if provider:
        reason=provider(dev)
        if reason: return reason
    if route.get('via') and not route.get('onlink'):
        gateway=ipaddress.ip_address(route['via'])
        if not (gateway.version==6 and gateway.is_link_local) and not any(
            gateway in ipaddress.ip_interface(a['local']+'/'+str(a['prefixlen'])).network
            for a in row.get('addr_info',[]) if a.get('family')==('inet' if gateway.version==4 else 'inet6')):
            return 'gateway-outside-interface-prefix'
    return None


def apply(net, route, delete=False, health=None):
    present=net.route_present(route)
    reason='removed' if delete else base_reason(net,route)
    monitor=validate(route.get('monitor'),route['dst'])
    if not reason and monitor['enabled']:
        health=health if health is not None else load()['routes'].get(key(route),{})
        age=time.monotonic()-health.get('observed',0)
        if not 0<=age<=max(60,monitor['interval']*2): reason='monitor-stale'
        elif not health.get('healthy'): reason='path-down'
    if reason:
        if present: net.raw_configure_route('del',route)
        return dict(installed=False,reason=reason)
    if not present: net.raw_configure_route('add',route)
    if not net.route_present(route): raise RuntimeError('Static route readback mismatch')
    return dict(installed=True,reason='eligible')


def sample(net,route):
    monitor=validate(route.get('monitor'),route['dst'])
    command=['ip','netns','exec',net.NS,'python3',str(Path(__file__).with_name('ffn_route_probe.py'))]
    p=subprocess.run(command,input=json.dumps(route),text=True,capture_output=True,timeout=monitor['timeout']+4)
    if p.returncode: raise RuntimeError('Route probe failed')
    results=json.loads(p.stdout)
    if len(results)!=len(monitor['targets']): raise RuntimeError('Incomplete probe round')
    return results


def tick(net,stop=False):
    # Same owner lock as configuration edits. Bounded probes run outside it;
    # results from an obsolete configuration are never installed.
    with open('/run/ffn-network.lock','a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        cfg=net.validate(json.loads(net.STATE.read_text()))
        routes=[r for r in cfg.get('routes',[]) if r.get('track_link')]
        state=load();old=state['routes'];records={}
        for route in routes:
            identity=key(route);health=old.get(identity,{})
            result=apply(net,route,delete=stop,health=health)
            records[identity]=dict(health,route=route,**result)
        save(dict(boot=boot(),observed=time.monotonic(),revision=cfg['revision'],routes=records))
    if stop:return
    due=[r for r in routes if validate(r.get('monitor'),r['dst'])['enabled'] and
         time.monotonic()-old.get(key(r),{}).get('observed',0)>=validate(r.get('monitor'),r['dst'])['interval']]
    # Oldest first avoids starvation; a single tick has a bounded packet budget.
    due.sort(key=lambda r:old.get(key(r),{}).get('observed',0))
    for route in due[:4]:
        settings=validate(route.get('monitor'),route['dst'])
        try: results=sample(net,route)
        except Exception: results=[False]*len(settings['targets'])
        with open('/run/ffn-network.lock','a') as lock:
            fcntl.flock(lock,fcntl.LOCK_EX)
            current=net.validate(json.loads(net.STATE.read_text()))
            if current!=cfg:return
            state=load();identity=key(route)
            health=advance(state['routes'].get(identity,{}),results,settings)
            health.update(observed=time.monotonic(),route=route)
            health.update(apply(net,route,health=health));state['routes'][identity]=health
            state.update(observed=time.monotonic(),revision=cfg['revision']);save(state)


def main():
    sys.path.insert(0,'/usr/local/sbin')
    net=importlib.import_module(os.getenv('FFN_NETWORK_MODULE','ffn_linux_network'))
    if sys.argv[1:] == ['stop']:tick(net,stop=True);return
    while True:
        try:tick(net)
        except Exception:
            # systemd restarts the owner; stop hook withdraws its managed routes.
            raise
        time.sleep(1)


if __name__=='__main__':main()
