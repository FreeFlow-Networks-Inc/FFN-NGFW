"""Dependency ordering and generation verification for configd apply cycles.

Configuration acknowledgement is independent of carrier, DHCP and reachability.
Providers must read back their settings; this coordinator records their result
and prevents failed or superseded generations from advancing the checkpoint.
"""
import hashlib
import json
import os
from pathlib import Path
import time
import uuid


STAGES=('validation','interfaces-and-routes','system-settings','security-and-nat','checkpoint')


def request_apply(running,status_path):
    running=Path(running);status_path=Path(status_path)
    generation=hashlib.sha256(running.read_bytes()).hexdigest()
    since=status_path.stat().st_mtime_ns if status_path.exists() else 0
    request=running.parent/'apply-request.json'
    temp=request.with_name(request.name+'.'+uuid.uuid4().hex+'.new')
    temp.write_text(json.dumps(dict(generation=generation,requested=time.time_ns())))
    temp.chmod(0o600);temp.replace(request)
    return generation,since


def await_apply(running,status_path,generation,since,timeout=120,clock=time.monotonic,sleep=time.sleep):
    deadline=clock()+timeout;running=Path(running);status_path=Path(status_path);latest=None
    while clock()<deadline:
        if hashlib.sha256(running.read_bytes()).hexdigest()!=generation:
            return dict(overall='superseded',commit_generation=generation,message='Running configuration changed while awaiting application')
        try:
            if status_path.stat().st_mtime_ns>since:
                row=json.loads(status_path.read_text())
                if row.get('commit_generation')==generation:
                    latest=row
                    if row.get('finished_at') and row.get('overall') in ('applied','partial-failure','validation-failed'):
                        return row
        except (OSError,ValueError):pass
        sleep(.2)
    return dict(overall='in-progress' if latest else 'unconfirmed',commit_generation=generation,
                phases=(latest or {}).get('phases',[]),message='Application has not completed; check apply status before retrying')


def dependency(path):
    """Order parents and definitions before consumers, reverse for removals."""
    path=path.replace('/','.').lower()
    if '.profiles.' in path or any('.'+k+'.' in path for k in ('address','address-group','service','service-group')):return 0
    if '.interface.' in path:
        if '.units.' in path:return 3
        if '.aggregate-group' in path:return 2
        if '.aggregate-ethernet.' in path:return 1
        return 2
    if '.zone.' in path:return 4
    if '.virtual-router.' in path:return 5
    if '.rulebase.' in path:return 7
    return 6


def ordered_paths(changes):
    # Whole-tree providers own replacement/removal semantics. Leaf providers
    # remove consumers before their definitions, then build the desired graph.
    return sorted(changes,key=lambda p:(0,-dependency(p),-p.count('.'),p)
                  if changes[p].get('kind')=='removed' else (1,dependency(p),p.count('.'),p))


class ApplyCycle:
    def __init__(self,path,status):
        self.path=Path(path);self.status=status;self.snapshot=self.path.read_bytes()
        self.digest=hashlib.sha256(self.snapshot).hexdigest()
        self.steps=[];self.position=-1
        status.commit_generation=self.digest;status.commit_phases=self.steps

    def current(self):
        if self.path.read_bytes()!=self.snapshot:
            raise RuntimeError('Running configuration changed during apply; this generation cannot be acknowledged')

    def advance(self,name):
        if name not in STAGES or STAGES.index(name)!=self.position+1:
            raise RuntimeError('Invalid config apply dependency order: '+name)
        self.current()
        if self.status.errors or self.status.validation_errors:
            raise RuntimeError('An earlier config apply stage failed; dependent stages were not run')
        if self.steps:self.steps[-1].update(state='verified',finished=time.time())
        self.position+=1;self.steps.append(dict(name=name,state='applying',started=time.time()))
        if hasattr(self.status,'write'):self.status.write()

    def finish(self):
        if self.steps:
            self.steps[-1].update(state='failed' if self.status.errors or self.status.validation_errors else
                                 'verified' if self.position==len(STAGES)-1 else 'incomplete',finished=time.time())

    def checkpoint(self,destination):
        self.advance('checkpoint')
        destination=Path(destination);temp=destination.with_name(destination.name+'.'+str(os.getpid())+'.new')
        try:
            with temp.open('wb') as out:
                os.chmod(temp,0o600);out.write(self.snapshot);out.flush();os.fsync(out.fileno())
            self.current();temp.replace(destination)
            fd=os.open(destination.parent,os.O_RDONLY|os.O_DIRECTORY)
            try:os.fsync(fd)
            finally:os.close(fd)
        finally:
            if temp.exists():temp.unlink()


def coordinated_apply(fn):
    """Serialize independent configd invocations, including manual replay."""
    from functools import wraps
    @wraps(fn)
    def wrapped(self,*args,**kwargs):
        import fcntl
        # Derive the lock from the engine's selected config directory, never
        # from customer interfaces or an assumed platform-specific pathname.
        path=Path(fn.__globals__['RUNNING_CONFIG'])
        with (path.parent/'.configd-apply.lock').open('a') as lock:
            fcntl.flock(lock,fcntl.LOCK_EX)
            return fn(self,*args,**kwargs)
    return wrapped
