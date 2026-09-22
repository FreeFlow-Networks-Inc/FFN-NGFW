"""Real supervised, atomic Security/NAT with an expiring fail-closed gate."""
import json
from pathlib import Path
import signal
import subprocess as S
import sys
import tempfile
import time
import uuid
from xml.etree import ElementTree as ET
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'opt'))
import ffn_nat_runtime as nat
import ffn_security_runtime as runtime
from ffn_session_events import Journal
from test_policy_plan import configuration


def main():
    token=uuid.uuid4().hex[:8];names=['ffn-run-'+token+'-'+n for n in ('dp','lan','wan')];dp,lan,wan=names;made=[];service=None
    def run(*args,text=None):
        p=S.run(args,input=text,text=True,capture_output=True,timeout=10)
        if p.returncode:raise RuntimeError(p.stderr)
        return p.stdout
    def ping(destination='198.51.100.2',ident=3456):
        return S.run(['ip','netns','exec',lan,nat.executable('ping'),'-c','1','-W','1','-e',str(ident),destination],capture_output=True,timeout=5).returncode==0
    def policy(action='allow'):
        root=ET.fromstring(configuration('security',{'action':action,'log-end':'yes' if action=='allow' else 'no'}))
        tree=ET.fromstring(configuration('nat',{'source-type':'dynamic-ip-and-port','source-interface':'ethernet1/2'}))
        root.find('./devices/entry/vsys/entry/rulebase').append(tree.find('./devices/entry/vsys/entry/rulebase/nat'))
        return ET.tostring(root,encoding='unicode')
    def wait_for(predicate,timeout=15):
        deadline=time.monotonic()+timeout
        while time.monotonic()<deadline:
            if predicate():return
            time.sleep(.2)
        raise AssertionError('Timed out: '+str(runtime.status()))
    try:
        for ns in names:run('ip','netns','add',ns);made.append(ns);run('ip','-n',ns,'link','set','lo','up')
        for port,peer,owner,network in [('p1','lan',lan,'192.0.2'),('p2','wan',wan,'198.51.100')]:
            run('ip','-n',dp,'link','add',port,'type','veth','peer','name',peer)
            run('ip','-n',dp,'link','set',peer,'netns',owner)
            for ns,dev,address in [(dp,port,network+'.1/24'),(owner,peer,network+'.2/24')]:
                run('ip','-n',ns,'address','add',address,'dev',dev);run('ip','-n',ns,'link','set',dev,'up')
            run('ip','-n',owner,'route','add','default','via',network+'.1')
        run('ip','netns','exec',dp,'sysctl','-qw','net.ipv4.ip_forward=1')
        with tempfile.TemporaryDirectory(prefix='ffn-policy-runtime-') as directory:
            path=Path(directory)
            nat.NS=dp;nat.LOCK=path/'lock';nat.STATE=path/'nat.json';nat.BINDINGS=path/'bindings.json';nat.PLATFORM_BINDINGS=path/'provider.json'
            runtime.STATE=nat.COORDINATED=path/'policy.json';runtime.HEALTH=path/'health.json';runtime.DATABASE=path/'sessions.db'
            nat.BINDINGS.write_text(json.dumps({'ethernet1/1':'p1','ethernet1/2':'p2'}))
            setup=('import sys\nfrom pathlib import Path\nsys.path.insert(0,'+repr(str(Path(__file__).resolve().parents[1]/'opt'))+')\n'
                'import ffn_nat_runtime as nat\nimport ffn_security_runtime as runtime\n'
                'nat.NS='+repr(dp)+'\n')
            for name in ('LOCK','STATE','BINDINGS','PLATFORM_BINDINGS','COORDINATED'):
                setup+='nat.'+name+'=Path('+repr(str(getattr(nat,name)))+')\n'
            for name in ('STATE','HEALTH','DATABASE'):
                setup+='runtime.'+name+'=Path('+repr(str(getattr(runtime,name)))+')\n'
            inject=path/'inject-overflow'
            setup+=('import ffn_session_events as events, errno\noriginal_receive=events.receive\n'
                    'def injected_receive(stream):\n'
                    ' marker=Path('+repr(str(inject))+')\n'
                    ' if marker.exists():\n'
                    '  marker.unlink()\n'
                    '  raise OSError(errno.ENOBUFS,"No buffer space available")\n'
                    ' return original_receive(stream)\n'
                    'events.receive=injected_receive\n')
            service=S.Popen(['ip','netns','exec',dp,'python3','-u','-c',setup+'runtime.serve()'],text=True,stdout=S.PIPE,stderr=S.PIPE)
            wait_for(lambda:runtime.status()['available'])
            assert not ping(),'Unconfigured provider admitted transit'
            assert ping('192.0.2.1',3457),'Closed transit gate affected interface-local input'
            with runtime.lock():runtime.apply(dict(revision=0,xml=policy()))
            wait_for(lambda:runtime.status()['applied'])
            assert ping(),'Coordinated Security/NAT did not pass traffic'
            # Restart with live kernel grants; no conntrack flush or fake end.
            service.terminate();out,err=service.communicate(timeout=20)
            assert service.returncode==0,(out,err)
            service=S.Popen(['ip','netns','exec',dp,'python3','-u','-c',setup+'runtime.serve()'],text=True,stdout=S.PIPE,stderr=S.PIPE)
            wait_for(lambda:runtime.status()['applied'])
            assert ping(),'Collector restart did not reconcile live NAT sessions'
            assert json.loads(runtime.HEALTH.read_text())['events']['reconciled_sessions']>=1
            previous=json.loads(runtime.HEALTH.read_text())['events']['recoveries']
            inject.touch();ping(ident=3440)
            wait_for(lambda:json.loads(runtime.HEALTH.read_text()).get('events',{}).get('recoveries',0)>previous)
            wait_for(lambda:runtime.status()['applied'])
            assert ping(),'ENOBUFS recovery did not restore policy forwarding'
            # Exercise batched durable writes while the supervisor also runs
            # nftables/ownership readback. This is an isolated namespace.
            recoveries=json.loads(runtime.HEALTH.read_text())['events']['recoveries']
            burst=run('ip','netns','exec',lan,nat.executable('ping'),'-f','-q','-c','2000','-w','15','198.51.100.2')
            assert ', 0% packet loss' in burst,burst
            assert runtime.status()['applied'],'Event burst expired the forwarding lease'
            assert json.loads(runtime.HEALTH.read_text())['events']['recoveries']==recoveries
            run('ip','netns','exec',dp,nat.executable('conntrack'),'-D','-p','icmp','--orig-src','192.0.2.2')
            def logs():
                j=Journal(runtime.DATABASE,runtime.boot())
                try:return j.recent()
                finally:j.close()
            wait_for(logs)
            assert logs()[0]['reply']['destination']=='198.51.100.1',logs()
            # Invalid new generation must leave the verified generation intact.
            before=runtime.STATE.read_bytes()
            with runtime.lock():
                try:runtime.apply(dict(revision=1,xml=policy().replace('<action>allow</action>','<action>reset-both</action>')))
                except nat.NatError:pass
                else:raise AssertionError('Unsupported action was activated')
            assert before==runtime.STATE.read_bytes(),'Validation altered running generation'
            original_atomic=runtime.atomic
            def fail_state(path,value):
                if path==runtime.STATE:raise OSError('Injected durable-state write failure')
                return original_atomic(path,value)
            runtime.atomic=fail_state
            try:
                with runtime.lock():
                    try:runtime.apply(dict(revision=1,xml=policy('drop')))
                    except OSError:pass
                    else:raise AssertionError('Injected persistence failure was ignored')
            finally:runtime.atomic=original_atomic
            assert before==runtime.STATE.read_bytes(),'Failed apply changed durable generation'
            wait_for(lambda:ping(ident=3461))
            run('ip','netns','exec',dp,nat.executable('conntrack'),'-D','-p','icmp','--orig-src','192.0.2.2')
            # Losing a binding closes transit. Its return resumes the same
            # stored generation without a config rewrite or an owner reset.
            run('ip','-n',dp,'link','set','p1','name','moved')
            time.sleep(2)
            assert not ping(ident=3462),'Lost interface binding retained transit permission'
            run('ip','-n',dp,'link','set','moved','name','p1')
            wait_for(lambda:ping(ident=3463))
            run('ip','netns','exec',dp,nat.executable('conntrack'),'-D','-p','icmp','--orig-src','192.0.2.2')
            service.send_signal(signal.SIGSTOP)
            time.sleep(runtime.LEASE_SECONDS+1)
            assert not ping(ident=3458),'Expired collector lease admitted transit'
            assert ping('192.0.2.1',3459),'Expired lease affected interface-local input'
            service.send_signal(signal.SIGCONT)
            wait_for(lambda:runtime.status()['applied'])
            with runtime.lock():runtime.apply(dict(revision=1,xml=policy('drop')))
            wait_for(lambda:runtime.status()['applied'])
            assert not ping(ident=3460),'Policy revocation did not deny transit'
            # No worker can change NAT independently of Security after adoption.
            with runtime.lock():
                try:nat.apply(dict(revision=nat.saved()['revision'],plan=nat.saved()['plan']))
                except nat.NatError:pass
                else:raise AssertionError('Standalone NAT bypassed coordinated ownership')
            service.terminate();stdout,stderr=service.communicate(timeout=15)
            assert service.returncode==0,(stdout,stderr)
            service=None
            print(json.dumps(dict(coordinated_security_nat=True,session_end=True,lease_expiry=True,
                local_input_isolation=True,invalid_generation_unchanged=True,live_revocation=True,
                persistence_rollback=True,binding_loss_recovery=True,collector_restart_recovery=True,enobufs_recovery=True,
                packet_burst=2000)))
    finally:
        if service is not None and service.poll() is None:
            service.send_signal(signal.SIGCONT);service.terminate()
            try:stdout,stderr=service.communicate(timeout=15)
            except S.TimeoutExpired:service.kill();stdout,stderr=service.communicate()
            if service.returncode:print(stdout,stderr,file=sys.stderr)
        for ns in reversed(made):
            assert ns.startswith('ffn-run-'+token+'-');S.run(['ip','netns','delete',ns],check=True)


if __name__=='__main__':main()
