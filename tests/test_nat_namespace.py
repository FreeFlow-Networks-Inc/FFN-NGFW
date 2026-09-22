"""Root-only packet test. Uses disposable namespaces; never the production table."""
import copy
import json
from pathlib import Path
import subprocess as S
import sys
import tempfile
import uuid
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'opt'))
import ffn_nat_runtime as nat


def main():
    token=uuid.uuid4().hex[:8];names=['ffn-nat-'+token+'-'+s for s in ('dp','lan','wan')];dp,lan,wan=names;made=[]
    def run(*args):return S.run(args,check=True,text=True,capture_output=True,timeout=10).stdout
    def ping(ident):return S.run(['ip','netns','exec',lan,nat.executable('ping'),'-c','1','-W','1','-e',str(ident),'198.51.100.2'],capture_output=True,timeout=5).returncode==0
    base=dict(name='outbound',scope='vsys1',position=1,ingress=['ethernet1/1'],egress=['ethernet1/2'],source=['192.0.2.0/24'],destination=['0.0.0.0/0'],services=[dict(protocol='any',source_ports=[],destination_ports=[])],snat=dict(type='masquerade',interface='ethernet1/2'),dnat=None)
    try:
        for ns in names:run('ip','netns','add',ns);made.append(ns);run('ip','-n',ns,'link','set','lo','up')
        for port,peer,owner,network in [('p1','lan',lan,'192.0.2'),('p2','wan',wan,'198.51.100')]:
            run('ip','-n',dp,'link','add',port,'type','veth','peer','name',peer)
            run('ip','-n',dp,'link','set',peer,'netns',owner)
            for ns,dev,address in [(dp,port,network+'.1/24'),(owner,peer,network+'.2/24')]:
                run('ip','-n',ns,'address','add',address,'dev',dev);run('ip','-n',ns,'link','set',dev,'up')
        run('ip','-n',lan,'route','add','default','via','192.0.2.1')
        run('ip','netns','exec',dp,sys.executable,'-c',"from pathlib import Path;Path('/proc/sys/net/ipv4/ip_forward').write_text('1')")
        with tempfile.TemporaryDirectory() as temp:
            nat.NS=dp;nat.STATE=Path(temp)/'nat.json';nat.BINDINGS=Path(temp)/'interfaces.json'
            nat.PLATFORM_BINDINGS=Path(temp)/'platform-bindings.json'
            nat.COORDINATED=Path(temp)/'coordinated-policy.json'
            nat.BINDINGS.write_text(json.dumps({'ethernet1/1':'p1','ethernet1/2':'p2'}))
            def apply(rows):return nat.apply({'revision':nat.saved()['revision'],'plan':{'version':1,'rules':rows}})
            assert not ping(1100),'WAN has no return route before source NAT'
            apply([base]);assert ping(1101),'Masquerade did not translate ICMP/reply'
            observed=nat.status();assert observed['applied']
            assert observed['usage'][0]['available'] and observed['usage'][0]['packets']>=1 and observed['usage'][0]['bytes']>0,observed['usage']
            print('Native ICMP source NAT, return translation and per-rule initial-packet counters passed',flush=True)
            exempt=copy.deepcopy(base);exempt.update(name='exception',snat={'type':'none'},destination=['198.51.100.2/32'])
            apply([exempt,base]);assert not ping(1102),'First-match no-NAT exception failed'
            apply([base]);assert ping(1103),'Removing no-NAT exception failed'
            static=copy.deepcopy(base);static.update(source=['192.0.2.2/32'],snat={'type':'static','address':'198.51.100.1'})
            apply([static]);assert ping(1104),'Static one-to-one SNAT failed'
            for index,(proto,combined) in enumerate([('udp',False),('tcp',False),('udp',True),('tcp',True)]):
                original=18080+index;translated=19090+index
                rule=copy.deepcopy(base);rule.update(name='inbound',ingress=['ethernet1/2'],source=['0.0.0.0/0'],destination=['198.51.100.1/32'],services=[dict(protocol=proto,source_ports=[],destination_ports=[str(original)])],snat={'type':'masquerade','interface':'ethernet1/1'} if combined else {'type':'none'},dnat={'address':'192.0.2.2','port':translated})
                apply([rule])
                server="import socket,json; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM if "+repr(proto)+"=='udp' else socket.SOCK_STREAM);s.settimeout(6);s.bind(('192.0.2.2',"+str(translated)+"));"+('s.listen();' if proto=='tcp' else '')+"print('ready',flush=True);"+('c,a=s.accept();d=c.recv(128);c.sendall(json.dumps(a).encode());c.close()' if proto=='tcp' else 'd,a=s.recvfrom(128);s.sendto(json.dumps(a).encode(),a)')
                proc=S.Popen(['ip','netns','exec',lan,sys.executable,'-uc',server],stdout=S.PIPE,stderr=S.PIPE,text=True)
                try:
                    assert proc.stdout.readline().strip()=='ready'
                    client="import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM if "+repr(proto)+"=='udp' else socket.SOCK_STREAM);s.settimeout(5);s.connect(('198.51.100.1',"+str(original)+"));s.send(b'nat-test');print(s.recv(128).decode())"
                    peer=json.loads(run('ip','netns','exec',wan,sys.executable,'-c',client))
                    assert peer[0]==('192.0.2.1' if combined else '198.51.100.2'),peer
                    proc.wait(timeout=7);assert proc.returncode==0
                finally:
                    if proc.poll() is None:proc.kill();proc.wait()
                print(proto+' '+('combined SNAT/DNAT' if combined else 'destination NAT')+' port forwarding and reply passed',flush=True)
            # Two independently addressed backends verify real distribution and
            # stable reverse translation, including a translated UDP port.
            run('ip','-n',lan,'address','add','192.0.2.3/24','dev','lan')
            for method in ('round-robin','source-ip-hash','ip-hash'):
                distributed=copy.deepcopy(base)
                distributed.update(name='distributed',ingress=['ethernet1/2'],source=['0.0.0.0/0'],destination=['198.51.100.1/32'],
                    services=[dict(protocol='udp',source_ports=[],destination_ports=['18100'])],snat={'type':'none'},
                    dnat=dict(type='dynamic',addresses=['192.0.2.2','192.0.2.3'],method=method,port=19100))
                apply([distributed])
                server="""import socket,select,time
sockets=[]
for address in ('192.0.2.2','192.0.2.3'):
 s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind((address,19100));sockets.append(s)
print('ready',flush=True)
for i in range(12):
 ready,_,_=select.select(sockets,[],[],8)
 if not ready:raise RuntimeError('missing translated request')
 for s in ready:
  message,peer=s.recvfrom(128);s.sendto(s.getsockname()[0].encode(),peer)
"""
                proc=S.Popen(['ip','netns','exec',lan,sys.executable,'-uc',server],stdout=S.PIPE,stderr=S.PIPE,text=True)
                try:
                    assert proc.stdout.readline().strip()=='ready'
                    client="""import socket,json
results=[]
for i in range(6):
 s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(4);s.connect(('198.51.100.1',18100))
 pair=[]
 for j in range(2):s.send(b'distribution');pair.append(s.recv(128).decode())
 assert pair[0]==pair[1],'existing connection changed backend'
 results.append(pair[0]);s.close()
print(json.dumps(results))
"""
                    selected=json.loads(run('ip','netns','exec',wan,sys.executable,'-c',client))
                    if method=='round-robin':assert selected.count('192.0.2.2')==selected.count('192.0.2.3')==3,selected
                    else:assert len(set(selected))==1,selected
                    proc.wait(timeout=10);assert proc.returncode==0
                finally:
                    if proc.poll() is None:proc.kill();proc.wait()
                print(method+' destination distribution, port translation and connection affinity passed',flush=True)
            apply([]);assert not ping(1105),'Removed NAT rules continued to translate new connections'
            assert nat.status()['usage']==[],'Deleted rules retained stale usage'
            apply([base]);nat.nft(['delete','table','ip',nat.TABLE]);nat.restore()
            assert ping(1106),'Boot replay did not restore source NAT'
            print('No-NAT ordering, static SNAT, deletion and empty-plan application passed',flush=True)
    except Exception:
        print(run('ip','netns','exec',dp,nat.executable('nft'),'-a','list','ruleset'),flush=True)
        print(run('ip','-n',dp,'route','show'),flush=True)
        raise
    finally:
        for ns in reversed(made):
            assert ns.startswith('ffn-nat-'+token+'-');S.run(['ip','netns','delete',ns],check=True)


if __name__=='__main__':main()
