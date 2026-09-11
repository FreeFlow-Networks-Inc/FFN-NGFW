"""Opt-in root integration test. Only disposable namespaces and veths are used."""
import json
from pathlib import Path
import subprocess as S
import sys
import tempfile
import time
import uuid
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'opt'))
import ffn_linux_network as net


def main():
    token=uuid.uuid4().hex[:8]
    names=['ffn-test-'+token+'-'+s for s in ('dp','left','right')]
    dp,left,right=names
    made=[]
    def run(*args): return S.run(args,check=True,capture_output=True,text=True).stdout
    def ping():
        return S.run(['ip','netns','exec',left,'ping','-c','1','-W','1','198.51.100.2'],capture_output=True).returncode==0
    try:
        for name in names:
            run('ip','netns','add',name);made.append(name)
        for port,peer,owner in [('p1','peer1',left),('p3','peer3',right)]:
            run('ip','-n',dp,'link','add',port,'type','veth','peer','name',peer)
            run('ip','-n',dp,'link','set',peer,'netns',owner)
            run('ip','-n',owner,'link','set',peer,'up')
            run('ip','-n',owner,'link','set','lo','up')
        with tempfile.TemporaryDirectory() as temp:
            net.NS=dp;net.PORT_BACKEND='native'
            net.STATE=Path(temp)/'network.json';net.OVERLAY_STATE=Path(temp)/'overlay.json'
            cfg={'revision':0,'ports':{'p1':{'mode':'l3','addresses':['192.0.2.1/24']},
                                     'p3':{'mode':'l3','addresses':['198.51.100.1/24']}}}
            net.save(cfg);net.start(cfg)
            for owner,peer,address,gateway in [(left,'peer1','192.0.2.2/24','192.0.2.1'),
                                              (right,'peer3','198.51.100.2/24','198.51.100.1')]:
                run('ip','-n',owner,'addr','add',address,'dev',peer)
                run('ip','-n',owner,'route','add','default','via',gateway)
            assert ping(),'native IPv4 routing failed'
            proposed={'revision':0,'ports':{p:{'mode':'l2','vlans':[100],'pvid':100} for p in ('p1','p3')}}
            net.patch(cfg,proposed)
            run('ip','-n',left,'address','add','198.51.100.3/24','dev','peer1')
            deadline=time.monotonic()+45  # Respect normal STP listening/learning.
            while not ping():
                if time.monotonic()>=deadline: raise AssertionError('native L2 switching failed')
                time.sleep(.25)
            cfg=json.loads(net.STATE.read_text())
            net.patch(cfg,{'revision':1,'ports':{'p3':{'mode':'disabled'}}})
            assert not ping(),'disabled interface forwarded traffic'
            print('Native backend: IPv4 routing, L3-to-L2 transition, VLAN access switching and disabled-port enforcement passed')
    except Exception:
        for name in made:
            for query in [('link',),('address',),('route',),('neigh',)]:
                print(name, query, run('ip','-n',name,*query))
        print(run('ip','netns','exec',dp,'bridge','vlan','show'))
        print(run('ip','netns','exec',dp,'bridge','-d','link','show'))
        raise
    finally:
        for name in reversed(made):
            assert name.startswith('ffn-test-'+token+'-')
            S.run(['ip','netns','delete',name],check=True)


if __name__=='__main__': main()
