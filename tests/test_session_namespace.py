"""Native conntrack labels, NAT, replies and durable end records; root required."""
import json
from pathlib import Path
import subprocess as S
import sys
import tempfile
import uuid
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'opt'))
from ffn_security_nft import render
from ffn_nat_runtime import executable
from test_policy_plan import configuration


def main():
    token=uuid.uuid4().hex[:8];names=['ffn-log-'+token+'-'+n for n in ('dp','lan','wan')];dp,lan,wan=names;made=[];collector=None
    def run(*args,text=None):
        p=S.run(args,input=text,text=True,capture_output=True,timeout=10)
        if p.returncode:raise RuntimeError(p.stderr)
        return p.stdout
    try:
        for ns in names:run('ip','netns','add',ns);made.append(ns);run('ip','-n',ns,'link','set','lo','up')
        for port,peer,owner,network in [('p1','lan',lan,'192.0.2'),('p2','wan',wan,'198.51.100')]:
            run('ip','-n',dp,'link','add',port,'type','veth','peer','name',peer)
            run('ip','-n',dp,'link','set',peer,'netns',owner)
            for ns,dev,address in [(dp,port,network+'.1/24'),(owner,peer,network+'.2/24')]:
                run('ip','-n',ns,'address','add',address,'dev',dev);run('ip','-n',ns,'link','set',dev,'up')
            run('ip','-n',owner,'route','add','default','via',network+'.1')
        for setting in ('net.ipv4.ip_forward=1','net.netfilter.nf_conntrack_acct=1','net.netfilter.nf_conntrack_events=1'):
            run('ip','netns','exec',dp,'sysctl','-qw',setting)
        links={r['ifname']:r['ifindex'] for r in json.loads(run('ip','-n',dp,'-j','link'))}
        mapping={'ethernet1/1':links['p1'],'ethernet1/2':links['p2']}
        tokens={('vsys1','rule-0'):51,('implicit','intrazone-default'):52}
        script=render(configuration('security',{'action':'allow','log-end':'yes'}),mapping,tokens)['script']
        script+='table ip test_nat {\n chain postrouting { type nat hook postrouting priority srcnat; policy accept; oifname "p2" masquerade; }\n}\n'
        run('ip','netns','exec',dp,executable('nft'),'-f','-',text=script)
        with tempfile.TemporaryDirectory(prefix='ffn-event-journal-') as directory:
            code='''import sys,select,time,json
from ffn_session_events import subscribe,receive,Journal
s=subscribe();j=Journal(sys.argv[1],'test-boot')
j.register({51:dict(scope='vsys1',name='rule-0',revision=1,logging=dict(start=False,end=True))})
print('ready',flush=True);deadline=time.monotonic()+15
while time.monotonic()<deadline:
 if select.select([s],[],[],1)[0]:
  for event in receive(s):j.record(event)
  rows=j.recent()
  if rows:
   print(json.dumps(rows[0]),flush=True);break
else:raise RuntimeError('No labelled session-end event')
j.close();s.close()
'''
            code='sys_path='+repr(str(Path(__file__).resolve().parents[1]/'opt'))+'\nimport sys\nsys.path.insert(0,sys_path)\n'+code
            collector=S.Popen(['ip','netns','exec',dp,'python3','-u','-c',code,str(Path(directory)/'sessions.db')],text=True,stdout=S.PIPE,stderr=S.PIPE)
            import select
            assert select.select([collector.stdout],[],[],5)[0],'Collector did not start'
            assert collector.stdout.readline().strip()=='ready'
            run('ip','netns','exec',lan,executable('ping'),'-c','1','-W','2','-e','3311','198.51.100.2')
            run('ip','netns','exec',dp,executable('conntrack'),'-D','-p','icmp','--orig-src','192.0.2.2')
            stdout,stderr=collector.communicate(timeout=18)
            assert collector.returncode==0,stderr
            row=json.loads(stdout);assert row['token']==51,row
            assert row['original']['source']=='192.0.2.2',row
            assert row['reply']['destination']=='198.51.100.1',row
            assert row['counters']['original']['packets']>=1 and row['counters']['reply']['packets']>=1,row
            assert row['started'] is not None and row['ended']>=row['started'],row
            print(json.dumps(dict(native_session_end=True,nat_tuple=True,reply_counters=True,rule_generation=row['rule']['revision'],token=row['token'])))
    finally:
        if collector is not None and collector.poll() is None:collector.kill();collector.communicate()
        for ns in reversed(made):
            assert ns.startswith('ffn-log-'+token+'-');S.run(['ip','netns','delete',ns],check=True)


if __name__=='__main__':main()
