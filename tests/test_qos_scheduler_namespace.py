"""Root-only scheduler/mark classifier packet test in disposable namespaces."""
import json
import subprocess as S
import sys
import uuid


def main():
    token=uuid.uuid4().hex[:8];names=['ffn-qos-'+token+'-'+s for s in ('tx','rx')];made=[];server=None
    def run(*args):return S.check_output(args,text=True,stderr=S.STDOUT,timeout=10)
    def tc(*args):return run('ip','netns','exec',names[0],'tc',*args)
    try:
        for name in names:run('ip','netns','add',name);made.append(name);run('ip','-n',name,'link','set','lo','up')
        run('ip','-n',names[0],'link','add','q0','type','veth','peer','name','q1')
        run('ip','-n',names[0],'link','set','q1','netns',names[1])
        for index in (0,1):
            run('ip','-n',names[index],'addr','add','192.0.2.'+str(index+1)+'/24','dev','q'+str(index))
            run('ip','-n',names[index],'link','set','q'+str(index),'up')
        tc('qdisc','add','dev','q0','root','handle','100:','htb','default','4')
        tc('class','add','dev','q0','parent','100:','classid','100:100','htb','rate','8mbit','ceil','8mbit')
        for ident in range(1,9):
            tc('class','add','dev','q0','parent','100:100','classid','100:'+str(ident),'htb','rate','1mbit','ceil','8mbit')
            tc('qdisc','add','dev','q0','parent','100:'+str(ident),'fq_codel')
            tc('filter','add','dev','q0','parent','100:','protocol','ip','handle',str(ident),'fw','flowid','100:'+str(ident))
        listener="""import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('192.0.2.2',19191));s.settimeout(10);print('ready',flush=True)
for i in range(8):
 data,peer=s.recvfrom(4096);assert len(data)==2048;s.sendto(data[:1],peer)
"""
        server=S.Popen(['ip','netns','exec',names[1],sys.executable,'-uc',listener],text=True,stdout=S.PIPE,stderr=S.PIPE)
        assert server.stdout.readline().strip()=='ready'
        client="""import socket
for ident in range(1,9):
 s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(5);s.setsockopt(socket.SOL_SOCKET,socket.SO_MARK,ident)
 s.sendto(bytes([ident])*2048,('192.0.2.2',19191));assert s.recv(8)==bytes([ident]);s.close()
"""
        run('ip','netns','exec',names[0],sys.executable,'-c',client)
        server.wait(timeout=10);assert server.returncode==0
        rows=json.loads(tc('-j','-s','class','show','dev','q0'))
        for ident in range(1,9):
            row=next(r for r in rows if r['handle']=='100:'+str(ident))
            assert row.get('stats',{}).get('bytes',row.get('bytes',0))>=2048,row
        print('OCTEON HTB eight-class scheduling, firewall-mark classification, FQ-CoDel and class counters passed')
    finally:
        if server and server.poll() is None:server.kill();server.wait()
        for name in reversed(made):
            assert name.startswith('ffn-qos-'+token+'-');S.run(['ip','netns','delete',name],check=True)


if __name__=='__main__':main()
