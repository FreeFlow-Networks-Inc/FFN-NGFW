"""Real IPv4 stateful forwarding in disposable namespaces; root required."""
import json
from pathlib import Path
import subprocess as S
import sys
import uuid
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'opt'))
from ffn_security_nft import render
from ffn_nat_runtime import executable
from test_policy_plan import configuration


def main():
    token=uuid.uuid4().hex[:8];names=['ffn-sec-'+token+'-'+n for n in ('dp','lan','wan')];dp,lan,wan=names;made=[]
    def run(*args,text=None):
        result=S.run(args,input=text,text=True,capture_output=True,timeout=10)
        if result.returncode:raise RuntimeError(result.stderr)
        return result.stdout
    def ping(ns,destination,ident):
        return S.run(['ip','netns','exec',ns,executable('ping'),'-c','1','-W','1','-e',str(ident),destination],capture_output=True,timeout=5).returncode==0
    try:
        for ns in names:run('ip','netns','add',ns);made.append(ns);run('ip','-n',ns,'link','set','lo','up')
        for port,peer,owner,network in [('p1','lan',lan,'192.0.2'),('p2','wan',wan,'198.51.100')]:
            run('ip','-n',dp,'link','add',port,'type','veth','peer','name',peer)
            run('ip','-n',dp,'link','set',peer,'netns',owner)
            for ns,dev,address in [(dp,port,network+'.1/24'),(owner,peer,network+'.2/24')]:
                run('ip','-n',ns,'address','add',address,'dev',dev);run('ip','-n',ns,'link','set',dev,'up')
            run('ip','-n',owner,'route','add','default','via',network+'.1')
        run('ip','netns','exec',dp,'sysctl','-qw','net.ipv4.ip_forward=1')
        links={r['ifname']:r['ifindex'] for r in json.loads(run('ip','-n',dp,'-j','link'))}
        mapping={'ethernet1/1':links['p1'],'ethernet1/2':links['p2']}
        present=False
        def apply(*rules):
            nonlocal present
            xml=configuration('security',*[dict(rule,**{'log-end':'no'}) for rule in rules])
            script=('delete table inet ffn_security\n' if present else '')+render(xml,mapping)['script']
            run('ip','netns','exec',dp,executable('nft'),'-c','-f','-',text=script)
            run('ip','netns','exec',dp,executable('nft'),'-f','-',text=script);present=True
        assert ping(lan,'198.51.100.2',3200),'Test topology has no return route'
        apply({'action':'drop'})
        assert not ping(lan,'198.51.100.2',3201),'Explicit drop allowed transit'
        apply({'action':'allow'})
        assert ping(lan,'198.51.100.2',3202),'Stateful allow or reply grant failed'
        assert not ping(wan,'192.0.2.2',3203),'Reverse unsolicited traffic bypassed policy'
        assert ping(lan,'192.0.2.1',3204),'Transit policy affected interface-local input'
        apply({'action':'drop'},{'action':'allow'})
        assert not ping(lan,'198.51.100.2',3202),'Existing grant survived policy revocation'
        apply({'action':'allow','service':['web']})
        assert not ping(lan,'198.51.100.2',3205),'TCP service rule matched ICMP'
        apply({'action':'allow'})
        # A platform guard following the Security chain accepts only the grant
        # marker. Without a Security table/grant, aggregate transit stays closed.
        guard='table inet test_guard {\n chain forward {\n type filter hook forward priority -250; policy accept;\n meta mark & 0x80000000 == 0 counter drop;\n }\n}\n'
        run('ip','netns','exec',dp,executable('nft'),'-f','-',text=guard)
        assert ping(lan,'198.51.100.2',3206),'Granted packet failed following transit guard'
        run('ip','netns','exec',dp,executable('nft'),'delete','table','inet','ffn_security');present=False
        assert not ping(lan,'198.51.100.2',3207),'Guard allowed transit after Security owner removal'
        print('Native stateful allow/reply, unsolicited deny, ordering, revocation, service match, input isolation and transit guard passed',flush=True)
    finally:
        for ns in reversed(made):
            assert ns.startswith('ffn-sec-'+token+'-');S.run(['ip','netns','delete',ns],check=True)


if __name__=='__main__':main()
