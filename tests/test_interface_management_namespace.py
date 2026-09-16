#!/usr/bin/env python3
"""Root-only packet regression in disposable namespaces; no live port changes."""
import copy
import os
from pathlib import Path
import subprocess as s
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'opt'))
import ffn_interface_management as m


def main():
    base='ffn-imp-test-'+str(os.getpid());host=base+'h';fw=base+'f'
    def run(*args):return s.run(args,check=True,capture_output=True,text=True,timeout=10)
    def ping(address, expected):
        result=s.run(['ip','netns','exec',host,'/usr/local/ffn-dp/bin/ping','-n','-c','1','-W','1',address],capture_output=True,text=True,timeout=4)
        assert (result.returncode==0)==expected, result.stdout+result.stderr
    try:
        for ns in (host,fw):run('ip','netns','add',ns);run('ip','-n',ns,'link','set','lo','up')
        run('ip','-n',host,'link','add','sender','type','veth','peer','name','p1','netns',fw)
        for ns,dev,address in ((host,'sender','192.0.2.2/24'),(fw,'p1','192.0.2.1/24')):
            run('ip','-n',ns,'addr','add',address,'dev',dev);run('ip','-n',ns,'link','set',dev,'up')
        run('ip','-n',fw,'addr','add','198.51.100.1/32','dev','lo')
        run('ip','-n',host,'route','add','198.51.100.1/32','via','192.0.2.1')
        # Transit policy is drop-all; the interface has no zone membership.
        run('ip','netns','exec',fw,'/usr/local/ffn-dp/sbin/nft','add','table','inet','security')
        run('ip','netns','exec',fw,'/usr/local/ffn-dp/sbin/nft','add','chain','inet','security','forward','{ type filter hook forward priority 0; policy drop; }')
        settings={'addresses':['192.0.2.1/24'],'management':{'profile':'PING-ONLY','ping':True,'sources':[],'tcp':[],'udp':[]}}
        m.apply(fw,'p1',settings);ping('192.0.2.1',True);ping('198.51.100.1',False)
        settings['management']['sources']=['192.0.2.3/32']
        m.apply(fw,'p1',settings);ping('192.0.2.1',False)
        settings['management']['sources']=['192.0.2.2/32']
        m.apply(fw,'p1',settings);ping('192.0.2.1',True)
        settings['management']['ping']=False
        m.apply(fw,'p1',settings);ping('192.0.2.1',False)
        settings['management']['ping']=True
        m.apply(fw,'p1',settings);ping('192.0.2.1',True)
        print('PASS: local Ping independent of transit policy/zones; source restrictions, profile revocation, destination ownership')
    finally:
        for ns in (host,fw):s.run(['ip','netns','delete',ns],capture_output=True)


if __name__=='__main__':main()
