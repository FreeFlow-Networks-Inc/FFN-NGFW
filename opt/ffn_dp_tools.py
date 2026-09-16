#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Read-only ABI and executable audit for tools required by DP services."""
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess as S
import sys

TOOLS={'ip':['-V'],'ss':['-V'],'tc':['-V'],'bridge':['-V'],'nft':['--version'],
       'conntrack':['-V'],'conntrackd':['-v'],'nfct':['list','version'],'ethtool':['--version'],
       'tcpdump':['--version'],'ping':['-V'],'arping':['-V'],'tracepath':['-V'],
       'traceroute':['--version'],'iperf3':['--version'],'socat':['-V']}
APPLETS=['insmod','modprobe','depmod','modinfo','lsmod','rmmod','sysctl','taskset','nsenter','nslookup','udhcpc','udhcpc6']


def locate(name):
    for prefix in ('/usr/local/ffn-dp/sbin','/usr/local/ffn-dp/bin'):
        path=Path(prefix)/name
        if path.is_file():return str(path)
    return shutil.which(name)


def elf(path):
    with open(path,'rb') as stream:header=stream.read(64)
    if header[:4]!=b'\x7fELF':return {'elf':False}
    return {'elf':True,'bits':{1:32,2:64}.get(header[4]),'byteorder':{1:'little',2:'big'}.get(header[5]),
            'machine':int.from_bytes(header[18:20],'little' if header[5]==1 else 'big')}


def status():
    machine=os.uname().machine;expected='mips' in machine.lower();results={}
    for name,args in TOOLS.items():
        path=locate(name);row={'available':False,'path':path}
        if path:
            try:
                row['abi']=elf(path)
                if expected and row['abi']!={'elf':True,'bits':64,'byteorder':'big','machine':8}:raise ValueError('Expected MIPS64 big-endian n64 executable')
                proc=S.run([path,*args],text=True,capture_output=True,timeout=5)
                row['available']=proc.returncode==0;row['version']=(proc.stdout+proc.stderr).strip().splitlines()[:2]
                row['returncode']=proc.returncode
            except Exception as error:row['error']=str(error)
        results[name]=row
    busybox=shutil.which('busybox')
    applets=S.run([busybox,'--list'],text=True,capture_output=True,timeout=5).stdout.splitlines() if busybox else []
    busyabi=elf(busybox) if busybox else None
    for name in APPLETS:
        results[name]={'available':name in applets and (not expected or busyabi=={'elf':True,'bits':64,'byteorder':'big','machine':8}),
                       'argv':[busybox,name] if busybox else None,'abi':busyabi,'implementation':'busybox'}
    return {'machine':machine,'byteorder':sys.byteorder,'pointer_bits':struct.calcsize('P')*8,
            'target':'mips64eb-n64' if expected else machine,'available':all(r['available'] for r in results.values()),'tools':results}


if __name__=='__main__':
    if sys.argv[1:] not in ([],['status']):raise SystemExit('usage: ffn_dp_tools.py [status]')
    print(json.dumps(status()))
