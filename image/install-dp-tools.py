#!/usr/bin/env python3
"""Install an audited MIPS64eb n64 toolkit into its private dataplane prefix.

Run on the target as root. ELF hashes and ABI are checked before writing.
Existing system tools are preserved; missing command names receive symlinks.
No network configuration or services are changed.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import sys
import tarfile
import time

PREFIX=Path('/usr/local/ffn-dp')
BINARIES={'nft':'sbin','conntrack':'sbin','conntrackd':'sbin','nfct':'sbin','ethtool':'sbin',
          'tcpdump':'bin','ping':'bin','arping':'bin','tracepath':'bin','traceroute':'bin','iperf3':'bin','socat':'bin'}


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('archive',type=Path);args=p.parse_args()
    if os.geteuid()!=0 or 'mips' not in os.uname().machine.lower() or sys.byteorder!='big' or struct.calcsize('P')!=8:raise SystemExit('Run as root on MIPS64 big-endian n64')
    if PREFIX.is_symlink():raise SystemExit('Private prefix must not be a symlink')
    with tarfile.open(args.archive) as archive:
        members=archive.getmembers();names={m.name:m for m in members}
        for m in members:
            if m.name!='usr/local/ffn-dp' and not m.name.startswith('usr/local/ffn-dp/'):raise SystemExit('Archive escapes private prefix')
            if '..' in Path(m.name).parts or m.isdev() or m.isfifo():raise SystemExit('Unsafe archive entry')
            if m.issym() and (m.linkname.startswith('/') or '..' in Path(m.linkname).parts):raise SystemExit('Unsafe archive symlink')
        manifest=json.load(archive.extractfile('usr/local/ffn-dp/manifest.json'))
        if manifest['target']!='mips64-linux-gnuabi64' or any(p['status']!='built' for p in manifest['packages'].values()):raise SystemExit('Incomplete MIPS64eb build')
        for relative,expected in manifest['elf_files'].items():
            data=archive.extractfile('usr/local/ffn-dp/'+relative).read()
            if hashlib.sha256(data).hexdigest()!=expected or data[:6]!=b'\x7fELF\x02\x02' or int.from_bytes(data[18:20],'big')!=8:raise SystemExit('ELF hash or ABI mismatch: '+relative)
        backup=Path('/var/backups/ffn/dp-tools-'+str(time.time_ns()))
        if PREFIX.exists():shutil.copytree(PREFIX,backup,symlinks=True)
        selected=[m for m in members if any(m.name.startswith('usr/local/ffn-dp/'+d+'/') for d in ('bin','sbin','lib','share/licenses')) or m.name=='usr/local/ffn-dp/manifest.json']
        archive.extractall('/',members=selected,filter='data')
    for name,directory in BINARIES.items():
        target=PREFIX/directory/name
        if not target.is_file():raise SystemExit('Missing installed tool: '+name)
        alias=Path('/usr')/directory/name
        if not alias.exists() and not alias.is_symlink():alias.symlink_to(target)
    for name in ('insmod','modprobe','depmod','modinfo','lsmod','rmmod','sysctl','taskset','nsenter','nslookup','udhcpc','udhcpc6'):
        alias=Path('/usr/bin' if name in ('taskset','nsenter','nslookup') else '/usr/sbin')/name
        if not alias.exists() and not alias.is_symlink():alias.symlink_to('/usr/bin/busybox')
    print(json.dumps({'installed':True,'elf_files':len(manifest['elf_files']),'backup':str(backup),'reboot_required':False}))


if __name__=='__main__':main()
