#!/usr/bin/env python3
"""Merge Virtual Router UI/API changes into an existing manager; no config writes.

Run from this repository with --target /opt/ffn-ngfw-v2. Restart the manager
after installation. Original files are retained in a timestamped backup.
"""
import argparse
import ast
from pathlib import Path
import re
import shutil
import time


API_NAMES = ('_vr_interface_inventory', 'vr_interface_choices', '_validate_vr_route',
             '_vr_platform_managed', 'vr_route_update', 'vr_route_add', 'vr_route_delete',
             'vr_create', 'vr_update')
UI_NAMES = ('loadVirtualRouters', 'vrGridRow', 'vrCardHtml', 'loadVrrStatic',
            'openVRModal', 'editVR', 'saveVR', 'openVRouteModal', 'saveVRoute', 'deleteVRoute')


def python_ranges(source):
    lines=source.splitlines(keepends=True)
    result={}
    for node in ast.parse(source).body:
        if not isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)):continue
        start=min([node.lineno,*[d.lineno for d in node.decorator_list]])-1
        result[node.name]=(sum(map(len,lines[:start])),sum(map(len,lines[:node.end_lineno])))
    return result


def merge_python(live, source):
    original=python_ranges(live);wanted=python_ranges(source);edits=[];new=[]
    for name in API_NAMES:
        a,b=wanted[name];body=source[a:b]
        if name in original:edits.append((*original[name],body))
        else:new.append(body)
    for a,b,body in sorted(edits,reverse=True):live=live[:a]+body+live[b:]
    if new:
        position=python_ranges(live)['vr_route_add'][0]
        live=live[:position]+'\n\n'.join(new)+'\n\n'+live[position:]
    compile(live,'ffn_manager.py','exec')
    return live


def merge_html(live, source):
    for name in UI_NAMES:
        pattern=r'^(?:async )?function '+re.escape(name)+r'\([^\n]*\).*?^}'
        wanted=list(re.finditer(pattern,source,re.M|re.S));old=list(re.finditer(pattern,live,re.M|re.S))
        if len(wanted)!=1 or len(old)!=1:raise ValueError('Expected one UI function: '+name)
        live=live[:old[0].start()]+wanted[0].group()+live[old[0].end():]
    start='<!-- Static Route Modal (per virtual router) -->';end='<!-- Interface Edit Modal -->'
    if live.count(start)!=1 or live.count(end)!=1:raise ValueError('Modal boundaries changed')
    live=live[:live.index(start)]+source[source.index(start):source.index(end)]+live[live.index(end):]
    live=live.replace('<th>Metric</th></tr></thead><tbody id="vrr-static-tbody">',
                      '<th>Metric</th><th>Actions</th></tr></thead><tbody id="vrr-static-tbody">')
    if '/static/vr-interfaces.js' not in live:
        live=live.replace('</body>','<script src="/static/vr-interfaces.js"></script>\n</body>')
    return live


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--target',required=True)
    args=parser.parse_args();target=Path(args.target);source=Path(__file__).resolve().parents[1]
    writes={target/'ffn_manager.py':merge_python((target/'ffn_manager.py').read_text(),(source/'opt/ffn_manager.py').read_text()).encode(),
            target/'static/index.html':merge_html((target/'static/index.html').read_text(),(source/'static/index.html').read_text()).encode(),
            target/'ffn_vr_interfaces.py':(source/'opt/ffn_vr_interfaces.py').read_bytes(),
            target/'static/vr-interfaces.js':(source/'static/vr-interfaces.js').read_bytes()}
    backup=target/('vr-backup-'+str(time.time_ns()))
    for path,data in writes.items():
        if path.exists():
            saved=backup/path.relative_to(target);saved.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(path,saved)
        temp=path.with_name(path.name+'.vr-new');temp.write_bytes(data);temp.chmod(0o644);temp.replace(path)
    print('Installed; backup: '+str(backup)+'. Restart manager; no firewall reboot required.')


if __name__=='__main__':main()
