#!/usr/bin/env python3
"""Merge Objects pages/API without replacing unrelated live manager changes.

Run with --target /opt/ffn-ngfw-v2 and restart only ffn-manager-v2 afterward.
Configuration files and runtime engines are never modified by this installer.
"""
import argparse
from pathlib import Path
import shutil
import time


def replace_section(live, source, start, end):
    for text in (live,source):
        if text.count(start)!=1 or text.count(end)!=1:
            raise ValueError('Unexpected source boundaries: '+start)
    a=live.index(start);b=live.index(end,a)
    return live[:a]+source[source.index(start):source.index(end,source.index(start))]+live[b:]


def merge_html(live, source):
    for start,end in [('  objects: [','  network: ['),
                      ("    'addresses':", "    'threat-sigs':"),
                      ('/* ---- Objects > Addresses ---- */','/* ---- Objects > Threat Signatures ---- */')]:
        live=replace_section(live,source,start,end)
    for asset in ('<script src="/static/config-objects.js"></script>',
                  '<link rel="stylesheet" href="/static/config-objects.css">'):
        if asset not in live: live=live.replace('</head>',asset+'\n</head>')
    return live


def merge_python(live):
    if '_install_object_api' not in live:
        hook='from ffn_config_objects import install as _install_object_api\n_install_object_api(app, get_current_user, _require_admin, _extension_audit, config_mgr, CANDIDATE_CONFIG)\n\n'
        marker='if __name__ == "__main__":'
        if live.count(marker)!=1: raise ValueError('Manager entry point not found')
        live=live.replace(marker,hook+marker)
    compile(live,'ffn_manager.py','exec')
    return live


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--target',required=True)
    args=parser.parse_args();target=Path(args.target);root=Path(__file__).resolve().parents[1]
    writes={'ffn_manager.py':merge_python((target/'ffn_manager.py').read_text()).encode(),
            'static/index.html':merge_html((target/'static/index.html').read_text(),(root/'static/index.html').read_text()).encode()}
    for name in ('ffn_config_objects.py','ffn_object_schema.py'):writes[name]=(root/'opt'/name).read_bytes()
    for name in ('config-objects.js','config-objects.css'):writes['static/'+name]=(root/'static'/name).read_bytes()
    backup=target/('objects-backup-'+str(time.time_ns()))
    for name,data in writes.items():
        path=target/name
        if path.exists():
            saved=backup/name;saved.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(path,saved)
        temp=path.with_name(path.name+'.objects-new');temp.write_bytes(data);temp.chmod(0o644);temp.replace(path)
    print('Installed. Backup: '+str(backup)+'. Restart ffn-manager-v2; no firewall reboot required.')


if __name__=='__main__':main()
