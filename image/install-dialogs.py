#!/usr/bin/env python3
"""Install dialog layers and VR candidate saves without rewriting unrelated UI.

Backs up changed files. Does not restart services or alter configuration data.
"""
import argparse
import ast
from pathlib import Path
import re
import shutil
import time

MANAGER_FUNCTIONS = ('iface_set_vr', 'vr_list', 'vr_get', 'vr_create', 'vr_update',
    'vr_delete', 'vr_get_routing', 'vr_set_routing', 'vr_routes_list',
    'vr_route_add', 'vr_route_update', 'vr_route_delete')
HELPERS = ('_vr_candidate_seed', '_vr_candidate_list', '_vr_candidate_get', '_vr_candidate_edit')


def function(source, name):
    node = next(n for n in ast.parse(source).body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == name)
    lines = source.splitlines(keepends=True)
    return ''.join(lines[node.lineno - 1:node.end_lineno])


def merge_manager(live, source):
    for name in MANAGER_FUNCTIONS:
        old = function(live, name)
        live = live.replace(old, function(source, name), 1)
    for name in HELPERS:
        replacement = function(source, name)
        try: old = function(live, name)
        except StopIteration:
            marker = '@app.get("/api/network/virtual-routers")'
            if live.count(marker) != 1: raise ValueError('Virtual router endpoint boundary changed')
            live = live.replace(marker, replacement + '\n\n' + marker, 1)
        else: live = live.replace(old, replacement, 1)
    compile(live, 'ffn_manager.py', 'exec')
    return live


def js_function(source, name):
    match = re.search(r'^(?:async )?function ' + re.escape(name) + r'\(', source, re.M)
    if match is None: raise ValueError('Missing dialog function ' + name)
    end = source.index('\n}\n', match.start()) + 3
    return source[match.start():end]


def merge_html(live, source):
    for name in ('openVrRouting', 'loadVrRouting', 'saveVrRouting', 'saveVR', 'openVRouteModal'):
        live = live.replace(js_function(live, name), js_function(source, name), 1)
    for callback in ('saveVRoute()', 'saveVR()', 'saveIface()', "saveAlias('${panName}')", 'saveJumbo()'):
        live = re.sub(r'(onclick="' + re.escape(callback) + r'">)Save(?: to Candidate)?</button>', r'\1OK</button>', live)
    live = live.replace('>Save to Candidate</button>', '>OK</button>')
    legacy = """document.addEventListener('click',e=>{
  if (e.target.classList.contains('modal-overlay')) e.target.classList.remove('show');
});
document.addEventListener('keydown',e=>{
  if (e.key==='Escape') document.querySelectorAll('.modal-overlay.show').forEach(m=>m.classList.remove('show'));
});"""
    live = live.replace(legacy, '// modal-layers.js owns backdrop/Escape handling for the topmost dialog.')
    if "querySelectorAll('.modal-overlay.show').forEach" in live:
        raise ValueError('Unsupported legacy Escape handler; inspect before installation')
    css = '<link rel="stylesheet" href="/static/modal-layers.css">'
    script = '<script src="/static/modal-layers.js"></script>'
    if css not in live: live = live.replace('</head>', css + '\n</head>', 1)
    if script not in live: live = live.replace('</body>', script + '\n</body>', 1)
    return live


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manager', default='/opt/ffn-ngfw-v2')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]; target = Path(args.manager)
    writes = {
        target/'ffn_manager.py': merge_manager((target/'ffn_manager.py').read_text(encoding='utf-8'), (root/'opt/ffn_manager.py').read_text(encoding='utf-8')),
        target/'static/index.html': merge_html((target/'static/index.html').read_text(encoding='utf-8'), (root/'static/index.html').read_text(encoding='utf-8')),
        target/'ffn_vr_candidate.py': (root/'opt/ffn_vr_candidate.py').read_text(encoding='utf-8')}
    for name in ('modal-layers.js', 'modal-layers.css'):
        writes[target/'static'/name] = (root/'static'/name).read_text(encoding='utf-8')
    backup = target/('dialogs-backup-' + str(time.time_ns())); backup.mkdir()
    for i, (path, text) in enumerate(writes.items()):
        mode = path.stat().st_mode & 0o777 if path.exists() else 0o644
        if path.exists(): shutil.copy2(path, backup/(str(i) + '-' + path.name))
        temp = path.with_name(path.name + '.dialogs-new')
        temp.write_text(text, encoding='utf-8'); temp.chmod(mode); temp.replace(path)
    print('Installed; backup: ' + str(backup) + '. Restart manager to load candidate saves. No reboot required.')


if __name__ == '__main__': main()
