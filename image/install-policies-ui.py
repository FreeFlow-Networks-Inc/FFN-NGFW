#!/usr/bin/env python3
"""Merge policy UI, daemon ownership, CLI commands and configd validation.

No configuration writes or service restarts. Back up before replacing code.
"""
import argparse
import ast
from pathlib import Path
import shutil
import time


def replace_once(source,old,new):
    if new in source:return source
    if source.count(old)!=1:raise ValueError('Unsupported source boundary: '+old[:90])
    return source.replace(old,new)


def method_range(source,klass,method):
    cls=next(n for n in ast.parse(source).body if isinstance(n,ast.ClassDef) and n.name==klass)
    node=next(n for n in cls.body if isinstance(n,ast.FunctionDef) and n.name==method)
    lines=source.splitlines(keepends=True)
    return sum(map(len,lines[:node.lineno-1])),sum(map(len,lines[:node.end_lineno]))


def merge_manager(live,source):
    for method in ('commit','_collect_paths'):
        a,b=method_range(live,'ConfigManager',method);x,y=method_range(source,'ConfigManager',method)
        live=live[:a]+source[x:y]+live[b:]
    marker='if __name__ == "__main__":'
    hook='from ffn_policy_api import install as _install_policy_api\n_install_policy_api(app, get_current_user, _require_admin, _extension_audit, config_mgr)\n\n'
    if '_install_policy_api' not in live:live=replace_once(live,marker,hook+marker)
    compile(live,'ffn_manager.py','exec');return live


def merge_control(live):
    anchor='        self.handlers: Dict[str, Callable] = {}\n'
    hook="        from ffn_policy_config import PolicyController\n        self.policy = PolicyController(os.getenv('FFN_CONFIG_DIR','/var/lib/ffn-ngfw/config'), commit)\n"
    live=replace_once(live,anchor,anchor+hook)
    anchor='        self.handlers.update({\n'
    live=replace_once(live,anchor,anchor+'            "policy/request":           self.policy.request,\n')
    compile(live,'ffn_controld.py','exec');return live


def merge_configd(live):
    anchor='        # 5. Compute diff vs last-applied (or against empty if forced).\n'
    hook='        # FFN policy activation boundary (before any platform side effects)\n        from ffn_policy_config import configd_validate\n        if not configd_validate(RUNNING_CONFIG, status):\n            return status\n\n'
    live=replace_once(live,anchor,hook+anchor)
    anchor='        logger.info("Validation passed")\n'
    hook="        from ffn_policy_config import require_supported, PolicyError\n        try:\n            require_supported(RUNNING_CONFIG.read_bytes())\n        except PolicyError as error:\n            logger.error('policy: %s', error)\n            sys.exit(5)\n"
    live=replace_once(live,anchor,hook+anchor)
    compile(live,'ffn_configd.py','exec');return live


def merge_cli(live):
    anchor='        cmd, args = tokens[0], tokens[1:]\n'
    hook="""        # FFN shared policy API command hook
        if tokens[:2] in (['show', 'policies'], ['request', 'policies']):
            import importlib.util
            spec = importlib.util.spec_from_file_location('ffn_policy_cli', '/opt/ffn-ngfw-v2/ffn_policy_cli.py')
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            if module.handle(tokens, api, self.token):
                return True
"""
    live=replace_once(live,anchor,hook+anchor)
    compile(live,'ffn-cli','exec');return live


def merge_html(live,source):
    for start,end in [('  policy: [','  objects: ['),('    // Policy tab','    // Objects tab')]:
        if any(s.count(start)!=1 or s.count(end)!=1 for s in (live,source)):raise ValueError('Policy navigation boundaries changed')
        a=live.index(start);b=live.index(end,a);x=source.index(start);y=source.index(end,x)
        live=live[:a]+source[x:y]+live[b:]
    asset='<script src="/static/config-policies.js"></script>'
    if asset not in live:live=replace_once(live,'</head>',asset+'\n</head>')
    return live


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manager',default='/opt/ffn-ngfw-v2');parser.add_argument('--daemons',default='/opt/ffn-ngfw')
    parser.add_argument('--cli',default='/usr/local/bin/ffn-cli');args=parser.parse_args()
    root=Path(__file__).resolve().parents[1];manager=Path(args.manager);daemon=Path(args.daemons);cli=Path(args.cli)
    writes={manager/'ffn_manager.py':merge_manager((manager/'ffn_manager.py').read_text(),(root/'opt/ffn_manager.py').read_text()),
            manager/'static/index.html':merge_html((manager/'static/index.html').read_text(),(root/'static/index.html').read_text()),
            daemon/'ffn_controld.py':merge_control((daemon/'ffn_controld.py').read_text()),
            daemon/'ffn_configd.py':merge_configd((daemon/'ffn_configd.py').read_text()),cli:merge_cli(cli.read_text())}
    for name in ('ffn_policy_api.py','ffn_policy_config.py','ffn_policy_cli.py','ffn_config_objects.py'):
        writes[manager/name]=(root/'opt'/name).read_text()
    writes[daemon/'ffn_policy_config.py']=(root/'opt/ffn_policy_config.py').read_text()
    for name in ('config-policies.js','config-objects.css'):writes[manager/'static'/name]=(root/'static'/name).read_text()
    backup=manager/('policies-backup-'+str(time.time_ns()));backup.mkdir()
    for i,(path,text) in enumerate(writes.items()):
        mode=path.stat().st_mode & 0o777 if path.exists() else 0o644
        if path.exists():shutil.copy2(path,backup/(str(i)+'-'+path.name))
        temp=path.with_name(path.name+'.policy-new');temp.write_text(text);temp.chmod(mode);temp.replace(path)
    print('Installed; backup '+str(backup)+'. Restart controld, configd and manager after validating the running policy report. No reboot required.')


if __name__=='__main__':main()
