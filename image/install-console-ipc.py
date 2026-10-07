#!/usr/bin/env python3
"""Merge console IPC into an existing shell, preserving its command handlers."""
API = '''def api(path: str, method: str = "GET", body: dict = None, token: str = None) -> dict:
    # FFN console transport: local controld only; never HTTPS or a web fallback.
    import importlib.util
    module_path = '/opt/ffn-ngfw/ffn_cli_transport.py'
    spec = importlib.util.spec_from_file_location('ffn_cli_transport', module_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    try:
        return module.request(path, method=method, body=body)
    except (RuntimeError, OSError, ValueError) as error:
        raise APIError(str(error)) from error


'''

MAIN = '''def main():
    signal.signal(signal.SIGTSTP, signal.SIG_IGN)
    # SSH/getty already authenticated this process. Controld derives identity
    # from SO_PEERCRED and rechecks the FFN database role on each command.
    try:
        identity = api('/api/auth/me')
        user = identity['username']
        if identity.get('pw_change_required'):
            print('FFN administrator password change required.')
            current = getpass.getpass('Current FFN password: ')
            new = getpass.getpass('New FFN password: ')
            if new != getpass.getpass('Confirm new FFN password: '):
                raise APIError('Passwords do not match')
            api('/api/auth/change-password', method='POST', body={'current_password':current,'new_password':new})
        session = Session(user, None)
        if len(sys.argv) >= 3 and sys.argv[1] == '-c':
            line = sys.argv[2]
            if shlex.split(line)[:1] in (['maint'], ['debug'], ['shell']):
                raise APIError('Maintenance commands are not available in command mode')
            session._dispatch(line)
            return
        audit('console-session', 'user='+user+' role='+identity['role'])
        session.run()
    except (APIError, OSError, ValueError) as error:
        print('Console access failed: '+str(error), file=sys.stderr)
        raise SystemExit(1)


'''


def merge_cli(source):
    if '# FFN console transport:' in source:return source
    a=source.index('def api(');b=source.index('# ---- Master key verification',a)
    source=source[:a]+API+source[b:]
    a=source.index('def main():');b=source.index('if __name__ == "__main__":',a)
    source=source[:a]+MAIN+source[b:]
    if 'def _cli_api_endpoint():' in source:
        a=source.index('def _cli_api_endpoint():');b=source.index('HISTORY_FILE',a)
        source=source[:a]+source[b:]
    else:
        source=source.replace('FFN_API = os.getenv("FFN_CLI_API", "https://127.0.0.1:8443")\n','')
    a=source.index('def _ssl_ctx():');b=source.index('def api(',a)
    source=source[:a]+source[b:]
    anchor='        cmd, args = tokens[0], tokens[1:]\n'
    if source.count(anchor)!=1:raise ValueError('CLI dispatch changed')
    source=source.replace(anchor,anchor+'''        if cmd in ('maint','debug','shell') and os.getuid() != 0:
            print('Operating-system maintenance is restricted to root.')
            return True
''')
    compile(source,'ffn-cli','exec')
    return source


def merge_controld(source):
    if 'console_server = None' in source:return source
    anchor='    server = await ipc.start()\n'
    if source.count(anchor)!=1:raise ValueError('Control startup changed')
    source=source.replace(anchor,anchor+'''    console_server = None
    if os.getenv('FFN_CONSOLE_ENABLED') == '1':
        from ffn_management_ipc import start_console
        console_server = await start_console()
''')
    anchor='    await server.wait_closed()\n'
    if source.count(anchor)!=1:raise ValueError('Control shutdown changed')
    source=source.replace(anchor,anchor+'''    if console_server:
        console_server.close()
        await console_server.wait_closed()
''')
    compile(source,'ffn_controld.py','exec');return source


def merge_manager(source):
    # Keep upgrades on an older appliance on the same authorization/lock model.
    from pathlib import Path
    import importlib.util
    sibling = Path(__file__).with_name('install-control-hardening.py')
    canonical = Path(__file__).resolve().parents[1] / 'opt/ffn_manager.py'
    if sibling.exists() and canonical.exists():
        spec = importlib.util.spec_from_file_location('ffn_control_hardening', sibling)
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        source = module.merge_manager(source, canonical.read_text())
    if 'from ffn_console_accounts import validate_username' not in source:
        anchor='    uname = (req.username or "").strip()\n'
        if source.count(anchor)!=1:raise ValueError('Manager user creation changed')
        source=source.replace(anchor,anchor+'''    if os.getenv('FFN_CONSOLE_IDENTITIES') == '1':
        from ffn_console_accounts import validate_username
        try: validate_username(uname)
        except ValueError as error: raise HTTPException(422, str(error))
''')
    source=source.replace('    if user.get("role") != "admin":\n        raise HTTPException(status_code=403, detail="Admin role required")\n',
                          '    _require_admin(user)\n')
    if 'app.add_middleware(WebGateway)' in source:return source
    for name in ('_cli_auth_start','startup'):
        anchor='async def '+name+'():\n'
        if source.count(anchor)!=1:raise ValueError('Manager startup changed')
        source=source.replace(anchor,anchor+"    if os.getenv('FFN_MANAGER_FRONTEND') == '1': return\n")
    anchor='if __name__ == "__main__":\n'
    if source.count(anchor)!=1:raise ValueError('Manager entry point changed')
    source=source.replace(anchor,"if os.getenv('FFN_MANAGER_FRONTEND') == '1':\n    from ffn_management_ipc import WebGateway\n    app.add_middleware(WebGateway)\n\n\n"+anchor)
    compile(source,'ffn_manager.py','exec');return source


def main():
    import json
    import os
    from pathlib import Path
    import shutil
    import subprocess
    import time
    if os.getuid()!=0:raise SystemExit('Root required')
    root=Path(__file__).resolve().parents[1]
    def run(*args):return subprocess.check_output(args,text=True,timeout=45)
    pid=run('systemctl','show','ffn-manager-v2','-p','MainPID','--value').strip()
    env=dict(item.split('=',1) for item in Path('/proc/'+pid+'/environ').read_text().split('\0') if '=' in item)
    values={k:v for k,v in env.items() if k.startswith('FFN_') and k not in
            ('FFN_MANAGER_FRONTEND','FFN_CONSOLE_ENABLED','FFN_CONSOLE_IDENTITIES')}
    # Both frontends use the daemon's configured worker selection. Never
    # silently fall back to a direct plane socket after console migration.
    values['FFN_CONTROL_GATEWAY']='controld'
    if any('\n' in v or '\r' in v for v in values.values()):raise ValueError('Multiline service environment unsupported')
    updates={
        '/usr/local/bin/ffn-cli':merge_cli(Path('/usr/local/bin/ffn-cli').read_text()),
        '/opt/ffn-ngfw/ffn_controld.py':merge_controld(Path('/opt/ffn-ngfw/ffn_controld.py').read_text()),
        '/opt/ffn-ngfw-v2/ffn_manager.py':merge_manager(Path('/opt/ffn-ngfw-v2/ffn_manager.py').read_text()),
        '/etc/ffn-ngfw/management-backend.env':'\n'.join(k+'='+json.dumps(v) for k,v in values.items())+'\n',
        '/etc/systemd/system/ffn-managementd.service':(root/'image/ffn-managementd.service').read_text(),
        '/etc/systemd/system/ffn-controld.service.d/50-console.conf':
            '[Unit]\nWants=ffn-managementd.service\nAfter=ffn-managementd.service\n[Service]\nEnvironment=FFN_CONSOLE_ENABLED=1\n',
        '/etc/systemd/system/ffn-manager-v2.service.d/50-backend.conf':
            '[Unit]\nWants=ffn-managementd.service\nAfter=ffn-managementd.service\n[Service]\nEnvironment=FFN_MANAGER_FRONTEND=1\n'}
    for name in ('ffn_management_ipc.py','ffn_cli_transport.py','ffn_console_identity.py','ffn_console_accounts.py','ffn_pam_console.py','ffn_authorization.py','ffn_config_lock.py','ffn_plane_api.py'):
        for base in ('/opt/ffn-ngfw','/opt/ffn-ngfw-v2'):updates[base+'/'+name]=(root/'opt'/name).read_text()
    for name,body in updates.items():
        if name.endswith('.py') or name.endswith('/ffn-cli'):compile(body,name,'exec')
    backup=Path('/var/backups/ffn/console-ipc-'+str(time.time_ns()));backup.mkdir(parents=True)
    manifest={}
    for name,body in updates.items():
        path=Path(name);path.parent.mkdir(parents=True,exist_ok=True);manifest[name]=path.exists()
        if path.exists():
            saved=backup/path.relative_to('/');saved.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(path,saved)
        temp=path.with_name(path.name+'.ipc-new');temp.write_text(body)
        temp.chmod(0o600 if name.endswith('.env') else 0o755 if name.endswith('/ffn-cli') else 0o644)
        temp.replace(path)
    (backup/'manifest.json').write_text(json.dumps(manifest))
    run('systemctl','daemon-reload');run('systemctl','stop','ffn-manager-v2')
    try:
        run('systemctl','enable','ffn-managementd');run('systemctl','restart','ffn-managementd')
        deadline=time.monotonic()+30
        while not Path('/run/ffn-ngfw/management.sock').exists():
            if time.monotonic()>deadline:raise RuntimeError('Management backend failed to start')
            time.sleep(.25)
        run('systemctl','restart','ffn-controld');run('systemctl','start','ffn-manager-v2')
    except Exception:
        run('systemctl','stop','ffn-managementd')
        for name,existed in manifest.items():
            path=Path(name)
            if existed:shutil.copy2(backup/path.relative_to('/'),path)
            else:path.unlink(missing_ok=True)
        run('systemctl','daemon-reload');run('systemctl','restart','ffn-controld');run('systemctl','start','ffn-manager-v2')
        raise
    print('Console uses controld; backend shared with WebUI. Backup: '+str(backup))


if __name__=='__main__':main()
