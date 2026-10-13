#!/usr/bin/env python3
"""Apply the FFN Protect management-plane edits to an installed appliance by anchor, with backups.

Run on the MP from the directory holding the shipped files (opt/, static/, management/, ffn-protect-mp).
Every anchor must match exactly once or nothing in that file is touched. Services are not restarted
here: ffn-managementd is restarted by the caller; ffn-plane@mp and ffn-configd are the operator's call.
"""
import json
import shutil
import sys
from pathlib import Path

STAMP = '.bak-20261013'
MANAGER = Path('/opt/ffn-ngfw-v2')
CORE = Path('/opt/ffn-ngfw')
PLATFORM = Path('/opt/ffn-platforms/pa5200-management')


def patch(path, edits):
    path = Path(path)
    text = path.read_text()
    for old, new in edits:
        if text.count(old) != 1:
            if text.count(new) == 1 and new.count(old) == 1:
                print('already patched', path)
                return
            raise SystemExit('anchor count %d in %s: %r' % (text.count(old), path, old[:70]))
    shutil.copy2(path, str(path) + STAMP)
    for old, new in edits:
        text = text.replace(old, new)
    path.write_text(text)
    print('patched', path)


def install(source, target, mode=0o644):
    target = Path(target)
    if target.exists() and not Path(str(target) + STAMP).exists():   # a rerun keeps the original backup
        shutil.copy2(target, str(target) + STAMP)
    shutil.copyfile(source, target)
    target.chmod(mode)
    print('installed', target)


# --- new files
for name in ('ffn_protect_intent.py', 'ffn_protect_gateway.py', 'ffn_config_protect.py'):
    install('opt/' + name, MANAGER / name)
for name in ('ffn_protect_intent.py', 'ffn_protect_gateway.py', 'ffn_interface_management.py'):
    install('opt/' + name, CORE / name)
install('opt/ffn_convergence.py', '/usr/local/lib/ffn/ffn_convergence.py')
install('static/protect.js', MANAGER / 'static/protect.js')
install('ffn-protect-mp', '/usr/local/sbin/ffn-protect', 0o755)

# --- manager
patch(MANAGER / 'ffn_manager.py', [(
    "_install_dhcp_api(app, get_current_user, _require_admin, _audit, config_mgr, CANDIDATE_CONFIG)\n",
    "_install_dhcp_api(app, get_current_user, _require_admin, _audit, config_mgr, CANDIDATE_CONFIG)\n"
    "from ffn_config_protect import install as _install_protect_api\n"
    "_install_protect_api(app, get_current_user, _require_admin, _audit, config_mgr, CANDIDATE_CONFIG)\n")])
patch(MANAGER / 'static/index.html', [
    ('<script src="/static/dhcp.js"></script>\n', '<script src="/static/dhcp.js"></script>\n<script src="/static/protect.js"></script>\n'),
    ("function renderFPPortals(c){c.innerHTML=netPageHTML(_CTX_FP_PORTALS);netRenderList(_CTX_FP_PORTALS);}",
     "function renderFPPortals(c){\n  if (window.ffnProtect) { window.ffnProtect.page(c, 'portals'); return; }\n"
     "  c.innerHTML = '<div class=\"page-header\"><h2>FFN Protect Portals</h2></div><p class=\"text-dim\">The FFN Protect console script did not load.</p>';\n}"),
    ("function renderFPGateways(c){c.innerHTML=netPageHTML(_CTX_FP_GATEWAYS);netRenderList(_CTX_FP_GATEWAYS);}",
     "function renderFPGateways(c){\n  if (window.ffnProtect) { window.ffnProtect.page(c, 'gateways'); return; }\n"
     "  c.innerHTML = '<div class=\"page-header\"><h2>FFN Protect Gateways</h2></div><p class=\"text-dim\">The FFN Protect console script did not load.</p>';\n}"),
    ("    {key:'permit_user_id', label:'User-ID Service', type:'select', opts:_OPT_YESNO},\n",
     "    {key:'permit_user_id', label:'User-ID Service', type:'select', opts:_OPT_YESNO},\n"
     "    {key:'permit_protect', label:'FFN Protect (443/tcp, 4501/udp)', type:'select', opts:_OPT_YESNO},\n")])
patch(MANAGER / 'ffn_config_zones.py', [(
    "            for entry in dev.findall('network/interface/'+kind+'/entry'):\n                name = entry.get('name','')\n                mode = next(",
    "            for entry in dev.findall('network/interface/'+kind+'/entry'):\n                name = entry.get('name','')\n"
    "                if kind == 'tunnel':\n                    # tunnel units (tunnel.N) are the interfaces; their container entry is not one\n"
    "                    for sub in entry.findall('units/entry'):\n                        if sub.get('name'): result[sub.get('name')] = 'layer3'\n"
    "                    continue\n                mode = next(")])

# --- platform management
patch(PLATFORM / 'hardware_backend.py', [(
    "    ('dhcp', 'apply'): ('/usr/local/sbin/ffn-dhcp', 'apply'),\n",
    "    ('dhcp', 'apply'): ('/usr/local/sbin/ffn-dhcp', 'apply'),\n    ('protect', 'status'): ('/usr/local/sbin/ffn-protect', 'status'),\n"
    "    ('protect', 'validate'): ('/usr/local/sbin/ffn-protect', 'validate'),\n    ('protect', 'apply'): ('/usr/local/sbin/ffn-protect', 'apply'),\n")])
patch(PLATFORM / 'control.py', [(
    "    ('dhcp', 'status'): ('/usr/local/sbin/ffn-dhcp', 'status'),\n",
    "    ('dhcp', 'status'): ('/usr/local/sbin/ffn-dhcp', 'status'),\n    ('protect', 'status'): ('/usr/local/sbin/ffn-protect', 'status'),\n")])
patch(PLATFORM / 'daemon_backend.py', [
    ("'dhcp':{'revision','servers','configuration'},", "'dhcp':{'revision','servers','configuration'},'protect':{'revision','protect','configuration'},"),
    ("            if resource in ('network','dhcp'):return await backend.run(resource,'validate',payload)",
     "            if resource in ('network','dhcp','protect'):return await backend.run(resource,'validate',payload)"),
    ("        actual='patch' if resource=='network' else 'apply' if resource=='dhcp' else payload['operation'] if resource=='thermal' else 'set'",
     "        actual='patch' if resource=='network' else 'apply' if resource in ('dhcp','protect') else payload['operation'] if resource=='thermal' else 'set'")])
shipped = Path('management/configd_applier.py').read_text()
start = shipped.index('def reconcile_protect(')
end = shipped.index('def reconcile_dhcp(')
function = shipped[start:end]
patch(PLATFORM / 'configd_applier.py', [
    ("        reconcile_dhcp(root,status,configuration_revision)\n\n\ndef reconcile_dhcp(",
     "        reconcile_dhcp(root,status,configuration_revision)\n        # FFN Protect portals and gateways likewise depend only on dataplane devices and addresses.\n"
     "        reconcile_protect(root,status,configuration_revision)\n\n\n" + function + "def reconcile_dhcp("),
    ("                or '.network.profiles.interface-management-profile.' in xpath\n",
     "                or '.network.profiles.interface-management-profile.' in xpath\n"
     "                or '.global-protect.' in xpath or '.network.interface.tunnel.' in xpath or '.shared.certificate.' in xpath\n"
     "                or '.shared.authentication-profile.' in xpath or '.shared.server-profile.' in xpath or '.shared.local-user-database.' in xpath\n")])

# --- the live plane table: the protect resource mirrors dhcp
for table in (Path('/etc/ffn/planes/mp.json'), PLATFORM / 'planes/mp.json'):
    if not table.exists():
        continue
    data = json.loads(table.read_text())
    commands = data['commands']
    if 'protect' in commands:
        print('already present', table)
        continue
    if 'dhcp' not in commands:
        print('no dhcp resource to mirror in', table, '(not the live table)')
        continue
    commands['protect'] = {action: ['protect' if a == 'dhcp' else a for a in argv] for action, argv in commands['dhcp'].items()}
    shutil.copy2(table, str(table) + STAMP)
    table.write_text(json.dumps(data, indent=2) + '\n')
    print('patched', table)
print('done')
