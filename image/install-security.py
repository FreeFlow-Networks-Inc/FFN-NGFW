#!/usr/bin/env python3
"""Install coordinated policy code; commissioning and service start are separate."""
import argparse
import importlib.util
from pathlib import Path
import shutil
import time


def once(text,old,new):
    if new in text:return text
    if text.count(old)!=1:raise ValueError('Unsupported Security integration boundary: '+old[:80])
    return text.replace(old,new,1)


def merge_control(text):
    anchor="        self.nat = NatGateway(self.planes, os.getenv('FFN_CONFIG_DIR','/var/lib/ffn-ngfw/config'))\n"
    text=once(text,anchor,anchor+"        from ffn_security_control import SecurityGateway\n        self.security = SecurityGateway(self.planes, os.getenv('FFN_CONFIG_DIR','/var/lib/ffn-ngfw/config'))\n")
    anchor='            "nat/apply":                self.nat.apply,\n'
    text=once(text,anchor,anchor+''.join('            "security/'+a+'":          self.security.'+a+',\n' for a in ('status','validate','apply')))
    compile(text,'ffn_controld.py','exec');return text


def merge_configd(text):
    if '# FFN coordinated Security/NAT ownership' in text:return text
    anchor='        # FFN NAT is reconciled as one ordered rulebase, including deletions.\n'
    block=("        # FFN coordinated Security/NAT ownership\n"
           "        from ffn_security_control import commissioned as security_commissioned\n"
           "        if security_commissioned():\n"
           "            changes = {p:c for p,c in changes.items() if not any(k in p for k in ('/rulebase/security/', '.rulebase.security.', '/rulebase/nat/', '.rulebase.nat.'))}\n\n")
    text=once(text,anchor,block+anchor)
    compile(text,'ffn_configd.py','exec');return text


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('role',choices=('mp','dp'));args=p.parse_args()
    root=Path(__file__).resolve().parents[1];writes={}
    modules=('ffn_security_control.py','ffn_nat_control.py','ffn_policy_config.py','ffn_policy_plan.py','ffn_nat_policy.py','ffn_ipv6_translation.py')
    if args.role=='mp':
        for directory in (Path('/opt/ffn-ngfw'),Path('/opt/ffn-ngfw-v2')):
            for name in modules:writes[directory/name]=(root/'opt'/name).read_text()
        for name,merge in (('ffn_controld.py',merge_control),('ffn_configd.py',merge_configd)):
            path=Path('/opt/ffn-ngfw')/name;writes[path]=merge(path.read_text())
    else:
        for name in modules+('ffn_nat_runtime.py','ffn_security_nft.py','ffn_security_runtime.py','ffn_session_events.py'):
            writes[Path('/usr/local/lib/ffn')/name]=(root/'opt'/name).read_text()
        writes[Path('/etc/systemd/system/ffn-security-runtime.service')]=(root/'systemd/ffn-security-runtime.service').read_text()
    backup=Path('/var/backups/ffn/security-'+str(time.time_ns()))
    for path,text in writes.items():
        if path.suffix=='.py':compile(text,str(path),'exec')
    for path,text in writes.items():
        if path.exists():
            previous=backup/str(path).lstrip('/');previous.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(path,previous)
        path.parent.mkdir(parents=True,exist_ok=True);temp=path.with_name(path.name+'.new')
        temp.write_text(text,encoding='utf-8');temp.chmod(path.stat().st_mode&0o777 if path.exists() else 0o644);temp.replace(path)
    print('Security code installed; provider not commissioned. Backup: '+str(backup))
    if args.role=='mp':
        print('Reload ffn-managementd, ffn-controld, ffn-configd and ffn-manager-v2 after installation; the shared management daemon also caches policy modules.')


if __name__=='__main__':main()
