#!/usr/bin/env python3
"""Narrowly install NAT manager/controld/configd integration; no service restarts.

Install DP controllers and platform/native worker selections first. Commissioning
requires /etc/ffn/nat-provider.json and a DP-owned interface map. This installer
does not write either file or apply any rules.
"""
import argparse
from pathlib import Path
import shutil
import time


def once(text,old,new):
    if new in text:return text
    if text.count(old)!=1:raise ValueError('Unsupported source boundary: '+old[:80])
    return text.replace(old,new,1)


def merge_control(text):
    anchor="        self.policy = PolicyController(os.getenv('FFN_CONFIG_DIR','/var/lib/ffn-ngfw/config'), commit)\n"
    text=once(text,anchor,anchor+"        from ffn_nat_control import NatGateway\n        self.nat = NatGateway(self.planes, os.getenv('FFN_CONFIG_DIR','/var/lib/ffn-ngfw/config'))\n")
    anchor='            "policy/request":           self.policy.request,\n'
    extra=''.join('            "nat/'+a+'":                self.nat.'+a+',\n' for a in ('preview','validate','apply','tools'))
    text=once(text,anchor,anchor+extra);compile(text,'ffn_controld.py','exec');return text


def merge_configd(text):
    if '# FFN NAT is reconciled as one ordered rulebase' in text:
        if text.count('reconcile_nat(RUNNING_CONFIG, status)')!=2:raise ValueError('Incomplete NAT configd integration')
        compile(text,'ffn_configd.py','exec');return text
    anchor='        if not changes:\n            logger.info("No changes vs last-applied'
    start=text.find(anchor)
    if start<0:raise ValueError('Missing configd no-change boundary')
    hook="        # FFN NAT is reconciled as one ordered rulebase, including deletions.\n        from ffn_nat_control import reconcile as reconcile_nat, commissioned as nat_commissioned\n        if nat_commissioned():\n            changes = {p:c for p,c in changes.items() if '/rulebase/nat/' not in p and '.rulebase.nat.' not in p}\n\n"
    if hook not in text:text=text[:start]+hook+text[start:]
    text=once(text,anchor,"        if not changes:\n            if not status.errors:\n                reconcile_nat(RUNNING_CONFIG, status)\n            logger.info(\"No changes vs last-applied")
    anchor='        # 7. Save as last-applied\n'
    text=once(text,anchor,'        if not status.errors and not status.validation_errors:\n            reconcile_nat(RUNNING_CONFIG, status)\n\n'+anchor)
    compile(text,'ffn_configd.py','exec');return text


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--manager',type=Path,default=Path('/opt/ffn-ngfw-v2'));p.add_argument('--daemons',type=Path,default=Path('/opt/ffn-ngfw'));a=p.parse_args()
    root=Path(__file__).resolve().parents[1]
    writes={a.daemons/'ffn_controld.py':merge_control((a.daemons/'ffn_controld.py').read_text()),a.daemons/'ffn_configd.py':merge_configd((a.daemons/'ffn_configd.py').read_text())}
    for directory in (a.manager,a.daemons):
        for name in ('ffn_nat_policy.py','ffn_nat_control.py','ffn_policy_config.py'):
            writes[directory/name]=(root/'opt'/name).read_text()
    for name in ('ffn_policy_api.py','ffn_policy_cli.py'):writes[a.manager/name]=(root/'opt'/name).read_text()
    writes[a.manager/'static/config-policies.js']=(root/'static/config-policies.js').read_text()
    backup=Path('/var/backups/ffn/nat-'+str(time.time_ns()))
    for path,text in writes.items():
        if path.suffix=='.py':compile(text,str(path),'exec')
    for path,text in writes.items():
        if path.exists():
            saved=backup/str(path).lstrip('/');saved.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(path,saved)
        mode=path.stat().st_mode & 0o777 if path.exists() else 0o644
        temp=path.with_name(path.name+'.nat-new');temp.write_text(text,encoding='utf-8');temp.chmod(mode);temp.replace(path)
    print('NAT code installed. Backup: '+str(backup)+'. Restart manager, controld and configd after validation.')


if __name__=='__main__':main()
