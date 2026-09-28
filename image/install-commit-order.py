#!/usr/bin/env python3
"""Install ordered, generation-fenced configd processing; no implicit apply."""
from pathlib import Path
import ast
import shutil
import sys


def once(text,old,new):
    if text.count(old)!=1:raise ValueError('Unsupported configd commit boundary: '+old[:80])
    return text.replace(old,new,1)


def merge(text):
    if '# FFN ordered configuration apply' in text:
        if '    engine.apply(force=is_cold_boot)' in text:
            text=once(text,'    engine.apply(force=is_cold_boot)','    startup_apply = engine.apply(force=is_cold_boot)')
            text=once(text,'        marker_path.write_text(cur_boot_id, encoding="utf-8")',
                      '        if startup_apply.overall == "applied":\n            marker_path.write_text(cur_boot_id, encoding="utf-8")')
        compile(text,'ffn_configd.py','exec');return text
    tree=ast.parse(text)
    engine=next(n for n in tree.body if isinstance(n,ast.ClassDef) and n.name=='ConfigEngine')
    method=next(n for n in engine.body if isinstance(n,ast.FunctionDef) and n.name=='apply')
    lines=text.splitlines(keepends=True);body=''.join(lines[method.lineno-1:method.end_lineno])
    body=once(body,'        status = ApplyStatus()','''        status = ApplyStatus()
        cycle = ApplyCycle(RUNNING_CONFIG, status)
        status._commit_cycle = cycle
        cycle.advance('validation')''')
    body=once(body,'        # FFN selected platform reconciliation',"        cycle.advance('interfaces-and-routes')\n        # FFN selected platform reconciliation")
    start=body.index('        if not changes:\n')
    end=body.index('        # 6. Dispatch',start)
    # Reconciliation and checkpoint must run even when every changed path was
    # consumed by the platform provider or a reboot requires an identical replay.
    body=body[:start]+"        cycle.advance('system-settings')\n\n"+body[end:]
    body=once(body,'        for xpath in sorted(changes):',"        for xpath in ordered_paths(changes):\n            cycle.current()\n            if status.errors or status.validation_errors:break")
    body=once(body,'            reconcile_nat(RUNNING_CONFIG, status)',"            cycle.advance('security-and-nat')\n            reconcile_nat(RUNNING_CONFIG, status)")
    body=once(body,'                shutil.copy2(RUNNING_CONFIG, LAST_APPLIED)',"                cycle.checkpoint(LAST_APPLIED)")
    body=once(body,'            logger.warning("Failed to update last-applied: %s", exc)',"            status.fail('commit/checkpoint', 'configd', str(exc))")
    # Catch revision races/phase errors in a single place and always return an
    # explicit failure; retain the successful provider records for diagnosis.
    prefix,rest=body.split("        cycle.advance('validation')",1)
    body=prefix+"        try:\n"+''.join('    '+line if line.strip() else line for line in ("        cycle.advance('validation')"+rest).splitlines(keepends=True))
    body+='''\n        except Exception as error:
            status.fail('commit/order', 'configd', str(error))
            status.finish(); status.write()
            return status
'''
    body='    @coordinated_apply\n'+body
    text=''.join(lines[:method.lineno-1])+body+''.join(lines[method.end_lineno:])
    text=once(text,'class ConfigEngine:', '# FFN ordered configuration apply\nfrom ffn_commit_apply import ApplyCycle, coordinated_apply, ordered_paths\n\nclass ConfigEngine:')
    text=once(text,'    def finish(self):\n',"    def finish(self):\n        if hasattr(self, '_commit_cycle'):self._commit_cycle.finish()\n")
    text=once(text,'            "overall": self.overall,','''            "commit_generation": getattr(self, 'commit_generation', None),
            "phases": getattr(self, 'commit_phases', []),
            "overall": self.overall,''')
    if '    engine.apply(force=is_cold_boot)' in text:
        text=once(text,'    engine.apply(force=is_cold_boot)','    startup_apply = engine.apply(force=is_cold_boot)')
        text=once(text,'        marker_path.write_text(cur_boot_id, encoding="utf-8")',
                  '        if startup_apply.overall == "applied":\n            marker_path.write_text(cur_boot_id, encoding="utf-8")')
    compile(text,'ffn_configd.py','exec');return text


if __name__=='__main__':
    path=Path(sys.argv[1]);source=path.read_text();result=merge(source)
    if result!=source:
        backup=path.with_name(path.name+'.pre-commit-order')
        if backup.exists():raise SystemExit('Review existing commit-order backup before installation')
        shutil.copy2(path,backup)
        temp=path.with_name(path.name+'.new');temp.write_text(result);shutil.copymode(path,temp);temp.replace(path)
    shutil.copy2(Path(__file__).resolve().parents[1]/'opt/ffn_commit_apply.py',path.parent/'ffn_commit_apply.py')
