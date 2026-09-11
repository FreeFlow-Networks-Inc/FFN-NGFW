#!/usr/bin/env python3
"""Add an explicit platform reconcile hook to the deployed v1 configd engine."""
from pathlib import Path
import shutil
import sys

path=Path(sys.argv[1])
source=path.read_text()
if '# FFN selected platform reconciliation' in source:
    raise SystemExit('Platform hook already installed')
anchor='        changes = diff_configs(old_paths, new_paths)\n'
assert source.count(anchor)==1, 'Unsupported configd version'
hook='''        # FFN selected platform reconciliation
        provider_path = os.environ.get('FFN_CONFIG_PLATFORM', '')
        if provider_path:
            try:
                import importlib.util
                if not Path(provider_path).is_absolute():
                    raise ValueError('Platform path must be absolute')
                spec = importlib.util.spec_from_file_location('ffn_config_platform', provider_path)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                provider = module.PlatformApplier(RUNNING_CONFIG)
                provider.reconcile(status)
                changes = {p:c for p,c in changes.items() if not provider.claims(p)}
            except Exception as error:
                status.fail('platform', 'platform', str(error))
                status.finish(); status.write()
                return status
'''
source=source.replace(anchor,anchor+hook)
anchor='            shutil.copy2(RUNNING_CONFIG, LAST_APPLIED)'
assert source.count(anchor)==1
source=source.replace(anchor,'            if not status.errors and not status.validation_errors:\n    '+anchor)
compile(source,str(path),'exec')
backup=path.with_name(path.name+'.pre-platform')
assert not backup.exists(), 'Existing backup must be reviewed'
shutil.copy2(path,backup)
temp=path.with_name(path.name+'.new');temp.write_text(source)
shutil.copymode(path,temp);temp.replace(path)
