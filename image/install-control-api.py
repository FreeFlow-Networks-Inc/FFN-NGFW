#!/usr/bin/env python3
"""Add the core control API mount to older harvested managers without replacing them."""
from pathlib import Path
import shutil
import time


def mount(source):
    marker = 'from ffn_plane_api import install as _install_plane_api'
    if marker in source:
        return source
    anchor = '_install_extensions(app, get_current_user, _require_admin, _extension_audit)\n'
    if source.count(anchor) != 1:
        raise ValueError('Unsupported manager: explicit extension audit hook required')
    result = source.replace(anchor, anchor + '\n' + marker + '\n' +
        '_install_plane_api(app, get_current_user, _require_admin, _extension_audit)\n')
    compile(result, 'ffn_manager.py', 'exec')
    return result


if __name__ == '__main__':
    path = Path('/opt/ffn-ngfw-v2/ffn_manager.py')
    before = path.read_text()
    after = mount(before)
    if after != before:
        backup = Path('/var/backups/ffn/control-api-' + str(time.time_ns()))
        backup.mkdir(parents=True)
        shutil.copy2(path, backup/path.name)
        temp = path.with_name(path.name + '.control-new')
        temp.write_text(after); shutil.copymode(path, temp)
        if path.read_text() != before:
            raise RuntimeError('Manager changed during installation')
        temp.replace(path)
        print('Installed core control API mount; backup: ' + str(backup))
