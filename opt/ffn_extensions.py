# SPDX-License-Identifier: GPL-2.0-or-later
"""Explicitly selected platform extension. No selection means no import/probe.

FFN_PLATFORM_EXTENSION is a locally administered absolute directory containing
extension.json, control.py and static/. It is never set by an HTTP request.
"""
import importlib.util
import json
import logging
import os
from pathlib import Path
import re

from fastapi import Depends
from fastapi.staticfiles import StaticFiles


def install(app, current_user, require_admin, record_audit, selected=None):
    selected = os.environ.get('FFN_PLATFORM_EXTENSION', '') if selected is None else selected
    descriptors = []
    state = 'disabled'
    if selected:
        try:
            root = Path(selected)
            if not root.is_absolute():
                raise ValueError('extension directory must be absolute')
            root = root.resolve(strict=True)
            manifest = json.loads((root / 'extension.json').read_text())
            ident = manifest['id']
            if not re.fullmatch(r'[a-z][a-z0-9-]{0,31}', ident):
                raise ValueError('invalid extension ID')
            if manifest.get('api_version') != 1:
                raise ValueError('unsupported extension API version')
            label = manifest['label']
            if not isinstance(label, str) or not 1 <= len(label) <= 80:
                raise ValueError('invalid extension label')
            spec = importlib.util.spec_from_file_location('ffn_extension_' + ident, root / 'control.py')
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            routes = mod.router(current_user, require_admin, record_audit)
            assets = StaticFiles(directory=str(root / 'static'))
            app.include_router(routes)
            app.mount('/static/extensions/' + ident, assets, name='extension-' + ident)
            descriptors.append({'id': ident, 'label': label,
                                'script': '/static/extensions/' + ident + '/ui.js'})
            state = 'enabled'
        except Exception:
            logging.getLogger(__name__).exception('Selected platform extension could not be loaded')
            state = 'unavailable'

    @app.get('/api/system/extensions')
    async def extensions(user=Depends(current_user)):
        return {'state': state, 'extensions': descriptors}

    return descriptors
