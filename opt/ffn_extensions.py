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

from fastapi import Depends, HTTPException
from fastapi.staticfiles import StaticFiles
from starlette.routing import Mount


def install(app, current_user, require_admin, record_audit, selected=None):
    selected = os.environ.get('FFN_PLATFORM_EXTENSION', '') if selected is None else selected
    descriptors = []
    state = 'disabled'
    runtime = None
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
            pages = manifest.get('pages', [])
            if not isinstance(pages, list) or len(pages) > 32:
                raise ValueError('invalid extension pages')
            page_ids = set()
            for page in pages:
                if (not isinstance(page, dict) or not {'id', 'label', 'tab'} <= set(page) or
                        set(page) - {'id', 'label', 'tab', 'after'} or
                        ('after' in page and (not isinstance(page['after'], str) or
                         not re.fullmatch(r'[a-z][a-z0-9-]{0,63}', page['after']))) or
                        not isinstance(page['id'], str) or
                        not re.fullmatch(r'[a-z][a-z0-9-]{0,31}', page['id']) or
                        page['id'] in page_ids or
                        page['tab'] not in ('dashboard', 'monitor', 'acc', 'policy', 'objects', 'network', 'device') or
                        not isinstance(page['label'], str) or not 1 <= len(page['label']) <= 80):
                    raise ValueError('invalid extension page declaration')
                page_ids.add(page['id'])
            spec = importlib.util.spec_from_file_location('ffn_extension_' + ident, root / 'control.py')
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            routes = mod.router(current_user, require_admin, record_audit)
            legacy_routes = (mod.legacy_router(current_user, require_admin, record_audit)
                             if hasattr(mod, 'legacy_router') else None)
            if legacy_routes is not None and legacy_routes.prefix != '/api/bcm':
                raise ValueError('invalid legacy hardware router prefix')
            runtime_routes = None
            if manifest.get('runtime_api_version') is not None:
                if manifest['runtime_api_version'] != 1:
                    raise ValueError('unsupported runtime API version')
                runtime_routes = mod.runtime_router(current_user, require_admin, record_audit)
                if runtime_routes.prefix != '/api/system/runtime':
                    raise ValueError('invalid runtime router prefix')
            assets = StaticFiles(directory=str(root / 'static'))
            app.include_router(routes)
            if legacy_routes is not None:
                # Selected hardware owns legacy mutation URLs as well. Place
                # these before the old generic BCM routes to prevent bypass.
                count = len(app.router.routes)
                app.include_router(legacy_routes)
                installed = app.router.routes[count:]
                del app.router.routes[count:]
                app.router.routes[0:0] = installed
            if runtime_routes is not None:
                app.include_router(runtime_routes)
                runtime = {'provider': ident, 'api_version': 1, 'base': '/api/system/runtime'}
            # Starlette uses the first matching route. The manager's earlier
            # /static mount otherwise consumes extension URLs and returns 404.
            asset_path = '/static/extensions/' + ident
            position = next((i for i, route in enumerate(app.router.routes)
                             if isinstance(route, Mount) and
                             asset_path.startswith(route.path.rstrip('/') + '/')),
                            len(app.router.routes))
            app.router.routes.insert(position, Mount(asset_path, app=assets, name='extension-' + ident))
            descriptors.append({'id': ident, 'label': label,
                                'script': '/static/extensions/' + ident + '/ui.js', 'pages': pages})
            state = 'enabled'
        except Exception:
            logging.getLogger(__name__).exception('Selected platform extension could not be loaded')
            state = 'unavailable'

    @app.get('/api/system/extensions')
    async def extensions(user=Depends(current_user)):
        return {'state': state, 'extensions': descriptors}

    @app.get('/api/system/runtime-provider')
    async def runtime_provider(user=Depends(current_user)):
        return {'state': state, 'runtime': runtime}

    if runtime is None:
        @app.get('/api/system/runtime/status')
        async def runtime_unavailable(user=Depends(current_user)):
            raise HTTPException(503, 'No compatible runtime provider selected')

    return descriptors
