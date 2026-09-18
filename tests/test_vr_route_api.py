"""vr_route_update: who may edit a route, and what an edit is allowed to touch.

WHY THIS FILE CHANGED SHAPE. It used to exec three AST nodes into a hand-built
scope and assert against the static_routes table, because the handler wrote
SQLite directly. It no longer does: vr_route_update validates, then delegates to
_vr_candidate_edit, which edits the CANDIDATE XML through ffn_vr_candidate.edit.
The scope never grew that function, so every test here died with

    NameError: name '_vr_candidate_edit' is not defined

in a traceback naming '<route handlers>' -- a file that does not exist, because
that is the name the compile() below gives the extracted nodes.

The assertions are the same questions asked of the new architecture. The three
status codes still come from the real code, not from stubs:

    403  _require_admin, inside _validate_vr_route
    422  ffn_vr_interfaces.validate_route, against the stubbed inventory
    404  ffn_vr_candidate.edit, 'Static route not found'

so a regression in any of them still fails here. What changed is only WHERE a
write would land: "the table is untouched" became "the candidate XML is
untouched", which is the same property about the storage that now exists.

_vr_candidate_edit is extracted and run for real rather than stubbed. Stubbing
it would have been the smaller edit and would have made this file pointless:
_require_admin moved INSIDE it, so a stub would delete the authorisation check
these tests exist to defend.
"""
import ast
import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from typing import Optional
from unittest.mock import AsyncMock, Mock
import xml.etree.ElementTree as ET
import aiosqlite
from fastapi import HTTPException, Depends
from pydantic import BaseModel

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'opt'))

SEED = [dict(id=1, name='default', table_id=254, interfaces=[], admin_up=True,
             protocol='static', config={}, routes=[
                 dict(id=7, dest_cidr='0.0.0.0/0', next_hop='192.0.2.1',
                      dev='ethernet1/1', metric=100),
                 dict(id=8, dest_cidr='198.51.100.0/24', next_hop='192.0.2.3',
                      dev='ethernet1/1', metric=50)])]
XML = ('<config><devices><entry name="localhost.localdomain"><network><interface>'
       '<ethernet><entry name="ethernet1/1"/></ethernet></interface></network>'
       '</entry></devices></config>')


class RouteAPI(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.candidate = Path(folder.name) / 'candidate.xml'
        self.candidate.write_text(XML)

        class Manager:
            holder = None
            def lock_status(self): return dict(locked=bool(self.holder), holder=self.holder)
            def acquire_lock(self, user, reason): self.holder = user; return True
            def release_lock(self, user): self.holder = None
            def _load(self, path): return ET.fromstring(path.read_text())
            def _save(self, root, path): path.write_bytes(ET.tostring(root))

        async def catalog(user):
            return [{'name': 'ethernet1/1', 'virtual_router': 'default'}]

        def admin(user):
            if user['role'] != 'admin':
                raise HTTPException(403, 'admin required')

        self.frr = Mock()
        self.scope = {
            'app': SimpleNamespace(put=lambda path: lambda fn: fn),
            'HTTPException': HTTPException, 'Depends': Depends,
            'get_current_user': lambda: None, 'BaseModel': BaseModel,
            'Optional': Optional, 'aiosqlite': aiosqlite, 'json': json,
            '_vr_interface_inventory': catalog, '_require_admin': admin,
            '_vr_platform_managed': lambda: True, '_get_frr': lambda: self.frr,
            'FrrManager': SimpleNamespace(
                render_fragment=lambda *a, **kw: json.dumps(kw.get('routes'))),
            # _vr_candidate_edit's own dependencies. The candidate editor
            # itself is NOT stubbed -- it is imported for real inside the
            # function, so route validity and the 404 are the real behaviour.
            'config_mgr': Manager(), 'CANDIDATE_CONFIG': self.candidate,
            '_vr_candidate_seed': AsyncMock(return_value=copy.deepcopy(SEED)),
            '_audit': AsyncMock(),
            # The management interface must be a name the inventory does not
            # offer, so the invalid-interface case is genuinely rejected.
            '_mgmt_iface': lambda: 'management0',
        }
        source = (Path(__file__).resolve().parents[1] / 'opt/ffn_manager.py')
        tree = ast.parse(source.read_text(encoding='utf-8'))
        wanted = ('VRRoute', '_validate_vr_route', '_vr_candidate_edit',
                  'vr_route_update')
        nodes = [n for n in tree.body if getattr(n, 'name', '') in wanted]
        missing = set(wanted) - {getattr(n, 'name', '') for n in nodes}
        self.assertFalse(missing, 'ffn_manager no longer defines %s -- this '
                                  'test extracts it by name' % sorted(missing))
        exec(compile(ast.Module(body=nodes, type_ignores=[]), '<route handlers>',
                     'exec'), self.scope)
        self.admin = {'username': 'test', 'role': 'admin'}

    def snapshot(self):
        return self.candidate.read_text()

    def route(self, **values):
        return self.scope['VRRoute'](**({'dest_cidr': '0.0.0.0/0',
                                         'next_hop': '192.0.2.1',
                                         'dev': 'ethernet1/1',
                                         'metric': 0} | values))

    async def test_edit_preserves_route_identity_other_routes_and_avoids_mp_frr(self):
        result = await self.scope['vr_route_update']('default', 7, self.route(),
                                                     self.admin)
        self.assertEqual(result['id'], 7)
        self.assertEqual(result['runtime'], 'not-applied')

        root = ET.fromstring(self.snapshot())
        entries = root.findall('.//static-route/entry')
        ids = sorted(e.findtext('ffn-id') for e in entries)
        self.assertEqual(ids, ['7', '8'], 'the edit added or dropped a route')
        edited = next(e for e in entries if e.findtext('ffn-id') == '7')
        self.assertEqual(edited.findtext('metric'), '0', 'the edit did not land')
        other = next(e for e in entries if e.findtext('ffn-id') == '8')
        self.assertEqual(other.findtext('metric'), '50',
                         'editing one route changed another')
        # A candidate edit must not reach the running dataplane.
        self.assertEqual(self.frr.mock_calls, [])

    async def test_viewer_invalid_interface_and_missing_route_do_not_write(self):
        before = self.snapshot()
        for user, route, ident, code in [
                ({'username': 'viewer', 'role': 'viewer'}, self.route(), 7, 403),
                (self.admin, self.route(dev='management0'), 7, 422),
                (self.admin, self.route(), 99, 404)]:
            with self.assertRaises(HTTPException) as error:
                await self.scope['vr_route_update']('default', ident, route, user)
            self.assertEqual(error.exception.status_code, code)
            self.assertEqual(self.snapshot(), before,
                             'a rejected edit still wrote the candidate')
        self.assertEqual(self.frr.mock_calls, [])


if __name__ == '__main__':
    unittest.main()
