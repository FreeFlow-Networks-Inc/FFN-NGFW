import ast
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from typing import Optional
from unittest.mock import Mock
import aiosqlite
from fastapi import HTTPException, Depends
from pydantic import BaseModel
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'opt'))


class RouteAPI(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        folder=tempfile.TemporaryDirectory();self.addCleanup(folder.cleanup)
        self.path=str(Path(folder.name)/'config.db')
        async with aiosqlite.connect(self.path) as db:
            await db.executescript('''CREATE TABLE virtual_routers(id INTEGER PRIMARY KEY,name TEXT,table_id INTEGER,frr_fragment TEXT,updated_at TEXT);
                CREATE TABLE static_routes(id INTEGER PRIMARY KEY,vr_id INTEGER,dest_cidr TEXT,next_hop TEXT,dev TEXT,metric INTEGER);
                INSERT INTO virtual_routers VALUES(1,'default',254,'old','old');
                INSERT INTO static_routes VALUES(7,1,'0.0.0.0/0','192.0.2.1','ethernet1/1',100);
                INSERT INTO static_routes VALUES(8,1,'198.51.100.0/24','192.0.2.3','ethernet1/1',50);''')
        async def fetch(db,name):
            db.row_factory=aiosqlite.Row
            return await (await db.execute('SELECT * FROM virtual_routers WHERE name=?',(name,))).fetchone()
        async def routes(db,ident):
            return [dict(row) for row in await (await db.execute('SELECT * FROM static_routes WHERE vr_id=?',(ident,))).fetchall()]
        async def catalog(user):
            return [{'name':'ethernet1/1','virtual_router':'default'}]
        async def audit(*args):pass
        def admin(user):
            if user['role']!='admin':raise HTTPException(403,'admin required')
        self.frr=Mock();self.scope={'app':SimpleNamespace(put=lambda path:lambda fn:fn),
            'aiosqlite':aiosqlite,'DB_PATH':self.path,'HTTPException':HTTPException,'Depends':Depends,
            'get_current_user':lambda:None,'BaseModel':BaseModel,'Optional':Optional,
            '_vr_fetch':fetch,'_vr_static_routes':routes,'_vr_interface_inventory':catalog,
            '_require_admin':admin,'_vr_platform_managed':lambda:True,'_get_frr':lambda:self.frr,
            '_vr_row_to_dict':lambda row:dict(row)|{'protocol':'static','router_id':None,'asn':None},
            'FrrManager':SimpleNamespace(render_fragment=lambda *args,**kw:json.dumps(kw['routes'])), 'audit':audit}
        tree=ast.parse((Path(__file__).resolve().parents[1]/'opt/ffn_manager.py').read_text(encoding='utf-8'))
        nodes=[node for node in tree.body if getattr(node,'name','') in ('VRRoute','_validate_vr_route','vr_route_update')]
        exec(compile(ast.Module(body=nodes,type_ignores=[]),'<route handlers>','exec'),self.scope)
        self.admin={'username':'test','role':'admin'}

    async def snapshot(self):
        async with aiosqlite.connect(self.path) as db:
            return await (await db.execute('SELECT * FROM static_routes ORDER BY id')).fetchall()

    def route(self,**values):
        return self.scope['VRRoute'](**({'dest_cidr':'0.0.0.0/0','next_hop':'192.0.2.1','dev':'ethernet1/1','metric':0}|values))

    async def test_edit_preserves_route_identity_other_routes_and_avoids_mp_frr(self):
        before=await self.snapshot()
        result=await self.scope['vr_route_update']('default',7,self.route(),self.admin)
        after=await self.snapshot()
        self.assertEqual(result['id'],7);self.assertEqual(result['runtime'],'not-applied')
        self.assertEqual(after[1],before[1]);self.assertEqual(after[0][-1],0)
        self.assertEqual(self.frr.mock_calls,[])

    async def test_viewer_invalid_interface_and_missing_route_do_not_write(self):
        before=await self.snapshot()
        for user,route,ident,code in [({'username':'viewer','role':'viewer'},self.route(),7,403),
                                   (self.admin,self.route(dev='management0'),7,422),
                                   (self.admin,self.route(),99,404)]:
            with self.assertRaises(HTTPException) as error:
                await self.scope['vr_route_update']('default',ident,route,user)
            self.assertEqual(error.exception.status_code,code)
        self.assertEqual(await self.snapshot(),before)


if __name__=='__main__':unittest.main()
