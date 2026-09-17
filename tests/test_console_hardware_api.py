import ast
import asyncio
import hashlib
from pathlib import Path
import re
import sys
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,AsyncMock
from xml.etree import ElementTree as ET
from fastapi import HTTPException
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'opt'))
from ffn_port_traffic import PortTraffic


def functions(names,scope):
    tree=ast.parse((Path(__file__).resolve().parents[1]/'opt/ffn_manager.py').read_text(encoding='utf-8'))
    body=[]
    for node in tree.body:
        if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)) and node.name in names:
            node.decorator_list=[];node.args.defaults=[];body.append(node)
    exec(compile(ast.Module(body=body,type_ignores=[]),'<handlers>','exec'),scope)


class HardwareAPITests(unittest.TestCase):
    def test_selected_hardware_outage_never_falls_back_to_host_nics(self):
        provider=Mock(side_effect=RuntimeError('offline'));host=Mock()
        scope=dict(app=SimpleNamespace(state=SimpleNamespace(platform_data_port_stats=provider)),psutil=host,
            _traffic_sampler=PortTraffic(),_traffic_lock=asyncio.Lock(),_traffic_cached=None,_traffic_sampled=0,
            asyncio=asyncio,time=time,HTTPException=HTTPException)
        functions({'dashboard_throughput'},scope)
        with self.assertRaises(HTTPException) as exc:asyncio.run(scope['dashboard_throughput']({}))
        self.assertEqual(exc.exception.status_code,503);host.net_io_counters.assert_not_called()
    def test_generic_dashboard_excludes_management_and_unassigned_nics(self):
        counter=SimpleNamespace(bytes_recv=100,bytes_sent=50,packets_recv=4,packets_sent=2)
        stats=SimpleNamespace(isup=True,speed=1000)
        psutil=SimpleNamespace(net_io_counters=lambda **k:{n:counter for n in ('mgmt0','data0','host0')},net_if_stats=lambda:{n:stats for n in ('mgmt0','data0','host0')})
        scope=dict(app=SimpleNamespace(state=SimpleNamespace()),psutil=psutil,fpga=SimpleNamespace(sim_mode=True),
            _this_is_a_faceplate_chassis=lambda:False,_list_linux_nics=lambda:['mgmt0','data0','host0'],_mgmt_iface=lambda:'mgmt0',
            _load_aliases=lambda:{'ethernet1/1':'data0','ethernet1/2':'mgmt0'},re=re,
            _traffic_sampler=PortTraffic(),_traffic_lock=asyncio.Lock(),_traffic_cached=None,_traffic_sampled=0,
            asyncio=asyncio,time=time,HTTPException=HTTPException)
        functions({'dashboard_throughput'},scope)
        result=asyncio.run(scope['dashboard_throughput']({}))
        self.assertEqual([p['name'] for p in result['ports']],['ethernet1/1'])
    def test_mp_candidate_permissions_revision_and_lock(self):
        manager=Mock();manager.get_xpath.return_value=None;manager.lock_status.return_value={'locked':False};manager.update_candidate.return_value={'status':'ok'}
        def admin(user):
            if user['role']!='admin':raise HTTPException(403,'Read-only')
        scope=dict(config_mgr=manager,_require_admin=admin,_mp_inventory=AsyncMock(return_value=[{'name':'MGT'}]),
            MP_INTERFACE_XPATH='device.mp-interfaces',hashlib=hashlib,ET=ET,Request=object,HTTPException=HTTPException,
            aiosqlite=SimpleNamespace(connect=Mock(return_value=AsyncMock())),DB_PATH='fixture',audit=AsyncMock())
        functions({'mp_interfaces_set','_mp_revision'},scope)
        config=dict(mode='dhcp',address='',gateway='',dns=[],mtu=1500,description='')
        request=SimpleNamespace(json=AsyncMock(return_value={'revision':hashlib.sha256(b'').hexdigest(),'config':config}))
        call=scope['mp_interfaces_set'];user={'username':'fixture','role':'admin'}
        for name,who,code in [('MGT',dict(user,role='readonly'),403),('BP-0',user,404)]:
            with self.assertRaises(HTTPException) as exc:asyncio.run(call(name,request,who))
            self.assertEqual(exc.exception.status_code,code)
        request.json.return_value['revision']='stale'
        with self.assertRaises(HTTPException) as exc:asyncio.run(call('MGT',request,user))
        self.assertEqual(exc.exception.status_code,409)
        request.json.return_value['revision']=hashlib.sha256(b'').hexdigest()
        manager.lock_status.return_value={'locked':True,'holder':'another'}
        with self.assertRaises(HTTPException) as exc:asyncio.run(call('MGT',request,user))
        self.assertEqual(exc.exception.status_code,423);manager.update_candidate.assert_not_called()
        manager.lock_status.return_value={'locked':False}
        result=asyncio.run(call('MGT',request,user))
        self.assertTrue(result['requires_commit']);manager.update_candidate.assert_called_once()


if __name__=='__main__':unittest.main()
