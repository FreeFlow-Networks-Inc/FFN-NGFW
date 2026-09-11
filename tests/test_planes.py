import asyncio
import copy
from pathlib import Path
import sys
import tempfile
import unittest
import uuid
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'opt'))
from ffn_planed import Plane, decode, encode, process


def request(action='apply', payload=None, resource='network'):
    return {'v':1,'id':str(uuid.uuid4()),'resource':resource,'action':action,
            'payload':{'revision':0,'ports':{'p1':{'mode':'l3','addresses':['192.0.2.1/24']}}} if payload is None else payload}


class Backend:
    def __init__(self): self.revision=0; self.applies=0; self.fail=False
    async def __call__(self, argv, raw, timeout):
        data=decode(raw); action=argv[-1]
        if action=='status': return {'config':{'revision':self.revision}}
        if data['revision']!=self.revision: raise ValueError('revision conflict')
        if action=='validate': return {'validated':True}
        self.applies+=1
        self.revision+=1
        if self.fail: raise RuntimeError('reply lost after apply')
        return {'config':{'revision':self.revision}}


class PlaneTests(unittest.IsolatedAsyncioTestCase):
    async def test_structured_controller_validation_error(self):
        argv=[sys.executable,'-c',"import json;print(json.dumps({'error':'port is not attached'}));raise SystemExit(2)"]
        with self.assertRaisesRegex(ValueError,'port is not attached'):
            await process(argv,b'{}\n',10)

    async def asyncSetUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.path=Path(self.temp.name)/'journal.db'
        self.backend=Backend()
        self.config={'role':'dp','commands':{'network':{a:[sys.executable,a] for a in ('status','validate','apply')}}}
        self.dp=Plane(self.config,self.path,self.backend)
        self.planes=[self.dp]
    async def asyncTearDown(self):
        for plane in self.planes: plane.db.close()
        self.temp.cleanup()

    async def relay(self, role, downstream):
        async def runner(argv,data,timeout): return await downstream.dispatch(decode(data))
        plane=Plane({'role':role,'peer':[sys.executable,'peer']},Path(self.temp.name)/(role+'.db'),runner)
        self.planes.append(plane)
        return plane

    async def test_three_planes_and_lost_reply_replay(self):
        cp=await self.relay('cp',self.dp);mp=await self.relay('mp',cp)
        original=mp.runner
        async def lose_reply(*args):
            await original(*args)
            raise ConnectionError('connection lost')
        mp.runner=lose_reply
        req=request()
        self.assertEqual((await mp.dispatch(req))['state'],'unknown')
        mp.runner=original
        answer=await mp.dispatch(req)
        self.assertEqual(answer['trace'],['mp','cp','dp'])
        self.assertEqual(answer['state'],'applied')
        self.assertEqual(self.backend.applies,1)
        changed=copy.deepcopy(req);changed['payload']['ports']['p1']['mode']='disabled'
        self.assertEqual((await mp.dispatch(changed))['state'],'rejected')

    async def test_restart_replays_record_without_backend(self):
        req=request();await self.dp.dispatch(req)
        self.dp.db.close();self.planes.remove(self.dp)
        self.dp=Plane(self.config,self.path,self.backend);self.planes.append(self.dp)
        self.assertEqual((await self.dp.dispatch(req))['state'],'applied')
        self.assertEqual(self.backend.applies,1)

    async def test_unknown_blocks_writes_until_explicit_reconciliation(self):
        self.backend.fail=True;req=request()
        self.assertEqual((await self.dp.dispatch(req))['state'],'unknown')
        self.backend.fail=False
        new=request(payload={'revision':1})
        self.assertEqual((await self.dp.dispatch(new))['state'],'rejected')
        self.assertEqual(self.backend.applies,1)
        query=request('result',{'request_id':req['id']})
        self.assertEqual((await self.dp.dispatch(query))['result']['state'],'unknown')
        bad=request('resolve',{'request_id':req['id'],'observed_revision':0})
        self.assertEqual((await self.dp.dispatch(bad))['state'],'rejected')
        good=request('resolve',{'request_id':req['id'],'observed_revision':1})
        self.assertEqual((await self.dp.dispatch(good))['state'],'reconciled')
        self.assertEqual((await self.dp.dispatch(new))['state'],'applied')

    async def test_validation_and_protocol_reject_without_apply(self):
        invalid=[dict(request(),v=True),dict(request(),id='not-uuid'),dict(request(),action=['apply']),
                 dict(request(),extra='command'),request(payload={'revision':True}),request(resource='shell')]
        for req in invalid: self.assertEqual((await self.dp.dispatch(req))['state'],'rejected')
        self.assertEqual((await self.dp.dispatch(request(payload={'revision':3})))['state'],'rejected')
        self.assertEqual(self.backend.applies,0)

    async def test_cp_local_resource_and_cpu_only_topology(self):
        cp=Plane({'role':'cp','peer':[sys.executable,'dp'],'commands':{'nif':{'status':[sys.executable,'status']}}},
                 Path(self.temp.name)/'cp-local.db',self.backend)
        self.planes.append(cp)
        self.assertEqual((await cp.dispatch(request('status',{},'nif')))['trace'],['cp'])
        mp=await self.relay('mp',self.dp)
        self.assertEqual((await mp.dispatch(request()))['trace'],['mp','dp'])


if __name__=='__main__': unittest.main()
