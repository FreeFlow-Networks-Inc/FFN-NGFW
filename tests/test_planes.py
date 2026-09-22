import asyncio
import copy
from pathlib import Path
import sys
import tempfile
import unittest
import uuid
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'opt'))
from ffn_planed import INVENTORY, MAX_TIMEOUT, Plane, decode, encode, process


def request(action='apply', payload=None, resource='network'):
    return {'v':1,'id':str(uuid.uuid4()),'resource':resource,'action':action,
            'payload':{'revision':0,'ports':{'p1':{'mode':'l3','addresses':['192.0.2.1/24']}}} if payload is None else payload}


def describe():
    return {'v':1,'id':str(uuid.uuid4()),'resource':INVENTORY,'action':'inventory','payload':{}}


class Backend:
    def __init__(self): self.revision=0; self.applies=0; self.fail=False; self.budgets=[]
    async def __call__(self, argv, raw, timeout):
        data=decode(raw); action=argv[-1]
        self.budgets.append((action,timeout))
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

    async def test_concurrent_identical_requests_execute_once(self):
        req=request()
        results=await asyncio.gather(*(self.dp.dispatch(req) for _ in range(12)))
        self.assertTrue(all(result['state']=='applied' for result in results))
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

    async def test_node_describes_resources_budgets_and_recovery(self):
        """The vocabulary comes from the node, so a platform needs no core change."""
        config={'role':'dp','commands':{'network':{a:[sys.executable,a] for a in ('status','validate','apply','lookup')},
                                        'bcm':{'status':[sys.executable,'status']}},
                'timeouts':{'default':{'status':25},'network':{'apply':110}}}
        plane=Plane(config,Path(self.temp.name)/'describe.db',self.backend)
        self.planes.append(plane)
        answer=await plane.dispatch(describe())
        self.assertEqual(answer['state'],'observed')
        described=answer['result']
        self.assertEqual((described['role'],described['relays']),('dp',False))
        network=described['resources']['network']
        self.assertEqual(network['actions'],['apply','lookup','resolve','result','status','validate'])
        self.assertEqual(network['timeouts'],{'apply':110,'lookup':20,'status':25,'validate':20})
        # A resource with no apply offers no recovery vocabulary it cannot honour.
        self.assertEqual(described['resources']['bcm']['actions'],['status'])
        # Describing a node must not map it: no controller path is returned.
        self.assertNotIn(Path(sys.executable).name,encode(described).decode())

    async def test_reserved_description_resource_cannot_be_driven(self):
        with self.assertRaises(ValueError):
            Plane({'role':'dp','commands':{INVENTORY:{'status':[sys.executable,'status']}}},
                  Path(self.temp.name)/'reserved.db',self.backend)
        for bad in (dict(describe(),action='status'),request('inventory',{},'network'),
                    dict(describe(),payload={'revision':0})):
            self.assertEqual((await self.dp.dispatch(bad))['state'],'rejected')

    async def test_description_names_the_request_that_blocks_a_resource(self):
        """Recovery must not depend on whoever issued the interrupted apply."""
        self.backend.fail=True;req=request()
        self.assertEqual((await self.dp.dispatch(req))['state'],'unknown')
        described=(await self.dp.dispatch(describe()))['result']
        self.assertEqual(described['resources']['network']['blocked'],[req['id']])
        self.assertEqual(described['resources']['network']['blocked_total'],1)
        self.backend.fail=False
        await self.dp.dispatch(request('resolve',{'request_id':req['id'],'observed_revision':1}))
        described=(await self.dp.dispatch(describe()))['result']
        self.assertEqual(described['resources']['network']['blocked'],[])

    async def test_relay_describes_its_peer_or_reports_silence(self):
        mp=await self.relay('mp',self.dp)
        described=(await mp.dispatch(describe()))['result']
        self.assertEqual((described['relays'],described['resources']),(True,{}))
        self.assertTrue(described['peer']['reachable'])
        self.assertIn('network',described['peer']['resources'])
        async def silent(*args): raise ConnectionError('peer down')
        mp.runner=silent
        # Silence about a downstream node must not read as a node with nothing on it.
        self.assertEqual((await mp.dispatch(describe()))['result']['peer'],{'reachable':False})

    async def test_configured_budget_reaches_the_controller(self):
        plane=Plane(dict(self.config,timeouts={'default':{'status':25},'network':{'apply':110}}),
                    Path(self.temp.name)/'budget.db',self.backend)
        self.planes.append(plane)
        await plane.dispatch(request('status',{}))
        await plane.dispatch(request())
        self.assertIn(('status',25),self.backend.budgets)
        self.assertIn(('apply',110),self.backend.budgets)
        self.assertIn(('validate',20),self.backend.budgets)
        # Outside the response ladder, or for something this node does not run.
        for outside in ({'default':{'apply':MAX_TIMEOUT+1}},{'network':{'status':0}},
                        {'absent':{'status':5}},{'network':{'lookup':5}}):
            with self.assertRaises(ValueError):
                Plane(dict(self.config,timeouts=outside),Path(self.temp.name)/'rejected.db',self.backend)


if __name__=='__main__': unittest.main()
