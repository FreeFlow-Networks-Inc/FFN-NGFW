"""Real Unix socket + subprocess transport, using an inert controller fixture."""
import asyncio
import json
from pathlib import Path
import sys
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'opt'))
from ffn_planed import serve, encode, decode
from test_planes import request


@unittest.skipIf(sys.platform=='win32','Unix sockets target Linux plane daemons')
class SocketTests(unittest.IsolatedAsyncioTestCase):
    async def test_real_mp_cp_dp_process_transport(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            backend=root/'backend.py'
            backend.write_text("import sys,json\nd=json.load(sys.stdin)\nprint(json.dumps({'validated':True} if sys.argv[1]=='validate' else {'config':{'revision':d['revision']+1}}))\n")
            script=str(Path(__file__).resolve().parents[1]/'opt/ffn_planed.py')
            dp={'role':'dp','commands':{'network':{a:[sys.executable,str(backend),a] for a in ('validate','apply')}}}
            cp={'role':'cp','peer':[sys.executable,script,'call','--socket',str(root/'dp.sock')]}
            mp={'role':'mp','peer':[sys.executable,script,'call','--socket',str(root/'cp.sock')]}
            tasks=[]
            try:
                for role,config in [('dp',dp),('cp',cp),('mp',mp)]:
                    task=asyncio.create_task(serve(config,root/(role+'.db'),root/(role+'.sock')))
                    tasks.append(task)
                    for _ in range(100):
                        if (root/(role+'.sock')).exists(): break
                        await asyncio.sleep(.01)
                    if task.done(): await task
                reader,writer=await asyncio.open_unix_connection(str(root/'mp.sock'))
                try:
                    req=request();writer.write(encode(req));await writer.drain()
                    result=decode(await asyncio.wait_for(reader.readline(),10))
                    self.assertEqual(result['trace'],['mp','cp','dp'])
                    self.assertEqual(result['state'],'applied')
                    self.assertEqual(result['result']['config']['revision'],1)
                    writer.write(encode(req));await writer.drain()
                    self.assertEqual(decode(await asyncio.wait_for(reader.readline(),10)),result)
                finally:
                    writer.close();await writer.wait_closed()
            finally:
                for task in tasks: task.cancel()
                await asyncio.gather(*tasks,return_exceptions=True)


if __name__=='__main__': unittest.main()
