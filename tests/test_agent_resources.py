import ast
import asyncio
import copy
from pathlib import Path
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'opt'))
from ffn_agent_resources import ResourceSampler, agent_plane_usage


def agent(usage=None, **kwargs):
    usage = usage or {'0': 20., '1': 40.}
    return dict(role='dp', connected=True, fresh=True, age_seconds=3,
                stale_after_seconds=40, last_observation={'report': {'ready': False,
                'private': 'must not leak', 'host_resources': dict(state='available',
                cores=[int(c) for c in usage], per_core=usage, sample_seconds=10,
                memory_bytes=100, memory_total_bytes=400)}}, **kwargs)


class ResourcesTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.time = 0
        self.sampler = ResourceSampler(self.root, lambda: self.time)
        (self.root / 'meminfo').write_text('MemTotal: 1000 kB\nMemAvailable: 600 kB\n')

    def sample(self, text, boot='boot1'):
        (self.root / 'stat').write_text(text)
        self.time += 10
        return self.sampler.sample(boot)

    def test_delta_guest_iowait_and_memory(self):
        self.assertIsNone(self.sample('cpu0 100 0 0 100 20 0 0 0 50 0')['cpu_percent'])
        got = self.sample('cpu0 120 0 0 160 40 0 0 0 70 0')
        self.assertEqual(got['cpu_percent'], 20)
        self.assertEqual(got['per_core'], {'0': 20})
        self.assertEqual(got['sample_seconds'], 10)
        self.assertEqual(got['memory_percent'], 40)
        self.assertEqual(got['memory_bytes'], 400 * 1024)

    def test_boot_reset_counter_regression_and_hotplug(self):
        self.sample('cpu0 10 0 0 10')
        self.assertIsNone(self.sample('cpu0 20 0 0 20', 'boot2')['cpu_percent'])
        self.assertEqual(self.sample('cpu0 30 0 0 30', 'boot2')['cpu_percent'], 50)
        self.assertIsNone(self.sample('cpu0 1 0 0 1', 'boot2')['cpu_percent'])
        added = self.sample('cpu0 2 0 0 2\ncpu2 4 0 0 4', 'boot2')
        self.assertEqual(added['cores'], [0, 2])
        self.assertIsNone(added['cpu_percent'])
        self.assertIsNone(added['per_core']['2'])
        self.assertEqual(self.sample('cpu2 5 0 0 5', 'boot2')['cpu_percent'], 50)

    def test_error_and_idle_are_distinct(self):
        self.assertEqual(self.sample('broken')['state'], 'unavailable')
        self.sample('cpu0 0 0 0 1')
        self.assertEqual(self.sample('cpu0 0 0 0 2')['cpu_percent'], 0)
        self.assertIsNone(self.sample('cpu0 0 0 0 2')['cpu_percent'])

    def test_selected_agent_projection_and_expiry(self):
        status = {'agents': {'dp0': agent()}}
        got = agent_plane_usage(status, 'dp')
        self.assertEqual(got['cpu_percent'], 30)
        self.assertEqual(got['memory_percent'], 25)
        self.assertEqual(got['expires_in_seconds'], 37)
        self.assertNotIn('private', str(got))
        # Readiness and CPU load are independent.
        self.assertEqual(got['state'], 'available')
        for field, value in [('fresh', False), ('connected', False), ('age_seconds', 40)]:
            bad = copy.deepcopy(status); bad['agents']['dp0'][field] = value
            got = agent_plane_usage(bad, 'dp')
            self.assertIsNone(got['cpu_percent'])
            self.assertIsNone(got['memory_bytes'])
            self.assertEqual(got['state'], 'stale')
        self.assertIsNone(agent_plane_usage(status, 'cp')['cpu_percent'])

    def test_multiple_agents_weighted_by_cores_and_partial_missing(self):
        status = {'agents': {'a': agent({'0': 0}), 'b': agent({'0': 100, '1': 100})}}
        got = agent_plane_usage(status, 'dp')
        self.assertEqual(got['cpu_percent'], 66.7)
        self.assertEqual(got['cores'], ['a:0', 'b:0', 'b:1'])
        status['agents']['b']['last_observation']['report']['host_resources']['per_core']['1'] = float('nan')
        self.assertIsNone(agent_plane_usage(status, 'dp')['cpu_percent'])
        del status['agents']['b']['last_observation']['report']['host_resources']
        self.assertEqual(agent_plane_usage(status, 'dp')['state'], 'unavailable')


class EndpointTests(unittest.IsolatedAsyncioTestCase):
    async def test_agent_vs_local_allocation_and_controller_failure(self):
        # Execute the actual endpoint without initializing unrelated manager services.
        import ffn_control_plane
        source = (Path(__file__).resolve().parents[1] / 'opt/ffn_manager.py').read_text(encoding='utf-8')
        node = next(n for n in ast.parse(source).body if isinstance(n, ast.AsyncFunctionDef) and n.name == 'plane_usage')
        node.decorator_list = []; node.args.defaults = [ast.Constant(None)]
        ps = Mock()
        ps.cpu_percent.return_value = [10, 20, 30, 40]
        ps.virtual_memory.return_value = SimpleNamespace(total=1000, used=400, percent=40)
        ps.swap_memory.return_value = SimpleNamespace(total=0, used=0)
        ps.process_iter.return_value = []
        env = dict(os=SimpleNamespace(cpu_count=lambda: 4, getenv=lambda key, default: default),
                   psutil=ps, _read_cpu_planes_conf=lambda: {'FFN_MGMT_CORES':'0', 'FFN_CTRL_CORES':'1', 'FFN_DPDK_CORES':'2,3'},
                   _expand_cpu_list=lambda text: [int(x) for x in text.split(',') if x], _read_isolcpus=lambda: [])
        exec(compile(ast.fix_missing_locations(ast.Module(body=[node], type_ignores=[])), 'endpoint', 'exec'), env)
        with patch.object(ffn_control_plane, 'control_rpc', AsyncMock(return_value={'agents': {}})):
            got = await env['plane_usage']()
            self.assertEqual(got['data_plane']['cpu_percent'], 35)
            self.assertEqual(got['management_plane']['cores'], [0])
        with patch.object(ffn_control_plane, 'control_rpc', AsyncMock(return_value={'agents': {'dp': agent()}})):
            got = await env['plane_usage']()
            self.assertEqual(got['data_plane']['cpu_percent'], 30)
            self.assertEqual(got['management_plane']['cores'], [0, 1, 2, 3])
            self.assertIsNone(got['control_plane']['cpu_percent'])
        with patch.object(ffn_control_plane, 'control_rpc', AsyncMock(side_effect=OSError)):
            got = await env['plane_usage']()
            self.assertIsNone(got['data_plane']['cpu_percent'])
            self.assertIsNone(got['control_plane']['cpu_percent'])


if __name__ == '__main__':
    unittest.main()
