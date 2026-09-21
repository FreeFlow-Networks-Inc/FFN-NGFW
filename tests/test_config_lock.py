import concurrent.futures
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'opt'))
from ffn_config_lock import ConfigLock


class LockTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'lock.sqlite3'
        self.now = 1000
        self.lock = self.new()

    def new(self):
        return ConfigLock(self.path, 60, lambda: self.now)

    def test_restart_keeps_owner_and_expiry(self):
        self.assertTrue(self.lock.acquire('alice', 'editing'))
        restarted = self.new()
        self.assertEqual(restarted.status()['holder'], 'alice')
        self.assertFalse(restarted.acquire('bob', 'editing'))
        self.assertFalse(restarted.release('bob'))
        self.now += 61
        self.assertTrue(restarted.acquire('bob', 'commit'))
        self.assertEqual(self.lock.status()['holder'], 'bob')

    def test_parallel_owners_have_exactly_one_winner(self):
        with concurrent.futures.ThreadPoolExecutor(8) as pool:
            results = list(pool.map(lambda i: self.new().acquire(str(i), 'editing'), range(16)))
        self.assertEqual(sum(results), 1)

    def test_renew_override_and_clock_rollback(self):
        self.lock.acquire('alice', 'editing')
        self.now -= 100
        self.assertFalse(self.new().acquire('bob', 'editing'))
        self.assertEqual(self.lock.status()['age_seconds'], 0)
        self.assertTrue(self.lock.acquire('alice', 'commit'))
        self.assertEqual(self.new().override(), 'alice')
        self.assertFalse(self.lock.status()['locked'])

    def test_unreadable_state_does_not_silently_unlock(self):
        self.path.write_bytes(b'not a database')
        with self.assertRaises(Exception):
            self.lock.acquire('alice', 'editing')
