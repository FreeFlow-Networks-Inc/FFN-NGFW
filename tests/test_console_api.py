"""General settings and snapshot workflows against isolated real configuration files."""
import asyncio
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import AsyncMock, patch

_tmp = tempfile.TemporaryDirectory(prefix="ffn-console-")
os.environ['FFN_DB_PATH'] = str(Path(_tmp.name) / 'config.db')
os.environ['FFN_CONFIG_DIR'] = str(Path(_tmp.name) / 'config')
os.environ['FFN_JWT_SECRET'] = 'console-tests-only'
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'opt'))
import ffn_manager as m

ADMIN = {'username':'test', 'role':'admin'}

class ConsoleTests(unittest.TestCase):
    def test_url_blocklist_persists_and_rejects_readonly(self):
        async def check():
            async with m.aiosqlite.connect(m.DB_PATH) as db:
                await db.execute('CREATE TABLE IF NOT EXISTS url_blocklist (url TEXT, category TEXT)')
                await db.execute('CREATE TABLE IF NOT EXISTS audit_log (username TEXT, action TEXT, detail TEXT)')
                await db.commit()
            entry = m.URLBlockEntry(url='blocked.example', category='custom')
            await m.url_blocklist_add(entry,ADMIN)
            with self.assertRaises(m.HTTPException) as raised:
                await m.url_blocklist_add(entry,{'username':'reader','role':'readonly'})
            self.assertEqual(raised.exception.status_code,403)
            async with m.aiosqlite.connect(m.DB_PATH) as db:
                rows = await (await db.execute('SELECT url FROM url_blocklist')).fetchall()
                self.assertEqual(rows,[('blocked.example',)])
        asyncio.run(check())

    def test_partial_setup_round_trip_preserves_other_values(self):
        async def check():
            with patch.object(m, 'audit', new=AsyncMock()):
                await m.system_setup(m.SetupConfig(hostname='old', dns_primary='192.0.2.53', ntp_server='time.example'), ADMIN)
                await m.system_setup(m.SetupConfig(hostname='new'), ADMIN)
                result = await m.system_setup_get(ADMIN)
                self.assertEqual(result['source'],'candidate')
                self.assertEqual(result['config']['hostname'],'new')
                self.assertEqual(result['config']['dns_primary'],'192.0.2.53')
                self.assertEqual(result['config']['ntp_server'],'time.example')
        asyncio.run(check())

    def test_readonly_cannot_modify_setup_or_snapshots(self):
        async def check():
            user = {'username':'reader', 'role':'readonly'}
            for call,args in [(m.system_setup,(m.SetupConfig(hostname='denied'),)),
                              (m.config_snapshot_save,(m.SnapshotSave(name='denied'),)),
                              (m.config_snapshot_restore,('denied',)),
                              (m.config_snapshot_delete,('denied',))]:
                with self.assertRaises(m.HTTPException) as raised:
                    await call(*args,user=user)
                self.assertEqual(raised.exception.status_code,403)
        asyncio.run(check())

    def test_snapshot_restore_only_changes_candidate_and_respects_lock(self):
        async def check():
            with patch.object(m, 'audit', new=AsyncMock()):
                original = m.RUNNING_CONFIG.read_bytes()
                await m.config_snapshot_save(m.SnapshotSave(name='console-backup'),ADMIN)
                m.config_mgr.release_lock('test')
                m.config_mgr.acquire_lock('other','editing')
                with self.assertRaises(m.HTTPException) as raised:
                    await m.config_snapshot_restore('console-backup',ADMIN)
                self.assertEqual(raised.exception.status_code,423)
                m.config_mgr.release_lock('other')
                result = await m.config_snapshot_restore('console-backup',ADMIN)
                self.assertEqual(result['status'],'restored-to-candidate')
                self.assertEqual(m.RUNNING_CONFIG.read_bytes(),original)
                self.assertEqual(m.CANDIDATE_CONFIG.read_bytes(),original)
                await m.config_snapshot_delete('console-backup',ADMIN)
                self.assertNotIn('console-backup',[s['name'] for s in m.config_mgr.snapshot_list()])
        asyncio.run(check())

if __name__ == '__main__': unittest.main()
