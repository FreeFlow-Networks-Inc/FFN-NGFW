"""Exercise effective review and promotion with real temporary XML and SQLite."""
import asyncio
import io
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from contextlib import redirect_stdout, closing
from unittest.mock import AsyncMock, Mock, patch

_tmp = tempfile.TemporaryDirectory(prefix='ffn-commit-review-')
os.environ['FFN_CONFIG_DIR'] = str(Path(_tmp.name)/'config')
os.environ['FFN_DB_PATH'] = str(Path(_tmp.name)/'config.db')
os.environ['FFN_JWT_SECRET'] = 'isolated-review-tests'
sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'opt'))
import ffn_manager as m
from ffn_policy_cli import handle

ADMIN = dict(username='reviewer',role='admin')
SCOPE = 'device.setup.management'


class CommitReviewTests(unittest.TestCase):
    def setUp(self):
        self.loop=asyncio.Runner()
        self.addCleanup(self.loop.close)
        m._commit_in_progress=asyncio.Lock()
        m.config_mgr._config_lock.override()
        m.app.state.platform_policy_guard=None
        self.addCleanup(lambda:setattr(m.app.state,'platform_policy_guard',None))
        with closing(sqlite3.connect(m.DB_PATH)) as db, db:
            db.execute('CREATE TABLE IF NOT EXISTS net_resources(kind TEXT,name TEXT,enabled INTEGER,config TEXT)')
            db.execute('DELETE FROM net_resources')
        xml=b'<config><device><setup><management><hostname>before</hostname><password>old-secret</password></management><services><dns>192.0.2.53</dns></services></setup></device></config>'
        m.CANDIDATE_CONFIG.write_bytes(xml);m.RUNNING_CONFIG.write_bytes(xml)
        projected=self.run_async(m._sync_netresources_to_xml(persist=False))
        m.config_mgr._save(projected,m.CANDIDATE_CONFIG);m.config_mgr._save(projected,m.RUNNING_CONFIG)
        self.base=m.RUNNING_CONFIG.read_bytes()
        self.edit('before','after')

    def run_async(self,call):return self.loop.run(call)
    def edit(self,old,new):
        m.CANDIDATE_CONFIG.write_bytes(m.CANDIDATE_CONFIG.read_bytes().replace(old.encode(),new.encode()))
    def review(self,scope=None,validate=False):return self.run_async(m.config_review(scope,validate,ADMIN))
    def resource(self,value):
        with closing(sqlite3.connect(m.DB_PATH)) as db, db:
            db.execute('DELETE FROM net_resources')
            db.execute('INSERT INTO net_resources VALUES(?,?,?,?)',('monitor-profiles','probe',1,json.dumps({'interval':value})))
    def commit(self,req):
        with patch.object(m,'audit',new=AsyncMock()), patch.object(m,'controld',None), \
             patch.object(m,'_apply_running_config',return_value=[]),patch.object(m,'_publish_to_planes',return_value={'published':False}):
            return self.run_async(m.config_commit(req,ADMIN))

    def test_preview_includes_sql_is_readonly_and_redacts_credentials(self):
        self.resource('10');self.edit('old-secret','new-secret')
        before=m.CANDIDATE_CONFIG.read_bytes();report=self.review()
        self.assertTrue(any('monitor-profile' in r['path'] for r in report['diff']['added']))
        encoded=json.dumps(report)
        self.assertNotIn('old-secret',encoded);self.assertNotIn('new-secret',encoded)
        self.assertIn('[redacted]',encoded)
        self.assertEqual(self.run_async(m.config_diff(ADMIN)),report['diff'])
        self.assertFalse(report['applied']);self.assertFalse(report['validated'])
        self.assertEqual(m.CANDIDATE_CONFIG.read_bytes(),before);self.assertEqual(m.RUNNING_CONFIG.read_bytes(),self.base)
        self.assertFalse(m.config_mgr.lock_status()['locked'])
        for field in ('pre-shared-key','psk','private_key','passphrase','phash','api-token'):
            redacted=m._redacted_commit_diff(dict(added=[dict(path='config.'+field,new='fixture-sensitive')],modified=[],removed=[]))
            self.assertEqual(redacted['added'][0]['new'],'[redacted]')

    def test_partial_commit_counts_only_scope_and_retains_other_edits(self):
        self.edit('192.0.2.53','198.51.100.53')
        review=self.review(SCOPE,True)
        self.assertEqual(review['diff']['total_changes'],1)
        result=self.commit(m.CommitRequest(partial_xpath=SCOPE,expected_revision=review['revision']))
        self.assertEqual(result['changes']['total'],1)
        running=m.config_mgr._load(m.RUNNING_CONFIG)
        self.assertEqual(running.findtext('./device/setup/management/hostname'),'after')
        self.assertEqual(running.findtext('./device/setup/services/dns'),'192.0.2.53')
        self.assertIn(b'198.51.100.53',m.CANDIDATE_CONFIG.read_bytes())

    def test_direct_commit_promotes_validated_bytes_even_if_candidate_changes(self):
        validated=[]
        def validate(xml):validated.append(xml);self.edit('after','newer-edit')
        with patch('ffn_policy_config.require_supported',side_effect=validate):
            result=m.config_mgr.commit('reviewer')
        self.assertEqual(result['status'],'committed')
        self.assertIn(b'<hostname>after</hostname>',validated[0])
        self.assertEqual(m.config_mgr._load(m.RUNNING_CONFIG).findtext('./device/setup/management/hostname'),'after')
        self.assertIn(b'newer-edit',m.CANDIDATE_CONFIG.read_bytes())

    def test_history_comparison_accepts_candidate_and_running_aliases(self):
        report=m.config_mgr.diff_between('running','candidate')
        self.assertEqual(report['total_changes'],1)
        self.assertEqual(report['modified'][0]['old'],'before')
        self.assertEqual(report['modified'][0]['new'],'after')

    def test_edit_during_sql_read_invalidates_review(self):
        original=m._sync_netresources_to_xml
        async def racing(*args,**kwargs):
            result=await original(*args,**kwargs);self.edit('after','concurrent');return result
        with patch.object(m,'_sync_netresources_to_xml',side_effect=racing):
            with self.assertRaises(m.HTTPException) as error:self.review()
        self.assertEqual(error.exception.status_code,409)

    def test_unselected_changes_do_not_activate_and_noop_does_not_drain(self):
        m.app.state.platform_policy_guard=Mock()
        result=self.commit(m.CommitRequest(partial_xpath='device.setup.services'))
        self.assertEqual(result['status'],'no-changes')
        m.app.state.platform_policy_guard.assert_not_called()
        self.assertEqual(m.RUNNING_CONFIG.read_bytes(),self.base)

    def test_revision_covers_candidate_running_sql_and_scope(self):
        revision=self.review()['revision']
        for mutate in (lambda:self.edit('after','changed'),lambda:m.RUNNING_CONFIG.write_bytes(self.base+b'\n'),lambda:self.resource('20')):
            mutate()
            with self.assertRaises(m.HTTPException) as error:self.commit(m.CommitRequest(expected_revision=revision))
            self.assertEqual(error.exception.status_code,409)
            self.assertFalse(m.config_mgr.lock_status()['locked'])
            revision=self.review()['revision']
        with self.assertRaises(m.HTTPException) as error:self.commit(m.CommitRequest(partial_xpath=SCOPE,expected_revision=revision))
        self.assertEqual(error.exception.status_code,409)

    def test_effective_partial_validation_excludes_unselected_policy(self):
        root=m.config_mgr._load(m.CANDIDATE_CONFIG)
        vsys=root.find('./devices/entry/vsys/entry')
        rule=m.ET.SubElement(m.ET.SubElement(m.ET.SubElement(m.ET.SubElement(vsys,'rulebase'),'qos'),'rules'),'entry',name='unsupported')
        m.ET.SubElement(rule,'disabled').text='no'
        m.config_mgr._save(root,m.CANDIDATE_CONFIG)
        self.assertFalse(self.review()['validation']['valid'])
        self.assertTrue(self.review(SCOPE,True)['validation']['valid'])
        guard=Mock();m.app.state.platform_policy_guard=guard
        with self.assertRaises(m.HTTPException):self.commit(m.CommitRequest())
        guard.assert_not_called();self.assertEqual(m.RUNNING_CONFIG.read_bytes(),self.base)

    def test_barrier_receives_scoped_projection_and_changed_inputs_abort(self):
        self.edit('192.0.2.53','198.51.100.53');observed=[]
        def guard(xml):observed.append(xml);self.edit('after','concurrent')
        m.app.state.platform_policy_guard=guard
        with self.assertRaises(m.HTTPException) as error:self.commit(m.CommitRequest(partial_xpath=SCOPE))
        self.assertEqual(error.exception.status_code,409)
        self.assertIn(b'192.0.2.53',observed[0]);self.assertNotIn(b'198.51.100.53',observed[0])
        self.assertEqual(m.RUNNING_CONFIG.read_bytes(),self.base)

    def test_failed_mirror_and_unknown_scope_are_never_no_changes(self):
        with self.assertRaises(m.HTTPException) as error:self.review('device.missing')
        self.assertEqual(error.exception.status_code,422)
        with closing(sqlite3.connect(m.DB_PATH)) as db, db:
            db.execute('INSERT INTO net_resources VALUES(?,?,?,?)',('monitor-profiles','broken',1,'not-json'))
        with self.assertRaises(m.HTTPException) as error:self.commit(m.CommitRequest())
        self.assertEqual(error.exception.status_code,422)
        self.assertEqual(m.RUNNING_CONFIG.read_bytes(),self.base)
        self.assertFalse(m.config_mgr.lock_status()['locked'])

    def test_permissions_lock_and_duplicate_commit(self):
        with self.assertRaises(m.HTTPException) as error:
            self.run_async(m.config_commit(m.CommitRequest(),dict(username='reader',role='read-only')))
        self.assertEqual(error.exception.status_code,403)
        m.config_mgr.acquire_lock('other','editing')
        self.assertFalse(self.review()['can_commit'])
        with self.assertRaises(m.HTTPException) as error:self.commit(m.CommitRequest())
        self.assertEqual(error.exception.status_code,423)
        m.config_mgr.release_lock('other')
        self.run_async(m._commit_in_progress.acquire())
        try:
            with self.assertRaises(m.HTTPException) as error:self.commit(m.CommitRequest())
            self.assertEqual(error.exception.status_code,409)
        finally:m._commit_in_progress.release()

    def test_cli_uses_authenticated_readonly_review(self):
        api=Mock(return_value={})
        with redirect_stdout(io.StringIO()):
            handle(['show','policies','commit-preview'],api,'token')
            handle(['request','policies','commit-validate',SCOPE],api,'token')
        self.assertEqual(api.call_args_list[0].args[0],'/api/config/review?validate=false')
        self.assertIn('validate=true',api.call_args.args[0]);self.assertEqual(api.call_args.kwargs,{'token':'token'})


if __name__=='__main__':unittest.main()
