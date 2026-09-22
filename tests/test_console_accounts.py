import importlib.util
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import types
import io
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'opt'))
import ffn_console_accounts as accounts
import ffn_pam_console as pam

spec=importlib.util.spec_from_file_location('installer',Path(__file__).resolve().parents[1]/'image/install-console-auth.py')
installer=importlib.util.module_from_spec(spec);spec.loader.exec_module(installer)


class Identities(unittest.TestCase):
    def test_virtual_identity_tombstones_and_password_free_export(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);dbpath=root/'users.db'
            with sqlite3.connect(dbpath) as db:
                db.execute('CREATE TABLE users(id INTEGER PRIMARY KEY AUTOINCREMENT,username TEXT,password_hash TEXT)')
                db.execute("INSERT INTO users(username,password_hash) VALUES ('alice','PRIVATE-HASH')");db.commit()
            original=Path.read_text
            def read(path,*args,**kw):return 'root:x:0:0:root:/root:/bin/bash\n' if str(path)=='/etc/passwd' else original(path,*args,**kw)
            with patch.object(accounts.grp,'getgrnam',return_value=types.SimpleNamespace(gr_gid=1234)), \
                    patch.object(accounts.os,'chown'),patch.object(Path,'read_text',read):
                report=accounts.sync(str(dbpath),root/'extra',root/'homes')
                first=(root/'extra/passwd').read_text()
                self.assertEqual(report['virtual_users'],1);self.assertNotIn('PRIVATE-HASH',first)
                self.assertIn('alice:x:200000:1234:',first)
                with sqlite3.connect(dbpath) as db:
                    db.execute('DELETE FROM users');db.commit()
                accounts.sync(str(dbpath),root/'extra',root/'homes')
                self.assertEqual((root/'extra/passwd').read_text(),'')
                with sqlite3.connect(dbpath) as db:
                    db.execute("INSERT INTO users(username,password_hash) VALUES ('alice','NEW-HASH')");db.commit()
                accounts.sync(str(dbpath),root/'extra',root/'homes')
                self.assertIn('alice:x:200001:',(root/'extra/passwd').read_text())

    def test_pam_preserves_linux_stack_and_is_idempotent(self):
        source='@include common-auth\naccount required pam_nologin.so\n@include common-account\n'
        result=installer.merge_pam(source)
        self.assertEqual(installer.merge_pam(result),result)
        self.assertIn('[success=done default=die] pam_exec.so quiet expose_authtok',result)
        self.assertIn('@include common-auth',result)
        self.assertIn('@include common-account',result)
        self.assertEqual(installer.merge_nss('passwd: files\ngroup: files\n'),'passwd: files extrausers\ngroup: files\n')
        self.assertEqual(installer.merge_nss('passwd: files # local\n'),'passwd: files extrausers # local\n')

    def test_pam_uses_database_auth_without_logging_passwords(self):
        with patch.object(pam.os,'getuid',return_value=0), \
                patch.dict(pam.os.environ,{'PAM_SERVICE':'sshd','PAM_USER':'alice','PAM_TYPE':'auth'}), \
                patch.object(pam.sys,'stdin',types.SimpleNamespace(buffer=io.BytesIO(b'test-only\x00'))), \
                patch.object(pam,'request',return_value={'username':'alice'}) as request:
            self.assertEqual(pam.main(),0)
            request.assert_called_once_with('/api/auth/login',method='POST',body={'username':'alice','password':'test-only'})

    def test_pam_rejects_unprivileged_helpers_root_and_unknown_accounts(self):
        with patch.object(pam.os,'getuid',return_value=1000),patch.object(pam,'request') as request:
            self.assertEqual(pam.main(),1);request.assert_not_called()
        with patch.object(pam.os,'getuid',return_value=0), \
                patch.dict(pam.os.environ,{'PAM_SERVICE':'sshd','PAM_USER':'root'}),patch.object(pam,'request') as request:
            self.assertEqual(pam.main(),1);request.assert_not_called()
        with patch.object(pam.os,'getuid',return_value=0), \
                patch.dict(pam.os.environ,{'PAM_SERVICE':'sshd','PAM_USER':'alice','PAM_TYPE':'account'}), \
                patch.object(pam,'request',return_value={'users':[]}):
            self.assertEqual(pam.main(),1)


if __name__=='__main__':unittest.main()
