"""Transactional configuration lease shared across processes and restarts."""
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
import sqlite3
import time


class ConfigLock:
    def __init__(self, path, timeout, clock=time.time):
        self.path, self.timeout, self.clock = Path(path), timeout, clock

    @contextmanager
    def transaction(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        db = sqlite3.connect(self.path, timeout=5)
        try:
            db.execute('PRAGMA synchronous=FULL')
            db.execute('BEGIN IMMEDIATE')
            db.execute('CREATE TABLE IF NOT EXISTS config_lock (id INTEGER PRIMARY KEY CHECK(id=1), holder TEXT NOT NULL, acquired REAL NOT NULL, reason TEXT NOT NULL)')
            now = self.clock()
            # Clock rollback must not prematurely release another editor's lock.
            db.execute('DELETE FROM config_lock WHERE ? - acquired > ?', (now, self.timeout))
            yield db, now
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def status(self):
        with self.transaction() as (db, now):
            row = db.execute('SELECT holder,acquired,reason FROM config_lock WHERE id=1').fetchone()
            if row is None:
                return {'locked': False}
            holder, acquired, reason = row
            age = max(0, now-acquired)
            return dict(locked=True, holder=holder, acquired_at=datetime.fromtimestamp(acquired).isoformat(),
                        age_seconds=int(age), expires_in=max(0, int(self.timeout-age)), reason=reason)

    def acquire(self, user, reason):
        if not isinstance(user, str) or not user:
            raise ValueError('Configuration lock requires an owner')
        with self.transaction() as (db, now):
            row = db.execute('SELECT holder FROM config_lock WHERE id=1').fetchone()
            if row and row[0] != user:
                return False
            db.execute('INSERT OR REPLACE INTO config_lock VALUES (1,?,?,?)', (user, now, reason))
            return True

    def release(self, user):
        with self.transaction() as (db, _):
            return db.execute('DELETE FROM config_lock WHERE holder=?', (user,)).rowcount == 1

    def override(self):
        # Caller must enforce admin authorization and audit the returned owner.
        with self.transaction() as (db, _):
            row = db.execute('SELECT holder FROM config_lock WHERE id=1').fetchone()
            db.execute('DELETE FROM config_lock')
            return row[0] if row else None
