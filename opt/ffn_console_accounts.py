"""Publish password-free SSH identities from the FFN administrator database.

NSS provides the OS session UID that sshd requires; passwords/roles remain
solely in FFN. UIDs are never reused, even after deletion and recreation.
"""
import grp
import os
from pathlib import Path
import re
import sqlite3


def validate_username(name):
    if name=='root' or not re.fullmatch(r'[a-zA-Z_][a-zA-Z0-9_.-]{0,31}',name):
        raise ValueError('Use a non-root console username: 1-32 letters, digits, underscores, dots or hyphens; start with a letter or underscore')
    for line in Path('/etc/passwd').read_text().splitlines():
        parts=line.split(':')
        if len(parts)==7 and parts[0]==name and parts[6]!='/usr/local/bin/ffn-cli':
            raise ValueError('Username belongs to a Linux system account')


def sync(db_path, directory=Path('/var/lib/extrausers'), homes=Path('/var/lib/ffn-console')):
    gid=grp.getgrnam('ffn-console').gr_gid
    local={}
    for line in Path('/etc/passwd').read_text().splitlines():
        parts=line.split(':')
        if len(parts)==7:local[parts[0]]=parts
    directory.mkdir(parents=True,exist_ok=True);homes.mkdir(parents=True,exist_ok=True)
    target=directory/'passwd';marker=directory/'ffn-owned'
    if target.exists() and target.stat().st_size and not marker.exists():
        raise RuntimeError('extrausers is owned by another provider')
    with sqlite3.connect(db_path,timeout=10) as db:
        db.execute('CREATE TABLE IF NOT EXISTS console_identities (user_id INTEGER PRIMARY KEY, username TEXT NOT NULL, uid INTEGER UNIQUE NOT NULL)')
        rows=db.execute('SELECT id,username FROM users ORDER BY id').fetchall()
        lines=[];known_local=[];skipped=[]
        for user_id,name in rows:
            if name=='root':continue
            if not re.fullmatch(r'[a-zA-Z_][a-zA-Z0-9_.-]{0,31}',name):
                skipped.append(name);continue
            if name in local:
                if local[name][6]!='/usr/local/bin/ffn-cli':
                    skipped.append(name);continue
                uid=int(local[name][2]);known_local.append(name)
            else:
                row=db.execute('SELECT uid,username FROM console_identities WHERE user_id=?',(user_id,)).fetchone()
                if row and row[1]!=name:raise RuntimeError('Console identity changed; refusing UID reuse')
                if row:uid=row[0]
                else:
                    uid=max(200000,db.execute('SELECT COALESCE(MAX(uid),199999)+1 FROM console_identities').fetchone()[0])
                    occupied={int(p[2]) for p in local.values()}
                    while uid in occupied:uid+=1
                    db.execute('INSERT INTO console_identities VALUES (?,?,?)',(user_id,name,uid))
                home=homes/name
                home.mkdir(mode=0o700,exist_ok=True);os.chown(home,uid,gid)
                lines.append(f'{name}:x:{uid}:{gid}:FFN control administrator:{home}:/usr/local/bin/ffn-cli\n')
        db.commit()
    # Only a dedicated extrausers namespace is supported. Refuse to overwrite
    # a directory used by another identity provider.
    marker.write_text('FFN console identities; credentials remain in the FFN DB\n')
    temp=directory/'passwd.ffn-new';temp.write_text(''.join(lines));temp.chmod(0o644);temp.replace(target)
    return {'virtual_users':len(lines),'local_cli_users':known_local,'unsupported_names':skipped}
