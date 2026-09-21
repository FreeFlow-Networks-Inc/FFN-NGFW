"""Resolve a kernel-authenticated console UID against the FFN administrator DB."""
import pwd
from fastapi import Header, HTTPException, Request
from typing import Optional


async def console_user(uid, path, manager):
    if type(uid) is not int or uid<0:raise HTTPException(401,'Invalid console identity')
    if uid==0:return {'username':'root','role':'superuser','pw_change_required':False,'authentication':'local-root'}
    try:name=pwd.getpwuid(uid).pw_name
    except KeyError:raise HTTPException(401,'Unknown console identity')
    async with manager.aiosqlite.connect(manager.DB_PATH) as db:
        db.row_factory=manager.aiosqlite.Row
        row=await (await db.execute('SELECT role,must_change_pw FROM users WHERE username=?',(name,))).fetchone()
    if row is None:raise HTTPException(403,'No FFN administrator account for this console identity')
    if row['must_change_pw'] and path not in manager.PW_CHANGE_ALLOWED_PATHS:
        raise HTTPException(403,'Password change required before using control functions')
    return {'username':name,'role':row['role'],'pw_change_required':bool(row['must_change_pw']),
            'authentication':'local-peercred'}


def install_identity(manager):
    async def current(request:Request, authorization:Optional[str]=Header(None)):
        if 'ffn.console_uid' in request.scope:
            return await console_user(request.scope['ffn.console_uid'],request.url.path,manager)
        return await manager.get_current_user(request,authorization)
    manager.app.dependency_overrides[manager.get_current_user]=current
