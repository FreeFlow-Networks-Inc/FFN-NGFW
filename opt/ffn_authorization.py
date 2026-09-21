"""Shared authorization for browser and kernel-authenticated console requests."""
from fastapi import HTTPException

ADMIN_ROLES = frozenset({'admin', 'superuser'})
ROLES = ADMIN_ROLES | {'operator', 'read-only'}
# These POST handlers inspect supplied data; they never change configuration.
READ_POSTS = frozenset('/api/config/policies/' + kind + '/test'
                       for kind in ('nat', 'qos', 'pbf', 'decryption'))


def authorize(request, user):
    role = user.get('role')
    if role not in ROLES:
        raise HTTPException(403, 'Unknown administrator role')
    method, path = request.method, request.url.path
    if method in {'GET', 'HEAD', 'OPTIONS'}:
        return user
    if method == 'POST' and (path in READ_POSTS or path == '/api/auth/change-password'):
        return user
    if role not in ADMIN_ROLES:
        raise HTTPException(403, 'Changing configuration or operating services requires admin or superuser role')
    return user
