#!/usr/bin/env python3
"""pam_exec helper: SSH credentials checked by controld against the FFN DB."""
import os
import sys
from ffn_cli_transport import request


def main():
    if os.getuid()!=0 or os.environ.get('PAM_SERVICE') not in ('sshd','ffn-console-test'):
        return 1
    name=os.environ.get('PAM_USER','')
    if name=='root':return 1  # root always follows the existing Linux PAM stack
    try:
        if os.environ.get('PAM_TYPE')=='auth':
            password=sys.stdin.buffer.read(513).rstrip(b'\x00').decode()
            if not password or len(password)>512:return 1
            result=request('/api/auth/login',method='POST',body={'username':name,'password':password})
            return 0 if result.get('username')==name else 1
        if os.environ.get('PAM_TYPE')=='account':
            result=request('/api/users')
            return 0 if any(u['username']==name for u in result['users']) else 1
    except Exception:
        return 1
    return 1


if __name__=='__main__':raise SystemExit(main())
