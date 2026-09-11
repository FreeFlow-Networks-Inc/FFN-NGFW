#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Compatibility CLI for network requests sent to the MP control daemon."""
import argparse
import asyncio
import json
import sys
import uuid
from ffn_plane_api import rpc
from ffn_planed import decode


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('action', choices=['status','validate','patch','lookup'])
    p.add_argument('--socket', default='/run/ffn-plane-mp/control.sock')
    p.add_argument('--request-id', default=None)
    args = p.parse_args()
    request = {'v':1, 'id':args.request_id or str(uuid.uuid4()), 'resource':'network',
               'action':'apply' if args.action == 'patch' else args.action,
               'payload':{} if args.action == 'status' else decode(sys.stdin.buffer.read(65537))}
    result = asyncio.run(rpc(args.socket, request))
    if not result['ok']:
        print(json.dumps(result), file=sys.stderr)
        raise SystemExit(1)
    print(json.dumps(dict(result['result'], control={'id':request['id'], 'state':result['state'], 'trace':result['trace']})))


if __name__ == '__main__': main()
