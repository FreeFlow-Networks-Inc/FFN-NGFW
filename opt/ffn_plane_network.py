#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""CLI for requests sent to the MP control daemon.

Named for the network resource it began with and still defaulting to it, but
the resource is now a choice: an installed platform's own resources are
reachable without a second tool, and `inventory` lists what a node offers
rather than requiring the caller to know it already.

`result` and `resolve` are the recovery pair the protocol requires and that the
core previously implemented on the daemon side without ever offering a client.
An interrupted apply leaves that resource blocked against further writes;
clearing it needs the original request ID -- which `inventory` reports, so it
does not have to have been kept -- and a revision the operator has actually
read back after inspecting and repairing runtime state. Neither command
replays the interrupted operation nor claims that it succeeded.

Imports nothing from the management API: the tool for a box whose manager is
unhappy must not depend on the manager's dependencies.
"""
import argparse
import asyncio
import json
import sys
import uuid

from ffn_planed import INVENTORY, LIMIT, decode, rpc

# The wire action behind each subcommand. `patch` predates this tool's other
# actions and is kept as the spelling operators and scripts already use.
WIRE = {'patch': 'apply'}
# Payload comes from stdin for these; the rest build their own, so a stray
# pipe cannot turn a read into a write.
STDIN = ('validate', 'patch', 'lookup')


def build(args, parser):
    action = WIRE.get(args.action, args.action)
    if action == 'inventory':
        return INVENTORY, action, {}
    if args.action in STDIN:
        payload = decode(sys.stdin.buffer.read(LIMIT + 1))
        if not isinstance(payload, dict):
            parser.error('%s payload must be a JSON object' % args.action)
        return args.resource, action, payload
    if action == 'status':
        return args.resource, action, {}
    if not args.recover:
        parser.error('%s needs --recover UUID; run inventory to list blocked requests' % args.action)
    if action == 'result':
        return args.resource, action, {'request_id': args.recover}
    if args.observed_revision is None:
        parser.error('resolve needs --observed-revision, read back from runtime status '
                     'after inspecting and repairing the interrupted change')
    return args.resource, action, {'request_id': args.recover,
                                   'observed_revision': args.observed_revision}


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('action', choices=['status', 'validate', 'patch', 'lookup',
                                      'result', 'resolve', 'inventory'])
    p.add_argument('--socket', default='/run/ffn-plane-mp/control.sock')
    p.add_argument('--resource', default='network',
                   help='resource to address; inventory names those available')
    p.add_argument('--request-id', default=None,
                   help='reuse a UUID to retry delivery of the same apply')
    p.add_argument('--recover', metavar='UUID',
                   help='request to read (result) or reconcile (resolve)')
    p.add_argument('--observed-revision', type=int,
                   help='revision observed after repairing an interrupted apply (resolve)')
    args = p.parse_args()
    resource, action, payload = build(args, p)
    request = {'v': 1, 'id': args.request_id or str(uuid.uuid4()),
               'resource': resource, 'action': action, 'payload': payload}
    result = asyncio.run(rpc(args.socket, request))
    if not result['ok']:
        print(json.dumps(result), file=sys.stderr)
        raise SystemExit(1)
    body = result['result'] if isinstance(result['result'], dict) else {'result': result['result']}
    print(json.dumps(dict(body, control={'id': request['id'], 'state': result['state'],
                                         'trace': result['trace']})))


if __name__ == '__main__': main()
