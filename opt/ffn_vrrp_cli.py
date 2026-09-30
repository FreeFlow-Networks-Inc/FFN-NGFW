"""Console commands using the existing authenticated control-daemon adapter."""
import copy
import json
from urllib.parse import urlencode


def command(tokens, api, token):
    endpoint = '/api/config/network/vrrp'
    if tokens[0] == 'show':
        query = {'source': 'candidate', 'scope': 'vsys1'}
        for arg in tokens[3:]:
            if arg in ('running', 'candidate'): query['source'] = arg
            elif arg.startswith('scope='): query['scope'] = arg[6:]
            else: raise ValueError('Use show policies vrrp [candidate|running] [scope=vsys1]')
        print(json.dumps(api(endpoint + '?' + urlencode(query), token=token), indent=2)); return
    if len(tokens) < 5 or tokens[3] not in ('add', 'edit', 'remove'):
        raise ValueError('Use request policies vrrp add|edit|remove <name> [field=value ...]')
    operation, name = tokens[3:5]
    values = {}
    for arg in tokens[5:]:
        key, sep, value = arg.partition('=')
        if not sep or key in values: raise ValueError('Use unique field=value arguments')
        values[key] = value
    data = api(endpoint + '?' + urlencode({'scope': values.get('scope', 'vsys1')}), token=token)
    if 'revision' not in data: raise ValueError('Unable to read candidate VRRP configuration')
    existing = next((e for e in data['entries'] if e['name'] == name), None)
    payload = dict(action={'add': 'create', 'edit': 'update', 'remove': 'delete'}[operation], name=name, revision=data['revision'])
    if operation == 'remove':
        if values: raise ValueError('Remove accepts only the entry name')
    else:
        if operation == 'edit' and existing is None: raise ValueError('VRRP entry not found')
        mode = values.get('mode', existing['mode'] if existing else 'participate')
        if mode not in data['defaults']: raise ValueError('Select participate or passthrough')
        entry = copy.deepcopy(existing if existing and mode == existing['mode'] else dict(data['defaults'][mode], name=name, mode=mode))
        for key, value in values.items():
            if key not in entry or key == 'name': raise ValueError('Unknown field for this mode: ' + key)
            if key in ('enabled', 'preempt'):
                if value not in ('yes', 'no'): raise ValueError(key + ' must be yes or no')
                value = value == 'yes'
            elif key in ('vrid', 'priority', 'advert_ms'):
                try: value = int(value)
                except ValueError: raise ValueError(key + ' must be an integer')
            elif key in ('virtual_addresses', 'track_interfaces'): value = value.split(',') if value else []
            entry[key] = value
        payload['entry'] = entry
    print(json.dumps(api(endpoint, method='POST', body=payload, token=token), indent=2))
