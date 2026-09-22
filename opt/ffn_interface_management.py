#!/usr/bin/env python3
"""Interface-local service permissions, independent of transit zones/rules.

The selected DP network owner installs these rules before assigning addresses.
This permits traffic to existing listeners; it never creates an admin listener.
"""
import ipaddress
import json
from pathlib import Path
import re
import shutil
import subprocess

SERVICES = {'ssh': ('tcp', [22]), 'http': ('tcp', [80]),
            'https': ('tcp', [443, 8443]), 'snmp': ('udp', [161]),
            'telnet': ('tcp', [23]), 'response-pages': ('tcp', [6080, 6081, 6082]),
            'user-id': ('tcp', [5007]), 'userid-service': ('tcp', [5007]),
            'userid-syslog-listener-ssl': ('tcp', [6514]),
            'userid-syslog-listener-udp': ('udp', [514])}


def yes(value):
    return str(value).strip().lower() in ('yes', 'true', '1', 'on')


def profile(device, name):
    result = {'profile': name or '', 'ping': False, 'tcp': [], 'udp': [], 'sources': []}
    if not name:
        return result
    entries = [p for p in device.findall('./network/profiles/interface-management-profile/entry')
               if p.get('name') == name]
    if len(entries) != 1:
        raise ValueError('Interface management profile is missing or ambiguous: ' + name)
    entry = entries[0]
    def enabled(key):
        values = [entry.findtext(key), entry.findtext('permit_' + key.replace('-', '_'))]
        values = [v for v in values if v is not None]
        if len({yes(v) for v in values}) > 1:
            raise ValueError('Conflicting management profile service fields: ' + key)
        return bool(values and yes(values[0]))
    if yes(entry.findtext('enabled', 'yes')):
        result['ping'] = enabled('ping')
        for key, (proto, ports) in SERVICES.items():
            if enabled(key):
                result[proto].extend(ports)
    for parent in ('permitted-ip', 'permitted_ips'):
        node = entry.find(parent)
        if node is None:
            continue
        if node.text and node.text.strip():
            # Older generic resource editor serializes lists as JSON text.
            try:
                values = json.loads(node.text)
            except ValueError:
                values = [node.text.strip()]
            if not isinstance(values, list):
                raise ValueError('Permitted sources must be a list')
            result['sources'].extend(values)
        for child in node:
            value = child.get('name') if child.tag == 'entry' else child.text
            if value:
                result['sources'].append(value)
    result['tcp'] = sorted(set(result['tcp']))
    result['udp'] = sorted(set(result['udp']))
    result['sources'] = sorted({str(ipaddress.ip_network(v, strict=False)) for v in result['sources']})
    return validate(result)


def validate(value):
    if (not isinstance(value, dict) or set(value) != {'profile', 'ping', 'tcp', 'udp', 'sources'}
            or not isinstance(value['profile'], str) or len(value['profile']) > 127
            or type(value['ping']) is not bool):
        raise ValueError('Invalid interface management permissions')
    for proto in ('tcp', 'udp'):
        if (not isinstance(value[proto], list) or len(value[proto]) > 32
                or any(type(p) is not int or not 1 <= p <= 65535 for p in value[proto])):
            raise ValueError('Invalid interface service ports')
    if not isinstance(value['sources'], list) or len(value['sources']) > 256:
        raise ValueError('Invalid permitted source list')
    for source in value['sources']:
        ipaddress.ip_network(source, strict=True)
    return value


def render(name, settings, exists=False):
    if not isinstance(name, str) or not re.fullmatch(r'[a-zA-Z][a-zA-Z0-9_.-]{0,14}', name):
        raise ValueError('Invalid managed interface name')
    permissions = validate(settings['management'])
    table = 'ffn_ifmgmt_' + name.replace('.', '_').replace('-', '_')
    lines = ['delete table inet ' + table] if exists else []
    lines += ['table inet ' + table + ' {', ' chain input {',
              '  type filter hook input priority -10; policy accept;',
              '  iifname != ' + json.dumps(name) + ' return',
              '  ct state invalid counter drop',
              '  ct direction reply ct state established,related accept',
              '  icmp type { destination-unreachable, time-exceeded, parameter-problem } accept',
              '  icmpv6 type { destination-unreachable, packet-too-big, time-exceeded, parameter-problem } accept',
              '  ip6 hoplimit 255 icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-advert } accept',
              '  udp sport 67 udp dport 68 accept',
              '  ip6 saddr fe80::/10 udp sport 547 udp dport 546 accept']
    for version, family, echo in ((4, 'ip', 'icmp'), (6, 'ip6', 'icmpv6')):
        addresses = sorted({str(ipaddress.ip_interface(a).ip) for a in settings.get('addresses', [])
                            if ipaddress.ip_interface(a).version == version})
        sources = [s for s in permissions['sources'] if ipaddress.ip_network(s).version == version]
        if not addresses or (permissions['sources'] and not sources):
            continue
        match = family + ' daddr { ' + ', '.join(addresses) + ' } '
        if sources:
            match += family + ' saddr { ' + ', '.join(sources) + ' } '
        if permissions['ping']:
            lines.append('  ' + match + echo + ' type echo-request counter accept')
        for proto in ('tcp', 'udp'):
            if permissions[proto]:
                lines.append('  ' + match + proto + ' dport { ' + ', '.join(map(str, permissions[proto])) + ' } counter accept')
    lines += ['  counter drop', ' }', '}']
    return table, '\n'.join(lines) + '\n'


def apply(namespace, name, settings, remove=False):
    table, _ = render(name, settings)
    nft = '/usr/local/ffn-dp/sbin/nft'
    if not Path(nft).is_file():
        nft = shutil.which('nft')
    if not nft:
        raise RuntimeError('nftables is required for interface management profiles')
    argv = ['ip', 'netns', 'exec', namespace, nft]
    listing = subprocess.run(argv + ['-j', 'list', 'tables'], capture_output=True, text=True, timeout=10)
    if listing.returncode:
        raise RuntimeError('Cannot inspect interface management enforcement: ' + listing.stderr[-512:])
    exists = any(x.get('table', {}).get('family') == 'inet' and x.get('table', {}).get('name') == table
                 for x in json.loads(listing.stdout)['nftables'])
    if remove and not exists:
        return
    _, script = render(name, settings, exists)
    if remove:
        script = 'delete table inet ' + table + '\n'
    for flags in (['-c', '-f', '-'], ['-f', '-']):
        result = subprocess.run(argv + flags, input=script, capture_output=True, text=True, timeout=10)
        if result.returncode:
            raise RuntimeError('Interface management enforcement failed: ' + result.stderr[-512:])
