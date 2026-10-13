#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""FFN Protect: a GlobalProtect-compatible portal and gateway on the dataplane.

Own code, written from the public description of the client protocol (the
OpenConnect project documents the endpoints, the request bodies, the XML the
client parses, the ESP keying and the SSL-tunnel framing from the client
side). No vendor file is involved. Standard library only: the dataplane has
no third-party modules.

The daemon is the control plane. It serves the HTTPS endpoints on the
configured WAN addresses, authenticates (local users, LDAP simple bind,
RADIUS PAP), assigns tunnel addresses, hands each client its ESP keys and
registers the session with ffn-protect-tunnel, the C worker that owns the
gateway's tunnel device and terminates ESP in UDP 4501. Clients whose ESP is
blocked fall back to the SSL tunnel: the daemon frames their packets and
moves them to the worker over a socket pair, so both kinds share the device
and the security policy sees one interface.

Intent, applied through the platform's `protect` plane resource like the
DHCP server's (`/etc/ffn/protect.json`):

    {"revision": N, "configuration": "<commit digest>", "applied_at": T,
     "protect": {"certificates": {name: {"certificate": PEM, "private_key": PEM, "chain": PEM}},
                 "auth_profiles": {name: {"method": "local" | "ldap" | "radius", ...}},
                 "users": {name: {"phash": "pbkdf2-sha256$iterations$salt$hash"}},
                 "portals": {name: {"interface", "address", "certificate", "auth_profile",
                                    "gateways": [{"name", "priority", "description"}], "root_ca", ...}},
                 "gateways": {name: {"interface", "address", "certificate", "auth_profile", "tunnel",
                                     "tunnel_address", "pools": [[first, last]], "dns", "dns_suffix",
                                     "access_routes", "exclude_routes", "tunnel_mode", "crypto",
                                     "idle_timeout", "login_lifetime", "mtu", "hip"}}}}

Command line: status | validate | apply (JSON on stdin) | serve.
"""
import base64
import hashlib
import hmac
import http.server
import ipaddress
import json
import os
import re
import secrets
import select
import signal
import socket
import socketserver
import ssl
import struct
import subprocess
import sys
import threading
import time
import urllib.parse
import uuid
from pathlib import Path
from xml.sax.saxutils import escape

# The environment overrides exist for the integration run in a network namespace on a build host; the
# dataplane unit sets none of them.
INTENT = Path(os.environ.get('FFN_PROTECT_INTENT', '/etc/ffn/protect.json'))
RUN = Path(os.environ.get('FFN_PROTECT_RUN', '/run/ffn-protect'))
WORKER = os.environ.get('FFN_PROTECT_WORKER', '/usr/local/sbin/ffn-protect-tunnel')
OWNER_ROWS = Path(os.environ.get('FFN_PROTECT_OWNER_ROWS', '/run'))
HTTPS_PORT = int(os.environ.get('FFN_PROTECT_HTTPS_PORT', '443'))
ESP_PORT = 4501
CLIENT_VERSION = '4100'
NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,62}\Z')
DEVICE = re.compile(r'(p[1-9][0-9]{0,2}|ae[1-9][0-9]{0,2})(\.[1-9][0-9]{0,3})?\Z')
TUNNEL = re.compile(r'tunnel\.[1-9][0-9]{0,3}\Z')
USERNAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9._@\\-]{0,63}\Z')
CRYPTO = {'aes-128-cbc': 16, 'aes-256-cbc': 32}
TUNNEL_MODES = ('esp-ssl', 'ssl-only')
MAX_BODY = 64 * 1024
MAX_REPORT = 512 * 1024
PBKDF2_ITERATIONS = 210000
GPST_MAGIC = 0x1a2b3c4d
GPST_HEADER = struct.Struct('!IHH8s')
GPST_TRAILER = b'\x01\x00\x00\x00\x00\x00\x00\x00'
MAX_SESSIONS = 1000
FAILURE_WINDOW = 300
FAILURE_LIMIT = 10


def log(message):
    print(time.strftime('%Y-%m-%dT%H:%M:%S ') + message, flush=True)


def atomic(path, value):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + '.' + str(os.getpid()) + '.tmp')
    temporary.write_text(json.dumps(value, sort_keys=True))
    temporary.chmod(0o600)
    temporary.replace(path)


def boot_id():
    try:
        return Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    except OSError:
        return None


def process_start(pid):
    try:
        return int(Path('/proc/%d/stat' % pid).read_text().rsplit(') ', 1)[1].split()[19])
    except (OSError, ValueError, IndexError):
        return None


# ---------------------------------------------------------------- credentials
def make_phash(password, iterations=PBKDF2_ITERATIONS, salt=None):
    """pbkdf2-sha256$iterations$salt$hash, the only form the local user database stores."""
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, iterations)
    return 'pbkdf2-sha256$%d$%s$%s' % (iterations, base64.b64encode(salt).decode(), base64.b64encode(digest).decode())


def verify_phash(phash, password):
    try:
        scheme, iterations, salt, digest = phash.split('$')
        iterations = int(iterations)
        if scheme != 'pbkdf2-sha256' or not 1000 <= iterations <= 10000000:
            return False
        actual = hashlib.pbkdf2_hmac('sha256', password.encode(), base64.b64decode(salt), iterations)
        return hmac.compare_digest(actual, base64.b64decode(digest))
    except (ValueError, TypeError):
        return False


def ber(tag, payload):
    n = len(payload)
    if n < 128:
        length = bytes([n])
    elif n < 256:
        length = b'\x81' + bytes([n])
    else:
        length = b'\x82' + n.to_bytes(2, 'big')
    return bytes([tag]) + length + payload


def ber_read(data, offset=0):
    """(tag, payload, next offset) of the element at offset; ValueError when malformed or incomplete."""
    if offset + 2 > len(data):
        raise ValueError('short element')
    tag, first, offset = data[offset], data[offset + 1], offset + 2
    if first < 128:
        length = first
    else:
        count = first & 0x7f
        if count == 0 or count > 4 or offset + count > len(data):
            raise ValueError('bad length')
        length = int.from_bytes(data[offset:offset + count], 'big')
        offset += count
    if offset + length > len(data):
        raise ValueError('truncated element')
    return tag, data[offset:offset + length], offset + length


def ldap_escape(value):
    """RFC 4514 escaping of an attribute value placed in a DN template."""
    out = []
    for i, ch in enumerate(value):
        if ch in ',+"\\<>;=' or (ch == '#' and i == 0) or (ch == ' ' and i in (0, len(value) - 1)):
            out.append('\\' + ch)
        else:
            out.append(ch)
    return ''.join(out)


def ldap_bind(host, port, use_tls, dn, password, timeout=5, ca=None, verify=True):
    """True when the directory accepts a simple bind as dn, False for refused credentials; OSError/ValueError otherwise."""
    if not password:
        return False   # an empty password is an anonymous bind, which every directory accepts
    request = ber(0x30, ber(0x02, b'\x01') + ber(0x60, ber(0x02, b'\x03') + ber(0x04, dn.encode()) + ber(0x80, password.encode())))
    with socket.create_connection((host, port), timeout=timeout) as raw:
        sock = raw
        if use_tls:
            context = ssl.create_default_context(cadata=ca) if ca else ssl.create_default_context()
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            if not verify:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            sock = context.wrap_socket(raw, server_hostname=host)
        sock.sendall(request)
        data = b''
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                raise ValueError('directory closed the connection')
            data += chunk
            try:
                tag, message, _ = ber_read(data)
                break
            except ValueError:
                if len(data) > 65536:
                    raise
        if tag != 0x30:
            raise ValueError('not an LDAP message')
        _, _, offset = ber_read(message)
        tag, response, _ = ber_read(message, offset)
        if tag != 0x61:
            raise ValueError('not a bind response')
        tag, code, _ = ber_read(response)
        if tag != 0x0a or len(code) != 1:
            raise ValueError('bind result malformed')
        if code[0] == 0:
            return True
        if code[0] in (32, 34, 48, 49, 50, 53):
            return False
        raise ValueError('LDAP result code %d' % code[0])


def radius_pap(host, port, secret, username, password, nas_ip, timeout=5, retries=2):
    """True on Access-Accept, False on Access-Reject; OSError when no authentic reply arrives."""
    identifier, authenticator, secret = secrets.randbelow(256), secrets.token_bytes(16), secret.encode()
    padded = password.encode()[:128] or bytes(16)
    padded += bytes(-len(padded) % 16)
    cipher, previous = b'', authenticator
    # RFC 2865 section 5.2: PAP hides the password with MD5(shared secret + authenticator) chained per
    # block, and the Response Authenticator is MD5 over the reply. The algorithm is the protocol's, not a
    # storage hash; no stronger digest interoperates with a RADIUS server.
    for i in range(0, len(padded), 16):
        block = hashlib.md5(secret + previous).digest()  # lgtm[py/weak-sensitive-data-hashing]
        previous = bytes(a ^ b for a, b in zip(padded[i:i + 16], block))
        cipher += previous

    def attribute(kind, value):
        return bytes([kind, len(value) + 2]) + value
    attributes = (attribute(1, username.encode()[:253]) + attribute(2, cipher) + attribute(4, socket.inet_aton(nas_ip))
                  + attribute(32, b'ffn-protect') + attribute(6, (2).to_bytes(4, 'big')) + attribute(61, (5).to_bytes(4, 'big')))
    request = struct.pack('!BBH', 1, identifier, 20 + len(attributes)) + authenticator + attributes
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        for _ in range(retries + 1):
            sock.sendto(request, (host, port))
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                try:
                    reply, _peer = sock.recvfrom(4096)
                except socket.timeout:
                    break
                if len(reply) < 20 or reply[1] != identifier:
                    continue
                code, _, length = struct.unpack('!BBH', reply[:4])
                if not 20 <= length <= len(reply):
                    continue
                expected = hashlib.md5(reply[:4] + authenticator + reply[20:length] + secret).digest()  # lgtm[py/weak-sensitive-data-hashing]
                if not hmac.compare_digest(expected, reply[4:20]):
                    continue
                return code == 2
    raise OSError('no reply from RADIUS server ' + host)


class Authenticator:
    """One decision per login attempt, with per-source and per-user failure limits."""
    DUMMY = make_phash('ffn', 1000)

    def __init__(self, profiles, users, ldap=ldap_bind, radius=radius_pap, clock=time.monotonic):
        self.profiles, self.users, self.ldap, self.radius, self.clock = profiles, users, ldap, radius, clock
        self.failures, self.lock = {}, threading.Lock()

    def limited(self, key):
        now = self.clock()
        with self.lock:
            recent = [t for t in self.failures.get(key, []) if now - t < FAILURE_WINDOW]
            self.failures[key] = recent
            return len(recent) >= FAILURE_LIMIT

    def failed(self, key):
        with self.lock:
            self.failures.setdefault(key, []).append(self.clock())

    def check(self, profile_name, username, password, source, nas_ip):
        """(accepted, detail). The detail never carries the password or a directory's words."""
        if not USERNAME.fullmatch(username or '') or not isinstance(password, str) or len(password) > 256:
            return False, 'invalid username or password'
        if self.limited('source:' + source) or self.limited('user:' + username):
            return False, 'too many failed attempts'
        profile = self.profiles.get(profile_name)
        if profile is None:
            return False, 'authentication profile missing'
        allow = profile.get('allow')
        accepted, detail = False, 'invalid username or password'
        if allow and username not in allow:
            verify_phash(self.DUMMY, password)
        elif profile['method'] == 'local':
            user = self.users.get(username)
            accepted = verify_phash(user['phash'] if user else self.DUMMY, password) and user is not None
        elif profile['method'] == 'ldap':
            dn = profile['bind_template'].replace('{user}', ldap_escape(username) if '=' in profile['bind_template'] else username)
            detail = 'directory unreachable'
            for server in profile['servers']:
                try:
                    accepted = self.ldap(server['host'], server['port'], profile.get('ssl', True), dn, password,
                                         timeout=profile.get('timeout', 5), ca=profile.get('ca') or None, verify=profile.get('verify', True))
                    detail = 'invalid username or password'
                    break
                except (OSError, ValueError) as error:
                    log('protect: ldap %s:%d: %s' % (server['host'], server['port'], str(error)[:120]))
        elif profile['method'] == 'radius':
            detail = 'authentication server unreachable'
            for server in profile['servers']:
                try:
                    accepted = self.radius(server['host'], server['port'], profile['secret'], username, password, nas_ip,
                                           timeout=profile.get('timeout', 5))
                    detail = 'invalid username or password'
                    break
                except OSError as error:
                    log('protect: radius %s:%d: %s' % (server['host'], server['port'], str(error)[:120]))
        if not accepted:
            self.failed('source:' + source)
            self.failed('user:' + username)
            return False, detail
        return True, ''


# ---------------------------------------------------------------- intent
def ip4(value, what):
    try:
        return str(ipaddress.IPv4Address(value))
    except (ValueError, TypeError):
        raise ValueError('%s: not an IPv4 address: %r' % (what, value))


def check_name(value, what):
    if not isinstance(value, str) or not NAME.fullmatch(value):
        raise ValueError('%s: invalid name %r' % (what, value))
    return value


def check_int(value, what, low, high):
    if type(value) is not int or not low <= value <= high:
        raise ValueError('%s: must be an integer from %d to %d' % (what, low, high))
    return value


def pem_blocks(text, label):
    if not isinstance(text, str) or ('-----BEGIN ' + label) not in text or ('-----END ' + label) not in text:
        raise ValueError('expected a PEM ' + label)
    return text.strip() + '\n'


def validate_pools(pools, what):
    result, total = [], 0
    if not isinstance(pools, list) or not pools:
        raise ValueError(what + ': at least one address pool is required')
    for pool in pools:
        if not isinstance(pool, list) or len(pool) != 2:
            raise ValueError(what + ': pools are [first, last] pairs')
        first, last = ipaddress.IPv4Address(ip4(pool[0], what)), ipaddress.IPv4Address(ip4(pool[1], what))
        if last < first:
            raise ValueError(what + ': pool end precedes its start')
        total += int(last) - int(first) + 1
        if total > 65536:
            raise ValueError(what + ': pools exceed 65536 addresses')
        result.append([str(first), str(last)])
    return result


def validate_servers(servers, what, default_port):
    if not isinstance(servers, list) or not 1 <= len(servers) <= 4:
        raise ValueError(what + ': one to four servers are required')
    result = []
    for server in servers:
        if not isinstance(server, dict) or not isinstance(server.get('host'), str) or not 1 <= len(server['host']) <= 253:
            raise ValueError(what + ': servers are {host, port}')
        if not re.fullmatch(r'[A-Za-z0-9.:-]+', server['host']):
            raise ValueError(what + ': invalid server host')
        result.append(dict(host=server['host'], port=check_int(server.get('port', default_port), what + ' port', 1, 65535)))
    return result


def validate_intent(request):
    """The daemon's own rules for a compiled intent; returns the normalised copy or raises ValueError."""
    if not isinstance(request, dict) or not isinstance(request.get('protect'), dict):
        raise ValueError('intent must carry a protect object')
    data = request['protect']
    unknown = set(data) - {'certificates', 'auth_profiles', 'users', 'portals', 'gateways'}
    if unknown:
        raise ValueError('unknown intent sections: ' + ', '.join(sorted(unknown)))
    out = dict(certificates={}, auth_profiles={}, users={}, portals={}, gateways={})
    for name, cert in (data.get('certificates') or {}).items():
        check_name(name, 'certificate')
        if not isinstance(cert, dict):
            raise ValueError('certificate %s: invalid' % name)
        out['certificates'][name] = dict(certificate=pem_blocks(cert.get('certificate'), 'CERTIFICATE'),
                                         private_key=pem_blocks(cert.get('private_key'), 'PRIVATE KEY'),
                                         chain=pem_blocks(cert['chain'], 'CERTIFICATE') if cert.get('chain') else '')
    for name, user in (data.get('users') or {}).items():
        check_name(name, 'user')
        if not isinstance(user, dict) or not isinstance(user.get('phash'), str) or not user['phash'].startswith('pbkdf2-sha256$'):
            raise ValueError('user %s: phash must be a pbkdf2-sha256 hash' % name)
        out['users'][name] = dict(phash=user['phash'])
    for name, profile in (data.get('auth_profiles') or {}).items():
        check_name(name, 'authentication profile')
        what = 'authentication profile ' + name
        if not isinstance(profile, dict) or profile.get('method') not in ('local', 'ldap', 'radius'):
            raise ValueError(what + ': method must be local, ldap or radius')
        row = dict(method=profile['method'])
        allow = profile.get('allow')
        if allow is not None:
            if not isinstance(allow, list) or any(not isinstance(u, str) or not USERNAME.fullmatch(u) for u in allow):
                raise ValueError(what + ': allow list must name users')
            row['allow'] = sorted(set(allow))
        row['timeout'] = check_int(profile.get('timeout', 5), what + ' timeout', 1, 60)
        if profile['method'] == 'ldap':
            template = profile.get('bind_template')
            if not isinstance(template, str) or '{user}' not in template or len(template) > 512:
                raise ValueError(what + ': bind_template must contain {user}')
            row.update(servers=validate_servers(profile.get('servers'), what, 636), bind_template=template,
                       ssl=bool(profile.get('ssl', True)), verify=bool(profile.get('verify', True)),
                       ca=pem_blocks(profile['ca'], 'CERTIFICATE') if profile.get('ca') else '')
        elif profile['method'] == 'radius':
            secret = profile.get('secret')
            if not isinstance(secret, str) or not 1 <= len(secret) <= 128:
                raise ValueError(what + ': a shared secret is required')
            row.update(servers=validate_servers(profile.get('servers'), what, 1812), secret=secret)
        out['auth_profiles'][name] = row
    listeners = {}
    for name, portal in (data.get('portals') or {}).items():
        check_name(name, 'portal')
        what = 'portal ' + name
        if not isinstance(portal, dict):
            raise ValueError(what + ': invalid')
        row = dict(interface=portal.get('interface'), address=ip4(portal.get('address'), what),
                   certificate=portal.get('certificate'), auth_profile=portal.get('auth_profile'), gateways=[],
                   root_ca=pem_blocks(portal['root_ca'], 'CERTIFICATE') if portal.get('root_ca') else '',
                   login_lifetime=check_int(portal.get('login_lifetime', 2592000), what + ' login_lifetime', 60, 31536000),
                   connect_method=portal.get('connect_method', 'user-logon'))
        if not isinstance(row['interface'], str) or not DEVICE.fullmatch(row['interface']):
            raise ValueError(what + ': interface must be a dataplane device')
        if row['certificate'] not in out['certificates']:
            raise ValueError(what + ': certificate %r is not in the intent' % row['certificate'])
        if row['auth_profile'] not in out['auth_profiles']:
            raise ValueError(what + ': authentication profile %r is not in the intent' % row['auth_profile'])
        if row['connect_method'] not in ('user-logon', 'on-demand', 'pre-logon'):
            raise ValueError(what + ': connect_method')
        if not isinstance(portal.get('gateways'), list) or not portal['gateways']:
            raise ValueError(what + ': at least one gateway entry is required')
        for entry in portal['gateways']:
            if not isinstance(entry, dict) or not isinstance(entry.get('name'), str) or not re.fullmatch(r'[A-Za-z0-9.-]{1,253}', entry['name']):
                raise ValueError(what + ': gateway entries name a host')
            row['gateways'].append(dict(name=entry['name'], priority=check_int(entry.get('priority', 1), what + ' gateway priority', 1, 5),
                                        description=str(entry.get('description', ''))[:64]))
        if listeners.get((row['interface'], row['address']), {}).get('portal'):
            raise ValueError(what + ': another portal already uses this address')
        listeners.setdefault((row['interface'], row['address']), {})['portal'] = name
        out['portals'][name] = row
    for name, gateway in (data.get('gateways') or {}).items():
        check_name(name, 'gateway')
        what = 'gateway ' + name
        if not isinstance(gateway, dict):
            raise ValueError(what + ': invalid')
        row = dict(interface=gateway.get('interface'), address=ip4(gateway.get('address'), what), certificate=gateway.get('certificate'),
                   auth_profile=gateway.get('auth_profile'), tunnel=gateway.get('tunnel'),
                   pools=validate_pools(gateway.get('pools'), what), dns=[], dns_suffix=[], access_routes=[], exclude_routes=[],
                   tunnel_mode=gateway.get('tunnel_mode', 'esp-ssl'), crypto=gateway.get('crypto', 'aes-128-cbc'),
                   idle_timeout=check_int(gateway.get('idle_timeout', 3600), what + ' idle_timeout', 60, 604800),
                   login_lifetime=check_int(gateway.get('login_lifetime', 2592000), what + ' login_lifetime', 60, 31536000),
                   mtu=check_int(gateway.get('mtu', 1400), what + ' mtu', 576, 1500), hip=bool(gateway.get('hip', False)))
        if not isinstance(row['interface'], str) or not DEVICE.fullmatch(row['interface']):
            raise ValueError(what + ': interface must be a dataplane device')
        if row['certificate'] not in out['certificates']:
            raise ValueError(what + ': certificate %r is not in the intent' % row['certificate'])
        if row['auth_profile'] not in out['auth_profiles']:
            raise ValueError(what + ': authentication profile %r is not in the intent' % row['auth_profile'])
        if not isinstance(row['tunnel'], str) or not TUNNEL.fullmatch(row['tunnel']):
            raise ValueError(what + ': tunnel must be a tunnel.N unit')
        try:
            tunnel_address = ipaddress.IPv4Interface(gateway.get('tunnel_address'))
        except (ValueError, TypeError):
            raise ValueError(what + ': tunnel_address must be an IPv4 address with prefix')
        if tunnel_address.network.prefixlen > 30:
            raise ValueError(what + ': tunnel_address needs a prefix of 30 bits or fewer')
        row['tunnel_address'] = str(tunnel_address)
        for first, last in row['pools']:
            for edge in (first, last):
                if ipaddress.IPv4Address(edge) == tunnel_address.ip:
                    raise ValueError(what + ': the pool contains the tunnel address itself')
        for key, limit in (('dns', 4), ('dns_suffix', 8), ('access_routes', 256), ('exclude_routes', 256)):
            values = gateway.get(key) or []
            if not isinstance(values, list) or len(values) > limit:
                raise ValueError('%s: %s accepts up to %d entries' % (what, key, limit))
            for value in values:
                if key == 'dns':
                    row[key].append(ip4(value, what + ' dns'))
                elif key == 'dns_suffix':
                    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9.-]{1,253}', value):
                        raise ValueError(what + ': invalid dns suffix')
                    row[key].append(value)
                else:
                    try:
                        row[key].append(str(ipaddress.IPv4Network(value)))
                    except (ValueError, TypeError):
                        raise ValueError('%s: %s entries are IPv4 networks' % (what, key))
        if row['tunnel_mode'] not in TUNNEL_MODES:
            raise ValueError(what + ': tunnel_mode must be esp-ssl or ssl-only')
        if row['crypto'] not in CRYPTO:
            raise ValueError(what + ': crypto must be aes-128-cbc or aes-256-cbc')
        if any(g['tunnel'] == row['tunnel'] for g in out['gateways'].values()):
            raise ValueError(what + ': tunnel %s is used by another gateway' % row['tunnel'])
        if listeners.get((row['interface'], row['address']), {}).get('gateway'):
            raise ValueError(what + ': another gateway already uses this address')
        listeners.setdefault((row['interface'], row['address']), {})['gateway'] = name
        out['gateways'][name] = row
    for (interface, address), owners in listeners.items():
        names = [out['portals'][owners['portal']]['certificate'] if 'portal' in owners else None,
                 out['gateways'][owners['gateway']]['certificate'] if 'gateway' in owners else None]
        if None not in names and names[0] != names[1]:
            raise ValueError('portal and gateway on %s must share one certificate' % address)
    return out


def read_intent():
    try:
        value = json.loads(INTENT.read_text())
        if type(value.get('revision')) is not int:
            raise ValueError('revision')
        return value
    except (OSError, ValueError, AttributeError):
        return dict(revision=0, protect=dict(certificates={}, auth_profiles={}, users={}, portals={}, gateways={}))


def intent_digest(protect):
    """What the commit path compares: the whole intent, secrets included, never the secrets themselves."""
    return hashlib.sha256(json.dumps(protect, sort_keys=True).encode()).hexdigest()


def redacted(protect):
    """The intent as the plane channel and the console may see it: no private keys, hashes or shared secrets."""
    out = json.loads(json.dumps(protect))
    for cert in out.get('certificates', {}).values():
        cert['private_key'] = '(private)'
    for user in out.get('users', {}).values():
        user['phash'] = '(hashed)'
    for profile in out.get('auth_profiles', {}).values():
        if 'secret' in profile:
            profile['secret'] = '(secret)'
    return out


# ---------------------------------------------------------------- XML the clients parse
def xml_text(tag, value):
    return '<%s>%s</%s>' % (tag, escape(str(value)), tag)


def prelogin_xml(portal_name, saml=None):
    parts = ['<?xml version="1.0" encoding="UTF-8"?>', '<prelogin-response>', xml_text('status', 'Success'), '<ccusername></ccusername>',
             '<autosubmit>false</autosubmit>', '<msg></msg>', '<newmsg></newmsg>', xml_text('authentication-message', 'Enter login credentials'),
             xml_text('username-label', 'Username'), xml_text('password-label', 'Password'), xml_text('panos-version', '1'),
             xml_text('region', 'US')]
    if saml:
        parts += [xml_text('saml-auth-method', saml['method']), xml_text('saml-request', saml['request'])]
    parts.append('</prelogin-response>')
    return '\n'.join(parts) + '\n'


def error_xml(message):
    return '<?xml version="1.0" encoding="UTF-8"?>\n<response status="error">' + xml_text('error', message) + '</response>\n'


def portal_config_xml(name, portal, cookie, prelogon_cookie='empty'):
    lines = ['<?xml version="1.0" encoding="UTF-8"?>', '<policy>', xml_text('portal-name', name),
             xml_text('portal-config-version', CLIENT_VERSION), xml_text('version', hashlib.sha256(name.encode()).hexdigest()[:32]),
             xml_text('client-role', 'global-protect-full'), xml_text('agent-user-override', 'off'),
             xml_text('connect-method', portal['connect_method']), xml_text('on-demand', 'yes' if portal['connect_method'] == 'on-demand' else 'no'),
             xml_text('refresh-config', 'yes'), xml_text('refresh-config-interval', '24'),
             '<authentication-modifier><none/></authentication-modifier>',
             '<authentication-override><accept-cookie>yes</accept-cookie><cookie-lifetime><lifetime-in-hours>%d</lifetime-in-hours>'
             '</cookie-lifetime><generate-cookie>yes</generate-cookie></authentication-override>' % max(1, portal['login_lifetime'] // 3600),
             '<gateways><cutoff-time>5</cutoff-time><external><list>']
    for entry in portal['gateways']:
        lines.append('<entry name="%s"><priority-rule><entry name="Any"><priority>%d</priority></entry></priority-rule>'
                     '<priority>%d</priority><manual>yes</manual>%s</entry>'
                     % (escape(entry['name'], {'"': '&quot;'}), entry['priority'], entry['priority'],
                        xml_text('description', entry['description'] or entry['name'])))
    lines += ['</list></external></gateways>',
              '<hip-collection><hip-report-interval>3600</hip-report-interval><max-wait-time>20</max-wait-time></hip-collection>']
    if portal.get('root_ca'):
        lines.append('<root-ca><entry name="FFN Root CA">' + xml_text('cert', portal['root_ca']) + '<install-in-cert-store>yes</install-in-cert-store></entry></root-ca>')
    lines += [xml_text('portal-userauthcookie', cookie), xml_text('portal-prelogonuserauthcookie', prelogon_cookie),
              '<scep-cert-auth-cookie>empty</scep-cert-auth-cookie>', '</policy>']
    return '\n'.join(lines) + '\n'


def login_xml(authcookie, portal_name, user, preferred_ip='', portal_cookie='', domain=''):
    """The gateway's answer to login.esp: argument positions are what the clients index."""
    arguments = ['(null)', authcookie, '(null)', portal_name, user, 'FFN Protect', 'default', domain or '(null)',
                 '(null)', '(null)', '(null)', '(null)', 'tunnel', '-1', CLIENT_VERSION, preferred_ip or '(null)',
                 portal_cookie or '(null)', '(null)', '(null)', '4', 'unknown']
    body = ''.join('<argument>%s</argument>' % escape(a) for a in arguments)
    return '<?xml version="1.0" encoding="UTF-8"?>\n<jnlp><application-desc>' + body + '</application-desc></jnlp>\n'


def esp_xml(esp):
    def key(name, value):
        return '<%s><bits>%d</bits><val>%s</val></%s>' % (name, len(value) * 8, value.hex(), name)
    return ('<ipsec>' + xml_text('udp-port', ESP_PORT) + xml_text('ipsec-mode', 'esp-tunnel') + xml_text('enc-algo', esp['crypto'])
            + xml_text('hmac-algo', 'sha1') + xml_text('c2s-spi', '0x%08X' % esp['c2s_spi']) + xml_text('s2c-spi', '0x%08X' % esp['s2c_spi'])
            + key('akey-s2c', esp['s2c_auth']) + key('ekey-s2c', esp['s2c_enc']) + key('akey-c2s', esp['c2s_auth']) + key('ekey-c2s', esp['c2s_enc'])
            + '</ipsec>')


def tunnel_config_xml(gateway_name, gateway, session):
    lines = ['<?xml version="1.0" encoding="UTF-8"?>', '<response status="success">', xml_text('need-tunnel', 'yes'),
             xml_text('ssl-tunnel-url', '/ssl-tunnel-connect.sslvpn'), xml_text('portal', session['portal'] or gateway_name),
             xml_text('user', session['user']), xml_text('lifetime', gateway['login_lifetime']), xml_text('timeout', 3600),
             xml_text('disconnect-on-idle', gateway['idle_timeout']), xml_text('bw-c2s', 0), xml_text('bw-s2c', 0),
             xml_text('gw-address', str(ipaddress.IPv4Interface(gateway['tunnel_address']).ip)), xml_text('ip-address', session['client_ip']),
             xml_text('netmask', '255.255.255.255'), xml_text('default-gateway', session['client_ip']), xml_text('mtu', gateway['mtu'])]
    for tag, values in (('dns', gateway['dns']), ('dns-suffix', gateway['dns_suffix']), ('access-routes', gateway['access_routes']),
                        ('exclude-access-routes', gateway['exclude_routes'])):
        if values:
            lines.append('<%s>%s</%s>' % (tag, ''.join(xml_text('member', v) for v in values), tag))
    if session.get('esp'):
        lines.append(esp_xml(session['esp']))
    lines.append('</response>')
    return '\n'.join(lines) + '\n'


# ---------------------------------------------------------------- the data path pieces the daemon owns
class Pool:
    def __init__(self, ranges):
        self.free, self.used = [], set()
        for first, last in ranges:
            self.free.extend(str(ipaddress.IPv4Address(n)) for n in range(int(ipaddress.IPv4Address(first)), int(ipaddress.IPv4Address(last)) + 1))
        self.size = len(self.free)

    def allocate(self, preferred=None):
        if preferred in self.free:
            self.free.remove(preferred)
            self.used.add(preferred)
            return preferred
        if not self.free:
            return None
        address = self.free.pop(0)
        self.used.add(address)
        return address

    def release(self, address):
        if address in self.used:
            self.used.discard(address)
            self.free.append(address)


def gpst_frames(buffer):
    """(frames, rest): complete (ethertype, payload) frames at the head of buffer; ValueError on a bad header."""
    frames = []
    while len(buffer) >= GPST_HEADER.size:
        magic, ethertype, length, _ = GPST_HEADER.unpack_from(buffer)
        if magic != GPST_MAGIC:
            raise ValueError('bad tunnel frame magic')
        if len(buffer) < GPST_HEADER.size + length:
            break
        frames.append((ethertype, bytes(buffer[GPST_HEADER.size:GPST_HEADER.size + length])))
        buffer = buffer[GPST_HEADER.size + length:]
    return frames, buffer


def gpst_frame(ethertype, payload):
    return GPST_HEADER.pack(GPST_MAGIC, ethertype, len(payload), GPST_TRAILER) + payload


def tls_send(sock, data, timeout=5):
    deadline = time.monotonic() + timeout
    while data:
        try:
            sent = sock.send(data)
            data = data[sent:]
        except ssl.SSLWantWriteError:
            if time.monotonic() > deadline:
                raise OSError('tunnel client is not reading')
            select.select([], [sock], [], 0.5)
        except ssl.SSLWantReadError:
            select.select([sock], [], [], 0.5)


def pump_ssl_tunnel(tls, pair, idle_timeout, alive, counters):
    """Move packets between the client's SSL tunnel and the worker's socket pair until either side ends."""
    tls.setblocking(False)
    pair.setblocking(False)
    buffer, last = b'', time.monotonic()
    while alive():
        wanted = [pair] + ([] if tls.pending() else [tls])
        readable, _, _ = select.select(wanted, [], [], 1.0)
        if tls in readable or tls.pending():
            try:
                chunk = tls.recv(65536)
            except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
                chunk = None
            except (ssl.SSLError, OSError):
                return 'client closed'
            if chunk == b'':
                return 'client closed'
            if chunk:
                last = time.monotonic()
                buffer += chunk
                if len(buffer) > 2 * 65536 + GPST_HEADER.size:
                    return 'oversized frame'
                frames, buffer = gpst_frames(buffer)
                for ethertype, payload in frames:
                    if ethertype == 0:
                        tls_send(tls, gpst_frame(0, b''))
                    elif ethertype == 0x0800 and 20 <= len(payload) <= 65535:
                        try:
                            pair.send(payload)
                            counters['rx'] += 1
                        except (BlockingIOError, OSError):
                            counters['drops'] += 1
        if pair in readable:
            try:
                packet = pair.recv(65536)
            except BlockingIOError:
                packet = None
            except OSError:
                return 'worker closed'
            if packet == b'':
                return 'worker closed'
            if packet:
                tls_send(tls, gpst_frame(0x0800, packet))
                counters['tx'] += 1
        if time.monotonic() - last > idle_timeout:
            return 'idle'
    return 'shutdown'


class Worker:
    """One ffn-protect-tunnel process per gateway, and its control connection."""

    def __init__(self, name, gateway, run=RUN, binary=WORKER, runner=subprocess.run):
        self.name, self.gateway, self.run, self.binary, self.runner = name, gateway, run, binary, runner
        self.control = run / (name + '.sock')
        self.process, self.connection, self.lock = None, None, threading.Lock()
        self.token = str(uuid.uuid4())

    def start(self):
        self.control.unlink(missing_ok=True)
        self.process = subprocess.Popen([self.binary, '--tun', self.gateway['tunnel'], '--control', str(self.control),
                                         '--bind', self.gateway['address'], '--port', str(ESP_PORT)],
                                        stdin=subprocess.DEVNULL, stdout=sys.stdout, stderr=subprocess.STDOUT)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise RuntimeError('tunnel worker exited with status %s' % self.process.returncode)
            if self.control.exists():
                try:
                    self.request(dict(op='ping'))
                    break
                except OSError:
                    pass
            time.sleep(0.1)
        else:
            raise RuntimeError('tunnel worker did not open its control socket')
        tunnel = self.gateway['tunnel']
        try:
            # IPv4 tunnels only: without this the kernel's IPv6 autoconfiguration sends solicitations into the device
            Path('/proc/sys/net/ipv6/conf', tunnel, 'disable_ipv6').write_text('1\n')
        except OSError:
            pass
        for argv in (['ip', 'link', 'set', 'dev', tunnel, 'up', 'mtu', str(self.gateway['mtu'])],
                     ['ip', 'addr', 'replace', self.gateway['tunnel_address'], 'dev', tunnel],
                     ['ip', 'link', 'set', 'dev', tunnel, 'alias', 'ffn-protect:' + self.token]):
            result = self.runner(argv, capture_output=True, text=True, timeout=10)
            if result.returncode:
                raise RuntimeError('%s: %s' % (' '.join(argv[:3]), result.stderr.strip()[:200]))

    def alive(self):
        return self.process is not None and self.process.poll() is None

    def stop(self):
        with self.lock:
            if self.connection:
                self.connection.close()
                self.connection = None
        if self.alive():
            self.process.terminate()
            try:
                self.process.wait(5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(5)
        self.control.unlink(missing_ok=True)

    def connect(self):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        sock.settimeout(5)
        sock.connect(str(self.control))
        return sock

    def request(self, message, fd=None):
        """One JSON operation and its reply; a dropped control connection is retried once."""
        payload = json.dumps(message).encode()
        with self.lock:
            for attempt in (1, 2):
                try:
                    if self.connection is None:
                        self.connection = self.connect()
                    if fd is None:
                        self.connection.send(payload)
                    else:
                        socket.send_fds(self.connection, [payload], [fd])
                    reply = self.connection.recv(65536)
                    if not reply:
                        raise OSError('control connection closed')
                    return json.loads(reply)
                except (OSError, ValueError):
                    if self.connection:
                        self.connection.close()
                    self.connection = None
                    if attempt == 2:
                        raise
        raise OSError('control request failed')

    def route(self, client_ip, add=True):
        argv = ['ip', 'route', 'replace' if add else 'del', client_ip + '/32', 'dev', self.gateway['tunnel']]
        self.runner(argv, capture_output=True, text=True, timeout=10)


# ---------------------------------------------------------------- sessions
class Session:
    FIELDS = ('id', 'user', 'portal', 'gateway', 'source', 'client_ip', 'mode', 'created', 'last_seen', 'hostname',
              'report', 'hip_checked', 'registered', 'tunnel_result')

    def __init__(self, **values):
        for field in self.FIELDS:
            setattr(self, field, values.get(field))
        self.authcookie = secrets.token_hex(32)
        self.esp = None
        self.created = self.last_seen = time.time()
        self.lock = threading.RLock()

    def view(self, counters=None):
        row = dict(id=self.id, user=self.user, portal=self.portal, gateway=self.gateway, source=self.source, client_ip=self.client_ip,
                   mode=self.mode, created=self.created, last_seen=self.last_seen, hostname=self.hostname, hip=bool(self.report),
                   registered=bool(self.registered), result=self.tunnel_result)
        if counters:
            row.update(rx_packets=counters.get('rx_packets', 0), tx_packets=counters.get('tx_packets', 0),
                       rx_bytes=counters.get('rx_bytes', 0), tx_bytes=counters.get('tx_bytes', 0), peer=counters.get('peer', ''),
                       drops=counters.get('drops', 0), replays=counters.get('replays', 0), auth_failures=counters.get('auth_failures', 0))
        return row


class GatewayState:
    def __init__(self, name, spec):
        self.name, self.spec = name, spec
        self.pool = Pool(spec['pools'])
        self.worker = Worker(name, spec)
        self.sessions = {}            # id -> Session
        self.next_id = 1
        self.spis = set()
        self.counters = {}            # id -> worker counters
        self.totals = {}
        self.lock = threading.RLock()
        self.state, self.detail = 'starting', ''

    def restart_needed(self, spec):
        keys = ('interface', 'address', 'tunnel', 'tunnel_address', 'mtu', 'pools')
        return any(self.spec[k] != spec[k] for k in keys)

    def new_spi(self):
        while True:
            spi = secrets.randbits(32)
            if spi >= 256 and spi not in self.spis:
                self.spis.add(spi)
                return spi


class Daemon:
    def __init__(self, run=RUN):
        self.run = run
        self.intent = dict(revision=0, protect=validate_intent(dict(protect={})))
        self.gateways = {}            # name -> GatewayState
        self.listeners = {}           # (interface, address) -> Listener
        self.wanted = {}              # (interface, address) -> (owners, certificate path)
        self.retry_after = {}         # (interface, address) -> monotonic time of the next bind attempt
        self.by_cookie = {}           # authcookie -> Session
        self.portal_cookies = {}      # cookie -> (user, portal, expires)
        self.authenticator = Authenticator({}, {})
        self.lock = threading.RLock()
        self.running = True
        self.reload_requested = False
        self.process_start = process_start(os.getpid())
        self.boot = boot_id()
        self.started = time.time()

    # ---- lifecycle
    def serve(self):
        self.run.mkdir(mode=0o700, parents=True, exist_ok=True)
        (self.run / 'pid').write_text(str(os.getpid()) + '\n')
        signal.signal(signal.SIGHUP, lambda *a: setattr(self, 'reload_requested', True))
        signal.signal(signal.SIGTERM, lambda *a: setattr(self, 'running', False))
        signal.signal(signal.SIGINT, lambda *a: setattr(self, 'running', False))
        self.load()
        log('protect: serving revision %d: %d listener(s), %d gateway(s)' % (self.intent['revision'], len(self.listeners), len(self.gateways)))
        threading.Thread(target=self.heartbeat, daemon=True, name='heartbeat').start()
        try:
            while self.running:
                if self.reload_requested:
                    self.reload_requested = False
                    self.load()
                self.tick()
                time.sleep(2)
        finally:
            for listener in list(self.listeners.values()):
                listener.shutdown()
                listener.server_close()
            for gateway in list(self.gateways.values()):
                for session in list(gateway.sessions.values()):
                    self.end_session(session, 'shutdown')
                gateway.worker.stop()
            for path in (self.run / 'status.json', self.run / 'pid'):
                path.unlink(missing_ok=True)
            for gateway in self.gateways.values():
                (OWNER_ROWS / ('ffn-protect-' + gateway.name + '-status.json')).unlink(missing_ok=True)
            log('protect: stopped')

    def load(self):
        intent = read_intent()
        try:
            protect = validate_intent(intent)
        except ValueError as error:
            log('protect: intent rejected: ' + str(error))
            return
        intent['protect'] = protect
        certs = self.run / 'certs'
        certs.mkdir(mode=0o700, parents=True, exist_ok=True)
        for name, cert in protect['certificates'].items():
            path = certs / (name + '.pem')
            text = cert['certificate'] + cert['chain'] + cert['private_key']
            if not path.exists() or path.read_text() != text:
                temporary = path.with_suffix('.tmp')
                temporary.write_text(text)
                temporary.chmod(0o600)
                temporary.replace(path)
        for stale in certs.glob('*.pem'):
            if stale.stem not in protect['certificates']:
                stale.unlink()
        with self.lock:
            self.authenticator = Authenticator(protect['auth_profiles'], protect['users'])
            for name in list(self.gateways):
                if name not in protect['gateways'] or self.gateways[name].restart_needed(protect['gateways'][name]):
                    self.stop_gateway(name)
            for name, spec in protect['gateways'].items():
                if name in self.gateways:
                    self.gateways[name].spec = spec
                else:
                    self.start_gateway(name, spec)
            wanted = {}
            for kind in ('portals', 'gateways'):
                for name, spec in protect[kind].items():
                    wanted.setdefault((spec['interface'], spec['address']), {})[kind[:-1]] = name
            for key, listener in list(self.listeners.items()):
                owners = wanted.get(key)
                if owners is None or listener.certificate != self.certificate_for(protect, owners):
                    listener.shutdown()
                    listener.server_close()
                    del self.listeners[key]
                    log('protect: listener %s:%d closed' % (key[1], HTTPS_PORT))
            self.wanted = {key: (owners, certs / (self.certificate_for(protect, owners) + '.pem')) for key, owners in wanted.items()}
            self.retry_after = {}
            self.intent = intent
            self.ensure_listeners()
        self.write_status()

    def ensure_listeners(self):
        """Open every wanted listener that is not open; a failed bind (the address not yet assigned, the
        port still held by the interface relay) is retried every ten seconds rather than once per reload."""
        now = time.monotonic()
        for key, (owners, path) in list(self.wanted.items()):
            if key in self.listeners:
                self.listeners[key].owners = owners
                continue
            if self.retry_after.get(key, 0) > now:
                continue
            try:
                self.listeners[key] = Listener(self, key[0], key[1], owners, path)
                self.retry_after.pop(key, None)
                log('protect: listening on %s:%d (%s)' % (key[1], HTTPS_PORT, ', '.join('%s %s' % kv for kv in sorted(owners.items()))))
            except OSError as error:
                self.retry_after[key] = now + 10
                log('protect: listener %s:%d failed: %s (retrying)' % (key[1], HTTPS_PORT, error))

    @staticmethod
    def certificate_for(protect, owners):
        if 'gateway' in owners:
            return protect['gateways'][owners['gateway']]['certificate']
        return protect['portals'][owners['portal']]['certificate']

    def start_gateway(self, name, spec):
        gateway = GatewayState(name, spec)
        self.gateways[name] = gateway
        try:
            gateway.worker.start()
            gateway.state, gateway.detail = 'up', ''
            log('protect: gateway %s up on %s (%s, worker pid %d)' % (name, spec['address'], spec['tunnel'], gateway.worker.process.pid))
        except (RuntimeError, OSError) as error:
            gateway.state, gateway.detail = 'error', str(error)[:200]
            log('protect: gateway %s failed: %s' % (name, gateway.detail))

    def stop_gateway(self, name):
        gateway = self.gateways.pop(name)
        for session in list(gateway.sessions.values()):
            self.end_session(session, 'gateway stopped')
        gateway.worker.stop()
        (OWNER_ROWS / ('ffn-protect-' + name + '-status.json')).unlink(missing_ok=True)
        log('protect: gateway %s stopped' % name)

    def tick(self):
        """Counters from the workers, expiry, dead-worker recovery, status and the owner rows."""
        now = time.time()
        for gateway in list(self.gateways.values()):
            if gateway.state == 'up' and not gateway.worker.alive():
                gateway.state, gateway.detail = 'error', 'tunnel worker exited'
                for session in list(gateway.sessions.values()):
                    self.end_session(session, 'worker exited')
                log('protect: gateway %s: worker exited, restarting' % gateway.name)
            if gateway.state == 'error':
                gateway.worker.stop()
                try:
                    gateway.worker.start()
                    gateway.state, gateway.detail = 'up', ''
                except (RuntimeError, OSError) as error:
                    gateway.detail = str(error)[:200]
                    continue
            try:
                stats = gateway.worker.request(dict(op='stats'))
                gateway.counters = {row['id']: row for row in stats.get('sessions', [])}
                gateway.totals = dict(tun=stats.get('tun', {}), udp=stats.get('udp', {}))
            except (OSError, ValueError) as error:
                gateway.detail = 'stats: ' + str(error)[:100]
            for session in list(gateway.sessions.values()):
                counters = gateway.counters.get(session.id)
                if counters and counters.get('last_rx'):
                    session.last_seen = max(session.last_seen, counters['last_rx'])
                if now - session.last_seen > gateway.spec['idle_timeout'] and session.mode == 'esp':
                    self.end_session(session, 'idle')
                elif now - session.created > gateway.spec['login_lifetime']:
                    self.end_session(session, 'login lifetime')
        with self.lock:
            for cookie, (user, portal, expires) in list(self.portal_cookies.items()):
                if expires < now:
                    del self.portal_cookies[cookie]
            self.ensure_listeners()
        self.write_status()

    def heartbeat(self):
        """The owner rows the platform's binding discovery reads, on their own clock: a stalled worker stats
        call must never let a row age past the discovery window and withdraw the tunnel from the policy."""
        while self.running:
            try:
                self.owner_rows()
            except OSError as error:
                log('protect: owner rows: ' + str(error)[:120])
            time.sleep(1)

    def owner_rows(self):
        for gateway in list(self.gateways.values()):
            if gateway.state != 'up' or not gateway.worker.alive():
                continue
            try:
                ifindex = socket.if_nametoindex(gateway.spec['tunnel'])
            except OSError:
                ifindex = None
            atomic((OWNER_ROWS / ('ffn-protect-' + gateway.name + '-status.json')),
                   dict(owner='protect-' + gateway.name, gateway=gateway.name, boot_id=self.boot, pid=os.getpid(), process_start=self.process_start,
                        updated_monotonic=time.monotonic(), token=gateway.worker.token, tunnel=gateway.spec['tunnel'], ifindex=ifindex,
                        configuration_revision=self.intent.get('configuration') or '', worker_pid=gateway.worker.process.pid))

    def write_status(self):
        now = time.time()
        gateways, sessions = {}, []
        for gateway in list(self.gateways.values()):
            rows = [s.view(gateway.counters.get(s.id)) for s in list(gateway.sessions.values())]
            sessions.extend(rows)
            gateways[gateway.name] = dict(state=gateway.state, detail=gateway.detail, tunnel=gateway.spec['tunnel'], address=gateway.spec['address'],
                                          worker_pid=gateway.worker.process.pid if gateway.worker.alive() else None,
                                          sessions=len(rows), pool_size=gateway.pool.size, pool_used=len(gateway.pool.used), totals=gateway.totals)
        listeners = [dict(interface=key[0], address=key[1], port=HTTPS_PORT, owners=listener.owners) for key, listener in self.listeners.items()]
        atomic(self.run / 'status.json', dict(schema=1, boot_id=self.boot, pid=os.getpid(), process_start=self.process_start, started=self.started,
                                              revision=self.intent['revision'], configuration=self.intent.get('configuration'),
                                              digest=intent_digest(self.intent['protect']), time=now,
                                              listeners=listeners, gateways=gateways, sessions=sessions))

    # ---- sessions
    def session_by_cookie(self, user, authcookie):
        with self.lock:
            session = self.by_cookie.get(authcookie or '')
        if session is None or session.user != user:
            return None
        return session

    def new_session(self, gateway, user, portal, source, hostname, preferred_ip=None):
        # one tunnel per user and client address: a reconnect replaces the earlier session
        with gateway.lock:
            replaced = [s for s in gateway.sessions.values() if s.user == user and s.source == source]
        for existing in replaced:
            self.end_session(existing, 'replaced by a new login')
        with gateway.lock:
            if len(gateway.sessions) >= MAX_SESSIONS:
                return None, 'gateway session limit reached'
            client_ip = gateway.pool.allocate(preferred_ip)
            if client_ip is None:
                return None, 'address pool exhausted'
            session = Session(id=gateway.next_id, user=user, portal=portal, gateway=gateway.name, source=source, client_ip=client_ip,
                              mode='pending', hostname=hostname)
            gateway.next_id += 1
            gateway.sessions[session.id] = session
        with self.lock:
            self.by_cookie[session.authcookie] = session
        return session, ''

    def end_session(self, session, reason):
        gateway = self.gateways.get(session.gateway)
        with session.lock:
            if session.tunnel_result == 'ended':
                return
            session.tunnel_result = 'ended'
        with self.lock:
            self.by_cookie.pop(session.authcookie, None)
        if gateway is not None:
            with gateway.lock:
                gateway.sessions.pop(session.id, None)
                gateway.pool.release(session.client_ip)
                if session.esp:
                    gateway.spis.discard(session.esp['c2s_spi'])
            if session.registered and gateway.worker.alive():
                try:
                    gateway.worker.request(dict(op='del', id=session.id))
                except (OSError, ValueError):
                    pass
                gateway.worker.route(session.client_ip, add=False)
        log('protect: session %d (%s from %s) ended: %s' % (session.id, session.user, session.source, reason))

    def register_esp(self, gateway, session, crypto):
        with session.lock:
            if session.registered:
                gateway.worker.request(dict(op='del', id=session.id))
                gateway.worker.route(session.client_ip, add=False)
                session.registered = False
            with gateway.lock:
                if session.esp:
                    gateway.spis.discard(session.esp['c2s_spi'])
                esp = dict(crypto=crypto, c2s_spi=gateway.new_spi(), s2c_spi=secrets.randbits(32) | 0x100,
                           c2s_enc=secrets.token_bytes(CRYPTO[crypto]), s2c_enc=secrets.token_bytes(CRYPTO[crypto]),
                           c2s_auth=secrets.token_bytes(20), s2c_auth=secrets.token_bytes(20))
            reply = gateway.worker.request(dict(op='add', id=session.id, client=session.client_ip, spi_in='0x%08x' % esp['c2s_spi'],
                                                spi_out='0x%08x' % esp['s2c_spi'], enc=esp['c2s_enc'].hex(), auth=esp['c2s_auth'].hex(),
                                                enc_out=esp['s2c_enc'].hex(), auth_out=esp['s2c_auth'].hex()))
            if not reply.get('ok'):
                raise OSError('worker refused the session: ' + str(reply.get('error')))
            gateway.worker.route(session.client_ip, add=True)
            session.esp, session.mode, session.registered = esp, 'esp', True

    def register_ssl(self, gateway, session, fd):
        with session.lock:
            if session.registered:
                gateway.worker.request(dict(op='del', id=session.id))
                session.registered = False
            reply = gateway.worker.request(dict(op='ssl', id=session.id, client=session.client_ip), fd=fd)
            if not reply.get('ok'):
                raise OSError('worker refused the session: ' + str(reply.get('error')))
            gateway.worker.route(session.client_ip, add=True)
            session.mode, session.registered = 'ssl', True


# ---------------------------------------------------------------- HTTPS
class Listener(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 64

    def __init__(self, daemon, interface, address, owners, certificate_path):
        self.daemon, self.interface, self.owners = daemon, interface, owners
        self.certificate = certificate_path.stem
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.context.load_cert_chain(str(certificate_path))
        super().__init__((address, HTTPS_PORT), Handler, bind_and_activate=False)
        try:
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, interface.encode() + b'\0')
        except OSError:
            pass
        self.server_bind()
        self.server_activate()
        threading.Thread(target=self.serve_forever, kwargs=dict(poll_interval=1), daemon=True, name='listener-' + address).start()

    def server_bind(self):
        # not HTTPServer.server_bind: that resolves the bound address to a name, and a reverse
        # lookup of a WAN address from the forwarding namespace can stall for seconds
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = self.server_address[0], self.server_address[1]

    def get_request(self):
        sock, address = self.socket.accept()
        sock.settimeout(30)
        return self.context.wrap_socket(sock, server_side=True, do_handshake_on_connect=False), address

    def handle_error(self, request, client_address):
        pass


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def setup(self):
        self.request.do_handshake()
        super().setup()

    def log_message(self, fmt, *args):
        pass

    def version_string(self):
        return 'FFN Protect'

    # ---- helpers
    @property
    def daemon(self):
        return self.server.daemon

    def read_body(self, limit=MAX_BODY):
        try:
            length = int(self.headers.get('Content-Length') or 0)
        except ValueError:
            raise ValueError('Content-Length')
        if not 0 <= length <= limit:
            raise ValueError('body too large')
        return self.rfile.read(length) if length else b''

    def form(self, limit=MAX_BODY):
        parsed = urllib.parse.urlsplit(self.path)
        values = {k: v[0] for k, v in urllib.parse.parse_qs(parsed.query, keep_blank_values=True).items()}
        if self.command == 'POST':
            body = self.read_body(limit).decode('utf-8', 'replace')
            values.update({k: v[0] for k, v in urllib.parse.parse_qs(body, keep_blank_values=True).items()})
        return parsed.path, values

    def reply(self, text, status=200, content_type='application/xml; charset=utf-8'):
        data = text.encode()
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(data)
        self.close_connection = True

    def refuse(self, message, status=200):
        self.reply(error_xml(message), status)

    def portal(self):
        name = self.server.owners.get('portal')
        return (name, self.daemon.intent['protect']['portals'][name]) if name else (None, None)

    def gateway(self):
        name = self.server.owners.get('gateway')
        return (name, self.daemon.gateways.get(name)) if name else (None, None)

    def source(self):
        return self.client_address[0]

    # ---- routing
    def do_GET(self):
        self.route()

    def do_POST(self):
        self.route()

    def route(self):
        try:
            path, values = self.form(MAX_REPORT if self.path.startswith('/ssl-vpn/hipreport.esp') else MAX_BODY)
        except (ValueError, OSError):
            return self.reply('', 400, 'text/plain')
        if path == '/ssl-tunnel-connect.sslvpn':
            return self.tunnel(values)
        handlers = {'/global-protect/prelogin.esp': self.prelogin, '/ssl-vpn/prelogin.esp': self.prelogin,
                    '/global-protect/getconfig.esp': self.portal_config, '/ssl-vpn/login.esp': self.login,
                    '/ssl-vpn/getconfig.esp': self.tunnel_config, '/ssl-vpn/hipreportcheck.esp': self.hip_check,
                    '/ssl-vpn/hipreport.esp': self.hip_report, '/ssl-vpn/logout.esp': self.logout}
        handler = handlers.get(path)
        if handler is None:
            return self.reply('', 404, 'text/plain')
        try:
            handler(values)
        except (OSError, ValueError, KeyError) as error:
            log('protect: %s from %s failed: %s' % (path, self.source(), str(error)[:160]))
            try:
                self.refuse('Internal error', 500)
            except OSError:
                pass

    # ---- endpoints
    def prelogin(self, values):
        portal_name, portal = self.portal()
        gateway_name, gateway = self.gateway()
        if portal is None and gateway is None:
            return self.reply('', 404, 'text/plain')
        self.reply(prelogin_xml(portal_name or gateway_name))

    def portal_config(self, values):
        portal_name, portal = self.portal()
        if portal is None:
            return self.reply('', 404, 'text/plain')
        user = values.get('user', '')
        cookie = values.get('portal-userauthcookie', '')
        accepted = False
        if cookie and cookie != 'empty':
            with self.daemon.lock:
                record = self.daemon.portal_cookies.get(cookie)
            accepted = record is not None and record[0] == user and record[1] == portal_name and record[2] > time.time()
        if not accepted:
            accepted, detail = self.daemon.authenticator.check(portal['auth_profile'], user, values.get('passwd', ''), self.source(), portal['address'])
            if not accepted:
                log('protect: portal %s login refused for %r from %s: %s' % (portal_name, user[:64], self.source(), detail))
                return self.refuse('Invalid username or password')
            cookie = secrets.token_hex(32)
            with self.daemon.lock:
                self.daemon.portal_cookies[cookie] = (user, portal_name, time.time() + portal['login_lifetime'])
        log('protect: portal %s: %s from %s received the configuration' % (portal_name, user, self.source()))
        self.reply(portal_config_xml(portal_name, portal, cookie))

    def login(self, values):
        gateway_name, gateway = self.gateway()
        if gateway is None:
            return self.reply('', 404, 'text/plain')
        if gateway.state != 'up':
            return self.refuse('Gateway unavailable', 503)
        user = values.get('user', '')
        cookie = values.get('portal-userauthcookie', '')
        portal_name = values.get('portal') or values.get('server') or ''
        accepted = False
        if cookie and cookie != 'empty':
            with self.daemon.lock:
                record = self.daemon.portal_cookies.get(cookie)
            accepted = record is not None and record[0] == user and record[2] > time.time()
            if accepted:
                portal_name = record[1]
        if not accepted:
            accepted, detail = self.daemon.authenticator.check(gateway.spec['auth_profile'], user, values.get('passwd', ''), self.source(), gateway.spec['address'])
            if not accepted:
                log('protect: gateway %s login refused for %r from %s: %s' % (gateway_name, user[:64], self.source(), detail))
                return self.refuse('Invalid username or password')
        hostname = re.sub(r'[^A-Za-z0-9._-]', '', values.get('computer', ''))[:64]
        preferred = values.get('preferred-ip') or None
        if preferred:
            try:
                preferred = str(ipaddress.IPv4Address(preferred))
            except ValueError:
                preferred = None
        session, detail = self.daemon.new_session(gateway, user, portal_name if NAME.fullmatch(portal_name or '') else '', self.source(), hostname, preferred)
        if session is None:
            log('protect: gateway %s: no session for %s from %s: %s' % (gateway_name, user, self.source(), detail))
            return self.refuse('Gateway unavailable', 503)
        log('protect: gateway %s: session %d for %s from %s (%s)' % (gateway_name, session.id, user, self.source(), session.client_ip))
        self.reply(login_xml(session.authcookie, session.portal or gateway_name, user, session.client_ip, cookie if accepted and cookie else ''))

    def authorised(self, values):
        """The session named by user and authcookie on this gateway, or None after a refusal was sent."""
        gateway_name, gateway = self.gateway()
        if gateway is None:
            self.reply('', 404, 'text/plain')
            return None, None
        session = self.daemon.session_by_cookie(values.get('user', ''), values.get('authcookie', ''))
        if session is None or session.gateway != gateway_name:
            self.refuse('Invalid session', 401)
            return gateway, None
        session.last_seen = time.time()
        return gateway, session

    def tunnel_config(self, values):
        gateway, session = self.authorised(values)
        if session is None:
            return
        spec = gateway.spec
        offered = [a.strip() for a in values.get('enc-algo', '').split(',') if a.strip()]
        hmacs = [a.strip() for a in values.get('hmac-algo', 'sha1').split(',') if a.strip()]
        crypto = spec['crypto'] if spec['crypto'] in offered or not offered else next((a for a in offered if a in CRYPTO), None)
        if spec['tunnel_mode'] == 'esp-ssl' and crypto and 'sha1' in hmacs and gateway.state == 'up':
            try:
                self.daemon.register_esp(gateway, session, crypto)
            except (OSError, ValueError) as error:
                log('protect: session %d: esp registration failed: %s' % (session.id, str(error)[:120]))
                session.esp = None
        else:
            session.esp = None
        self.reply(tunnel_config_xml(gateway.name, spec, dict(portal=session.portal, user=session.user, client_ip=session.client_ip, esp=session.esp)))

    def hip_check(self, values):
        gateway, session = self.authorised(values)
        if session is None:
            return
        needed = gateway.spec['hip'] and not session.report
        session.hip_checked = time.time()
        self.reply('<?xml version="1.0" encoding="UTF-8"?>\n<response status="success">' + xml_text('hip-report-needed', 'yes' if needed else 'no') + '</response>\n')

    def hip_report(self, values):
        gateway, session = self.authorised(values)
        if session is None:
            return
        report = values.get('report', '')[:MAX_REPORT]
        session.report = dict(received=time.time(), size=len(report),
                              hostname=(re.search(r'<host-name>([^<]{1,64})</host-name>', report) or [None, None])[1],
                              os=(re.search(r'<os>([^<]{1,128})</os>', report) or [None, None])[1])
        if session.report['hostname'] and not session.hostname:
            session.hostname = re.sub(r'[^A-Za-z0-9._-]', '', session.report['hostname'])[:64]
        self.reply('<?xml version="1.0" encoding="UTF-8"?>\n<response status="success"></response>\n')

    def logout(self, values):
        gateway, session = self.authorised(values)
        if session is None:
            return
        self.daemon.end_session(session, 'client logout')
        self.reply('<?xml version="1.0" encoding="UTF-8"?>\n<response status="success"><logout>yes</logout></response>\n')

    def tunnel(self, values):
        gateway_name, gateway = self.gateway()
        if gateway is None:
            return self.reply('', 404, 'text/plain')
        session = self.daemon.session_by_cookie(values.get('user', ''), values.get('authcookie', ''))
        if session is None or session.gateway != gateway_name or gateway.state != 'up':
            return self.reply('', 502, 'text/plain')
        ours, theirs = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        try:
            self.daemon.register_ssl(gateway, session, theirs.fileno())
        except (OSError, ValueError) as error:
            ours.close()
            theirs.close()
            log('protect: session %d: ssl registration failed: %s' % (session.id, str(error)[:120]))
            return self.reply('', 503, 'text/plain')
        theirs.close()
        counters = dict(rx=0, tx=0, drops=0)
        log('protect: session %d: ssl tunnel for %s from %s' % (session.id, session.user, self.source()))
        try:
            self.connection.sendall(b'START_TUNNEL')
            result = pump_ssl_tunnel(self.connection, ours, gateway.spec['idle_timeout'],
                                     lambda: self.daemon.running and session.tunnel_result != 'ended', counters)
        except (OSError, ValueError) as error:
            result = str(error)[:80]
        finally:
            ours.close()
        self.close_connection = True
        if session.tunnel_result != 'ended':
            if result in ('client closed', 'idle', 'oversized frame', 'worker closed'):
                self.daemon.end_session(session, 'ssl tunnel ' + result)
            else:
                session.tunnel_result = result


# ---------------------------------------------------------------- command line
def running_status(run=RUN):
    try:
        value = json.loads((run / 'status.json').read_text())
    except (OSError, ValueError):
        return None
    if value.get('boot_id') != boot_id() or process_start(value.get('pid', 0)) != value.get('process_start'):
        return None
    return value


def status():
    intent = read_intent()
    protect = intent.get('protect', {})
    summary = {kind: sorted(protect.get(kind, {})) for kind in ('portals', 'gateways', 'auth_profiles', 'users', 'certificates')}
    return dict(config=dict(revision=intent['revision'], configuration=intent.get('configuration'), digest=intent_digest(protect),
                            protect=redacted(protect), summary=summary),
                boot_id=boot_id(), running=running_status())


def apply(request, clock=time.time, run=RUN):
    if not isinstance(request, dict) or set(request) - {'revision', 'protect', 'configuration'}:
        raise ValueError('apply takes revision, protect and configuration')
    current = read_intent()
    if type(request.get('revision')) is not int or request['revision'] != current['revision']:
        raise ValueError('revision conflict; refresh status')
    protect = validate_intent(request)
    intent = dict(revision=current['revision'] + 1, configuration=request.get('configuration'), applied_at=clock(), protect=protect)
    atomic(INTENT, intent)
    signalled = False
    try:
        os.kill(int((run / 'pid').read_text().strip()), signal.SIGHUP)
        signalled = True
    except (OSError, ValueError):
        pass
    deadline = time.monotonic() + 8
    while signalled and time.monotonic() < deadline:
        running = running_status(run)
        if running and running.get('revision') == intent['revision']:
            break
        time.sleep(0.2)
    return status()


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    action = argv[0] if argv else 'status'
    if action == 'serve':
        Daemon().serve()
        return 0
    if action == 'phash':
        print(make_phash(sys.stdin.readline().rstrip('\n')))
        return 0
    if action not in ('status', 'validate', 'apply'):
        raise SystemExit('usage: ffn_protect_gateway.py status|validate|apply|serve|phash')
    try:
        if action == 'status':
            result = status()
        else:
            data = sys.stdin.buffer.read((4 << 20) + 1)
            if len(data) > (4 << 20):
                raise ValueError('request exceeds 4 MiB')
            request = json.loads(data) if data.strip() else {}
            if action == 'validate':
                protect = validate_intent(request)
                result = dict(validated=True, portals=sorted(protect['portals']), gateways=sorted(protect['gateways']))
            else:
                result = apply(request)
    except (ValueError, OSError) as error:
        print(json.dumps({'error': str(error)[:512]}))
        return 2
    print(json.dumps(result))
    return 0


if __name__ == '__main__':
    sys.exit(main())
