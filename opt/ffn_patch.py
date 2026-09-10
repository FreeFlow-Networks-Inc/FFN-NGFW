#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Signed, journaled management-code patches. No shell hooks or package scripts.

Build a delta from two flat installation trees, publish it as kind 'patch' with
ffn_payload.py, then check/stage/install on the appliance. The WebUI launches
workers in a separate systemd unit so restarting the manager cannot kill them.
"""
import argparse
from contextlib import contextmanager
import hashlib
import importlib.metadata
import io
import json
import os
from pathlib import Path
import re
import shutil
import ssl
import subprocess
import sys
import tarfile
import tempfile
import time
from urllib.parse import urlsplit, quote
import urllib.request
import uuid

import ffn_payload as payload

MAX_BYTES = 128 * 1024 * 1024
MAX_FILES = 4096
SERVICES = ('ffn-controld.service', 'ffn-configd.service', 'ffn-manager-v2.service')
TERMINAL = ('succeeded', 'failed', 'rolled_back')


class PatchError(ValueError):
    def __init__(self, message):
        super().__init__(message)
        self.public_message = message


def digest(data):
    return hashlib.sha256(data).hexdigest()


def code_path(name):
    if not isinstance(name, str) or len(name) > 200 or not re.fullmatch(r'[A-Za-z0-9_-][A-Za-z0-9_./-]*', name):
        raise PatchError('Invalid code path')
    parts = name.split('/')
    if any(p in ('', '.', '..') for p in parts):
        raise PatchError('Invalid code path')
    allowed = (len(parts) == 1 and name.endswith('.py')) or (
        parts[0] == 'static' and Path(name).suffix.lower() in
        ('.html', '.css', '.js', '.json', '.svg', '.png', '.ico', '.woff', '.woff2'))
    if not allowed:
        raise PatchError('Patches may contain only Python code and WebUI assets')
    return name


def confined(root, name):
    """Check lexical containment before probing, then reject every symlink hop."""
    root = os.path.realpath(root)
    target = os.path.abspath(os.path.join(root, name))
    if not target.startswith(os.path.join(root, '')):
        raise PatchError('Path outside installation')
    cursor = root
    for part in Path(name).parts:
        cursor = os.path.abspath(os.path.join(cursor, part))
        if not cursor.startswith(os.path.join(root, '')):
            raise PatchError('Path outside installation')
        if os.path.islink(cursor):
            raise PatchError('Symlink targets are not patchable')
    resolved = os.path.realpath(target)
    if not resolved.startswith(os.path.join(root, '')):
        raise PatchError('Path outside installation')
    return Path(resolved)


def atomic(path, data, mode=0o600):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, tmp = tempfile.mkstemp(prefix='.patch-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
        if os.name != 'nt':
            directory = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def save(path, obj):
    atomic(path, json.dumps(obj, indent=2).encode())


def remove(path):
    path.unlink()
    if os.name != 'nt':
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)


def read(path, default=None):
    try:
        return json.loads(Path(path).read_text(encoding='utf-8'))
    except FileNotFoundError:
        return default


@contextmanager
def lock(directory):
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    with open(directory / 'lock', 'a+b') as stream:
        try:
            if os.name == 'nt':
                import msvcrt
                stream.seek(0)
                stream.write(b'0')
                stream.flush()
                stream.seek(0)
                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            raise PatchError('Another patch operation is running') from None
        try:
            yield
        finally:
            if os.name == 'nt':
                stream.seek(0)
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(stream, fcntl.LOCK_UN)


def server_url(value):
    if not isinstance(value, str) or any(ord(c) < 33 for c in value):
        raise PatchError('Update server must be an HTTPS URL')
    parsed = urlsplit(value)
    if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise PatchError('Use an HTTPS server URL without credentials, query or fragment')
    return value.rstrip('/')


class HTTPSOnly(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urlsplit(newurl).scheme != 'https':
            raise PatchError('Refusing update redirect outside HTTPS')
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def download(url, limit):
    opener = urllib.request.build_opener(HTTPSOnly(), urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    with opener.open(url, timeout=30) as response:
        data = response.read(limit + 1)
    if len(data) > limit:
        raise PatchError('Download exceeds size limit')
    return data


def unpack(data):
    """Read a bounded regular-file-only archive; never call tar.extract()."""
    files = {}
    total = 0
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
        for item in archive:
            if len(files) >= MAX_FILES or not item.isfile() or item.name in files:
                raise PatchError('Invalid or duplicate archive member')
            if item.name != 'patch.json':
                if not item.name.startswith('files/'):
                    raise PatchError('Unexpected archive member')
                code_path(item.name[6:])
            total += item.size
            if item.size < 0 or total > MAX_BYTES:
                raise PatchError('Expanded patch exceeds size limit')
            files[item.name] = archive.extractfile(item).read(item.size + 1)
    manifest = json.loads(files.pop('patch.json', b'{}'))
    if manifest.get('schema') != 1 or not isinstance(manifest.get('files'), list) or not manifest['files']:
        raise PatchError('Unsupported or empty patch manifest')
    seen = set()
    for entry in manifest['files']:
        name = code_path(entry['path'])
        if name in seen:
            raise PatchError('Duplicate patch target')
        seen.add(name)
        for field in ('before', 'after'):
            if entry.get(field) is not None and not re.fullmatch('[0-9a-f]{64}', entry[field]):
                raise PatchError('Invalid file hash')
        if entry.get('before') == entry.get('after'):
            raise PatchError('Patch entry does not change a file')
        if entry.get('after'):
            content = files.pop('files/' + name, None)
            if content is None or digest(content) != entry['after']:
                raise PatchError('Patch file hash mismatch')
            if name.endswith('.py'):
                compile(content, name, 'exec')
            entry['content'] = content
        if entry.get('mode', 0o644) not in (0o644, 0o755):
            raise PatchError('Unsafe file mode')
    if files:
        raise PatchError('Archive contains undeclared files')
    ordered = sorted(seen)
    if any(right.startswith(left + '/') for left, right in zip(ordered, ordered[1:])):
        raise PatchError('Patch paths overlap')
    return manifest


class PatchManager:
    def __init__(self, root=None, state=None, pub=None, run=None):
        self.root = Path(root or os.environ.get('FFN_PATCH_ROOT', '/opt/ffn-ngfw-v2')).resolve()
        self.state = Path(state or os.environ.get('FFN_PATCH_STATE', '/var/lib/ffn-ngfw/patches')).resolve()
        if os.path.commonpath([self.root, self.state]) == str(self.root):
            raise PatchError('Patch state must be outside the code installation')
        self.pub = Path(pub or os.environ.get('FFN_UPDATE_PUB', '/etc/ffn-ngfw/update.pub'))
        self.run = run or subprocess.run

    def status(self):
        st = read(self.state / 'state.json', {})
        job = read(self.state / 'job.json')
        journal = read(self.state / 'journal.json')
        return {**st, 'job': job, 'root': str(self.root), 'public_key_present': self.pub.is_file(),
                'worker_available': sys.platform == 'linux' and shutil.which('systemd-run') is not None,
                'recovery_required': bool(journal and journal['phase'] != 'committed'),
                'rollback_available': bool(journal and journal['phase'] == 'committed'),
                'history': read(self.state / 'history.json', [])}

    def _state(self, **updates):
        st = read(self.state / 'state.json', {})
        st.update(updates)
        save(self.state / 'state.json', st)

    def verify(self, manifest):
        pub = payload.load_hex(str(self.pub))
        if not pub or len(pub) != 32:
            raise PatchError('Install an Ed25519 update public key before patching')
        ok, why = payload.verify_manifest(manifest, pub=pub)
        if not ok:
            raise PatchError(why)
        meta = manifest.get('payloads', {}).get('patch')
        if not isinstance(meta, dict) or not re.fullmatch(r'[A-Za-z0-9_-][A-Za-z0-9_.-]{0,150}', meta.get('file', '')):
            raise PatchError('No valid patch offered by update server')
        if not re.fullmatch('[0-9a-f]{64}', meta.get('sha256', '')):
            raise PatchError('Invalid release hash')
        if not isinstance(meta.get('size'), int) or not 0 < meta['size'] <= MAX_BYTES:
            raise PatchError('Invalid release size')
        if not isinstance(meta.get('version'), str) or not 0 < len(meta['version']) <= 100:
            raise PatchError('Invalid release version')
        if not isinstance(meta.get('published'), int) or meta['published'] <= 0:
            raise PatchError('Invalid release timestamp')
        return meta

    def check(self, url):
        url = server_url(url)
        manifest = json.loads(download(url + '/manifest.json', 1024 * 1024))
        meta = self.verify(manifest)
        self._state(available=meta, checked_at=int(time.time()))
        return manifest, meta

    def preflight(self, archive, meta):
        if len(archive) != meta['size'] or digest(archive) != meta['sha256']:
            raise PatchError('Downloaded package size or SHA-256 does not match signed release')
        package = unpack(archive)
        if package.get('version') != meta['version']:
            raise PatchError('Package version differs from signed release')
        installed = read(self.state / 'state.json', {}).get('installed') or {}
        if installed.get('sha256') == meta['sha256']:
            raise PatchError('This patch is already installed')
        if installed.get('published', 0) >= meta['published']:
            raise PatchError('Release is not newer; use rollback to restore previous code')
        for name, version in package.get('requires', {}).items():
            try:
                found = importlib.metadata.version(name)
            except importlib.metadata.PackageNotFoundError:
                found = None
            if found != version:
                raise PatchError('Required dependency missing or incompatible: ' + name + '==' + version)
        backup_size = 0
        for entry in package['files']:
            target = confined(self.root, entry['path'])
            before = digest(target.read_bytes()) if target.is_file() else None
            if before != entry.get('before') or (target.exists() and not target.is_file()):
                raise PatchError('Installed file differs from patch baseline: ' + entry['path'])
            if target.exists():
                backup_size += target.stat().st_size
        self.state.mkdir(parents=True, exist_ok=True, mode=0o700)
        if shutil.disk_usage(self.state).free < backup_size + len(archive) + 16 * 1024 * 1024:
            raise PatchError('Insufficient space for rollback backup')
        if shutil.disk_usage(self.root).free < MAX_BYTES + 16 * 1024 * 1024:
            raise PatchError('Insufficient space to install patch')
        return package

    def stage(self, url, expected):
        manifest, meta = self.check(url)
        if expected != meta['sha256']:
            raise PatchError('Offered patch changed; check for updates again')
        archive = download(server_url(url) + '/' + quote(meta['file']), meta['size'])
        package = self.preflight(archive, meta)
        atomic(self.state / 'staged.tgz', archive)
        save(self.state / 'staged-manifest.json', manifest)
        self._state(staged={**meta, 'files': [{k: v for k, v in e.items() if k != 'content'} for e in package['files']],
                            'requires': package.get('requires', {}), 'staged_at': int(time.time())})

    def _service(self, verb, unit):
        # Both executable and unit set are fixed by the installed updater.
        if verb not in ('is-active', 'stop', 'start') or unit not in SERVICES:
            raise PatchError('Invalid service operation')
        return self.run(['systemctl', verb, unit], executable='systemctl', shell=False,
                        capture_output=True, timeout=60).returncode == 0

    def _restart(self, services):
        for unit in services:
            if not self._service('start', unit):
                raise PatchError('Service failed to start: ' + unit)
        # Catch immediate startup failures rather than treating start dispatch as health.
        for _ in range(5):
            time.sleep(2)
            for unit in services:
                if not self._service('is-active', unit):
                    raise PatchError('Service did not stay active: ' + unit)

    def install(self, expected):
        meta = self.verify(read(self.state / 'staged-manifest.json', {}))
        if expected != meta['sha256']:
            raise PatchError('Staged patch changed; review it again')
        package = self.preflight((self.state / 'staged.tgz').read_bytes(), meta)
        if read(self.state / 'journal.json', {}).get('phase') not in (None, 'committed'):
            raise PatchError('Recover the interrupted operation first')
        services = [unit for unit in SERVICES if self._service('is-active', unit)]
        if 'ffn-manager-v2.service' not in services:
            raise PatchError('The management service must be active before installation')
        backup = uuid.uuid4().hex
        entries = []
        for item in package['files']:
            target = confined(self.root, item['path'])
            entry = {k: v for k, v in item.items() if k != 'content'}
            if target.exists():
                entry['old_mode'] = target.stat().st_mode & 0o777
                atomic(confined(self.state / backup, item['path']), target.read_bytes())
            entries.append(entry)
        journal = {'phase': 'prepared', 'backup': backup, 'files': entries, 'services': services,
                   'previous': read(self.state / 'state.json', {}).get('installed'), 'release': meta}
        save(self.state / 'journal.json', journal)
        try:
            for unit in reversed(services):
                if not self._service('stop', unit):
                    raise PatchError('Service failed to stop: ' + unit)
            for item in package['files']:
                target = confined(self.root, item['path'])
                if item.get('after'):
                    atomic(target, item['content'], item.get('mode', 0o644))
                elif target.exists():
                    remove(target)
            self._restart(services)
            self._state(installed={**meta, 'at': int(time.time())}, staged=None)
            journal['phase'] = 'committed'
            save(self.state / 'journal.json', journal)
        except Exception:
            self.restore(check_current=False)
            raise PatchError('Installation failed; previous files and services restored') from None

    def restore(self, check_current=True):
        journal = read(self.state / 'journal.json')
        if not journal:
            raise PatchError('No rollback journal exists')
        if check_current and journal['phase'] != 'committed':
            raise PatchError('Use recovery for an interrupted operation')
        # Verify the entire backup BEFORE stopping a service or changing a file.
        contents = {}
        for entry in journal['files']:
            target = confined(self.root, code_path(entry['path']))
            if check_current:
                current = digest(target.read_bytes()) if target.is_file() else None
                if current != entry.get('after'):
                    raise PatchError('Local changes prevent rollback: ' + entry['path'])
            if entry.get('before'):
                content = confined(self.state / journal['backup'], entry['path']).read_bytes()
                if digest(content) != entry['before']:
                    raise PatchError('Rollback backup is damaged')
                contents[entry['path']] = content
        journal['phase'] = 'restoring'
        save(self.state / 'journal.json', journal)
        for unit in reversed(journal['services']):
            if not self._service('stop', unit):
                raise PatchError('Cannot stop service for recovery: ' + unit)
        for entry in journal['files']:
            target = confined(self.root, entry['path'])
            if entry.get('before'):
                atomic(target, contents[entry['path']], entry.get('old_mode', 0o644))
            elif target.exists():
                remove(target)
        self._restart(journal['services'])
        self._state(installed=journal['previous'], staged=None)
        remove(self.state / 'journal.json')

    def submit(self, action, actor, url='', expected=''):
        if action not in ('check', 'stage', 'install', 'rollback', 'recover'):
            raise PatchError('Unsupported patch action')
        if action in ('check', 'stage'):
            url = server_url(url)
        if action in ('stage', 'install', 'rollback') and not re.fullmatch('[0-9a-f]{64}', expected):
            raise PatchError('Review and select a patch first')
        with lock(self.state):
            job = read(self.state / 'job.json')
            if job and job['status'] not in TERMINAL:
                # Recovery is only allowed after the previous independent unit stopped.
                if action != 'recover' or self.run(['systemctl', 'is-active', 'ffn-patch-' + job['id']],
                    executable='systemctl', shell=False, capture_output=True, timeout=5).returncode == 0:
                    raise PatchError('Another patch operation is pending; recover it if interrupted')
            if read(self.state / 'journal.json', {}).get('phase') not in (None, 'committed') and action != 'recover':
                raise PatchError('Recover the interrupted installation first')
            job = {'id': uuid.uuid4().hex, 'action': action, 'actor': actor, 'url': url,
                   'expected': expected, 'status': 'queued', 'started_at': int(time.time())}
            save(self.state / 'job.json', job)
            try:
                result = self.run(['systemd-run', '--quiet', '--collect', '--unit=ffn-patch-' + job['id'],
                    '--property=Type=exec', '--', sys.executable, str(Path(__file__).resolve()),
                    '--root', str(self.root), '--state', str(self.state), '--pub', str(self.pub),
                    'worker', job['id']], executable='systemd-run', shell=False, capture_output=True, timeout=15)
                if result.returncode:
                    raise PatchError('Could not start independent patch worker')
            except Exception:
                job.update(status='failed', message='Could not start independent patch worker')
                save(self.state / 'job.json', job)
                raise PatchError(job['message']) from None
        return job

    def worker(self, job_id):
        # A newly started worker may overlap submit while it still holds the lock.
        for attempt in range(30):
            try:
                with lock(self.state):
                    return self._work(job_id)
            except PatchError as exc:
                if str(exc) != 'Another patch operation is running' or attempt == 29:
                    raise
                time.sleep(0.1)

    def _work(self, job_id):
        job = read(self.state / 'job.json', {})
        if job.get('id') != job_id or job.get('status') != 'queued':
            raise PatchError('Job is no longer queued')
        job.update(status='running', message='Running ' + job['action'])
        current = read(self.state / 'state.json', {})
        selected = current.get('staged' if job['action'] == 'install' else 'installed') or {}
        if job['action'] in ('install', 'rollback'):
            job['version'] = selected.get('version')
        save(self.state / 'job.json', job)
        try:
            action = job['action']
            if action == 'check':
                _, release = self.check(job['url'])
                job['version'] = release['version']
            elif action == 'stage':
                self.stage(job['url'], job['expected'])
                job['version'] = read(self.state / 'state.json')['staged']['version']
            elif action == 'install':
                self.install(job['expected'])
            elif action == 'rollback':
                if (read(self.state / 'state.json', {}).get('installed') or {}).get('sha256') != job['expected']:
                    raise PatchError('Installed patch changed; review rollback again')
                self.restore()
            elif read(self.state / 'journal.json', {}).get('phase') not in (None, 'committed'):
                self.restore(check_current=False)
            job.update(status='succeeded', message=action.capitalize() + ' completed')
        except Exception as exc:
            job.update(status='failed', message=exc.public_message if isinstance(exc, PatchError) else 'Patch operation failed; inspect the worker journal')
        job['finished_at'] = int(time.time())
        save(self.state / 'job.json', job)
        history = read(self.state / 'history.json', [])
        save(self.state / 'history.json', ([job] + history)[:50])
        return 0 if job['status'] == 'succeeded' else 1


def build(base, source, version, output, requires):
    if not version or len(version) > 100:
        raise PatchError('Provide a version of at most 100 characters')
    roots = [Path(base).resolve(), Path(source).resolve()]
    paths = set()
    def source_file(root, name):
        prefix = 'opt/' if '/' not in name and (root / 'opt').is_dir() else ''
        return confined(root, prefix + name)
    for root in roots:
        candidates = list((root / 'opt' if (root / 'opt').is_dir() else root).glob('*.py'))
        if (root / 'static').is_dir():
            candidates.extend((root / 'static').rglob('*'))
        for p in candidates:
            if p.is_file() or p.is_symlink():
                name = p.relative_to(root).as_posix()
                if name.startswith('opt/'):
                    name = name[4:]
                try:
                    code_path(name)
                except PatchError:
                    continue
                paths.add(name)
    entries, blobs = [], {}
    for name in sorted(paths):
        old, new = [source_file(root, name) for root in roots]
        before = old.read_bytes() if old.is_file() else None
        after = new.read_bytes() if new.is_file() else None
        if before == after:
            continue
        entries.append({'path': name, 'before': digest(before) if before is not None else None,
                        'after': digest(after) if after is not None else None,
                        'mode': 0o755 if new.exists() and new.stat().st_mode & 0o111 else 0o644})
        if after is not None:
            blobs['files/' + name] = after
    manifest = {'schema': 1, 'version': version, 'files': entries, 'requires': requires}
    blobs['patch.json'] = json.dumps(manifest).encode()
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode='w:gz') as archive:
        for name, data in blobs.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = 0o644
            archive.addfile(info, io.BytesIO(data))
    data = out.getvalue()
    if len(data) > MAX_BYTES:
        raise PatchError('Patch is too large')
    unpack(data)
    atomic(Path(output), data)
    return {'version': version, 'files': len(entries), 'sha256': digest(data), 'bytes': len(data)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root')
    parser.add_argument('--state')
    parser.add_argument('--pub')
    subs = parser.add_subparsers(dest='command', required=True)
    b = subs.add_parser('build')
    for arg in ('base', 'source', 'version', 'output'):
        b.add_argument('--' + arg, required=True)
    b.add_argument('--require', action='append', default=[])
    subs.add_parser('status')
    w = subs.add_parser('worker')
    w.add_argument('job_id')
    for action in ('check', 'stage', 'install', 'rollback', 'recover'):
        p = subs.add_parser(action)
        p.add_argument('--url', default='')
        p.add_argument('--sha256', default='')
    args = parser.parse_args()
    try:
        if args.command == 'build':
            requires = dict(item.split('==', 1) for item in args.require)
            result = build(args.base, args.source, args.version, args.output, requires)
        else:
            manager = PatchManager(args.root, args.state, args.pub)
            if args.command == 'status':
                result = manager.status()
            elif args.command == 'worker':
                return manager.worker(args.job_id)
            else:
                result = manager.submit(args.command, 'cli', args.url, args.sha256)
        print(json.dumps(result, indent=2))
        return 0
    except Exception as exc:
        print(str(exc) if isinstance(exc, PatchError) else 'Patch operation failed', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
