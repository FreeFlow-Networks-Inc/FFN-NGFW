#!/usr/bin/env python3
"""Fetch a GitHub plane release pinned by the installed platform's trusted lock.

This is an MP staging operation, never a boot/reset or rootfs extraction command.
The lock is trusted code-package metadata, not something downloaded from a release.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sys
import tempfile
import time
import urllib.parse
import urllib.request

ABI = 1
MAX_MANIFEST = 1024 * 1024
MAX_ASSET = 2 * 1024**3
CACHE = '/var/lib/ffn-ngfw/plane-images'


def digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def require(ok, message):
    if not ok:
        raise ValueError(message)


def token(value, pattern):
    return isinstance(value, str) and re.fullmatch(pattern, value) is not None


def validate_lock(lock):
    require(isinstance(lock, dict), 'Image lock must be an object')
    require(lock.get('schema') == 1, 'Unsupported image lock schema')
    require(type(lock.get('enabled')) is bool, 'Image lock needs enabled boolean')
    require(token(lock.get('platform'), r'[a-z][a-z0-9-]{0,63}'), 'Invalid platform')
    if not lock['enabled']:
        return
    require(lock.get('runtime_abi') == ABI, 'Incompatible plane runtime ABI')
    require(token(lock.get('repository'), r'[A-Za-z0-9_-]+/[A-Za-z0-9_.-]+'), 'Invalid GitHub repository')
    require(token(lock.get('tag'), r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}'), 'Invalid release tag')
    for field, size in (('manifest_sha256', 64), ('platform_commit', 40), ('core_commit', 40)):
        require(token(lock.get(field), '[0-9a-f]{%d}' % size), 'Invalid ' + field)
    require(lock.get('architecture') == 'mips64eb', 'Unsupported plane architecture')


def validate_manifest(manifest, lock):
    require(isinstance(manifest, dict), 'Manifest must be an object')
    require(manifest.get('schema') == 1, 'Unsupported manifest schema')
    for field in ('platform', 'runtime_abi', 'architecture', 'platform_commit', 'core_commit'):
        require(manifest.get(field) == lock[field], 'Image mismatch: ' + field)
    assets = manifest.get('assets')
    require(isinstance(assets, list) and len(assets) == 2, 'Release must contain both CP and DP')
    require(all(isinstance(a, dict) for a in assets), 'Malformed plane assets')
    require({a.get('role') for a in assets} == {'cp', 'dp'}, 'Duplicate or missing plane role')
    for asset in assets:
        require(asset.get('name') == 'ffn-%s-%s.tar.xz' % (lock['platform'], asset['role']), 'Unexpected asset name')
        require(token(asset.get('sha256'), r'[0-9a-f]{64}'), 'Invalid asset digest')
        require(type(asset.get('size')) is int and 0 < asset['size'] <= MAX_ASSET, 'Invalid asset size')
        require(token(asset.get('kernel_release'), r'[A-Za-z0-9_.+-]{1,128}'), 'Invalid kernel release')
    return assets


def check_url(url):
    parsed = urllib.parse.urlsplit(url)
    require(parsed.scheme == 'https' and parsed.port in (None, 443) and not parsed.username,
            'Image downloads require HTTPS')
    require(parsed.hostname in ('github.com', 'release-assets.githubusercontent.com',
                                'objects.githubusercontent.com'), 'Unexpected release download host')


class ReleaseRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        check_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def download(url, destination, limit):
    check_url(url)
    opener = urllib.request.build_opener(ReleaseRedirect)
    request = urllib.request.Request(url, headers={'User-Agent': 'FFN-plane-images/1'})
    started = time.monotonic()
    with opener.open(request, timeout=30) as response, destination.open('xb') as stream:
        check_url(response.url)
        count = 0
        while True:
            require(time.monotonic() - started < 1800, 'Image download deadline exceeded')
            block = response.read(min(1024 * 1024, limit + 1 - count))
            if not block:
                break
            count += len(block)
            require(count <= limit, 'Release asset exceeds size limit')
            stream.write(block)
        stream.flush()
        os.fsync(stream.fileno())


def verify_cache(path, lock):
    manifest_path = path / 'manifest.json'
    require(manifest_path.is_file() and not manifest_path.is_symlink(), 'Manifest missing from cache')
    require(digest(manifest_path) == lock['manifest_sha256'], 'Manifest digest mismatch')
    assets = validate_manifest(json.loads(manifest_path.read_text()), lock)
    for asset in assets:
        p = path / asset['name']
        require(p.is_file() and not p.is_symlink() and p.stat().st_size == asset['size'], 'Cached image missing/truncated')
        require(digest(p) == asset['sha256'], 'Image digest mismatch: ' + asset['role'])
    return assets


def stage(lock, cache=Path(CACHE), offline=False, fetch=download):
    validate_lock(lock)
    if not lock['enabled']:
        return {'state': 'not-published', 'platform': lock['platform'], 'reboot_required': False}
    cache = Path(cache)
    target = cache / lock['platform'] / lock['manifest_sha256']
    require(not target.is_symlink(), 'Refusing symlink cache entry')
    if target.exists():
        verify_cache(target, lock)  # Corrupt caches fail closed; never silently replace them.
    else:
        require(not offline, 'Matching images are not cached; management-plane Internet is required')
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        work = Path(tempfile.mkdtemp(prefix='.download-', dir=target.parent))
        try:
            base = 'https://github.com/%s/releases/download/%s/' % (lock['repository'], lock['tag'])
            fetch(base + 'manifest.json', work / 'manifest.json', MAX_MANIFEST)
            require(digest(work / 'manifest.json') == lock['manifest_sha256'], 'Untrusted release manifest')
            assets = validate_manifest(json.loads((work / 'manifest.json').read_text()), lock)
            require(shutil.disk_usage(work).free > sum(a['size'] for a in assets) + MAX_MANIFEST,
                    'Insufficient image cache space')
            for asset in assets:
                fetch(base + asset['name'], work / asset['name'], asset['size'])
            verify_cache(work, lock)
            try:
                work.rename(target)  # Only the complete, verified pair becomes visible.
            except OSError:
                if not target.is_dir():
                    raise
                verify_cache(target, lock)  # Another stage operation may have won.
        finally:
            if work.exists():
                shutil.rmtree(work)
    return {'state': 'staged', 'platform': lock['platform'], 'path': str(target),
            'manifest_sha256': lock['manifest_sha256'], 'roles': ['cp', 'dp'],
            'activated': False, 'reboot_required': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--lock', required=True, type=Path)
    parser.add_argument('--cache', default=Path(CACHE), type=Path)
    parser.add_argument('--offline', action='store_true')
    args = parser.parse_args()
    try:
        print(json.dumps(stage(json.loads(args.lock.read_text()), args.cache, args.offline), indent=2))
    except (ValueError, OSError, KeyError, TypeError) as error:
        print('ffn-plane-images: ' + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
