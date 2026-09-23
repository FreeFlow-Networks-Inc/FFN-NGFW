#!/usr/bin/env python3
"""Publish validated code patches atomically. This command never installs them."""
import argparse
import json
import os
from pathlib import Path
import re
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'opt'))
import ffn_patch as patch
import ffn_payload as payload
import ffn_vendor as vendor


def signed(manifest, public):
    ok, why = payload.verify_manifest(manifest, pub=public)
    if not ok:
        raise ValueError(why)
    return manifest


def check_archive(path, version=None):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > patch.MAX_BYTES:
        raise ValueError('Expected a bounded regular patch archive')
    data = path.read_bytes()
    package = patch.unpack(data)
    v = package.get('version')
    if not isinstance(v, str) or not 0 < len(v) <= 100 or (version is not None and v != version):
        raise ValueError('Invalid or mismatched patch version')
    if vendor.check_clean(str(path)) != 0:
        raise ValueError('Publication scan rejected the patch')
    return data, package


def publish(directory, seed_path, public_path, archive, notes='', imported=None):
    directory = Path(directory)
    # Signing material must not live anywhere in the public tree.
    if Path(seed_path).resolve().is_relative_to(directory.resolve()):
        raise ValueError('Signing seed must be outside publication directory')
    if os.name != 'nt' and Path(seed_path).stat().st_mode & 0o077:
        raise ValueError('Signing seed must be private (mode 0600)')
    seed = payload.load_hex(str(seed_path))
    public = payload.load_hex(str(public_path))
    if not seed or len(seed) != 32 or public != payload.ffn_ed25519.publickey(seed):
        raise ValueError('Signing seed and public key do not match')
    data, package = check_archive(archive)
    sha = patch.digest(data)
    stamp = int(time.time())
    if imported is not None:
        signed(imported, public)
        old = imported.get('payloads', {}).get('patch', {})
        if (old.get('sha256') != sha or old.get('size') != len(data)
                or old.get('version') != package['version']):
            raise ValueError('Imported patch does not match signed metadata')
        stamp, notes = old['published'], old.get('notes', '')
    directory.mkdir(parents=True, exist_ok=True, mode=0o755)
    with patch.lock(directory):
        current = patch.read(directory / 'manifest.json')
        if current:
            signed(current, public)
            previous = current.get('payloads', {}).get('patch', {})
            if previous.get('sha256') == sha:
                verify(directory, public_path)
                return previous
            if previous.get('version') == package['version']:
                raise ValueError('A version cannot be reused for different content')
            if imported is not None and stamp <= previous.get('published', 0):
                raise ValueError('Cannot import an older release over the current release')
            if imported is None:
                stamp = max(stamp, previous.get('published', 0) + 1)
        meta = dict(file='patch-' + sha + '.tgz', version=package['version'],
                    sha256=sha, size=len(data), published=stamp, notes=notes)
        # Platform image releases share the signed catalog. Publishing a code
        # patch must not remove independently selected CP/DP image releases.
        manifest = dict(current or {})
        manifest['payloads'] = dict(manifest.get('payloads', {}), patch=meta)
        manifest['updated'] = max(stamp, manifest.get('updated', 0))
        signature, algorithm = payload.sign_manifest(manifest, seed=seed)
        manifest.update(signature=signature, sig_alg=algorithm)
        # Make the immutable payload durable before exposing its signed catalog.
        patch.atomic(directory / meta['file'], data, mode=0o644)
        if current:
            history = directory / '.history'
            history.mkdir(exist_ok=True, mode=0o700)
            raw = json.dumps(current, indent=2).encode()
            patch.atomic(history / (patch.digest(raw) + '.json'), raw)
        patch.atomic(directory / 'manifest.json', json.dumps(manifest, indent=2).encode(), mode=0o644)
        return meta


def verify(directory, public_path):
    directory = Path(directory)
    public = payload.load_hex(str(public_path))
    if not public or len(public) != 32:
        raise ValueError('Expected Ed25519 public key')
    manifest = signed(json.loads((directory / 'manifest.json').read_text()), public)
    meta = manifest.get('payloads', {}).get('patch', {})
    if not re.fullmatch(r'[A-Za-z0-9_-][A-Za-z0-9_.-]{0,150}', meta.get('file', '')):
        raise ValueError('Invalid published filename')
    data, package = check_archive(directory / meta['file'], meta.get('version'))
    if patch.digest(data) != meta.get('sha256') or len(data) != meta.get('size'):
        raise ValueError('Published payload hash or size mismatch')
    return dict(version=package['version'], sha256=meta['sha256'], files=len(package['files']), verified=True)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--dir', type=Path, required=True)
    ap.add_argument('--public-key', type=Path, required=True)
    sub = ap.add_subparsers(dest='command', required=True)
    pub = sub.add_parser('publish')
    pub.add_argument('--seed', type=Path, required=True)
    pub.add_argument('--file', type=Path, required=True)
    pub.add_argument('--notes', default='')
    pub.add_argument('--import-manifest', type=Path,
                     help='Verify an existing signed release and preserve its original publication timestamp')
    sub.add_parser('verify')
    args = ap.parse_args()
    try:
        if args.command == 'verify':
            result = verify(args.dir, args.public_key)
        else:
            imported = json.loads(args.import_manifest.read_text()) if args.import_manifest else None
            result = publish(args.dir, args.seed, args.public_key, args.file, args.notes, imported)
        print(json.dumps(result, indent=2))
    except (ValueError, OSError, patch.PatchError) as exc:
        ap.exit(1, str(exc) + '\n')


if __name__ == '__main__':
    main()
