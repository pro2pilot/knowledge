#!/usr/bin/env python3
"""Verify all input bytes and reconstruct one exact CI source ZIP."""
import argparse
import hashlib
import json
from pathlib import Path
import re

LIMIT = 64 * 1024 * 1024
HASH = re.compile(r'^[a-f0-9]{64}$')


def sha(data):
    return hashlib.sha256(data).hexdigest()


def bounded(file, count, digest):
    if not isinstance(count, int) or isinstance(count, bool) or count <= 0 or count > LIMIT or not HASH.fullmatch(digest or ''):
        raise ValueError('Invalid transport pin')
    if file.is_symlink() or file.stat().st_size != count:
        raise ValueError('Transport file size or identity mismatch: ' + file.name)
    with file.open('rb') as handle:
        data = handle.read(count + 1)
    if len(data) != count or sha(data) != digest:
        raise ValueError('Transport file bytes mismatch: ' + file.name)
    return data


def reconstruct(base_path, descriptor_path):
    if descriptor_path.is_symlink() or descriptor_path.stat().st_size > 1024 * 1024:
        raise ValueError('Invalid transport descriptor')
    description = json.loads(descriptor_path.read_bytes())
    if description.get('schema') != 'knowledge-exact-zip-transport.v1':
        raise ValueError('Unknown transport schema')
    base = bounded(base_path, description['base_bytes'], description['base_sha256'])
    parts = description['parts']
    if not isinstance(parts, list) or not 1 <= len(parts) <= 1024:
        raise ValueError('Invalid transport part count')
    delta = bytearray()
    for index, part in enumerate(parts):
        if part['name'] != 'SOURCE.delta-%03d.bin' % index or part['bytes'] > 65536:
            raise ValueError('Invalid ordered transport part')
        delta.extend(bounded(descriptor_path.parent / part['name'], part['bytes'], part['sha256']))
        if len(delta) > LIMIT:
            raise ValueError('Delta exceeds transport bound')
    if len(delta) != description['delta_bytes'] or sha(delta) != description['delta_sha256']:
        raise ValueError('Whole delta mismatch')
    segments = description['segments']
    if not isinstance(segments, list) or not 1 <= len(segments) <= 20000:
        raise ValueError('Invalid segment count')
    target = bytearray()
    for segment in segments:
        origin = segment['source']; offset, size = segment['offset'], segment['bytes']
        if origin not in {'base', 'delta'} or not isinstance(offset, int) or isinstance(offset, bool) or \
                not isinstance(size, int) or isinstance(size, bool) or offset < 0 or size <= 0:
            raise ValueError('Invalid segment')
        data = base if origin == 'base' else delta
        if offset + size > len(data) or len(target) + size > LIMIT:
            raise ValueError('Segment exceeds pinned input/output')
        block = data[offset:offset + size]
        if sha(block) != segment['sha256']:
            raise ValueError('Segment bytes mismatch')
        target.extend(block)
    if len(target) != description['target_bytes'] or sha(target) != description['target_sha256']:
        raise ValueError('Exact target ZIP mismatch')
    return bytes(target), description


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--base', required=True)
    parser.add_argument('--descriptor', required=True)
    parser.add_argument('--out', required=True)
    args = parser.parse_args()
    target, description = reconstruct(Path(args.base), Path(args.descriptor))
    destination = Path(args.out)
    with destination.open('xb') as handle:
        handle.write(target)
    print(json.dumps({'status': 'PASS_EXACT_ZIP_TRANSPORT', 'target_sha256': description['target_sha256'], 'bytes': len(target)}))


if __name__ == '__main__':
    main()
