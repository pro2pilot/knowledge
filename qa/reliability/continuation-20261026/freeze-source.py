#!/usr/bin/env python3
"""Create a bounded, deterministic native-QA snapshot of checkout source/.knowledge."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import stat

from prepare import LIMIT, bounded, encoded, metadata, new_output, rows, sha, verify_zip, write_new, zip_bytes


def capture(source):
    source = Path(source).resolve(strict=True)
    files = {}
    file_rows = []
    total = 0
    for base, dirs, names in os.walk(source, followlinks=False):
        directory = Path(base)
        dirs.sort()
        names.sort()
        for name in dirs:
            child = directory / name
            if child.is_symlink() or not child.is_dir():
                raise ValueError('Nonphysical source directory')
        for name in names:
            if len(file_rows) >= 4096:
                raise ValueError('Source file count exceeds snapshot limit')
            file = directory / name
            if file.is_symlink() or not file.is_file():
                raise ValueError('Nonregular source file')
            info = file.lstat()
            if info.st_nlink != 1:
                raise ValueError('Hard-linked source file')
            mode = stat.S_IMODE(info.st_mode)
            mode = '0755' if mode & 0o111 else '0644'
            body = bounded(file, LIMIT - total)
            relative = file.relative_to(source).as_posix()
            row = metadata(relative, body, mode)
            files[relative] = (body, mode)
            file_rows.append(row)
            total += len(body)
    if not files:
        raise ValueError('Empty source tree')
    archive = zip_bytes(files)
    manifest = {
        'schema_version': 'knowledge-native-qa-source.v1',
        'status': 'PASS_FROZEN_SOURCE',
        'scope': 'Bounded checkout snapshot of source/.knowledge. Targeted diagnostic only; not release qualification.',
        'created_utc': datetime.now(timezone.utc).isoformat(),
        'archive': 'SOURCE.zip',
        'archive_sha256': sha(archive),
        'archive_bytes': len(archive),
        'file_count': len(file_rows),
        'uncompressed_bytes': total,
        'source_root': 'source/.knowledge',
        'files': sorted(file_rows, key=lambda row: row['path']),
    }
    rows(manifest)
    verify_zip(archive, manifest)
    return archive, manifest


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', default='source/.knowledge')
    parser.add_argument('--out', required=True)
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[3]
    expected_path = repo / 'source/.knowledge'
    source_path = Path(args.source).absolute()
    if expected_path.is_symlink() or expected_path.parent.is_symlink() or source_path != expected_path:
        parser.error('--source must resolve to this checkout\'s source/.knowledge')
    source = expected_path.resolve(strict=True)
    output_path = Path(args.out).resolve(strict=False)
    if not output_path.is_relative_to(repo) or output_path.is_relative_to(source):
        parser.error('--out must be a new path inside this checkout')
    archive, manifest = capture(source)
    output = new_output(output_path)
    manifest_bytes = encoded(manifest)
    pins = encoded({'files': {row['path']: row['sha256'] for row in manifest['files']}})
    write_new(output / 'SOURCE.zip', archive)
    write_new(output / 'SOURCE_MANIFEST.json', manifest_bytes)
    write_new(output / 'SOURCE_PINS.json', pins)
    for row in manifest['files']:
        destination = output / 'source/.knowledge' / row['path']
        body = bounded(source / row['path'])
        if metadata(row['path'], body, row['mode']) != row:
            raise ValueError('Checkout source changed after snapshot')
        write_new(destination, body)
        destination.chmod(int(row['mode'], 8))
    print(json.dumps({'status': 'PASS_CHECKOUT_SOURCE_SNAPSHOT', 'archive_sha256': manifest['archive_sha256'],
                      'file_count': manifest['file_count'], 'source_root': 'source/.knowledge',
                      'release_gate_qualified': False}))


if __name__ == '__main__':
    main()
