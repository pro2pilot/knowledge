#!/usr/bin/env python3
"""Verify the pinned 650-file ancestor and reconstruct one exact frozen cohort."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import zipfile

BASE_ZIP_SHA = '750c3b561b594e97358adfa46969aa52f416e5c8cd3ce9a754dd533e5e02647c'
BASE_MANIFEST_SHA = 'bc4aa130f2d85addaf6b9d2d3f8062141e3c32fcfdf34b104a5e36e33fd64723'
LIMIT = 64 * 1024 * 1024
HASH = re.compile(r'^[a-f0-9]{64}$')
# Every addition is approved individually. Native outputs, runtime state, and
# arbitrary new product/test files can never enter through a broad prefix.
EXTRA_SOURCE_PATHS = frozenset({
    'schemas/verification-execution-observation.schema.json',
    'tools/lib/macos-command-runner.js',
    'tools/lib/macos-command-scope.js',
    'tools/lib/macos-command-worker.js',
    'tools/lib/macos-lock-preflight.js',
    'tools/lib/macos-worker-envelope.js',
    'tools/lib/macos-workspace-protocol.js',
    'tools/lib/macos-workspace-session.js',
    'tools/lib/watch-maintenance-worker.js',
    'tests/reliability-darwin-boolean-wire.test.js',
    'tests/reliability-darwin-scope-query.test.js',
    'tests/reliability-darwin-storage-guardian-contract.test.js',
    'tests/reliability-runtime-install-completeness.test.js',
    'tests/reliability-watchdog-progress-close.test.js',
    'tests/reliability-windows-powershell-selection.test.js',
    'tests/reliability-macos-command-runner.test.js',
    'tests/reliability-macos-lock-preflight.test.js',
    'tests/reliability-macos-custody.test.js',
    'tests/reliability-macos-native-authority.test.js',
    'tests/reliability-macos-failed-observation.test.js',
    'tests/reliability-macos-worker-envelope.test.js',
    'tests/reliability-macos-workspace-protocol.test.js',
    'tests/reliability-watcher-control.test.js',
    'tests/reliability-watcher-native.test.js',
    'tests/repair-producer-dependency-closure.test.js',
})


def sha(body):
    return hashlib.sha256(body).hexdigest()


def relative(value):
    if not isinstance(value, str) or not value or len(value) > 512 or any(c in value for c in '\\:<>"|?*') or any(ord(c) < 32 for c in value):
        raise ValueError('Invalid relative path')
    path = PurePosixPath(value)
    if path.is_absolute() or str(path) != value or any(part in {'.', '..'} or part.endswith((' ', '.')) or re.match(r'^(?:con|prn|aux|nul|com[0-9]|lpt[0-9])(?:\.|$)', part, re.I) for part in path.parts):
        raise ValueError('Noncanonical relative path: ' + value)
    return path


def physical_parents(file):
    for parent in file.parents:
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
            raise ValueError('Nonphysical parent: ' + str(parent))


def bounded(file, maximum=LIMIT):
    file = Path(file).absolute()
    physical_parents(file)
    before = file.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > maximum:
        raise ValueError('Invalid regular input: ' + str(file))
    fd = os.open(file, os.O_RDONLY | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode):
            raise ValueError('Opened input is not regular')
        body = bytearray()
        while len(body) <= maximum:
            chunk = os.read(fd, min(65536, maximum + 1 - len(body)))
            if not chunk:
                break
            body.extend(chunk)
        after = os.fstat(fd)
    finally:
        os.close(fd)
    named_after = file.lstat()
    fields = ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns')
    key = lambda info: tuple(getattr(info, item) for item in fields)
    if len(body) > maximum or len(body) != opened.st_size or any(key(info) != key(opened) for info in (before, after, named_after)) or before.st_ctime_ns != named_after.st_ctime_ns or opened.st_ctime_ns != after.st_ctime_ns:
        raise ValueError('Input changed during bounded read: ' + str(file))
    physical_parents(file)
    return bytes(body)


def rows(manifest):
    if manifest.get('schema_version') != 'knowledge-native-qa-source.v1' or manifest.get('status') != 'PASS_FROZEN_SOURCE':
        raise ValueError('Invalid source manifest schema/status')
    result = {}
    folded = set()
    for row in manifest.get('files', []):
        name = str(relative(row['path']))
        if name in result or name.casefold() in folded or row.get('mode') not in {'0644', '0755'} or not HASH.fullmatch(row.get('sha256', '')) or type(row.get('bytes')) is not int or not 0 <= row['bytes'] <= LIMIT:
            raise ValueError('Invalid or duplicate source row: ' + name)
        result[name] = row
        folded.add(name.casefold())
    if len(result) != manifest.get('file_count') or sum(row['bytes'] for row in result.values()) != manifest.get('uncompressed_bytes'):
        raise ValueError('Manifest totals mismatch')
    if not 1 <= len(result) <= 4096 or sum(row['bytes'] for row in result.values()) > LIMIT:
        raise ValueError('Source cohort exceeds bounded inventory/byte limit')
    for name in result:
        if any(str(parent).casefold() in folded for parent in relative(name).parents if str(parent) != '.'):
            raise ValueError('Source file/directory collision')
    return result


def metadata(name, body, mode):
    return {'path': name, 'bytes': len(body), 'sha256': sha(body), 'mode': mode}


def verify_zip(body, manifest):
    expected = rows(manifest)
    if sha(body) != manifest.get('archive_sha256') or len(body) != manifest.get('archive_bytes'):
        raise ValueError('ZIP pin mismatch')
    result = {}
    with zipfile.ZipFile(io.BytesIO(body)) as archive:
        infos = archive.infolist()
        if len(infos) != len(expected) or len({entry.filename for entry in infos}) != len(infos):
            raise ValueError('ZIP membership count/duplicates mismatch')
        for entry in infos:
            name = entry.filename
            if not name.startswith('.knowledge/'):
                raise ValueError('ZIP source root mismatch')
            name = str(relative(name[len('.knowledge/'):]))
            row = expected.get(name)
            mode = entry.external_attr >> 16
            if row is None or entry.is_dir() or entry.file_size != row['bytes'] or not stat.S_ISREG(mode) or stat.S_IMODE(mode) != int(row['mode'], 8) or entry.flag_bits & 1:
                raise ValueError('ZIP source member mismatch: ' + name)
            data = archive.read(entry)
            if metadata(name, data, row['mode']) != row:
                raise ValueError('ZIP source bytes mismatch: ' + name)
            result[name] = (data, row['mode'])
    return result


def base(archive, manifest):
    manifest_bytes = bounded(manifest, 8 * 1024 * 1024)
    archive_bytes = bounded(archive)
    if sha(manifest_bytes) != BASE_MANIFEST_SHA or sha(archive_bytes) != BASE_ZIP_SHA:
        raise ValueError('Not the exact approved original 650-file ancestor')
    description = json.loads(manifest_bytes)
    if description.get('file_count') != 650:
        raise ValueError('Ancestor count is not 650')
    return verify_zip(archive_bytes, description), description


def zip_bytes(files):
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w', compression=zipfile.ZIP_STORED, allowZip64=False) as archive:
        for name, (body, mode) in sorted(files.items()):
            relative(name)
            entry = zipfile.ZipInfo('.knowledge/' + name, (2026, 10, 26, 0, 0, 0))
            entry.create_system = 3
            entry.external_attr = (stat.S_IFREG | int(mode, 8)) << 16
            entry.compress_type = zipfile.ZIP_STORED
            archive.writestr(entry, body)
    return output.getvalue()


def new_output(value):
    output = Path(value).absolute()
    physical_parents(output)
    output.mkdir(mode=0o700)
    return output


def write_new(file, body):
    file.parent.mkdir(parents=True, exist_ok=True)
    physical_parents(file)
    with file.open('xb') as handle:
        handle.write(body)


def encoded(value):
    return (json.dumps(value, indent=2, ensure_ascii=False) + '\n').encode('utf-8')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--base-archive', required=True)
    parser.add_argument('--base-manifest', required=True)
    parser.add_argument('--overlay', required=True)
    parser.add_argument('--out', required=True)
    args = parser.parse_args()
    files, _ = base(args.base_archive, args.base_manifest)
    overlay_file = Path(args.overlay).absolute()
    overlay = json.loads(bounded(overlay_file, 8 * 1024 * 1024))
    if overlay.get('schema_version') != 'knowledge-continuation-overlay.v1' or overlay.get('base') != {'archive_sha256': BASE_ZIP_SHA, 'manifest_sha256': BASE_MANIFEST_SHA, 'file_count': 650}:
        raise ValueError('Invalid overlay ancestor binding')
    target_bytes = bounded(overlay_file.parent / 'SOURCE_MANIFEST.json', 8 * 1024 * 1024)
    if sha(target_bytes) != overlay.get('target_manifest_sha256'):
        raise ValueError('Frozen manifest hash mismatch')
    target = json.loads(target_bytes)
    expected = rows(target)
    extras = target.get('explicit_extra_paths', target.get('explicit_extra_tests', []))
    if not isinstance(extras, list) or any(not isinstance(name, str) for name in extras) or len(set(extras)) != len(extras) or not set(extras) <= EXTRA_SOURCE_PATHS or set(extras) != set(expected) - set(files):
        raise ValueError('Frozen additions do not match the exact explicit source allowlist')
    changed = set()
    for index, change in enumerate(overlay.get('changes', [])):
        name = str(relative(change['path']))
        if name in changed or change.get('overlay') != f'overlays/{index:04d}.bin':
            raise ValueError('Noncanonical overlay row')
        changed.add(name)
        old = metadata(name, *files[name]) if name in files else None
        if old != change.get('base'):
            raise ValueError('Overlay old bytes/mode mismatch: ' + name)
        result = change.get('result')
        if result != expected.get(name) or result['mode'] != (old['mode'] if old else '0644'):
            raise ValueError('Overlay result bytes/mode mismatch: ' + name)
        if old is None and name not in EXTRA_SOURCE_PATHS:
            raise ValueError('New overlay is not an explicitly approved source path')
        body = bounded(overlay_file.parent / change['overlay'])
        if metadata(name, body, result['mode']) != result or old == result:
            raise ValueError('Invalid or unnecessary overlay data: ' + name)
        files[name] = (body, result['mode'])
    if {name: metadata(name, *value) for name, value in files.items()} != expected:
        raise ValueError('Reconstructed full source does not match target manifest')
    archive = zip_bytes(files)
    if {'sha256': sha(archive), 'bytes': len(archive)} != overlay.get('target_archive'):
        raise ValueError('Deterministic ZIP reproduction mismatch')
    verify_zip(archive, target)
    output = new_output(args.out)
    write_new(output / 'SOURCE.zip', archive)
    write_new(output / 'SOURCE_MANIFEST.json', target_bytes)
    write_new(output / 'SOURCE_PINS.json', encoded({'files': {name: value['sha256'] for name, value in sorted(expected.items())}}))
    for name, (body, mode) in sorted(files.items()):
        destination = output / 'source' / '.knowledge' / name
        write_new(destination, body)
        destination.chmod(int(mode, 8))
    print(json.dumps({'status': 'PASS_EXACT_OVERLAY_RECONSTRUCTION', 'archive_sha256': sha(archive), 'file_count': len(files), 'source': str(output / 'source' / '.knowledge'), 'native_qualification': 'PENDING'}))


if __name__ == '__main__':
    main()
