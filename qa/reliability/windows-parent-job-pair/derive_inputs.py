#!/usr/bin/env python3
"""Derive exact reviewed Windows cohorts from an already published input ZIP.

All source bytes and executable modes must match complete manifests. ZIP_STORED
avoids a dependency on the runner's zlib version. This produces input only; it
does not interpret a test result or turn a failed baseline into a successful run.
"""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import stat
import zipfile


def digest(data):
    return hashlib.sha256(data).hexdigest()


def read_json(path):
    data = path.read_bytes()
    if len(data) > 2_000_000:
        raise ValueError('Oversized input metadata')
    return json.loads(data)


def safe_relative(value):
    p = PurePosixPath(value)
    if not isinstance(value, str) or not value or p.is_absolute() or '..' in p.parts or '\\' in value or str(p) != value:
        raise ValueError('Noncanonical source path')
    return value


def inventory(manifest):
    rows = manifest['files']
    if not isinstance(rows, list) or len(rows) != manifest['file_count']:
        raise ValueError('Invalid source count')
    paths = [safe_relative(row['path']) for row in rows]
    if paths != sorted(set(paths)):
        raise ValueError('Duplicate or unsorted inventory')
    for row in rows:
        if row['mode'] not in ['0644', '0755'] or not isinstance(row['bytes'], int) or row['bytes'] < 0:
            raise ValueError('Invalid source mode or length')
    return {row['path']: row for row in rows}


def source_row(name, data, mode):
    return {'path': name, 'bytes': len(data), 'sha256': digest(data), 'mode': mode}


def derive(base_archive, directory, out, cohort):
    pins = read_json(directory / 'DERIVATION_PINS.json')
    if pins['schema_version'] != 'knowledge-windows-custody-input-derivation.v1' or cohort not in ['before', 'after']:
        raise ValueError('Unrecognized derivation contract')
    original_bytes = base_archive.read_bytes()
    if digest(original_bytes) != pins['base_archive_sha256']:
        raise ValueError('Base archive hash mismatch')
    original = read_json(directory / pins['base_manifest'])
    if original['archive_sha256'] != pins['base_archive_sha256'] or original['archive_bytes'] != len(original_bytes):
        raise ValueError('Base manifest binding mismatch')
    base_rows = inventory(original)
    bodies = {}
    with zipfile.ZipFile(base_archive) as archive:
        infos = archive.infolist()
        if [i.filename for i in infos] != ['.knowledge/' + name for name in base_rows]:
            raise ValueError('Base ZIP inventory mismatch')
        for entry in infos:
            name = entry.filename[len('.knowledge/'):]
            mode = entry.external_attr >> 16
            if not stat.S_ISREG(mode) or entry.flag_bits & 1:
                raise ValueError('Nonregular or encrypted input member')
            data = archive.read(entry)
            actual = source_row(name, data, '0755' if mode & 0o111 else '0644')
            if actual != base_rows[name]:
                raise ValueError('Base member binding mismatch')
            bodies[name] = data
    target = pins['cohorts'][cohort]
    manifest = read_json(directory / target['manifest'])
    rows = inventory(manifest)
    overlays = target['overlays']
    if len({entry['path'] for entry in overlays}) != len(overlays):
        raise ValueError('Duplicate overlay')
    for entry in overlays:
        name = safe_relative(entry['path'])
        asset = safe_relative(entry['asset'])
        if not asset.startswith('overlays/') or entry['before'] != base_rows.get(name) or entry['after'] != rows.get(name):
            raise ValueError('Overlay provenance mismatch')
        body = (directory / asset).read_bytes()
        if source_row(name, body, entry['after']['mode']) != entry['after']:
            raise ValueError('Overlay bytes mismatch')
        bodies[name] = body
    if sorted(bodies) != list(rows):
        raise ValueError('Derived inventory mismatch')
    for name, row in rows.items():
        if source_row(name, bodies[name], row['mode']) != row:
            raise ValueError('Derived member mismatch')
        if name in base_rows and name not in {entry['path'] for entry in overlays} and row['mode'] != base_rows[name]['mode']:
            raise ValueError('Unrecorded executable mode delta')
    out.mkdir(parents=True, exist_ok=False)
    archive_path = out / (cohort + '.zip')
    with zipfile.ZipFile(archive_path, 'x', compression=zipfile.ZIP_STORED) as archive:
        for name, row in rows.items():
            entry = zipfile.ZipInfo('.knowledge/' + name, date_time=(1980, 1, 1, 0, 0, 0))
            entry.create_system = 3
            entry.external_attr = (stat.S_IFREG | int(row['mode'], 8)) << 16
            entry.compress_type = zipfile.ZIP_STORED
            archive.writestr(entry, bodies[name])
    produced = archive_path.read_bytes()
    if digest(produced) != target['archive_sha256'] or len(produced) != target['archive_bytes'] or manifest['archive_sha256'] != target['archive_sha256'] or manifest['archive_bytes'] != target['archive_bytes']:
        raise ValueError('Derived ZIP exact-byte binding mismatch')
    with zipfile.ZipFile(archive_path) as archive:
        if archive.testzip() is not None or len(archive.infolist()) != len(rows):
            raise ValueError('Derived ZIP readback failed')
    if digest(base_archive.read_bytes()) != pins['base_archive_sha256']:
        raise ValueError('Base archive changed during derivation')
    receipt = {
        'schema_version': 'knowledge-windows-custody-derived-input.v1',
        'status': 'PASS_INPUT_DERIVATION', 'native_test_status': 'NOT_RUN',
        'cohort': cohort, 'base_archive_sha256': pins['base_archive_sha256'],
        'archive_sha256': digest(produced), 'archive_bytes': len(produced),
        'files': len(rows), 'overlay_count': len(overlays), 'base_unchanged': True,
        'controller_sha256': digest(Path(__file__).read_bytes()),
        'pins_sha256': digest((directory / 'DERIVATION_PINS.json').read_bytes()),
        'target_manifest_sha256': digest((directory / target['manifest']).read_bytes()),
    }
    (out / 'DERIVATION.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps(receipt, indent=2))
    return receipt


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--base-archive', required=True)
    parser.add_argument('--out', required=True)
    parser.add_argument('--cohort', required=True, choices=['before', 'after'])
    args = parser.parse_args()
    derive(Path(args.base_archive), Path(__file__).resolve().parent, Path(args.out), args.cohort)
