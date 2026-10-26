#!/usr/bin/env python3
"""Freeze the pinned ancestor's owned paths plus exact allowlisted additions."""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
from prepare import BASE_ZIP_SHA, BASE_MANIFEST_SHA, EXTRA_SOURCE_PATHS, LIMIT, base, bounded, encoded, metadata, new_output, relative, sha, verify_zip, write_new, zip_bytes


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', required=True)
    parser.add_argument('--base-archive', required=True)
    parser.add_argument('--base-manifest', required=True)
    parser.add_argument('--out', required=True)
    parser.add_argument('--extra', action='append', default=[])
    args = parser.parse_args()
    original, ancestor = base(args.base_archive, args.base_manifest)
    names = set(original)
    for value in args.extra:
        name = str(relative(value))
        if name not in EXTRA_SOURCE_PATHS or name in names:
            raise ValueError('Extra must be one distinct explicitly approved source path: ' + name)
        names.add(name)
    source = Path(args.source).absolute()
    files = {}
    if len(names) > 4096:
        raise ValueError('Too many explicit source files')
    total = 0
    for name in sorted(names):
        body = bounded(source / name)
        total += len(body)
        if total > LIMIT:
            raise ValueError('Source cohort exceeds bounded byte limit')
        files[name] = (body, original[name][1] if name in original else '0644')
    archive = zip_bytes(files)
    manifest = {'schema_version': 'knowledge-native-qa-source.v1', 'status': 'PASS_FROZEN_SOURCE',
        'scope': 'Continuation of the exact 650-file Linux reliability cohort, preserving original modes and including only exact allowlisted, explicitly requested source additions. Physical native qualification is pending; not a release approval.',
        'created_utc': datetime.now(timezone.utc).isoformat(), 'archive': 'SOURCE.zip', 'archive_sha256': sha(archive), 'archive_bytes': len(archive),
        'file_count': len(files), 'uncompressed_bytes': sum(len(value[0]) for value in files.values()),
        'files': [metadata(name, *value) for name, value in sorted(files.items())],
        'excluded_native_runtime_artifacts': ancestor.get('excluded_native_runtime_artifacts', []),
        'native_qualification': 'PENDING', 'release_gate_qualified': False,
        'base_archive_sha256': BASE_ZIP_SHA, 'base_manifest_sha256': BASE_MANIFEST_SHA,
        'explicit_extra_paths': args.extra,
        'explicit_extra_tests': [name for name in args.extra if name.startswith('tests/')]}
    verify_zip(archive, manifest)
    # Reject a moving source snapshot before creating any deliverable.
    for name, (body, _) in files.items():
        if bounded(source / name) != body:
            raise ValueError('Source changed during freeze: ' + name)
    manifest_bytes = encoded(manifest)
    changes = []
    overlay_data = []
    for name, value in sorted(files.items()):
        if original.get(name) == value:
            continue
        slot = f'overlays/{len(changes):04d}.bin'
        changes.append({'path': name, 'overlay': slot, 'base': metadata(name, *original[name]) if name in original else None,
                        'result': metadata(name, *value)})
        overlay_data.append((slot, value[0]))
    overlay = {'schema_version': 'knowledge-continuation-overlay.v1',
        'base': {'archive_sha256': BASE_ZIP_SHA, 'manifest_sha256': BASE_MANIFEST_SHA, 'file_count': 650},
        'target_manifest_sha256': sha(manifest_bytes), 'target_archive': {'sha256': sha(archive), 'bytes': len(archive)},
        'changes': changes, 'native_qualification': 'PENDING', 'release_gate_qualified': False}
    output = new_output(args.out)
    write_new(output / 'SOURCE.zip', archive)
    write_new(output / 'SOURCE_MANIFEST.json', manifest_bytes)
    write_new(output / 'SOURCE_PINS.json', encoded({'files': {name: sha(value[0]) for name, value in sorted(files.items())}}))
    write_new(output / 'OVERLAY.json', encoded(overlay))
    for name, body in overlay_data:
        write_new(output / name, body)
    print(json.dumps({'status': 'PASS_FROZEN_SOURCE', 'archive_sha256': sha(archive), 'file_count': len(files), 'overlays': len(changes), 'native_qualification': 'PENDING'}))


if __name__ == '__main__':
    main()
