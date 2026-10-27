#!/usr/bin/env python3
"""Build a bounded offline source/evidence handoff, then seal reviewed bytes."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path, PurePosixPath
import re
import stat
import zipfile

LIMIT = 128 * 1024 * 1024


def digest(body):
    return hashlib.sha256(body).hexdigest()


def encoded(value):
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + '\n').encode()


def safe_name(name):
    p = PurePosixPath(name)
    if not name or p.is_absolute() or str(p) != name or '\\' in name or ':' in name or any(x in ('', '.', '..') for x in name.split('/')):
        raise ValueError('Noncanonical package member')
    return name


def read(file):
    file = Path(file)
    before = file.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > LIMIT:
        raise ValueError('Input is not a bounded owned regular file')
    body = file.read_bytes()
    after = file.lstat()
    keys = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
    if len(body) != before.st_size or any(getattr(before, k) != getattr(after, k) for k in keys):
        raise ValueError('Input changed during read')
    return body


def public_inventory(root):
    inventory = json.loads(read(root / 'SHA256SUMS.json'))
    actual = {p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_file()} - {'SHA256SUMS.json'}
    if not isinstance(inventory, dict) or actual != set(inventory):
        raise ValueError('Public inventory membership differs')
    for name, row in inventory.items():
        body = read(root / safe_name(name))
        if row.get('sha256') != digest(body) or row.get('bytes') != len(body):
            raise ValueError('Public inventory bytes differ')


def write_zip(file, members):
    with zipfile.ZipFile(file, 'x', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name, body in sorted(members.items()):
            info = zipfile.ZipInfo(safe_name(name), (2026, 10, 27, 0, 0, 0))
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, body)


def verify_zip(file, expected):
    with zipfile.ZipFile(file) as archive:
        names = archive.namelist()
        if names != sorted(expected) or len(names) != len(set(x.casefold() for x in names)) or archive.testzip() is not None:
            raise ValueError('ZIP structure or CRC differs')
        for item in archive.infolist():
            if item.flag_bits & 1 or (item.external_attr >> 16) != stat.S_IFREG | 0o644 or archive.read(item) != expected[item.filename]:
                raise ValueError('ZIP member readback differs')
    return {'bytes': file.stat().st_size, 'sha256': digest(read(file)), 'members': len(expected), 'crc': 'PASS', 'all_member_bytes': 'PASS'}


def build(args):
    out = Path(args.out)
    out.mkdir(mode=0o700)
    members = {}

    def add(name, body):
        safe_name(name)
        if name.casefold() in {p.casefold() for p in members} or sum(map(len, members.values())) + len(body) > 256 * 1024 * 1024:
            raise ValueError('Duplicate or oversized package')
        members[name] = body

    def tree(root, prefix):
        root = Path(root)
        for file in sorted(root.rglob('*')):
            if file.is_symlink():
                raise ValueError('Symlink in handoff inputs')
            if file.is_file():
                add(prefix + '/' + file.relative_to(root).as_posix(), read(file))

    source = Path(args.prepared)
    manifest = json.loads(read(source / 'SOURCE_MANIFEST.json'))
    if digest(read(source / 'SOURCE.zip')) != manifest['archive_sha256']:
        raise ValueError('Frozen source archive binding differs')
    for name in ('SOURCE.zip', 'SOURCE_MANIFEST.json', 'SOURCE_PINS.json'):
        add('source/final/' + name, read(source / name))
    for name in ('SOURCE.zip', 'SOURCE_MANIFEST.json'):
        add('source/base650/' + name, read(Path(args.base) / name))
    tree(args.overlay, 'source/reconstruction')
    add('repository/knowledge-audit.bundle', read(args.bundle))
    add('README_RU.txt', read(args.readme))
    add('STATUS.json', read(args.status))
    add('WORK_RULES_RU.txt', read(Path(__file__).with_name('WORK_RULES_RU.txt')))
    add('reproduce/build-handoff.py', read(__file__))
    if args.assembly:
        assembly = Path(args.assembly)
        # Export only the immutable package and its explicit receipts/logs;
        # scratch source copies and build work directories are not evidence.
        for file in sorted(assembly.iterdir()):
            if file.is_file() and file.suffix in ('.zip', '.json', '.txt', '.log'):
                add('candidate/' + file.name, read(file))
    evidence = []
    for item in args.evidence:
        label, value = item.split('=', 1)
        if not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,100}', label):
            raise ValueError('Invalid evidence label')
        root = Path(value)
        public_inventory(root)
        result = json.loads(read(root / 'RESULT.json'))
        evidence.append({'label': label, 'commit': result.get('commit'), 'source_zip_sha256': result.get('source_zip_sha256'),
                         'platform': result.get('platform'), 'architecture': result.get('architecture'),
                         'macos_cohort': result.get('macos_cohort'), 'status': result.get('status')})
        tree(root, 'evidence/' + label)
    for item in args.review:
        label, value = item.split('=', 1)
        add('reviews/' + safe_name(label), read(value))
    add('EVIDENCE_INDEX.json', encoded({'schema': 'knowledge-handoff-evidence-index.v1', 'snapshots': evidence,
        'counts_are_per_cohort': True, 'historical_results_do_not_qualify_final_source': True}))
    inventory = {'schema': 'knowledge-handoff-members.v1', 'commit': args.commit,
                 'source_sha256': manifest['archive_sha256'], 'source_file_count': manifest['file_count'],
                 'files': {name: {'bytes': len(body), 'sha256': digest(body)} for name, body in sorted(members.items())}}
    add('MANIFEST.json', encoded(inventory))
    package = out / 'KNOWLEDGE_RC5_SOURCE_EVIDENCE_HANDOFF_20261027.zip'
    write_zip(package, members)
    checked = verify_zip(package, members)
    receipt = {'schema': 'knowledge-handoff-postzip.v1', 'status': 'PASS_EXACT_ARCHIVE_READBACK', 'archive': package.name,
               **checked, 'manifest_sha256': digest(members['MANIFEST.json']), 'commit': args.commit,
               'source_sha256': manifest['archive_sha256'], 'release_gate_qualified': False,
               'meaning': 'Archive integrity only; platform/runtime qualification is in STATUS.json and exact source-bound evidence.'}
    (out / 'POSTZIP_VERIFICATION.json').write_bytes(encoded(receipt))
    print(json.dumps(receipt))


def seal(args):
    root = Path(args.directory)
    receipt = json.loads(read(root / 'POSTZIP_VERIFICATION.json'))
    package = root / safe_name(receipt['archive'])
    body = read(package)
    if digest(body) != receipt['sha256'] or len(body) != receipt['bytes']:
        raise ValueError('Reviewed handoff archive changed')
    review = read(args.independent_review)
    parsed = json.loads(review)
    if parsed.get('status') != 'PASS_INDEPENDENT_HANDOFF_READBACK' or parsed.get('archive_sha256') != receipt['sha256']:
        raise ValueError('Independent review does not bind this archive')
    contents = {package.name: body, 'POSTZIP_VERIFICATION.json': read(root / 'POSTZIP_VERIFICATION.json'),
                'INDEPENDENT_REVIEW.json': review, 'README_RU.txt': read(args.readme)}
    target = root / 'KNOWLEDGE_RC5_DELIVERY_20261027.zip'
    write_zip(target, contents)
    print(json.dumps({'status': 'PASS_SEALED_DELIVERY', 'archive': str(target), **verify_zip(target, contents),
                      'release_gate_qualified': False}))


def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest='command', required=True)
    b = sub.add_parser('build')
    for name in ('prepared', 'base', 'overlay', 'bundle', 'readme', 'status', 'commit', 'out'):
        b.add_argument('--' + name, required=True)
    b.add_argument('--assembly')
    b.add_argument('--evidence', action='append', default=[])
    b.add_argument('--review', action='append', default=[])
    s = sub.add_parser('seal')
    for name in ('directory', 'independent-review', 'readme'):
        s.add_argument('--' + name, required=True)
    args = p.parse_args()
    build(args) if args.command == 'build' else seal(args)


if __name__ == '__main__':
    main()
