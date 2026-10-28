#!/usr/bin/env python3
"""Copy only exact source-checked native pairs from the pinned baseline ZIP."""
import argparse
import hashlib
import json
from pathlib import Path
import zipfile

EXPECTED = '055b9d950038f00a9716a57b7c6b8e9f5103d760bb9f1449181669cbe2ccd0b7'
sha = lambda data: hashlib.sha256(data).hexdigest()
p = argparse.ArgumentParser()
p.add_argument('--package', type=Path, required=True)
p.add_argument('--source', type=Path, required=True)
p.add_argument('--output', type=Path, required=True)
a = p.parse_args()
assert sha(a.package.read_bytes()) == EXPECTED, 'Baseline ZIP hash changed'
records = []
with zipfile.ZipFile(a.package) as z:
    names = z.namelist()
    assert len(names) == len(set(names)) == 499 and z.testzip() is None, 'Baseline inventory or CRC changed'
    for platform in ['linux', 'darwin', 'win32']:
        for arch in ['x64', 'arm64']:
            stems = ['lock-publication'] + (['verification-linux-namespace'] if platform == 'linux' else
                                            ['command-windows-job'] if platform == 'win32' else [])
            for stem in stems:
                folder = 'tools/lib/native/' + platform + '-' + arch + '/'
                manifest_name = folder + stem + '.manifest.json'
                raw = z.read('.knowledge/' + manifest_name)
                manifest = json.loads(raw)
                binary_name = stem if stem == 'verification-linux-namespace' else stem + '.node'
                source_name = ('tools/lib/' if stem == 'verification-linux-namespace' else 'tools/native/') + stem + '.c'
                assert manifest['platform'] == platform and manifest['architecture'] == arch
                assert manifest['binary'] == binary_name
                assert manifest['source_sha256'] == sha((a.source / source_name).read_bytes()), source_name
                binary = z.read('.knowledge/' + folder + binary_name)
                assert 0 < len(binary) <= 16 * 1024 * 1024 and len(binary) == manifest['binary_bytes']
                assert sha(binary) == manifest['binary_sha256']
                dest = a.source / folder
                dest.mkdir(parents=True, exist_ok=True)
                for name, body in [(stem + '.manifest.json', raw), (binary_name, binary)]:
                    target = dest / name
                    assert not target.is_symlink()
                    target.write_bytes(body)
                    target.chmod(0o755 if name == 'verification-linux-namespace' else 0o644)
                records.append({'path': folder + binary_name, 'manifest': manifest})
assert len(records) == 10
a.output.parent.mkdir(parents=True, exist_ok=True)
a.output.write_text(json.dumps({'status': 'PASS_NATIVE_INPUT', 'zip_sha256': EXPECTED, 'pairs': records}, indent=2) + '\n')
