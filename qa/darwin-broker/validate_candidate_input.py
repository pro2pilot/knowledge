"""Check compile/test input byte equivalence to the exact audit ZIP.

Tests remain separately pinned QA overlays. This is not the supported installer
or common verification pipeline, and never grants backend qualification.
"""
from pathlib import Path, PurePosixPath
import hashlib
import json
import stat
import zipfile

if not __debug__:
    raise RuntimeError('optimized Python would disable candidate checks')
HERE = Path(__file__).resolve().parent
RESULT = HERE / 'CANDIDATE_INPUT_RESULT.json'
if RESULT.exists():
    raise RuntimeError('preserve the existing candidate input result')
receipt = json.loads((HERE / 'CANDIDATE_INPUT_RECEIPT.json').read_bytes())
asset = HERE / 'candidate/knowledge-v3.4.4.zip'
sha = lambda b: hashlib.sha256(b).hexdigest()
assert sha(asset.read_bytes()) == receipt['sha256'] and asset.stat().st_size == receipt['bytes']
with zipfile.ZipFile(asset) as z:
    names = z.namelist()
    assert len(names) == len(set(names)) == len({n.casefold() for n in names})
    for name in names:
        parts = PurePosixPath(name).parts
        assert parts and parts[0] == '.knowledge' and '\\' not in name
        assert not PurePosixPath(name).is_absolute() and all(p not in ('', '.', '..') for p in parts)
    package = json.loads(z.read('.knowledge/package.json'))
    manifest = json.loads(z.read('.knowledge/install-manifest.json'))
    assert package['version'] == manifest['schema_version'] == '3.4.4'
    assert package['knowledge_release']['audit_revision'] == 'independent-audit.20261021.darwin-prototype.3'
    assert package['knowledge_release']['audit_status'] == 'development_snapshot_not_certified'
    for name, expected in receipt['member_sha256'].items():
        assert sha(z.read('.knowledge/' + name)) == expected, name
    replacements = {}
    for name in ('verification-darwin-broker.m', 'verification-darwin-stub.c',
                 'verification-darwin-uid-history.h', 'verification-darwin-uid-history.m'):
        replacements[name] = 'tools/lib/' + name
    for name in ('inert-data.js', 'verification-darwin-client.js', 'verification-isolated-copy.js',
                 'verification-darwin-broker.m', 'verification-darwin-stub.c',
                 'verification-darwin-uid-history.h', 'verification-darwin-uid-history.m'):
        replacements['copy/tools/lib/' + name] = 'tools/lib/' + name
    for name in ('verification-darwin-uid-history.h', 'verification-darwin-uid-history.m'):
        replacements['uid-history/' + name] = 'tools/lib/' + name
    for target, member in replacements.items():
        data = z.read('.knowledge/' + member)
        path = HERE / target
        metadata = path.lstat()
        assert stat.S_ISREG(metadata.st_mode) and not path.is_symlink() and metadata.st_nlink == 1
        assert path.resolve(strict=True).is_relative_to(HERE.resolve(strict=True))
        assert member in receipt['member_sha256'] and path.read_bytes() == data, target
result = {'status': 'PASS_ZIP_BYTES_SELECTED', 'candidate_sha256': receipt['sha256'],
          'candidate_source_commit_declared_by_build_receipt': receipt['source_commit'],
          'selected_targets': replacements,
          'member_sha256': receipt['member_sha256'], 'backend_certified': False,
          'scope': 'read-only byte equivalence of selected compile/test inputs to packaged native sources and JS modules; separately pinned QA tests, not installer/pipeline acceptance'}
RESULT.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
print(json.dumps({k: v for k, v in result.items() if k not in ('member_sha256', 'selected_targets')}))
