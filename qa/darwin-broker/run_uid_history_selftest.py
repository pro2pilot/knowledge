"""Physical native persistence tests in one explicitly owned disposable fixture.

Python is always ordinary UID. Only the pinned native test binary and fixed
system file tools run through sudo. No production path or project is modified.
"""
from pathlib import Path
import hashlib
import json
import os
import platform
import subprocess
import tempfile
import time

HERE = Path(__file__).resolve().parent
SOURCE = HERE / 'uid-history'
OUT = HERE / 'evidence' / 'uid-history'
OUT.mkdir(exist_ok=False)
record = {'scope': 'experimental UID-history native unit tests only',
          'backend_certified': False, 'platform': platform.platform(),
          'architecture': platform.machine(), 'commands': [], 'status': 'FAIL'}
fixture = None
native_finished = False
EXPECTED_TESTS = [
    'explicit_empty_fixture', *(['create_own_directory'] * 4), 'actual_host',
    'explicit_init_pending', 'persist_genesis_registry_with_actual_path',
    'explicit_finalize', 'second_singleton_refused', 'consume_burns_pending',
    'pending_not_usable', 'registry_confirm_with_actual_path', 'exact_reservation',
    'wrong_uid_refused', 'restart_preserves_checkpoint', 'restart_never_reuses_uid',
    'second_registry_confirm_with_actual_path', 'own_legacy_slash_format_differs',
    'nonmatching_whole_registry_codec_rejected', 'restore_own_canonical_registry',
    'canonical_registry_path_roundtrip', 'own_foreign_marker_fixture',
    'foreign_marker_preserves_last_trusted_cache', 'restore_own_original_marker',
    'own_head_rollback_fixture', 'partial_rollback_quarantines',
    'quarantine_never_appends', 'existing_history_not_reinitialized',
    'restore_own_head_for_isolated_registry_case', 'own_registry_loss_fixture',
    'serve_does_not_create_registry',
]


def parse_assertions(stdout):
    rows = [json.loads(line) for line in stdout.splitlines() if line]
    if len(rows) != len(EXPECTED_TESTS) + 1:
        raise RuntimeError('native assertion inventory length differs')
    checks, summary = rows[:-1], rows[-1]
    if (any(type(row) is not dict or set(row) != {'test', 'pass'} or
            row.get('test') != name or row.get('pass') is not True
            for row, name in zip(checks, EXPECTED_TESTS)) or
            type(summary) is not dict or set(summary) != {'checks', 'capability_qualified'} or
            type(summary.get('checks')) is not int or summary['checks'] != len(EXPECTED_TESTS) or
            summary.get('capability_qualified') is not False):
        raise RuntimeError('native assertion names, types or summary differ')
    return checks, summary

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def run(name, argv, timeout=30):
    start = time.monotonic()
    try:
        result = subprocess.run(argv, capture_output=True, timeout=timeout, shell=False)
    except subprocess.TimeoutExpired as error:
        (OUT / (name + '.stdout.log')).write_bytes(error.stdout or b'')
        (OUT / (name + '.stderr.log')).write_bytes(error.stderr or b'')
        record['commands'].append({'name': name, 'argv': argv, 'timeout': True,
                                   'elapsed_ms': round((time.monotonic() - start) * 1000, 3)})
        raise
    (OUT / (name + '.stdout.log')).write_bytes(result.stdout)
    (OUT / (name + '.stderr.log')).write_bytes(result.stderr)
    record['commands'].append({'name': name, 'argv': argv, 'exit_code': result.returncode,
                               'elapsed_ms': round((time.monotonic() - start) * 1000, 3)})
    return result

def checked_fixture(path):
    if (path.parent != Path('/private/tmp') or not path.name.startswith('knowledge-uid-history.') or
            path.is_symlink() or path.resolve(strict=True) != path):
        raise RuntimeError('fixture escaped the explicit private/tmp test prefix')
    return path

try:
    if platform.system() != 'Darwin' or os.getuid() == 0:
        raise RuntimeError('requires an ordinary macOS controller')
    expected = json.loads((SOURCE / 'SOURCE_RECEIPT.json').read_bytes())
    before = {name: digest(SOURCE / name) for name in expected['files']}
    record['source_receipt'] = expected
    record['source_before'] = before
    assert before == expected['files'], 'source byte pins differ'
    binary = OUT / 'uid-history-selftest'
    compile_result = run('compile', ['/usr/bin/clang', '-fobjc-arc', '-Wall', '-Wextra',
        '-Wno-deprecated-declarations', '-framework', 'Foundation', '-I' + str(SOURCE),
        str(SOURCE / 'verification-darwin-uid-history.m'),
        str(SOURCE / 'uid-history-native-selftest.m'), '-o', str(binary)], 120)
    if compile_result.returncode:
        raise RuntimeError('native UID-history selftest compile failed')
    record['binary_sha256'] = digest(binary)
    fixture = checked_fixture(Path(tempfile.mkdtemp(prefix='knowledge-uid-history.', dir='/private/tmp')))
    for name, argv in [('protect-fixture', ['/usr/sbin/chown', '0:0', str(fixture)]),
                       ('mode-fixture', ['/bin/chmod', '0755', str(fixture)]),
                       ('own-bin-dir', ['/usr/bin/install', '-d', '-o', '0', '-g', '0', '-m', '0755', str(fixture / 'bin')]),
                       ('own-empty-fixture', ['/usr/bin/install', '-d', '-o', '0', '-g', '0', '-m', '0755', str(fixture / 'fixture')]),
                       ('install', ['/usr/bin/install', '-o', '0', '-g', '0', '-m', '0555', str(binary), str(fixture / 'bin/selftest')])]:
        if run(name, ['/usr/bin/sudo', '-n', *argv]).returncode:
            raise RuntimeError('own native fixture setup failed: ' + name)
    record['installed_sha256'] = digest(fixture / 'bin/selftest')
    assert record['installed_sha256'] == record['binary_sha256']
    result = run('native-selftest', ['/usr/bin/sudo', '-n', str(fixture / 'bin/selftest'), str(fixture / 'fixture')], 120)
    native_finished = True
    checks, summary = parse_assertions(result.stdout)
    record['checks'] = checks
    record['summary'] = summary
    if result.returncode:
        raise RuntimeError('native UID-history assertions failed')
    record['status'] = 'PASS'
except BaseException as error:
    record['error'] = str(error)
finally:
    if fixture:
        try:
            checked_fixture(fixture)
            if native_finished:
                snapshot = run('collect-native-fixture', ['/usr/bin/sudo', '-n', '/usr/bin/tar',
                    '-cf', '-', '-C', str(fixture), 'fixture'])
                if snapshot.returncode or not snapshot.stdout:
                    raise RuntimeError('raw native fixture snapshot failed; retaining fixture')
                archive = OUT / 'native-fixture.tar'
                archive.write_bytes(snapshot.stdout)
                record['native_fixture_archive'] = {'path': str(archive), 'bytes': len(snapshot.stdout),
                    'sha256': digest(archive), 'scope': 'synthetic root-owned native test data only'}
                removed = run('remove-own-fixture', ['/usr/bin/sudo', '-n', '/bin/rm', '-rf', '--', str(fixture)])
                record['fixture_removed'] = removed.returncode == 0 and not fixture.exists()
            else:
                record['fixture_removed'] = False
                record['cleanup_unconfirmed'] = 'native completion was not observed; fixture retained'
        except BaseException as error:
            record['cleanup_error'] = str(error)
    record['source_after'] = {name: digest(SOURCE / name) for name in record.get('source_before', {})}
    record['source_unchanged'] = record.get('source_before') == record['source_after']
    if not record['source_unchanged'] or (fixture and not record.get('fixture_removed')):
        record['status'] = 'FAIL'
    (OUT / 'RESULT.json').write_text(json.dumps(record, indent=2) + '\n')
print(json.dumps(record))
raise SystemExit(0 if record['status'] == 'PASS' else 1)
