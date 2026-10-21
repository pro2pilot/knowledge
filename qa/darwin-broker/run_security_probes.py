"""Run audit-only probes on a disposable macOS runner; never certifies backend."""
from pathlib import Path
import hashlib
import json
import os
import platform
import subprocess
import tempfile
import time

HERE = Path(__file__).resolve().parent
OUT = HERE / 'evidence'
OUT.mkdir(exist_ok=True)
rows = []

def command(name, argv, timeout=120):
    start = time.monotonic()
    with (OUT / (name + '.stdout.log')).open('wb') as stdout, (OUT / (name + '.stderr.log')).open('wb') as stderr:
        r = subprocess.run(argv, stdout=stdout, stderr=stderr, timeout=timeout)
    row = {'name': name, 'argv': argv, 'exit_code': r.returncode,
           'elapsed_ms': round((time.monotonic()-start)*1000, 3)}
    rows.append(row)
    return r.returncode

assert platform.system() == 'Darwin' and os.getuid() > 0
record = {'scope': 'audit fixtures only; no product capability or ACK', 'backend_certified': False,
          'platform': platform.platform(), 'uid': os.getuid(), 'commands': rows}
fixture = None
try:
    for name in ['credential-exec-probe', 'host-port-probe', 'task-access-probe']:
        source = HERE / (name + '.c')
        record[name + '_source_sha256'] = hashlib.sha256(source.read_bytes()).hexdigest()
        code = command('compile-' + name, ['/usr/bin/clang', '-std=c11', '-O2', '-Wall', '-Wextra',
                       str(source), '-o', str(OUT / name)])
        assert code == 0, 'probe compile failure: ' + name
    fixture = Path(tempfile.mkdtemp(prefix='knowledge-broker-credential.', dir='/private/tmp')).resolve()
    assert fixture.parent == Path('/private/tmp') and fixture.name.startswith('knowledge-broker-credential.')
    assert not fixture.is_symlink()
    assert command('protect-root', ['/usr/bin/sudo', '-n', '/usr/sbin/chown', '0:0', str(fixture)]) == 0
    assert command('protect-mode', ['/usr/bin/sudo', '-n', '/bin/chmod', '0755', str(fixture)]) == 0
    for name, owner, group, mode in [('probe', 0, 0, '0755'), ('root-suid', 0, 0, '4755'),
                                    ('original-suid', os.getuid(), os.getgid(), '4755'), ('root-sgid', 0, 0, '2755')]:
        assert command('install-' + name, ['/usr/bin/sudo', '-n', '/usr/bin/install', '-o', str(owner), '-g', str(group),
                       '-m', mode, str(OUT / 'credential-exec-probe'), str(fixture / name)]) == 0
    copy = fixture / 'copy'
    assert command('make-copy', ['/usr/bin/sudo', '-n', '/bin/mkdir', str(copy)]) == 0
    assert command('own-copy', ['/usr/bin/sudo', '-n', '/usr/sbin/chown', '1800000123:1800000123', str(copy)]) == 0
    assert command('mode-copy', ['/usr/bin/sudo', '-n', '/bin/chmod', '0700', str(copy)]) == 0
    broker = OUT / 'knowledge-native-broker'
    assert command('exact-profile', [str(broker), '--print-profile', '--workspace=' + str(copy),
                   '--runtime=' + str(fixture / 'probe')]) == 0
    profile = (OUT / 'exact-profile.stdout.log').read_text()
    record['profile_sha256'] = hashlib.sha256(profile.encode()).hexdigest()
    record['profile_runtime_difference'] = 'Exact native generator; diagnostic non-SUID probe literal replaces Node runtime literal'
    command('credential-matrix', ['/usr/bin/sudo', '-n', str(fixture / 'probe'), str(fixture / 'root-suid'),
            str(fixture / 'original-suid'), str(fixture / 'root-sgid'), str(copy), str(os.getuid()),
            '1800000123', profile])
    events = [json.loads(line) for line in (OUT / 'credential-matrix.stdout.log').read_text().splitlines()]
    record['matrix_summary'] = next((x for x in events if x.get('kind') == 'summary'), None)
    cases, current = [], None
    for event in events:
        if event['kind'] == 'case_begin':
            current = dict(event, events=[])
            cases.append(current)
        elif current is not None:
            current['events'].append(event)
    record['cases'] = cases
    record['suid_and_sgid_controls'] = [c for c in cases if not c['sandboxed'] and c['import_method'] == 0]
    record['sandbox_normal_control'] = [c for c in cases if c['sandboxed'] and c['fixture'] == 0 and c['import_method'] == 0]
    command('host-port', ['/usr/bin/sudo', '-n', str(OUT / 'host-port-probe')])
    task_probe = fixture / 'task-access-probe'
    assert command('install-task-access-probe', ['/usr/bin/sudo', '-n', '/usr/bin/install', '-o', '0', '-g', '0', '-m', '0755',
                   str(OUT / 'task-access-probe'), str(task_probe)]) == 0
    assert command('task-access-profile', [str(broker), '--print-profile', '--workspace=' + str(copy),
                   '--runtime=' + str(task_probe)]) == 0
    task_profile = (OUT / 'task-access-profile.stdout.log').read_text()
    record['task_access_profile_sha256'] = hashlib.sha256(task_profile.encode()).hexdigest()
    command('task-access', ['/usr/bin/sudo', '-n', str(task_probe), str(os.getuid()), '1800000123', task_profile])
    record['status'] = 'DIAGNOSTICS_COMPLETE_REVIEW_REQUIRED'
except BaseException as error:
    record['status'] = 'INFRASTRUCTURE_FAILED'
    record['failure'] = str(error)
finally:
    if fixture:
        # Only the freshly created exact fixture; no parent enumeration or symlink traversal.
        resolved_parent = fixture.parent.resolve(strict=True)
        assert resolved_parent == Path('/private/tmp') and fixture.name.startswith('knowledge-broker-credential.')
        assert not fixture.is_symlink()
        record['fixture_cleanup_exit'] = command('remove-own-fixture', ['/usr/bin/sudo', '-n', '/bin/rm', '-rf', '--', str(fixture)])
    (OUT / 'SECURITY_PROBES_RESULT.json').write_text(json.dumps(record, indent=2) + '\n')
print(json.dumps({k: v for k, v in record.items() if k not in ['cases', 'commands']}))
raise SystemExit(0 if record['status'] == 'DIAGNOSTICS_COMPLETE_REVIEW_REQUIRED' else 1)
