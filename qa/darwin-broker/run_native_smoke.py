"""Explicit administrator fixture setup; only native binaries ever run as root."""
from pathlib import Path
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import tempfile
import time

HERE = Path(__file__).resolve().parent
OUT = HERE / 'evidence'
OUT.mkdir(exist_ok=True)
commands = []
record = {'scope': 'disposable macOS isolated-copy native smoke, not product qualification',
          'platform': platform.platform(), 'backend_certified': False, 'commands': commands}
fixture, daemon, descriptor = None, None, None

def run(name, argv, timeout=120):
    start = time.monotonic()
    with (OUT / (name + '.stdout.log')).open('wb') as stdout, (OUT / (name + '.stderr.log')).open('wb') as stderr:
        r = subprocess.run(argv, stdout=stdout, stderr=stderr, timeout=timeout)
    commands.append({'name': name, 'argv': argv, 'exit_code': r.returncode,
                     'elapsed_ms': round((time.monotonic()-start)*1000, 3)})
    return r.returncode

try:
    assert platform.system() == 'Darwin' and os.getuid() > 0
    assert run('compile-path-diagnostics', ['/usr/bin/clang', '-fobjc-arc', '-framework', 'Foundation',
               str(HERE / 'path-diagnostics.m'), '-o', str(OUT / 'path-diagnostics')]) == 0
    assert run('compile-uid-scan', ['/usr/bin/clang', '-std=c11', '-O2', '-Wall', '-Wextra',
               str(HERE / 'uid-scan.c'), '-o', str(OUT / 'uid-scan')]) == 0
    fixture = Path(tempfile.mkdtemp(prefix='knowledge-native-smoke.', dir='/private/tmp')).resolve()
    assert fixture.parent == Path('/private/tmp') and not fixture.is_symlink()
    assert run('protect-smoke-root', ['/usr/bin/sudo', '-n', '/usr/sbin/chown', '0:0', str(fixture)]) == 0
    assert run('mode-smoke-root', ['/usr/bin/sudo', '-n', '/bin/chmod', '0711', str(fixture)]) == 0
    for name, mode in [('bin','0711'), ('runtime','0711'), ('control','0711'), ('registry','0700'), ('workspaces','0711')]:
        assert run('mkdir-' + name, ['/usr/bin/sudo', '-n', '/bin/mkdir', str(fixture / name)]) == 0
        assert run('mode-' + name, ['/usr/bin/sudo', '-n', '/bin/chmod', mode, str(fixture / name)]) == 0
    binary, node, sock = fixture / 'bin/broker', fixture / 'runtime/node', fixture / 'control/broker.sock'
    actual_node = Path(shutil.which('node')).resolve(strict=True)
    record['original_node_sha256'] = hashlib.sha256(actual_node.read_bytes()).hexdigest()
    for name, source, dest in [('broker', OUT / 'knowledge-native-broker', binary), ('node', actual_node, node)]:
        assert run('install-' + name, ['/usr/bin/sudo', '-n', '/usr/bin/install', '-o', '0', '-g', '0', '-m', '0555', str(source), str(dest)]) == 0
        record[name + '_installed_sha256'] = hashlib.sha256(dest.read_bytes()).hexdigest()
    assert record['node_installed_sha256'] == record['original_node_sha256']
    run('path-diagnostics', [str(OUT / 'path-diagnostics'), str(binary), str(fixture)])
    run('fixture-path-permissions', ['/bin/ls', '-lde', '/private', '/private/tmp', str(fixture),
        str(fixture / 'bin'), str(binary)])
    daemon_argv = ['/usr/bin/sudo', '-n', str(binary), '--serve', '--qualification-mode',
                   '--registry=' + str(fixture / 'registry'), '--socket=' + str(sock),
                   '--workspaces=' + str(fixture / 'workspaces'), '--runtime=' + str(node)]
    with (OUT / 'daemon.stdout.log').open('wb') as stdout, (OUT / 'daemon.stderr.log').open('wb') as stderr:
        daemon = subprocess.Popen(daemon_argv, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr)
        record['daemon_launcher_pid'] = daemon.pid
        until = time.monotonic() + 15
        while time.monotonic() < until and not sock.exists() and daemon.poll() is None:
            time.sleep(.05)
        if not sock.exists():
            raise RuntimeError('native daemon startup failed, exit=' + str(daemon.poll()))
        code = run('native-smoke', ['python3', str(HERE / 'daemon-harness.py'), '--binary=' + str(binary),
                   '--socket=' + str(sock), '--node=' + str(node),
                   '--profile-output=' + str(OUT / 'exact-native-profile.sb')], timeout=180)
        result = json.loads((OUT / 'native-smoke.stdout.log').read_bytes())
        descriptor = result.get('descriptor')
        record['smoke_exit_code'] = code
        record['physical_smoke_passed'] = result.get('physical_smoke_passed', False)
        record['native_cleanup_facts_confirmed'] = result.get('native_cleanup_facts_confirmed', False)
        proof = result.get('native_proof')
        if proof:
            encoded = json.dumps(proof, sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode()
            digest = hashlib.sha256(encoded).hexdigest()
            attempt = proof['attempt_id']
            assert re.fullmatch('[a-f0-9]{64}', attempt)
            receipt = fixture / 'registry' / (attempt + '.' + digest + '.receipt.json')
            assert run('native-proof-readback', ['/usr/bin/sudo', '-n', '/bin/cat', str(receipt)]) == 0
            back = (OUT / 'native-proof-readback.stdout.log').read_bytes()
            record['protected_receipt_matches_response'] = back == encoded
            record['native_proof_sha256'] = digest
            assert back == encoded
        record['status'] = 'PHYSICAL_SMOKE_PASS_UNQUALIFIED' if code == 0 else 'PHYSICAL_SMOKE_FAIL'
except BaseException as error:
    record['status'] = 'PHYSICAL_SMOKE_FAIL'
    record['error'] = str(error)
finally:
    if daemon and daemon.poll() is None:
        # This exact unreaped launcher handle belongs to this harness; never discover targets by process name.
        run('stop-own-native-daemon', ['/usr/bin/sudo', '-n', '/bin/kill', '-TERM', str(daemon.pid)])
        try:
            daemon.wait(timeout=70)
        except subprocess.TimeoutExpired:
            record['daemon_stop_unconfirmed'] = True
        record['daemon_launcher_exit'] = daemon.poll()
    membership_clear = descriptor is None
    if descriptor:
        uid = descriptor['task_ruid']
        assert isinstance(uid, int) and 1000000000 <= uid < 1900000000
        membership_clear = run('post-stop-uid-scan', [str(OUT / 'uid-scan'), str(uid)]) == 0
        record['post_stop_membership_clear'] = membership_clear
    if fixture and (not daemon or daemon.poll() is not None) and membership_clear:
        assert fixture.parent.resolve(strict=True) == Path('/private/tmp')
        assert fixture.name.startswith('knowledge-native-smoke.') and not fixture.is_symlink()
        record['fixture_cleanup_exit'] = run('remove-own-native-fixture', ['/usr/bin/sudo', '-n', '/bin/rm', '-rf', '--', str(fixture)])
    elif fixture:
        record['fixture_cleanup_deferred'] = 'Native membership or daemon exit is unconfirmed; disposable runner must be discarded'
    (OUT / 'NATIVE_SMOKE_RESULT.json').write_text(json.dumps(record, indent=2) + '\n')
print(json.dumps(record))
raise SystemExit(0 if record['status'] == 'PHYSICAL_SMOKE_PASS_UNQUALIFIED' else 1)
