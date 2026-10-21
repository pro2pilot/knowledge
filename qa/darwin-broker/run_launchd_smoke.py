"""Test-only launchd startup-method probe for the pinned RC5 native broker.

Run on an explicitly authorized disposable macOS runner as an ordinary user.
This does not qualify the backend or claim trusted OS-origin verification.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import platform
import plistlib
import re
import shutil
import subprocess
import tempfile
import time
import uuid

SOURCE_SHA = '19e9690b2849c47c14f1676623a7c2854357a3400d1fb9d1661113c7f55003d0'
SCRIPT_DIR = Path(__file__).resolve().parent
CWD = Path.cwd().resolve()
HERE = CWD if (CWD / 'compile_native.py').is_file() and (CWD / 'daemon-harness.py').is_file() else SCRIPT_DIR

def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()

def run(name, argv, record, timeout=30, data=None):
    start = time.monotonic()
    try:
        p = subprocess.run(argv, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           timeout=timeout, shell=False)
        timed_out = False
    except subprocess.TimeoutExpired as error:
        stdout = error.stdout or b''
        stderr = error.stderr or b''
        if isinstance(stdout, str): stdout = stdout.encode()
        if isinstance(stderr, str): stderr = stderr.encode()
        p = subprocess.CompletedProcess(argv, None, stdout, stderr)
        timed_out = True
    (OUT / (name + '.stdout.log')).write_bytes(p.stdout)
    (OUT / (name + '.stderr.log')).write_bytes(p.stderr)
    record['commands'].append({'name': name, 'argv': argv, 'exit_code': p.returncode,
                               'timed_out': timed_out,
                               'elapsed_ms': round((time.monotonic()-start)*1000, 3)})
    return p

def checked_fixture(path):
    root = Path('/private/tmp')
    lexical = Path(path)
    resolved_root = root.resolve(strict=True)
    resolved = lexical.resolve(strict=True)
    if (lexical.parent != root or not lexical.name.startswith('knowledge-launchd-smoke.') or
            lexical.is_symlink() or resolved.parent != resolved_root or
            not resolved.name.startswith('knowledge-launchd-smoke.')):
        raise RuntimeError('fixture path escaped the checked /private/tmp prefix')
    return lexical

parser = argparse.ArgumentParser()
parser.add_argument('--broker', type=Path, default=HERE / 'evidence' / 'knowledge-native-broker')
parser.add_argument('--node', type=Path, default=Path(shutil.which('node')).resolve() if shutil.which('node') else None)
attempt12_harness = SCRIPT_DIR / 'D' / 'native' / 'daemon-harness-attempt12.py'
parser.add_argument('--harness', type=Path, default=attempt12_harness if attempt12_harness.is_file() else HERE / 'daemon-harness.py')
parser.add_argument('--uid-scan', type=Path, default=HERE / 'evidence' / 'uid-scan')
parser.add_argument('--source-receipt', type=Path, default=HERE / 'SOURCE_RECEIPT.json')
parser.add_argument('--compile-result', type=Path, default=HERE / 'evidence' / 'COMPILE_RESULT.json')
args = parser.parse_args()
EVIDENCE_ROOT = HERE / 'evidence'
if EVIDENCE_ROOT.is_symlink() or not EVIDENCE_ROOT.is_dir():
    raise SystemExit('expected build evidence directory is missing or a symlink')
OUT = EVIDENCE_ROOT / ('launchd-smoke-' + uuid.uuid4().hex[:12])
OUT.mkdir(mode=0o700)
record = {'scope': 'launchd startup-method physical probe only', 'backend_certified': False,
          'trusted_os_origin_verified': False, 'commands': [], 'capability_semantics': False,
          'platform': platform.platform(), 'architecture': platform.machine()}
fixture = None
bootstrapped = False
label = None
descriptor = None
membership_clear = False
harness_started = False

try:
    if platform.system() != 'Darwin' or os.getuid() == 0:
        raise RuntimeError('requires a non-root macOS controller user')
    if args.node is None:
        raise RuntimeError('node was not found on PATH')
    if OUT.parent.is_symlink() or not OUT.parent.is_dir():
        raise RuntimeError('expected build evidence directory is missing or a symlink')
    source_receipt = json.loads(args.source_receipt.read_bytes())
    compile_result = json.loads(args.compile_result.read_bytes())
    if source_receipt.get('native_sha256') != SOURCE_SHA:
        raise RuntimeError('SOURCE_RECEIPT does not pin the expected native source')
    if (compile_result.get('source_sha256') != SOURCE_SHA or compile_result.get('status') != 'PASS' or
            compile_result.get('exit_code') != 0 or compile_result.get('source_unchanged') is not True):
        raise RuntimeError('fresh COMPILE_RESULT does not confirm a successful unchanged pinned source build')
    record['source_receipt_native_sha256'] = source_receipt['native_sha256']
    record['compile_result_source_sha256'] = compile_result['source_sha256']
    record['compile_result_status'] = compile_result['status']
    record['compile_result_source_unchanged'] = compile_result['source_unchanged']
    broker_source, node_source = args.broker.resolve(strict=True), args.node.resolve(strict=True)
    if args.broker.is_symlink() or args.node.is_symlink() or not broker_source.is_file() or not node_source.is_file():
        raise RuntimeError('broker or resolved Node artifact is not an ordinary file')
    origin_source = HERE / 'launch-origin-probe.c'
    if not origin_source.is_file():
        origin_source = SCRIPT_DIR / 'launch-origin-probe.c'
    origin_binary = OUT / 'launch-origin-probe'
    record['launch_origin_source_sha256'] = sha(origin_source)
    compiled_origin = run('compile-launch-origin-probe', ['/usr/bin/clang', '-std=c11', '-Wall', '-Wextra', '-Werror',
                           str(origin_source), '-o', str(origin_binary)], record, 120)
    if compiled_origin.returncode != 0:
        raise RuntimeError('ordinary-user launch-origin-probe compile failed')
    record['launch_origin_binary_sha256_before_install'] = sha(origin_binary)
    record['broker_sha256_before_install'] = sha(broker_source)
    record['node_sha256_before_install'] = sha(node_source)
    record['broker_input_path'] = str(broker_source)
    record['node_input_path'] = str(node_source)
    fixture = Path(tempfile.mkdtemp(prefix='knowledge-launchd-smoke.', dir='/private/tmp'))
    checked_fixture(fixture)
    suffix = fixture.name.rsplit('.', 1)[1].replace('_', '')
    label = 'org.knowledgekit.rc5.launchd-smoke.' + suffix
    for name in ['bin', 'runtime', 'control', 'registry', 'workspaces', 'logs', 'launchd']:
        p = fixture / name
        p.mkdir()
        mode = '0700' if name in ('registry', 'logs', 'launchd') else '0711'
        assert run('protect-dir-' + name, ['/usr/bin/sudo', '-n', '/usr/sbin/chown', '0:0', str(p)], record).returncode == 0
        assert run('mode-dir-' + name, ['/usr/bin/sudo', '-n', '/bin/chmod', mode, str(p)], record).returncode == 0
    assert run('protect-fixture', ['/usr/bin/sudo', '-n', '/usr/sbin/chown', '0:0', str(fixture)], record).returncode == 0
    assert run('mode-fixture', ['/usr/bin/sudo', '-n', '/bin/chmod', '0711', str(fixture)], record).returncode == 0
    binary, node, origin_probe = fixture / 'bin/broker', fixture / 'runtime/node', fixture / 'bin/launch-origin-probe'
    for name, source, target in [('broker', broker_source, binary), ('node', node_source, node),
                                 ('launch-origin-probe', origin_binary, origin_probe)]:
        assert run('install-' + name, ['/usr/bin/sudo', '-n', '/usr/bin/install', '-o', '0', '-g', '0', '-m', '0555', str(source), str(target)], record).returncode == 0
        record[name + '_sha256_after_install'] = sha(target)
        expected_hash = (record['broker_sha256_before_install'] if name == 'broker' else
                         record['node_sha256_before_install'] if name == 'node' else
                         record['launch_origin_binary_sha256_before_install'])
        if record[name + '_sha256_after_install'] != expected_hash:
            raise RuntimeError(name + ' installed bytes changed')
    sock = fixture / 'control/broker.sock'
    stdout, stderr = fixture / 'logs/daemon.stdout.log', fixture / 'logs/daemon.stderr.log'
    for p in [stdout, stderr]:
        assert run('create-' + p.name, ['/usr/bin/sudo', '-n', '/usr/bin/touch', str(p)], record).returncode == 0
        assert run('mode-' + p.name, ['/usr/bin/sudo', '-n', '/bin/chmod', '0600', str(p)], record).returncode == 0
    plist_path = fixture / 'launchd/job.plist'
    plist = {'Label': label, 'ProgramArguments': [str(binary), '--serve', '--qualification-mode',
        '--registry=' + str(fixture / 'registry'), '--socket=' + str(sock),
        '--workspaces=' + str(fixture / 'workspaces'), '--runtime=' + str(node)],
        'RunAtLoad': True, 'KeepAlive': False, 'StandardOutPath': str(stdout), 'StandardErrorPath': str(stderr)}
    staging = OUT / 'launchd-job.plist'
    staging.write_bytes(plistlib.dumps(plist, fmt=plistlib.FMT_XML, sort_keys=True))
    assert run('install-plist', ['/usr/bin/sudo', '-n', '/usr/bin/install', '-o', '0', '-g', '0', '-m', '0444', str(staging), str(plist_path)], record).returncode == 0
    bootstrap = run('bootstrap-own-label', ['/usr/bin/sudo', '-n', '/bin/launchctl', 'bootstrap', 'system', str(plist_path)], record)
    if bootstrap.returncode != 0:
        loaded = run('check-own-label-after-bootstrap-error', ['/usr/bin/sudo', '-n', '/bin/launchctl', 'print', 'system/' + label], record)
        bootstrapped = loaded.returncode == 0
        raise RuntimeError('launchd bootstrap failed; controller harness was not run')
    bootstrapped = True
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline and not sock.exists():
        time.sleep(0.1)
    if not sock.exists():
        raise RuntimeError('launchd service did not create its socket; controller harness was not run')
    startup_print = run('launchctl-print-before-harness', ['/usr/bin/sudo', '-n', '/bin/launchctl', 'print', 'system/' + label], record)
    record['launchd_startup_method_observed'] = startup_print.returncode == 0 and bool(re.search(rb'\bpid\s*=\s*[0-9]+', startup_print.stdout))
    if not record['launchd_startup_method_observed']:
        raise RuntimeError('launchd did not report an active PID for its own label before harness')
    pid_match = re.search(rb'\bpid\s*=\s*([0-9]+)', startup_print.stdout)
    if not pid_match:
        raise RuntimeError('own launchd label did not expose a decimal PID')
    launched_pid = int(pid_match.group(1))
    record['launchd_broker_pid'] = launched_pid
    origin_checks = {}
    daemon_origin = run('origin-own-launchdaemon-pid', ['/usr/bin/sudo', '-n', str(origin_probe), '--pid=' + str(launched_pid)], record)
    try:
        daemon_report = json.loads(daemon_origin.stdout)
        target = daemon_report.get('target', {})
        daemon_ok = (daemon_origin.returncode == 0 and daemon_report.get('creation_parent_is_init') is True and
                     daemon_report.get('proc_pidpath_pid1_is_sbin_launchd') is True and
                     daemon_report.get('parent_unique_matches_pid1') is True and target.get('pid') == launched_pid and
                     daemon_report.get('target_identity_fresh_twice') is True and
                     daemon_report.get('pid1_identity_fresh_twice') is True and target.get('ppid') == 1 and target.get('ruid_is_root') is True and
                     target.get('euid_is_root') is True and target.get('suid_is_root') is True and
                     os.path.realpath(target.get('image', '')) == os.path.realpath(str(binary)))
        origin_checks['launchdaemon_pid'] = {'passed': daemon_ok, 'report': daemon_report,
                                             'exit_code': daemon_origin.returncode}
    except Exception as error:
        origin_checks['launchdaemon_pid'] = {'passed': False, 'parse_error': str(error), 'exit_code': daemon_origin.returncode}
    direct_origin = run('origin-direct-sudo-self', ['/usr/bin/sudo', '-n', str(origin_probe), '--self'], record)
    try:
        direct_report = json.loads(direct_origin.stdout)
        direct_ok = (direct_origin.returncode == 0 and direct_report.get('mode') == 'self' and
                     direct_report.get('creation_parent_is_init') is False and
                     direct_report.get('target_identity_fresh_twice') is True and
                     direct_report.get('target', {}).get('euid_is_root') is True)
        origin_checks['direct_sudo'] = {'passed': direct_ok, 'report': direct_report,
                                        'exit_code': direct_origin.returncode}
    except Exception as error:
        origin_checks['direct_sudo'] = {'passed': False, 'parse_error': str(error), 'exit_code': direct_origin.returncode}
    orphan_origin = run('origin-orphan-canary', ['/usr/bin/sudo', '-n', str(origin_probe), '--orphan-canary'], record, 9)
    orphan_timed_out = record['commands'][-1].get('timed_out', False) or orphan_origin.returncode is None
    try:
        orphan_report = json.loads(orphan_origin.stdout)
        orphan_ok = (not orphan_timed_out and orphan_origin.returncode == 0 and orphan_report.get('mode') == 'orphan-canary' and
                     orphan_report.get('target', {}).get('ppid') == 1 and
                     orphan_report.get('target_identity_fresh_twice') is True and
                     orphan_report.get('parent_unique_matches_pid1') is False and
                     orphan_report.get('creation_parent_is_init') is False)
        origin_checks['orphan_canary'] = {'passed': orphan_ok, 'report': orphan_report,
                                          'exit_code': orphan_origin.returncode,
                                          'timed_out': orphan_timed_out,
                                          'status': 'passed' if orphan_ok else 'exit-ambiguous-fail'}
    except Exception as error:
        origin_checks['orphan_canary'] = {'passed': False, 'parse_error': str(error),
                                          'exit_code': orphan_origin.returncode,
                                          'timed_out': record['commands'][-1].get('timed_out', False),
                                          'status': 'exit-ambiguous-fail'}
    record['launch_origin_canaries'] = origin_checks
    record['launch_origin_canaries_passed'] = all(item.get('passed') is True for item in origin_checks.values())
    harness_started = True
    run_evidence = OUT / 'native-run'
    run_evidence.mkdir(mode=0o700)
    harness = run('ordinary-user-daemon-harness', ['python3', str(args.harness), '--binary=' + str(binary),
        '--socket=' + str(sock), '--node=' + str(node), '--profile-output=' + str(OUT / 'exact-native-profile.sb'),
        '--evidence-dir=' + str(run_evidence)], record, 180)
    try:
        result = json.loads(harness.stdout)
    except (ValueError, TypeError):
        raise RuntimeError('daemon harness returned invalid JSON')
    descriptor = result.get('descriptor')
    (OUT / 'native-proof-response.json').write_text(json.dumps(result.get('native_proof'), sort_keys=True, separators=(',', ':')) + '\n')
    print_result = run('launchctl-print-own-label', ['/usr/bin/sudo', '-n', '/bin/launchctl', 'print', 'system/' + label], record)
    if print_result.returncode != 0:
        raise RuntimeError('could not inspect own launchd label')
    record['launchctl_print_has_pid'] = bool(re.search(rb'\bpid\s*=\s*[0-9]+', print_result.stdout))
    proof = result.get('native_proof')
    if proof:
        encoded = json.dumps(proof, sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode()
        attempt = proof.get('attempt_id')
        digest = hashlib.sha256(encoded).hexdigest()
        if not isinstance(attempt, str) or not re.fullmatch('[a-f0-9]{64}', attempt):
            raise RuntimeError('native proof attempt identifier is invalid')
        receipt = fixture / 'registry' / (attempt + '.' + digest + '.receipt.json')
        readback = run('root-receipt-readback', ['/usr/bin/sudo', '-n', '/bin/cat', str(receipt)], record)
        (OUT / 'root-receipt-readback.json').write_bytes(readback.stdout)
        record['root_receipt_matches_response'] = readback.returncode == 0 and readback.stdout == encoded
        record['native_proof_sha256'] = digest
        if not record['root_receipt_matches_response']:
            raise RuntimeError('root-protected receipt did not match the returned public proof')
    else:
        raise RuntimeError('daemon harness produced no native proof for root receipt readback')
    record['harness_physical_smoke_passed'] = result.get('physical_smoke_passed') is True and harness.returncode == 0
    record['status'] = ('LAUNCHD_STARTUP_OBSERVED_HARNESS_PASS' if record.get('launchd_startup_method_observed') and record['harness_physical_smoke_passed'] and record['launch_origin_canaries_passed']
                       else 'LAUNCHD_ORIGIN_CANARY_FAIL' if record.get('launchd_startup_method_observed') and not record['launch_origin_canaries_passed']
                       else 'LAUNCHD_STARTUP_OBSERVED_HARNESS_FAIL' if record.get('launchd_startup_method_observed')
                       else 'LAUNCHD_PROBE_INCOMPLETE')
except BaseException as error:
    record['status'] = 'LAUNCHD_PROBE_FAIL'
    record['error'] = str(error)
finally:
    if fixture and label and bootstrapped:
        stopped = run('bootout-own-label', ['/usr/bin/sudo', '-n', '/bin/launchctl', 'bootout', 'system/' + label], record, 45)
        record['bootout_exit_code'] = stopped.returncode
        time.sleep(1)
        absent = run('verify-own-label-absent', ['/usr/bin/sudo', '-n', '/bin/launchctl', 'print', 'system/' + label], record)
        bootstrapped = absent.returncode == 0
        record['own_launchd_label_absent'] = not bootstrapped
    if fixture:
        try:
            checked_fixture(fixture)
            if not bootstrapped and not harness_started:
                membership_clear = True
                record['post_stop_private_uid_state'] = 'no ordinary-user harness started'
            if not bootstrapped and descriptor and isinstance(descriptor.get('task_ruid'), int):
                uid = descriptor['task_ruid']
                if 1000000000 <= uid < 1900000000:
                    membership_clear = run('post-stop-uid-scan', [str(args.uid_scan), str(uid)], record).returncode == 0
            record['post_stop_membership_clear'] = membership_clear
            # Never remove the fixture until the exact service is booted out and private UID membership is clear.
            if not bootstrapped and membership_clear:
                outlog = run('collect-own-root-daemon-stdout', ['/usr/bin/sudo', '-n', '/bin/cat', str(fixture / 'logs/daemon.stdout.log')], record)
                errlog = run('collect-own-root-daemon-stderr', ['/usr/bin/sudo', '-n', '/bin/cat', str(fixture / 'logs/daemon.stderr.log')], record)
                if outlog.returncode or errlog.returncode:
                    raise RuntimeError('could not collect own root daemon logs; fixture retained')
                removed = run('remove-own-fixture', ['/usr/bin/sudo', '-n', '/bin/rm', '-rf', '--', str(fixture)], record)
                record['fixture_cleanup_exit'] = removed.returncode
            else:
                record['fixture_cleanup_deferred'] = 'own launchd label stop or private UID-zero scan was not confirmed'
        except BaseException as cleanup_error:
            record['fixture_cleanup_deferred'] = str(cleanup_error)
    record['cleanup_confirmed'] = not fixture or (not bootstrapped and membership_clear and record.get('fixture_cleanup_exit') == 0)
    if record['status'] == 'LAUNCHD_STARTUP_OBSERVED_HARNESS_PASS' and not record['cleanup_confirmed']:
        record['status'] = 'LAUNCHD_STARTUP_OBSERVED_CLEANUP_UNCONFIRMED'
    (OUT / 'LAUNCHD_SMOKE_RESULT.json').write_text(json.dumps(record, indent=2) + '\n')
print(json.dumps(record))
raise SystemExit(0 if record['status'] == 'LAUNCHD_STARTUP_OBSERVED_HARNESS_PASS' and record.get('launch_origin_canaries_passed') and record['cleanup_confirmed'] else 1)
