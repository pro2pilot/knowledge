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
import stat
import subprocess
import tempfile
import time
import uuid

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

def assess_host_postdrop(stdout, exit_code):
    """Validate the fixed probe stages without treating diagnostics as qualification."""
    stages = {}
    try:
        for line in stdout.splitlines():
            if line.strip():
                value = json.loads(line)
                if isinstance(value, dict) and isinstance(value.get('stage'), str):
                    stages[value['stage']] = value
    except (ValueError, TypeError):
        return {'passed': False, 'process_exit_code': exit_code, 'parse_ok': False,
                'backend_certified': False}
    root = stages.get('root_before_scrub', {})
    required_stages = ('private_post_drop', 'private_post_scrub', 'private_post_exec')
    postdrop_ok = all(stages.get(name, {}).get('observation_ok') is True and
                      stages[name].get('host_boot_rc') == 22 and
                      stages[name].get('fresh_host_rc') == 0 and
                      stages[name].get('send_type_rc') == 0 and
                      stages[name].get('send_right') is True and
                      stages[name].get('host_info_rc') == 0 for name in required_stages)
    reaped = stages.get('parent_reaped', {})
    root_positive = (root.get('fresh_host_rc') == 0 and root.get('send_type_rc') == 0 and
                     root.get('send_right') is True and root.get('host_info_rc') == 0 and
                     type(root.get('host_info_count')) is int and root.get('host_info_count') > 0)
    passed = (exit_code == 0 and root_positive and postdrop_ok and
              reaped.get('timeout') is False and reaped.get('probe_ok') is True)
    return {'passed': passed, 'process_exit_code': exit_code, 'parse_ok': True,
            'root_host_basic_positive': root_positive,
            'postdrop_stages_exact_invalid_host': postdrop_ok,
            'parent_reaped_probe_ok': reaped.get('probe_ok') is True,
            'parent_reaped_timeout': reaped.get('timeout'),
            'stages_present': sorted(stages), 'backend_certified': False}

parser = argparse.ArgumentParser()
parser.add_argument('--broker', type=Path, default=HERE / 'evidence' / 'knowledge-native-broker')
parser.add_argument('--node', type=Path, default=Path(shutil.which('node')).resolve() if shutil.which('node') else None)
attempt13_harness = SCRIPT_DIR / 'native' / 'daemon-harness-attempt13.py'
parser.add_argument('--harness', type=Path, default=attempt13_harness if attempt13_harness.is_file() else HERE / 'daemon-harness.py')
parser.add_argument('--uid-scan', type=Path, default=HERE / 'evidence' / 'uid-scan')
parser.add_argument('--source-receipt', type=Path, default=HERE / 'SOURCE_RECEIPT.json')
parser.add_argument('--compile-result', type=Path, default=HERE / 'evidence' / 'COMPILE_RESULT.json')
parser.add_argument('--expected-source-sha', help='Optional frozen-source SHA pin for this CI attempt')
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
host_probe_attempted = False
host_probe_processes_reaped = True
host_uid_scan_clear = True

try:
    if platform.system() != 'Darwin' or os.getuid() == 0:
        raise RuntimeError('requires a non-root macOS controller user')
    if args.node is None:
        raise RuntimeError('node was not found on PATH')
    if OUT.parent.is_symlink() or not OUT.parent.is_dir():
        raise RuntimeError('expected build evidence directory is missing or a symlink')
    source_receipt = json.loads(args.source_receipt.read_bytes())
    compile_result = json.loads(args.compile_result.read_bytes())
    receipt_sha = source_receipt.get('native_sha256')
    if not isinstance(receipt_sha, str) or not re.fullmatch('[a-f0-9]{64}', receipt_sha):
        raise RuntimeError('SOURCE_RECEIPT does not contain a valid native source SHA')
    if args.expected_source_sha and receipt_sha != args.expected_source_sha:
        raise RuntimeError('SOURCE_RECEIPT differs from the explicit frozen-source pin')
    if (compile_result.get('source_sha256') != receipt_sha or compile_result.get('status') != 'PASS' or
            compile_result.get('exit_code') != 0 or compile_result.get('source_unchanged') is not True):
        raise RuntimeError('fresh COMPILE_RESULT does not confirm a successful unchanged pinned source build')
    record['source_receipt_native_sha256'] = receipt_sha
    record['source_pin_origin'] = 'SOURCE_RECEIPT plus fresh COMPILE_RESULT'
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
    host_source = SCRIPT_DIR / 'host-postdrop-probe.c'
    host_binary = OUT / 'host-postdrop-probe'
    record['host_postdrop_source_sha256'] = sha(host_source)
    compiled_host = run('compile-host-postdrop-probe', ['/usr/bin/clang', '-O2', '-Wall', '-Wextra',
        '-Wno-deprecated-declarations', str(host_source), '-o', str(host_binary)], record, 120)
    if compiled_host.returncode != 0:
        raise RuntimeError('ordinary-user host-postdrop-probe compile failed')
    record['host_postdrop_binary_sha256_before_install'] = sha(host_binary)
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
    host_probe = fixture / 'bin/host-postdrop-probe'
    for name, source, target in [('broker', broker_source, binary), ('node', node_source, node),
                                 ('launch-origin-probe', origin_binary, origin_probe),
                                 ('host-postdrop-probe', host_binary, host_probe)]:
        assert run('install-' + name, ['/usr/bin/sudo', '-n', '/usr/bin/install', '-o', '0', '-g', '0', '-m', '0555', str(source), str(target)], record).returncode == 0
        record[name + '_sha256_after_install'] = sha(target)
        expected_hash = (record['broker_sha256_before_install'] if name == 'broker' else
                         record['node_sha256_before_install'] if name == 'node' else
                         record['launch_origin_binary_sha256_before_install'] if name == 'launch-origin-probe' else
                         record['host_postdrop_binary_sha256_before_install'])
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
        pid1 = daemon_report.get('pid1_birth', {})
        daemon_ok = (daemon_origin.returncode == 0 and daemon_report.get('creation_parent_is_init') is True and
                     daemon_report.get('proc_pidpath_pid1_is_sbin_launchd') is True and
                     daemon_report.get('parent_unique_matches_pid1') is True and target.get('pid') == launched_pid and
                     daemon_report.get('target_identity_fresh_twice') is True and
                     daemon_report.get('pid1_identity_fresh_twice') is True and target.get('ppid') == 1 and
                     all(target.get(key) is True for key in ('ruid_is_root', 'euid_is_root', 'suid_is_root')) and
                     all(pid1.get(key) is True for key in ('ruid_is_root', 'euid_is_root', 'suid_is_root')) and
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
    csrutil = run('csrutil-status-readonly', ['/usr/bin/csrutil', 'status'], record, 15)
    record['csrutil_status_readonly'] = {'exit_code': csrutil.returncode,
                                         'stdout_sha256': hashlib.sha256(csrutil.stdout).hexdigest(),
                                         'stderr_sha256': hashlib.sha256(csrutil.stderr).hexdigest(),
                                         'stdout': csrutil.stdout.decode('utf-8', errors='replace')[:4096],
                                         'stderr': csrutil.stderr.decode('utf-8', errors='replace')[:4096]}
    host_workspace = fixture / 'workspaces/host-postdrop'
    assert run('create-host-postdrop-workspace', ['/usr/bin/sudo', '-n', '/bin/mkdir', str(host_workspace)], record).returncode == 0
    assert run('protect-host-postdrop-workspace', ['/usr/bin/sudo', '-n', '/usr/sbin/chown', '0:0', str(host_workspace)], record).returncode == 0
    assert run('mode-host-postdrop-workspace', ['/usr/bin/sudo', '-n', '/bin/chmod', '0711', str(host_workspace)], record).returncode == 0
    host_probe_attempted = True
    host_probe_processes_reaped = False
    host_plain = run('host-postdrop-without-profile', ['/usr/bin/sudo', '-n', str(host_probe), '1800000124'], record, 10)
    record['host_postdrop_without_profile'] = {'exit_code': host_plain.returncode,
        'stdout': host_plain.stdout.decode('utf-8', errors='replace')[:8192],
        'stderr_sha256': hashlib.sha256(host_plain.stderr).hexdigest()}
    generated_profile = run('generate-exact-host-postdrop-profile', [str(binary), '--print-profile',
        '--workspace=' + str(host_workspace), '--runtime=' + str(host_probe)], record, 20)
    profile_path = OUT / 'host-postdrop-profile.source.sb'
    if generated_profile.returncode != 0 or not generated_profile.stdout:
        raise RuntimeError('native broker did not produce the exact host-postdrop profile')
    profile_path.write_bytes(generated_profile.stdout)
    record['host_postdrop_profile_sha256_before_install'] = hashlib.sha256(generated_profile.stdout).hexdigest()
    installed_profile = fixture / 'bin/host-postdrop-profile.sb'
    assert run('install-exact-host-postdrop-profile', ['/usr/bin/sudo', '-n', '/usr/bin/install',
        '-o', '0', '-g', '0', '-m', '0444', str(profile_path), str(installed_profile)], record).returncode == 0
    record['host_postdrop_profile_sha256_after_install'] = sha(installed_profile)
    if record['host_postdrop_profile_sha256_after_install'] != record['host_postdrop_profile_sha256_before_install']:
        raise RuntimeError('installed root-protected host-postdrop profile bytes changed')
    host_profiled = run('host-postdrop-with-exact-profile', ['/usr/bin/sudo', '-n', str(host_probe),
        '1800000124', str(installed_profile)], record, 10)
    record['host_postdrop_with_profile'] = {'exit_code': host_profiled.returncode,
        'stdout': host_profiled.stdout.decode('utf-8', errors='replace')[:8192],
        'stderr_sha256': hashlib.sha256(host_profiled.stderr).hexdigest(),
        'profile_sha256': record['host_postdrop_profile_sha256_after_install'],
        'backend_certified': False}
    host_checks = {
        'without_profile': assess_host_postdrop(host_plain.stdout.decode('utf-8', errors='replace'), host_plain.returncode),
        'with_profile': assess_host_postdrop(host_profiled.stdout.decode('utf-8', errors='replace'), host_profiled.returncode),
    }
    record['host_postdrop_checks'] = host_checks
    host_probe_processes_reaped = all(
        item.get('process_exit_code') == 0 and item.get('parent_reaped_probe_ok') is True and
        item.get('parent_reaped_timeout') is False for item in host_checks.values())
    record['host_probe_processes_reaped'] = host_probe_processes_reaped
    record['host_postdrop_checks_passed'] = all(item.get('passed') is True for item in host_checks.values())
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
    record['timing_contract_probe'] = result.get('timing_contract_probe', {'status': 'NOT_REPORTED'})
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
    record['status'] = ('LAUNCHD_STARTUP_OBSERVED_HARNESS_PASS' if record.get('launchd_startup_method_observed') and record['harness_physical_smoke_passed'] and record['launch_origin_canaries_passed'] and record.get('host_postdrop_checks_passed') is True
                       else 'LAUNCHD_ORIGIN_CANARY_FAIL' if record.get('launchd_startup_method_observed') and not record['launch_origin_canaries_passed']
                       else 'LAUNCHD_HOST_POSTDROP_FAIL' if record.get('launchd_startup_method_observed') and record.get('host_postdrop_checks_passed') is not True
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
    if fixture and host_probe_attempted:
        host_scan = run('post-host-probe-uid-scan', [str(args.uid_scan), '1800000124'], record)
        host_uid_scan_clear = host_scan.returncode == 0
        record['host_probe_uid_zero_confirmed'] = host_uid_scan_clear
        record['host_probe_processes_reaped'] = host_probe_processes_reaped
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
            if not bootstrapped and membership_clear and descriptor and isinstance(descriptor.get('workspace_path'), str):
                workspace = Path(descriptor['workspace_path'])
                expected_root = (fixture / 'workspaces').resolve(strict=True)
                try:
                    if (workspace.is_symlink() or workspace.parent.resolve(strict=True) != expected_root or
                            workspace.name in ('', '.', '..')):
                        raise RuntimeError('private workspace path is outside the owned fixture')
                    private_output = workspace / 'private-output.txt'
                    fd = os.open(str(private_output), os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
                    try:
                        st = os.fstat(fd)
                        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_size > 65536:
                            raise RuntimeError('private output type or size is unexpected')
                        data = os.read(fd, 65537)
                    finally:
                        os.close(fd)
                    record['original_owner_private_output_readback'] = {
                        'readable': len(data) <= 65536,
                        'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest(),
                        'semantics_only': True}
                except (OSError, RuntimeError) as read_error:
                    record['original_owner_private_output_readback'] = {
                        'readable': False, 'error_type': type(read_error).__name__, 'semantics_only': True}
            # Never remove the fixture until the exact service is booted out and private UID membership is clear.
            if not bootstrapped and membership_clear and host_probe_processes_reaped and host_uid_scan_clear:
                outlog = run('collect-own-root-daemon-stdout', ['/usr/bin/sudo', '-n', '/bin/cat', str(fixture / 'logs/daemon.stdout.log')], record)
                errlog = run('collect-own-root-daemon-stderr', ['/usr/bin/sudo', '-n', '/bin/cat', str(fixture / 'logs/daemon.stderr.log')], record)
                if outlog.returncode or errlog.returncode:
                    raise RuntimeError('could not collect own root daemon logs; fixture retained')
                removed = run('remove-own-fixture', ['/usr/bin/sudo', '-n', '/bin/rm', '-rf', '--', str(fixture)], record)
                record['fixture_cleanup_exit'] = removed.returncode
            else:
                record['fixture_cleanup_deferred'] = 'launchd stop, private UID scan, host-probe reaping, or host UID-zero scan was not confirmed'
        except BaseException as cleanup_error:
            record['fixture_cleanup_deferred'] = str(cleanup_error)
    record['cleanup_confirmed'] = not fixture or (not bootstrapped and membership_clear and
        host_probe_processes_reaped and host_uid_scan_clear and record.get('fixture_cleanup_exit') == 0)
    if record['status'] == 'LAUNCHD_STARTUP_OBSERVED_HARNESS_PASS' and not record['cleanup_confirmed']:
        record['status'] = 'LAUNCHD_STARTUP_OBSERVED_CLEANUP_UNCONFIRMED'
    (OUT / 'LAUNCHD_SMOKE_RESULT.json').write_text(json.dumps(record, indent=2) + '\n')
print(json.dumps(record))
raise SystemExit(0 if record['status'] == 'LAUNCHD_STARTUP_OBSERVED_HARNESS_PASS' and
                 record.get('launch_origin_canaries_passed') and record.get('host_postdrop_checks_passed') and
                 record.get('host_probe_processes_reaped') and record.get('host_probe_uid_zero_confirmed') and
                 record['cleanup_confirmed'] else 1)
