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

def run(name, argv, record, timeout=30, data=None, native_root=False):
    start = time.monotonic()
    try:
        p = subprocess.run(argv, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           timeout=timeout, shell=False)
        timed_out = False
    except subprocess.TimeoutExpired as error:
        if native_root:
            record['root_native_exits_confirmed'] = False
        stdout = error.stdout or b''
        stderr = error.stderr or b''
        if isinstance(stdout, str): stdout = stdout.encode()
        if isinstance(stderr, str): stderr = stderr.encode()
        p = subprocess.CompletedProcess(argv, None, stdout, stderr)
        timed_out = True
    if native_root and b'stub describe cleanup_unconfirmed:' in p.stderr:
        record['root_native_exits_confirmed'] = False
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

def label_absent(result, label):
    # A timeout or arbitrary launchctl error is not evidence of absence.
    expected = 'Could not find service "' + label + '" in domain for system'
    lines = result.stderr.decode('utf-8', errors='replace').splitlines()
    return result.returncode == 113 and lines == ['Bad request.', expected]

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
            'parent_reaping_observed': exit_code in (0,1) and type(reaped.get('wait_status')) is int and type(reaped.get('timeout')) is bool,
            'parent_reaped_timeout': reaped.get('timeout'),
            'stages_present': sorted(stages), 'backend_certified': False}

def check_init_cli(binary, node, fixture, policy_id, record):
    """Exercise parser/preflight refusals before the own fixture is initialized."""
    roots = {'registry': str(fixture / 'registry'), 'allocator': str(fixture / 'allocator'),
             'anchors': str(fixture / 'anchors'), 'workspaces': str(fixture / 'workspaces'),
             'socket': str(fixture / 'control/broker.sock')}
    canonical = {key: '/Library/PrivilegedHelperTools/KnowledgeVerification-' + suffix for key, suffix in
                 [('registry', 'state'), ('allocator', 'allocator'), ('anchors', 'anchors'),
                  ('workspaces', 'workspaces'), ('socket', 'control/broker.sock')]}
    options = lambda values: ['--' + key + '=' + value for key, value in values.items()]
    owner = '--allow-owner=' + str(os.getuid())
    init = ['--init-install', '--qualification-mode', '--runtime=' + str(node),
            '--confirm-reserved-uid-range=1000000000:1900000000', '--account-policy=' + policy_id, owner]
    serve = ['--serve', '--qualification-mode', '--runtime=' + str(node)]
    cases = []
    for mode, base in [('init', init), ('serve', serve)]:
        cases += [('qualification_defaults_' + mode, base),
                  ('qualification_all_canonical_' + mode, base + options(canonical)),
                  ('qualification_missing_socket_' + mode,
                   base + options({key: value for key, value in roots.items() if key != 'socket'})),
                  ('qualification_mixed_' + mode, base + options({**roots, 'anchors': canonical['anchors']})),
                  ('qualification_nested_production_' + mode,
                   base + options({**roots, 'registry': canonical['registry'] + '/diagnostic-state'})),
                  ('custom_without_qualification_' + mode,
                   [value for value in base if value != '--qualification-mode'] + options(roots))]
    for name, replacement in [('root_owner', '--allow-owner=0'), ('noncanonical_owner', '--allow-owner=0501'),
                               ('reserved_owner', '--allow-owner=1000000000')]:
        cases.append((name, [replacement if value == owner else value for value in init] + options(roots)))
    cases += [('duplicate_owner', init + [owner] + options(roots)),
              ('missing_owner', [value for value in init if value != owner] + options(roots)),
              ('missing_policy', [value for value in init if not value.startswith('--account-policy=')] + options(roots)),
              ('unknown_policy', ['--account-policy=unknown.v1' if value.startswith('--account-policy=') else value
                                  for value in init] + options(roots)),
              ('owner_cap_exceeded', [value for value in init if value != owner] +
               ['--allow-owner=' + str(uid) for uid in range(1, 66)] + options(roots))]
    observations = []
    for name, argv in cases:
        result = run('cli-' + name, ['/usr/bin/sudo', '-n', str(binary), *argv], record, 60, native_root=True)
        observations.append({'name': name, 'exit_code': result.returncode, 'stdout_empty': result.stdout == b''})
        if result.returncode != 64 or result.stdout:
            raise RuntimeError('native CLI did not reject the exact unsafe/invalid configuration: ' + name)
    unknown = ['--allow-owner=999999999' if value == owner else value for value in init] + options(roots)
    result = run('cli-unknown-owner-before-history', ['/usr/bin/sudo', '-n', str(binary), *unknown],
                 record, 60, native_root=True)
    if result.returncode != 78 or result.stdout:
        raise RuntimeError('native init did not refuse the synthetic unavailable owner')
    observations.append({'name': 'unknown_owner_before_history', 'exit_code': result.returncode, 'stdout_empty': True})
    for name in ('registry', 'allocator', 'anchors', 'workspaces', 'control'):
        result = run('cli-own-empty-' + name, ['/usr/bin/sudo', '-n', '/bin/ls', '-A', str(fixture / name)], record)
        if result.returncode or result.stdout:
            raise RuntimeError('refused CLI configurations created state in the own uninitialized fixture')
    return {'cases': observations, 'own_state_directories_unchanged_empty': True,
            'scope': 'CLI refusals and own fixture only; no assertion of global filesystem tracing'}

parser = argparse.ArgumentParser()
parser.add_argument('--broker', type=Path, default=HERE / 'evidence' / 'knowledge-native-broker')
parser.add_argument('--stub', type=Path, default=HERE / 'evidence' / 'knowledge-native-stub')
parser.add_argument('--node', type=Path, default=Path(shutil.which('node')).resolve() if shutil.which('node') else None)
attempt13_harness = SCRIPT_DIR / 'native' / 'daemon-harness-attempt13.py'
parser.add_argument('--harness', type=Path, default=attempt13_harness if attempt13_harness.is_file() else HERE / 'daemon-harness.py')
parser.add_argument('--uid-scan', type=Path, default=HERE / 'evidence' / 'uid-scan')
parser.add_argument('--source-receipt', type=Path, default=HERE / 'SOURCE_RECEIPT.json')
parser.add_argument('--compile-result', type=Path, default=HERE / 'evidence' / 'COMPILE_RESULT.json')
parser.add_argument('--host-probe-only', action='store_true')
parser.add_argument('--expected-source-sha', help='Optional frozen-source SHA pin for this CI attempt')
parser.add_argument('--m2-scenario', choices=('normal', 'interrupt_drain'),
                    help='Use the two-phase harness and an owned native admission-lock probe')
parser.add_argument('--uid-registry-fault', choices=('unlink', 'corrupt'),
                    help='Run only the owned active-reservation entry-store fault check')
parser.add_argument('--active-state-fault', choices=('policy-unlink', 'registry-unlink'),
                    help='Run the active monitor regression for one exact owned-state unlink')
parser.add_argument('--check-init-cli', action='store_true')
args = parser.parse_args()
controller_modes = sum(bool(value) for value in
    (args.m2_scenario, args.uid_registry_fault, args.active_state_fault, args.host_probe_only))
if controller_modes > 1:
    parser.error('M2, UID-registry-fault, active-state-fault, and host-probe controllers are exclusive')
if args.check_init_cli and (args.m2_scenario != 'normal' or args.uid_registry_fault or
                            args.active_state_fault or args.host_probe_only):
    parser.error('--check-init-cli requires the normal M2 scenario')
EVIDENCE_ROOT = HERE / 'evidence'
if EVIDENCE_ROOT.is_symlink() or not EVIDENCE_ROOT.is_dir():
    raise SystemExit('expected build evidence directory is missing or a symlink')
OUT = EVIDENCE_ROOT / ('launchd-smoke-' + uuid.uuid4().hex[:12])
OUT.mkdir(mode=0o700)
record = {'scope': 'launchd startup-method physical probe only', 'backend_certified': False,
          'trusted_os_origin_verified': False, 'commands': [], 'capability_semantics': False,
          'platform': platform.platform(), 'architecture': platform.machine()}
record['root_native_exits_confirmed'] = True
active_state_run_helper_exit_confirmed = True
ordinary_helper_image_membership_clear = False
helper_image_binary = None
fixture = None
bootstrapped = False
registration_attempted = False
root_logs_created = False
label = None
descriptor = None
membership_clear = False
harness_started = False
host_probe_attempted = False
host_probe_processes_reaped = True
host_uid_scan_clear = True
groups_probe_attempted = False
groups_probe_reaped = True
groups_uid_scan_clear = True

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
    receipt_stub_sha = source_receipt.get('stub_sha256')
    if not isinstance(receipt_sha, str) or not re.fullmatch('[a-f0-9]{64}', receipt_sha):
        raise RuntimeError('SOURCE_RECEIPT does not contain a valid native source SHA')
    if args.expected_source_sha and receipt_sha != args.expected_source_sha:
        raise RuntimeError('SOURCE_RECEIPT differs from the explicit frozen-source pin')
    if not isinstance(receipt_stub_sha, str) or not re.fullmatch('[a-f0-9]{64}', receipt_stub_sha):
        raise RuntimeError('SOURCE_RECEIPT lacks the frozen C stub source pin')
    if (compile_result.get('source_sha256') != receipt_sha or compile_result.get('status') != 'PASS' or
            compile_result.get('exit_code') != 0 or compile_result.get('source_unchanged') is not True):
        raise RuntimeError('fresh COMPILE_RESULT does not confirm a successful unchanged pinned source build')
    if compile_result.get('stub_source_sha256') != receipt_stub_sha or compile_result.get('stub_exit_code') != 0:
        raise RuntimeError('fresh COMPILE_RESULT does not confirm the paired C stub')
    record['source_receipt_native_sha256'] = receipt_sha
    record['source_pin_origin'] = 'SOURCE_RECEIPT plus fresh COMPILE_RESULT'
    record['compile_result_source_sha256'] = compile_result['source_sha256']
    record['compile_result_status'] = compile_result['status']
    record['compile_result_source_unchanged'] = compile_result['source_unchanged']
    history_files = source_receipt.get('uid_history_files', {})
    account_policy = source_receipt.get('account_policy_id')
    if (account_policy != compile_result.get('account_policy_id') or
            account_policy not in (None, 'admin_reserved_interval_no_runtime_nss.v1')):
        raise RuntimeError('account-policy compile/source metadata differs or is unsupported')
    if (history_files != compile_result.get('uid_history_files', {}) or
            ((args.uid_registry_fault or args.active_state_fault) and len(history_files) != 2)):
        raise RuntimeError('UID-history compile/source metadata differs or fault test lacks the component')
    if args.uid_registry_fault and args.m2_scenario:
        raise RuntimeError('fault test and normal two-phase scenarios are distinct controller runs')
    broker_source, stub_source, node_source = args.broker.resolve(strict=True), args.stub.resolve(strict=True), args.node.resolve(strict=True)
    if args.broker.is_symlink() or args.stub.is_symlink() or args.node.is_symlink() or not broker_source.is_file() or not stub_source.is_file() or not node_source.is_file():
        raise RuntimeError('broker or resolved Node artifact is not an ordinary file')
    if (sha(broker_source) != compile_result.get('broker_binary_sha256') or
            sha(stub_source) != compile_result.get('stub_binary_sha256') or
            compile_result.get('stub_pair_description') != {
                'schema': 'knowledge-darwin-stub.v1',
                'broker_binary_sha256': sha(broker_source),
                'broker_source_sha256': receipt_sha, 'stub_source_sha256': receipt_stub_sha,
                'capability_qualified': False}):
        raise RuntimeError('supplied native executable bytes do not match the fresh compile pair')
    record['actual_binary_pair_matches_compile'] = True
    dependencies = run('node-runtime-dependencies', ['/usr/bin/otool', '-L', str(node_source)], record, 20)
    lines = dependencies.stdout.decode('utf-8', errors='strict').splitlines()[1:]
    libraries = [line.strip().split(' (', 1)[0] for line in lines if line.strip()]
    record['node_runtime_libraries'] = libraries
    if dependencies.returncode or not libraries or len(libraries) > 64 or not all(
            item.startswith('/usr/lib/') or item.startswith('/System/Library/') for item in libraries):
        raise RuntimeError('test runtime must be a complete standalone Node binary with only OS library dependencies')
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
    groups_source = SCRIPT_DIR / 'kernel-groups-regression.c'
    groups_binary = OUT / 'kernel-groups-regression'
    record['kernel_groups_regression_source_sha256'] = sha(groups_source)
    groups_compile = run('compile-kernel-groups-regression', ['/usr/bin/clang', '-std=c11', '-D_DARWIN_C_SOURCE',
        '-O2', '-Wall', '-Wextra', '-Wno-deprecated-declarations', str(groups_source), '-o', str(groups_binary)], record, 120)
    if groups_compile.returncode:
        raise RuntimeError('kernel groups regression did not compile')
    record['kernel_groups_regression_binary_sha256'] = sha(groups_binary)
    if args.active_state_fault:
        helper_image_source = SCRIPT_DIR / 'helper-image-scan.c'
        helper_image_binary = OUT / 'helper-image-scan'
        record['helper_image_scan_source_sha256'] = sha(helper_image_source)
        compiled_image_scan = run('compile-helper-image-scan', ['/usr/bin/clang', '-std=c11',
            '-D_DARWIN_C_SOURCE', '-O2', '-Wall', '-Wextra', '-Werror', str(helper_image_source),
            '-o', str(helper_image_binary)], record, 120)
        if compiled_image_scan.returncode:
            raise RuntimeError('read-only ordinary helper image observer did not compile')
        record['helper_image_scan_binary_sha256'] = sha(helper_image_binary)
    admission_binary = None
    if args.m2_scenario:
        admission_source = SCRIPT_DIR / 'admission-flock-probe.c'
        admission_binary = OUT / 'admission-flock-probe'
        record['admission_probe_source_sha256'] = sha(admission_source)
        compiled_admission = run('compile-admission-probe', ['/usr/bin/clang', '-std=c11',
            '-O2', '-Wall', '-Wextra', '-Werror', str(admission_source), '-o', str(admission_binary)], record, 120)
        if compiled_admission.returncode:
            raise RuntimeError('owned admission-lock probe did not compile')
        record['admission_probe_binary_sha256'] = sha(admission_binary)
    record['broker_sha256_before_install'] = sha(broker_source)
    record['stub_sha256_before_install'] = sha(stub_source)
    record['stub_source_sha256'] = receipt_stub_sha
    record['node_sha256_before_install'] = sha(node_source)
    record['broker_input_path'] = str(broker_source)
    record['node_input_path'] = str(node_source)
    fixture = Path(tempfile.mkdtemp(prefix='knowledge-launchd-smoke.', dir='/private/tmp'))
    checked_fixture(fixture)
    suffix = fixture.name.rsplit('.', 1)[1].replace('_', '')
    label = 'org.knowledgekit.rc5.launchd-smoke.' + suffix
    fixture_dirs = ['bin', 'runtime', 'control', 'registry', 'workspaces', 'logs', 'launchd']
    if history_files:
        fixture_dirs += ['allocator', 'anchors']
    for name in fixture_dirs:
        p = fixture / name
        p.mkdir()
        mode = '0700' if name in ('registry', 'logs', 'launchd', 'allocator') else '0755' if name == 'anchors' else '0711'
        assert run('protect-dir-' + name, ['/usr/bin/sudo', '-n', '/usr/sbin/chown', '0:0', str(p)], record).returncode == 0
        assert run('mode-dir-' + name, ['/usr/bin/sudo', '-n', '/bin/chmod', mode, str(p)], record).returncode == 0
    assert run('protect-fixture', ['/usr/bin/sudo', '-n', '/usr/sbin/chown', '0:0', str(fixture)], record).returncode == 0
    assert run('mode-fixture', ['/usr/bin/sudo', '-n', '/bin/chmod', '0711', str(fixture)], record).returncode == 0
    binary, node, origin_probe = fixture / 'bin/broker', fixture / 'runtime/node', fixture / 'bin/launch-origin-probe'
    stub = fixture / 'bin/knowledge-native-stub'
    host_probe = fixture / 'bin/host-postdrop-probe'
    groups_probe = fixture / 'bin/kernel-groups-regression'
    for name, source, target in [('broker', broker_source, binary), ('stub', stub_source, stub), ('node', node_source, node),
                                 ('launch-origin-probe', origin_binary, origin_probe),
                                 ('kernel-groups-regression', groups_binary, groups_probe),
                                 ('host-postdrop-probe', host_binary, host_probe)]:
        assert run('install-' + name, ['/usr/bin/sudo', '-n', '/usr/bin/install', '-o', '0', '-g', '0', '-m', '0555', str(source), str(target)], record).returncode == 0
        record[name + '_sha256_after_install'] = sha(target)
        expected_hash = (record['broker_sha256_before_install'] if name == 'broker' else
                         record['stub_sha256_before_install'] if name == 'stub' else
                         record['node_sha256_before_install'] if name == 'node' else
                         record['launch_origin_binary_sha256_before_install'] if name == 'launch-origin-probe' else
                         record['kernel_groups_regression_binary_sha256'] if name == 'kernel-groups-regression' else
                         record['host_postdrop_binary_sha256_before_install'])
        if record[name + '_sha256_after_install'] != expected_hash:
            raise RuntimeError(name + ' installed bytes changed')
    admission_probe = None
    if admission_binary:
        admission_probe = fixture / 'bin/admission-flock-probe'
        assert run('install-admission-probe', ['/usr/bin/sudo', '-n', '/usr/bin/install', '-o', '0',
            '-g', '0', '-m', '0555', str(admission_binary), str(admission_probe)], record).returncode == 0
        record['admission_probe_installed_sha256'] = sha(admission_probe)
        if record['admission_probe_installed_sha256'] != record['admission_probe_binary_sha256']:
            raise RuntimeError('owned admission-lock probe bytes changed at install')
    pre_groups = run('pre-kernel-groups-uid-scan', [str(args.uid_scan), '1800000125'], record)
    if pre_groups.returncode:
        raise RuntimeError('kernel groups regression UID is not observed unused')
    groups_probe_attempted = True
    groups_probe_reaped = False
    groups_run = run('kernel-groups-regression', ['/usr/bin/sudo', '-n', str(groups_probe), '1800000125'], record, 20)
    groups_result = json.loads(groups_run.stdout)
    record['kernel_groups_regression'] = groups_result
    groups_probe_reaped = groups_result.get('cleanup_confirmed') is True
    if groups_run.returncode or groups_result.get('status') != 'PASS' or not groups_probe_reaped:
        raise RuntimeError('kernel group positive/extra-group negative regression failed')
    sock = fixture / 'control/broker.sock'
    stdout, stderr = fixture / 'logs/daemon.stdout.log', fixture / 'logs/daemon.stderr.log'
    for p in [stdout, stderr]:
        assert run('create-' + p.name, ['/usr/bin/sudo', '-n', '/usr/bin/touch', str(p)], record).returncode == 0
        assert run('mode-' + p.name, ['/usr/bin/sudo', '-n', '/bin/chmod', '0600', str(p)], record).returncode == 0
    root_logs_created = True
    plist_path = fixture / 'launchd/job.plist'
    plist = {'Label': label, 'ProgramArguments': [str(binary), '--serve', '--qualification-mode',
        '--registry=' + str(fixture / 'registry'), '--socket=' + str(sock),
        '--workspaces=' + str(fixture / 'workspaces'), '--runtime=' + str(node)],
        'RunAtLoad': True, 'KeepAlive': False, 'StandardOutPath': str(stdout), 'StandardErrorPath': str(stderr)}
    if history_files:
        history_options = ['--allocator=' + str(fixture / 'allocator'), '--anchors=' + str(fixture / 'anchors')]
        plist['ProgramArguments'] += history_options
        init_argv = [str(binary), '--init-install', '--qualification-mode',
            '--confirm-reserved-uid-range=1000000000:1900000000',
            '--registry=' + str(fixture / 'registry'), '--socket=' + str(sock),
            '--workspaces=' + str(fixture / 'workspaces'), '--runtime=' + str(node), *history_options]
        if account_policy:
            init_argv += ['--account-policy=' + account_policy, '--allow-owner=' + str(os.getuid())]
        if args.check_init_cli:
            if not account_policy:
                raise RuntimeError('CLI policy matrix requires the current explicit account policy')
            record['init_cli_matrix'] = check_init_cli(binary, node, fixture, account_policy, record)
        initialized = run('explicit-native-init', ['/usr/bin/sudo', '-n', *init_argv], record, 60, native_root=True)
        if initialized.returncode or json.loads(initialized.stdout).get('ok') is not True:
            raise RuntimeError('explicit own-fixture native initialization failed')
        init_files = [fixture / name for name in ('anchors/install.json', 'anchors/uid-head.json',
                                                  'allocator/consumed.journal', 'registry/registry.json')]
        if account_policy:
            init_files.append(fixture / 'anchors/account-policy.json')
        init_before = {}
        for i, path in enumerate(init_files):
            observed = run('init-before-' + str(i), ['/usr/bin/sudo', '-n', '/bin/cat', str(path)], record)
            if observed.returncode:
                raise RuntimeError('initialized own state could not be read back')
            init_before[str(path.relative_to(fixture))] = hashlib.sha256(observed.stdout).hexdigest()
        reinitialized = run('refuse-native-reinit', ['/usr/bin/sudo', '-n', *init_argv], record, 60, native_root=True)
        if (reinitialized.returncode != 78 or reinitialized.stdout or
                (not account_policy and not reinitialized.stderr.startswith(b'explicit init failed:'))):
            raise RuntimeError('existing own-fixture UID history did not produce the expected native refusal')
        init_after = {}
        for i, path in enumerate(init_files):
            observed = run('init-after-' + str(i), ['/usr/bin/sudo', '-n', '/bin/cat', str(path)], record)
            if observed.returncode:
                raise RuntimeError('native reinit refusal did not preserve its state')
            init_after[str(path.relative_to(fixture))] = hashlib.sha256(observed.stdout).hexdigest()
        if init_before != init_after:
            raise RuntimeError('native reinit refusal modified existing own-fixture state bytes')
        record['explicit_uid_history_init'] = True
        record['existing_uid_history_reinit_refused'] = True
        record['uid_history_init_files_unchanged_on_reinit'] = init_after
    staging = OUT / 'launchd-job.plist'
    staging.write_bytes(plistlib.dumps(plist, fmt=plistlib.FMT_XML, sort_keys=True))
    assert run('install-plist', ['/usr/bin/sudo', '-n', '/usr/bin/install', '-o', '0', '-g', '0', '-m', '0444', str(staging), str(plist_path)], record).returncode == 0
    registration_attempted = True
    bootstrapped = True  # unknown until a checked absence, including timeout
    bootstrap = run('bootstrap-own-label', ['/usr/bin/sudo', '-n', '/bin/launchctl', 'bootstrap', 'system', str(plist_path)], record)
    if bootstrap.returncode != 0:
        loaded = run('check-own-label-after-bootstrap-error', ['/usr/bin/sudo', '-n', '/bin/launchctl', 'print', 'system/' + label], record)
        bootstrapped = not label_absent(loaded, label)
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
    public_probe = run('public-native-probe', [str(binary), '--request', '--socket=' + str(sock)],
        record, 20, data=b'{"op":"probe"}')
    probe = json.loads(public_probe.stdout)
    if (public_probe.returncode or probe.get('ok') is not True or
            probe.get('source_sha256') != receipt_sha or
            probe.get('binary_sha256') != record['broker_sha256_before_install'] or
            probe.get('stub_source_sha256') != receipt_stub_sha or
            probe.get('stub_binary_sha256') != record['stub_sha256_before_install'] or
            probe.get('capability_qualified') is not False):
        raise RuntimeError('actual public native probe differs from the compiled diagnostic pair')
    record['public_native_probe_bound_to_compile'] = True
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
        item.get('parent_reaping_observed') is True for item in host_checks.values())
    record['host_probe_processes_reaped'] = host_probe_processes_reaped
    record['host_postdrop_checks_passed'] = all(item.get('passed') is True for item in host_checks.values())
    if args.host_probe_only:
        record['host_probe_only'] = True
        record['status'] = 'HOST_PROBE_ONLY_PASS' if record['host_postdrop_checks_passed'] else 'HOST_PROBE_ONLY_FAIL'
    else:
        harness_started = True
        if args.active_state_fault:
            active_state_run_helper_exit_confirmed = False
        run_evidence = OUT / 'native-run'
        run_evidence.mkdir(mode=0o700)
        selected_harness = (SCRIPT_DIR / 'active-state-fault-harness.py'
                            if args.active_state_fault else args.harness)
        harness_argv = ['python3', str(selected_harness), '--binary=' + str(binary),
            '--socket=' + str(sock), '--node=' + str(node), '--profile-output=' + str(OUT / 'exact-native-profile.sb'),
            '--evidence-dir=' + str(run_evidence)]
        if args.m2_scenario:
            harness_argv += ['--scenario=' + args.m2_scenario, '--admission-probe=' + str(admission_probe)]
            record['m2_scenario'] = args.m2_scenario
        if args.uid_registry_fault:
            harness_argv += ['--fault=' + args.uid_registry_fault]
            record['uid_registry_fault'] = args.uid_registry_fault
        if args.active_state_fault:
            harness_argv += ['--fault=' + args.active_state_fault]
            record['active_state_fault'] = args.active_state_fault
        record['harness_source_sha256'] = sha(selected_harness)
        harness = run('ordinary-user-daemon-harness', harness_argv, record, 180)
        try:
            result = json.loads(harness.stdout)
        except (ValueError, TypeError):
            raise RuntimeError('daemon harness returned invalid JSON')
        if args.active_state_fault:
            # A missing PID can mean registration failed after Popen, not that
            # no child existed. This controller never reaps that grandchild.
            active_state_run_helper_exit_confirmed = False
            record['active_state_run_helper_exit_confirmed'] = active_state_run_helper_exit_confirmed
            record['active_state_run_helper_lifecycle_status'] = result.get(
                'native_run_helper_lifecycle_status', 'not_started_or_not_reported')
        descriptor = result.get('descriptor')
        if (not isinstance(descriptor, dict) or result.get('source_sha256') != receipt_sha or
                descriptor.get('source_sha256') != receipt_sha or
                descriptor.get('broker_binary_sha256') != record['broker_sha256_before_install'] or
                descriptor.get('stub_source_sha256') != receipt_stub_sha or
                descriptor.get('stub_binary_sha256') != record['stub_sha256_before_install'] or
                descriptor.get('stub_wire_version') != 'KVS1'):
            raise RuntimeError('actual native harness descriptor differs from the fresh source/binary pair')
        if history_files and (
                descriptor.get('uid_history_header_sha256') != history_files.get('verification-darwin-uid-history.h') or
                descriptor.get('uid_history_source_sha256') != history_files.get('verification-darwin-uid-history.m')):
            raise RuntimeError('actual native descriptor UID sources differ from the fresh compile pair')
        if account_policy and (descriptor.get('account_policy_id') != account_policy or
                descriptor.get('account_policy_sha256') != probe.get('account_policy', {}).get('sha256')):
            raise RuntimeError('actual descriptor account policy differs from the installed public probe')
        record['harness_actual_pair_matches_compile'] = True
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
            if args.uid_registry_fault:
                if (proof.get('state') != 'cleanup_unconfirmed' or
                        proof.get('native_cleanup_facts_confirmed') is not False or
                        proof.get('cleanup_confirmed') is not False or
                        result.get('proof_current_persistence_confirmed') is not False):
                    raise RuntimeError('entry-store fault was not explicitly an unconfirmed current result')
                record['current_proof_persistence_confirmed'] = False
                record['receipt_scope'] = 'diagnostic readback only; current registry commit intentionally unconfirmed'
            elif args.active_state_fault:
                if (proof.get('state') != 'cleanup_unconfirmed' or
                        proof.get('native_cleanup_facts_confirmed') is not False or
                        proof.get('cleanup_confirmed') is not False or
                        proof.get('capability_qualified') is not False or
                        result.get('authority_wait', {}).get('exit_code') != -9 or
                        result.get('post_wait_status', {}).get('stop_reason') !=
                            ('account_policy_unconfirmed' if args.active_state_fault == 'policy-unlink'
                             else 'registry_durability_unconfirmed') or
                        result.get('physical_smoke_passed') is not True or
                        result.get('post_wait_status', {}).get('admission_closed') is not True or
                        result.get('post_wait_status', {}).get('state') != 'cleanup_unconfirmed' or
                        result.get('immutable_primary_observation', {}).get('authority_exit_expected_sigkill') is not True or
                        result.get('aftermath_observation', {}).get('oracle_passed') is not True):
                    raise RuntimeError('active-state fault did not preserve the expected unconfirmed monitor result')
                record['current_proof_persistence_confirmed'] = False
                record['receipt_scope'] = 'diagnostic readback only; current state commit intentionally unconfirmed'
            elif not record['root_receipt_matches_response']:
                raise RuntimeError('root-protected receipt did not match the returned public proof')
        else:
            if args.active_state_fault:
                record['native_proof_available'] = False
                record['active_state_fault_expected_result'] = False
            else:
                raise RuntimeError('daemon harness produced no native proof for root receipt readback')
        if args.active_state_fault:
            record['native_proof_available'] = bool(proof)
            record['active_state_fault_expected_result'] = bool(
                proof and proof.get('state') == 'cleanup_unconfirmed' and
                proof.get('native_cleanup_facts_confirmed') is False and
                proof.get('cleanup_confirmed') is False and
                result.get('post_wait_status', {}).get('admission_closed') is True and
                result.get('immutable_primary_observation', {}).get('authority_exit_expected_sigkill') is True and
                result.get('aftermath_observation', {}).get('oracle_passed') is True)
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
    if fixture and label and registration_attempted:
        stopped = run('bootout-own-label', ['/usr/bin/sudo', '-n', '/bin/launchctl', 'bootout', 'system/' + label], record, 45)
        record['bootout_exit_code'] = stopped.returncode
        time.sleep(1)
        absent = run('verify-own-label-absent', ['/usr/bin/sudo', '-n', '/bin/launchctl', 'print', 'system/' + label], record)
        bootstrapped = not label_absent(absent, label)
        record['own_launchd_label_absent'] = not bootstrapped
    if fixture and host_probe_attempted:
        host_scan = run('post-host-probe-uid-scan', [str(args.uid_scan), '1800000124'], record)
        host_uid_scan_clear = host_scan.returncode == 0
        record['host_probe_uid_zero_confirmed'] = host_uid_scan_clear
        record['host_probe_processes_reaped'] = host_probe_processes_reaped
    if fixture and groups_probe_attempted:
        groups_scan = run('post-kernel-groups-uid-scan', [str(args.uid_scan), '1800000125'], record)
        groups_uid_scan_clear = groups_scan.returncode == 0
        record['kernel_groups_uid_zero_confirmed'] = groups_uid_scan_clear
        record['kernel_groups_processes_reaped'] = groups_probe_reaped
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
            # Root startup can finish its direct process while reporting an
            # unconfirmed --describe descendant. Keep this sticky and distinct
            # from the ordinary-owner image observation below.
            if root_logs_created and not bootstrapped:
                outlog = run('collect-own-root-daemon-stdout', ['/usr/bin/sudo', '-n', '/bin/cat', str(fixture / 'logs/daemon.stdout.log')], record)
                errlog = run('collect-own-root-daemon-stderr', ['/usr/bin/sudo', '-n', '/bin/cat', str(fixture / 'logs/daemon.stderr.log')], record)
                if outlog.returncode or errlog.returncode:
                    raise RuntimeError('could not collect own root daemon logs; fixture retained')
                if b'stub describe cleanup_unconfirmed:' in errlog.stdout:
                    record['root_native_exits_confirmed'] = False
            # This is quiescent fixture housekeeping, not a reap or production
            # cleanup proof. No further native broker client is launched here.
            authority_wait = result.get('authority_wait', {}) if args.active_state_fault and 'result' in locals() else {}
            if (args.active_state_fault and helper_image_binary and not bootstrapped and membership_clear and
                    authority_wait.get('actual_wait_completed') is True and
                    authority_wait.get('direct_child_reaped_by_controller') is True and
                    record['root_native_exits_confirmed']):
                until = time.monotonic() + 5
                consecutive_zero = 0
                for index in range(12):
                    if time.monotonic() >= until:
                        break
                    checked_fixture(fixture)
                    if sha(helper_image_binary) != record['helper_image_scan_binary_sha256']:
                        raise RuntimeError('ordinary image observer bytes changed')
                    observed = run('ordinary-helper-image-scan-' + str(index),
                        [str(helper_image_binary), str(binary)], record, min(2, max(0.01, until-time.monotonic())))
                    try:
                        value = json.loads(observed.stdout)
                    except (ValueError, TypeError):
                        break
                    valid = (isinstance(value, dict) and
                        value.get('schema') == 'knowledge-qa-helper-image-observation.v1' and
                        type(value.get('owner_uid')) is int and value['owner_uid'] == os.getuid() and
                        value.get('observation_valid') is True and value.get('self_canary') is True and
                        type(value.get('unknown')) is int and value['unknown'] == 0 and
                        type(value.get('image_members')) is int and value.get('reaped') is False and
                        value.get('production_proof') is False)
                    if not valid or observed.returncode not in (0, 1):
                        break
                    consecutive_zero = consecutive_zero + 1 if observed.returncode == 0 and value['image_members'] == 0 else 0
                    if consecutive_zero == 2:
                        ordinary_helper_image_membership_clear = True
                        break
                    time.sleep(0.05)
                record['ordinary_helper_image_membership_clear'] = ordinary_helper_image_membership_clear
                record['ordinary_helper_observation_scope'] = 'two fresh quiescent ordinary-owner image-zero observations; not exact-birth wait, reap or production proof'
            active_helper_housekeeping_clear = (active_state_run_helper_exit_confirmed or ordinary_helper_image_membership_clear)
            # Never remove the fixture until the exact service is booted out and private UID membership is clear.
            if (not bootstrapped and membership_clear and host_probe_processes_reaped and host_uid_scan_clear and
                    groups_probe_reaped and groups_uid_scan_clear and record['root_native_exits_confirmed'] and
                    active_helper_housekeeping_clear):
                if history_files:
                    captured = run('collect-own-uid-history', ['/usr/bin/sudo', '-n', '/usr/bin/tar',
                        '-cf', '-', '-C', str(fixture), 'anchors', 'allocator'], record)
                    if captured.returncode or not captured.stdout or len(captured.stdout) > 128 * 1024 * 1024:
                        raise RuntimeError('could not preserve own UID history; fixture retained')
                    archive = OUT / 'native-uid-history.tar'
                    archive.write_bytes(captured.stdout)
                    record['native_uid_history_archive'] = {'path': str(archive),
                        'bytes': len(captured.stdout), 'sha256': hashlib.sha256(captured.stdout).hexdigest(),
                        'scope': 'own synthetic anchors/allocator only; active registry before fault retained as hash/size only'}
                removed = run('remove-own-fixture', ['/usr/bin/sudo', '-n', '/bin/rm', '-rf', '--', str(fixture)], record)
                record['fixture_cleanup_exit'] = removed.returncode
            else:
                record['fixture_cleanup_deferred'] = ('launchd stop, private UID scan, probe reaping, root initializer exit, '
                    'or active-state native run-helper exit was not confirmed')
        except BaseException as cleanup_error:
            record['fixture_cleanup_deferred'] = str(cleanup_error)
    record['cleanup_confirmed'] = not fixture or (not bootstrapped and membership_clear and
        host_probe_processes_reaped and host_uid_scan_clear and groups_probe_reaped and groups_uid_scan_clear and
        record['root_native_exits_confirmed'] and
        (active_state_run_helper_exit_confirmed or ordinary_helper_image_membership_clear) and
        record.get('fixture_cleanup_exit') == 0)
    if record['status'] == 'LAUNCHD_STARTUP_OBSERVED_HARNESS_PASS' and not record['cleanup_confirmed']:
        record['status'] = 'LAUNCHD_STARTUP_OBSERVED_CLEANUP_UNCONFIRMED'
    (OUT / 'LAUNCHD_SMOKE_RESULT.json').write_text(json.dumps(record, indent=2) + '\n')
print(json.dumps(record))
raise SystemExit(0 if (
    (args.host_probe_only and record['status'] == 'HOST_PROBE_ONLY_PASS' and record['cleanup_confirmed']) or
    (not args.host_probe_only and record['status'] == 'LAUNCHD_STARTUP_OBSERVED_HARNESS_PASS' and
     record.get('launch_origin_canaries_passed') and record.get('host_postdrop_checks_passed') and
     record.get('host_probe_processes_reaped') and record.get('host_probe_uid_zero_confirmed') and
     record['cleanup_confirmed'])) else 1)
