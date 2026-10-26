#!/usr/bin/env python3
"""Strict public evidence for the normal production gate; raw stays private."""
import argparse, hashlib, importlib.util, json, math, os, re
from pathlib import Path

HEX = re.compile(r'^[a-f0-9]{64}$')
FILES = {'darwin-production-lifecycle.py', 'run_pipeline4.py', 'external-frame'}
TYPES = {'QAError', 'FileNotFoundError', 'PermissionError', 'TypeError', 'AttributeError', 'KeyError', 'ValueError',
    'OSError', 'TimeoutExpired', 'RuntimeError', 'ImportError', 'ModuleNotFoundError', 'SyntaxError', 'UnknownException'}
PHASES = {'input', 'public-run', 'finalization-reader', 'retry', 'complete'}
PRODUCT_PHASES = {'setup', 'copy_chunk', 'test_setup', 'command', 'finalization', 'receipt_commit', 'between_tests', 'batch_finalization'}
PROOF_DIAGNOSTICS = {'proof_top_current', 'proof_body_current', 'proof_reply_flags', 'proof_schema', 'proof_source_binding',
    'proof_digest', 'proof_boundary_facts', 'proof_clock', 'proof_terminal', 'proof_command_drain', 'proof_structure',
    'control_input_bound', 'control_descriptor', 'control_capability', 'control_role_identity', 'control_authority_exit'}
PROTECTED_CASES = {'search_only_ancestor': True, 'readable_ancestor': True, 'leaf_write_acl': False,
    'parent_write_acl': False, 'leaf_read_acl': True, 'leaf_symlink': False, 'writable_ancestor': False, 'unsearchable_ancestor': False}
BEFORE_PROTECTED_SOURCE_SHA = '48f8a3c6c945b79c27ee6c46311dc6706809b1062f1db6618f67878e1601691b'
BASIC_CASES = {'normal': 0, 'scratch_readonly': 0, 'silent_long': 0, 'exit7': 7}
FAILURE_CASES = {'cancel', 'authority_death', 'controller_death', 'paused_storage_cancel', 'paused_storage_controller_death',
    'paused_storage_guardian_death', 'double_storage_guardian_controller_death'}
FAILURE_ASSETS = {'darwin-production-failure-cases.py', 'darwin-production-failure-caller.js', 'darwin-production-control.js',
    'darwin-production-process-observer.c', 'darwin-test-signal.c', 'darwin-production-failure-summary.py'}
FAILURES = set('runner_architecture_mismatch runtime_copy_pin_mismatch node_version_failed node_version_invalid '
    'node_checksums_oversized node_headers_checksum_missing node_headers_checksum_mismatch node_headers_archive_unsafe '
    'node_headers_archive_truncated native_addon_build_failed native_addon_pin_mismatch ordinary_owner_required '
    'installed_binary_pin_mismatch normal_install_failed normal_daemon_not_observed normal_daemon_birth_unconfirmed '
    'normal_socket_unavailable normal_mode_not_admissible normal_registry_unreadable duplicate_production_result '
    'public_production_normal_failed project_source_mutated normal_service_exit_unconfirmed normal_daemon_exit_unconfirmed '
    'normal_UID_cleanup_unconfirmed source_changed compile_shipping_broker_failed compile_shipping_stub_failed '
    'stub_pair_mismatch_shipping uid_scan_compile_failed birth_observer_compile_failed protected_install_parent_unavailable '
    'install_parent_creation_unconfirmed public_writer_cleanup_unconfirmed_preserve_fixture protected_baseline_source_pin_mismatch '
    'protected_baseline_compile_failed protected_executable_contract_failed protected_executable_hash_mismatch '
    'protected_search_denial_not_observed protected_write_acl_fixture_inactive public_production_case_invalid '
    'public_production_basic_failed production_failure_helper_compile_failed production_failure_case_invalid '
    'production_failure_case_deadline production_failure_helper_timeout_preserve_fixture production_failure_helper_protocol '
    'production_failure_helper_exit_mismatch production_failure_actor_binding production_failure_actor_parent_binding '
    'production_failure_signal_unconfirmed production_failure_UID_unconfirmed production_failure_UID_cleanup_deadline '
    'production_failure_actor_exit_unconfirmed production_failure_caller_exited_before_action production_failure_execution_not_observed '
    'production_failure_registry_actor_mismatch production_failure_cancel_not_durable production_failure_paused_writer_missing '
    'production_failure_live_writer_reclaimed production_failure_live_writer_claim_lost production_failure_caller_exit_invalid '
    'production_failure_caller_output_oversized production_failure_caller_protocol production_failure_unexpected_acceptance '
    'production_failure_attempt_replaced production_failure_recovery_failed production_failure_terminal_not_confirmed '
    'production_failure_project_mutated'.split())
STAGES = set('node-version node-exec-path node-system-dylibs compile-lock-addon compile-uid-scan compile-birth-observer '
    'canonical-roots-must-be-absent init-production bootstrap-production capture-production-daemon probe-production '
    'read-production-registry public-production-normal public-production-scratch_readonly public-production-silent_long '
    'public-production-exit7 bootout-production post-stop-production-uid '
    'verify-owned-canonical-inodes remove-owned-canonical-inodes verify-owned-fixture remove-owned-fixture '
    'protect-fixture mode-fixture launchctl-print-own-label launchctl-verify-own-label-absent compare-native-process-birth '
    'ensure-protected-install-parent remove-created-install-parent compile-protected-before-addon create-protected-fixture '
    'mode-protected-readable acl-protected-leaf-write prove-protected-leaf-write acl-protected-leaf-reset restore-protected-fixture '
    'acl-protected-parent-write prove-protected-parent-write acl-protected-parent-reset acl-protected-leaf-read '
    'symlink-protected-fixture mode-protected-writable mode-protected-no-search compile-production-process-observer '
    'compile-production-signal production-failure-status production-failure-cancel production-failure-recover '
    'production-failure-capture-parent production-failure-signal-exact production-failure-uid-observation'.split())


def digest(value): return value if isinstance(value, str) and HEX.fullmatch(value) else None
def number(value): return value if type(value) in (int, float) and math.isfinite(value) and value >= 0 else None
def boolean(value): return value if type(value) is bool else None
def exit_code(value): return value if type(value) is int and -255 <= value <= 255 else None
def sha(data): return hashlib.sha256(data).hexdigest()
def compile_excerpt(data, private, source):
    text = data[:32768].decode('utf8', errors='replace')
    for old, new in ((str(private), '<private-evidence>'), (str(source), '<pinned-source>'),
        (os.environ.get('GITHUB_WORKSPACE', ''), '<workspace>'), (os.environ.get('RUNNER_TEMP', ''), '<runner-temp>')):
        if old: text = text.replace(old, new)
    text = re.sub(r'\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})\b', '<redacted-token>', text)
    text = re.sub(r'\b[a-fA-F0-9]{24,128}\b', '<opaque-hex>', text)
    return '\n'.join(line[:300] for line in text.splitlines()[:8])[:1600]
def load(path, maximum=16*1024*1024):
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > maximum: return {}
        value = json.loads(path.read_bytes());return value if isinstance(value, dict) else {}
    except (OSError, ValueError): return {}


def error_codes(source):
    # Only enum-shaped literals in the exact publicly supplied first-party
    # source are eligible, never arbitrary error messages or payload output.
    codes = set('ERR_ASSERTION controller_assertion_failed darwin_protected_path_unsafe ERR_INVALID_ARG_TYPE ERR_INVALID_ARG_VALUE ERR_OUT_OF_RANGE '
        'ERR_MODULE_NOT_FOUND MODULE_NOT_FOUND ERR_DLOPEN_FAILED ERR_CHILD_PROCESS_IPC_REQUIRED ERR_IPC_CHANNEL_CLOSED '
        'ERR_IPC_DISCONNECTED EACCES EPERM ENOENT ENOTDIR EISDIR ELOOP EEXIST ENOSPC EMFILE ENFILE ENOMEM EIO EPIPE '
        'ETIMEDOUT EBADF EINTR ENOTSUP ENOSYS'.split())
    for name in ('verification-darwin-production.js', 'verification-darwin-preparation.js', 'verification-darwin-preparer.js',
        'verification-darwin-session.js', 'verification-darwin-session-protocol.js', 'verification-darwin-client.js',
        'verification-darwin-control.js', 'verification-darwin-finalization.js', 'verification-darwin-store.js',
        'verification-control.js', 'verification-finalization.js', 'verification-execution.js', 'lock-publication.js',
        'verification-policy.js', 'inert-data.js', 'verification-darwin-authority.js', 'verification-darwin-storage-guardian.js',
        'verification-recovery.js', 'verification-darwin-scope.js', 'contained-lock-manager.js', 'stable-file.js', 'json-store.js'):
        p = source/'tools/lib'/name
        if p.is_file() and not p.is_symlink():
            codes.update(re.findall(r"['\"]((?:verification_|native_lock_|transaction_|stable_file_|contained_path_)[A-Za-z0-9_]{1,100})['\"]", p.read_text()))
    native = source/'tools/lib/verification-darwin-broker.m'
    if native.is_file() and not native.is_symlink(): codes.update(re.findall(r'@"([A-Z][A-Z0-9_]{2,100})"', native.read_text()))
    protected = source/'tools/native/lock-publication.c'
    if protected.is_file() and not protected.is_symlink(): codes.update(re.findall(r'"(darwin_protected_[a-z_]{1,80})"', protected.read_text()))
    return codes


def input_inventory_valid(source, rows):
    if not isinstance(rows, list) or not rows: return False
    expected = {}
    for row in rows:
        if not isinstance(row, dict) or set(row) != {'path', 'bytes', 'sha256', 'executable'}: return False
        name = row['path'];parts = Path(name) if isinstance(name, str) else None
        if parts is None or parts.is_absolute() or '..' in parts.parts or '\\' in name or len(parts.parts) < 2 or \
            parts.parts[0] != source.name or name in expected or type(row['bytes']) is not int or row['bytes'] < 0 or \
            type(row['executable']) is not bool or not digest(row['sha256']): return False
        expected[name] = row
    actual = {}
    try:
        for base, dirs, files in os.walk(source, followlinks=False):
            if any((Path(base)/name).is_symlink() for name in dirs): return False
            for name in files:
                file = Path(base)/name;st = file.lstat()
                if file.is_symlink() or not file.is_file() or st.st_nlink != 1: return False
                data = file.read_bytes();key = file.relative_to(source.parent).as_posix()
                actual[key] = {'path': key, 'bytes': len(data), 'sha256': sha(data), 'executable': bool(st.st_mode & 0o111)}
    except OSError: return False
    return actual == expected


def protected_contract(raw, codes, addon):
    raw = raw if isinstance(raw, dict) else {};rows = [];seen = set();valid = True
    for item in raw.get('cases', []) if isinstance(raw.get('cases'), list) else []:
        if not isinstance(item, dict) or item.get('name') not in PROTECTED_CASES:
            valid = False;continue
        name = item['name'];required = PROTECTED_CASES[name]
        if name in seen: valid = False
        seen.add(name);row = {'name': name, 'required_acceptance': required,
            'status': item.get('status') if item.get('status') == 'PASS_PHYSICAL_PAIRED' else 'FAIL'}
        valid = valid and item.get('required_acceptance') is required and row['status'] == 'PASS_PHYSICAL_PAIRED'
        for version in ('before', 'after'):
            value = item.get(version) if isinstance(item.get(version), dict) else {}
            record = {'accepted': boolean(value.get('accepted')), 'code': value.get('code') if value.get('code') in codes else None,
                'native_error': value.get('native_error') if type(value.get('native_error')) is int and 0 <= value['native_error'] < 4096 else None,
                'sha256': digest(value.get('sha256')), 'source_sha256': digest(value.get('source_sha256')), 'exit_code': exit_code(value.get('exit_code'))}
            row[version] = record;expected = False if version == 'before' and name == 'search_only_ancestor' else required
            valid = valid and record['exit_code'] == 0 and record['accepted'] is expected and record['source_sha256'] == \
                (BEFORE_PROTECTED_SOURCE_SHA if version == 'before' else addon.get('source_sha256'))
            if expected: valid = valid and record['sha256'] == sha(b'#!/bin/sh\nexit 0\n')
            else: valid = valid and record['code'] is not None
        if name == 'search_only_ancestor': valid = valid and row['before']['native_error'] == 13
        rows.append(row)
    valid = valid and seen == set(PROTECTED_CASES) and raw.get('status') == 'PASS_PHYSICAL_PAIRED' and \
        raw.get('write_acl_effects_verified') is True and raw.get('before_source_sha256') == BEFORE_PROTECTED_SOURCE_SHA and \
        raw.get('after_source_sha256') == addon.get('source_sha256') and raw.get('after_binary_sha256') == addon.get('binary_sha256') and \
        bool(digest(raw.get('before_binary_sha256')))
    return {'status': 'PASS_PHYSICAL_PAIRED' if valid else 'FAIL_OR_INCOMPLETE', 'cases': rows,
        'write_acl_effects_verified': boolean(raw.get('write_acl_effects_verified')),
        **{key: digest(raw.get(key)) for key in ('before_source_sha256', 'after_source_sha256', 'before_binary_sha256', 'after_binary_sha256')}}


def build(private, source, controller_status, architecture, case_set='normal'):
    raw = load(private/'SUMMARY.json');inputs = load(private/'INPUTS.json', 4*1024*1024)
    fallback = load(private/'DIAGNOSTIC.json', 65536);codes = error_codes(source)
    expected_cases = {'normal': 0} if case_set == 'normal' else BASIC_CASES if case_set == 'basic' else \
        {'normal': 0, **{name: None for name in FAILURE_CASES}} if case_set == 'failures' else {}
    failure_reducer = None
    if case_set == 'failures':
        helper = Path(__file__).with_name('darwin-production-failure-summary.py')
        spec = importlib.util.spec_from_file_location('production_failure_summary', helper)
        failure_reducer = importlib.util.module_from_spec(spec);spec.loader.exec_module(failure_reducer)
    # Do not silently discard an extra, malformed or unreviewed case and still
    # certify the explicitly selected frozen cohort.
    raw_cases = raw.get('cases')
    case_inventory_valid = bool(expected_cases) and isinstance(raw_cases, list) and len(raw_cases) == len(expected_cases) and \
        all(isinstance(item, dict) and item.get('name') in expected_cases for item in raw_cases) and \
        {item['name'] for item in raw_cases} == set(expected_cases)
    cases = []
    for item in raw.get('cases', []) if isinstance(raw.get('cases'), list) else []:
        if not isinstance(item, dict) or item.get('name') not in expected_cases: continue
        if case_set == 'failures' and item['name'] in FAILURE_CASES:
            row = failure_reducer.reduce_case(item, codes)
            row.update(stdout_sha256=digest(item.get('stdout_sha256')), stderr_sha256=digest(item.get('stderr_sha256')))
            cases.append(row);continue
        terminal = item.get('terminal') if isinstance(item.get('terminal'), dict) else {}
        err = terminal.get('error') if isinstance(terminal.get('error'), dict) else {}
        containment = err.get('containment') if isinstance(err.get('containment'), dict) else {}
        record = None
        if isinstance(terminal.get('result'), list) and len(terminal['result']) == 1 and isinstance(terminal['result'][0], dict):
            record = terminal['result'][0].get('record')
        record = record if isinstance(record, dict) else {}
        cases.append({'name': item['name'], 'status': item.get('status') if item.get('status') in ('PASS_PHYSICAL_PRODUCTION', 'FAIL') else 'UNCONFIRMED',
            'elapsed_ms': number(item.get('elapsed_ms')), 'controller_exit_code': exit_code(item.get('controller_exit_code')),
            'KVE_KVF_ACK_verified': boolean(item.get('KVE_KVF_ACK_verified')), 'phase': terminal.get('stage') if terminal.get('stage') in PHASES else 'unknown',
            'failed_observation_verified': boolean(item.get('failed_observation_verified')),
            'success': boolean(terminal.get('success')), 'error_code': terminal.get('error_code') if terminal.get('error_code') in codes else None,
            'containment_reason': containment.get('reason') if containment.get('reason') in codes else None,
            'product_stage': err.get('stage') if err.get('stage') in PRODUCT_PHASES else None,
            'proof_diagnostic': err.get('darwin_diagnostic') if isinstance(err.get('darwin_diagnostic'), str) and err.get('darwin_diagnostic') in PROOF_DIAGNOSTICS else None,
            'timed_out': boolean(err.get('timed_out')), 'recovery_required': boolean(err.get('recovery_required')),
            'teardown_status': err.get('teardown', {}).get('status') if isinstance(err.get('teardown'), dict) and
                err['teardown'].get('status') in ('completed', 'not_required', 'unconfirmed') else None,
            'stdout_sha256': digest(item.get('stdout_sha256')), 'stderr_sha256': digest(item.get('stderr_sha256')),
            'expected_exit_code': expected_cases[item['name']], 'execution_exit_code': exit_code(record.get('exit_code')),
            'execution_status': record.get('status') if record.get('status') in ('pass', 'fail') else None,
            'observed_elapsed_ms': number(terminal.get('observed_elapsed_ms')),
            'finalized_accepted': terminal.get('finalized', {}).get('status') == 'accepted' if isinstance(terminal.get('finalized'), dict) else False,
            'acceptance_count': len(terminal['acceptances']) if isinstance(terminal.get('acceptances'), list) else None,
            'source_unchanged': boolean(terminal.get('source_unchanged')),
            'failed_KVE_verified': boolean(terminal.get('failed_KVE_verified')),
            'failed_attempt_no_ACK': boolean(terminal.get('failed_attempt_no_ACK')),
            'failed_cleanup_confirmed': boolean(terminal.get('failed_cleanup_confirmed')),
            'retry_accepted': boolean(terminal.get('retry_accepted')),
            'retry_distinct_attempt': boolean(terminal.get('retry_distinct_attempt')),
            'no_progress_ms': number(terminal.get('budget', {}).get('no_progress_ms')) if isinstance(terminal.get('budget'), dict) else None,
            'copy_only_progress_monitor': terminal.get('budget', {}).get('progress_monitored_operations') == ['native_copy_chunk'] if isinstance(terminal.get('budget'), dict) else False})
    diagnostics = []
    values = raw.get('diagnostics', fallback.get('diagnostics', []))
    for item in values[:4] if isinstance(values, list) else []:
        if not isinstance(item, dict): continue
        frames = []
        for frame in item.get('frames', [])[:16] if isinstance(item.get('frames'), list) else []:
            if isinstance(frame, dict) and frame.get('file') in FILES and type(frame.get('line')) is int and 0 < frame['line'] < 1000000:
                frames.append({'file': frame['file'], 'line': frame['line']})
        diagnostics.append({'type': item.get('type') if item.get('type') in TYPES else 'UnknownException',
            'stage': item.get('stage') if item.get('stage') in ('execute', 'cleanup', 'bootstrap') else 'unknown', 'frames': frames})
    stages = [];compiler_diagnostics = []
    for item in raw.get('records', []) if isinstance(raw.get('records'), list) else []:
        if not isinstance(item, dict): continue
        name = item.get('name');match = re.fullmatch(r'(\d{3,6})-(.+)', name or '')
        if not match: continue
        suffix = match[2]
        known = suffix in STAGES or re.fullmatch(r'(?:create|identify)-canonical-(?:registry|allocator|anchors|workspaces|control)', suffix) or \
            re.fullmatch(r'(?:mkdir|chown|chmod)-(?:bin|runtime|logs|launchd)', suffix) or \
            re.fullmatch(r'install-production-(?:broker|stub|node|plist)', suffix) or \
            re.fullmatch(r'(?:compile|describe)-shipping-\d{2}-(?:broker|stub)', suffix) or \
            re.fullmatch(r'protected-(?:before|after)-(?:'+ '|'.join(PROTECTED_CASES) +')', suffix)
        stages.append({'stage': name if known else match[1]+'-unclassified-stage', 'stage_name_sha256': sha(name.encode()),
            'exit_code': exit_code(item.get('exit_code')), 'timed_out': boolean(item.get('timed_out')),
            'elapsed_ms': number(item.get('elapsed_ms')), 'stdout_sha256': digest(item.get('stdout_sha256')), 'stderr_sha256': digest(item.get('stderr_sha256'))})
        if known and re.fullmatch(r'compile-(?:lock-addon|protected-before-addon|uid-scan|birth-observer|production-process-observer|production-signal|shipping-\d{2}-(?:broker|stub))', suffix):
            stderr = private/(name+'.stderr.raw')
            if stderr.is_file() and not stderr.is_symlink() and stderr.stat().st_size <= 4*1024*1024:
                compiler_diagnostics.append({'stage': name, 'stderr_excerpt': compile_excerpt(stderr.read_bytes(), private, source)})
    binaries = []
    for item in raw.get('binary_history', []) if isinstance(raw.get('binary_history'), list) else []:
        if not isinstance(item, dict): continue
        binaries.append({**{key: digest(item.get(key)) for key in ('broker_sha256', 'stub_sha256', 'source_sha256', 'stub_source_sha256')},
            'kind': 'shipping' if item.get('kind') == 'shipping' else 'unknown', 'qa_io_enabled': boolean(item.get('qa_io_enabled'))})
    addon = raw.get('native_addon') if isinstance(raw.get('native_addon'), dict) else {}
    executable_contract = protected_contract(raw.get('protected_executable_contract'), codes, addon)
    source_rows = inputs.get('files') if isinstance(inputs.get('files'), list) else []
    valid_inputs = input_inventory_valid(source, source_rows) and all(digest(inputs.get(key)) for key in
        ('controller_sha256', 'lifecycle_sha256', 'reference_runner_sha256'))
    if case_set == 'basic': valid_inputs = valid_inputs and all(digest(inputs.get(key)) for key in ('matrix_controller_sha256', 'workloads_sha256'))
    failure_assets = inputs.get('failure_assets') if isinstance(inputs.get('failure_assets'), dict) else {}
    failure_helpers = raw.get('failure_helper_pins') if isinstance(raw.get('failure_helper_pins'), dict) else {}
    if case_set == 'failures':
        valid_inputs = valid_inputs and set(failure_assets) == FAILURE_ASSETS and all(digest(value) for value in failure_assets.values()) and \
            set(failure_helpers) == {'process_observer_pin', 'signal_pin'} and all(isinstance(value, dict) and \
                set(value) == {'source_sha256', 'binary_sha256'} and all(digest(part) for part in value.values()) for value in failure_helpers.values()) and \
            failure_helpers['process_observer_pin']['source_sha256'] == failure_assets['darwin-production-process-observer.c'] and \
            failure_helpers['signal_pin']['source_sha256'] == failure_assets['darwin-test-signal.c']
    actual_arch = 'x64' if architecture == 'x86_64' else 'arm64'
    expected_status = {'basic': 'PASS_PHYSICAL_PRODUCTION_BASIC', 'failures': 'PASS_PHYSICAL_PRODUCTION_FAILURES',
        'normal': 'PASS_PHYSICAL_PRODUCTION_NORMAL'}.get(case_set)
    accepted_cases = all(case['status'] == 'PASS_PHYSICAL_PRODUCTION_FAILURE' if case['name'] in FAILURE_CASES and case_set == 'failures' else \
        case['status'] == 'PASS_PHYSICAL_PRODUCTION' and case['success'] is True and case['controller_exit_code'] == 0 and \
        (case['KVE_KVF_ACK_verified'] is False and case['failed_observation_verified'] is True if case_set == 'basic' and case['name'] == 'exit7' \
            else case['KVE_KVF_ACK_verified'] is True) for case in cases)
    passed = controller_status == 0 and raw.get('status') == expected_status and raw.get('source_unchanged') is True and \
        raw.get('cleanup_confirmed') is True and raw.get('architecture') == architecture and case_inventory_valid and len(cases) == len(expected_cases) and \
        accepted_cases and \
        len(binaries) == 1 and binaries[0]['kind'] == 'shipping' and binaries[0]['qa_io_enabled'] is False and \
        all(binaries[0][key] for key in ('broker_sha256', 'stub_sha256', 'source_sha256', 'stub_source_sha256')) and \
        digest(addon.get('source_sha256')) and digest(addon.get('binary_sha256')) and \
        addon.get('platform') == 'darwin' and addon.get('architecture') == actual_arch and valid_inputs and \
        executable_contract['status'] == 'PASS_PHYSICAL_PAIRED'
    if case_set == 'basic':
        passed = passed and raw.get('case_set') == 'basic' and all(case['name'] == 'normal' or \
            case['execution_exit_code'] == case['expected_exit_code'] and \
            case['execution_status'] == ('pass' if case['expected_exit_code'] == 0 else 'fail') and \
            (case['finalized_accepted'] is False and case['acceptance_count'] == 0 and \
                case['error_code'] == 'verification_command_failed' and case['teardown_status'] == 'completed' and \
                case['recovery_required'] is False and case['timed_out'] is False and \
                all(case[key] is True for key in ('failed_KVE_verified', 'failed_attempt_no_ACK', 'failed_cleanup_confirmed',
                    'retry_accepted', 'retry_distinct_attempt')) if case['name'] == 'exit7' else \
                case['finalized_accepted'] is True and case['acceptance_count'] == 1) and case['source_unchanged'] is True and \
            (case['name'] != 'silent_long' or case['observed_elapsed_ms'] is not None and case['observed_elapsed_ms'] >= 125000 and \
                case['no_progress_ms'] == 500 and case['copy_only_progress_monitor']) for case in cases)
    if case_set == 'failures': passed = passed and raw.get('case_set') == 'failures'
    manifest_sha = sha(json.dumps(source_rows, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode()) if source_rows else None
    summary = {'schema': 'knowledge-darwin-production-public.v1', 'status': \
        {'basic': 'PASS_PRODUCTION_BASIC_MATRIX', 'failures': 'PASS_PRODUCTION_FAILURE_MATRIX', 'normal': 'PASS_PRODUCTION_NORMAL_GATE'}[case_set] if passed else 'FAIL_OR_INCOMPLETE',
        'case_set': case_set if case_set in ('normal', 'basic', 'failures') else 'invalid',
        'controller_exit_code': controller_status, 'architecture': raw.get('architecture') if raw.get('architecture') in ('x86_64', 'arm64') else None,
        'expected_architecture': architecture, 'source_unchanged': boolean(raw.get('source_unchanged')), 'cleanup_confirmed': boolean(raw.get('cleanup_confirmed')),
        'exact_source_inventory_verified': bool(valid_inputs), 'exact_case_inventory_verified': bool(case_inventory_valid),
        'source_manifest_sha256': manifest_sha, 'source_manifest_file_count': len(source_rows),
        'controller_sha256': digest(inputs.get('controller_sha256')), 'lifecycle_sha256': digest(inputs.get('lifecycle_sha256')),
        'matrix_controller_sha256': digest(inputs.get('matrix_controller_sha256')), 'workloads_sha256': digest(inputs.get('workloads_sha256')),
        'failure_assets': {name: digest(failure_assets.get(name)) for name in sorted(FAILURE_ASSETS)} if case_set == 'failures' else None,
        'failure_helper_pins': {name: {key: digest(value.get(key)) for key in ('source_sha256', 'binary_sha256')}
            for name, value in failure_helpers.items() if name in ('process_observer_pin', 'signal_pin') and isinstance(value, dict)} if case_set == 'failures' else None,
        'reference_runner_sha256': digest(inputs.get('reference_runner_sha256')), 'cases': cases, 'compiled_pairs': binaries,
        'native_addon': {key: digest(addon.get(key)) for key in ('source_sha256', 'binary_sha256')}, 'diagnostics': diagnostics,
        'protected_executable_contract': executable_contract,
        'compiler_diagnostics': compiler_diagnostics,
        'failure_code': raw.get('failure') if raw.get('failure') in FAILURES else ('private_failure' if raw.get('failure') else None),
        'failure_codes': [part.removeprefix('cleanup:') for part in raw.get('failure', '').split(';')
            if part.removeprefix('cleanup:') in FAILURES][:4] if isinstance(raw.get('failure'), str) else [],
        'workflow_commit': os.environ.get('GITHUB_SHA') if re.fullmatch('[a-f0-9]{40}', os.environ.get('GITHUB_SHA', '')) else None,
        'workflow_run_id': os.environ.get('GITHUB_RUN_ID') if re.fullmatch('[0-9]+', os.environ.get('GITHUB_RUN_ID', '')) else None,
        'release_gate_qualified': False, 'scope': 'Fixed public production cohort. Double storage-guardian and controller death preserves a live writer claim until explicitly operator-assisted exit. Kernel I/O stalls and release qualification remain separate.',
        'raw_evidence_scope': 'runner-private; tokens, raw native replies, account/host identifiers, paths and payload output excluded'}
    parent = raw.get('installation_parent') if isinstance(raw.get('installation_parent'), dict) else {}
    summary['installation_parent'] = {key: boolean(parent.get(key)) for key in
        ('ok', 'created', 'removed', 'exists_before', 'directory_before', 'symlink_before', 'root_owned_before')}
    summary['installation_parent']['errno'] = parent.get('errno') if type(parent.get('errno')) is int and 0 < parent['errno'] < 4096 else None
    summary['installation_parent']['mode_before'] = parent.get('mode_before') if type(parent.get('mode_before')) is int and 0 <= parent['mode_before'] <= 0o7777 else None
    return summary, {'schema': 'knowledge-darwin-production-public-stages.v1', 'stages': stages}


def main():
    ap = argparse.ArgumentParser();ap.add_argument('--private', required=True);ap.add_argument('--public', required=True)
    ap.add_argument('--source', required=True);ap.add_argument('--controller-status', type=int, required=True)
    ap.add_argument('--expected-arch', choices=('x86_64', 'arm64'), required=True)
    ap.add_argument('--case-set', choices=('normal', 'basic', 'failures'), default='normal');args = ap.parse_args()
    private = Path(args.private).resolve();public = Path(args.public).resolve();source = Path(args.source).resolve()
    if public == private or public.is_relative_to(private) or private.is_relative_to(public): raise SystemExit('public_private_overlap')
    summary, stages = build(private, source, args.controller_status, args.expected_arch, args.case_set)
    public.mkdir(mode=0o755, parents=True, exist_ok=False)
    for name, value in (('summary.json', summary), ('stages.json', stages)):
        p = public/name;p.write_text(json.dumps(value, indent=2, sort_keys=True)+'\n');p.chmod(0o644)
    print(json.dumps({'status': summary['status'], 'public_files': ['summary.json', 'stages.json'], 'release_gate_qualified': False}))
    return 0 if summary['status'] == {'basic': 'PASS_PRODUCTION_BASIC_MATRIX', 'failures': 'PASS_PRODUCTION_FAILURE_MATRIX',
                                    'normal': 'PASS_PRODUCTION_NORMAL_GATE'}[args.case_set] else 1


if __name__ == '__main__': raise SystemExit(main())
