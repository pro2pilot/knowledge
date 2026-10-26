#!/usr/bin/env python3
"""Strict public projection of the six physical writable-workspace cases.

Raw scope descriptors, bearer tokens, paths, UIDs and actor identities never
enter this projection. A clean child exit is insufficient without all of the
independent native/tree/cleanup observations and exact input bindings.
"""
import argparse
import ast
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import re

HERE = Path(__file__).resolve().parent
CASES = ('normal_two_flow_steps', 'evaluation_check', 'cancel', 'controller_death',
         'double_guardian_controller_death', 'state_writer_fifo_read_cancel')
HEX = re.compile(r'^[a-f0-9]{64}$')


def module(name, file):
    spec = importlib.util.spec_from_file_location(name, file)
    value = importlib.util.module_from_spec(spec);spec.loader.exec_module(value)
    return value


legacy = module('writable_public_helpers', HERE/'darwin-production-summary.py')
fixture = module('writable_fixed_fixture', HERE/'macos-writable-lifecycle.py')
sha = lambda value: hashlib.sha256(value).hexdigest()
digest = lambda value: value if isinstance(value, str) and HEX.fullmatch(value) else None
obj = lambda value: value if isinstance(value, dict) else {}
canonical = lambda value: json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode()
ASSETS = ('macos-writable-lifecycle.py', 'macos-workspace-provision.c', 'darwin-production-failure-cases.py',
          'darwin-production-process-observer.c', 'darwin-test-signal.c')
SAFE_ERRORS = {'command_cancelled', 'command_work_timeout', 'command_cleanup_unconfirmed',
               'command_macos_worker_failed', 'contained_path_unsafe'}


def package_valid(private, source, source_rows, special, addon, arch):
    """Bind the derived protected package, not the different original inventory."""
    try:
        members = special.get('protected_package_members')
        if not isinstance(members, list) or not members or special.get('protected_package_sha256') != sha(canonical(members)):
            return False
        expected = {row['path'].removeprefix(source.name+'/'): {key: row[key] for key in ('bytes', 'sha256')} for row in source_rows}
        expected['tools/macos-qa-step.js'] = {'bytes': len(fixture.LEAF.encode()), 'sha256': sha(fixture.LEAF.encode())}
        directory = 'tools/lib/native/darwin-'+('x64' if arch == 'x86_64' else 'arm64')
        stage = private/'macos-package-stage'
        manifest_file = stage/directory/'lock-publication.manifest.json'
        manifest = legacy.load(manifest_file, 16384)
        if manifest != addon or not manifest or type(addon.get('binary_bytes')) is not int or addon['binary_bytes'] < 1:
            return False
        expected[directory+'/lock-publication.manifest.json'] = {'bytes': manifest_file.stat().st_size, 'sha256': sha(manifest_file.read_bytes())}
        expected[directory+'/lock-publication.node'] = {'bytes': addon['binary_bytes'], 'sha256': addon['binary_sha256']}
        actual = {}
        for row in members:
            if not isinstance(row, dict) or set(row) != {'path', 'bytes', 'sha256'}: return False
            name = row['path']
            if not isinstance(name, str) or not name or Path(name).is_absolute() or '\\' in name or \
                    any(part in ('', '.', '..') for part in name.split('/')) or name in actual or \
                    type(row['bytes']) is not int or row['bytes'] < 0 or not digest(row['sha256']): return False
            actual[name] = {key: row[key] for key in ('bytes', 'sha256')}
        if actual != expected or [row['path'] for row in members] != sorted(actual): return False
        physical = []
        for file in sorted(stage.rglob('*')):
            if file.is_symlink(): return False
            if file.is_file():
                st = file.stat()
                if st.st_nlink != 1: return False
                physical.append({'path': file.relative_to(stage).as_posix(), 'bytes': st.st_size, 'sha256': sha(file.read_bytes())})
        return physical == members and special.get('package_derivation') == 'exact runtime copy plus fixed QA leaf and compiled source-bound addon'
    except (OSError, KeyError, TypeError, ValueError): return False


def case_projection(row):
    row = obj(row);name = row.get('name');o = obj(row.get('observations'))
    t = obj(row.get('terminal'));value = obj(t.get('value'))
    facts = {key: o.get(key) is True for key in ('exact_actor_exits', 'independent_uid_zero',
        'typed_native_closure', 'automatic_native_cleanup', 'outside_canary_unchanged')}
    facts['no_acceptance_after_cancel'] = o.get('acceptance_after_cancel') is False
    facts['no_external_recovery'] = o.get('external_recovery_requested') is False
    count = 2 if name == 'normal_two_flow_steps' else 1
    facts['exact_allocation_count'] = type(o.get('private_allocation_count')) is int and o['private_allocation_count'] == count
    rc = row.get('controller_exit_code')
    if name == 'normal_two_flow_steps':
        first, second = obj(value.get('first')), obj(value.get('second'))
        a, b = obj(first.get('parsed')), obj(second.get('parsed'))
        facts.update(public_operations_succeeded=t.get('ok') is True and type(rc) is int and rc == 0 and first.get('success') is True and second.get('success') is True,
            both_native_ownership_completed=obj(first.get('ownership')).get('status') == 'completed' and obj(second.get('ownership')).get('status') == 'completed',
            distinct_private_identities=type(a.get('uid')) is int and type(b.get('uid')) is int and
                1000000000 <= a['uid'] < 1900000000 and 1000000000 <= b['uid'] < 1900000000 and
                a['uid'] != b['uid'] and b.get('previous_uid') == a['uid'],
            detached_tree_exercised=a.get('detached_tree_ready') is True,
            owner_and_next_identity_write_continuity=value.get('owner_write_continuity') is True and b.get('writable_continuity') is True)
        facts.update({key: a.get(key) is True for key in ('private_uid_outside_write_denied',
            'metadata_change_denied', 'owner_uid_escalation_denied', 'nonpinned_exec_denied')})
    elif name == 'evaluation_check':
        facts.update(public_evaluation_passed=t.get('ok') is True and type(rc) is int and rc == 0 and value.get('status') == 'pass',
            native_ownership_completed=obj(value.get('ownership')).get('status') == 'completed')
    elif name in ('cancel', 'state_writer_fifo_read_cancel'):
        facts.update(cancellation_reported=t.get('ok') is False and type(rc) is int and rc == 2 and t.get('code') == 'command_cancelled',
            native_cleanup_reported=obj(t.get('cleanup')).get('status') == 'completed', no_recovery_required=t.get('recovery_required') is False)
        if name == 'state_writer_fifo_read_cancel': facts['actual_blocked_fifo_reader_observed'] = o.get('actual_state_writer_fifo_fd_observed') is True
    elif name in ('controller_death', 'double_guardian_controller_death'):
        facts['actual_controller_kill_without_terminal'] = type(rc) is int and rc == -9 and row.get('terminal') is None
        if name == 'double_guardian_controller_death':
            facts['writer_scheduling_pause_exercised'] = o.get('scheduling_pause_not_kernel_io') is True
            facts['all_three_exact_kills_delivered'] = o.get('both_guardians_and_controller_exact_kill_delivered') is True
    else: facts['known_case'] = False
    elapsed = row.get('elapsed_ms')
    elapsed = elapsed if type(elapsed) in (int, float) and math.isfinite(elapsed) and 0 <= elapsed <= 240000 else None
    valid = name in CASES and row.get('status') == 'PASS_PHYSICAL_MACOS_WRITABLE' and elapsed is not None and all(facts.values())
    code = t.get('code')
    return {'name': name if name in CASES else 'unknown_case', 'status': 'PASS_PHYSICAL_MACOS_WRITABLE' if valid else 'FAIL_OR_INCOMPLETE',
        'facts': facts, 'elapsed_ms': elapsed, 'controller_exit_code': rc if type(rc) is int and -255 <= rc <= 255 else None,
        'error_code': code if isinstance(code, str) and code in SAFE_ERRORS else None}


def build(private, source, rc, arch):
    raw = legacy.load(private/'SUMMARY.json');inputs = legacy.load(private/'INPUTS.json')
    special = legacy.load(private/'MACOS_WRITABLE_INPUTS.json')
    rows = raw.get('cases') if isinstance(raw.get('cases'), list) else []
    cases = [case_projection(row) for row in rows]
    exact_cases = len(cases) == len(CASES) and [row['name'] for row in cases] == list(CASES)
    source_rows = inputs.get('files') if isinstance(inputs.get('files'), list) else []
    exact_source = legacy.input_inventory_valid(source, source_rows)
    exact_fixture = tuple(fixture.CASES) == CASES and special.get('leaf_sha256') == sha(fixture.LEAF.encode()) and \
        special.get('caller_sha256') == sha(fixture.CALLER.encode()) and \
        special.get('provision_source_sha256') == sha((HERE/'macos-workspace-provision.c').read_bytes()) and \
        digest(special.get('provision_binary_sha256')) and \
        inputs.get('writable_assets') == {name: sha((HERE/name).read_bytes()) for name in ASSETS} and \
        inputs.get('lifecycle_sha256') == sha((HERE/'darwin-production-lifecycle.py').read_bytes()) and \
        inputs.get('controller_sha256') == sha((HERE/'darwin-production-controller.js').read_bytes()) and \
        inputs.get('reference_runner_sha256') == sha((HERE.parent/'reference/qa/darwin-pipeline4/run_pipeline4.py').read_bytes())
    provision = private/'macos-workspace-provision'
    exact_fixture = bool(exact_fixture and provision.is_file() and not provision.is_symlink() and
        special.get('provision_binary_sha256') == sha(provision.read_bytes()))
    batch = legacy.load(private/'MACOS_SIGNAL_BATCH_INPUTS.json')
    batch_source = private/'macos-exact-signal-batch.c';batch_binary = private/'macos-exact-signal-batch'
    batch_code = next(ast.literal_eval(node.value) for node in ast.walk(ast.parse((HERE/'macos-writable-lifecycle.py').read_text()))
        if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == 'batch_code' for target in node.targets))
    exact_fixture = bool(exact_fixture and batch_source.is_file() and not batch_source.is_symlink() and
        batch_binary.is_file() and not batch_binary.is_symlink() and batch_source.read_bytes() == batch_code.encode() and
        batch.get('source_sha256') == sha(batch_source.read_bytes()) and batch.get('binary_sha256') == sha(batch_binary.read_bytes()) and
        batch.get('included_exact_signal_source_sha256') == sha((HERE/'darwin-test-signal.c').read_bytes()))
    binaries = []
    for row in raw.get('binary_history', []) if isinstance(raw.get('binary_history'), list) else []:
        row = obj(row);binaries.append({key: digest(row.get(key)) for key in ('source_sha256', 'stub_source_sha256', 'broker_sha256', 'stub_sha256')})
    expected_native = {'source_sha256': sha((source/'tools/lib/verification-darwin-broker.m').read_bytes()),
        'stub_source_sha256': sha((source/'tools/lib/verification-darwin-stub.c').read_bytes())}
    native = len(binaries) == 1 and all(binaries[0].values()) and all(binaries[0][key] == val for key, val in expected_native.items()) and \
        raw['binary_history'][0].get('kind') == 'shipping' and raw['binary_history'][0].get('qa_io_enabled') is False
    addon = obj(raw.get('native_addon'))
    native = native and addon.get('platform') == 'darwin' and addon.get('architecture') == ('x64' if arch == 'x86_64' else 'arm64') and \
        addon.get('schema_version') == 'knowledge-lock-native-binary.v1' and addon.get('napi_version') == 8 and \
        addon.get('binary') == 'lock-publication.node' and \
        addon.get('source_sha256') == sha((source/'tools/native/lock-publication.c').read_bytes()) and digest(addon.get('binary_sha256'))
    exact_fixture = exact_fixture and package_valid(private, source, source_rows, special, addon, arch)
    installed = raw.get('installed_bindings')
    native = native and isinstance(installed, list) and len(installed) == 3 and \
        {obj(row).get('role') for row in installed} == {'broker', 'stub', 'node'} and all(
            digest(obj(row).get('source_sha256')) and row['source_sha256'] == row.get('installed_sha256') and
            (row['role'] == 'node' or row['source_sha256'] == binaries[0][row['role']+'_sha256']) for row in installed)
    passed = type(rc) is int and rc == 0 and raw.get('status') == 'PASS_PHYSICAL_MACOS_WRITABLE' and raw.get('case_set') == 'writable' and \
        raw.get('architecture') == arch and raw.get('source_unchanged') is True and raw.get('cleanup_confirmed') is True and \
        exact_cases and exact_source and exact_fixture and native and all(row['status'] == 'PASS_PHYSICAL_MACOS_WRITABLE' for row in cases)
    failure = raw.get('failure') if isinstance(raw.get('failure'), str) else ''
    allowed = set()
    for path in (HERE/'macos-writable-lifecycle.py', HERE/'darwin-production-lifecycle.py'):
        allowed.update(re.findall(r"['\"]((?:macos_|normal_|public_|source_|compile_)[a-zA-Z0-9_]{1,100})['\"]", path.read_text()))
    errors = sorted({part for part in re.findall(r'[A-Za-z][A-Za-z0-9_]{2,120}', failure) if part in allowed})
    stages = []
    for row in raw.get('records', []) if isinstance(raw.get('records'), list) else []:
        row = obj(row);name = row.get('name', '')
        match = re.fullmatch(r'\d{3,6}-(compile-(?:macos-workspace-provision|lock-addon|protected-before-addon|shipping-broker|shipping-stub|uid-scan|birth-observer|production-process-observer|production-signal))', name) if isinstance(name, str) else None
        if not match: continue
        file = private/(name+'.stderr.raw')
        if file.is_file() and not file.is_symlink() and file.stat().st_size <= 4*1024*1024:
            body = file.read_bytes()
            stages.append({'stage': match[1], 'stderr_bytes': len(body), 'stderr_sha256': sha(body)})
    return {'schema': 'knowledge-macos-writable-public.v1', 'status': 'PASS_PHYSICAL_MACOS_WRITABLE' if passed else 'FAIL_OR_INCOMPLETE',
        'controller_exit_code': rc, 'expected_architecture': arch, 'source_unchanged': raw.get('source_unchanged') is True,
        'cleanup_confirmed': raw.get('cleanup_confirmed') is True, 'exact_case_inventory_verified': bool(exact_cases),
        'exact_source_inventory_verified': bool(exact_source), 'exact_fixture_verified': bool(exact_fixture), 'native_bindings_verified': bool(native),
        'cases': cases, 'failure_codes': errors, 'compiler_diagnostics': stages, 'compiled_pairs': binaries,
        'controller_sha256': sha((HERE/'macos-writable-lifecycle.py').read_bytes()), 'summary_controller_sha256': sha(Path(__file__).read_bytes()),
        'source_inventory_sha256': sha(json.dumps(source_rows, sort_keys=True, separators=(',', ':')).encode()),
        'source_file_count': len(source_rows),
        'workflow_commit': os.environ.get('GITHUB_SHA') if re.fullmatch(r'[a-f0-9]{40}|[a-f0-9]{64}', os.environ.get('GITHUB_SHA', '')) else None,
        'workflow_run_id': os.environ.get('GITHUB_RUN_ID') if re.fullmatch(r'[0-9]{1,30}', os.environ.get('GITHUB_RUN_ID', '')) else None,
        'release_gate_qualified': False, 'scope': 'Six explicit public writable workspace cases. FIFO read is a real blocked read; SIGSTOP is scheduling suspension. No disk failure, reboot, full-release, or untested watcher claim.'}


def main():
    ap = argparse.ArgumentParser();ap.add_argument('--private', required=True);ap.add_argument('--public', required=True)
    ap.add_argument('--source', required=True);ap.add_argument('--controller-status', type=int, required=True)
    ap.add_argument('--expected-arch', choices=('x86_64', 'arm64'), required=True);a = ap.parse_args()
    public = Path(a.public);public.mkdir(parents=True, exist_ok=False)
    try:
        result = build(Path(a.private), Path(a.source), a.controller_status, a.expected_arch)
    except (OSError, KeyError, TypeError, ValueError, StopIteration):
        result = {'schema': 'knowledge-macos-writable-public.v1', 'status': 'FAIL_OR_INCOMPLETE',
            'failure_codes': ['projection_input_invalid'], 'release_gate_qualified': False}
    (public/'summary.json').write_text(json.dumps(result, indent=2, sort_keys=True)+'\n')
    print(json.dumps({'status':result['status'], 'release_gate_qualified':False}))
    return 0 if result['status'] == 'PASS_PHYSICAL_MACOS_WRITABLE' else 1


if __name__ == '__main__': raise SystemExit(main())
