#!/usr/bin/env python3
"""Strict public projection of the seven physical writable-workspace cases.

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
         'double_guardian_controller_death', 'state_writer_fifo_read_cancel', 'team_flow_controller_death_retry')
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
               'command_macos_worker_failed', 'contained_path_unsafe', 'ERR_ASSERTION', 'untyped'}
TEAM_FACTS = ('public_team_main_async', 'abandoned_lock_published', 'old_lock_scope_native_bound',
    'old_native_scope_closed_before_restart', 'new_team_run_distinct', 'new_native_attempt_distinct',
    'new_lock_generation_distinct', 'old_generation_quarantined_exact', 'old_run_remains_incomplete',
    'new_team_lock_released', 'fresh_team_cleanup_completed', 'restart_not_retry_of', 'actual_state_writer_fifo_fd_observed')
DOCTOR_STEPS = ('sync-tracked.js --scan', 'build-wiki-graph.js', 'lint-wiki.js', 'external-memory-status.js',
    'build-routing-bundle.js', 'build-search-index.js', 'scan-secrets.js', 'doctor.js')


def diagnostic_catalog(source, source_rows):
    """Only exact static literal spellings from this pinned source cohort."""
    enums, frames = set(SAFE_ERRORS), {}
    # The fixed caller is pinned independently by exact_fixture_verified.
    for text in (fixture.CALLER,fixture.TEAM_CALLER,fixture.LEAF):
        enums.update(re.findall(r'''(?:@)?["']([A-Za-z][A-Za-z0-9_]{1,95})["']''', text))
    for row in source_rows:
        name = row.get('path', '').removeprefix(source.name+'/')
        if not isinstance(name, str) or not name.startswith('tools/') or Path(name).suffix not in ('.js', '.c', '.m', '.h'): continue
        path = source/name
        if path.is_symlink() or not path.is_file(): continue
        body = path.read_bytes()
        if row.get('sha256') != sha(body): continue
        text = body.decode('utf8', errors='replace');frames[name] = len(text.splitlines())
        enums.update(re.findall(r'''(?:@)?["']([A-Za-z][A-Za-z0-9_]{1,95})["']''', text))
    return enums, frames


def diagnostics(terminal, catalog):
    terminal = obj(terminal);enums, known_frames = catalog
    detail = obj(terminal.get('diagnostic'))
    result = {key: detail.get(key,terminal.get(key)) if isinstance(detail.get(key,terminal.get(key)), str) and detail.get(key,terminal.get(key)) in enums else None
        for key in ('code', 'native_error_code', 'stage', 'step_failure_code')}
    frames = []
    stack = terminal.get('error_stack')
    if isinstance(stack, str) and len(stack) <= 32768:
        for name, count in known_frames.items():
            for match in re.finditer(re.escape('/'+name)+r':([1-9][0-9]{0,5}):([1-9][0-9]{0,5})(?=[)\s]|$)', stack):
                line, column = map(int, match.groups())
                if line <= count and column <= 100000:
                    frames.append({'source_file': name, 'line': line, 'column': column})
    for frame in detail.get('frames', []) if isinstance(detail.get('frames'),list) else []:
        frame=obj(frame);names=[name for name in known_frames if frame.get('file') in (name,Path(name).name)]
        if len(names)==1 and type(frame.get('line')) is int and 1 <= frame['line'] <= known_frames[names[0]] and \
                type(frame.get('column')) is int and 1 <= frame['column'] <= 100000:
            frames.append({'source_file':names[0], 'line':frame['line'], 'column':frame['column']})
    result['source_frames'] = frames[:8]
    result['error_name'] = detail.get('error_name') if detail.get('error_name') in ('Error','TypeError','RangeError','SyntaxError','AssertionError') else None
    child=obj(detail.get('descendant'));result['descendant']={'stage':child.get('stage') if child.get('stage') in enums else None,
        'code':child.get('code') if child.get('code') in ('EPERM','EACCES','ENOENT','EINVAL','EAGAIN','ENOMEM','ENOSYS','EMFILE','ENFILE','ERR_ASSERTION') else None,
        'exit':child.get('exit') if type(child.get('exit')) is int and -255<=child['exit']<=255 else None,
        'signal':child.get('signal') if child.get('signal') in ('SIGKILL','SIGTERM','SIGABRT','SIGSEGV') else None}
    result['step_exit'] = detail.get('step_exit') if type(detail.get('step_exit')) is int and -255 <= detail['step_exit'] <= 255 else None
    return result


def team_proof_valid(private, row, source, binaries):
    """Require the actual abandoned generation, native closure and public retry."""
    try:
        file = private/'TEAM_RECOVERY_PROOF.private.json'
        if file.is_symlink() or file.stat().st_size > 4*1024*1024 or row.get('team_recovery_proof_sha256') != sha(file.read_bytes()): return False
        p = legacy.load(file, 4*1024*1024);inputs = legacy.load(private/'TEAM_RECOVERY_INPUTS.json')
        caller = private/'macos-team-recovery-caller.cjs'
        if inputs.get('team_caller_sha256') != sha(fixture.TEAM_CALLER.encode()) or caller.is_symlink() or caller.read_bytes() != fixture.TEAM_CALLER.encode() or \
                inputs.get('updates_disabled') is not True or type(inputs.get('expected_shipping_doctor_steps')) is not int or inputs['expected_shipping_doctor_steps'] != 8: return False
        config = (source/'config.yaml').read_bytes();configured = config.replace(b'updates:\n  enabled: true', b'updates:\n  enabled: false', 1)
        if config.count(b'updates:\n  enabled: true') != 1 or inputs.get('original_config_sha256') != sha(config) or inputs.get('configured_config_sha256') != sha(configured): return False
        if not isinstance(p.get('old_owner_text'), str) or not isinstance(p.get('old_scope_text'), str) or \
                p['old_owner_text'] != p.get('quarantined_owner_text') or p['old_scope_text'] != p.get('quarantined_scope_text') or \
                p.get('old_final_exists') is not False or p.get('lock_absent') is not True: return False
        owner = obj(json.loads(p['old_owner_text']));old_scope = obj(json.loads(p['old_scope_text']))
        report = obj(p.get('retry_report'));out = obj(report.get('value'));new_scope = obj(report.get('scope'))
        owner_binding=obj(owner.get('execution_scope'));lease=obj(owner.get('kernel_lease'))
        if owner.get('schema_version') != 'knowledge-lock-owner.v3' or not isinstance(owner.get('lock_id'),str) or \
                not re.fullmatch(r'[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}',owner['lock_id']) or type(owner.get('pid')) is not int or owner['pid']<=0 or \
                owner.get('publication')!='atomic-directory-noreplace.v1' or lease.get('method')!='owner-inode-lease.v1' or \
                any(not isinstance(lease.get(key),str) or not re.fullmatch(r'[1-9][0-9]{0,39}',lease[key]) for key in ('owner_ino','directory_ino')) or \
                owner_binding.get('schema_version')!='knowledge-command-scope-binding.v1' or owner_binding.get('backend')!='macos_uid_guardian' or \
                owner_binding.get('sha256') != sha(p['old_scope_text'].encode()): return False
        scopes = (old_scope, new_scope);bindings = [obj(value.get('binding')) for value in scopes]
        if any(value.get('schema_version') != 'knowledge-command-scope.v1' or value.get('backend') != 'macos_uid_guardian' for value in scopes) or \
                any(not digest(value.get('attempt_id')) or value.get('descriptor_sha256') != sha(canonical(value.get('descriptor'))) or
                    obj(value.get('descriptor')).get('attempt_id') != value['attempt_id'] for value in bindings) or bindings[0]['attempt_id'] == bindings[1]['attempt_id']: return False
        descriptors=[value['descriptor'] for value in bindings]
        if any(d.get('schema')!='knowledge-macos-writable-descriptor.v1' or d.get('mode')!='admin_writable_workspace.v1' or d.get('stub_wire_version')!='KVS3' or
                type(d.get('task_ruid')) is not int or not 1000000000<=d['task_ruid']<1900000000 for d in descriptors) or descriptors[0]['task_ruid']==descriptors[1]['task_ruid']: return False
        old, new, final = (obj(p.get(key)) for key in ('old_start', 'new_start', 'new_final'))
        if old.get('schema_version') != 'knowledge-team-flow-start.v2' or new.get('schema_version') != 'knowledge-team-flow-start.v2' or \
                final.get('schema_version') != 'knowledge-team-flow-finalization.v2' or not all(isinstance(x.get('run_id'), str) and re.fullmatch(r'TFR-[a-f0-9]{32}', x['run_id']) for x in (old,new)) or \
                old['run_id'] == new['run_id'] or new['run_id'] != final.get('run_id') or new['run_id'] != out.get('run_id') or \
                not digest(new.get('content_sha256')) or final.get('start_sha256') != new['content_sha256'] or \
                any(value.get('flow') != 'doctor' or value.get('retry_of') is not None for value in (old,new,final,out)) or \
                any(old.get(key) != new.get(key) or new.get(key) != final.get(key) or not isinstance(new.get(key),str) or not new[key] for key in ('repo_id','workspace_id','state_root')): return False
        if obj(final.get('release')).get('status') != 'released' or obj(out.get('team_release')).get('status') != 'released' or \
                final.get('final_status') not in ('ok','failed') or final.get('checks_status') != out.get('checks_status') or \
                out.get('checks_status') not in ('ok','failed') or out.get('overall_status') not in ('ok','failed') or \
                row.get('quality_status') != out['checks_status'] or row.get('overall_status') != out['overall_status'] or \
                any(obj(value).get('status') != 'completed' for value in (report.get('cleanup'),out.get('ownership'),out.get('command_cleanup'),out.get('command_authority_cleanup'))) or \
                obj(row.get('terminal')).get('value') != out or obj(row.get('terminal')).get('cleanup') != report.get('cleanup'): return False
        steps = out.get('steps')
        if type(out.get('steps_total')) is not int or out['steps_total'] != 8 or not isinstance(steps,list) or \
                [obj(step).get('command') for step in steps] != list(DOCTOR_STEPS): return False
        events = p.get('team_events')
        if not isinstance(events,list): return False
        acquired = [obj(value) for value in events if obj(value).get('type') == 'lock_acquired' and obj(value).get('lock') == 'flow']
        released = [obj(value) for value in events if obj(value).get('type') == 'lock_released' and obj(value).get('lock') == 'flow']
        if len(acquired) != 2 or acquired[0].get('lock_id') != owner.get('lock_id') or not isinstance(acquired[1].get('lock_id'),str) or \
                not acquired[1]['lock_id'] or acquired[1]['lock_id'] == owner.get('lock_id') or len(released) != 1 or \
                released[0].get('lock_id') != acquired[1]['lock_id'] or released[0].get('released') is not True: return False
        closures = p.get('native_closures')
        if not isinstance(closures,list) or len(closures) != 2: return False
        for value, binding in zip(closures, bindings):
            d = binding['descriptor']
            if not isinstance(value,dict) or value.get('ok') is not True or value.get('schema') != 'knowledge-darwin-scope-observation.v1' or \
                    value.get('status') != 'completed' or value.get('state') != 'closed' or value.get('attempt_id') != binding['attempt_id'] or \
                    value.get('descriptor_sha256') != binding['descriptor_sha256'] or not digest(value.get('observation_nonce')) or \
                    any(value.get(key) is not True for key in ('cleanup_only','capability_qualified','cleanup_observation_current','registry_healthy',
                        'allocation_tuple_verified_current','kernel_membership_zero','admission_closed','spawn_exclusion_acquired','spawn_intents_resolved',
                        'guardian_exit_confirmed','root_child_exit_confirmed','registered_authority_exited','native_scope_closed','clock_healthy')) or \
                    any(value.get(key) is not False for key in ('proof_current','observation_cached','qualification_mode','qa_persistence_gate','active_attempt')) or \
                    any(value.get(key) != d.get(key) or not digest(value.get(key)) for key in ('source_sha256','stub_source_sha256')) or \
                    value.get('source_sha256') != binaries[0]['source_sha256'] or value.get('stub_source_sha256') != binaries[0]['stub_source_sha256'] or \
                    value.get('binary_sha256') != binaries[0]['broker_sha256'] or value.get('stub_binary_sha256') != binaries[0]['stub_sha256']: return False
        return True
    except (OSError, KeyError, TypeError, ValueError, IndexError): return False


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
        for file in sorted(stage.rglob('*'), key=lambda item: item.relative_to(stage).as_posix()):
            if file.is_symlink(): return False
            if file.is_file():
                st = file.stat()
                if st.st_nlink != 1: return False
                physical.append({'path': file.relative_to(stage).as_posix(), 'bytes': st.st_size, 'sha256': sha(file.read_bytes())})
        return physical == members and special.get('package_derivation') == 'exact runtime copy plus fixed QA leaf and compiled source-bound addon'
    except (OSError, KeyError, TypeError, ValueError): return False


def case_projection(row, catalog=None):
    row = obj(row);name = row.get('name');o = obj(row.get('observations'))
    t = obj(row.get('terminal'));value = obj(t.get('value'))
    facts = {key: o.get(key) is True for key in ('exact_actor_exits', 'independent_uid_zero',
        'typed_native_closure', 'automatic_native_cleanup', 'outside_canary_unchanged')}
    facts['no_acceptance_after_cancel'] = o.get('acceptance_after_cancel') is False
    facts['no_external_recovery'] = o.get('external_recovery_requested') is False
    fifo = obj(o.get('fifo_reader'))
    fifo_flags = ('observed', 'target_fifo', 'birth_before', 'birth_after', 'target_stable', 'fd_scan_complete')
    fifo_counts = ('fd_count', 'vnode_count', 'fifo_count', 'exact_read_fd_count', 'errno')
    fifo_diagnostic = {key: fifo.get(key) if type(fifo.get(key)) is bool else None for key in fifo_flags}
    fifo_diagnostic.update({key: fifo.get(key) if type(fifo.get(key)) is int and 0 <= fifo[key] <= 16384 else None for key in fifo_counts})
    if name in ('state_writer_fifo_read_cancel', 'team_flow_controller_death_retry'):
        facts['exact_fifo_inode_and_writer_birth'] = fifo.get('schema') == 'knowledge-macos-qa-fifo-reader.v1' and \
            all(fifo_diagnostic[key] is True for key in fifo_flags) and fifo_diagnostic['exact_read_fd_count'] == 1 and fifo_diagnostic['errno'] == 0 and \
            all(fifo_diagnostic[key] is not None for key in fifo_counts) and \
            fifo_diagnostic['fd_count'] >= fifo_diagnostic['vnode_count'] >= fifo_diagnostic['fifo_count'] >= 1
    count = 2 if name in ('normal_two_flow_steps', 'team_flow_controller_death_retry') else 1
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
    elif name == 'team_flow_controller_death_retry':
        facts.update({key:o.get(key) is True for key in TEAM_FACTS})
        facts.update(no_manual_owner_repair=o.get('manual_owner_repair') is False,
            original_controller_killed=type(row.get('initial_controller_exit_code')) is int and row['initial_controller_exit_code']==-9,
            fresh_public_run_returned=t.get('ok') is True and type(rc) is int and rc==0,
            eight_shipping_steps_executed=type(o.get('fresh_team_steps_executed')) is int and o['fresh_team_steps_executed']==8)
    else: facts['known_case'] = False
    elapsed = row.get('elapsed_ms')
    elapsed = elapsed if type(elapsed) in (int, float) and math.isfinite(elapsed) and 0 <= elapsed <= (360000 if name==CASES[-1] else 240000) else None
    valid = name in CASES and row.get('status') == 'PASS_PHYSICAL_MACOS_WRITABLE' and elapsed is not None and all(facts.values())
    code = t.get('code')
    diagnostic = diagnostics(t, catalog or (SAFE_ERRORS, {}))
    return {'name': name if name in CASES else 'unknown_case', 'status': 'PASS_PHYSICAL_MACOS_WRITABLE' if valid else 'FAIL_OR_INCOMPLETE',
        'facts': facts, 'elapsed_ms': elapsed, 'controller_exit_code': rc if type(rc) is int and -255 <= rc <= 255 else None,
        'error_code': code if isinstance(code, str) and code in (catalog[0] if catalog else SAFE_ERRORS) else None,
        'diagnostic': diagnostic, 'fifo_observation': fifo_diagnostic if name in ('state_writer_fifo_read_cancel', 'team_flow_controller_death_retry') else None,
        'quality_status': row.get('quality_status') if name==CASES[-1] and row.get('quality_status') in ('ok','failed') else None,
        'overall_status': row.get('overall_status') if name==CASES[-1] and row.get('overall_status') in ('ok','failed') else None}


def build(private, source, rc, arch):
    raw = legacy.load(private/'SUMMARY.json');inputs = legacy.load(private/'INPUTS.json')
    special = legacy.load(private/'MACOS_WRITABLE_INPUTS.json')
    rows = raw.get('cases') if isinstance(raw.get('cases'), list) else []
    source_rows = inputs.get('files') if isinstance(inputs.get('files'), list) else []
    exact_source = legacy.input_inventory_valid(source, source_rows)
    catalog = diagnostic_catalog(source, source_rows) if exact_source else (SAFE_ERRORS,{})
    cases = [case_projection(row,catalog) for row in rows]
    exact_cases = len(cases) == len(CASES) and [row['name'] for row in cases] == list(CASES)
    fixture_checks = {
        'exact_case_contract': tuple(fixture.CASES)==CASES,
        'fixed_leaf': special.get('leaf_sha256')==sha(fixture.LEAF.encode()),
        'fixed_caller': special.get('caller_sha256')==sha(fixture.CALLER.encode()),
        'provision_source': special.get('provision_source_sha256')==sha((HERE/'macos-workspace-provision.c').read_bytes()),
        'writable_assets': inputs.get('writable_assets')=={name:sha((HERE/name).read_bytes()) for name in ASSETS},
        'lifecycle_controller': inputs.get('lifecycle_sha256')==sha((HERE/'darwin-production-lifecycle.py').read_bytes()),
        'node_controller': inputs.get('controller_sha256')==sha((HERE/'darwin-production-controller.js').read_bytes()),
        'reference_controller': inputs.get('reference_runner_sha256')==sha((HERE.parent/'reference/qa/darwin-pipeline4/run_pipeline4.py').read_bytes())}
    provision = private/'macos-workspace-provision'
    fixture_checks['provision_binary'] = bool(provision.is_file() and not provision.is_symlink() and
        special.get('provision_binary_sha256') == sha(provision.read_bytes()))
    observer = private/'production-process-observer'
    observer_pin = obj(obj(raw.get('failure_helper_pins')).get('process_observer_pin'))
    fixture_checks['fifo_observer_binary'] = bool(observer.is_file() and not observer.is_symlink() and
        observer.stat().st_nlink == 1 and observer_pin.get('binary_sha256') == sha(observer.read_bytes()) and
        observer_pin.get('source_sha256') == sha((HERE/'darwin-production-process-observer.c').read_bytes()))
    batch = legacy.load(private/'MACOS_SIGNAL_BATCH_INPUTS.json')
    batch_source = private/'macos-exact-signal-batch.c';batch_binary = private/'macos-exact-signal-batch'
    batch_code = next(ast.literal_eval(node.value) for node in ast.walk(ast.parse((HERE/'macos-writable-lifecycle.py').read_text()))
        if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == 'batch_code' for target in node.targets))
    fixture_checks['exact_signal_batch'] = bool(batch_source.is_file() and not batch_source.is_symlink() and
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
    if native:
        for role in ('broker','stub'):
            file=private/(role+'-shipping-01')
            native=bool(native and file.is_file() and not file.is_symlink() and sha(file.read_bytes())==binaries[0][role+'_sha256'])
    addon = obj(raw.get('native_addon'))
    native = native and addon.get('platform') == 'darwin' and addon.get('architecture') == ('x64' if arch == 'x86_64' else 'arm64') and \
        addon.get('schema_version') == 'knowledge-lock-native-binary.v1' and addon.get('napi_version') == 8 and \
        addon.get('binary') == 'lock-publication.node' and \
        addon.get('source_sha256') == sha((source/'tools/native/lock-publication.c').read_bytes()) and digest(addon.get('binary_sha256'))
    fixture_checks['protected_package_derivation'] = bool(package_valid(private, source, source_rows, special, addon, arch))
    exact_fixture = all(fixture_checks.values())
    installed = raw.get('installed_bindings')
    native = native and isinstance(installed, list) and len(installed) == 3 and \
        {obj(row).get('role') for row in installed} == {'broker', 'stub', 'node'} and all(
            digest(obj(row).get('source_sha256')) and row['source_sha256'] == row.get('installed_sha256') and
            (row['role'] == 'node' or row['source_sha256'] == binaries[0][row['role']+'_sha256']) for row in installed)
    for row, projected in zip(rows,cases):
        if projected['name']==CASES[-1]:
            verified=bool(native and exact_source and team_proof_valid(private,obj(row),source,binaries))
            projected['facts']['exact_team_recovery_proof_verified']=verified
            if not verified: projected['status']='FAIL_OR_INCOMPLETE'
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
        match = re.fullmatch(r'\d{3,6}-(compile-(?:macos-workspace-provision|macos-exact-signal-batch|lock-addon|protected-before-addon|shipping-(?:[0-9]{2}-)?(?:broker|stub)|uid-scan|birth-observer|production-process-observer|production-signal))', name) if isinstance(name, str) else None
        if not match: continue
        file = private/(name+'.stderr.raw')
        if file.is_file() and not file.is_symlink() and file.stat().st_size <= 4*1024*1024:
            body = file.read_bytes()
            stages.append({'stage': match[1], 'stderr_bytes': len(body), 'stderr_sha256': sha(body)})
    return {'schema': 'knowledge-macos-writable-public.v2', 'status': 'PASS_PHYSICAL_MACOS_WRITABLE' if passed else 'FAIL_OR_INCOMPLETE',
        'controller_exit_code': rc, 'expected_architecture': arch, 'source_unchanged': raw.get('source_unchanged') is True,
        'cleanup_confirmed': raw.get('cleanup_confirmed') is True, 'exact_case_inventory_verified': bool(exact_cases),
        'exact_source_inventory_verified': bool(exact_source), 'exact_fixture_verified': bool(exact_fixture), 'native_bindings_verified': bool(native),
        'fixture_checks': fixture_checks,
        'cases': cases, 'failure_codes': errors, 'compiler_diagnostics': stages, 'compiled_pairs': binaries if native else [],
        'controller_sha256': sha((HERE/'macos-writable-lifecycle.py').read_bytes()), 'summary_controller_sha256': sha(Path(__file__).read_bytes()),
        'source_inventory_sha256': sha(json.dumps(source_rows, sort_keys=True, separators=(',', ':')).encode()),
        'source_file_count': len(source_rows),
        'workflow_commit': os.environ.get('GITHUB_SHA') if re.fullmatch(r'[a-f0-9]{40}|[a-f0-9]{64}', os.environ.get('GITHUB_SHA', '')) else None,
        'workflow_run_id': os.environ.get('GITHUB_RUN_ID') if re.fullmatch(r'[0-9]{1,30}', os.environ.get('GITHUB_RUN_ID', '')) else None,
        'release_gate_qualified': False, 'scope': 'Seven explicit public writable workspace cases, including a real abandoned Team lock and fresh public restart. Quality results are separate from ownership closure. FIFO read is a real blocked read; SIGSTOP is scheduling suspension. No disk failure, reboot, full-release, or untested watcher claim.'}


def main():
    ap = argparse.ArgumentParser();ap.add_argument('--private', required=True);ap.add_argument('--public', required=True)
    ap.add_argument('--source', required=True);ap.add_argument('--controller-status', type=int, required=True)
    ap.add_argument('--expected-arch', choices=('x86_64', 'arm64'), required=True);a = ap.parse_args()
    public = Path(a.public);public.mkdir(parents=True, exist_ok=False)
    try:
        result = build(Path(a.private), Path(a.source), a.controller_status, a.expected_arch)
    except (OSError, KeyError, TypeError, ValueError, StopIteration):
        result = {'schema': 'knowledge-macos-writable-public.v2', 'status': 'FAIL_OR_INCOMPLETE',
            'failure_codes': ['projection_input_invalid'], 'release_gate_qualified': False}
    (public/'summary.json').write_text(json.dumps(result, indent=2, sort_keys=True)+'\n')
    print(json.dumps({'status':result['status'], 'release_gate_qualified':False}))
    return 0 if result['status'] == 'PASS_PHYSICAL_MACOS_WRITABLE' else 1


if __name__ == '__main__': raise SystemExit(main())
