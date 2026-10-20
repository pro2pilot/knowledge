#!/usr/bin/env python3
"""Read-only, fail-closed collector for one frozen POSIX matrix cell.

Raw command records, their physical result files and raw streams are authority.
No historical overlays, reruns, cleanup, product edits or inferred test PASS.
"""
from __future__ import annotations
import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import stat
import zipfile
import sys


class EvidenceError(ValueError):
    pass


def need(condition, message):
    if not condition:
        raise EvidenceError(message)


def physical(path):
    name=str(path)
    if os.name=='nt' and name.startswith('\\\\?\\UNC\\'):
        name='\\\\'+name[8:]
    elif os.name=='nt' and name.startswith('\\\\?\\'):
        name=name[4:]
    path = Path(os.path.abspath(os.path.normpath(name)))
    if os.name == 'nt' and not str(path).startswith('\\\\?\\'):
        path = Path('\\\\?\\UNC\\'+str(path)[2:] if str(path).startswith('\\\\') else '\\\\?\\' + str(path))
    return path


def pin(path):
    data = physical(path).read_bytes()
    return {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}


def reparse(path):
    path=physical(path)
    info=path.lstat()
    return stat.S_ISLNK(info.st_mode) or bool(getattr(info,'st_file_attributes',0) & getattr(stat,'FILE_ATTRIBUTE_REPARSE_POINT',0x400)) or bool(getattr(path,'is_junction',lambda:False)())


def pairs(rows):
    out = {}
    for key, value in rows:
        need(key not in out, 'duplicate JSON key: ' + key)
        out[key] = value
    return out


def decode(data):
    return json.loads(data, object_pairs_hook=pairs,
                      parse_constant=lambda value: (_ for _ in ()).throw(EvidenceError('nonfinite JSON: ' + value)))


def load(path):
    return decode(physical(path).read_text(encoding='utf-8-sig'))


def digest(value):
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True,
                                    separators=(',', ':')).encode('utf-8')).hexdigest()


def relative_name(value):
    need(isinstance(value, str) and bool(value) and '\\' not in value and ':' not in value,
         'invalid portable relative path')
    path = PurePosixPath(value)
    need(not path.is_absolute() and '..' not in path.parts and str(path) == value,
         'unsafe/noncanonical relative path: ' + value)
    return path


def inside(root, value):
    rel = relative_name(value)
    root = physical(root)
    need(not reparse(root),'linked evidence root')
    root=root.resolve(strict=True)
    candidate = root.joinpath(*rel.parts)
    current = root
    for part in rel.parts:
        current = current / part
        need(not reparse(current), 'linked evidence: ' + value)
    candidate = candidate.resolve(strict=True)
    need(candidate.is_relative_to(root) and candidate.is_file(), 'missing/escaped evidence: ' + value)
    return candidate


def tree(root):
    root = physical(root)
    need(root.is_dir() and not reparse(root), 'missing/linked source tree')
    out = {}
    for current, dirs, files in os.walk(root, followlinks=False):
        for name in dirs:
            need(not reparse(Path(current) / name), 'linked source directory')
        for name in files:
            path = Path(current) / name
            need(not reparse(path) and path.is_file(), 'nonregular source')
            out[path.relative_to(root).as_posix()] = pin(path)
    need(out, 'empty source manifest')
    return out


def archive_manifest(archive):
    out, folded = {}, set()
    with zipfile.ZipFile(physical(archive)) as handle:
        for item in handle.infolist():
            name = item.filename.rstrip('/')
            relative_name(name)
            need(name == '.knowledge' or name.startswith('.knowledge/'), 'wrong ZIP root')
            if item.is_dir():
                continue
            rel = name[len('.knowledge/'):]
            relative_name(rel)
            need(rel.casefold() not in folded, 'duplicate ZIP member')
            folded.add(rel.casefold())
            data = handle.read(item)
            out[rel] = {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
    need(out, 'empty runtime ZIP')
    return out


def manifest(value):
    need(isinstance(value, dict) and value, 'missing/empty manifest')
    for name, value_pin in value.items():
        relative_name(name)
        need(isinstance(value_pin, dict) and set(value_pin) == {'bytes', 'sha256'}, 'bad manifest pin schema')
        need(type(value_pin['bytes']) is int and value_pin['bytes'] >= 0 and
             isinstance(value_pin['sha256'], str) and re.fullmatch('[0-9a-f]{64}', value_pin['sha256']), 'bad manifest pin')
    return value


def stamp(value):
    need(isinstance(value, str), 'missing timestamp')
    result = datetime.fromisoformat(value.replace('Z', '+00:00'))
    need(result.tzinfo is not None, 'timestamp lacks timezone')
    return result


def derive_suites(source):
    programs = sorted(p for p in source if p.startswith('tools/') and p.count('/') == 1 and
                      Path(p).name.startswith('self-test') and p.endswith('.js'))
    need(programs, 'no self-test programs')
    suites = []
    for name in programs:
        args = {'self-test-team-mode.js': ['--keep-temp'], 'self-test-install-policy.js': ['--keep']}.get(Path(name).name, [])
        suites.append({'id': Path(name).stem, 'files': [name], 'cwd': '.knowledge', 'argv': [name, *args]})
    groups = [
        ('currency-overlay-suite', ['tests/currency-overlay.test.js', 'tests/currency-maintenance.test.js', 'tests/currency-overlay-review-gaps.test.js']),
        ('portable-source-suite', ['tests/self-test-transaction-recovery-policy.js', 'tests/self-test-typed-module-scope.js', 'tests/self-test-sync-history-preservation.js'])]
    for identifier, files in groups:
        need(all(file in source for file in files), 'required grouped suite missing')
        suites.append({'id': identifier, 'files': files, 'cwd': '.knowledge', 'argv': ['--test', '--test-concurrency=1', *files]})
    suites.extend([
        {'id': 'docs-contract', 'files': [], 'cwd': '.', 'argv': ['--test', 'audit-contract/verify-docs.test.cjs']},
        {'id': 'recording-blockers-workflow', 'files': ['tools/self-test-recording-blockers.js'], 'cwd': '.knowledge', 'argv': ['tools/self-test-recording-blockers.js', '--workflow-fixture']}])
    grouped = {file for suite in suites for file in suite['files']}
    for name in sorted(p for p in source if p.startswith('tests/') and
                       (p.endswith(('.test.js', '.test.cjs', '.test.mjs')) or
                        Path(p).name.startswith('self-test-') and Path(p).suffix in ('.js', '.cjs', '.mjs'))):
        if name not in grouped:
            suites.append({'id': 'additional-' + Path(name).stem.replace('.', '-'), 'files': [name],
                           'cwd': '.knowledge', 'argv': ['--test', '--test-concurrency=1', name]})
    need(len({s['id'] for s in suites}) == len(suites), 'duplicate derived suite identity')
    need('tests/native-watchdog-deadline.test.js' in grouped or any('tests/native-watchdog-deadline.test.js' in s['files'] for s in suites), 'watchdog suite missing')
    return suites


def derive_syntax(source,runtime):
    # WindowsPath sorts components, not slash-joined strings. In particular,
    # external/pinecone.js precedes external-memory-status.js in the runner.
    key=lambda name:tuple(part.lower() for part in PurePosixPath(name).parts)
    return [{'root':root,'path':name} for root,files in [('source',source),('runtime',runtime)]
            for name in sorted(files,key=key) if Path(name).suffix in ('.js','.cjs','.mjs')]


def trust_transaction_outcomes(value):
    """Fixed candidate schema: blocked is the expected negative-test outcome.

    Re-read frozen self-test-trust-transaction.js before changing this profile.
    Deliberately do not recursively classify nested diagnostic status values.
    """
    pre=['after_initial_manifest','after_stage_0','after_stage_1','after_stage_2','after_prepare_manifest']
    post=['after_commit_marker','after_promote_0','after_promote_1','after_promote_2','after_committed_manifest']
    blocked={
        'tampered_backup':('transaction_backup_corrupt',{'targets_mutated':0}),
        'invalid_marker':('transaction_commit_marker_invalid',{'targets_mutated':0}),
        'marker_identity_mismatch':('transaction_commit_marker_invalid',{'targets_mutated':0}),
        'manifest_hash_mismatch':('transaction_manifest_hash_mismatch',{'targets_mutated':0}),
        'late_staged_corruption':('transaction_staged_corrupt',{'targets_mutated':0}),
        'journal_path_escape':('transaction_manifest_invalid',{'targets_mutated':0}),
        'precommit_target_drift':('transaction_precommit_target_drift',{'recovery_writes':0}),
        'post_intent_target_drift':('transaction_recovery_target_drift',{'recovery_writes':0}),
        'duplicate_target':('transaction_duplicate_target',{'target_mutated':False}),
        'untrusted_containment':('transaction_containment_untrusted',{'outside_target_mutated':False}),
        'terminal_status_tamper':('transaction_manifest_invalid',{'targets_mutated':0}),
        'reserved_transaction_id':('transaction_id_reserved',{'target_mutated':False}),
        'guarded_read_set_drift':('transaction_guard_drift',{'target_mutated':False}),
        'guarded_recovery_drift':('transaction_guard_drift',{'recovery_action':'rolled_back_guard_drift','target_mutated':False}),
        'junction_containment_root':('transaction_reparse_path',{})}
    integrity={name:{'status':'blocked','error_code':error,**details} for name,(error,details) in blocked.items()}
    integrity.update({
        'transaction_intent_replay':{'status':'blocked','body_error_code':'transaction_intent_mismatch','target_error_code':'transaction_intent_mismatch','identical_replay_idempotent':True},
        'rolled_back_retry_archive':{'status':'pass','retry_committed':True,'archived_attempts':1,'subsequent_recovery_idempotent':True},
        'missing_guard_transition':{'status':'pass','appeared_outside_transaction':'blocked','appeared_error_code':'transaction_guard_drift','bound_write_committed':True}})
    expected=[{'fault_at':point,'recovered':'restored_old_state','final_state':'old'} for point in pre]
    expected += [{'fault_at':point,'recovered':'already_committed' if point=='after_committed_manifest' else 'completed_commit','final_state':'new'} for point in post]
    expected += [{'junction_reparse':{'status':'blocked','error_code':'transaction_reparse_path'}},{'integrity':integrity}]
    need(digest(value.get('checks'))==digest(expected),'trust transaction outcome contract mismatch')
    for key,wanted in {'fault_injection_points':10,'partial_state_recoveries':10,'integrity_tamper_checks':18,'mixed_states':0}.items():
        need(type(value.get(key)) is int and value[key]==wanted,'trust transaction counter mismatch')
    need(value.get('fixture_cleaned') is True,'trust transaction fixture cleanup not confirmed')


def wiki_structural_outcomes(value):
    """These row status values are observed wiki states, not test verdicts."""
    broken='structurally_broken';warning='usable_with_warnings'
    names=[('doctor_aggregate_override',broken),('correct','healthy'),('broken',broken),('duplicate',warning),('orphan',warning),('multiple',broken),
           ('lint_healthy_graph_broken',broken),('lint_warning_graph_healthy',warning),('lint_broken_graph_healthy',broken),
           ('graph_broken_edges_array_without_summary',broken),('same_generated_at_broken_graph_wins',broken),('backwards_timestamp_broken_graph_wins',broken),('older_lint_broken_status_wins',broken)]
    prefix=[{'name':name,'structural_status':status,'status':status} for name,status in names]
    prefix += [{'name':'strict_healthy_exit','observed_process_exit':0},{'name':'strict_broken_exit','observed_process_exit':2},
               {'name':'repaired','structural_status':'healthy','status':'healthy'}]
    rows=value.get('checks')
    need(isinstance(rows,list) and len(rows)==len(prefix)+1 and digest(rows[:-1])==digest(prefix),'wiki structural expected outcome mismatch')
    last=rows[-1]
    expected={'name':'cross_consumer_divergence_fail_closed','routing':'knowledge-routing-bootstrap.v1','doctor':broken,'inspector':broken,'pr_summary':broken,'field_report':broken}
    need(isinstance(last,dict) and set(last)==set(expected)|{'checkpoints'} and all(last.get(k)==v for k,v in expected.items()),'wiki cross-consumer outcome mismatch')
    checkpoints=last['checkpoints'];identities=['A-manual-broken-graph','B-after-routing','C-after-doctor','D-after-inspector','E-after-pr-summary','F-after-field-report']
    need(isinstance(checkpoints,list) and len(checkpoints)==len(identities),'wiki checkpoint inventory mismatch')
    for checkpoint,identifier in zip(checkpoints,identities):
        fields={'checkpoint','expected','actual','pass','state_root','system_root','target_root','artifacts'}
        need(isinstance(checkpoint,dict) and set(checkpoint)==fields and checkpoint['checkpoint']==identifier and checkpoint['expected']==checkpoint['actual']==broken and checkpoint['pass'] is True,'wiki checkpoint not confirmed')
        need(checkpoint['state_root']==checkpoint['system_root'] and all(type(checkpoint[k]) is str and checkpoint[k] for k in ('state_root','system_root','target_root')),'wiki checkpoint root schema')
        artifacts=checkpoint['artifacts'];need(isinstance(artifacts,list) and artifacts,'wiki checkpoint artifacts missing')
        for artifact in artifacts:
            need(isinstance(artifact,dict) and type(artifact.get('exists')) is bool,'wiki artifact existence schema')
            relative_name(artifact.get('path'))
            if artifact['exists']:
                need(type(artifact.get('size')) is int and artifact['size']>=0 and isinstance(artifact.get('sha256'),str) and re.fullmatch('[0-9a-f]{64}',artifact['sha256']),'wiki artifact pin schema')


def json_outcome(value, suite_id=None):
    need(isinstance(value, dict) and value, 'empty/nonobject JSON self-test')
    need(value.get('status') in ('pass', 'passed', 'ok'), 'nonpassing/missing JSON test status')
    if 'ok' in value:
        need(type(value['ok']) is bool and value['ok'], 'JSON ok is not true')
    meaningful = False
    if suite_id=='self-test-wiki-structural-status':
        wiki_structural_outcomes(value)
        return 'pass'
    if value.get('schema_version')=='knowledge-trust-transaction-test.v1':
        need(suite_id in (None,'self-test-trust-transaction'),'trust schema in unrelated suite')
        trust_transaction_outcomes(value)
        return 'pass'
    for key in ('failed', 'tests_failed', 'checks_failed', 'checks_blocked', 'cancelled', 'todo', 'skipped', 'blocked'):
        if key in value:
            # Actual self-test-doctor-audit schema uses a list of skipped names.
            if key=='skipped' and value.get('network')=='disabled_in_all_fixtures' and type(value.get('commands_executed')) is int:
                need(type(value[key]) is list and not value[key], 'Doctor audit skipped checks')
            else:
                need(type(value[key]) is int and value[key]==0, 'invalid/nonzero JSON failure counter: ' + key)
    for key in ('passed','tests_passed','checks_passed'):
        if key in value:need(type(value[key]) is int and value[key]>=0,'invalid JSON passed counter: '+key)
    for total, passed_keys in [('total', ['passed']), ('tests_total', ['tests_passed']), ('checks_total', ['checks_passed','passed'])]:
        if total in value:
            need(type(value[total]) is int and value[total] > 0, 'empty/invalid JSON total')
            meaningful = True
            present=[key for key in passed_keys if key in value]
            need(present or total=='checks_total' and isinstance(value.get('checks'),list) and len(value['checks'])==value[total], 'missing matching JSON passed counter/outcomes')
            for passed in present:
                need(value[passed] == value[total], 'JSON counter mismatch')
    for key in ('checks', 'results', 'tests'):
        if key in value:
            if key=='checks' and isinstance(value[key],dict):
                fields={'stale_history_cleared','current_risk_tiers_match_trust_report','repaired_modules_leave_current_risk','referenced_modules_and_paths_exist','critical_path_projection_matches_source'}
                need(suite_id in (None,'self-test-handoff-current-state') and value.get('schema_version')=='3.4.4' and set(value[key])==fields and all(type(v) is bool and v for v in value[key].values()),'unrecognized/nonpassing boolean checks map')
                meaningful=True
                continue
            need(isinstance(value[key], list) and value[key], 'empty/invalid JSON outcomes')
            meaningful = True
            if key == 'checks' and 'checks_total' in value:
                need(len(value[key]) == value['checks_total'], 'JSON check inventory mismatch')
            for row in value[key]:
                need(isinstance(row, (str, dict)) and bool(row), 'empty JSON outcome row')
                if isinstance(row, dict):
                    acknowledged=False
                    for field in ('status','outcome'):
                        if field in row:
                            need(type(row[field]) is str and row[field] in ('pass','passed','ok'),'nonpassing/unknown JSON row '+field)
                            acknowledged=True
                    for field in ('ok','pass','success'):
                        if field in row:
                            need(type(row[field]) is bool and row[field] is True,'nonpassing/invalid JSON row '+field)
                            acknowledged=True
                    need(acknowledged,'unrecognized opaque JSON outcome row')
                    need('recovered' not in row,'recovery outcome requires recognized suite schema')
                    if 'signal' in row:need(row['signal'] is None,'JSON outcome process signal')
                    if 'exit' in row:need(type(row['exit']) is int and row['exit']==0,'JSON outcome nonzero/invalid exit')
    if type(value.get('matrix_cases')) is int and value['matrix_cases'] > 0:
        meaningful = True
    need(meaningful, 'JSON self-test has no executed checks')
    return 'pass'


def tap_outcome(body):
    lines = body.splitlines()
    need(lines and lines[0] == 'TAP version 13', 'TAP header missing')
    plans = re.findall(r'^1\.\.(\d+)\s*$', body, re.MULTILINE)
    need(len(plans) == 1 and int(plans[0]) > 0, 'TAP final plan missing/empty/duplicate')
    counts = {}
    for key, value in re.findall(r'^# (tests|suites|pass|fail|cancelled|skipped|todo) (\d+)\s*$', body, re.MULTILINE):
        need(key not in counts, 'duplicate TAP counter')
        counts[key] = int(value)
    need(set(counts)-{'suites'} == {'tests', 'pass', 'fail', 'cancelled', 'skipped', 'todo'} and counts['tests'] > 0, 'TAP counters missing/empty')
    need(counts['tests'] == sum(counts[key] for key in ('pass', 'fail', 'cancelled', 'skipped', 'todo')), 'TAP totals inconsistent')
    top_results = [int(n) for n in re.findall(r'^(?:not )?ok\s+(\d+)(?:\s|$)', body, re.MULTILINE)]
    # Node's multi-file runner can restart ordinals for file-wrapper tests after
    # another file's node:test rows; physical portable-source-suite does this.
    need(len(top_results)==int(plans[0]) and all(1<=n<=int(plans[0]) for n in top_results), 'TAP top-level result/plan mismatch')
    all_results = re.findall(r'^[ \t]*(?:not )?ok\s+\d+(?:\s|$)', body, re.MULTILINE)
    need(len(all_results) == counts['tests'] + counts.get('suites',0), 'TAP result body/summary mismatch')
    result_lines=re.findall(r'^[ \t]*(?:not )?ok\s+\d+[^\r\n]*',body,re.MULTILINE)
    skipped=sum(bool(re.search(r'\s#\s*SKIP\b',line,re.IGNORECASE)) for line in result_lines)
    todos=sum(bool(re.search(r'\s#\s*TODO\b',line,re.IGNORECASE)) for line in result_lines)
    need(skipped==counts['skipped'] and todos==counts['todo'],'TAP directive/summary mismatch')
    if re.search(r'^\s*Bail out!',body,re.MULTILINE):
        return 'fail'
    if any(counts[key] for key in ('fail', 'cancelled', 'todo')):
        return 'fail'
    if re.search(r'^\s*not ok\b', body, re.MULTILINE):
        return 'fail'
    return 'partial' if counts['skipped'] else 'pass'


def counts(rows):
    counter = Counter(row['derived_status'] for row in rows)
    return {'total': len(rows), 'passed': counter['pass'], 'failed': counter['fail'], 'partial': counter['partial']}


def aggregate(rows):
    need(rows, 'no command results')
    statuses = {row['derived_status'] for row in rows}
    return 'fail' if 'fail' in statuses else 'partial' if 'partial' in statuses else 'pass'


def offline_config(source):
    """Independently reproduce the one declared scalar fixture adaptation."""
    previous=(physical(source)/'config.yaml').read_bytes()
    lines=previous.splitlines(keepends=True)
    headers=[i for i,line in enumerate(lines) if re.fullmatch(rb'updates:[ \t]*(?:#[^\r\n]*)?\r?\n?',line)]
    need(len(headers)==1,'fixture config updates block')
    start=headers[0]+1;end=len(lines)
    for i in range(start,len(lines)):
        if lines[i].strip() and not lines[i].startswith((b' ',b'\t',b'#')):
            end=i;break
    matches=[]
    for i in range(start,end):
        match=re.fullmatch(rb'(?P<prefix>  enabled:[ \t]*)(?P<value>true|false)(?P<suffix>[ \t]*(?:#[^\r\n]*)?\r?\n?)',lines[i])
        if match:matches.append((i,match))
    need(len(matches)==1,'fixture config updates.enabled scalar')
    i,match=matches[0];lines[i]=match['prefix']+b'false'+match['suffix'];current=b''.join(lines)
    metadata={'path':'.knowledge/config.yaml','setting':'updates.enabled','before_value':match['value']==b'true',
              'after_value':False,'before_sha256':hashlib.sha256(previous).hexdigest(),
              'after_sha256':hashlib.sha256(current).hexdigest(),'changed':previous!=current,
              'reason':'Explicit --offline-auto-updates fixture profile; no global network or command mocks'}
    return current,metadata


def collect(run, source, archive, freeze, expected=None):
    run, source, archive = physical(run), physical(source), physical(archive)
    raw_files = {}
    def read(name):
        file = inside(run, name)
        raw_files[name] = pin(file)
        return load(file)
    replay, env, inventory = read('replay-results.json'), read('environment.json'), read('inventory.json')
    need(isinstance(replay, dict) and replay.get('schema_version') == 'knowledge-full-source-audit-replay.v1', 'replay schema')
    need(isinstance(env, dict) and env.get('schema_version') == 'knowledge-full-source-audit-environment.v1', 'environment schema')
    need(isinstance(inventory, dict) and inventory.get('schema_version') == 'knowledge-full-source-audit-inventory.v1', 'inventory schema')
    need(replay.get('fatal_error') is None, 'runner fatal error')
    start, end = stamp(replay.get('started_at')), stamp(replay.get('finished_at'))
    need(start <= end and env.get('started_at') == replay['started_at'], 'run timestamp binding')
    live_source, runtime = tree(source), archive_manifest(archive)
    frozen = load(freeze)
    frozen_source = frozen.get('source', {})
    frozen_archive = frozen.get('archive', {})
    need(frozen.get('schema_version') == 'knowledge-platform-matrix-freeze.v1', 'freeze schema mismatch')
    need(frozen_source.get('files') == len(live_source) and manifest(frozen_source.get('entries')) == live_source, 'frozen source mismatch')
    need(frozen_source.get('manifest_sha256') == digest(live_source), 'freeze source manifest digest mismatch')
    need(frozen_archive.get('bytes') == pin(archive)['bytes'] and frozen_archive.get('sha256') == pin(archive)['sha256'], 'frozen archive pin mismatch')
    need(frozen_archive.get('runtime_entries') == runtime and frozen_archive.get('runtime_manifest_sha256') == digest(runtime), 'frozen runtime inventory mismatch')
    need(physical(env.get('source_input')).resolve() == source.resolve(), 'environment source mismatch')
    need(physical(env.get('archive_path_at_execution')).resolve() == archive.resolve(), 'archive location mismatch')
    need(env.get('parallel_workers') == 1 and inventory.get('shard_index') == 0 and inventory.get('shard_count') == 1 and not inventory.get('explicit_suite_filter'), 'incomplete shard/filter')
    suites = derive_suites(live_source)
    syntax=derive_syntax(live_source,runtime)
    if expected is not None:
        need((len(live_source), len(runtime)) == tuple(expected), 'source/runtime inventory mismatch')
    need(frozen_archive.get('runtime_entries') == runtime, 'frozen runtime inventory mismatch')
    need(frozen_archive.get('runtime_manifest_sha256') == digest(runtime), 'frozen runtime manifest digest mismatch')
    need(inventory.get('source_files') == len(live_source) and inventory.get('runtime_files') == len(runtime), 'recorded file inventory mismatch')
    need(inventory.get('all_suite_ids') == [s['id'] for s in suites], 'all-suite identity mismatch')
    recorded_suites = inventory.get('self_tests')
    need(isinstance(recorded_suites, list) and len(recorded_suites) == len(suites), 'suite inventory incomplete')
    for actual, wanted in zip(recorded_suites, suites):
        need(isinstance(actual, dict) and all(actual.get(k) == v for k, v in wanted.items()), 'suite identity/argv mismatch')
    need(inventory.get('syntax_checks') == syntax, 'syntax inventory mismatch')
    watchdog = inventory.get('native_watchdog_deadline_test')
    need(watchdog == {'path': 'tests/native-watchdog-deadline.test.js', 'present': True, 'included': True}, 'watchdog inventory binding')
    expected_manifests = {'input-source': live_source, 'source': live_source, 'runtime': runtime}
    replay_keys = {'input-source': 'input_source', 'source': 'source_snapshot', 'runtime': 'runtime_snapshot'}
    for kind, wanted in expected_manifests.items():
        before = manifest(read(kind + '-manifest-before.json'))
        after = manifest(read(kind + '-manifest-after.json'))
        need(before == after == wanted, 'physical/recorded manifest mismatch: ' + kind)
        for phase in ('before', 'after'):
            need(replay.get(replay_keys[kind] + '_manifest_sha256_' + phase) == digest(wanted), 'replay manifest digest mismatch: ' + kind)
    need(env.get('source_input_manifest_sha256') == digest(live_source), 'environment source digest mismatch')
    need(frozen_source.get('manifest_sha256') == digest(live_source), 'freeze source manifest digest mismatch')
    work = physical(env.get('work_directory'))
    need(tree(work/'snapshots/source/.knowledge') == live_source and tree(work/'snapshots/runtime/.knowledge') == runtime, 'live snapshots changed')
    archive_pin, node = pin(archive), physical(env.get('node_argument'))
    node_pin = pin(node)
    for phase in ('before', 'after'):
        need(replay.get('archive_sha256_' + phase) == archive_pin['sha256'] and replay.get('node_binary_sha256_' + phase) == node_pin['sha256'], 'archive/node pin mismatch')
    need(env.get('archive_sha256') == archive_pin['sha256'] and env.get('archive_bytes') == archive_pin['bytes'] and env.get('node_binary_sha256') == node_pin['sha256'], 'environment binary pins mismatch')
    need(env.get('node_reported_identity',{}).get('platform') == ('linux' if sys.platform.startswith('linux') else 'darwin'), 'Node platform identity mismatch')
    for flag in ('source_input_unchanged', 'source_snapshot_unchanged', 'runtime_snapshot_unchanged', 'archive_unchanged', 'node_binary_unchanged'):
        need(replay.get(flag) is True, 'runner integrity flag false/missing: ' + flag)
    for name, key in [('run_full_validation.py', 'runner_sha256'), ('run_candidate_base.py', 'base_runner_sha256')]:
        need(pin(inside(run, 'audit-runner/' + name))['sha256'] == env.get(key), 'runner code pin mismatch')
    records = replay.get('commands')
    need(isinstance(records, list) and records, 'missing/empty commands')
    suite_map = {f'suites/{i:03d}-{s["id"]}': s for i,s in enumerate(suites,1)}
    syntax_map = {}
    for root in ('source','runtime'):
        for i,item in enumerate((x for x in syntax if x['root']==root),1):
            syntax_map[f'syntax/{root}/{i:03d}-{item["path"].replace("/","__")}'] = item
    setup_map = {f'fixture-setup/{i:03d}-{s["id"]}-{action}': action for i,s in enumerate(suites,1) for action in ('init','add','git-isolation')}
    names = [row.get('name') if isinstance(row,dict) else None for row in records]
    expected_names = set(suite_map)|set(syntax_map)|set(setup_map)|{'runtime-probe','nested-node-preflight'}
    need(len(names) == len(set(names)) and set(names) == expected_names, 'missing/extra/duplicate command identity')
    physical_results = {p.relative_to(run).as_posix() for p in (run/'commands').rglob('result.json')}
    need(physical_results == {row.get('result_file') for row in records}, 'orphan/missing physical command result')
    derived = []
    stream_pins = []
    fixture_pins=[]
    adapted_config,adaptation=offline_config(source)
    effective_source={**live_source,'config.yaml':{'bytes':len(adapted_config),'sha256':hashlib.sha256(adapted_config).hexdigest()}}
    def fixture_json(reference,expected_path):
        need(isinstance(reference,str) and reference and not PurePosixPath(reference).is_absolute() and ':' not in reference and '\\' not in reference,'invalid fixture reference')
        expected_path=physical(expected_path)
        need(not reparse(work),'linked fixture work root')
        cursor=work
        for part in expected_path.relative_to(work).parts:
            cursor=cursor/part
            need(not reparse(cursor),'linked fixture evidence path')
        rel=relative_name(reference)
        if rel.parts[0]=='work':
            actual=physical(work.joinpath(*rel.parts[1:])).resolve(strict=True)
        else:
            actual=physical(run.joinpath(*rel.parts)).resolve(strict=True)
        expected_path=expected_path.resolve(strict=True)
        need(actual==expected_path and actual.is_file() and not actual.is_symlink(),'fixture reference location mismatch')
        fixture_pins.append({'reference':reference,'physical_path':str(actual).removeprefix('\\\\?\\'),**pin(actual)})
        return load(actual)
    for record in records:
        name = record['name']
        need(read(record.get('result_file')) == record, 'embedded/physical result mismatch: ' + name)
        a,b = stamp(record.get('started_at')),stamp(record.get('finished_at'))
        need(start <= a <= b <= end, 'command timestamp outside run: ' + name)
        need(type(record.get('duration_seconds')) in (int,float) and math.isfinite(record['duration_seconds']) and record['duration_seconds'] >= 0, 'bad command duration')
        command = record.get('command')
        need(isinstance(command,list) and command and all(isinstance(x,str) and x for x in command), 'missing argv')
        contents = {}
        for stream in ('stdout','stderr'):
            need(record.get(stream) == 'commands/' + name + '/' + stream + '.log', 'stream identity mismatch')
            p = inside(run,record[stream]); actual=pin(p)
            need(actual == {'bytes': record.get(stream+'_bytes'),'sha256':record.get(stream+'_sha256')}, 'modified/truncated stream: ' + name)
            contents[stream]=p.read_text(encoding='utf-8-sig')
            stream_pins.append({'path':record[stream],**actual})
        parsed = None
        try: parsed=decode(contents['stdout'])
        except (ValueError,UnicodeError): pass
        if 'parsed_stdout' in record:
            need(parsed is not None and read(record['parsed_stdout']) == parsed,'parsed/raw JSON mismatch')
        need(type(record.get('timed_out')) is bool and (record.get('execution_error') is None or isinstance(record.get('execution_error'),str)), 'execution schema')
        need('exit_code' in record and (type(record['exit_code']) is int or record['exit_code'] is None),'invalid/missing process exit_code')
        if 'signal' in record:need(record['signal'] is None or type(record['signal']) is str and bool(record['signal']),'invalid process signal')
        cleanup_record=record.get('process_cleanup')
        need(not isinstance(cleanup_record,dict) or cleanup_record.get('quarantined') is not True, 'owned process cleanup was quarantined: '+name)
        failed = record['exit_code'] != 0 or record['timed_out'] or record.get('execution_error') is not None or record.get('signal') is not None or record.get('cancelled') is True
        need(record['exit_code'] is not None or failed,'absent process exit without failure')
        status = 'fail' if failed else 'pass'
        if isinstance(parsed,dict) and (parsed.get('status') in ('fail','failed','error') or parsed.get('ok') is False): status='fail'
        if name in suite_map:
            suite=suite_map[name]
            need(record.get('category') == 'self-test' and command == [str(node).removeprefix('\\\\?\\'),*suite['argv']], 'suite command/category mismatch')
            need(record.get('suite') == recorded_suites[list(suite_map).index(name)], 'record suite mismatch')
            need(record.get('source_file_pins') == {p:live_source[p] for p in suite['files']}, 'suite source pins mismatch')
            fixture_root=work/name.split('/')[1][:3]
            metadata=fixture_json(record.get('fixture_manifest'),fixture_root/'fixture-manifest.json')
            need(metadata.get('schema_version')=='knowledge-artifact-replay-fixture.v1' and metadata.get('copied_source_was_byte_identical') is True,'fixture manifest schema/copy binding')
            fixture_ref=relative_name(metadata.get('fixture_root',''))
            metadata_fixture=(work.joinpath(*fixture_ref.parts[1:]) if fixture_ref.parts[0]=='work' else run.joinpath(*fixture_ref.parts)).resolve()
            need(metadata_fixture==fixture_root.resolve(),'fixture root binding')
            need(metadata.get('source_manifest')=='source-manifest-before.json' and metadata.get('source_manifest_sha256')==digest(live_source),'fixture original source binding')
            need(metadata.get('configuration_overrides')==record.get('configuration_overrides')==[adaptation],'undeclared fixture configuration adaptation')
            need(manifest(metadata.get('effective_fixture_manifest'))==effective_source and metadata.get('effective_fixture_manifest_sha256')==digest(effective_source),'effective fixture manifest mismatch')
            need(all(metadata['effective_fixture_manifest'][p]==record['source_file_pins'][p] for p in suite['files']),'effective fixture suite pins mismatch')
            after_fixture=manifest(fixture_json(record.get('fixture_source_manifest_after'),fixture_root/'source-manifest-after-test.json'))
            changed=[p for p in sorted(set(effective_source)|set(after_fixture)) if effective_source.get(p)!=after_fixture.get(p)]
            need(record.get('fixture_changed_paths')==changed and record.get('fixture_preserved') is True,'fixture after/change inventory mismatch')
            need(tree(fixture_root/'.knowledge')==after_fixture,'physical retained fixture differs from after manifest')
            need(physical(record.get('cwd_absolute_at_execution')).resolve()==(fixture_root/suite['cwd']).resolve(),'suite physical cwd mismatch')
            if suite['id']=='docs-contract':
                need(pin(fixture_root/'audit-contract/verify-docs.test.cjs')['sha256']==record.get('docs_contract_sha256'),'docs fixture script pin mismatch')
            if not failed and status!='fail':
                if '--test' in command:
                    need(record.get('output_contract') == 'tap', 'missing TAP contract')
                    status=tap_outcome(contents['stdout'])
                else:
                    need(record.get('output_contract') == 'json', 'missing JSON contract')
                    status=json_outcome(parsed,suite['id'])
        elif name in syntax_map:
            need(record.get('category') == 'syntax' and command == [str(node).removeprefix('\\\\?\\'),'--check',syntax_map[name]['path']], 'syntax command/category mismatch')
        elif name in setup_map:
            need(record.get('category') == 'fixture-setup', 'setup category mismatch')
            if setup_map[name]=='init':need(command == ['git','init','--quiet'], 'fixture init argv')
            if setup_map[name]=='add':need(command == ['git','-c','core.autocrlf=false','add','.knowledge'], 'fixture add argv')
            if setup_map[name]=='git-isolation' and not failed:
                need(isinstance(parsed,dict) and parsed.get('status')=='pass' and parsed.get('actual_git_exit_code')==128 and parsed.get('expected_git_exit_code')==128 and not parsed.get('stdout') and not parsed.get('error'), 'Git isolation probe failed')
        else:
            need(record.get('category')=='runtime' and command[0]==str(node).removeprefix('\\\\?\\'), 'runtime probe command')
            if name=='runtime-probe' and not failed:
                need(parsed == env.get('node_reported_identity') and parsed.get('platform')==('linux' if sys.platform.startswith('linux') else 'darwin') and physical(parsed.get('execPath')).resolve()==node.resolve(), 'runtime identity mismatch')
            elif not failed:
                need(isinstance(parsed,dict) and parsed.get('status')=='pass' and type(parsed.get('child_exit_code')) is int and parsed['child_exit_code']==0 and parsed.get('child_error') is None, 'nested probe failed')
        need(record.get('status')==status, 'raw command status mismatch: ' + name)
        derived.append({'name':name,'category':record['category'],'derived_status':status,
                        'verdict_basis':'process_failure' if failed else 'raw_output_contract'})
    self_rows=[row for row in derived if row['category']=='self-test']; syntax_rows=[row for row in derived if row['category']=='syntax']
    for key,rows,wanted in [('self_tests',self_rows,len(suites)),('syntax_checks',syntax_rows,len(syntax))]:
        need(replay.get(key)=={**counts(rows),'expected':wanted,'not_run':0}, 'runner counter mismatch: ' + key)
    status=aggregate(derived)
    need(replay.get('status')==status, 'runner-status mismatch')
    return {'schema_version':'rc5-posix-matrix-cell-collection.v1','status':status,'created_at':datetime.now(timezone.utc).isoformat(),
            'run_directory':str(run).removeprefix('\\\\?\\'),'revision':frozen.get('release_identity',{}).get('audit_revision'),
            'source_files':len(live_source),'runtime_files':len(runtime),'inventory_suite_count':len(suites),'syntax_inventory_count':len(syntax),
            'self_tests':counts(self_rows),'syntax_checks':counts(syntax_rows),'physical_command_count':len(derived),
            'commands':derived,'raw_stream_pins':stream_pins,'raw_artifact_pins':raw_files,'physical_fixture_manifest_pins':fixture_pins,
            'archive_pin':archive_pin,'node_pin':node_pin,'source_manifest_sha256':digest(live_source),'runtime_manifest_sha256':digest(runtime),
            'all_evidence_integrity_checks_hold':True,'no_historical_overlays':True,'full_release_gate':'not_run',
            'native_containment_capability':'unavailable; POSIX cells do not certify Windows Job Object or native watchdog containment',
            'limitations':['POSIX diagnostic cell only; Windows-native containment remains a release blocker','Partial outcomes remain partial; count and pin checks do not prove operational coverage']}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for flag in ('run','source','archive','freeze','receipt'):parser.add_argument('--'+flag,type=Path,required=True)
    args=parser.parse_args()
    need(not physical(args.receipt).exists(),'refusing to overwrite evidence receipt')
    result=collect(args.run,args.source,args.archive,args.freeze)
    physical(args.receipt).parent.mkdir(parents=True,exist_ok=True)
    physical(args.receipt).write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({key:result[key] for key in ('status','self_tests','syntax_checks','physical_command_count','source_files','runtime_files')},indent=2))
    return 0


if __name__=='__main__':
    try:raise SystemExit(main())
    except (EvidenceError,KeyError,TypeError,ValueError,OSError,zipfile.BadZipFile) as error:
        raise SystemExit('Collection refused: '+type(error).__name__+': '+str(error))
