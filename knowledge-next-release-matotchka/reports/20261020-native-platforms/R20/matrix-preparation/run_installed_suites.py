#!/usr/bin/env python3
"""Prepare/run the ten installed RC5 suites against exact final ZIP bytes.

Run only after the reviewed platform freeze receipt is available. Every suite receives a
fresh copy extracted from the supplied ZIP. Setup and suite argv, raw streams,
stream SHA256s, fixture manifests, Node identity and artifact pins are retained.
"""
import argparse
import hashlib
import json
import os
import shutil
import signal
import sys
from pathlib import Path

import run_candidate_base as audit

MATRIX_FREEZE_SCHEMA = 'knowledge-platform-matrix-freeze.v1'
SUITES = [
    'install-check',
    'self-test-lock-layout-safety',
    'self-test-native-verification-boundaries',
    'self-test-doctor-audit',
    'self-test-team-mode',
    'self-test-team-finalization',
    'self-test-verification-finalization',
    'self-test-watch-runtime-safety',
    'self-test-export-privacy',
    'self-test-agent-footer',
]
SKIPPED = {'skip', 'skipped', 'not_run', 'not-run', 'not run', 'not_executed', 'not-executed',
           'not executed', 'pending', 'blocked'}
PASSED = {'pass', 'passed', 'ok', 'success', 'completed'}
FAILED = {'fail', 'failed', 'error', 'broken', 'degraded', 'unhealthy', 'needs_repair'}


def inspect_suite_json(parsed, suite):
    """Check only the suite result and named semantic rows, never nested evidence."""
    if not isinstance(parsed, dict):
        return ['suite stdout JSON root must be an object']
    errors = []
    root_status = str(parsed.get('status', '')).strip().lower()
    if not root_status:
        errors.append('top-level status is missing')
    elif root_status in SKIPPED:
        errors.append(f'top-level status is non-passing: {root_status}')
    elif root_status in FAILED or root_status not in PASSED:
        errors.append(f'top-level status is not an accepted success: {root_status}')
    for key in ('outcome', 'semantic_outcome'):
        value = parsed.get(key)
        if value is not None and str(value).strip().lower() not in PASSED:
            errors.append(f'top-level {key} is not a success: {value!r}')
    for key in ('ok', 'success', 'semantic_pass'):
        if parsed.get(key) is False:
            errors.append(f'top-level {key}=false')

    # Only these arrays contain suite assertion outcomes. Other nested objects
    # (observations, fixture state, flow logs and expected failure evidence) are data.
    outcome_arrays = [key for key in ('checks', 'results', 'tests') if isinstance(parsed.get(key), list)]
    outcome_count = 0
    for key in outcome_arrays:
        rows = parsed[key]
        outcome_count += len(rows)
        for index, row in enumerate(rows):
            if not isinstance(row, dict):
                continue
            if not any(field in row for field in ('status', 'outcome', 'semantic_outcome')):
                errors.append(f'{key}[{index}] has no explicit semantic outcome field')
            for field in ('status', 'outcome', 'semantic_outcome'):
                value = row.get(field)
                if value is None:
                    continue
                semantic = str(value).strip().lower()
                if semantic in SKIPPED or semantic in FAILED or semantic not in PASSED:
                    errors.append(f'{key}[{index}].{field} is not a success: {value!r}')
            for field in ('ok', 'success', 'semantic_pass'):
                if row.get(field) is False:
                    errors.append(f'{key}[{index}].{field}=false')

    count_fields = ('total', 'checks_total', 'passed', 'checks_passed', 'failed', 'checks_failed',
                    'unexpected_failure_count', 'unexpected_failed_count',
                    'unexpected_semantic_failure_count', 'critical_failed_count')
    counts = {key: parsed[key] for key in count_fields if key in parsed and parsed[key] is not None}
    for key, value in counts.items():
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            errors.append(f'{key} must be a numeric semantic counter')
        elif key in ('total', 'checks_total', 'passed', 'checks_passed') and value <= 0:
            errors.append(f'{key} must be positive')
        elif key in ('failed', 'checks_failed', 'unexpected_failure_count', 'unexpected_failed_count',
                     'unexpected_semantic_failure_count', 'critical_failed_count') and value != 0:
            errors.append(f'{key} must be zero, got {value}')
    if suite != 'install-check' and not counts.get('total') and not counts.get('checks_total') and outcome_count == 0:
        errors.append('self-test JSON has no positive semantic count or outcome rows')
    if suite != 'install-check' and any(key in counts for key in ('total', 'checks_total')) and not any(
            key in counts for key in ('passed', 'checks_passed')) and outcome_count == 0:
        errors.append('declared self-test total has no positive passed counter or outcome rows')
    for total_key in ('total', 'checks_total'):
        if total_key in counts and 'checks' in outcome_arrays and counts[total_key] != len(parsed['checks']):
            errors.append(f'{total_key} does not match checks array length')
    if 'checks' in outcome_arrays and parsed['checks'] and all(
            isinstance(row, dict) and str(row.get('status', '')).strip().lower() in PASSED
            for row in parsed['checks']) and 'checks_passed' in counts:
        if counts['checks_passed'] != len(parsed['checks']):
            errors.append('checks_passed does not match successful checks rows')
    if 'checks' in outcome_arrays and parsed['checks'] and all(
            isinstance(row, dict) and str(row.get('status', '')).strip().lower() in PASSED
            for row in parsed['checks']) and 'passed' in counts:
        if counts['passed'] != len(parsed['checks']):
            errors.append('passed does not match successful checks rows')
    if isinstance(parsed.get('skipped'), list) and parsed['skipped']:
        errors.append(f'top-level skipped list contains {len(parsed["skipped"])} item(s)')
    for key in ('skipped', 'skip_count', 'not_run', 'not_run_count'):
        value = parsed.get(key)
        if isinstance(value, (int, float)) and value > 0:
            errors.append(f'top-level {key} must be zero, got {value}')
    return errors


def checked_execute(replay, name, argv, cwd, temp, timeout, category):
    row = replay.execute(name, [str(part) for part in argv], cwd, temp, timeout, category)
    if category == 'installed-suite':
        parsed_path = replay.output / row['parsed_stdout'] if row.get('parsed_stdout') else None
        if parsed_path is None:
            row['semantic_failures'].append('complete suite JSON output is required')
        else:
            parsed = json.loads(parsed_path.read_text(encoding='utf-8'))
            suite_id = Path(name).name.split('-', 1)[1]
            for error in inspect_suite_json(parsed, suite_id):
                row['semantic_failures'].append(error)
            # Platform truth comes from this controller's real interpreter and
            # the separately pinned Node identity, never from suite fixture data.
            row['actual_platform'] = sys.platform
        if row['semantic_failures']:
            only_skip_errors=all(any(token in error.lower() for token in ('skip','skipped','not_run','not run')) for error in row['semantic_failures'])
            row['status']='partial' if only_skip_errors and row['exit_code']==0 and not row['timed_out'] and row.get('execution_error') is None else 'fail'
            audit.write_json(replay.output / row['result_file'], row)
    return row


def main():
    def cancel(signum, frame):
        raise KeyboardInterrupt(f'outer cancellation signal {signum}')
    signal.signal(signal.SIGTERM, cancel)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', required=True, type=Path)
    parser.add_argument('--expected-archive-sha256', required=True)
    parser.add_argument('--freeze', required=True, type=Path)
    parser.add_argument('--node', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--fixture-root', required=True, type=Path,
                        help='Short, new fixture root such as K:\\q19installed\\suites')
    args = parser.parse_args()
    freeze = json.loads(args.freeze.read_text(encoding='utf-8-sig'))
    if freeze.get('schema_version') != MATRIX_FREEZE_SCHEMA:
        parser.error('freeze receipt schema mismatch')
    release_identity = freeze.get('release_identity', {})
    expected_revision = release_identity.get('audit_revision')
    expected_files = len(freeze.get('archive', {}).get('runtime_entries', {}))
    if not expected_revision or expected_files < 1:
        parser.error('freeze receipt is missing runtime identity or inventory')
    if not args.node.is_absolute():
        parser.error('--node must be an absolute path to the selected Node executable')
    args.archive = args.archive.resolve(strict=True)
    args.node = args.node.resolve(strict=True)
    args.output = args.output.resolve()
    args.fixture_root = args.fixture_root.resolve()
    if sys.platform not in ('linux', 'darwin'):
        raise RuntimeError(f'This matrix controller accepts only Linux/macOS cells; sys.platform={sys.platform!r}')
    if not args.archive.is_file() or not args.node.is_file() or expected_files < 1:
        parser.error('Archive, Node executable and positive expected file count are required')
    if args.output.exists() and (not args.output.is_dir() or any(args.output.iterdir())):
        parser.error('--output must be new or empty; existing evidence is never overwritten')
    if args.fixture_root.exists() and (not args.fixture_root.is_dir() or any(args.fixture_root.iterdir())):
        parser.error('--fixture-root must be new or empty; existing fixtures are never overwritten')
    if args.output == args.fixture_root or args.output in args.fixture_root.parents or args.fixture_root in args.output.parents:
        parser.error('Evidence output and short fixture root must not overlap')
    if args.output == args.archive.parent or args.output in args.archive.parents or args.archive in args.output.parents:
        parser.error('Evidence output must not overlap the candidate archive path')
    if audit.sha256_file(args.archive) != args.expected_archive_sha256.lower() or args.expected_archive_sha256.lower() != freeze.get('archive', {}).get('sha256'):
        raise RuntimeError('Candidate ZIP SHA256 differs from the frozen expected digest')

    args.output.mkdir(parents=True, exist_ok=True)
    replay = audit.Replay(args.archive, args.output, args.node, 180, 30, True)
    original_environment = replay.environment
    def isolated_environment(temp):
        env, overrides, removed = original_environment(temp)
        for key in list(env):
            if key.upper().startswith('GIT_') or key in ('NODE_OPTIONS', 'NODE_PATH'):
                removed.append(key)
                del env[key]
        overrides.update({'KNOWLEDGE_AGENT_ID': 'rc5-platforms-matrix',
                          'KNOWLEDGE_UPDATE_DISABLE_ON_LAUNCH': '1',
                          'KNOWLEDGE_FLOW_NO_OPEN': '1', 'KNOWLEDGE_INSPECTOR_NO_OPEN': '1',
                          'GIT_CEILING_DIRECTORIES': str(temp), 'GIT_TERMINAL_PROMPT': '0',
                          'KNOWLEDGE_DISABLE_GIT_DISCOVERY': '1'})
        env.update(overrides)
        return env, overrides, sorted(set(removed))
    replay.environment = isolated_environment
    original_relative = replay.relative
    fixture_root = args.fixture_root
    def relative_with_short_fixtures(file):
        try:
            return original_relative(file)
        except ValueError:
            return 'short-fixtures/' + Path(file).resolve().relative_to(fixture_root).as_posix()
    replay.relative = relative_with_short_fixtures
    replay.extraction = audit.extract_checked(args.archive, replay.source.parent)
    replay.before = audit.source_manifest(replay.source)
    if len(replay.before) != expected_files:
        raise RuntimeError(f'Installed runtime file count differs: expected {expected_files}, got {len(replay.before)}')
    package = json.loads((replay.source / 'package.json').read_text(encoding='utf-8-sig'))
    release = package.get('knowledge_release', {})
    identity = {'version': package.get('version'), 'candidate_label': release.get('candidate_label'),
                'candidate_name': release.get('candidate_name'), 'audit_revision': release.get('audit_revision')}
    expected_identity = release_identity
    if identity != expected_identity:
        raise RuntimeError(f'ZIP runtime package identity mismatch: {identity!r}')
    if args.archive.name != identity['candidate_name']:
        raise RuntimeError('Candidate archive basename differs from package metadata')
    archive_sha_before = audit.sha256_file(args.archive)
    node_sha_before = audit.sha256_file(args.node)
    controller_path = Path(__file__).resolve()
    controller_sha_before = audit.sha256_file(controller_path)
    helper_path = Path(audit.__file__).resolve()
    helper_sha_before = audit.sha256_file(helper_path)
    audit.write_json(args.output / 'archive-extraction.json', replay.extraction)
    audit.write_json(args.output / 'RUNTIME_BEFORE.json', replay.before)
    audit.write_json(args.output / 'ENVIRONMENT.json', {
        'archive': str(args.archive), 'archive_sha256': archive_sha_before,
        'runtime_root': str(replay.source), 'node': str(args.node), 'node_sha256': node_sha_before,
        'controller': str(controller_path), 'controller_sha256': controller_sha_before,
        'helper': str(helper_path), 'helper_sha256': helper_sha_before, 'package_identity': identity,
        'expected_runtime_files': expected_files, 'freeze_receipt_sha256': audit.sha256_file(args.freeze),
        'platform': sys.platform, 'fixture_root': str(fixture_root),
        'scope': '10 focused installed suites, each on a fresh copy of ZIP-extracted .knowledge; offline fixture override only',
        'full_release_gate': 'not_run', 'provider_setup': 'not_run'})
    shutil.copyfile(Path(__file__), args.output / Path(__file__).name)
    shutil.copyfile(helper_path, args.output / helper_path.name)
    node_identity = replay.node_environment()
    node_reported = node_identity.get('node_reported_identity')
    if not isinstance(node_reported, dict) or node_reported.get('platform') != ('linux' if sys.platform == 'linux' else 'darwin'):
        raise RuntimeError(f'Selected Node runtime does not match the actual POSIX cell: {node_identity!r}')
    if os.path.normcase(os.path.realpath(node_reported.get('execPath', ''))) != os.path.normcase(os.path.realpath(args.node)):
        raise RuntimeError(f'Node execPath differs from the selected absolute executable: {node_identity!r}')
    audit.write_json(args.output / 'NODE_IDENTITY.json', node_identity)

    # Resolve Git once and retain physical argv for isolated fixture setup.
    git = shutil.which('git')
    if not git:
        raise RuntimeError('Git executable is required for isolated installed fixture setup')
    results = []
    workroot_records = []
    fatal = None
    try:
        for index, suite in enumerate(SUITES, 1):
            # Keep the fixture basename numeric and short. Team-mode creates
            # nested Git worktrees below this root; including the suite name
            # can push those legitimate Windows paths past MAX_PATH.
            workroot_name = f'{index:03d}'
            if len(workroot_name) != 3 or not workroot_name.isdecimal():
                raise RuntimeError(f'Installed suite workroot is not a three-digit numeric path: {workroot_name!r}')
            fixture = fixture_root / workroot_name
            workroot_records.append({'suite': suite, 'workroot_name': workroot_name,
                                     'workroot_path': str(fixture)})
            fixture.parent.mkdir(parents=True, exist_ok=True)
            fixture_data = replay.prepare_fixture(fixture)
            installed = fixture / '.knowledge'
            initial = replay.before
            temp = fixture / 'tmp'
            env, overrides, removed = replay.environment(temp)
            for label, argv in [('git-init', [git, 'init', '--quiet']),
                                ('git-add', [git, '-c', 'core.autocrlf=false', 'add', '.knowledge'])]:
                setup = checked_execute(replay, f'setup/{index:03d}-{label}', argv, fixture, temp, 30, 'fixture-setup')
                if setup['status'] != 'pass':
                    raise RuntimeError(f'Fixture setup failed for {suite}: {label}')
            argv = [str(args.node), f'tools/{suite}.js']
            if suite == 'install-check':
                argv.append('--json')
            if suite == 'self-test-team-mode':
                argv.append('--keep-temp')
            row = checked_execute(replay, f'suites/{index:03d}-{suite}', argv, installed, temp, 180, 'installed-suite')
            after = audit.source_manifest(installed)
            row.update({'configuration_override': fixture_data['configuration_overrides'],
                        'copied_from_zip_runtime_byte_identically_before_override': True,
                        'fixture_changed_paths': [p for p in sorted(set(initial) | set(after)) if initial.get(p) != after.get(p)]})
            audit.write_json(args.output / row['result_file'], row)
            results.append(row)
            audit.write_json(args.output / 'PROGRESS.json', results)
    except Exception as error:
        fatal = f'{type(error).__name__}: {error}'

    runtime_after = audit.source_manifest(replay.source)
    archive_after = audit.sha256_file(args.archive)
    node_after = audit.sha256_file(args.node)
    helper_after = audit.sha256_file(helper_path)
    controller_sha_after = audit.sha256_file(controller_path)
    identities = {'archive_unchanged': archive_after == archive_sha_before,
                  'runtime_unchanged': runtime_after == replay.before,
                  'node_unchanged': node_after == node_sha_before,
                  'helper_unchanged': helper_after == helper_sha_before,
                  'controller_unchanged': controller_sha_after == controller_sha_before}
    workroot_layout_ok = (len(workroot_records) == len(SUITES) and
                          len({record['workroot_name'] for record in workroot_records}) == len(SUITES) and
                          all(record['workroot_name'].isdecimal() and len(record['workroot_name']) == 3
                              for record in workroot_records))
    complete = len(results) == len(SUITES) and fatal is None
    passed = (complete and workroot_layout_ok and all(identities.values()) and
              all(row['status'] == 'pass' for row in results))
    partial_only = (complete and workroot_layout_ok and all(identities.values()) and
                    all(row['status'] in ('pass','partial') for row in results) and any(row['status']=='partial' for row in results))
    audit.write_json(args.output / 'RUNTIME_AFTER.json', runtime_after)
    summary = {'schema': 'knowledge-rc5-installed-public-audit.v1', 'status': 'pass' if passed else 'partial' if partial_only else 'fail',
               'completed': complete, 'fatal_error': fatal, 'platform': sys.platform,
               'node_identity': node_identity, 'fixture_root': str(fixture_root), 'package_identity': identity,
               'runtime_files': len(replay.before), 'runtime_archive_sha256': archive_sha_before,
               'controller_sha256': controller_sha_before, 'helper_sha256': helper_sha_before,
               'identities': identities,
               'suites': {'expected': len(SUITES), 'total': len(results),
                          'passed': sum(row['status'] == 'pass' for row in results),
                          'failed': sum(row['status'] == 'fail' for row in results),
                          'partial': sum(row['status'] == 'partial' for row in results)},
               'fixture_layout': {'expected_workroots': len(SUITES),
                                  'numeric_short_names': workroot_layout_ok,
                                  'workroots': workroot_records},
               'suite_ids': SUITES, 'suite_results': results,
               'limits': ['POSIX diagnostic only; 10 focused installed suites, not the full release gate or Windows-native capability.',
                          'Each suite uses a fresh copy of runtime ZIP bytes with only updates.enabled=false recorded as a fixture override.',
                          'Explicit skip/not-run/pending/blocked semantic outcomes fail and cannot count as pass. Native Windows behavior remains untested here.']}
    audit.write_json(args.output / 'SUMMARY.json', summary)
    print(json.dumps({key: summary[key] for key in ('status', 'completed', 'fatal_error', 'identities', 'suites')}), flush=True)
    return 0 if passed or partial_only else 1


if __name__ == '__main__':
    raise SystemExit(main())
