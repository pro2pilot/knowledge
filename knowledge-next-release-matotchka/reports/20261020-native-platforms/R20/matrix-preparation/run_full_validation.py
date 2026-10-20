#!/usr/bin/env python3
"""Audit-only serial replay of frozen source suites and runtime/source syntax.

This adapts run_candidate_base.py; it does not claim execution of the original
handoff runners. All suite fixtures use the full source checkout. The inventoried bundled
programs are pinned to ZIP bytes, but that is source-context execution, not all
installed-asset operational workflows. Actual ZIP installation is a separate
candidate replay. No production code is altered by this runner.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import sys

from run_candidate_base import (Replay, extract_checked, manifest_digest,
                                sha256_file, source_manifest, utc_now, write_json)


def discover_source_test_files(source):
    """Return current source-only Node test paths; inventory is never frozen."""
    source = Path(source)
    return sorted(file.relative_to(source).as_posix()
                  for file in (source / 'tests').rglob('*')
                  if file.is_file() and
                  (file.name.endswith(('.test.js', '.test.cjs', '.test.mjs')) or
                   file.name.startswith('self-test-') and file.suffix in ('.js', '.cjs', '.mjs')))


def suite_environment_profile(suite_id):
    """Return the one explicit audit-only environment override needed by watchdog."""
    if suite_id == 'additional-native-watchdog-deadline-test':
        return {'KNOWLEDGE_AUDIT_RETAIN_FIXTURES': '1'}
    return {}


def build_suite_inventory(source, bundled_paths, only_suite=None, shard_index=0, shard_count=1):
    """Build the complete current suite inventory without executing product code."""
    source = Path(source)
    suite_inventory = []
    top_tests = sorted((source / 'tools').glob('self-test*.js'))
    bundled_paths = set(bundled_paths)
    for test in top_tests:
        rel = test.relative_to(source).as_posix()
        retention_args = {'self-test-team-mode.js': ['--keep-temp'],
                          'self-test-install-policy.js': ['--keep']}.get(test.name, [])
        suite_inventory.append({
            'id': test.stem, 'files': [rel], 'argv': [rel, *retention_args], 'cwd': '.knowledge',
            'kind': 'bundled-program-in-full-source-fixture' if rel in bundled_paths else 'source-only-program',
            'bundled_test_bytes_identical': rel in bundled_paths,
            'declared_fixture_retention_arguments': retention_args,
        })
    suite_inventory.extend([
        {'id': 'currency-overlay-suite', 'files': ['tests/currency-overlay.test.js', 'tests/currency-maintenance.test.js', 'tests/currency-overlay-review-gaps.test.js'], 'kind': 'source-only-node-test', 'cwd': '.knowledge'},
        {'id': 'portable-source-suite', 'files': ['tests/self-test-transaction-recovery-policy.js', 'tests/self-test-typed-module-scope.js', 'tests/self-test-sync-history-preservation.js'], 'kind': 'source-only-node-test', 'cwd': '.knowledge'},
        {'id': 'docs-contract', 'files': [], 'kind': 'audit-docs-contract', 'cwd': '.', 'argv': ['--test', 'audit-contract/verify-docs.test.cjs']},
        {'id': 'recording-blockers-workflow', 'files': ['tools/self-test-recording-blockers.js'], 'kind': 'bundled-program-workflow-variant', 'cwd': '.knowledge', 'argv': ['tools/self-test-recording-blockers.js', '--workflow-fixture']},
    ])
    grouped_files = {rel for suite in suite_inventory for rel in suite['files']}
    for rel in discover_source_test_files(source):
        if rel in grouped_files:
            continue
        suite_inventory.append({'id': 'additional-' + Path(rel).stem.replace('.', '-'), 'files': [rel],
                                'kind': 'additional-source-only-node-test', 'cwd': '.knowledge'})
    watchdog_rel = 'tests/native-watchdog-deadline.test.js'
    watchdog_file = source / watchdog_rel
    if watchdog_file.is_file() and not any(watchdog_rel in suite['files'] for suite in suite_inventory):
        suite_inventory.append({'id': 'native-watchdog-deadline', 'files': [watchdog_rel],
                                'kind': 'additional-source-only-node-test', 'cwd': '.knowledge'})
    for suite in suite_inventory:
        if 'argv' not in suite:
            suite['argv'] = ['--test', '--test-concurrency=1', *suite['files']]
    all_suite_ids = [suite['id'] for suite in suite_inventory]
    if only_suite:
        if not set(only_suite).issubset(all_suite_ids):
            raise RuntimeError('Unknown explicitly selected suite')
        suite_inventory = [suite for suite in suite_inventory if suite['id'] in only_suite]
    if shard_count < 1 or not 0 <= shard_index < shard_count:
        raise ValueError('Invalid suite shard selection')
    suite_inventory = [suite for index, suite in enumerate(suite_inventory)
                       if index % shard_count == shard_index]
    return {
        'source_top_level_programs': len(top_tests),
        'all_suite_ids': all_suite_ids,
        'self_tests': suite_inventory,
        'native_watchdog_deadline_test': {'path': watchdog_rel, 'present': watchdog_file.is_file(),
                                           'included': any(watchdog_rel in suite['files'] for suite in suite_inventory)},
    }


class FullValidation(Replay):
    def __init__(self, args):
        super().__init__(args.archive, args.output, args.node, args.suite_timeout,
                         args.syntax_timeout, True)
        self.input_source = args.source
        self.input_before = source_manifest(self.input_source)
        self.work = args.work
        self.docs = args.docs
        self.source = self.work / 'snapshots/source/.knowledge'
        self.runtime = self.work / 'snapshots/runtime/.knowledge'
        self.runtime_before = None
        self.suite_inventory = []
        self.current_fixture = None
        self.syntax_expected = 0
        self.fixture_results = []
        self.shard_index = args.shard_index
        self.shard_count = args.shard_count
        self.only_suite = args.only_suite
        self.current_suite_id = None

    def relative(self, file):
        file=Path(file).resolve()
        try: return file.relative_to(self.output).as_posix()
        except ValueError:
            try: return 'work/' + file.relative_to(self.work).as_posix()
            except ValueError: raise ValueError(f'evidence path is outside output and work roots: {file}')

    def environment(self, temp):
        if not temp.is_relative_to(self.work):
            temp = self.work / 'temporary' / 'runtime-probe'
        env, overrides, removed = super().environment(temp)
        # Do not inherit host Git routing or injected Node modules into fixtures.
        for key in list(env):
            if key.upper().startswith('GIT_') or key in ('NODE_OPTIONS', 'NODE_PATH'):
                removed.append(key)
                del env[key]
        overrides.update({
            'PATH': str(self.node.parent) + os.pathsep + os.environ.get('PATH', ''),
            'GIT_CEILING_DIRECTORIES': str(temp),
            'GIT_TERMINAL_PROMPT': '0',
            'KNOWLEDGE_UPDATE_DISABLE_ON_LAUNCH': '1',
        })
        if self.current_fixture:
            overrides.update({
                'KNOWLEDGE_AGENT_ID': 'rc5-platforms-matrix',
                'KNOWLEDGE_AUDIT_SYSTEM_ROOT': str(self.current_fixture / '.knowledge'),
                'KNOWLEDGE_ROUTING_TEST_TMP': str(self.current_fixture / 'tmp/typed-scope'),
                'KNOWLEDGE_TRANSACTION_TEST_TMP': str(self.current_fixture / 'tmp/transaction'),
                'KNOWLEDGE_SYNC_TEST_TMP': str(self.current_fixture / 'tmp/sync-history'),
            })
            # The base runner clears inherited KNOWLEDGE_* values. Add the one
            # explicit audit profile only while launching the watchdog suite.
            overrides.update(suite_environment_profile(self.current_suite_id))
        env.update(overrides)
        return env, overrides, sorted(set(removed))

    def prepare_git_fixture(self, identifier):
        fixture = self.work / identifier[:3]
        self.current_fixture = fixture
        fixture_record = super().prepare_fixture(fixture)
        for action, argv in [('init', ['git', 'init', '--quiet']),
                             ('add', ['git', '-c', 'core.autocrlf=false', 'add', '.knowledge'])]:
            record = self.execute(f'fixture-setup/{identifier}-{action}', argv,
                                  fixture, fixture / 'tmp', 60, 'fixture-setup')
            if record['status'] != 'pass':
                raise RuntimeError(f'Git fixture {action} failed for {identifier}')
        # Preserve the index identity used by any source-inventory tools.
        index = fixture / '.git/index'
        fixture_record['git_index_sha256_before_test'] = sha256_file(index)
        fixture_record['git_setup'] = 'git init --quiet; git -c core.autocrlf=false add .knowledge'
        probe_path = fixture / 'tmp' / 'nongit-isolation-probe'
        probe_path.mkdir()
        probe_code = "const cp=require('child_process');const r=cp.spawnSync('git',['-C',process.argv[1],'rev-parse','--show-toplevel'],{encoding:'utf8',timeout:5000});const ok=!r.error&&r.status===128&&!r.stdout;console.log(JSON.stringify({status:ok?'pass':'fail',expected_git_exit_code:128,actual_git_exit_code:r.status,error:r.error?.code||null,stdout:r.stdout,stderr:r.stderr}));if(!ok)process.exitCode=1;"
        probe = self.execute(f'fixture-setup/{identifier}-git-isolation', [str(self.node), '-e', probe_code, str(probe_path)],
                             fixture, fixture / 'tmp', 30, 'fixture-setup')
        if probe['status'] != 'pass':
            raise RuntimeError(f'Nested fixture Git isolation probe failed for {identifier}')
        return fixture, fixture_record

    def run(self):
        runner_copy = self.output / 'audit-runner'
        runner_copy.mkdir()
        for name in ['run_full_validation.py', 'run_candidate_base.py']:
            shutil.copyfile(Path(__file__).with_name(name), runner_copy / name)
        write_json(self.output / 'input-source-manifest-before.json', self.input_before)
        self.source.parent.mkdir(parents=True)
        shutil.copytree(self.input_source, self.source)
        self.before = source_manifest(self.source)
        if self.before != self.input_before:
            raise RuntimeError('Frozen source snapshot did not match supplied source')
        write_json(self.output / 'source-manifest-before.json', self.before)
        self.extraction = extract_checked(self.archive, self.runtime.parent)
        write_json(self.output / 'archive-extraction.json', self.extraction)
        self.runtime_before = source_manifest(self.runtime)
        write_json(self.output / 'runtime-manifest-before.json', self.runtime_before)
        env = self.node_environment()
        child_probe_code = "const cp=require('child_process');const r=cp.spawnSync(process.execPath,['-e','process.stdout.write(JSON.stringify({ok:true,execPath:process.execPath}))'],{encoding:'utf8',timeout:5000});let p;try{p=JSON.parse(r.stdout)}catch{};const ok=!r.error&&r.status===0&&p?.ok===true&&p?.execPath===process.execPath;console.log(JSON.stringify({status:ok?'pass':'fail',child_exit_code:r.status,child_error:r.error?.code||null,child_stdout:r.stdout,child_stderr:r.stderr}));if(!ok)process.exitCode=1;"
        probe = self.execute('nested-node-preflight', [str(self.node), '-e', child_probe_code],
                             self.output, self.work / 'temporary/nested-node-preflight', 30, 'runtime')
        if probe['status'] != 'pass':
            raise RuntimeError('Nested Node spawnSync preflight failed; product suites not started')
        env.update({
            'schema_version': 'knowledge-full-source-audit-environment.v1',
            'source_input': str(self.input_source),
            'source_input_manifest_sha256': manifest_digest(self.input_before),
            'runner_sha256': sha256_file(Path(__file__).resolve()),
            'base_runner_sha256': sha256_file(Path(__file__).with_name('run_candidate_base.py')),
            'adaptation': 'source fixtures, per-suite Git checkout, source-only suites and docs, dual syntax inventories',
            'work_directory': str(self.work),
            'isolation': 'one external suite worker; fresh complete source copy and independent writable temp per suite',
            'scope': 'dynamically inventoried top-level self-test programs and shipped byte pins, source-only tests, docs contract, recording-blocker workflow variant; source/runtime syntax',
            'fixture_retention': 'runner never deletes suite fixtures; unmodified suites may perform their own declared cleanup',
            'full_release_gate': 'not_run; synthetic flow release inside install-policy is part of isolated tests',
        })
        write_json(self.output / 'environment.json', env)
        top_tests = sorted((self.source / 'tools').glob('self-test*.js'))
        bundled = sorted((self.runtime / 'tools').glob('self-test*.js'))
        bundled_paths = {file.relative_to(self.runtime).as_posix() for file in bundled}
        for test in top_tests:
            rel = test.relative_to(self.source).as_posix()
            if rel in bundled_paths and self.before[rel] != self.runtime_before[rel]:
                raise RuntimeError(f'Shipped/source test byte mismatch: {rel}')
        source_javascript = sorted(file for file in self.source.rglob('*') if file.is_file() and file.suffix in ('.js', '.cjs', '.mjs'))
        runtime_javascript = sorted(file for file in self.runtime.rglob('*') if file.is_file() and file.suffix in ('.js', '.cjs', '.mjs'))
        discovered = build_suite_inventory(self.source, bundled_paths, self.only_suite,
                                           self.shard_index, self.shard_count)
        self.suite_inventory = discovered['self_tests']
        all_suite_ids = discovered['all_suite_ids']
        if self.only_suite or self.shard_index != self.shard_count - 1:
            source_javascript = []
            runtime_javascript = []
        self.inventory = {
            'schema_version': 'knowledge-full-source-audit-inventory.v1',
            'source_files': len(self.before), 'runtime_files': len(self.runtime_before),
            'all_suite_ids': all_suite_ids,
            'explicit_suite_filter': self.only_suite,
            'shard_index': self.shard_index, 'shard_count': self.shard_count,
            'source_top_level_programs': discovered['source_top_level_programs'],
            'bundled_top_level_programs': len(bundled),
            'self_tests': self.suite_inventory,
            'native_watchdog_deadline_test': discovered['native_watchdog_deadline_test'],
            'syntax_checks': [{'root': 'source', 'path': file.relative_to(self.source).as_posix()} for file in source_javascript] +
                             [{'root': 'runtime', 'path': file.relative_to(self.runtime).as_posix()} for file in runtime_javascript],
            'coverage_note': 'program presence and syntax do not imply full operational or live-provider coverage',
        }
        self.syntax_expected = len(source_javascript) + len(runtime_javascript)
        write_json(self.output / 'inventory.json', self.inventory)
        for index, suite in enumerate(self.suite_inventory, 1):
            if (self.output / 'STOP_AFTER_SUITE').exists():
                raise RuntimeError('Audit controller stop requested at suite boundary')
            identifier = f'{index:03d}-{suite["id"]}'
            fixture, fixture_record = self.prepare_git_fixture(identifier)
            if suite['kind'] == 'audit-docs-contract':
                destination = fixture / 'audit-contract/verify-docs.test.cjs'
                destination.parent.mkdir()
                shutil.copyfile(self.docs, destination)
                fixture_record['docs_contract_sha256'] = sha256_file(destination)
            effective_before = source_manifest(fixture / '.knowledge')
            self.current_suite_id = suite['id']
            record = self.execute(f'suites/{identifier}', [str(self.node), *suite['argv']],
                                  fixture / suite['cwd'], fixture / 'tmp', self.suite_timeout, 'self-test')
            effective_after = source_manifest(fixture / '.knowledge')
            changed = [key for key in sorted(set(effective_before) | set(effective_after)) if effective_before.get(key) != effective_after.get(key)]
            after_file = fixture / 'source-manifest-after-test.json'
            write_json(after_file, effective_after)
            record.update(fixture_record)
            record.update({
                'suite': suite, 'source_file_pins': {rel: self.before[rel] for rel in suite['files']},
                'fixture_changed_paths': changed,
                'fixture_source_manifest_after': self.relative(after_file),
                'fixture_preserved': True,
            })
            write_json(self.output / record['result_file'], record)
            self.self_results.append(record)
            self.current_suite_id = None
            self.current_fixture = None
            if (self.output / 'STOP_AFTER_SUITE').exists():
                raise RuntimeError('Audit controller stop requested at suite boundary')
        for kind, root, files in [('source', self.source, source_javascript), ('runtime', self.runtime, runtime_javascript)]:
            for index, file in enumerate(files, 1):
                rel = file.relative_to(root).as_posix()
                identifier = f'{kind}/{index:03d}-{rel.replace("/", "__")}'
                record = self.execute(f'syntax/{identifier}', [str(self.node), '--check', rel],
                                      root, self.work / 'temporary/syntax', self.syntax_timeout, 'syntax')
                self.syntax_results.append(record)

    def finalize(self):
        input_after = source_manifest(self.input_source)
        source_after = source_manifest(self.source) if self.source.is_dir() else None
        runtime_after = source_manifest(self.runtime) if self.runtime.is_dir() else None
        for name, data in [('input-source-manifest-after.json', input_after), ('source-manifest-after.json', source_after), ('runtime-manifest-after.json', runtime_after)]:
            if data is not None:
                write_json(self.output / name, data)
        archive_after, node_after = sha256_file(self.archive), sha256_file(self.node)
        identities = {
            'source_input_unchanged': input_after == self.input_before,
            'source_snapshot_unchanged': self.before is not None and source_after == self.before,
            'runtime_snapshot_unchanged': self.runtime_before is not None and runtime_after == self.runtime_before,
            'archive_unchanged': archive_after == self.archive_sha256_before,
            'node_binary_unchanged': node_after == self.node_sha256_before,
        }
        counts = lambda rows: {'total': len(rows), 'passed': sum(row['status'] == 'pass' for row in rows), 'failed': sum(row['status'] == 'fail' for row in rows), 'partial': sum(row['status'] == 'partial' for row in rows)}
        complete = len(self.self_results) == len(self.suite_inventory) and len(self.syntax_results) == self.syntax_expected
        passed = self.inventory is not None and self.fatal_error is None and complete and all(identities.values()) and all(row['status'] == 'pass' for row in self.command_results)
        partial_only = not passed and self.inventory is not None and self.fatal_error is None and complete and all(identities.values()) and all(row['status'] in ('pass','partial') for row in self.command_results)
        result = {
            'schema_version': 'knowledge-full-source-audit-replay.v1',
            'status': 'pass' if passed else 'partial' if partial_only else 'fail', 'started_at': self.started_at, 'finished_at': utc_now(),
            'fatal_error': self.fatal_error, **identities,
            'archive_sha256_before': self.archive_sha256_before, 'archive_sha256_after': archive_after,
            'node_binary_sha256_before': self.node_sha256_before, 'node_binary_sha256_after': node_after,
            'input_source_manifest_sha256_before': manifest_digest(self.input_before),
            'input_source_manifest_sha256_after': manifest_digest(input_after),
            'source_snapshot_manifest_sha256_before': manifest_digest(self.before) if self.before is not None else None,
            'source_snapshot_manifest_sha256_after': manifest_digest(source_after) if source_after is not None else None,
            'runtime_snapshot_manifest_sha256_before': manifest_digest(self.runtime_before) if self.runtime_before is not None else None,
            'runtime_snapshot_manifest_sha256_after': manifest_digest(runtime_after) if runtime_after is not None else None,
            'self_tests': {**counts(self.self_results), 'expected': len(self.suite_inventory), 'not_run': len(self.suite_inventory) - len(self.self_results)},
            'syntax_checks': {**counts(self.syntax_results), 'expected': self.syntax_expected, 'not_run': self.syntax_expected - len(self.syntax_results)},
            'commands': self.command_results,
            'original_handoff_runner_executed': False,
            'offline_auto_updates': True,
            'scope': 'full source-context suite replay; installed-asset smoke recorded separately; no full release gate or live providers',
        }
        write_json(self.output / 'replay-results.json', result)
        print(json.dumps({key: result[key] for key in ['status', 'self_tests', 'syntax_checks', 'fatal_error', *identities]}, ensure_ascii=False), flush=True)
        return 0 if passed else 1


def main():
    def cancel(signum, frame):
        raise KeyboardInterrupt(f'outer cancellation signal {signum}')
    signal.signal(signal.SIGTERM, cancel)
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['source', 'archive', 'node', 'docs', 'output', 'work']:
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--suite-timeout', type=int, default=300)
    parser.add_argument('--syntax-timeout', type=int, default=30)
    parser.add_argument('--shard-index', type=int, default=0)
    parser.add_argument('--shard-count', type=int, default=1)
    parser.add_argument('--only-suite', action='append', default=[])
    args = parser.parse_args()
    if not 0 <= args.shard_index < args.shard_count <= 8:
        parser.error('Require 0 <= shard-index < shard-count <= 8')
    for name in ['source', 'archive', 'node', 'docs']:
        setattr(args, name, getattr(args, name).resolve(strict=True))
    for name in ['output', 'work']:
        directory = getattr(args, name).resolve()
        if directory.exists() and any(directory.iterdir()):
            parser.error(f'--{name} must be new or empty')
        directory.mkdir(parents=True, exist_ok=True)
        setattr(args, name, directory)
    replay = FullValidation(args)
    try:
        replay.run()
    except (Exception, KeyboardInterrupt) as error:
        replay.fatal_error = f'{type(error).__name__}: {error}'
    return replay.finalize()


if __name__ == '__main__':
    sys.exit(main())
