#!/usr/bin/env python3
"""Replay every bundled self-test and syntax-check a frozen .knowledge ZIP.

Usage:
  python run_candidate.py --archive /path/knowledge.zip \
      --output /path/new-replay-directory --node /absolute/path/to/node

No dependencies beyond Python 3.9+ and the explicitly selected Node runtime.
The output directory must be new or empty. Tests run one at a time, each in a
fresh full installed-asset copy with its own writable temporary directory.
Raw stdout/stderr are never truncated. Evidence links are output-relative.
This is an installed-asset audit runner, not the source-only release gate.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shutil
import signal
import stat
import subprocess
import sys
import time
import zipfile


MAX_MEMBERS = 16000
MAX_FILE_BYTES = 32 * 1024 * 1024
MAX_TOTAL_BYTES = 256 * 1024 * 1024


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def sha256_file(file):
    hasher = hashlib.sha256()
    with Path(file).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            hasher.update(block)
    return hasher.hexdigest()


def write_json(file, value):
    file = Path(file)
    file.parent.mkdir(parents=True, exist_ok=True)
    file.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')


def source_manifest(root):
    entries = {}
    for file in sorted(root.rglob('*')):
        if file.is_symlink():
            entries[file.relative_to(root).as_posix()] = {'kind': 'unexpected_symlink'}
        elif file.is_file():
            entries[file.relative_to(root).as_posix()] = {
                'bytes': file.stat().st_size,
                'sha256': sha256_file(file),
            }
    return entries


def manifest_digest(manifest):
    body = json.dumps(manifest, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode('utf-8')
    return hashlib.sha256(body).hexdigest()


def extract_checked(archive, snapshot):
    """Validate the complete namespace before extracting any ZIP member."""
    with zipfile.ZipFile(archive) as package:
        members = package.infolist()
        if not members or len(members) > MAX_MEMBERS:
            raise ValueError('ZIP member count is empty or exceeds the configured safety limit')
        names = {}
        casefold_names = set()
        total = 0
        for item in members:
            raw = item.filename
            if not raw or '\\' in raw or '\x00' in raw or raw.startswith('/'):
                raise ValueError(f'Unsafe ZIP path: {raw!r}')
            parts = raw.rstrip('/').split('/')
            if any(part in ('', '.', '..') or ':' in part for part in parts):
                raise ValueError(f'Noncanonical ZIP path: {raw!r}')
            if parts[0] != '.knowledge':
                raise ValueError(f'ZIP entry is outside the installed .knowledge root: {raw!r}')
            normalized = '/'.join(parts)
            if normalized in names or normalized.casefold() in casefold_names:
                raise ValueError(f'Duplicate or case-colliding ZIP path: {raw!r}')
            names[normalized] = item
            casefold_names.add(normalized.casefold())
            mode = (item.external_attr >> 16) & 0xffff
            kind = stat.S_IFMT(mode)
            if kind not in (0, stat.S_IFREG, stat.S_IFDIR) or stat.S_ISLNK(mode):
                raise ValueError(f'ZIP symlink or special file is not allowed: {raw!r}')
            if item.flag_bits & 1:
                raise ValueError(f'Encrypted ZIP entry is not allowed: {raw!r}')
            if item.file_size < 0 or item.file_size > MAX_FILE_BYTES:
                raise ValueError(f'ZIP member exceeds the uncompressed safety limit: {raw!r}')
            total += item.file_size
            if total > MAX_TOTAL_BYTES:
                raise ValueError('ZIP aggregate uncompressed bytes exceed the safety limit')
        for name, item in names.items():
            ancestors = PurePosixPath(name).parents
            for ancestor in ancestors:
                parent = names.get(ancestor.as_posix())
                if parent is not None and not parent.is_dir():
                    raise ValueError(f'ZIP file/directory prefix collision: {name!r}')
            if name == '.knowledge' and not item.is_dir():
                raise ValueError('The .knowledge root cannot be a regular file')
        snapshot.mkdir(parents=True, exist_ok=False)
        extracted_bytes = 0
        for item in members:
            target = snapshot.joinpath(*item.filename.rstrip('/').split('/'))
            if item.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            written = 0
            # Reading to EOF verifies each member CRC through ZipExtFile.
            with package.open(item) as incoming, target.open('xb') as outgoing:
                while True:
                    block = incoming.read(1024 * 1024)
                    if not block:
                        break
                    written += len(block)
                    if written > item.file_size or written > MAX_FILE_BYTES:
                        raise ValueError(f'ZIP member expanded beyond declared size: {item.filename!r}')
                    outgoing.write(block)
            if written != item.file_size:
                raise ValueError(f'ZIP member size did not match its declaration: {item.filename!r}')
            extracted_bytes += written
        source = snapshot / '.knowledge'
        if not (source / 'package.json').is_file() or not (source / 'tools').is_dir():
            raise ValueError('ZIP is missing .knowledge/package.json or .knowledge/tools')
        return {
            'members': len(members), 'uncompressed_bytes': extracted_bytes,
            'crc_verified_by_full_read': True,
            'safety_limits': {'max_members': MAX_MEMBERS, 'max_file_bytes': MAX_FILE_BYTES, 'max_total_bytes': MAX_TOTAL_BYTES},
        }


def process_group_exists(group):
    try:
        os.killpg(group, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def cleanup_group(process, reason):
    """Terminate remaining owned descendants, including after a normal exit."""
    record = {'reason': reason, 'pid': process.pid, 'actions': []}
    if os.name == 'posix':
        if not process_group_exists(process.pid):
            record['actions'].append('process_group_already_gone')
            return record
        try:
            os.killpg(process.pid, signal.SIGTERM)
            record['actions'].append('SIGTERM_process_group')
        except ProcessLookupError:
            return record
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            process.poll()
            if not process_group_exists(process.pid):
                return record
            time.sleep(0.05)
        if process_group_exists(process.pid):
            try:
                os.killpg(process.pid, signal.SIGKILL)
                record['actions'].append('SIGKILL_process_group')
            except ProcessLookupError:
                pass
    else:
        # Windows taskkill is scoped to the exact process tree created here.
        # This branch is supplied for portability; Linux is the audited host.
        try:
            result = subprocess.run(['taskkill', '/PID', str(process.pid), '/T', '/F'],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
            record['actions'].append({'taskkill_exit_code': result.returncode})
        except (OSError, subprocess.TimeoutExpired) as error:
            record['actions'].append({'taskkill_error': str(error)})
            if process.poll() is None:
                process.kill()
                record['actions'].append('kill_direct_process')
    return record


class Replay:
    def __init__(self, archive, output, node, suite_timeout, syntax_timeout, offline_auto_updates):
        self.archive = archive
        self.output = output
        self.node = node
        self.suite_timeout = suite_timeout
        self.syntax_timeout = syntax_timeout
        self.offline_auto_updates = offline_auto_updates
        self.source = output / 'snapshot/.knowledge'
        self.started_at = utc_now()
        self.archive_sha256_before = sha256_file(archive)
        self.node_sha256_before = sha256_file(node)
        self.command_results = []
        self.self_results = []
        self.syntax_results = []
        self.before = None
        self.inventory = None
        self.extraction = None
        self.fatal_error = None

    def relative(self, file):
        return Path(file).relative_to(self.output).as_posix()

    def environment(self, temp):
        temp.mkdir(parents=True, exist_ok=True)
        inherited = dict(os.environ)
        removed = sorted(key for key in inherited if key.upper().startswith(('KNOWLEDGE_', 'PINECONE_', 'MEM0_')))
        for key in removed:
            inherited.pop(key)
        overrides = {
            'TMPDIR': str(temp), 'TEMP': str(temp), 'TMP': str(temp),
            'KNOWLEDGE_FLOW_NO_OPEN': '1', 'KNOWLEDGE_INSPECTOR_NO_OPEN': '1',
            'BROWSER': 'none',
        }
        inherited.update(overrides)
        return inherited, overrides, removed

    def prepare_fixture(self, fixture):
        installed = fixture / '.knowledge'
        shutil.copytree(self.source, installed)
        manifest = source_manifest(installed)
        if manifest != self.before:
            raise RuntimeError('Fresh fixture copy does not match the frozen source manifest')
        overrides = []
        if self.offline_auto_updates:
            config = installed / 'config.yaml'
            previous = config.read_bytes()
            # Only the documented scalar in the updates block is changed.
            # Preserve all other bytes, including comments and newline style.
            lines = previous.splitlines(keepends=True)
            headers = [index for index, line in enumerate(lines)
                       if re.fullmatch(rb'updates:[ \t]*(?:#[^\r\n]*)?\r?\n?', line)]
            if len(headers) != 1:
                raise ValueError('Offline profile requires exactly one documented config.yaml updates block')
            first = headers[0] + 1
            last = len(lines)
            for index in range(first, len(lines)):
                line = lines[index]
                if line.strip() and not line.startswith((b' ', b'\t', b'#')):
                    last = index
                    break
            matches = []
            for index in range(first, last):
                match = re.fullmatch(rb'(?P<prefix>  enabled:[ \t]*)(?P<value>true|false)(?P<suffix>[ \t]*(?:#[^\r\n]*)?\r?\n?)', lines[index])
                if match:
                    matches.append((index, match))
            if len(matches) != 1:
                raise ValueError('Offline profile requires one updates.enabled boolean using the documented YAML format')
            index, match = matches[0]
            lines[index] = match['prefix'] + b'false' + match['suffix']
            current = b''.join(lines)
            config.write_bytes(current)
            overrides.append({
                'path': '.knowledge/config.yaml', 'setting': 'updates.enabled',
                'before_value': match['value'] == b'true', 'after_value': False,
                'before_sha256': hashlib.sha256(previous).hexdigest(),
                'after_sha256': hashlib.sha256(current).hexdigest(),
                'changed': previous != current,
                'reason': 'Explicit --offline-auto-updates fixture profile; no global network or command mocks',
            })
            manifest['config.yaml'] = {'bytes': len(current), 'sha256': hashlib.sha256(current).hexdigest()}
        record = {
            'schema_version': 'knowledge-artifact-replay-fixture.v1',
            'fixture_root': self.relative(fixture),
            'source_manifest': 'source-manifest-before.json',
            'source_manifest_sha256': manifest_digest(self.before),
            'copied_source_was_byte_identical': True,
            'configuration_overrides': overrides,
            'effective_fixture_manifest_sha256': manifest_digest(manifest),
            'effective_fixture_manifest': manifest,
        }
        manifest_file = fixture / 'fixture-manifest.json'
        write_json(manifest_file, record)
        return {'fixture_manifest': self.relative(manifest_file), 'configuration_overrides': overrides}

    def execute(self, name, command, cwd, temp, timeout, category):
        log_dir = self.output / 'commands' / name
        log_dir.mkdir(parents=True, exist_ok=False)
        stdout_file = log_dir / 'stdout.log'
        stderr_file = log_dir / 'stderr.log'
        environment, overrides, removed = self.environment(temp)
        started_at = utc_now()
        start = time.monotonic()
        process = None
        exit_code = None
        timed_out = False
        execution_error = None
        cleanup = None
        with stdout_file.open('wb') as stdout, stderr_file.open('wb') as stderr:
            try:
                options = {'start_new_session': True} if os.name == 'posix' else {'creationflags': subprocess.CREATE_NEW_PROCESS_GROUP}
                process = subprocess.Popen(command, cwd=str(cwd), env=environment,
                                           stdout=stdout, stderr=stderr, **options)
                try:
                    exit_code = process.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    timed_out = True
                    cleanup = cleanup_group(process, 'timeout')
                    exit_code = process.wait(timeout=10)
                finally:
                    if cleanup is None:
                        cleanup = cleanup_group(process, 'post_command_owned_descendant_cleanup')
                    if process.poll() is None:
                        process.kill()
                        exit_code = process.wait(timeout=10)
            except Exception as error:
                execution_error = f'{type(error).__name__}: {error}'
                if process is not None:
                    cleanup = cleanup_group(process, 'execution_error')
                    try:
                        exit_code = process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        exit_code = process.wait(timeout=10)
        parsed = None
        parsed_valid = False
        parse_error = None
        if stdout_file.stat().st_size:
            try:
                parsed = json.loads(stdout_file.read_text(encoding='utf-8-sig'))
                parsed_valid = True
            except (ValueError, UnicodeError) as error:
                parse_error = f'{type(error).__name__}: {error}'
        semantic_failures = []
        if isinstance(parsed, dict):
            if parsed.get('status') in ('fail', 'failed', 'error'):
                semantic_failures.append(f"reported status={parsed['status']}")
            if parsed.get('ok') is False:
                semantic_failures.append('reported ok=false')
            if isinstance(parsed.get('failed'), int) and parsed['failed'] > 0:
                semantic_failures.append(f"reported failed={parsed['failed']}")
        passed = exit_code == 0 and not timed_out and execution_error is None and not semantic_failures
        record = {
            'name': name, 'category': category, 'command': [str(part) for part in command],
            'cwd': self.relative(cwd), 'cwd_absolute_at_execution': str(cwd),
            'environment_overrides': overrides,
            'cleared_inherited_application_environment_keys': removed,
            'inherited_environment_values': 'not serialized; only declared application overrides are recorded',
            'started_at': started_at, 'finished_at': utc_now(),
            'duration_seconds': round(time.monotonic() - start, 6),
            'timeout_seconds': timeout, 'timed_out': timed_out,
            'exit_code': exit_code, 'execution_error': execution_error,
            'semantic_failures': semantic_failures, 'status': 'pass' if passed else 'fail',
            'stdout': self.relative(stdout_file), 'stderr': self.relative(stderr_file),
            'stdout_bytes': stdout_file.stat().st_size, 'stderr_bytes': stderr_file.stat().st_size,
            'stdout_sha256': sha256_file(stdout_file), 'stderr_sha256': sha256_file(stderr_file),
            'stdout_json_parse_error': parse_error, 'process_cleanup': cleanup,
            'result_file': self.relative(log_dir / 'result.json'),
        }
        if parsed_valid:
            parsed_file = log_dir / 'parsed-stdout.json'
            write_json(parsed_file, parsed)
            record['parsed_stdout'] = self.relative(parsed_file)
            if isinstance(parsed, dict):
                record['reported_summary'] = {key: parsed[key] for key in
                    ('status', 'checks_total', 'total', 'passed', 'failed') if key in parsed}
        write_json(log_dir / 'result.json', record)
        self.command_results.append(record)
        if category != 'syntax' or record['status'] == 'fail':
            print(json.dumps({'name': name, 'status': record['status'], 'exit_code': exit_code,
                              'duration_seconds': record['duration_seconds']}), flush=True)
        return record

    def node_environment(self):
        probe = self.execute('runtime-probe', [str(self.node), '-e',
            'process.stdout.write(JSON.stringify({version:process.version,execPath:process.execPath,platform:process.platform,arch:process.arch}))'],
            self.output, self.output / 'temporary/runtime-probe', 30, 'runtime')
        if probe['status'] != 'pass' or 'parsed_stdout' not in probe:
            raise RuntimeError('Selected absolute Node runtime did not produce the required runtime identity probe')
        identity = json.loads((self.output / probe['parsed_stdout']).read_text(encoding='utf-8'))
        if not isinstance(identity, dict) or not os.path.isabs(str(identity.get('execPath', ''))):
            raise RuntimeError('Node process.execPath is not absolute; physical runtime binding cannot be audited honestly')
        return {
            'schema_version': 'knowledge-artifact-replay-environment.v1',
            'started_at': self.started_at,
            'platform': platform.platform(), 'python_version': platform.python_version(),
            'node_argument': str(self.node), 'node_binary_sha256': self.node_sha256_before,
            'node_reported_identity': identity,
            'runner_sha256': sha256_file(Path(__file__).resolve()),
            'archive_path_at_execution': str(self.archive), 'archive_filename': self.archive.name,
            'archive_sha256': self.archive_sha256_before, 'archive_bytes': self.archive.stat().st_size,
            'parallel_workers': 1, 'suite_timeout_seconds': self.suite_timeout,
            'syntax_timeout_seconds': self.syntax_timeout,
            'isolation': 'fresh full installed copy and independent writable TMPDIR/TEMP/TMP for each suite',
            'offline_auto_updates': self.offline_auto_updates,
            'cleared_inherited_environment_prefixes': ['KNOWLEDGE_', 'PINECONE_', 'MEM0_'],
            'scope': 'bundled self-tests and JavaScript syntax checks; not a maintainer release gate',
        }

    def run(self):
        environment = self.node_environment()
        write_json(self.output / 'environment.json', environment)
        self.extraction = extract_checked(self.archive, self.output / 'snapshot')
        write_json(self.output / 'archive-extraction.json', self.extraction)
        self.before = source_manifest(self.source)
        write_json(self.output / 'source-manifest-before.json', self.before)
        package = json.loads((self.source / 'package.json').read_text(encoding='utf-8-sig'))
        tests = sorted(file for file in self.source.rglob('self-test*.js') if file.is_file())
        javascript = sorted(file for file in self.source.rglob('*.js') if file.is_file())
        if not tests:
            raise ValueError('Archive contains no bundled self-test*.js suites')
        self.inventory = {
            'schema_version': 'knowledge-artifact-replay-inventory.v1',
            'package_name': package.get('name'), 'package_version': package.get('version'),
            'self_tests': [file.relative_to(self.source).as_posix() for file in tests],
            'syntax_checks': [file.relative_to(self.source).as_posix() for file in javascript],
            'npm_self_test_scripts': {key: value for key, value in package.get('scripts', {}).items() if 'self-test' in key},
            'source_only_release_gate_available': (self.source / 'tools/release-gate.js').is_file(),
            'source_only_release_gate_status': 'not_run_by_this_installed_asset_audit_runner',
            'watch_coverage_self_tests': [file.relative_to(self.source).as_posix() for file in tests if 'watch' in file.name],
            'offline_auto_updates': self.offline_auto_updates,
        }
        write_json(self.output / 'inventory.json', self.inventory)
        for index, test in enumerate(tests, 1):
            relative = test.relative_to(self.source).as_posix()
            identifier = f'{index:03d}-{test.stem}'
            fixture = self.output / 'fixtures' / identifier
            fixture_record = self.prepare_fixture(fixture)
            record = self.execute(f'self-tests/{identifier}', [str(self.node), relative],
                                  fixture / '.knowledge', fixture / 'tmp', self.suite_timeout, 'self-test')
            record['source_test'] = relative
            record['source_test_sha256'] = self.before[relative]['sha256']
            record.update(fixture_record)
            write_json(self.output / record['result_file'], record)
            self.self_results.append(record)
        for index, file in enumerate(javascript, 1):
            relative = file.relative_to(self.source).as_posix()
            identifier = f'{index:03d}-{relative.replace("/", "__")}'
            record = self.execute(f'syntax/{identifier}', [str(self.node), '--check', relative],
                                  self.source, self.output / 'temporary/syntax', self.syntax_timeout, 'syntax')
            self.syntax_results.append(record)

    def finalize(self):
        after = source_manifest(self.source) if self.source.is_dir() else None
        if after is not None:
            write_json(self.output / 'source-manifest-after.json', after)
        unchanged = self.before is not None and after == self.before
        changes = []
        if self.before is not None and after is not None:
            changes = [key for key in sorted(set(self.before) | set(after)) if self.before.get(key) != after.get(key)]
        expected_tests = len(self.inventory['self_tests']) if self.inventory else 0
        expected_syntax = len(self.inventory['syntax_checks']) if self.inventory else 0
        archive_after = sha256_file(self.archive)
        node_after = sha256_file(self.node)
        archive_unchanged = archive_after == self.archive_sha256_before
        node_unchanged = node_after == self.node_sha256_before
        counts = lambda rows: {'total': len(rows), 'passed': sum(row['status'] == 'pass' for row in rows), 'failed': sum(row['status'] == 'fail' for row in rows)}
        all_pass = bool(self.inventory) and self.fatal_error is None and unchanged and archive_unchanged and node_unchanged and \
            len(self.self_results) == expected_tests and len(self.syntax_results) == expected_syntax and \
            all(row['status'] == 'pass' for row in self.command_results)
        result = {
            'schema_version': 'knowledge-artifact-replay.v1',
            'status': 'pass' if all_pass else 'fail', 'started_at': self.started_at, 'finished_at': utc_now(),
            'fatal_error': self.fatal_error,
            'archive_sha256': self.archive_sha256_before,
            'archive_sha256_after': archive_after, 'archive_unchanged': archive_unchanged,
            'node_binary_sha256_before': self.node_sha256_before,
            'node_binary_sha256_after': node_after, 'node_binary_unchanged': node_unchanged,
            'archive_extraction': 'archive-extraction.json' if self.extraction else None,
            'environment': 'environment.json' if (self.output / 'environment.json').exists() else None,
            'inventory': 'inventory.json' if self.inventory else None,
            'source_manifest_before': 'source-manifest-before.json' if self.before is not None else None,
            'source_manifest_after': 'source-manifest-after.json' if after is not None else None,
            'source_manifest_sha256_before': manifest_digest(self.before) if self.before is not None else None,
            'source_manifest_sha256_after': manifest_digest(after) if after is not None else None,
            'source_unchanged': unchanged, 'source_changed_paths': changes,
            'self_tests': {**counts(self.self_results), 'expected': expected_tests, 'not_run': expected_tests - len(self.self_results), 'skipped': 0},
            'syntax_checks': {**counts(self.syntax_results), 'expected': expected_syntax, 'not_run': expected_syntax - len(self.syntax_results)},
            'offline_auto_updates': self.offline_auto_updates,
            'commands': self.command_results,
            'release_gate': 'not_run_source_only_maintainer_gate_is_outside_runner_scope',
            'evidence_note': 'Raw logs and parsed JSON are complete. All file links are relative to this replay directory. fixtures/ and snapshot/ are disposable replay inputs.',
        }
        write_json(self.output / 'replay-results.json', result)
        print(json.dumps({key: result[key] for key in ('status', 'self_tests', 'syntax_checks', 'offline_auto_updates', 'source_unchanged', 'fatal_error')}), flush=True)
        return 0 if all_pass else 1


def arguments():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--archive', required=True, type=Path, help='Install ZIP containing one .knowledge root')
    parser.add_argument('--output', required=True, type=Path, help='New or empty evidence directory')
    parser.add_argument('--node', required=True, type=Path, help='Absolute path to the Node executable')
    parser.add_argument('--suite-timeout', type=int, default=300)
    parser.add_argument('--syntax-timeout', type=int, default=30)
    parser.add_argument('--offline-auto-updates', action='store_true', help='Set only updates.enabled=false in each fixture config.yaml; preserve snapshot/archive and record exact override hashes')
    args = parser.parse_args()
    if not args.node.is_absolute():
        parser.error('--node must be an absolute executable path')
    if args.suite_timeout < 1 or args.syntax_timeout < 1:
        parser.error('Timeouts must be positive seconds')
    args.archive = args.archive.resolve(strict=True)
    args.node = args.node.resolve(strict=True)
    args.output = args.output.resolve()
    if not args.archive.is_file() or not args.node.is_file():
        parser.error('--archive and --node must be existing regular files')
    if args.output.exists() and (not args.output.is_dir() or any(args.output.iterdir())):
        parser.error('--output must be a new or empty directory; existing evidence is never overwritten')
    return args


def main():
    args = arguments()
    args.output.mkdir(parents=True, exist_ok=True)
    replay = Replay(args.archive, args.output, args.node, args.suite_timeout, args.syntax_timeout, args.offline_auto_updates)
    try:
        replay.run()
    except (Exception, KeyboardInterrupt) as error:
        replay.fatal_error = f'{type(error).__name__}: {error}'
    return replay.finalize()


if __name__ == '__main__':
    sys.exit(main())
