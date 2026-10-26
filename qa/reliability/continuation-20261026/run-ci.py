#!/usr/bin/env python3
"""Bounded, source-bound continuation gate. Darwin raw evidence stays private."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import signal
import stat
import subprocess
import sys
import threading
import time
import traceback
from prepare import bounded, encoded, rows, sha, verify_zip, write_new

ROOT = Path(__file__).resolve().parents[3]
QA = ROOT / 'qa/reliability'
EXTRA_LINUX = [
    'modeled reused namespace coordinate refusal can be resolved only by the fixed outer observer',
    'modeled ambiguous local observation remains unknown without a confirmed relay proof',
    'modeled active local scope is never overridden by an outer closure reply',
    'modeled local helper integrity or cleanup failure cannot be masked by an outer observer',
]
REPORT_CASES = [f'coherent {command} after {fault} during view publication' for command in ('collect-metrics', 'build-visual-inspector') for fault in ('enospc', 'kill')] + [
    'commit failure preserves the previous complete report',
    'corrupt committed generation cannot fall back to a stale compatibility view',
    'missing commit after migration cannot expose a stale compatibility view',
    'legacy single-file reports remain readable before migration',
    'all report views and commit are preflighted before the current generation changes',
    'snapshot replacement during read retries to a single intact generation',
    'growing snapshot reads stay bounded and fail closed',
    'UTF-8 BOM bytes remain part of the committed string view',
    'UTF-8 BOM bytes remain part of the committed buffer view',
    'lock-layout names cannot be used as report views',
    'migration fence survives a fault immediately after first commit',
    'legacy read racing first generation publication: fence-only',
    'legacy read racing first generation publication: commit-present',
    'legacy read racing first generation publication: view-removed',
    'legacy absent-file fallback rechecks a concurrently published migration fence',
]
QUERY_CASES = [
    'modeled synchronous scope identity query reaches both native requests and validates its peer',
    'real spawnSync consumes UTF8 request bytes while its response remains a Buffer',
    'source I/O denial is fail-closed and exposes only an allowlisted diagnostic',
    'malformed identity reply never becomes a proof and identifies its decoder stage',
    'protected executable failure keeps the existing typed code and cannot leak exception text',
    'unknown exception metadata is discarded and native request errors stay unconfirmed',
    'configuration is explicit, inert, strict, and normalizes copy limits',
    'native environment removes dynamic loader and script injection variables without mutation',
    'reply decoder rejects oversized, malformed, unknown, and mistyped protocol bodies',
    'unqualified hosts fail closed without attempting any broker process',
    'probe wrapper preserves the helper lifecycle budget and passes both native timing limits',
]


def unchanged(source, manifest):
    return all(sha(bounded(source / name)) == row['sha256'] for name, row in rows(manifest).items())


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--prepared', required=True)
    parser.add_argument('--out', required=True)
    parser.add_argument('--platform', choices=['linux', 'win32', 'darwin'], required=True)
    parser.add_argument('--arch', choices=['x64', 'arm64'], required=True)
    parser.add_argument('--phase', choices=['diagnostic', 'full'], default='diagnostic')
    args = parser.parse_args()
    prepared = Path(args.prepared).resolve(strict=True)
    source = prepared / 'source/.knowledge'
    manifest = json.loads(bounded(prepared / 'SOURCE_MANIFEST.json'))
    verify_zip(bounded(prepared / 'SOURCE.zip'), manifest)
    if not unchanged(source, manifest):
        raise RuntimeError('Prepared source mismatch')
    out = Path(args.out).absolute();out.mkdir(mode=0o700)
    public, private = out / 'public', out / 'private'
    public.mkdir();private.mkdir(mode=0o700)
    temporary = private / 'tmp';temporary.mkdir()
    env = dict(os.environ)
    env.update({'TMPDIR': str(temporary), 'TMP': str(temporary), 'TEMP': str(temporary), 'NODE_OPTIONS': '', 'NODE_PATH': '', 'CI': 'true'})
    for key in list(env):
        if key.startswith('KNOWLEDGE_'):
            env.pop(key)
    started = time.monotonic();overall_end = started + 1500
    result = {'schema_version': 'knowledge-continuation-ci.v1', 'status': 'RUNNING', 'phase': args.phase,
        'platform': args.platform, 'architecture': args.arch, 'commit': os.environ.get('GITHUB_SHA'),
        'source_zip_sha256': manifest['archive_sha256'], 'source_manifest_sha256': sha(bounded(prepared / 'SOURCE_MANIFEST.json')),
        'source_file_count': manifest['file_count'], 'controller_sha256': sha(bounded(__file__)), 'steps': [],
        'release_gate_qualified': False, 'scope': 'Exact frozen continuation cohort; native gates and modeled predicates remain separate. Ordinary macOS writable Flow remains unsupported.'}
    def save():
        (public / 'RESULT.json').write_bytes(encoded(result))
    save()

    def run(name, command, timeout=180, cwd=None):
        row = {'name': name, 'timeout_seconds': timeout, 'status': 'FAIL'}
        result['steps'].append(row);save()
        seconds = min(timeout, max(0, overall_end - time.monotonic() - 75))
        print(json.dumps({'phase': name, 'event': 'start', 'timeout_seconds': seconds}), flush=True)
        if seconds < 1:
            row['failure'] = 'overall_budget_exhausted';save()
            print(json.dumps({'phase': name, 'event': 'end', 'status': 'FAIL', 'elapsed_seconds': 0}), flush=True)
            return row, ''
        folder = private / 'steps' / name;folder.mkdir(parents=True)
        began = time.monotonic();streams = {}
        try:
            process = subprocess.Popen([str(value) for value in command], cwd=cwd or ROOT, env=env,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=os.name != 'nt',
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == 'nt' else 0)
            def consume(label, pipe):
                digest = hashlib.sha256();count = 0;kept = bytearray()
                try:
                    while True:
                        data = pipe.read(65536)
                        if not data: break
                        count += len(data);digest.update(data)
                        if len(kept) < 8 * 1024 * 1024: kept.extend(data[:8 * 1024 * 1024 - len(kept)])
                    streams[label] = {'bytes': count, 'sha256': digest.hexdigest(), 'truncated': count != len(kept), 'eof': True}
                except Exception as error:
                    streams[label] = {'eof': False, 'error_type': type(error).__name__}
                (folder / (label + '.log')).write_bytes(kept)
            threads = [threading.Thread(target=consume, args=(label, pipe), daemon=True) for label, pipe in [('stdout', process.stdout), ('stderr', process.stderr)]]
            for thread in threads: thread.start()
            timed_out = False
            try: process.wait(timeout=seconds)
            except subprocess.TimeoutExpired:
                timed_out = True
                # POSIX Python controllers catch KeyboardInterrupt and run their
                # exact-fixture finally cleanup before a last-resort group kill.
                try: process.send_signal(signal.CTRL_BREAK_EVENT if os.name == 'nt' else signal.SIGINT)
                except OSError: process.terminate()
                try: process.wait(timeout=60)
                except subprocess.TimeoutExpired:
                    # Popen retains the actual Windows process HANDLE. Do not
                    # resolve a possibly reused numeric PID through taskkill.
                    if os.name == 'nt': process.kill()
                    else: os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=15)
            for thread in threads: thread.join(timeout=5)
            row.update(exit_code=process.returncode, timed_out=timed_out, streams=streams,
                elapsed_seconds=time.monotonic()-began)
            complete = len(streams) == 2 and all(value.get('eof') and not value.get('truncated') for value in streams.values())
            row['cleanup_unconfirmed'] = timed_out or not complete
            row['status'] = 'PASS' if process.returncode == 0 and not timed_out and complete else 'FAIL'
            output = (folder / 'stdout.log').read_text(encoding='utf-8', errors='strict') if (folder / 'stdout.log').exists() else ''
        except Exception as error:
            row['failure_type'] = type(error).__name__;row['cleanup_unconfirmed'] = True;output = ''
        save()
        print(json.dumps({'phase': name, 'event': 'end', 'status': row['status'], 'elapsed_seconds': time.monotonic()-began}), flush=True)
        return row, output

    def copy_public(directory, destination):
        if not directory.is_dir(): return
        for file in sorted(directory.rglob('*')):
            if file.is_symlink(): raise RuntimeError('Public artifact symlink')
            if file.is_file(): write_new(destination / file.relative_to(directory), bounded(file))

    def tap(name, runtime_source, test_files, expected, timeout=180):
        if name not in {'report-generation', 'macos-client-query'}:
            raise RuntimeError('Raw TAP publication is not allowlisted')
        row, output = run(name, [node, '--test', '--test-reporter=tap', '--test-concurrency=1', *[runtime_source / item for item in test_files]], timeout, runtime_source)
        for label in ('stdout', 'stderr'):
            file = private / 'steps' / name / (label + '.log')
            if file.is_file(): write_new(public / 'steps' / name / (label + '.log'), bounded(file, 8 * 1024 * 1024))
        spec = importlib.util.spec_from_file_location('continuation_nested_tap', QA / 'linux-final-01/nested_tap.py')
        module = importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        parsed = module.parse_nested_tap(output)
        names = {tuple(case['path']) for case in parsed['cases']}
        valid = parsed['valid_structure'] and names == {(name,) for name in expected} and len(parsed['cases']) == len(expected) and \
            parsed['counts'] == {'tests': len(expected), 'suites': 0, 'pass': len(expected), 'fail': 0, 'cancelled': 0, 'skipped': 0, 'todo': 0} and \
            all(case['outcome'] == 'ok' and case['directive'] is None for case in parsed['cases'])
        row['tap'] = parsed;row['strict_expected_case_names'] = expected
        row['status'] = 'PASS' if row['status'] == 'PASS' and valid else 'FAIL';save()

    node = shutil.which('node')
    runtime_source = source
    try:
        host, output = run('host', [node, '-p', 'JSON.stringify({platform:process.platform,arch:process.arch,node:process.version})'])
        observed = json.loads(output)
        if host['status'] != 'PASS' or observed != {'platform': args.platform, 'arch': args.arch, 'node': 'v22.17.1'}:
            raise RuntimeError('Actual host/runtime differs from admitted matrix')
        result['runtime'] = observed
        if args.platform in ('linux', 'win32'):
            origin = QA / ('linux-final-01' if args.platform == 'linux' else 'windows-progress-03')
            controller = private / 'controller';controller.mkdir()
            shutil.copyfile(origin / 'native_qa.py', controller / 'native_qa.py')
            policy = json.loads(bounded(origin / 'EXPECTED_CASES.json'))
            if args.platform == 'linux':
                shutil.copyfile(origin / 'nested_tap.py', controller / 'nested_tap.py')
                paths = policy['nested_required_paths']['linux_runtime']
                if any([name] in paths for name in EXTRA_LINUX): raise RuntimeError('Duplicate continuation test policy')
                paths.extend([[name] for name in EXTRA_LINUX])
            write_new(controller / 'EXPECTED_CASES.json', encoded(policy))
            qa_out = private / 'native-qa'
            run('native-runtime', [sys.executable, controller / 'native_qa.py', '--archive', prepared / 'SOURCE.zip', '--manifest', prepared / 'SOURCE_MANIFEST.json', '--out', qa_out], 1200)
            copy_public(qa_out / 'public', public / 'native-runtime')
            runtime_source = qa_out / 'scratch/.knowledge'
            if not unchanged(runtime_source, manifest): raise RuntimeError('Native cohort source changed')
        else:
            native = private / 'native-build'
            build_row, _ = run('native-build', [sys.executable, QA / 'compile_native.py', '--source', source, '--pins', prepared / 'SOURCE_PINS.json', '--out', native], 240)
            arch = 'x86_64' if args.arch == 'x64' else 'arm64'
            for cases in ('failures', 'basic'):
                location = private / ('macos-production-' + cases)
                row, _ = run('macos-production-' + cases, [sys.executable, QA / 'controllers/darwin-production-lifecycle.py', '--source', source,
                    '--reference', QA / 'reference', '--evidence', location, '--expected-arch', arch, '--case-set', cases], 540)
                run('macos-summary-' + cases, [sys.executable, QA / 'controllers/darwin-production-summary.py', '--private', location,
                    '--public', public / ('macos-production-' + cases), '--source', source, '--controller-status', row.get('exit_code', 1), '--expected-arch', arch, '--case-set', cases], 60)
            if args.phase == 'full':
                location = private / 'macos-physical'
                row, _ = run('macos-physical', [sys.executable, QA / 'controllers/darwin-native-lifecycle.py', '--source', source,
                    '--reference', QA / 'reference', '--evidence', location, '--expected-arch', arch], 480)
                run('macos-physical-summary', [sys.executable, QA / 'controllers/darwin-public-summary.py', '--private', location,
                    '--public', public / 'macos-physical', '--source', source, '--controller-status', row.get('exit_code', 1), '--expected-arch', arch], 60)
            # Build-only artifacts are read back before being used by report tests;
            # no prebuilt runtime bytes enter the frozen manifest or native claims.
            if build_row['status'] == 'PASS':
                receipt_bytes = bounded(native / 'BUILD.json')
                receipt = json.loads(receipt_bytes)
                if receipt.get('status') != 'PASS_COMPILE_AND_LOAD' or receipt.get('runtime') != observed:
                    raise RuntimeError('Native build receipt/runtime mismatch')
                destination = source / 'tools/lib/native' / ('darwin-' + args.arch)
                export = public / 'native' / ('macos-' + args.arch)
                for name in ('lock-publication.node', 'lock-publication.manifest.json', 'verification-darwin-broker', 'verification-darwin-stub'):
                    relative_name = 'native/darwin-' + args.arch + '/' + name
                    body = bounded(native / relative_name)
                    if receipt['binaries'].get(relative_name) != sha(body): raise RuntimeError('Built addon changed')
                    write_new(export / name, body)
                    if name in ('lock-publication.node', 'lock-publication.manifest.json'):
                        write_new(destination / name, body)
                write_new(export / 'BUILD.json', receipt_bytes)
            tap('macos-client-query', source, ['tests/reliability-darwin-scope-query.test.js', 'tests/verification-darwin-client.test.js'], QUERY_CASES)
        tap('report-generation', runtime_source, ['tests/report-generation.test.js'], REPORT_CASES, 180)
        result['source_after_unchanged'] = unchanged(source, manifest)
        result['runtime_source_after_unchanged'] = unchanged(runtime_source, manifest)
    except BaseException as error:
        result['failure_type'] = type(error).__name__
        # No exception messages, paths, locals or fixture capabilities enter
        # public diagnostics; the controller frame alone locates setup faults.
        result['failure_frames'] = [{'file': Path(frame.filename).name, 'line': frame.lineno}
            for frame in traceback.extract_tb(error.__traceback__) if Path(frame.filename).name in {'run-ci.py', 'prepare.py'}]
        (private / 'failure.txt').write_text(str(error), encoding='utf-8')
    finally:
        try:
            result['source_after_unchanged'] = unchanged(source, manifest)
            result['runtime_source_after_unchanged'] = unchanged(runtime_source, manifest)
        except BaseException as error:
            result['source_readback_failure_type'] = type(error).__name__
            result['source_after_unchanged'] = result['runtime_source_after_unchanged'] = False
        result['elapsed_seconds'] = time.monotonic() - started
        result['status'] = 'PASS_SCOPED_CONTINUATION' if result['steps'] and all(row['status'] == 'PASS' for row in result['steps']) and result.get('source_after_unchanged') and result.get('runtime_source_after_unchanged') and not result.get('failure_type') else 'FAIL_OR_INCOMPLETE'
        save()
        inventory = {file.relative_to(public).as_posix(): {'bytes': file.stat().st_size, 'sha256': sha(bounded(file))} for file in sorted(public.rglob('*')) if file.is_file()}
        (public / 'SHA256SUMS.json').write_bytes(encoded(inventory))
        print(json.dumps({'status': result['status'], 'source_zip_sha256': result['source_zip_sha256'], 'platform': args.platform,
            'architecture': args.arch, 'phase': args.phase, 'release_gate_qualified': False}))
    return 0 if result['status'] == 'PASS_SCOPED_CONTINUATION' else 1


if __name__ == '__main__':
    raise SystemExit(main())
