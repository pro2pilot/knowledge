#!/usr/bin/env python3
"""Build and physically test one frozen source ZIP on the actual host OS.

No repository mutation or publication occurs. Only public/ is an artifact;
downloaded toolchains, extracted source, caches and fixture state stay scratch.
"""
import argparse
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
import tarfile
import threading
import time
import urllib.request
import zipfile

LOG_LIMIT = 8 * 1024 * 1024
SOURCE_LIMIT = 64 * 1024 * 1024
PRIMARY_TESTS = [
    'tests/reliability-lock-publication.test.js',
    'tests/reliability-lock-lifecycle.test.js',
    'tests/reliability-lock-loader.test.js',
    'tests/reliability-lock-inode-binding.test.js',
    'tests/reliability-lock-compatibility.test.js',
    'tests/reliability-lock-permissions.test.js',
    'tests/reliability-lock-scope.test.js',
    'tests/audit-lock-bounded-owner-read.test.js',
    'tests/audit-lock-cleanup-budget.test.js',
    'tests/lock-monotonic-budget.test.js',
    'tests/lock-owner-initialization.test.js',
    'tests/lock-owner-native-scope.test.js',
    'tests/lock-owner-recovery-budget.test.js',
    'tests/lock-owner-uncertainty.test.js',
    'tests/lock-recovery-generation.test.js',
]
ABI_TESTS = PRIMARY_TESTS[:6]


def sha(body):
    return hashlib.sha256(body).hexdigest()


def file_sha(file):
    return sha(Path(file).read_bytes())


def source_path(name):
    value = PurePosixPath(name)
    if value.is_absolute() or not value.parts or any(p in {'.', '..'} for p in value.parts) or '\\' in name or ':' in name:
        raise ValueError('Unsafe relative archive path: ' + name)
    return value


class Failure(RuntimeError):
    pass


def assess_tap(output, platform_name, group, policy):
    totals = {key: int(value) for key, value in re.findall(r'^# (tests|suites|pass|fail|cancelled|skipped|todo) (\d+)\s*$', output, re.M)}
    cases = []
    for outcome, name, directive, reason in re.findall(r'^(ok|not ok) \d+ - (.*?)(?: # (SKIP|TODO)(?: (.*))?)?\s*$', output, re.M):
        cases.append({'name': name.strip(), 'outcome': outcome, 'directive': directive or None, 'reason': reason or None})
    required = set(policy['required_cases'][group])
    allowed_skips = set(policy['allowed_skips_by_platform'][platform_name])
    names = {case['name'] for case in cases}
    skipped = [case for case in cases if case['directive'] == 'SKIP']
    unexpected_skips = [case['name'] for case in skipped if case['name'] not in allowed_skips]
    missing = sorted(required - names)
    passed = sum(case['outcome'] == 'ok' and not case['directive'] for case in cases)
    valid = bool(totals.get('tests')) and passed > 0 and not missing and not unexpected_skips and \
        len(names) == len(cases) == totals.get('tests') and len(skipped) == totals.get('skipped') and \
        passed == totals.get('pass') and not totals.get('fail', 0) and not totals.get('cancelled', 0) and not totals.get('todo', 0)
    return {'valid': valid, 'counts': totals, 'skips': skipped,
            'unexpected_skips': unexpected_skips, 'missing_required_cases': missing,
            'qualified_case_names': [case['name'] for case in cases if case['outcome'] == 'ok' and not case['directive']]}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--archive', required=True)
    parser.add_argument('--manifest', required=True)
    parser.add_argument('--out', required=True)
    parser.add_argument('--node', default=shutil.which('node'))
    args = parser.parse_args()
    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=False)
    public, scratch = out / 'public', out / 'scratch'
    public.mkdir(); scratch.mkdir()
    case_policy_path = Path(__file__).with_name('EXPECTED_CASES.json')
    case_policy = json.loads(case_policy_path.read_text())
    if case_policy.get('schema_version') != 'knowledge-native-qa-case-policy.v1':
        raise Failure('Unknown case qualification policy.')
    result = {'schema_version': 'knowledge-native-runtime-qa.v1', 'status': 'RUNNING',
              'scope': 'Actual common-lock runtime scenarios on this host; excludes Darwin production broker qualification and whole-release acceptance.',
              'controller_sha256': file_sha(__file__), 'case_policy_sha256': file_sha(case_policy_path), 'host': platform.platform(),
              'commit': os.environ.get('GITHUB_SHA'), 'steps': [], 'downloads': []}
    (public / 'EXPECTED_CASES.json').write_text(json.dumps(case_policy, indent=2) + '\n')
    env = dict(os.environ)
    env.update({'NODE_OPTIONS': '', 'NODE_PATH': '', 'CI': 'true',
                'TMPDIR': str(scratch / 'tmp'), 'TMP': str(scratch / 'tmp'), 'TEMP': str(scratch / 'tmp')})
    for name in ['KNOWLEDGE_LOCK_TEST_SOURCE', 'KNOWLEDGE_AUDIT_SYSTEM_ROOT',
                 'KNOWLEDGE_LOCK_TIMEOUT_MS', 'KNOWLEDGE_LOCK_STALE_MS']:
        env.pop(name, None)
    (scratch / 'tmp').mkdir()
    result['controlled_environment'] = {key: env[key] for key in ['NODE_OPTIONS', 'NODE_PATH', 'CI', 'TMPDIR', 'TMP', 'TEMP']}

    def save():
        (public / 'RESULT.json').write_text(json.dumps(result, indent=2) + '\n')

    def run(name, command, cwd=None, timeout=180, check=True):
        command = [str(x) for x in command]
        folder = public / 'steps' / ('%02d-' % (len(result['steps']) + 1) + name)
        folder.mkdir(parents=True)
        print(json.dumps({'phase': name, 'timeout_seconds': timeout}), flush=True)
        record = {'name': name, 'command': command, 'cwd': str(cwd) if cwd else None,
                  'timeout_seconds': timeout, 'started_utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}
        result['steps'].append(record); save()
        started = time.monotonic()
        proc = subprocess.Popen(command, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                start_new_session=os.name != 'nt')
        record['pid'] = proc.pid
        streams = {}

        def drain(pipe, label):
            kept, total, hasher = bytearray(), 0, hashlib.sha256()
            try:
                while True:
                    chunk = pipe.read(65536)
                    if not chunk:
                        break
                    total += len(chunk); hasher.update(chunk)
                    kept.extend(chunk[:max(0, LOG_LIMIT - len(kept))])
            finally:
                streams[label] = {'bytes': total, 'sha256_complete_stream': hasher.hexdigest(),
                                  'truncated': total > LOG_LIMIT, 'body': bytes(kept)}
        readers = [threading.Thread(target=drain, args=(proc.stdout, 'stdout'), daemon=True),
                   threading.Thread(target=drain, args=(proc.stderr, 'stderr'), daemon=True)]
        for reader in readers:
            reader.start()
        timed_out = False
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            if os.name == 'nt':
                # Popen.kill uses the retained exact process HANDLE. Do not
                # replace this with an unqualified taskkill of a recycled PID.
                proc.kill()
            else:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            try:
                proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                pass
        for reader in readers:
            reader.join(timeout=10)
        incomplete = any(reader.is_alive() for reader in readers)
        record.update({'exit_code': proc.returncode, 'timed_out': timed_out,
                       'cleanup_unconfirmed': incomplete or (timed_out and os.name == 'nt'),
                       'elapsed_seconds': time.monotonic() - started})
        for label in ['stdout', 'stderr']:
            stream = streams.get(label, {'bytes': None, 'sha256_complete_stream': None, 'truncated': True, 'body': b''})
            (folder / (label + '.log')).write_bytes(stream['body'])
            record[label] = {k: v for k, v in stream.items() if k != 'body'}
            record[label]['retained_sha256'] = sha(stream['body'])
        record['result'] = 'FAIL' if timed_out or incomplete or proc.returncode or any(v.get('truncated') for v in streams.values()) else 'PASS'
        save()
        if record['result'] != 'PASS' and check:
            raise Failure('Command failed; exact raw output is retained: ' + name)
        return record, streams.get('stdout', {}).get('body', b'')

    def verify_source(source, manifest):
        changed = []
        for row in manifest['files']:
            file = source / row['path']
            if not file.is_file() or file.is_symlink() or file_sha(file) != row['sha256']:
                changed.append(row['path'])
        return changed

    def extract_source(archive_path, manifest):
        if manifest.get('schema_version') != 'knowledge-native-qa-source.v1' or manifest.get('status') != 'PASS_FROZEN_SOURCE':
            raise Failure('The input is not a successful frozen source manifest.')
        if file_sha(archive_path) != manifest['archive_sha256']:
            raise Failure('Source ZIP hash mismatch.')
        expected = {'.knowledge/' + row['path']: row for row in manifest['files']}
        if len(expected) != len(manifest['files']) or len(expected) > 10000 or sum(r['bytes'] for r in expected.values()) > SOURCE_LIMIT:
            raise Failure('Source inventory is duplicate or exceeds the bounded source limit.')
        with zipfile.ZipFile(archive_path) as archive:
            infos = archive.infolist()
            if len(infos) != len(expected) or set(archive.namelist()) != set(expected) or archive.testzip() is not None:
                raise Failure('Source ZIP CRC/inventory mismatch.')
            for info in infos:
                parts = source_path(info.filename)
                row = expected[info.filename]
                if parts.parts[0] != '.knowledge' or info.is_dir() or info.file_size != row['bytes'] or info.file_size > SOURCE_LIMIT:
                    raise Failure('Invalid source ZIP member.')
                mode = info.external_attr >> 16
                if mode and not stat.S_ISREG(mode):
                    raise Failure('Source ZIP contains a nonregular file.')
                body = archive.read(info)
                if sha(body) != row['sha256']:
                    raise Failure('Source ZIP member hash mismatch: ' + info.filename)
                destination = scratch.joinpath(*parts.parts)
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(body)
                destination.chmod(int(row['mode'], 8))
        source = scratch / '.knowledge'
        if verify_source(source, manifest):
            raise Failure('Extracted source did not match exact input bytes.')
        return source

    tables = {}

    def download(version, name):
        base = 'https://nodejs.org/dist/v' + version + '/'
        destination = scratch / 'toolchains' / version / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        if version not in tables:
            with urllib.request.urlopen(base + 'SHASUMS256.txt', timeout=60) as response:
                body = response.read(1024 * 1024 + 1)
            if len(body) > 1024 * 1024:
                raise Failure('Oversized official checksum list.')
            tables[version] = {line.split()[1]: line.split()[0] for line in body.decode('ascii').splitlines() if len(line.split()) == 2}
            (public / ('NODE_' + version + '_SHASUMS256.txt')).write_bytes(body)
        if name not in tables[version]:
            raise Failure('Requested official Node artifact is absent from its checksum list: ' + name)
        with urllib.request.urlopen(base + name, timeout=90) as response:
            body = response.read(80 * 1024 * 1024 + 1)
        if len(body) > 80 * 1024 * 1024 or sha(body) != tables[version][name]:
            raise Failure('Downloaded Node artifact failed its bounded checksum verification.')
        destination.write_bytes(body)
        result['downloads'].append({'url': base + name, 'bytes': len(body), 'sha256': sha(body), 'checksum_verified': True})
        save()
        return destination

    def extract_toolchain(file):
        destination = file.parent / ('extracted-' + sha(file.read_bytes())[:16])
        destination.mkdir(exist_ok=False)
        if file.suffix == '.zip':
            with zipfile.ZipFile(file) as archive:
                for info in archive.infolist():
                    parts = source_path(info.filename.rstrip('/'))
                    mode = info.external_attr >> 16
                    if stat.S_ISLNK(mode):
                        raise Failure('Toolchain ZIP has a symbolic link.')
                    target = destination.joinpath(*parts.parts)
                    if info.is_dir():
                        target.mkdir(parents=True, exist_ok=True)
                    else:
                        target.parent.mkdir(parents=True, exist_ok=True)
                        target.write_bytes(archive.read(info))
        else:
            with tarfile.open(file) as archive:
                members = archive.getmembers()
                for member in members:
                    source_path(member.name.rstrip('/'))
                    if not (member.isfile() or member.isdir() or member.issym()):
                        raise Failure('Unsupported official toolchain archive entry.')
                    # Node runtime tarballs contain internal bin/npm links.
                    # They are not needed by this QA and are not materialized.
                    if member.issym():
                        continue
                    target = destination.joinpath(*PurePosixPath(member.name).parts)
                    if member.isdir():
                        target.mkdir(parents=True, exist_ok=True)
                    else:
                        target.parent.mkdir(parents=True, exist_ok=True)
                        target.write_bytes(archive.extractfile(member).read())
                        target.chmod(member.mode & 0o777)
        return destination

    def tests(node, names, label, source, platform_name, group):
        for name in names:
            if not (source / name).is_file():
                raise Failure('Requested test does not exist: ' + name)
        record, output = run(label, [node, '--test', '--test-reporter=tap', '--test-concurrency=1',
                                     *[source / name for name in names]], cwd=source, timeout=420, check=False)
        decoded = output.decode('utf-8', errors='replace')
        record['requested_test_files'] = names
        assessed = assess_tap(decoded, platform_name, group, case_policy)
        record.update(assessed)
        # SKIP remains visible and is never counted as platform qualification.
        # Existing Linux-native legacy-procfs tests legitimately skip elsewhere.
        if record['result'] != 'PASS' or not assessed['valid']:
            save()
            raise Failure('Native test suite did not complete successfully: ' + label)
        save()

    source = None
    manifest = None
    native_destination = None
    try:
        manifest = json.loads(Path(args.manifest).read_text())
        (public / 'SOURCE_MANIFEST.json').write_text(json.dumps(manifest, indent=2) + '\n')
        result['source_zip_sha256'] = file_sha(args.archive)
        source = extract_source(Path(args.archive), manifest)
        node = Path(args.node).resolve(strict=True)
        _, observed = run('host-runtime', [node, '-p', 'JSON.stringify({platform:process.platform,architecture:process.arch,node:process.version,napi:process.versions.napi})'])
        host = json.loads(observed)
        result['runtime'] = host; result['runtime_binary_sha256'] = file_sha(node)
        if host['platform'] not in {'linux', 'darwin', 'win32'} or host['architecture'] not in {'x64', 'arm64'}:
            raise Failure('Host platform/architecture is outside the explicit native matrix.')
        version = '22.17.1' if host['platform'] == 'win32' and host['architecture'] == 'arm64' else '18.20.8'
        headers_archive = download(version, 'node-v' + version + '-headers.tar.gz')
        headers = extract_toolchain(headers_archive) / ('node-v' + version) / 'include' / 'node'
        native_destination = source / 'tools' / 'lib' / 'native' / (host['platform'] + '-' + host['architecture'])
        command = [node, source / 'tools/build-lock-native.js', '--headers', headers, '--output', native_destination]
        if host['platform'] == 'win32':
            compiler = shutil.which('cl.exe')
            if not compiler:
                raise Failure('Visual C developer environment is unavailable.')
            node_lib = download(version, 'win-' + host['architecture'] + '/node.lib')
            command += ['--compiler', compiler, '--node-lib', node_lib]
            run('build-command-job-addon-compile-only', [node, source / 'tools/build-command-native.js',
                '--headers', headers, '--compiler', compiler, '--node-lib', node_lib,
                '--output', native_destination], cwd=source, timeout=180)
            result['windows_command_job'] = {'status': 'PASS_COMPILE_ONLY',
                'runtime_qualification': 'NOT_RUN', 'scope': 'Compilation only; no custody, drain or recovery qualification.'}
            # Diagnose the actual Win32/NT relative rename boundary, including
            # no-replace collisions with a live owner-inode lease. This probe
            # uses only controller-owned fixtures and is not a mock provider.
            probe_source = source / 'tests/helpers/reliability-windows-rename-probe.c'
            probe_binary = scratch / 'windows-relative-rename-probe.exe'
            run('build-windows-relative-rename-probe', [compiler, '/nologo', '/std:c11', '/W4', '/O2',
                '/Fe' + str(probe_binary), '/Fo' + str(scratch / 'windows-relative-rename-probe.obj'), probe_source], cwd=scratch)
            result['windows_relative_rename_probe'] = {'source_sha256': file_sha(probe_source), 'binary_sha256': file_sha(probe_binary)}
            run('windows-relative-rename-api-comparison', [probe_binary, scratch / 'windows-rename-fixture'], cwd=scratch)
        run('build-native-addon', command, cwd=source, timeout=180)
        if host['platform'] == 'linux':
            c_file = source / 'tools/lib/verification-linux-namespace.c'
            binary = native_destination / 'verification-linux-namespace'
            compiler = shutil.which('cc')
            if not compiler:
                raise Failure('A C compiler is unavailable for the actual Linux scope fixture.')
            run('build-linux-scope-fixture', [compiler, '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
                                            '-Wno-misleading-indentation', '-fstack-protector-strong', '-D_FORTIFY_SOURCE=2',
                                            c_file, '-o', binary], cwd=source)
            binary.chmod(0o755)
            (native_destination / 'verification-linux-namespace.manifest.json').write_text(json.dumps({
                'schema_version': 'knowledge-command-native-binary.v1', 'platform': 'linux', 'architecture': host['architecture'],
                'binary': binary.name, 'source_sha256': file_sha(c_file), 'binary_sha256': file_sha(binary),
                'binary_bytes': binary.stat().st_size}, indent=2) + '\n')
            # Preserve actual setup stage/errno and read-only host policy;
            # observation completion is not feature qualification. The full
            # subsequent suite retains every existing pass/fail assertion.
            run('linux-namespace-capability-diagnostic',
                [node, source / 'tests/helpers/reliability-linux-capability-diagnostic.cjs'], cwd=source, timeout=90)
        info = "const q=require(process.argv[1]).qualifyNativePublication();console.log(JSON.stringify({node:process.version,napi:process.versions.napi,qualified:q.info,manifest:q.manifest}));"
        run('qualified-addon-current-runtime', [node, '-e', info, source / 'tools/lib/lock-publication.js'], cwd=source)
        tests(node, PRIMARY_TESTS, 'current-runtime-common-locks', source, host['platform'], 'main')
        _, transition_output = run('public-owner-transitions', [node, source / 'tools/self-test-lock-owner-transitions.js'], cwd=source)
        transition = json.loads(transition_output)
        if transition.get('failed') or transition.get('status') != 'passed':
            raise Failure('Public transition self-test did not pass.')
        result['public_transition_counts'] = {key: transition[key] for key in ['total', 'passed', 'failed']}
        if host['platform'] == 'win32' and host['architecture'] == 'arm64':
            result['node18_abi'] = {'status': 'NOT_RUN_PLATFORM_NOT_DISTRIBUTED',
                                    'reason': 'Official Node 18.20.8 does not ship a win-arm64 executable; this job qualifies the actual Node 22 arm64 runtime only.'}
        else:
            suffix = '.zip' if host['platform'] == 'win32' else '.tar.xz'
            prefix = 'win' if host['platform'] == 'win32' else host['platform']
            name = 'node-v18.20.8-' + prefix + '-' + host['architecture']
            distribution = extract_toolchain(download('18.20.8', name + suffix)) / name
            legacy_node = distribution / ('node.exe' if host['platform'] == 'win32' else 'bin/node')
            if os.name != 'nt':
                legacy_node.chmod(0o755)
            run('qualified-addon-node18', [legacy_node, '-e', info, source / 'tools/lib/lock-publication.js'], cwd=source)
            tests(legacy_node, ABI_TESTS, 'node18-actual-abi-and-lifecycle', source, host['platform'], 'node18')
            result['node18_abi'] = {'status': 'PASS_ACTUAL_RUNTIME', 'version': '18.20.8',
                                    'binary_sha256': file_sha(legacy_node), 'scope': ABI_TESTS}
        changed = verify_source(source, manifest)
        result['source_changes_during_build_and_tests'] = changed
        if changed:
            raise Failure('Source input changed during native QA.')
        result['status'] = 'PASS_SCOPED_NATIVE_RUNTIME'
    except Exception as error:
        result['status'] = 'FAIL'
        result['error'] = {'type': type(error).__name__, 'message': str(error)}
    finally:
        if source is not None and manifest is not None:
            result['source_changes_during_build_and_tests'] = verify_source(source, manifest)
            if result['source_changes_during_build_and_tests']:
                result['status'] = 'FAIL'
        if native_destination is not None and native_destination.is_dir():
            exported = public / 'native' / native_destination.name
            exported.mkdir(parents=True, exist_ok=True)
            for entry in sorted(native_destination.iterdir()):
                if entry.is_file() and (entry.name.endswith(('.node', '.manifest.json')) or entry.name == 'verification-linux-namespace'):
                    shutil.copy2(entry, exported / entry.name)
                elif entry.is_dir() and entry.name.startswith(('.build-', '.command-build-')) and (entry / 'BUILD.json').is_file():
                    shutil.copy2(entry / 'BUILD.json', exported / (entry.name.lstrip('.') + '-BUILD.json'))
        save()
        inventory = {str(file.relative_to(public)).replace(os.sep, '/'): {'bytes': file.stat().st_size, 'sha256': file_sha(file)}
                     for file in sorted(public.rglob('*')) if file.is_file()}
        (public / 'SHA256SUMS.json').write_text(json.dumps(inventory, indent=2) + '\n')
        print(json.dumps({'status': result['status'], 'result': str(public / 'RESULT.json'),
                          'scope': result['scope'], 'error': result.get('error')}, indent=2), flush=True)
    return 0 if result['status'] == 'PASS_SCOPED_NATIVE_RUNTIME' else 1


if __name__ == '__main__':
    raise SystemExit(main())
