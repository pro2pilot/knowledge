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
    summary_rows = re.findall(r'^# (tests|suites|pass|fail|cancelled|skipped|todo) (\d+)\s*$', output, re.M)
    totals = {key: int(value) for key, value in summary_rows}
    singleton_totals = len(summary_rows) == len(totals) == 7
    cases = []
    for outcome, number, name, directive, reason in re.findall(r'^(ok|not ok) ([1-9]\d*) - (.*?)(?: # (SKIP|TODO)(?: (.*))?)?\s*$', output, re.M):
        cases.append({'number': int(number), 'name': name.strip(), 'outcome': outcome, 'directive': directive or None, 'reason': reason or None})
    plans = re.findall(r'^1\.\.([1-9]\d*)\s*$', output, re.M)
    complete_plan = len(plans) == 1 and int(plans[0]) == totals.get('tests') and [c['number'] for c in cases] == list(range(1, len(cases) + 1))
    bailout = bool(re.search(r'^Bail out!', output, re.M | re.I))
    required = set(policy['required_cases'][group])
    allowed_skips = set(policy['allowed_skips_by_platform'][platform_name])
    names = {case['name'] for case in cases}
    skipped = [case for case in cases if case['directive'] == 'SKIP']
    unexpected_skips = [case['name'] for case in skipped if case['name'] not in allowed_skips]
    missing = sorted(required - names)
    unexpected_cases = sorted(names - required)
    passed = sum(case['outcome'] == 'ok' and not case['directive'] for case in cases)
    valid = complete_plan and not bailout and singleton_totals and all(case['outcome'] == 'ok' and case['directive'] != 'TODO' for case in cases) and \
        totals.get('pass', -1) + totals.get('skipped', -1) == totals.get('tests') and totals.get('suites') == 0 and \
        totals.get('tests') == len(required) and passed > 0 and not missing and not unexpected_cases and not unexpected_skips and \
        len(names) == len(cases) == totals.get('tests') and len(skipped) == totals.get('skipped') and \
        passed == totals.get('pass') and not totals.get('fail', 0) and not totals.get('cancelled', 0) and not totals.get('todo', 0)
    return {'valid': valid, 'counts': totals, 'skips': skipped,
            'unexpected_skips': unexpected_skips, 'missing_required_cases': missing, 'unexpected_case_names': unexpected_cases,
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
              'scope': 'Frozen Windows bootstrap/Flow/KVE source cohort. Actual Windows native builds precede 57 command/Flow/channel/evaluation cases including parent pipe ownership, three public KVE cases, common locks and supported Node 18 ABI. Three exact Linux-only command cases remain unqualified. No whole-release qualification.',
              'controller_sha256': file_sha(__file__), 'python_version': platform.python_version(), 'case_policy_sha256': file_sha(case_policy_path), 'host': platform.platform(),
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
            eof, read_error = False, None
            try:
                while True:
                    chunk = pipe.read(65536)
                    if not chunk:
                        eof = True
                        break
                    total += len(chunk); hasher.update(chunk)
                    kept.extend(chunk[:max(0, LOG_LIMIT - len(kept))])
            except Exception as error:
                read_error = {'type': type(error).__name__, 'message': str(error)}
            finally:
                streams[label] = {'bytes': total, 'sha256_complete_stream': hasher.hexdigest() if eof and read_error is None else None,
                                  'sha256_observed_prefix': hasher.hexdigest(), 'eof': eof, 'read_error': read_error,
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
            stream = streams.get(label, {'bytes': None, 'sha256_complete_stream': None, 'truncated': True, 'eof': False, 'read_error': {'type': 'MissingReaderResult'}, 'body': b''})
            (folder / (label + '.log')).write_bytes(stream['body'])
            record[label] = {k: v for k, v in stream.items() if k != 'body'}
            record[label]['retained_sha256'] = sha(stream['body'])
        record['result'] = 'FAIL' if timed_out or incomplete or proc.returncode != 0 or set(streams) != {'stdout', 'stderr'} or any(v.get('truncated') or not v.get('eof') or v.get('read_error') for v in streams.values()) else 'PASS'
        save()
        if record['result'] != 'PASS' and check:
            raise Failure('Command failed; exact raw output is retained: ' + name)
        return record, streams.get('stdout', {}).get('body', b'')

    extracted_modes = {}

    def safe_bytes(file, maximum=16 * 1024 * 1024):
        file = Path(file)
        for parent in [file.parent, *file.parents]:
            value = parent.lstat()
            if not stat.S_ISDIR(value.st_mode) or stat.S_ISLNK(value.st_mode):
                raise Failure('Nonphysical native/source ancestor: ' + str(parent))
        before = file.lstat()
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > maximum:
            raise Failure('Nonregular, linked or oversized input: ' + str(file))
        fd = os.open(file, os.O_RDONLY | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NOFOLLOW', 0))
        try:
            opened = os.fstat(fd)
            body = bytearray()
            while len(body) <= maximum:
                chunk = os.read(fd, min(65536, maximum + 1 - len(body)))
                if not chunk: break
                body.extend(chunk)
            after = os.fstat(fd)
        finally:
            os.close(fd)
        # CPython Windows path stat reports creation time as deprecated ctime,
        # while fstat reports native metadata change time. Compare each ctime
        # within its own provider; preserve every shared identity field and
        # require the separately named creation time across providers.
        fields = ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns') + (
            ('st_birthtime_ns',) if os.name == 'nt' else ('st_ctime_ns',))
        identity = lambda value: tuple(getattr(value, key) for key in fields)
        named_after = file.lstat()
        changed_ctime = before.st_ctime_ns != named_after.st_ctime_ns or opened.st_ctime_ns != after.st_ctime_ns
        if len(body) > maximum or len(body) != opened.st_size or changed_ctime or any(identity(value) != identity(opened) for value in [before, after, named_after]):
            snapshots = {'before': before, 'opened': opened, 'after': after, 'named_after': named_after}
            differences = {key: {name: getattr(value, key) for name, value in snapshots.items()}
                           for key in (*fields, 'st_ctime_ns') if len({getattr(value, key) for value in snapshots.values()}) != 1}
            raise Failure('Input changed during bounded read: ' + str(file) + ' ' + json.dumps({
                'differing_fields': differences, 'observed_bytes': len(body), 'opened_bytes': opened.st_size,
                'observed_sha256': sha(body), 'maximum': maximum}, sort_keys=True))
        return bytes(body), {'bytes': len(body), 'sha256': sha(body), 'mode': format(stat.S_IMODE(opened.st_mode), '04o')}

    def generated(relative, directory=False):
        if native_destination is None or source is None:
            return False
        prefix = native_destination.relative_to(source).as_posix()
        if directory and relative in {'tools/lib/native', prefix}:
            return True
        if not relative.startswith(prefix + '/'):
            return False
        tail = relative[len(prefix) + 1:]
        if not directory and tail in {'lock-publication.node', 'lock-publication.manifest.json',
                                     'command-windows-job.node', 'command-windows-job.manifest.json'}:
            return True
        match = re.fullmatch(r'(\.build-|\.command-build-)[A-Za-z0-9]{6}(?:/(.*))?', tail)
        if not match:
            return False
        if directory:
            return match.group(2) is None
        stem = 'lock-publication' if match.group(1) == '.build-' else 'command-windows-job'
        return match.group(2) in {'BUILD.json', stem + '.c', stem + '.node', stem + '.obj', stem + '.lib', stem + '.exp'}

    def verify_source(source, manifest):
        expected = {row['path']: row for row in manifest['files']}
        parents = {parent.as_posix() for name in expected for parent in PurePosixPath(name).parents if parent.as_posix() != '.'}
        seen, changed = set(), []
        root_stat = source.lstat()
        if not stat.S_ISDIR(root_stat.st_mode) or stat.S_ISLNK(root_stat.st_mode):
            return ['[source root is not a physical directory]']
        for file in sorted(source.rglob('*')):
            relative = file.relative_to(source).as_posix()
            value = file.lstat()
            if stat.S_ISDIR(value.st_mode):
                if relative not in parents and not generated(relative, directory=True): changed.append(relative + '/')
                continue
            if not stat.S_ISREG(value.st_mode) or value.st_nlink != 1:
                changed.append(relative + ':type_or_links'); continue
            if relative not in expected:
                if not generated(relative): changed.append(relative + ':unexpected')
                continue
            seen.add(relative); row = expected[relative]
            body, observed = safe_bytes(file, SOURCE_LIMIT)
            expected_mode = extracted_modes.get(relative, row['mode'])
            if observed != {'bytes': row['bytes'], 'sha256': row['sha256'], 'mode': expected_mode}:
                changed.append(relative + ':bytes_mode_or_hash')
        changed.extend(name + ':missing' for name in sorted(set(expected) - seen))
        return sorted(changed)

    def native_snapshot():
        if native_destination is None:
            raise Failure('Native output directory is unavailable.')
        values = {}
        for name in ['lock-publication.node', 'lock-publication.manifest.json', 'command-windows-job.node', 'command-windows-job.manifest.json']:
            body, row = safe_bytes(native_destination / name)
            values[name] = {'body': body, **row}
        for stem, source_name in [('lock-publication', 'lock-publication.c'), ('command-windows-job', 'command-windows-job.c')]:
            item = json.loads(values[stem + '.manifest.json']['body'])
            binary = values[stem + '.node']
            if item.get('binary_sha256') != binary['sha256'] or item.get('binary_bytes') != binary['bytes'] or item.get('binary') != stem + '.node' or item.get('source_sha256') != file_sha(source / 'tools/native' / source_name):
                raise Failure('Native manifest/binary/source pins disagree: ' + stem)
        return values

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
                if mode and (not stat.S_ISREG(mode) or stat.S_IMODE(mode) != int(row['mode'], 8)):
                    raise Failure('Source ZIP contains a nonregular file.')
                body = archive.read(info)
                if sha(body) != row['sha256']:
                    raise Failure('Source ZIP member hash mismatch: ' + info.filename)
                destination = scratch.joinpath(*parts.parts)
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(body)
                destination.chmod(int(row['mode'], 8))
                extracted_modes[row['path']] = format(stat.S_IMODE(destination.stat().st_mode), '04o')
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

    def tests(node, names, label, source, platform_name, group, timeout=420):
        for name in names:
            if not (source / name).is_file():
                raise Failure('Requested test does not exist: ' + name)
        record, output = run(label, [node, '--test', '--test-reporter=tap', '--test-concurrency=1',
                                     *[source / name for name in names]], cwd=source, timeout=timeout, check=False)
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
    built_native = None
    try:
        manifest = json.loads(Path(args.manifest).read_text())
        (public / 'SOURCE_MANIFEST.json').write_text(json.dumps(manifest, indent=2) + '\n')
        result['source_zip_sha256'] = file_sha(args.archive)
        source = extract_source(Path(args.archive), manifest)
        node = Path(args.node).resolve(strict=True)
        _, observed = run('host-runtime', [node, '-p', 'JSON.stringify({platform:process.platform,architecture:process.arch,node:process.version,napi:process.versions.napi})'])
        host = json.loads(observed)
        result['runtime'] = host; result['runtime_binary_sha256'] = file_sha(node)
        if host['platform'] != 'win32' or host['architecture'] not in {'x64', 'arm64'}:
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
            run('build-command-job-addon', [node, source / 'tools/build-command-native.js',
                '--headers', headers, '--compiler', compiler, '--node-lib', node_lib,
                '--output', native_destination], cwd=source, timeout=180)
            result['windows_command_job'] = {'status': 'PASS_COMPILE_ONLY',
                'runtime_qualification': 'NOT_RUN', 'scope': 'Compilation complete; runtime stage has not completed.'}
            # Diagnose the actual Win32/NT relative rename boundary, including
            # no-replace collisions with a live immutable-owner Event. This probe
            # uses only controller-owned fixtures and is not a mock provider.
            probe_source = source / 'tests/helpers/reliability-windows-rename-probe.c'
            probe_binary = scratch / 'windows-relative-rename-probe.exe'
            run('build-windows-relative-rename-probe', [compiler, '/nologo', '/std:c11', '/W4', '/O2',
                '/Fe' + str(probe_binary), '/Fo' + str(scratch / 'windows-relative-rename-probe.obj'), probe_source,
                '/link', 'advapi32.lib'], cwd=scratch)
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
            run('linux-nested-observer-diagnostic',
                [node, source / 'tests/helpers/reliability-linux-nested-observer-diagnostic.cjs'], cwd=source, timeout=90)
        built_native = native_snapshot()
        result['native_after_build'] = {name: {k: v for k, v in row.items() if k != 'body'} for name, row in built_native.items()}
        info = "const q=require(process.argv[1]).qualifyNativePublication();console.log(JSON.stringify({node:process.version,napi:process.versions.napi,qualified:q.info,manifest:q.manifest}));"
        run('qualified-addon-current-runtime', [node, '-e', info, source / 'tools/lib/lock-publication.js'], cwd=source)
        if host['platform'] == 'win32':
            # All four files execute even when an earlier case fails. The
            # 900 s outer ceiling accommodates real 60 s negative cleanup
            # budgets across eight holder-lifecycle scenarios; product
            # budgets and per-case assertions are not changed by this gate.
            result['windows_command_job']['runtime_qualification'] = 'RUNNING'
            tests(node, ['tests/reliability-command-runner.test.js', 'tests/reliability-flow-owned.test.js',
                'tests/reliability-windows-command-lifecycle.test.js', 'tests/reliability-windows-team-crash.test.js',
                'tests/reliability-windows-bootstrap.test.js', 'tests/reliability-invocation-worker.test.js',
                'tests/reliability-holder-channel.test.js', 'tests/reliability-evaluation-preflight.test.js',
                'tests/reliability-sync-parent-channel.test.js'], 'windows-command-flow-lifecycle',
                source, host['platform'], 'windows_commands', timeout=1200)
            result['windows_command_job'] = {'status': 'PASS_SCOPED_RUNTIME',
                'runtime_qualification': 'PASS_EXPLICIT_CASES',
                'scope': 'Exact 57-case command/Flow/bootstrap/holder/Team/transport/evaluation group; three named Linux-only skips remain unqualified.'}
            tests(node, ['tests/reliability-kve-invocation-public.test.js'], 'windows-public-kve-crash-cancel',
                source, host['platform'], 'public_kve', timeout=600)
        tests(node, PRIMARY_TESTS, 'current-runtime-common-locks', source, host['platform'], 'main')
        tests(node, ['tests/reliability-owner-selftest-budget.test.js'], 'public-owner-slow-preparation',
            source, host['platform'], 'selftest_budget')
        if host['platform'] == 'linux':
            tests(node, ['tests/reliability-linux-authority-profile.test.js'], 'linux-actual-authority-profile',
                source, host['platform'], 'linux_authority')
        _, transition_output = run('public-owner-transitions', [node, source / 'tools/self-test-lock-owner-transitions.js'], cwd=source)
        transition = json.loads(transition_output)
        expected_transition_count = 29 if host['platform'] == 'win32' else 22
        if transition.get('failed') or transition.get('status') != 'passed' or \
                transition.get('total') != expected_transition_count or transition.get('passed') != expected_transition_count or \
                len(transition.get('checks', [])) != expected_transition_count:
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
        try:
            if source is not None and manifest is not None:
                result['source_changes_during_build_and_tests'] = verify_source(source, manifest)
                if result['source_changes_during_build_and_tests']:
                    result['status'] = 'FAIL'
            if built_native is not None:
                current = native_snapshot()
                same = all({k: v for k, v in current[name].items() if k != 'body'} ==
                           {k: v for k, v in built_native[name].items() if k != 'body'} for name in built_native)
                result['native_artifacts_unchanged_after_tests'] = same
                result['native_after_tests'] = {name: {k: v for k, v in row.items() if k != 'body'} for name, row in current.items()}
                if not same:
                    result['status'] = 'FAIL'
                if same and not result.get('source_changes_during_build_and_tests'):
                    exported = public / 'native' / native_destination.name
                    exported.mkdir(parents=True, exist_ok=True)
                    for name, row in current.items():
                        (exported / name).write_bytes(row['body'])
                    # Build receipts are diagnostic; they are never native runtime authority.
                    for entry in sorted(native_destination.iterdir()):
                        if entry.is_dir() and not entry.is_symlink() and re.fullmatch(r'\.(?:build|command-build)-[A-Za-z0-9]{6}', entry.name):
                            body, _ = safe_bytes(entry / 'BUILD.json', 4 * 1024 * 1024)
                            (exported / (entry.name[1:] + '-BUILD.json')).write_bytes(body)
                else:
                    result['native_export'] = 'WITHHELD_INPUT_OR_ARTIFACT_CHANGED'
            else:
                result['native_export'] = 'NOT_AVAILABLE_BUILD_NOT_COMPLETE'
        except Exception as error:
            result['status'] = 'FAIL'
            result['final_readback_error'] = {'type': type(error).__name__, 'message': str(error)}
        save()
        inventory = {str(file.relative_to(public)).replace(os.sep, '/'): {'bytes': file.stat().st_size, 'sha256': file_sha(file)}
                     for file in sorted(public.rglob('*')) if file.is_file()}
        (public / 'SHA256SUMS.json').write_text(json.dumps(inventory, indent=2) + '\n')
        print(json.dumps({'status': result['status'], 'result': str(public / 'RESULT.json'),
                          'scope': result['scope'], 'error': result.get('error')}, indent=2), flush=True)
    return 0 if result['status'] == 'PASS_SCOPED_NATIVE_RUNTIME' else 1


if __name__ == '__main__':
    raise SystemExit(main())
