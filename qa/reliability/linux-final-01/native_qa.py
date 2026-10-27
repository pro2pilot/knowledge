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
from nested_tap import assess_nested_tap, parse_nested_tap

LOG_LIMIT = 8 * 1024 * 1024
SOURCE_LIMIT = 64 * 1024 * 1024
LINUX_CAPABILITIES = {
    0: 'cap_chown', 1: 'cap_dac_override', 2: 'cap_dac_read_search', 3: 'cap_fowner',
    4: 'cap_fsetid', 5: 'cap_kill', 6: 'cap_setgid', 7: 'cap_setuid', 8: 'cap_setpcap',
    9: 'cap_linux_immutable', 10: 'cap_net_bind_service', 11: 'cap_net_broadcast',
    12: 'cap_net_admin', 13: 'cap_net_raw', 14: 'cap_ipc_lock', 15: 'cap_ipc_owner',
    16: 'cap_sys_module', 17: 'cap_sys_rawio', 18: 'cap_sys_chroot', 19: 'cap_sys_ptrace',
    20: 'cap_sys_pacct', 21: 'cap_sys_admin', 22: 'cap_sys_boot', 23: 'cap_sys_nice',
    24: 'cap_sys_resource', 25: 'cap_sys_time', 26: 'cap_sys_tty_config', 27: 'cap_mknod',
    28: 'cap_lease', 29: 'cap_audit_write', 30: 'cap_audit_control', 31: 'cap_setfcap',
    32: 'cap_mac_override', 33: 'cap_mac_admin', 34: 'cap_syslog', 35: 'cap_wake_alarm',
    36: 'cap_block_suspend', 37: 'cap_audit_read', 38: 'cap_perfmon', 39: 'cap_bpf',
    40: 'cap_checkpoint_restore',
}
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
LINUX_TESTS = [
    'tests/' + name + '.test.js' for name in [
        'audit-generators-boundaries', 'reliability-linux-authority-profile',
        'reliability-command-runner', 'reliability-flow-owned', 'reliability-lock-scope',
        'reliability-native-close-order', 'verification-linux-absence-visibility',
        'reliability-linux-namespace-link', 'reliability-linux-pidfd-binding',
        'reliability-native-clock', 'reliability-scope-query-budget',
        'reliability-scope-query-native-relay', 'reliability-invocation-worker',
        'reliability-holder-channel', 'reliability-evaluation-preflight',
        'reliability-kve-invocation-public', 'reliability-linux-natural-exit',
        'reliability-flow-long-work', 'reliability-sync-parent-channel',
        'reliability-progress-graceful-close', 'reliability-updater-bounded-read',
        'reliability-installed-native-modes']
]
NATIVE_FILES = ['lock-publication.node', 'lock-publication.manifest.json',
                'verification-linux-namespace', 'verification-linux-namespace.manifest.json']


def sha(body):
    return hashlib.sha256(body).hexdigest()


def file_sha(file):
    return sha(Path(file).read_bytes())


def kernel_denial_snapshot():
    """Read a bounded, read-only dmesg snapshot and retain only denial enums/digests."""
    limit = 1024 * 1024
    started = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
    executable = shutil.which('dmesg')
    if not executable:
        return {'status': 'unavailable', 'started_utc': started, 'events': []}
    proc = None
    streams = {}

    def drain(pipe, label):
        kept = bytearray();total = 0;hasher = hashlib.sha256()
        try:
            while True:
                chunk = pipe.read(16384)
                if not chunk: break
                total += len(chunk);hasher.update(chunk)
                kept.extend(chunk)
                if len(kept) > limit: del kept[:len(kept)-limit]
            streams[label] = {'body': bytes(kept), 'bytes': total, 'sha256': hasher.hexdigest(), 'eof': True}
        except Exception as error:
            streams[label] = {'body': bytes(kept), 'bytes': total, 'sha256': hasher.hexdigest(),
                              'eof': False, 'error_type': type(error).__name__}

    try:
        sudo = shutil.which('sudo')
        command = ([sudo, '-n', executable, '--time-format=iso'] if sudo else
                   [executable, '--time-format=iso'])
        proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        readers = [threading.Thread(target=drain, args=(proc.stdout, 'stdout'), daemon=True),
                   threading.Thread(target=drain, args=(proc.stderr, 'stderr'), daemon=True)]
        for reader in readers: reader.start()
        timed_out = False
        try: exit_code = proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            timed_out = True;proc.kill();exit_code = proc.wait(timeout=2)
        for reader in readers: reader.join(timeout=2)
        complete = all(not reader.is_alive() for reader in readers) and set(streams) == {'stdout', 'stderr'} and all(row.get('eof') for row in streams.values())
        out = streams.get('stdout', {}).get('body', b'')
        err = streams.get('stderr', {}).get('body', b'').decode('utf-8', errors='replace').lower()
        if timed_out: status = 'timeout'
        elif exit_code == 0 and complete: status = 'captured'
        elif 'permission denied' in err or 'operation not permitted' in err: status = 'permission_denied'
        else: status = 'unavailable'
        events = []
        if status == 'captured':
            for line in out.decode('utf-8', errors='replace').splitlines():
                lowered = line.lower()
                if not re.search(r'apparmor|seccomp|audit|userns|namespace|unshare|clone', lowered) or \
                        not re.search(r'denied|denial|eperm|eacces|permission|error=-1|error=-13', lowered):
                    continue
                field = lambda key: (re.search(r'\b' + re.escape(key) + r'="([^"]{1,160})"', line) or [None, None])[1]
                subsystem = next((name for name in ('apparmor', 'seccomp', 'audit', 'userns') if name in lowered), None)
                operation_value = field('operation')
                operation = operation_value if operation_value in {'userns_create', 'clone', 'clone3', 'unshare', 'capable'} else None
                class_value = field('class')
                class_name = class_value if class_value in {'namespace', 'userns', 'capability'} else None
                info_value = field('info')
                info_lower = (info_value or '').lower()
                info = ('user_namespace_restricted' if 'user namespace' in info_lower and 'restrict' in info_lower else
                        'unprivileged_userns_restricted' if 'unprivileged_userns' in info_lower else
                        'permission_denied' if 'permission' in info_lower or 'denied' in info_lower else None)
                errno_match = re.search(r'\b(?:error|errno)=(-?\d+)\b', line)
                errno_value = abs(int(errno_match.group(1))) if errno_match else None
                error_code = 'EPERM' if errno_value == 1 else 'EACCES' if errno_value == 13 else None
                profile_value = field('profile')
                profile = profile_value if profile_value in {'unprivileged_userns', 'unconfined'} else None
                capability_match = re.search(r'\b(?:capability|capable)=(\d+)\b', line)
                capability_number = int(capability_match.group(1)) if capability_match and int(capability_match.group(1)) in LINUX_CAPABILITIES else None
                pid_match = re.search(r'\bpid=(\d+)\b', line)
                stamp = re.match(r'^\[?((?:\d{4}-\d\d-\d\dT)?\d{2}:\d\d:\d\d(?:\.\d+)?Z?)\]?', line)
                events.append({'kernel_timestamp': stamp.group(1) if stamp else None, 'subsystem': subsystem,
                    'operation': operation, 'class': class_name, 'info': info, 'error_code': error_code,
                    'profile_allowlisted': profile, 'capability': capability_number,
                    'capability_name': LINUX_CAPABILITIES.get(capability_number),
                    'private_pid': int(pid_match.group(1)) if pid_match else None,
                    'line_sha256': sha(line.encode('utf-8'))})
        return {'status': status, 'started_utc': started,
                'stdout_sha256': streams.get('stdout', {}).get('sha256'),
                'stderr_sha256': streams.get('stderr', {}).get('sha256'),
                'truncated': any(row.get('bytes', 0) > limit for row in streams.values()),
                'events': events[-32:]}
    except OSError as error:
        return {'status': 'permission_denied' if error.errno in (1, 13) else 'unavailable',
                'started_utc': started, 'events': []}


def kernel_denial_delta(before, after, owned_processes):
    previous = {item['line_sha256'] for item in before.get('events', [])}
    status = 'captured' if before.get('status') == after.get('status') == 'captured' else \
        'permission_denied' if 'permission_denied' in (before.get('status'), after.get('status')) else after.get('status')
    attributed = []
    for item in after.get('events', []):
        owned = owned_processes.get(item.get('private_pid'))
        if item['line_sha256'] in previous or not owned or not item.get('operation'):
            continue
        projected = {key: value for key, value in item.items() if key != 'private_pid'}
        projected['sampled_process_label'] = owned[1] if isinstance(owned, tuple) else owned
        projected['attribution'] = 'numeric_pid_and_test_window_correlation_only'
        projected['causal_proof'] = False
        attributed.append(projected)
    if status == 'captured' and after.get('events') and not attributed:
        status = 'captured_no_attributed_denial'
    return {'status': status, 'window_start_utc': before.get('started_utc'),
            'window_end_utc': after.get('started_utc'), 'before_stdout_sha256': before.get('stdout_sha256'),
            'after_stdout_sha256': after.get('stdout_sha256'), 'causal_proof': False, 'events': attributed[-32:]}


def sample_owned_process_tree(root_pid, owned):
    """Keep a private PID→synthetic-label map for this test subprocess tree only."""
    pending = [root_pid]
    seen = set()
    while pending and len(seen) < 128:
        pid = pending.pop()
        if pid in seen: continue
        seen.add(pid)
        try:
            raw_stat = Path('/proc', str(pid), 'stat').read_text(encoding='ascii')
            remainder = raw_stat[raw_stat.rfind(')')+1:].split()
            start_ticks = remainder[19]
            if pid not in owned:
                owned[pid] = (start_ticks, 'nested_authority_runner' if pid == root_pid else f'nested_authority_child_{len(owned):03d}')
            elif owned[pid][0] != start_ticks:
                continue
            children = Path('/proc', str(pid), 'task', str(pid), 'children').read_text(encoding='ascii')
            pending.extend(int(value) for value in children.split() if value.isdigit())
        except (OSError, IndexError, ValueError):
            continue


def nested_denial_projection(output):
    """Extract only the fixed nested-setup diagnostic tuple, never TAP/raw text."""
    pattern = re.compile(r'\\?"stage\\?"\s*:\s*\\?"(nested_native_setup)\\?"\s*,\s*'
        r'\\?"depth\\?"\s*:\s*(\d+)\s*,\s*\\?"uid\\?"\s*:\s*\d+\s*,\s*'
        r'\\?"code\\?"\s*:\s*\\?"(namespace_create_denied)\\?"\s*,\s*'
        r'\\?"native_errno\\?"\s*:\s*(\d+)\s*,\s*\\?"native_observer_stage\\?"\s*:\s*(\d+)')
    rows = set()
    for match in pattern.finditer(output):
        stage, depth, code, errno, observer_stage = match.groups()
        rows.add((stage, int(depth), code, int(errno), int(observer_stage)))
    return [{'stage': stage, 'depth': depth, 'error_code': code, 'native_errno': errno,
             'errno_name': 'EPERM' if errno == 1 else 'EACCES' if errno == 13 else 'OTHER',
             'native_observer_stage': observer_stage}
            for stage, depth, code, errno, observer_stage in sorted(rows) if 1 <= depth <= 3 and errno in (1, 13)]


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
    parser.add_argument('--public-invocation-fixture')
    parser.add_argument('--public-invocation-fixture-sha256')
    parser.add_argument('--suite', choices=['full', 'linux-nested-diagnostic'], default='full')
    args = parser.parse_args()
    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=False)
    public, scratch = out / 'public', out / 'scratch'
    public.mkdir(); scratch.mkdir(mode=0o700 if args.suite == 'linux-nested-diagnostic' else 0o755)
    case_policy_path = Path(__file__).with_name('EXPECTED_CASES.json')
    case_policy = json.loads(case_policy_path.read_text())
    if case_policy.get('schema_version') != 'knowledge-native-qa-case-policy.v1':
        raise Failure('Unknown case qualification policy.')
    safe_target = args.suite == 'linux-nested-diagnostic'
    private_steps = scratch / 'private-steps'
    if safe_target: private_steps.mkdir(mode=0o700)
    owned_process_map = {}
    result = {'schema_version': 'knowledge-native-runtime-qa.v1', 'status': 'RUNNING',
              'scope': ('Targeted Linux ARM64 native build, read-only host probes and three real nested-authority cases; no full runtime qualification.' if args.suite == 'linux-nested-diagnostic' else
                  'Frozen Linux reliability cohort. Actual common-lock N-API and namespace builds precede exact nested runtime cases, common locks, public repair/update/namespace self-tests and actual Node 18 ABI checks. Host policy remains unchanged; no whole-release qualification.'),
              'release_gate_qualified': False,
              'controller_sha256': file_sha(__file__), 'python_version': platform.python_version(), 'case_policy_sha256': file_sha(case_policy_path), 'host': platform.platform(),
              'commit': os.environ.get('GITHUB_SHA'), 'steps': [], 'downloads': []}
    (public / 'EXPECTED_CASES.json').write_text(json.dumps(case_policy, indent=2) + '\n')
    env = dict(os.environ)
    env.update({'NODE_OPTIONS': '', 'NODE_PATH': '', 'CI': 'true',
                'TMPDIR': str(scratch / 'tmp'), 'TMP': str(scratch / 'tmp'), 'TEMP': str(scratch / 'tmp')})
    for name in ['KNOWLEDGE_LOCK_TEST_SOURCE', 'KNOWLEDGE_AUDIT_SYSTEM_ROOT',
                 'KNOWLEDGE_LOCK_TIMEOUT_MS', 'KNOWLEDGE_LOCK_STALE_MS', 'KNOWLEDGE_PUBLIC_INVOCATION_SOURCE']:
        env.pop(name, None)
    (scratch / 'tmp').mkdir()
    result['controlled_environment'] = ({'NODE_OPTIONS': '', 'NODE_PATH': '', 'CI': 'true',
        'TMPDIR': 'private_scratch', 'TMP': 'private_scratch', 'TEMP': 'private_scratch'} if safe_target else
        {key: env[key] for key in ['NODE_OPTIONS', 'NODE_PATH', 'CI', 'TMPDIR', 'TMP', 'TEMP']})

    def save():
        (public / 'RESULT.json').write_text(json.dumps(result, indent=2) + '\n')

    def run(name, command, cwd=None, timeout=180, check=True, observe_owned_processes=False):
        command = [str(x) for x in command]
        folder = (private_steps if safe_target else public / 'steps') / ('%02d-' % (len(result['steps']) + 1) + name)
        folder.mkdir(parents=True)
        print(json.dumps({'phase': name, 'timeout_seconds': timeout}), flush=True)
        record = {'name': name, 'timeout_seconds': timeout, 'started_utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}
        if safe_target:
            record.update(command_sha256=sha(json.dumps(command, separators=(',', ':')).encode()),
                          cwd_role='pinned_source' if cwd == source else 'qa_controller')
        else:
            record.update(command=command, cwd=str(cwd) if cwd else None)
        result['steps'].append(record); save()
        started = time.monotonic()
        proc = subprocess.Popen(command, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                start_new_session=os.name != 'nt')
        if observe_owned_processes: owned_process_map.clear()
        if safe_target: record['process_identity'] = 'native_qa_child'
        else: record['pid'] = proc.pid
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
                read_error = {'type': type(error).__name__} if safe_target else {'type': type(error).__name__, 'message': str(error)}
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
            if observe_owned_processes:
                deadline = time.monotonic() + timeout
                while proc.poll() is None:
                    sample_owned_process_tree(proc.pid, owned_process_map)
                    remaining = deadline - time.monotonic()
                    if remaining <= 0: raise subprocess.TimeoutExpired(command, timeout)
                    try: proc.wait(timeout=min(0.02, remaining))
                    except subprocess.TimeoutExpired: pass
            else:
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
            if safe_target and isinstance(record[label].get('read_error'), dict):
                record[label]['read_error'] = {'type': record[label]['read_error'].get('type')}
            record[label]['retained_sha256'] = sha(stream['body'])
        if observe_owned_processes:
            record['test_owned_process_count'] = len(owned_process_map)
        record['result'] = 'FAIL' if timed_out or incomplete or proc.returncode != 0 or set(streams) != {'stdout', 'stderr'} or any(v.get('truncated') or not v.get('eof') or v.get('read_error') for v in streams.values()) else 'PASS'
        save()
        if record['result'] != 'PASS' and check:
            raise Failure('Command failed: ' + name if safe_target else 'Command failed; exact raw output is retained: ' + name)
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
        fd = os.open(file, os.O_RDONLY | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
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
        if not directory and tail in set(NATIVE_FILES):
            return True
        match = re.fullmatch(r'(\.build-)[A-Za-z0-9]{6}(?:/(.*))?', tail)
        if not match:
            return False
        if directory:
            return match.group(2) is None
        return match.group(2) in {'BUILD.json', 'lock-publication.c', 'lock-publication.node'}

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
        for name in NATIVE_FILES:
            body, row = safe_bytes(native_destination / name)
            values[name] = {'body': body, **row}
        for stem, binary_name, source_name in [
            ('lock-publication', 'lock-publication.node', 'tools/native/lock-publication.c'),
            ('verification-linux-namespace', 'verification-linux-namespace', 'tools/lib/verification-linux-namespace.c')]:
            item = json.loads(values[stem + '.manifest.json']['body'])
            binary = values[binary_name]
            source_body, _ = safe_bytes(source / source_name)
            if item.get('platform') != host['platform'] or item.get('architecture') != host['architecture'] or item.get('binary_sha256') != binary['sha256'] or item.get('binary_bytes') != binary['bytes'] or item.get('binary') != binary_name or item.get('source_sha256') != sha(source_body):
                raise Failure('Native manifest/binary/source/platform pins disagree: ' + stem)
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

    external_public_invocation = None

    def tests(node, names, label, source, platform_name, group, timeout=420):
        for name in names:
            if not (source / name).is_file():
                raise Failure('Requested test does not exist: ' + name)
        paths = [source / name for name in names]
        external_used = group == 'linux_runtime' and external_public_invocation is not None
        if external_used:
            original = 'tests/reliability-kve-invocation-public.test.js'
            if names.count(original) != 1 or file_sha(external_public_invocation) != args.public_invocation_fixture_sha256:
                raise Failure('External invocation fixture binding changed before execution.')
            paths[names.index(original)] = external_public_invocation
        record, output = run(label, [node, '--test', '--test-reporter=tap', '--test-concurrency=1',
                                     *paths], cwd=source, timeout=timeout, check=False)
        decoded = output.decode('utf-8', errors='strict')
        record['requested_test_files'] = names
        record['executed_test_files'] = [str(path) for path in paths]
        if external_used:
            record['external_public_invocation_fixture'] = result['external_public_invocation_fixture']
            if file_sha(external_public_invocation) != args.public_invocation_fixture_sha256:
                raise Failure('External invocation fixture binding changed during execution.')
        assessed = (assess_nested_tap if group == 'linux_runtime' else assess_tap)(decoded, platform_name, group, case_policy)
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
        if bool(args.public_invocation_fixture) != bool(args.public_invocation_fixture_sha256):
            raise Failure('External invocation fixture requires both an explicit path and SHA256.')
        if args.public_invocation_fixture:
            expected = args.public_invocation_fixture_sha256
            if not re.fullmatch(r'[a-f0-9]{64}', expected):
                raise Failure('Invalid external invocation fixture SHA256.')
            supplied = Path(args.public_invocation_fixture).resolve(strict=True)
            with supplied.open('rb') as handle:
                body = handle.read(1024 * 1024 + 1)
            if len(body) > 1024 * 1024 or sha(body) != expected:
                raise Failure('External invocation fixture does not match its bounded SHA256 binding.')
            original = 'tests/reliability-kve-invocation-public.test.js'
            base_sha = file_sha(source / original)
            if base_sha != '18906a5e77bd05fd35ebeefc2ef4d96085c5b84c750ab566b481fd73270dfdec':
                raise Failure('External invocation fixture is not derived from the frozen 675-file source fixture.')
            external_public_invocation = scratch / 'public-invocation-idempotence.test.js'
            external_public_invocation.write_bytes(body)
            (public / 'PUBLIC_INVOCATION_FIXTURE.js').write_bytes(body)
            env['KNOWLEDGE_PUBLIC_INVOCATION_SOURCE'] = str(source)
            result['external_public_invocation_fixture'] = {
                'sha256': expected, 'bytes': len(body), 'artifact': 'PUBLIC_INVOCATION_FIXTURE.js',
                'derived_from': original, 'derived_from_sha256': base_sha,
                'runtime_source_zip_sha256': result['source_zip_sha256'],
                'runtime_source': str(source), 'source_inventory_modified': False,
                'reason': 'External and automatic crash recovery may race; identical failed terminal attempt, generation, invocation and native closure proof remain mandatory.',
                'case_count': 3, 'case_names_and_budgets_unchanged': True}
        node = Path(args.node).resolve(strict=True)
        _, observed = run('host-runtime', [node, '-p', 'JSON.stringify({platform:process.platform,architecture:process.arch,node:process.version,napi:process.versions.napi})'])
        host = json.loads(observed)
        result['runtime'] = host; result['runtime_binary_sha256'] = file_sha(node)
        if host['platform'] != 'linux' or host['architecture'] not in {'x64', 'arm64'}:
            raise Failure('Host platform/architecture is outside the explicit native matrix.')
        if args.suite == 'linux-nested-diagnostic' and (host['platform'], host['architecture']) != ('linux', 'arm64'):
            raise Failure('Targeted nested diagnostic requires linux/arm64.')
        version = '18.20.8'
        headers_archive = download(version, 'node-v' + version + '-headers.tar.gz')
        headers = extract_toolchain(headers_archive) / ('node-v' + version) / 'include' / 'node'
        native_destination = source / 'tools' / 'lib' / 'native' / (host['platform'] + '-' + host['architecture'])
        command = [node, source / 'tools/build-lock-native.js', '--headers', headers, '--output', native_destination]
        run('build-native-addon', command, cwd=source, timeout=180)
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
        built_native = native_snapshot()
        result['native_after_build'] = {name: {k: v for k, v in row.items() if k != 'body'} for name, row in built_native.items()}
        # Preserve actual setup stage/errno and read-only host policy;
        # observation completion is not feature qualification. The full
        # subsequent suite retains every existing pass/fail assertion.
        run('linux-namespace-capability-diagnostic',
            [node, source / 'tests/helpers/reliability-linux-capability-diagnostic.cjs'], cwd=source, timeout=90,
            check=args.suite != 'linux-nested-diagnostic')
        run('linux-nested-observer-diagnostic',
            [node, source / 'tests/helpers/reliability-linux-nested-observer-diagnostic.cjs'], cwd=source, timeout=90,
            check=args.suite != 'linux-nested-diagnostic')
        info = "const q=require(process.argv[1]).qualifyNativePublication();console.log(JSON.stringify({node:process.version,napi:process.versions.napi,qualified:q.info,manifest:q.manifest}));"
        run('qualified-addon-current-runtime', [node, '-e', info, source / 'tools/lib/lock-publication.js'], cwd=source,
            check=args.suite != 'linux-nested-diagnostic')
        if args.suite == 'linux-nested-diagnostic':
            expected_nested_cases = [
                'nonzero UID: three real authority scopes retain no capabilities and preserve UID mapping',
                'current UID: the exact nested mapping determines the authority capability profile',
                'nonzero UID: ordinary command workers remain in the zero-capability profile',
            ]
            before = kernel_denial_snapshot()
            record, output = run('linux-nested-authority-diagnostic', [node, '--test', '--test-reporter=tap',
                '--test-concurrency=1', source / 'tests/reliability-linux-authority-profile.test.js'],
                cwd=source, timeout=120, check=False, observe_owned_processes=True)
            record['kernel_denial_capture'] = kernel_denial_delta(before, kernel_denial_snapshot(), owned_process_map)
            parsed = parse_nested_tap(output.decode('utf-8', errors='strict'))
            record['nested_failure_projection'] = nested_denial_projection(output.decode('utf-8', errors='replace'))
            observed = [case['path'][-1] for case in parsed['cases']]
            counts = parsed.get('counts', {})
            qualified = parsed.get('valid_structure') is True and observed == expected_nested_cases and counts == {
                'tests': 3, 'suites': 0, 'pass': 3, 'fail': 0, 'cancelled': 0, 'skipped': 0, 'todo': 0} and \
                all(case['outcome'] == 'ok' and case['directive'] is None for case in parsed['cases']) and \
                record.get('result') == 'PASS'
            record['nested_case_counts'] = counts
            record['nested_case_names'] = observed
            record['exact_nested_contract'] = bool(qualified)
            record['result'] = 'PASS' if qualified else 'FAIL'
            result['targeted_suite'] = {'status': 'PASS_SCOPED_NESTED_DIAGNOSTIC' if qualified else 'FAIL',
                'case_count': len(observed), 'expected_case_count': len(expected_nested_cases),
                'kernel_denial_capture_status': record['kernel_denial_capture']['status'],
                'release_gate_qualified': False}
            save()
            if not qualified:
                raise Failure('Targeted nested authority diagnostic failed.')
            changed = verify_source(source, manifest)
            result['source_changes_during_build_and_tests'] = changed
            if changed:
                raise Failure('Source input changed during targeted native diagnostic.')
            diagnostic_steps_pass = all(step.get('result') == 'PASS' for step in result['steps'])
            if not diagnostic_steps_pass:
                result['targeted_suite']['status'] = 'FAIL'
                result['status'] = 'FAIL'
            else:
                result['status'] = 'PASS_SCOPED_NATIVE_DIAGNOSTIC'
        else:
            tests(node, LINUX_TESTS, 'linux-actual-reliability', source, host['platform'], 'linux_runtime', timeout=1200)
            tests(node, PRIMARY_TESTS, 'current-runtime-common-locks', source, host['platform'], 'main')
            tests(node, ['tests/reliability-owner-selftest-budget.test.js'], 'public-owner-slow-preparation',
                source, host['platform'], 'selftest_budget')
            _, transition_output = run('public-owner-transitions', [node, source / 'tools/self-test-lock-owner-transitions.js'], cwd=source)
            transition = json.loads(transition_output)
            expected_transition_count = 22
            if transition.get('failed') or transition.get('status') != 'passed' or \
                    transition.get('total') != expected_transition_count or transition.get('passed') != expected_transition_count or \
                    len(transition.get('checks', [])) != expected_transition_count:
                raise Failure('Public transition self-test did not pass.')
            result['public_transition_counts'] = {key: transition[key] for key in ['total', 'passed', 'failed']}
            public_checks = {}
            for script, label, minimum in [
                ('tools/self-test-repair-on-touch.js', 'public-repair-on-touch', 104),
                ('tools/self-test-update-safety.js', 'public-update-safety', 15),
                ('tools/self-test-repair-audit.js', 'public-repair-audit', 14),
                ('tools/self-test-linux-namespace.js', 'public-linux-namespace', 15)]:
                record, output = run(label, [node, source / script], cwd=source, timeout=600, check=False)
                try:
                    observation = json.loads(output.decode('utf-8'))
                    if label == 'public-linux-namespace':
                        rows = observation.get('results', [])
                        valid = observation.get('schema_version') == 'knowledge-linux-namespace-selftest.v1' and observation.get('platform') == 'linux' and observation.get('architecture') == host['architecture'] and len(rows) == minimum and observation.get('pass') == minimum and observation.get('fail') == 0 and observation.get('blocked') == 0 and len({row.get('name') for row in rows}) == minimum and all(row.get('status') == 'PASS' for row in rows)
                        counts = {key: observation.get(key) for key in ['pass', 'fail', 'blocked']}
                    elif label == 'public-repair-audit':
                        rows = observation.get('checks', [])
                        valid = observation.get('schema_version') == 'knowledge-repair-audit-self-test.v1' and observation.get('status') == 'pass' and len(rows) == minimum and observation.get('passed') == minimum and observation.get('failed') == 0 and len({row.get('name') for row in rows}) == minimum and all(row.get('status') == 'pass' for row in rows)
                        counts = {'passed': observation.get('passed'), 'failed': observation.get('failed')}
                    else:
                        rows = observation.get('checks', [])
                        valid = observation.get('status') == 'pass' and observation.get('checks_total') == len(rows) and len(rows) >= minimum and all(isinstance(name, str) and name for name in rows) and len(set(rows)) == len(rows)
                        counts = {'checks_total': observation.get('checks_total'), 'required_minimum_checks': minimum}
                    public_checks[label] = {'valid': bool(valid), 'counts': counts, 'reported_case_names': [row['name'] for row in rows] if label in {'public-linux-namespace', 'public-repair-audit'} else rows}
                except Exception as error:
                    valid = False
                    public_checks[label] = {'valid': False, 'parse_error': type(error).__name__}
                result['public_self_tests'] = public_checks
                save()
                if record['result'] != 'PASS' or not valid:
                    raise Failure('Public self-test did not satisfy its explicit result contract: ' + label)
            name = 'node-v18.20.8-linux-' + host['architecture']
            distribution = extract_toolchain(download('18.20.8', name + '.tar.xz')) / name
            legacy_node = distribution / 'bin/node'
            legacy_node.chmod(0o755)
            run('qualified-addon-node18', [legacy_node, '-e', info, source / 'tools/lib/lock-publication.js'], cwd=source)
            tests(legacy_node, ABI_TESTS, 'node18-actual-abi-and-lifecycle', source, host['platform'], 'node18')
            changed = verify_source(source, manifest)
            result['source_changes_during_build_and_tests'] = changed
            if changed:
                raise Failure('Source input changed during native QA.')
            result['status'] = 'PASS_SCOPED_NATIVE_RUNTIME'
    except Exception as error:
        result['status'] = 'FAIL'
        result['error'] = {'type': type(error).__name__}
        if not safe_target:
            result['error']['message'] = str(error)
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
                        if entry.is_dir() and not entry.is_symlink() and re.fullmatch(r'\.build-[A-Za-z0-9]{6}', entry.name):
                            body, _ = safe_bytes(entry / 'BUILD.json', 4 * 1024 * 1024)
                            if safe_target:
                                result.setdefault('native_build_receipts', []).append({'sha256': sha(body), 'bytes': len(body), 'raw_receipt': 'private'})
                            else:
                                (exported / (entry.name[1:] + '-BUILD.json')).write_bytes(body)
                else:
                    result['native_export'] = 'WITHHELD_INPUT_OR_ARTIFACT_CHANGED'
            else:
                result['native_export'] = 'NOT_AVAILABLE_BUILD_NOT_COMPLETE'
        except Exception as error:
            result['status'] = 'FAIL'
            result['final_readback_error'] = {'type': type(error).__name__}
            if not safe_target:
                result['final_readback_error']['message'] = str(error)
        save()
        inventory = {str(file.relative_to(public)).replace(os.sep, '/'): {'bytes': file.stat().st_size, 'sha256': file_sha(file)}
                     for file in sorted(public.rglob('*')) if file.is_file()}
        (public / 'SHA256SUMS.json').write_text(json.dumps(inventory, indent=2) + '\n')
        print(json.dumps({'status': result['status'], 'result': str(public / 'RESULT.json'),
                          'scope': result['scope'], 'error': result.get('error')}, indent=2), flush=True)
    return 0 if result['status'] in {'PASS_SCOPED_NATIVE_RUNTIME', 'PASS_SCOPED_NATIVE_DIAGNOSTIC'} else 1


if __name__ == '__main__':
    raise SystemExit(main())
