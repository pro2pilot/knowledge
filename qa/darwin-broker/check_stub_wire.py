"""Bounded, decode-only wire parser checks for the experimental Darwin stub.

On macOS, run the binary built by compile_native.py as the ordinary workflow
user. This checks C decoding only; it does not launch the privileged stub or
qualify a backend. On other platforms, --self-check validates serializer bounds
without claiming native coverage.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import struct
import subprocess
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
OUT = HERE / 'evidence'
WIRE_MAX = 1024 * 1024
STRING_MAX = 131072
ENV_MAX = 131329
HEX = 'a' * 64
RUNTIME = 'b' * 64


def _bytes(value):
    return value.encode('utf-8') if isinstance(value, str) else bytes(value)


def _field(value):
    value = _bytes(value)
    return struct.pack('!I', len(value)) + value


def body(*, uid=1000000123, deadline=None, attempt=HEX, runtime=RUNTIME,
         cwd='workspace', profile='(version 1) (deny default)', argv=None, env=None):
    """Serialize the exact KVS1 C struct fields; byte values enable malformed cases."""
    argv = ['/usr/bin/true'] if argv is None else argv
    env = [] if env is None else env
    deadline = int(time.monotonic() * 1000) + 300000 if deadline is None else deadline
    out = bytearray(struct.pack('!IIIIQQQQQ', 0x4B565331, uid, len(argv), len(env),
                                deadline, 1, 2, 3, 4))
    for value in (attempt, runtime, cwd, profile):
        out.extend(_field(value))
    for value in argv:
        out.extend(_field(value))
    for value in env:
        out.extend(_field(value))
    return bytes(out)


def frame(data):
    return struct.pack('!I', len(data)) + data


def _max_body():
    profile = '(version 1) (deny default)'
    argv = ['/usr/bin/true']
    current = body(profile=profile, argv=argv)
    while True:
        remaining = WIRE_MAX - len(current)
        if remaining < 8:
            profile += ' ' * (8 - remaining)
            current = body(profile=profile, argv=argv)
            remaining = WIRE_MAX - len(current)
        if remaining <= STRING_MAX + 8:
            amount = remaining - 8
            if amount < 0 or amount > STRING_MAX:
                raise AssertionError('cannot exactly fill KVS1 body with a final empty argv field')
            argv.extend((b'Z' * amount, ''))
            current = body(profile=profile, argv=argv)
            break
        if len(argv) >= 256:
            raise AssertionError('argv count limit reached while filling maximum body')
        argv.append(b'Z' * STRING_MAX)
        current = body(profile=profile, argv=argv)
    if len(current) != WIRE_MAX:
        raise AssertionError('maximum-body fixture crossed the 1 MiB boundary')
    return current, argv


def cases():
    maximum, max_argv = _max_body()
    valid = body()
    cases = [
        ('valid_ascii', frame(valid), 0, (1, 0)),
        ('valid_unicode_profile_and_env', frame(body(profile='(unicode: café 雪)', env=['LANG=es_MX.UTF-8'])), 0, (1, 1)),
        ('valid_empty_argv_item', frame(body(argv=['/usr/bin/true', ''])), 0, (2, 0)),
        ('valid_profile_exact_limit', frame(body(profile=b'P' * STRING_MAX)), 0, (1, 0)),
        ('valid_body_exact_1mib', frame(maximum), 0, (len(max_argv), 0)),
        ('valid_future_monotonic_deadline_5m', frame(body(deadline=int(time.monotonic() * 1000) + 300000)), 0, (1, 0)),
    ]

    bad_magic = bytearray(valid); bad_magic[0:4] = struct.pack('!I', 0)
    uid_zero = bytearray(valid); uid_zero[4:8] = struct.pack('!I', 0)
    argc_zero = bytearray(valid); argc_zero[8:12] = struct.pack('!I', 0)
    argc_large = bytearray(valid); argc_large[8:12] = struct.pack('!I', 257)
    envc_large = bytearray(valid); envc_large[12:16] = struct.pack('!I', 257)
    deadline_zero = bytearray(valid); deadline_zero[16:24] = struct.pack('!Q', 0)
    bad_attempt = body(attempt='g' + 'a' * 63)
    cases.extend([
        ('truncated_outer_header', b'\x00\x00\x00', 64, None),
        ('truncated_body', struct.pack('!I', len(valid) + 1) + valid, 64, None),
        ('outer_oversize', struct.pack('!I', WIRE_MAX + 1), 64, None),
        ('bad_magic', frame(bad_magic), 64, None),
        ('uid_zero', frame(uid_zero), 64, None),
        ('argc_zero', frame(argc_zero), 64, None),
        ('argc_over_limit', frame(argc_large), 64, None),
        ('envc_over_limit', frame(envc_large), 64, None),
        ('zero_deadline', frame(deadline_zero), 64, None),
        ('attempt_not_lower_hex', frame(bad_attempt), 64, None),
        ('absolute_cwd', frame(body(cwd='/absolute')), 64, None),
        ('parent_component_cwd', frame(body(cwd='a/../b')), 64, None),
        ('empty_profile', frame(body(profile='')), 64, None),
        ('profile_over_limit', frame(body(profile=b'P' * (STRING_MAX + 1))), 64, None),
        ('argv_item_over_limit', frame(body(argv=['/usr/bin/true', b'A' * (STRING_MAX + 1)])), 64, None),
        ('environment_item_over_limit', frame(body(env=['K=' + ('V' * (ENV_MAX - 1))])), 64, None),
        ('embedded_nul', frame(body(env=['K=a\x00b'])), 64, None),
        ('invalid_utf8', frame(body(argv=['/usr/bin/true', b'\xff'])), 64, None),
        ('trailing_body_byte', frame(valid + b'X'), 64, None),
        ('trailing_outer_byte', frame(valid) + b'X', 64, None),
        ('duplicate_environment_key', frame(body(env=['DUP=one', 'DUP=two'])), 64, None),
        ('invalid_environment_name', frame(body(env=['BAD-NAME=value'])), 64, None),
        ('forbidden_dyld_insert', frame(body(env=['DYLD_INSERT_LIBRARIES=/tmp/x'])), 64, None),
        ('forbidden_dyld_framework', frame(body(env=['DYLD_FRAMEWORK_PATH=/tmp'])), 64, None),
        ('forbidden_node_options', frame(body(env=['NODE_OPTIONS=--require=x'])), 64, None),
        ('forbidden_bash_env', frame(body(env=['BASH_ENV=/tmp/x'])), 64, None),
        ('forbidden_env', frame(body(env=['ENV=/tmp/x'])), 64, None),
    ])
    # Invalid claimed lengths are rejected before allocation or decoding.
    overread = bytearray(valid)
    overread[56:60] = struct.pack('!I', 0xFFFFFFFF)  # first string length
    cases.append(('string_length_exceeds_remaining_body', frame(overread), 64, None))
    cases.append(('argc_claim_exceeds_payload', frame(bytearray(valid[:8] + struct.pack('!I', 2) + valid[12:])), 64, None))
    cases.append(('envc_claim_exceeds_payload', frame(bytearray(valid[:12] + struct.pack('!I', 1) + valid[16:])), 64, None))
    return cases


def self_check():
    exact, max_argv = _max_body()
    assert len(exact) == WIRE_MAX
    assert max_argv[-1] == ''  # KVS1 permits an empty argv field.
    assert len(frame(exact)) == WIRE_MAX + 4
    assert len(body(profile=b'P' * STRING_MAX)) <= WIRE_MAX
    assert len(body(env=['K=' + 'V' * (ENV_MAX - 2)])) < WIRE_MAX
    assert len(cases()) == 36
    print(json.dumps({'status': 'PORTABLE_SERIALIZER_SELF_CHECK_PASS',
                      'native_parser_run': False, 'backend_certified': False,
                      'cases_prepared': len(cases()), 'max_body_bytes': len(exact)}))
    return 0


def _digest_file(path):
    digest = hashlib.sha256()
    with path.open('rb') as source:
        for chunk in iter(lambda: source.read(65536), b''):
            digest.update(chunk)
    return digest.hexdigest()


def _capture_digest(fileobj, maximum=65536):
    fileobj.flush()
    size = os.fstat(fileobj.fileno()).st_size
    fileobj.seek(0)
    digest = hashlib.sha256()
    prefix = bytearray()
    while True:
        chunk = fileobj.read(65536)
        if not chunk:
            break
        digest.update(chunk)
        if len(prefix) < maximum + 1:
            prefix.extend(chunk[:maximum + 1 - len(prefix)])
    data = bytes(prefix)
    return digest.hexdigest(), size, data[:maximum], size <= maximum


def _typed_reply(raw, expected_counts):
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return False, None
    expected_keys = {'schema', 'decode_only', 'argc', 'envc', 'capability_qualified'}
    if not isinstance(value, dict) or set(value) != expected_keys:
        return False, None
    argc, envc = expected_counts
    valid = (value.get('schema') == 'knowledge-darwin-wire-check.v1'
             and value.get('decode_only') is True and type(value.get('argc')) is int
             and value.get('argc') == argc and type(value.get('envc')) is int
             and value.get('envc') == envc and value.get('capability_qualified') is False)
    return valid, value if valid else None


def native_run():
    if platform.system() != 'Darwin':
        print(json.dumps({'status': 'NOT_RUN_NON_DARWIN', 'native_parser_run': False,
                          'backend_certified': False}))
        return 2
    if not hasattr(os, 'getuid') or os.getuid() == 0 or os.geteuid() == 0:
        print(json.dumps({'status': 'NOT_RUN_REQUIRES_ORDINARY_UID', 'native_parser_run': False,
                          'backend_certified': False}))
        return 2
    binary = OUT / 'knowledge-native-stub'
    if not binary.is_file() or not os.access(binary, os.X_OK):
        print(json.dumps({'status': 'NOT_RUN_STUB_BINARY_MISSING', 'native_parser_run': False,
                          'backend_certified': False, 'binary_path': str(binary)}))
        return 2

    OUT.mkdir(exist_ok=True)
    blocked = ('DYLD_',)
    env = {key: value for key, value in os.environ.items()
           if not key.startswith(blocked) and key not in ('NODE_OPTIONS', 'BASH_ENV', 'ENV')}
    argv = [str(binary), '--check-config']
    runs = []
    all_passed = True
    for name, payload, expected_exit, expected_counts in cases():
        started = time.monotonic()
        timed_out = False
        return_code = None
        with tempfile.TemporaryFile() as stdout_file, tempfile.TemporaryFile() as stderr_file:
            try:
                proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=stdout_file,
                                        stderr=stderr_file, cwd=str(HERE), env=env,
                                        close_fds=True, shell=False)
                proc.communicate(payload, timeout=8)
                return_code = proc.returncode
            except subprocess.TimeoutExpired:
                timed_out = True
                proc.kill()
                proc.communicate()
                return_code = proc.returncode
            stdout_sha, stdout_size, stdout_bytes, stdout_bounded = _capture_digest(stdout_file)
            stderr_sha, stderr_size, _, stderr_bounded = _capture_digest(stderr_file)
        reply_ok, decoded = (False, None)
        if expected_exit == 0 and return_code == 0 and stdout_bounded and stderr_bounded:
            reply_ok, decoded = _typed_reply(stdout_bytes, expected_counts)
        passed = (not timed_out and return_code == expected_exit and stdout_bounded
                  and stderr_bounded and (reply_ok if expected_exit == 0 else stdout_size == 0))
        all_passed = all_passed and passed
        entry = {'name': name, 'argv': argv, 'exit_code': return_code,
                 'expected_exit_code': expected_exit, 'elapsed_ms': round((time.monotonic() - started) * 1000, 3),
                 'payload_bytes': len(payload), 'payload_sha256': hashlib.sha256(payload).hexdigest(),
                 'stdout_bytes': stdout_size, 'stdout_sha256': stdout_sha,
                 'stderr_bytes': stderr_size, 'stderr_sha256': stderr_sha,
                 'timed_out': timed_out, 'passed': passed}
        if expected_exit == 0:
            entry['typed_reply'] = decoded if reply_ok else 'invalid-or-unexpected-shape'
        runs.append(entry)
        if timed_out:
            break

    record = {'scope': 'Darwin C stub KVS1 decode-only parser checks; not launch mode or backend qualification',
              'status': 'PASS' if all_passed and len(runs) == 36 else 'FAIL',
              'native_parser_run': True, 'backend_certified': False,
              'platform': platform.platform(), 'machine': platform.machine(),
              'binary_path': str(binary), 'binary_sha256': _digest_file(binary),
              'argv': argv, 'case_count': len(runs), 'expected_case_count': 36,
              'timeout_seconds_per_case': 8, 'cases': runs}
    OUT.mkdir(exist_ok=True)
    result_path = OUT / 'STUB_WIRE_RESULT.json'
    result_path.write_text(json.dumps(record, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'status': record['status'], 'case_count': record['case_count'],
                      'result_path': str(result_path), 'backend_certified': False}))
    return 0 if record['status'] == 'PASS' else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--self-check', action='store_true',
                        help='run bounded serializer checks only; does not call the native binary')
    args = parser.parse_args()
    return self_check() if args.self_check else native_run()


if __name__ == '__main__':
    raise SystemExit(main())
