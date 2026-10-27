#!/usr/bin/env python3
"""Actual root filesystem/restart tests; component evidence, never broker PASS."""
import argparse
import hashlib
import json
import os
import platform
from pathlib import Path
import select
import struct
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
SOURCE = HERE.parents[2] / 'source' / '.knowledge' / 'tools' / 'lib'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    if os.getuid() != 0 or os.geteuid() != 0:
        raise SystemExit('root-owned filesystem fixture required; no skip-as-PASS')
    binary = output / 'native-history-qa'
    command = ['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', '-O2',
               '-fstack-protector-strong', '-D_FORTIFY_SOURCE=2',
               '-DKNOWLEDGE_LINUX_UID_HISTORY_TEST_IO', '-I', str(SOURCE),
               str(HERE / 'native-history-qa.c'),
               str(SOURCE / 'verification-linux-uid-history.c'), '-lcrypto', '-o', str(binary)]
    compiled = subprocess.run(command, capture_output=True, text=True)
    compiler_version = subprocess.run(['cc', '--version'], capture_output=True, text=True,
                                      timeout=10).stdout.splitlines()[0]
    (output / 'build.stdout.txt').write_text(compiled.stdout)
    (output / 'build.stderr.txt').write_text(compiled.stderr)
    if compiled.returncode:
        raise SystemExit(compiled.stderr)
    fixtures = Path(tempfile.mkdtemp(prefix='history-fixtures-', dir=output))
    os.chmod(fixtures, 0o700)
    events = []

    def run(op, base, value=None, environment=None, expect=True):
        cmd = [str(binary), op, str(base / 'anchor'), str(base / 'journal')]
        if value is not None:
            cmd.append(value)
        result = subprocess.run(cmd, capture_output=True, text=True,
                                env={**os.environ, **(environment or {})}, timeout=10)
        row = json.loads(result.stdout) if result.stdout.strip() else {}
        if expect is not None:
            assert (result.returncode == 0) is expect, (op, result.returncode, row, result.stderr)
            assert row.get('ok') is expect, (op, row)
        return row, result.returncode

    def fixture(name, initialized=True):
        base = fixtures / name
        base.mkdir(mode=0o700)
        (base / 'anchor').mkdir(mode=0o700)
        (base / 'journal').mkdir(mode=0o700)
        if initialized:
            run('initialize', base)
        return base

    def case(name, callback):
        try:
            details = callback()
            events.append({'case': name, 'status': 'PASS', 'details': details})
        except Exception as error:
            events.append({'case': name, 'status': 'FAIL', 'error': repr(error)})
            save()
            raise

    def save():
        facts = {
            'schema': 'knowledge-linux-native-history-component.v1',
            'scope': 'root-native durable UID history; no process/cgroup/KVE closure claim',
            'production_broker_available': False,
            'host': {'system': platform.system(), 'machine': platform.machine(),
                     'kernel': platform.release(), 'uid': os.getuid(), 'euid': os.geteuid()},
            'build_command': command,
            'compiler_version': compiler_version,
            'fault_scope': 'injected operation error or userspace _exit(88); not power loss or kernel I/O stall',
            'test_count': len(events),
            'pass_count': sum(row['status'] == 'PASS' for row in events),
            'fail_count': sum(row['status'] == 'FAIL' for row in events),
            'tests': events,
            'source_sha256': {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                              for path in [SOURCE / 'verification-linux-uid-history.c',
                                           SOURCE / 'verification-linux-uid-history.h',
                                           HERE / 'native-history-qa.c', HERE / 'run-history-qa.py']},
            'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
        }
        (output / 'facts.json').write_text(json.dumps(facts, indent=2) + '\n')

    nonce1, nonce2, nonce3, nonce4 = ('01' * 32, '02' * 32, '03' * 32, '04' * 32)

    def lifecycle():
        base = fixture('lifecycle')
        before, _ = run('inspect', base)
        assert before['records'] == 0 and not before['pending']
        run('initialize', base, expect=False)
        for index, nonce in enumerate((nonce1, nonce2, nonce3)):
            state, _ = run('reserve', base, nonce)
            assert state['authority_uid'] == 1000100000 + index * 2
            assert state['worker_uid'] == 1000100001 + index * 2
            assert state['pending'] and state['allocations'] == index + 1
            run('reserve', base, nonce4, expect=False)
            run('wrong-close', base, expect=False)
            run('zero-proof', base, expect=False)
            assert run('inspect', base)[0]['pending']
            state, _ = run('close', base)
            assert not state['pending']
            run('close', base, expect=False)
            run('reserve', base, nonce, expect=False)
        run('reserve', base, nonce4, expect=False)
        raw = (base / 'journal' / 'journal').read_bytes()
        records = [raw[i:i+256] for i in range(0, len(raw), 256)]
        assert len(records) == 7
        for i, record in enumerate(records):
            assert hashlib.sha256(record[:224]).digest() == record[224:]
            assert struct.unpack_from('<Q', record, 16)[0] == i
            if i:
                assert record[152:184] == records[i-1][224:]
                assert struct.unpack_from('<I', record, 8)[0] == (2 if i % 2 else 3)
        assert records[-1] == (base / 'anchor' / 'head').read_bytes()
        genesis = records[0]
        for offset, path in ((184, base / 'journal' / 'journal'), (200, base / 'journal' / 'lock')):
            info = path.stat()
            assert struct.unpack_from('<QQ', genesis, offset) == (info.st_dev, info.st_ino)
        return {'allocations': 3, 'records': 6, 'unique_uids': 6,
                'independent_sha256_chain_verified': True}

    case('durable_restart_lifecycle_nonce_and_range_fences', lifecycle)

    def locked():
        base = fixture('singleton')
        owner = subprocess.Popen([str(binary), 'hold', str(base / 'anchor'), str(base / 'journal')],
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 text=True)
        try:
            assert select.select([owner.stdout], [], [], 10)[0], 'native lock owner readiness timed out'
            assert json.loads(owner.stdout.readline()) == {'holding': True}
            rejected, _ = run('inspect', base, expect=False)
            assert rejected['reason'] == 'singleton_lock_unavailable'
            owner.communicate('x', timeout=10)
            assert owner.returncode == 0
            run('inspect', base)
        finally:
            if owner.poll() is None:
                owner.kill()
                owner.wait()
        return {'concurrent_owner_rejected': True, 'reopen_after_exit': True}

    case('actual_process_singleton_lock', locked)

    def mutate(name, mutation):
        def execute():
            base = fixture(name)
            run('reserve', base, nonce1)
            mutation(base)
            row, _ = run('inspect', base, expect=False)
            run('reserve', base, nonce2, expect=False)
            run('initialize', base, expect=False)
            return {'rejection': row['reason'], 'no_repair_or_allocation': True}
        case(name, execute)

    for name, relative in [('missing_marker', 'anchor/marker'), ('missing_head', 'anchor/head'),
                           ('missing_journal', 'journal/journal'), ('missing_lock', 'journal/lock')]:
        mutate(name, lambda base, relative=relative: (base / relative).unlink())
    mutate('partial_journal_tail', lambda base: (base / 'journal/journal').open('ab').write(b'X'))
    mutate('empty_journal', lambda base: (base / 'journal/journal').write_bytes(b''))
    mutate('wrong_file_mode', lambda base: (base / 'journal/journal').chmod(0o644))
    mutate('writable_directory', lambda base: (base / 'journal').chmod(0o777))
    mutate('head_rollback_only', lambda base: (base / 'anchor/head').write_bytes((base / 'anchor/marker').read_bytes()))
    mutate('journal_hardlink', lambda base: os.link(base / 'journal/journal', base / 'journal/extra'))

    def replace_file(base, relative):
        path = base / relative
        copy = path.with_name(path.name + '.replacement')
        copy.write_bytes(path.read_bytes())
        copy.chmod(0o600)
        copy.replace(path)
    mutate('identical_journal_replacement_inode', lambda base: replace_file(base, 'journal/journal'))
    mutate('identical_lock_replacement_inode', lambda base: replace_file(base, 'journal/lock'))

    def symlink(base):
        path = base / 'journal/journal'
        path.rename(path.with_name('target'))
        path.symlink_to('target')
    mutate('journal_symlink', symlink)

    def malformed(base, offset, value):
        path = base / 'journal/journal'
        body = bytearray(path.read_bytes())
        struct.pack_into('<I', body, 256 + offset, value)
        body[256+224:512] = hashlib.sha256(body[256:256+224]).digest()
        path.write_bytes(body)
        (base / 'anchor/head').write_bytes(body[-256:])
    mutate('valid_hash_wrong_uid_order', lambda base: malformed(base, 32, 1000100002))
    mutate('valid_hash_unexpected_closed_record', lambda base: malformed(base, 8, 3))
    mutate('valid_hash_nonzero_reserved_bytes', lambda base: malformed(base, 184, 1))

    def bad_config():
        base = fixture('wrong-config')
        row, _ = run('wrong-config', base, expect=False)
        return row
    case('configuration_epoch_mismatch', bad_config)

    for phase in ('before_journal_write', 'before_journal_fsync', 'after_journal_fsync',
                  'before_head_rename', 'before_head_directory_fsync'):
        for mode in ('FAIL', 'CRASH'):
            def interrupted(phase=phase, mode=mode):
                base = fixture(phase + '-' + mode)
                row, rc = run('reserve', base, nonce1,
                              environment={'KV_HISTORY_TEST_' + mode: phase}, expect=None)
                assert rc == (88 if mode == 'CRASH' else 1)
                observed, open_rc = run('inspect', base, expect=None)
                if phase == 'before_journal_write':
                    assert open_rc == 0 and observed['allocations'] == 0
                    state, _ = run('reserve', base, nonce2)
                    assert state['authority_uid'] == 1000100000
                elif phase == 'before_head_directory_fsync':
                    assert open_rc == 0 and observed['pending'] and observed['allocations'] == 1
                    run('reserve', base, nonce2, expect=False)
                else:
                    assert open_rc != 0
                    run('reserve', base, nonce2, expect=False)
                    run('initialize', base, expect=False)
                return {'fault_phase': phase, 'fault_mode': mode,
                        'reopen_reason': observed.get('reason'), 'no_burned_uid_reissued': True}
            case('publication_' + phase + '_' + mode.lower(), interrupted)
    save()
    print(json.dumps({'status': 'PASS', 'component_tests': len(events), 'facts': str(output / 'facts.json')}))
    # Fixtures contain intentionally corrupted histories, preserved as evidence.


if __name__ == '__main__':
    main()
