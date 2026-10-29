#!/usr/bin/env python3
"""Read-only hosted macOS prerequisite observation; never product qualification."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys


def digest(data):
    return hashlib.sha256(data).hexdigest()


def sip_status(result):
    if result.get('exit_code') != 0 or result.get('timed_out') or result.get('error'):
        return 'unknown'
    expected = {
        b'System Integrity Protection status: enabled.': 'enabled',
        b'System Integrity Protection status: disabled.': 'disabled',
    }
    # Stderr, custom configurations, extra lines and localization are not proof.
    if result.get('stderr', b''):
        return 'unknown'
    return expected.get(result.get('stdout', b'').strip(), 'unknown')


def admission(*, system, machine, architecture, uid, github_actions, sip, translated):
    failures = []
    if system != 'Darwin':
        failures.append('darwin_required')
    if machine != {'x64': 'x86_64', 'arm64': 'arm64'}[architecture]:
        failures.append('architecture_mismatch')
    if uid == 0 or uid is None:
        failures.append('ordinary_user_required')
    if github_actions != 'true':
        failures.append('github_actions_runner_required')
    if translated not in ('0', 'not_available_on_intel'):
        failures.append('native_execution_unconfirmed')
    if sip != 'enabled':
        failures.append('stock_sip_not_enabled')
    return failures


def translation_status(result, architecture, machine):
    if result.get('timed_out') or result.get('error'):
        return 'unknown'
    if result.get('exit_code') == 0 and not result.get('stderr'):
        return {b'0': '0', b'1': '1'}.get(result.get('stdout', b'').strip(), 'unknown')
    if (architecture == 'x64' and machine == 'x86_64' and result.get('exit_code') == 1
            and not result.get('stdout')
            and result.get('stderr', b'').strip() == b'sysctl: unknown oid \'sysctl.proc_translated\''):
        return 'not_available_on_intel'
    return 'unknown'


def probe(argv, output, name):
    def identity():
        try:
            executable = Path(argv[0]).resolve(strict=True)
            data = executable.read_bytes()
            stat = executable.stat()
            return {'path': str(executable), 'sha256': digest(data), 'bytes': len(data),
                    'device': stat.st_dev, 'inode': stat.st_ino, 'uid': stat.st_uid,
                    'mode': stat.st_mode}
        except OSError as error:
            return {'error': type(error).__name__}
    before = identity()
    try:
        result = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True,
                                timeout=15, check=False, env={**os.environ, 'LC_ALL': 'C', 'LANG': 'C'})
        value = {'argv': argv, 'exit_code': result.returncode, 'timed_out': False,
                 'stdout': result.stdout, 'stderr': result.stderr}
    except subprocess.TimeoutExpired as error:
        value = {'argv': argv, 'exit_code': None, 'timed_out': True,
                 'stdout': error.stdout or b'', 'stderr': error.stderr or b''}
    except OSError as error:
        value = {'argv': argv, 'exit_code': None, 'timed_out': False,
                 'error': type(error).__name__, 'stdout': b'', 'stderr': b''}
    value['executable_before'] = before
    value['executable_after'] = identity()
    value['executable_unchanged'] = 'error' not in before and before == value['executable_after']
    for stream in ('stdout', 'stderr'):
        (output / (name + '.' + stream)).write_bytes(value[stream])
    return value


def public_result(value):
    return {**{k: v for k, v in value.items() if k not in ('stdout', 'stderr')},
            **{s: {'bytes': len(value[s]), 'sha256': digest(value[s])} for s in ('stdout', 'stderr')}}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', required=True)
    parser.add_argument('--arch', required=True, choices=['x64', 'arm64'])
    args = parser.parse_args()
    output = Path(args.out).resolve()
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    probes = {}
    for name, argv in (
        ('sip', ['/usr/bin/csrutil', 'status']),
        ('os', ['/usr/bin/sw_vers']),
        ('kernel', ['/usr/bin/uname', '-a']),
        ('machine', ['/usr/bin/uname', '-m']),
        ('translation', ['/usr/sbin/sysctl', '-n', 'sysctl.proc_translated']),
        ('compiler', ['/usr/bin/xcrun', '--find', 'clang']),
        ('service_manager', ['/bin/launchctl', 'version']),
    ):
        probes[name] = probe(argv, output, name)
    translated = translation_status(probes['translation'], args.arch, platform.machine())
    sip = sip_status(probes['sip'])
    failures = admission(system=platform.system(), machine=platform.machine(),
        architecture=args.arch, uid=os.getuid() if hasattr(os, 'getuid') else None,
        github_actions=os.environ.get('GITHUB_ACTIONS'), sip=sip, translated=translated)
    for name in ('os', 'kernel', 'machine', 'compiler', 'service_manager'):
        if probes[name]['exit_code'] != 0 or probes[name]['timed_out']:
            failures.append(name + '_unavailable')
    for name, value in probes.items():
        if not value['executable_unchanged']:
            failures.append(name + '_executable_identity_unconfirmed')
    report = {
        'schema_version': 'knowledge-audit9-macos-prerequisite.v1',
        'status': 'BLOCKED_PREREQUISITE' if failures else 'PASS_PREREQUISITE_ONLY',
        'release_qualified': False, 'production_qualified': False,
        'stock_sip_qualified': False, 'root_mutations_started': False,
        'scope': 'Read-only host prerequisites. Enabled SIP does not prove the protected executable canary, production custody, KVE/ACK, cleanup or a release gate.',
        'source_commit': os.environ.get('GITHUB_SHA'),
        'workflow_run': os.environ.get('GITHUB_RUN_ID'),
        'workflow_attempt': os.environ.get('GITHUB_RUN_ATTEMPT'),
        'workflow_ref': os.environ.get('GITHUB_WORKFLOW_REF'),
        'workflow_job': os.environ.get('GITHUB_JOB'),
        'repository': os.environ.get('GITHUB_REPOSITORY'),
        'runner_label': os.environ.get('EXPECTED_RUNNER_LABEL'),
        'image_os': os.environ.get('ImageOS'), 'image_version': os.environ.get('ImageVersion'),
        'runner_arch': os.environ.get('RUNNER_ARCH'),
        'architecture_expected': args.arch, 'machine_observed': platform.machine(),
        'uid': os.getuid() if hasattr(os, 'getuid') else None,
        'sip_status': sip, 'translated': translated, 'blockers': failures,
        'python_version': platform.python_version(),
        'python_executable': str(Path(sys.executable).resolve()),
        'python_sha256': digest(Path(sys.executable).read_bytes()),
        'probe_sha256': digest(Path(__file__).read_bytes()),
        'probes': {name: public_result(result) for name, result in probes.items()},
    }
    (output / 'RESULT.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'status': report['status'], 'sip_status': sip, 'blockers': failures}))
    return 2 if failures else 0


if __name__ == '__main__':
    raise SystemExit(main())
