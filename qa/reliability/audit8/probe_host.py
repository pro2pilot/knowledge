#!/usr/bin/env python3
"""Read-only macOS SIP prerequisites; this never qualifies product execution."""
import argparse
import hashlib
import json
import os
import pathlib
import platform
import re
import subprocess
import time

LABELS = {'macos-15-intel': 'x64', 'macos-15': 'arm64', 'macos-14': 'arm64'}


def observe(argv):
    started = time.monotonic()
    try:
        result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=10, check=False)
        out, err = result.stdout, result.stderr
        return {'argv': argv, 'exit_code': result.returncode, 'timed_out': False,
                'elapsed_ms': round((time.monotonic() - started) * 1000, 3),
                'stdout': out.decode('utf-8', errors='replace')[:8192],
                'stderr': err.decode('utf-8', errors='replace')[:8192],
                'stdout_bytes': len(out), 'stderr_bytes': len(err),
                'stdout_sha256': hashlib.sha256(out).hexdigest(),
                'stderr_sha256': hashlib.sha256(err).hexdigest()}
    except (subprocess.TimeoutExpired, OSError) as error:
        return {'argv': argv, 'exit_code': None,
                'timed_out': isinstance(error, subprocess.TimeoutExpired),
                'elapsed_ms': round((time.monotonic() - started) * 1000, 3),
                'error_type': type(error).__name__}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--label', required=True, choices=LABELS)
    parser.add_argument('--out', required=True)
    args = parser.parse_args()
    machine = platform.machine().lower()
    arch = 'arm64' if machine in ('arm64', 'aarch64') else 'x64' if machine in ('x86_64', 'amd64') else machine
    report = {'schema_version': 'knowledge-audit8-host-prerequisite.v1',
              'status': 'UNCONFIRMED', 'probe_only': True,
              'release_qualified': False, 'stock_sip_qualified': False,
              'runtime_qualification_executed': False, 'host_has_stock_sip': False,
              'security_configuration_changed': False,
              'runner_label': args.label, 'expected_arch': LABELS[args.label],
              'system': platform.system(), 'process_arch': arch,
              'workflow_run': os.environ.get('GITHUB_RUN_ID'),
              'workflow_attempt': os.environ.get('GITHUB_RUN_ATTEMPT'),
              'commit': os.environ.get('GITHUB_SHA'),
              'image_version': os.environ.get('ImageVersion'),
              'image_os': os.environ.get('ImageOS'),
              'scope': 'Read-only host prerequisites. Enabled SIP alone does not establish any product runtime, failure-path, installed-package, or release qualification.'}
    if report['system'] != 'Darwin' or arch != LABELS[args.label]:
        report['status'] = 'HOST_MISMATCH'
    else:
        report['os_version'] = observe(['/usr/bin/sw_vers'])
        report['hardware_arm64'] = observe(['/usr/sbin/sysctl', '-n', 'hw.optional.arm64'])
        report['sip'] = observe(['/usr/bin/csrutil', 'status'])
        sip = report['sip']
        exact = sip.get('exit_code') == 0 and sip.get('stdout_bytes', 8193) <= 8192 and sip.get('stderr_bytes', 8193) <= 8192
        if exact and re.fullmatch(r'System Integrity Protection status: enabled\.\s*', sip.get('stdout', '').strip()):
            report.update(status='HOST_PREREQUISITE_ENABLED', host_has_stock_sip=True)
        elif exact and re.fullmatch(r'System Integrity Protection status: disabled\.\s*', sip.get('stdout', '').strip()):
            report['status'] = 'BLOCKED_STOCK_SIP_NOT_ENABLED'
        else:
            report['status'] = 'BLOCKED_STOCK_SIP_UNCONFIRMED'
    output = pathlib.Path(args.out)
    output.mkdir(parents=True, exist_ok=False)
    (output/'RESULT.json').write_text(json.dumps(report, indent=2, sort_keys=True)+'\n', encoding='utf8')
    print(json.dumps({key: report[key] for key in ('status', 'runner_label', 'process_arch', 'host_has_stock_sip', 'runtime_qualification_executed', 'release_qualified')}))
    return 0 if report['host_has_stock_sip'] else 2


if __name__ == '__main__':
    raise SystemExit(main())
