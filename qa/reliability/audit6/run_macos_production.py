#!/usr/bin/env python3
"""Bounded production admission on a disposable macOS runner.

The canonical installer/controller is reused without qualification-mode.
Observed SIP status stays separate from production-path success. Raw runtime
records remain private; only the existing strict reducer is published.
"""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[3]
ASSETS = ['darwin-production-lifecycle.py', 'darwin-production-controller.js',
          'darwin-production-summary.py', 'darwin-protected-executable-probe.js',
          'lock-publication-before-search.c']
FAILURE_ASSETS = ['darwin-production-failure-cases.py', 'darwin-production-failure-caller.js',
                 'darwin-production-control.js', 'darwin-production-process-observer.c',
                 'darwin-test-signal.c', 'darwin-production-failure-summary.py']

def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def save(path, value):
    Path(path).write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')

def need(condition, reason):
    if not condition:
        raise RuntimeError(reason)

def sip_observation():
    result = subprocess.run(['/usr/bin/csrutil', 'status'], stdin=subprocess.DEVNULL,
        capture_output=True, timeout=15, check=False)
    expected = {b'System Integrity Protection status: enabled.': 'enabled',
                b'System Integrity Protection status: disabled.': 'disabled'}
    value = expected.get(result.stdout.strip(), 'unknown') if result.returncode == 0 else 'unknown'
    return {'status': value, 'exit_code': result.returncode,
            'stdout_sha256': hashlib.sha256(result.stdout).hexdigest(),
            'stderr_sha256': hashlib.sha256(result.stderr).hexdigest(),
            'stdout_bytes': len(result.stdout), 'stderr_bytes': len(result.stderr)}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--source', required=True)
    ap.add_argument('--pins', required=True)
    ap.add_argument('--out', required=True)
    ap.add_argument('--arch', required=True, choices=['x64', 'arm64'])
    ap.add_argument('--case-set', choices=['normal', 'failures'], default='normal')
    ap.add_argument('--require-stock-sip', action='store_true')
    args = ap.parse_args()
    out = Path(args.out).resolve();out.mkdir(mode=0o700, parents=True, exist_ok=False)
    public = out/'public';public.mkdir()
    source = Path(args.source).resolve(strict=True)
    pin_file = Path(args.pins).resolve(strict=True)
    pins = json.loads(pin_file.read_text())
    report = {'schema_version': 'knowledge-audit6-macos-production.v1', 'status': 'FAIL',
        'commit': os.environ.get('GITHUB_SHA'), 'workflow_run': os.environ.get('GITHUB_RUN_ID'),
        'runtime_architecture': args.arch, 'case_set': args.case_set, 'source_pins_sha256': sha(pin_file),
        'stock_sip_required': args.require_stock_sip, 'stock_sip_qualified': False,
        'normal_path_on_stock_sip_verified': False,
        'release_qualified': False, 'scope': 'Canonical production path, protected executable contract and only the explicitly selected case set on the observed disposable host; no universal macOS, kernel I/O stall or full release qualification.',
        'root_mutations_started': False,
        'controller_exit_code': None, 'controller_timeout': False, 'controller_cleanup_confirmed': False}
    try:
        need(platform.system() == 'Darwin' and os.environ.get('GITHUB_ACTIONS') == 'true',
             'disposable_darwin_github_runner_required')
        need(platform.machine() == ('x86_64' if args.arch == 'x64' else 'arm64'), 'host_architecture_mismatch')
        need(os.getuid() != 0, 'ordinary_controller_required')
        need(pins.get('file_count') == len(pins.get('files', {})) > 0, 'source_inventory_invalid')
        report['sip_before'] = sip_observation()
        if args.require_stock_sip and report['sip_before']['status'] != 'enabled':
            report['status'] = 'BLOCKED_STOCK_SIP_NOT_ENABLED'
            report['root_mutations_started'] = False
            return 2
        stage = out/'stage'/'.knowledge';stage.mkdir(parents=True)
        for name, digest in pins['files'].items():
            relative = Path(name)
            need(not relative.is_absolute() and '..' not in relative.parts and '\\' not in name, 'source_path_invalid')
            original = source/relative
            need(original.is_file() and not original.is_symlink() and sha(original) == digest, 'source_pin_mismatch:'+name)
            target = stage/relative;target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(original, target);target.chmod(0o644)
        controllers = ROOT/'qa/reliability/controllers'
        reference = ROOT/'qa/reliability/reference'
        assets = ASSETS + (FAILURE_ASSETS if args.case_set == 'failures' else [])
        report['qa_pins'] = {str((controllers/n).relative_to(ROOT)):sha(controllers/n) for n in assets}
        report['qa_pins'][Path(__file__).resolve().relative_to(ROOT).as_posix()] = sha(__file__)
        for f in (reference/'qa/darwin-pipeline4').glob('*.py'):
            report['qa_pins'][f.relative_to(ROOT).as_posix()] = sha(f)
        for f in [reference/'qa/darwin-pipeline4/birth-observer.c',reference/'qa/darwin-pipeline4/PINS.json',reference/'qa/darwin-broker/uid-scan.c']:
            report['qa_pins'][f.relative_to(ROOT).as_posix()] = sha(f)
        save(public/'SOURCE_PINS.json', pins)
        raw = out/'private'
        argv = [sys.executable, str(controllers/'darwin-production-lifecycle.py'),
            '--source', str(stage), '--reference', str(reference), '--evidence', str(raw),
            '--expected-arch', 'x86_64' if args.arch == 'x64' else 'arm64', '--case-set', args.case_set]
        started = time.monotonic()
        with (out/'controller.stdout.private').open('wb') as stdout, (out/'controller.stderr.private').open('wb') as stderr:
            child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                                     start_new_session=True)
            report['root_mutations_started'] = True
            try:
                code = child.wait(timeout=660)
            except subprocess.TimeoutExpired:
                report['controller_timeout'] = True
                # This scaffolding never treats signal delivery as resource
                # closure. The disposable job remains the ultimate boundary;
                # protected root state is not deleted after unknown cleanup.
                try: os.killpg(child.pid, signal.SIGTERM)
                except ProcessLookupError: pass
                try: code = child.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    child.kill();code = child.wait(timeout=10)
        report['controller_exit_code'] = code
        report['controller_elapsed_s'] = round(time.monotonic()-started,3)
        report['controller_output_pins'] = {n:{'sha256':sha(out/n),'bytes':(out/n).stat().st_size}
            for n in ['controller.stdout.private','controller.stderr.private']}
        spec = importlib.util.spec_from_file_location('darwin_production_summary',controllers/'darwin-production-summary.py')
        reducer = importlib.util.module_from_spec(spec);spec.loader.exec_module(reducer)
        summary, stages = reducer.build(raw, stage, code, 'x86_64' if args.arch == 'x64' else 'arm64', args.case_set)
        save(public/'summary.json',summary);save(public/'stages.json',stages)
        report['controller_cleanup_confirmed'] = summary.get('cleanup_confirmed') is True
        report['sip_after'] = sip_observation()
        report['sip_unchanged'] = report['sip_after'] == report['sip_before']
        for name, digest in pins['files'].items():
            need(sha(source/name) == digest and sha(stage/name) == digest, 'source_changed:'+name)
        expected = {'normal':'PASS_PRODUCTION_NORMAL_GATE','failures':'PASS_PRODUCTION_FAILURE_MATRIX'}[args.case_set]
        need(summary.get('status') == expected and code == 0 and
             not report['controller_timeout'] and report['controller_cleanup_confirmed'] and report['sip_unchanged'],
             'production_gate_incomplete')
        report['normal_path_on_stock_sip_verified'] = report['sip_before']['status'] == 'enabled'
        report['status'] = ('PASS_NORMAL_PRODUCTION_ON_OBSERVED_HOST' if args.case_set == 'normal'
                            else 'PASS_PRODUCTION_FAILURE_MATRIX_ON_OBSERVED_HOST')
        report['stock_sip_scope'] = ('SELECTED_CASE_SET_ONLY; complete stock-SIP host qualification is separate'
            if report['normal_path_on_stock_sip_verified'] else 'NOT_QUALIFIED_SIP_DISABLED_OR_UNKNOWN')
        return 0
    except BaseException as error:
        # Publish typed errors only. Unexpected messages can contain native
        # descriptors or absolute host paths and stay outside the artifact.
        reason = str(error).split(':', 1)[0]
        report['error'] = {'type':type(error).__name__,
            'code':reason if re.fullmatch('[a-z0-9_]{1,80}',reason) else 'unexpected_controller_error'}
        (out/'wrapper.error.private').write_text(type(error).__name__+':'+str(error)+'\n')
        return 1
    finally:
        save(public/'RESULT.json',report)
        print(json.dumps({'status':report['status'],'stock_sip_qualified':report['stock_sip_qualified'],
                          'cleanup_confirmed':report['controller_cleanup_confirmed']}))

if __name__ == '__main__':
    raise SystemExit(main())
