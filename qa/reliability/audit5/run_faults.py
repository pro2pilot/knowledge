#!/usr/bin/env python3
"""Run fixed, bounded isolated component experiments and post-exit acceptance."""
from __future__ import annotations
import argparse, hashlib, json, os, pathlib, re, shutil, subprocess, sys, time

def main():
    parser = argparse.ArgumentParser(); parser.add_argument('--out', required=True)
    args = parser.parse_args()
    out = pathlib.Path(args.out).resolve(); out.mkdir(parents=True, exist_ok=False)
    code = pathlib.Path(__file__).resolve().parents[1] / 'linux-service-slice-27'
    results = {'schema_version': 'knowledge-audit5-component-faults.v1',
        'source_revision': os.environ.get('GITHUB_SHA'), 'workflow_run_id': os.environ.get('GITHUB_RUN_ID'),
        'scope': 'isolated readonly component; pipe stalls are not disk or kernel D-state tests',
        'production_qualified': False, 'release_qualified': False, 'status': 'RUNNING', 'cases': [],
        'qa_source_sha256': {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(code.iterdir())
            if p.is_file() and p.suffix in {'.py', '.js', '.c'}}}
    def save(): (out / 'RESULTS.json').write_text(json.dumps(results, indent=2) + '\n')
    save()
    for mode in ('none', 'import-receipt-held', 'result-held'):
        case_dir = out / mode; case_dir.mkdir()
        row = {'fault': mode, 'status': 'FAIL'}; results['cases'].append(row)
        started = time.monotonic()
        # Keep private controller stderr outside the public artifact. Its bounded
        # size and digest are diagnostics; only controller-authored public facts
        # are exported. No root/user environment or arbitrary project is supplied.
        private = pathlib.Path(os.environ['RUNNER_TEMP']) / ('audit5-' + mode + '-' + str(os.getpid()))
        private.mkdir(mode=0o700)
        try:
            with (private / 'prepare.stdout').open('wb') as stdout, (private / 'prepare.stderr').open('wb') as stderr:
                p = subprocess.run([sys.executable, '-B', str(code / 'controller.py'), 'prepare', '--fault', mode],
                    stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, timeout=180)
            row['prepare_exit'] = p.returncode
            receipt_bytes = (private / 'prepare.stdout').read_bytes()
            if p.returncode != 0 or len(receipt_bytes) > 65536:
                raise RuntimeError('prepare_failed')
            receipt = json.loads(receipt_bytes)
            run_id = receipt.get('run_id')
            if not isinstance(run_id, str) or not re.fullmatch('[a-f0-9]{32}', run_id) or \
                receipt.get('status') != 'PREPARED_COMPONENT_QA' or \
                receipt.get('fault_mode') != {'none': 0, 'import-receipt-held': 1, 'result-held': 2}[mode]:
                raise RuntimeError('invalid_prepare_receipt')
            public = pathlib.Path('/tmp') / ('knowledge-slice-prep-' + run_id) / 'public'
            if public.is_symlink() or not public.is_dir(): raise RuntimeError('public_directory_unavailable')
            with (public / 'prepare-receipt.json').open('xb') as handle: handle.write(receipt_bytes)
            os.chmod(public / 'prepare-receipt.json', 0o644)
            row['run_id'] = run_id
            with (private / 'controller.stdout').open('wb') as stdout, (private / 'controller.stderr').open('wb') as stderr:
                p = subprocess.run(['sudo', '-n', sys.executable, '-B', str(code / 'controller.py'), 'run', '--run-id', run_id],
                    stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, timeout=200)
            row['controller_exit'] = p.returncode
            accepted = subprocess.run([sys.executable, '-B', str(code / 'acceptance.py'), '--public-dir', str(public),
                '--controller-exit', str(p.returncode), '--run-id', run_id,
                '--source-revision', os.environ['GITHUB_SHA'], '--workflow-run-id', os.environ['GITHUB_RUN_ID'],
                '--workflow-run-attempt', os.environ['GITHUB_RUN_ATTEMPT'],
                '--controller-step-outcome', 'success' if p.returncode == 0 else 'failure'],
                stdin=subprocess.DEVNULL, capture_output=True, timeout=20)
            row['acceptance_exit'] = accepted.returncode
            for name in ('prepare-receipt.json', 'RESULT.json', 'NATIVE.json', 'ACCEPTANCE.json'):
                path = public / name
                if path.is_file() and not path.is_symlink() and path.stat().st_size <= 160 * 1024:
                    shutil.copyfile(path, case_dir / name)
            if accepted.returncode != 0: raise RuntimeError('independent_acceptance_rejected')
            acceptance = json.loads((case_dir / 'ACCEPTANCE.json').read_text())
            expected = 'ACCEPTED_COMPONENT_QA' if mode == 'none' else 'ACCEPTED_FAULT_QA'
            if acceptance.get('status') != expected: raise RuntimeError('acceptance_status_mismatch')
            row['status'] = expected
        except Exception as error:
            row['error'] = type(error).__name__ + ': ' + str(error)
        finally:
            row['elapsed_s'] = round(time.monotonic() - started, 3)
            row['private_logs'] = {}
            for p in private.iterdir():
                if not p.is_file(): continue
                size = p.stat().st_size; digest = hashlib.sha256(); read = 0
                with p.open('rb') as handle:
                    while read < 16 * 1024 * 1024:
                        chunk = handle.read(min(65536, 16 * 1024 * 1024 - read))
                        if not chunk: break
                        digest.update(chunk); read += len(chunk)
                row['private_logs'][p.name] = {'bytes': size, 'sample_bytes': read,
                    'truncated': read != size, 'sample_sha256': digest.hexdigest()}
            if row['status'] == 'FAIL' and 'run_id' in row:
                for name in ('prepare-receipt.json', 'RESULT.json', 'NATIVE.json', 'ACCEPTANCE.json'):
                    p = public / name
                    if p.is_file() and not p.is_symlink() and p.stat().st_size <= 160 * 1024:
                        shutil.copyfile(p, case_dir / name)
            save(); print(json.dumps(row), flush=True)
        if row['status'] == 'FAIL':
            try:
                cleanup = json.loads((case_dir / 'RESULT.json').read_text()).get('host_cleanup_confirmed') is True
            except (OSError, ValueError, TypeError):
                cleanup = False
            if not cleanup:
                results['stopped_after_unconfirmed_cleanup'] = True
                break
    results['status'] = 'PASS_COMPONENT_FAULTS' if len(results['cases']) == 3 and all(r['status'].startswith('ACCEPTED_') for r in results['cases']) else 'FAIL'
    save()
    return 0 if results['status'] == 'PASS_COMPONENT_FAULTS' else 1

if __name__ == '__main__': raise SystemExit(main())
