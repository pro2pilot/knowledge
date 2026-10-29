#!/usr/bin/env python3
"""Physical historical-candidate Windows ARM Team crash/cancellation diagnosis."""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import tempfile
import time
import zipfile

HERE = Path(__file__).resolve().parent
EXPECTED = '81a6d8d4daf8d3d73f4ac298297893fe40b488627d1f176f7960e5179c8cb542'
FIXTURE_PINS = {
    'knowledge-v3.4.4.zip': EXPECTED,
    'team-crash-tests/reliability-windows-team-crash.test.js': '9ee6dbbcd409570422ffe9354639d36edf4b903eae3c9e422dd06ec3e6f009ce',
    'team-crash-tests/helpers/reliability-windows-custody-trace.cjs': '28272d88db67d272714b0519f6e7d8a9efd9121a9a5da652d62fedd3b3fa1927',
}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    out = Path('arm-team-evidence').resolve()
    out.mkdir(exist_ok=False)
    report = {'schema_version': 'knowledge-audit9-windows-arm-team.v1', 'status': 'FAIL',
              'source_commit': os.environ.get('GITHUB_SHA'), 'workflow_run': os.environ.get('GITHUB_RUN_ID'),
              'workflow_attempt': os.environ.get('GITHUB_RUN_ATTEMPT'), 'candidate_sha256': EXPECTED,
              'release_qualified': False, 'final_candidate_qualified': False,
              'scope': 'Two physical Windows Job Object Team crash/cancellation scenarios against a pinned historical candidate plus exact source-only test overlays.'}
    try:
        prerequisite = json.loads(Path('arm-prerequisite/RESULT.json').read_text())
        if (os.name != 'nt' or prerequisite.get('status') != 'PASS_PREREQUISITE_ONLY'
                or prerequisite.get('source_commit') != os.environ.get('GITHUB_SHA')
                or prerequisite.get('workflow_run') != os.environ.get('GITHUB_RUN_ID')
                or prerequisite.get('workflow_attempt') != os.environ.get('GITHUB_RUN_ATTEMPT')
                or prerequisite.get('runtime', {}).get('architecture') != 'arm64'):
            raise RuntimeError('native_arm_prerequisite_required')
        report['prerequisite_sha256'] = digest(Path('arm-prerequisite/RESULT.json'))
        origin = json.loads((HERE / 'fixtures/TEAM_ORIGIN.json').read_text())
        if (origin.get('schema_version') != 'knowledge-audit9-arm-team-origin.v1'
                or origin.get('historical_candidate_sha256') != EXPECTED
                or origin.get('test_origin_source_commit') != 'f52864e2de45b49fa56a074d1b088d4c448cf213'
                or origin.get('files') != FIXTURE_PINS):
            raise RuntimeError('fixture_exact_inventory_mismatch')
        for name, expected in origin['files'].items():
            if PurePosixPath(name).is_absolute() or '..' in PurePosixPath(name).parts or '\\' in name:
                raise RuntimeError('fixture_name_invalid')
            if digest(HERE / 'fixtures' / name) != expected:
                raise RuntimeError('fixture_pin_mismatch')
        package = HERE / 'fixtures/knowledge-v3.4.4.zip'
        if digest(package) != EXPECTED:
            raise RuntimeError('historical_candidate_mismatch')
        parent = Path(os.environ['RUNNER_TEMP']).resolve(strict=True)
        temp = Path(tempfile.mkdtemp(prefix='knowledge-arm-team-', dir=parent)).resolve(strict=True)
        if HERE == temp or HERE in temp.parents or ' ' in str(temp):
            raise RuntimeError('fixture_parent_invalid')
        report['fixture_retained'] = str(temp)
        with zipfile.ZipFile(package) as archive:
            if len(archive.infolist()) != 499 or archive.testzip() is not None:
                raise RuntimeError('historical_inventory_mismatch')
            for entry in archive.infolist():
                rel = PurePosixPath(entry.filename)
                if (rel.is_absolute() or '..' in rel.parts or '\\' in entry.filename or ':' in entry.filename
                        or entry.is_dir() or rel.parts[0] != '.knowledge' or stat.S_ISLNK(entry.external_attr >> 16)):
                    raise RuntimeError('unsafe_candidate_entry')
                destination = temp.joinpath(*rel.parts)
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(archive.read(entry))
        system = temp / '.knowledge'
        before = {p.relative_to(system).as_posix(): digest(p) for p in system.rglob('*') if p.is_file()}
        for name in ('reliability-windows-team-crash.test.js', 'helpers/reliability-windows-custody-trace.cjs'):
            target = system / 'tests' / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(HERE / 'fixtures/team-crash-tests' / name, target)
        report['origin'] = origin
        node = Path(shutil.which('node')).resolve(strict=True)
        if digest(node) != prerequisite['runtime']['executable_sha256']:
            raise RuntimeError('prerequisite_node_identity_changed')
        report['node_sha256'] = digest(node)
        argv = [str(node), '--test', '--test-concurrency=1', '--test-reporter=tap',
                str(system / 'tests/reliability-windows-team-crash.test.js')]
        report['argv'] = argv
        env = {k: v for k, v in os.environ.items() if not k.upper().startswith(('KNOWLEDGE_', 'GIT_'))}
        env.update(TMP=str(temp), TEMP=str(temp), TMPDIR=str(temp), CI='1', KNOWLEDGE_UPDATE_DISABLE_ON_LAUNCH='1')
        start = time.monotonic()
        with (out / 'team.stdout').open('wb') as stdout, (out / 'team.stderr').open('wb') as stderr:
            child = subprocess.Popen(argv, cwd=system, env=env, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr)
            report['child_pid'] = child.pid
            try:
                while child.poll() is None:
                    if time.monotonic() - start > 660 or max((out / 'team.stdout').stat().st_size, (out / 'team.stderr').stat().st_size) > 8 * 1024 * 1024:
                        raise TimeoutError('cohort_budget_or_output_exceeded')
                    time.sleep(0.1)
            except BaseException:
                report['emergency_harness_cleanup'] = True
                subprocess.run(['taskkill', '/PID', str(child.pid), '/T', '/F'], stdin=subprocess.DEVNULL,
                               stdout=stderr, stderr=stderr, timeout=20, check=False)
                child.wait(timeout=15)
                raise
        report['exit_code'] = child.returncode
        report['elapsed_s'] = round(time.monotonic() - start, 3)
        tap = (out / 'team.stdout').read_bytes()
        totals = {key.decode(): int(value) for key, value in re.findall(rb'^# (tests|pass|fail|cancelled|skipped|todo) (\d+)\r?$', tap, re.M)}
        report['totals'] = totals
        report['original_499_runtime_hashes_unchanged'] = len(before) == 499 and all((system / name).is_file() and digest(system / name) == value for name, value in before.items())
        report['runtime_parity_scope'] = 'Original 499 file hashes only; source-only overlays are explicit additions. Windows modes/full extra-file inventory are not certified.'
        report['node_identity_unchanged'] = digest(node) == report['node_sha256']
        report['scenarios'] = ['original CLI SIGKILL with signed terminal custody receipt and next Flow recovery',
                               'nested fixed Flow AbortSignal cancellation with signed terminal custody receipt and next Flow recovery']
        if (child.returncode != 0 or totals != {'tests': 2, 'pass': 2, 'fail': 0, 'cancelled': 0, 'skipped': 0, 'todo': 0}
                or not report['original_499_runtime_hashes_unchanged'] or not report['node_identity_unchanged']):
            raise RuntimeError('physical_team_custody_incomplete')
        report['status'] = 'PASS_HISTORICAL_CANDIDATE_TEAM_ARM_ONLY'
        return 0
    except BaseException as error:
        report['error'] = {'type': type(error).__name__, 'message': str(error)}
        return 1
    finally:
        report['logs'] = {p.name: digest(p) for p in out.glob('team.*') if p.is_file()}
        (out / 'RESULT.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
        print(json.dumps({'status': report['status'], 'error': report.get('error')}))


if __name__ == '__main__':
    raise SystemExit(main())
