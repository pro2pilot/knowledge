#!/usr/bin/env python3
"""Physical Windows cleanup qualification with exact source/native evidence."""
import argparse, importlib.util, json, os, pathlib, re, shutil, sys, time
P = pathlib.Path
HERE = P(__file__).resolve().parent
ROOT = HERE.parents[3]
spec = importlib.util.spec_from_file_location('installed_audit6', ROOT/'qa/reliability/audit6/run_installed_contract.py')
base = importlib.util.module_from_spec(spec); spec.loader.exec_module(base)
spec = importlib.util.spec_from_file_location('owned_execute', HERE/'owned_execute.py')
owned = importlib.util.module_from_spec(spec); spec.loader.exec_module(owned)
BASE_ZIP = '055b9d950038f00a9716a57b7c6b8e9f5103d760bb9f1449181669cbe2ccd0b7'


def inventory(root):
    return {p.relative_to(root).as_posix(): base.sha(p) for p in sorted(root.rglob('*')) if p.is_file()}


def admit_tap(row, stdout, policy):
    totals = re.findall(r'^# (tests|pass|fail|skipped|cancelled|todo) (\d+)\s*$', stdout, re.M)
    counts = {k: int(v) for k, v in totals}
    cases = re.findall(r'^(ok|not ok) \d+ - (.*?)(?: # (SKIP|TODO)(?: .*)?)?$', stdout, re.M)
    names = [name for _, name, _ in cases]
    skipped = [name for status, name, directive in cases if directive == 'SKIP' and status == 'ok']
    good = row['status'] == 'PASS_PROCESS' and len(totals) == len(counts) == 6 and \
        counts.get('tests') == len(policy['cases']) and counts.get('pass') == len(policy['cases'])-len(policy['allowed_windows_skips']) and \
        counts.get('skipped') == len(policy['allowed_windows_skips']) and all(counts.get(k) == 0 for k in ['fail','cancelled','todo']) and \
        len(names) == len(set(names)) == len(policy['cases']) and set(names) == set(policy['cases']) and \
        all(status == 'ok' and directive != 'TODO' for status, _, directive in cases) and set(skipped) == set(policy['allowed_windows_skips'])
    row.update(tap=counts, observed_cases=names, allowed_skips=skipped)
    row['tap_admission'] = 'PASS' if good else 'FAIL'
    if row['status'] == 'PASS_PROCESS': row['status'] = 'PASS_NATIVE_SOURCE_SUITE' if good else 'FAIL_NATIVE_SOURCE_SUITE'


def main():
    ap = argparse.ArgumentParser()
    for name in ['package', 'arch', 'out']: ap.add_argument('--'+name, required=True)
    ap.add_argument('--source', default=str(ROOT/'source/.knowledge'))
    ap.add_argument('--cohort-seconds', type=int, default=1200)
    a = ap.parse_args(); out = P(a.out).resolve(); out.mkdir(parents=True, exist_ok=False)
    report = {'schema_version':'knowledge-audit8-windows-native-cleanup.v1','status':'FAIL',
              'commit':os.environ.get('GITHUB_SHA'),'workflow_run':os.environ.get('GITHUB_RUN_ID'),
              'scope':'Exact checked-out source with source-bound native pairs from the preserved ZIP; final ZIP matrix is separate.',
              'release_qualified':False,'prior_audit7_timeout_record_rewritten':False,'steps':[]}
    deadline = time.monotonic()+a.cohort_seconds
    try:
        base.need(sys.platform == 'win32' and a.arch in ('x64','arm64'), 'physical_windows_required')
        extracted, contents = base.extract(a,out,report)
        base.need(report['artifact_sha256'] == BASE_ZIP, 'base_package_changed')
        previous = extracted/'.knowledge'; source = P(a.source).resolve(strict=True)
        # The exact old archive supplies native binaries only. Its runtime
        # code is not silently substituted for the source being qualified.
        system = out/'source-runtime'/'.knowledge'; shutil.copytree(source,system)
        shutil.copytree(previous/'tools/lib/native',system/'tools/lib/native',dirs_exist_ok=True)
        for path in (system/'tools/lib/native').rglob('*'):
            if path.is_file(): base.need(base.sha(path) == base.sha(previous/'tools/lib/native'/path.relative_to(system/'tools/lib/native')), 'native_copy_changed')
        frozen = inventory(system); base.save(out/'SOURCE_RUNTIME_PINS.json',frozen)
        report.update(source_runtime_pins_sha256=base.sha(out/'SOURCE_RUNTIME_PINS.json'), source_runtime_files=len(frozen))
        tests = base.strict_json((HERE/'EXPECTED_CASES.json').read_text())['suites']
        for name, policy in tests.items():
            base.need(base.sha(system/'tests'/(name+'.test.js')) == policy['source_sha256'], 'test_source_binding:'+name)
        execute = owned.make_execute(base,system,expected_arch=a.arch)
        temp = base.prepare_fixture_temp(out,report,deadline)
        node = shutil.which('node'); base.need(bool(node),'node_required')
        for name, policy in tests.items():
            row,_ = execute(name,[node,'--test','--test-reporter=tap','--test-concurrency=1',str(system/'tests'/(name+'.test.js'))],system,out,deadline,300,fixture_tmp=temp)
            if 'stdout_sha256' in row: admit_tap(row,(out/(name+'.stdout.json')).read_text(encoding='utf8'),policy)
            report['steps'].append(row); base.save(out/'RESULT.json',report)
            base.need(row['status'] == 'PASS_NATIVE_SOURCE_SUITE' and row['cleanup_confirmed'], 'native_source_suite_failed:'+name)
        argv = [node,str(system/'tools/self-test-team-mode.js'),'--keep-temp']
        row,value = execute('team-normal',argv,system,out,deadline,360,fixture_tmp=temp)
        base.admit_report('tools/self-test-team-mode.js',row,value)
        names = [x if isinstance(x,str) else x.get('name') for x in value.get('checks',[])] if isinstance(value,dict) else []
        report['steps'].append(row); base.save(out/'RESULT.json',report)
        base.need(row['status'] == 'PASS_SELFTEST' and len(names) == len(set(names)) == 27, 'complete_team_normal_flow_required')
        forced = owned.make_execute(base,system,expected_arch=a.arch,cancel_on_team_native_ready=2)
        row,_ = forced('team-forced-cancel',argv,system,out,deadline,360,fixture_tmp=temp)
        report['steps'].append(row); base.save(out/'RESULT.json',report)
        base.need(row['status'] == 'CANCELLED_CLEANUP_CONFIRMED' and row['cleanup_confirmed'] and
                  row.get('cancellation',{}).get('reason') == 'team_native_ready' and
                  row.get('cancellation',{}).get('team_native_scopes_observed') == 2,
                  'team_forced_native_cleanup_required')
        after = inventory(system)
        report['source_runtime_changes'] = sorted(n for n in set(frozen)|set(after) if frozen.get(n) != after.get(n))
        base.need(not report['source_runtime_changes'],'source_runtime_mutated')
        # --keep-temp preserves fixture files for audit. All native process
        # scopes and their private loaded helpers have separate closure proof.
        report['fixture_retirement'] = 'not_requested_keep_temp_diagnostics'
        report['status'] = 'PASS_WINDOWS_NATIVE_QA_CLOSURE'; return 0
    except BaseException as error:
        report['error'] = {'type':type(error).__name__,'message':str(error)}; return 1
    finally:
        base.save(out/'RESULT.json',report)
        print(json.dumps({'status':report['status'],'error':report.get('error'),
                          'steps':[{k:r.get(k) for k in ['name','status','cleanup_confirmed','elapsed_s']} for r in report['steps']]}),flush=True)


if __name__ == '__main__':sys.exit(main())
