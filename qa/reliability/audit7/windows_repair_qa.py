#!/usr/bin/env python3
"""Bounded complete Windows repair self-tests from one exact installed package.

Reuse the installed-contract extractor and process runner. Per-check stderr
frames diagnose cumulative runtime versus a stalled stage; they never replace
the public report, process exit, native cleanup, or the release gate.
"""
import argparse, importlib.util, json, math, os, pathlib, platform, shutil, sys, time

P = pathlib.Path
HERE = P(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('installed', HERE.parent/'audit6/run_installed_contract.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
SCRIPTS = [
    ('self-test-doctor-repair-lifecycle', 90, 5),
    ('self-test-repair-audit', 240, 14),
    ('self-test-repair-on-touch', 360, 124),
]


def phases(path):
    frames, active, previous, errors = [], [], -1, []
    for line in path.read_text(encoding='utf8', errors='replace').splitlines():
        try: item = m.strict_json(line)
        except (ValueError, UnicodeError): continue
        if not isinstance(item, dict) or item.get('schema_version') != 'knowledge-selftest-phase.v1': continue
        event, name, elapsed = item.get('event'), item.get('name'), item.get('elapsed_ms')
        if event not in ('begin', 'pass', 'exit', 'fail') or not isinstance(name, str) or \
                type(elapsed) not in (int, float) or not math.isfinite(elapsed) or elapsed < 0 or elapsed < previous:
            errors.append('invalid_phase_frame'); continue
        previous = elapsed; frames.append(item)
        if event == 'begin': active.append(name)
        elif not active or active.pop() != name: errors.append('unbalanced_phase_frame')
    return {'frames': frames, 'unfinished': active, 'errors': errors,
            'diagnostic_only_not_native_cleanup_proof': True}


def main():
    ap = argparse.ArgumentParser()
    for name in ('package', 'arch', 'out'): ap.add_argument('--'+name, required=True)
    ap.add_argument('--only-doctor', action='store_true')
    a = ap.parse_args(); out = P(a.out).resolve(); out.mkdir(parents=True, exist_ok=False)
    scripts = [(SCRIPTS[0][0], 120, SCRIPTS[0][2])] if a.only_doctor else SCRIPTS
    report = {'schema_version': 'knowledge-audit7-windows-repair.v1', 'status': 'FAIL',
              'commit': os.environ.get('GITHUB_SHA'), 'workflow_run': os.environ.get('GITHUB_RUN_ID'),
              'host': {'system': platform.system(), 'machine': platform.machine()}, 'steps': [],
              'release_qualified': False, 'retries': 0,
              'scope': 'Complete Doctor lifecycle self-test; remaining public scripts not executed in this targeted run.'
                       if a.only_doctor else 'Complete three declared public repair self-tests, not all 54 public tests.',
              'declared_scripts': [{'name': n, 'cap_s': cap, 'expected_checks': count} for n, cap, count in scripts]}
    deadline = time.monotonic()+(150 if a.only_doctor else 720)
    try:
        m.need(sys.platform == 'win32', 'windows_required')
        extracted, contents = m.extract(a, out, report); system = extracted/'.knowledge'
        pins = m.strict_json((P(a.package)/'SOURCE_PINS.json').read_text())
        for name, _, _ in scripts:
            relative = 'tools/'+name+'.js'
            m.need(m.sha(system/relative) == pins['files'][relative] == m.sha(m.ROOT/'source/.knowledge'/relative),
                   'installed_selftest_source_pin_mismatch:'+name)
        temp = m.prepare_fixture_temp(out, report, deadline)
        node = shutil.which('node'); m.need(bool(node), 'node_required')
        row, value = m.execute('native-load', [node, '-e', m.base.NATIVE_JS], system, out, deadline, 20, fixture_tmp=temp)
        report['steps'].append(row)
        m.need(row['status'] == 'PASS_PROCESS' and value and value.get('status') == 'pass' and
               value.get('arch') == a.arch, 'native_runtime_not_qualified')
        report['selftests'] = []
        for name, cap, expected in scripts:
            row, value = m.execute(name, [node, str(system/'tools'/(name+'.js'))], system, out,
                                   deadline, cap, fixture_tmp=temp)
            report['selftests'].append(row)
            m.admit_report('tools/'+name+'.js', row, value)
            observed = phases(out/(name+'.stderr.txt')) if 'stderr_sha256' in row else None
            row['phase_diagnostics'] = observed
            if row['status'] == 'PASS_SELFTEST':
                checks = value.get('checks')
                names = [c if isinstance(c, str) else c.get('name') if isinstance(c, dict) else None
                         for c in checks] if isinstance(checks, list) else []
                passed_phases = [f['name'] for f in observed['frames'] if f['event'] == 'pass'] if observed else []
                if not isinstance(checks, list) or len(checks) != expected or not observed or \
                        observed['unfinished'] or observed['errors'] or \
                        any(not isinstance(n, str) or passed_phases.count(n) != 1 for n in names) or \
                        len(set(names)) != len(names):
                    row.update(status='FAIL_COMPLETE_CHECK_INVENTORY_OR_PHASES')
            m.save(out/'RESULT.json', report)
            if row.get('timed_out') or row.get('output_limit_exceeded') or row['status'].startswith('NOT_RUN'):
                report['cohort_halted'] = row['name']; break
        changed = [n for n, v in contents.items() if m.sha(extracted/n) != v['sha256']]
        report['installed_byte_changes'] = changed
        m.need(not changed, 'installed_bytes_changed')
        m.need(len(report['selftests']) == len(scripts) and
               all(r['status'] == 'PASS_SELFTEST' for r in report['selftests']), 'repair_contract_incomplete')
        report['status'] = 'PASS_COMPLETE_INSTALLED_DOCTOR_LIFECYCLE' if a.only_doctor else \
                           'PASS_THREE_COMPLETE_INSTALLED_REPAIR_SELFTESTS'; return 0
    except BaseException as error:
        report['error'] = {'type': type(error).__name__, 'message': str(error)}; return 1
    finally:
        m.save(out/'RESULT.json', report)
        print(json.dumps({'status': report['status'], 'error': report.get('error'),
                          'selftests': [{k: r.get(k) for k in ('name', 'status', 'elapsed_s', 'checks_total')}
                                        for r in report.get('selftests', [])]}), flush=True)


if __name__ == '__main__': sys.exit(main())
