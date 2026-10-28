#!/usr/bin/env python3
"""Exact installed public Windows contract, using retained native QA custody.

Two disjoint fixed shards cover the existing 54 public entries. This does not
replace the maintainer release gate, which the user runs locally.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sys
import time

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value


base = module('audit8_installed_base', ROOT/'qa/reliability/audit6/run_installed_contract.py')
owned = module('audit8_owned_execute', HERE/'owned_execute.py')
native_suite = module('audit8_native_suite', HERE/'run_native_cleanup.py')
HEAVY = ['tools/self-test-team-registry-concurrency.js', 'tools/self-test-recording-blockers.js',
         'tools/self-test-team-mode.js', 'tools/self-test-dedicated-verification.js',
         'tools/self-test-linux-namespace.js', 'tools/self-test-agent-task-workflow.js']
CAPS = {'default': 90, 'heavy': 150, 'tools/self-test-agent-task-workflow.js': 240,
        'tools/self-test-team-mode.js': 360, 'tools/self-test-repair-on-touch.js': 360,
        'tools/self-test-repair-audit.js': 240, 'tools/self-test-update-safety.js': 240,
        'tools/self-test-doctor-audit.js': 150, 'tools/self-test-field-report.js': 150}


def main():
    parser = argparse.ArgumentParser()
    for name in ['package', 'arch', 'out']:
        parser.add_argument('--'+name, required=True)
    parser.add_argument('--shard-index', type=int, choices=[0, 1], required=True)
    parser.add_argument('--shard-count', type=int, choices=[2], default=2)
    parser.add_argument('--cohort-seconds', type=int, default=1200)
    parser.add_argument('--expected-zip-sha256')
    args = parser.parse_args()
    out = Path(args.out).resolve(); out.mkdir(parents=True, exist_ok=False)
    started = time.monotonic(); deadline = started + args.cohort_seconds
    report = {'schema_version': 'knowledge-audit8-installed-windows-contract.v1', 'status': 'FAIL',
              'commit': os.environ.get('GITHUB_SHA'), 'workflow_run': os.environ.get('GITHUB_RUN_ID'),
              'platform': sys.platform, 'arch': args.arch, 'release_qualified': False,
              'full_release_gate': 'NOT_RUN_USER_WILL_RUN_LOCALLY', 'retries': 0,
              'scope': 'One exact ZIP; fixed shard of 54 public entries; every public self-test has native Job custody. '
                       'Shard 0 adds eight source-pinned custody/Team-crash cases against a byte-identical copy of installed code and forced Team cancellation.',
              'steps': [], 'selftests': [], 'fault_checks': [], 'remaining_not_run': [],
              'script_time_caps_s': CAPS, 'cohort_time_cap_s': args.cohort_seconds,
              'fixture_retirement': 'not_requested_keep_temp_diagnostics'}
    save = lambda: base.save(out/'RESULT.json', report)
    system = None; contents = None
    try:
        base.need(sys.platform == 'win32' and args.arch in ['x64', 'arm64'], 'physical_windows_required')
        base.need(900 <= args.cohort_seconds <= 1800, 'cohort_budget_invalid')
        extracted, contents = base.extract(args, out, report); system = extracted/'.knowledge'
        if args.expected_zip_sha256 is not None:
            base.need(report['artifact_sha256'] == args.expected_zip_sha256, 'expected_zip_digest_mismatch')
        contract = base.strict_json((system/'install-manifest.json').read_text(encoding='utf8'))['release_contract']
        scripts = contract['public_self_test_paths']
        base.need(len(scripts) == len(set(scripts)) == 54 and all((system/name).is_file() for name in scripts),
                  'exact_public_54_inventory_required')
        ordered = [name for name in scripts if name not in HEAVY] + [name for name in HEAVY if name in scripts]
        assigned = [name for index, name in enumerate(ordered) if index % 2 == args.shard_index]
        base.need(len(assigned) == 27, 'exact_public_shard_inventory_required')
        report.update(public_selftests=scripts, planned_public_order=ordered,
                      public_inventory_sha256=hashlib.sha256(json.dumps(scripts, separators=(',', ':')).encode()).hexdigest(),
                      shard={'index': args.shard_index, 'count': 2, 'selection': 'full_order_index_modulo_count',
                             'planned_public_order': assigned,
                             'assigned_to_other_shard': [name for name in ordered if name not in assigned]})
        for expected in contract['native_runtime_artifacts']:
            base.base.native_pair(system, expected, system/expected['binary'], system/expected['manifest'])
        execute = owned.make_execute(base, system, expected_arch=args.arch)
        temporary = base.prepare_fixture_temp(out, report, deadline)
        node = shutil.which('node'); base.need(bool(node), 'node_required')
        for name, argv, cwd in [
            ('installed-native-load', [node, '-e', base.base.NATIVE_JS], system),
            ('git-init', ['git', 'init', '--initial-branch=main'], extracted),
            ('install-check', [node, str(system/'tools/install-check.js'), '--json'], extracted)
        ]:
            row, value = execute(name, argv, cwd, out, deadline, fixture_tmp=temporary)
            report['steps'].append(row)
            base.need(row['status'] == 'PASS_PROCESS' and row['cleanup_confirmed'], name+'_process_or_cleanup_failed')
            if name == 'installed-native-load':
                base.need(isinstance(value, dict) and value.get('status') == 'pass' and value.get('arch') == args.arch,
                          'installed_native_load_failed'); row['status'] = 'PASS_NATIVE_LOAD'; report['runtime'] = value
            elif name == 'install-check':
                row['report'] = value
                base.need(isinstance(value, dict) and value.get('status') in ['ok', 'warning', 'warnings', 'pass'],
                          'installed_check_failed'); row['status'] = 'PASS_INSTALL_CHECK'
            save()
        for index, script in enumerate(assigned):
            if script == 'tools/self-test-linux-namespace.js':
                report['selftests'].append({'name': Path(script).stem, 'script': script, 'status': 'NOT_APPLICABLE',
                                           'installed_script_sha256': contents['.knowledge/'+script]['sha256'],
                                           'reason': 'physical_linux_namespace_requires_linux'}); continue
            extra = ['--keep-temp'] if script == 'tools/self-test-team-mode.js' else \
                    ['--workflow-fixture'] if script == 'tools/self-test-recording-blockers.js' else []
            cap = CAPS.get(script, CAPS['heavy' if script in HEAVY else 'default'])
            row, value = execute(Path(script).stem, [node, str(system/script), *extra], system, out, deadline,
                                 timeout=cap, fixture_tmp=temporary)
            row.update(script=script, installed_script_sha256=contents['.knowledge/'+script]['sha256'])
            base.admit_report(script, row, value); report['selftests'].append(row); save()
            if not row.get('cleanup_confirmed') or row['status'] == 'NOT_RUN_BUDGET_EXHAUSTED':
                report['cohort_halted'] = True; report['remaining_not_run'] = assigned[index+1:]; break
        if args.shard_index == 0 and not report.get('cohort_halted'):
            suites = ['reliability-windows-qa-custody', 'reliability-windows-team-crash']
            pins = base.strict_json((Path(args.package)/'SOURCE_PINS.json').read_text(encoding='utf8'))
            policies = base.strict_json((HERE/'EXPECTED_CASES.json').read_text(encoding='utf8'))['suites']
            testroot = out/'installed-fault-source'/'.knowledge'; shutil.copytree(system, testroot)
            added = ['tests/'+name+'.test.js' for name in suites] + ['tests/helpers/reliability-windows-custody-trace.cjs']
            report['fault_source_inventory'] = {}
            for relative in added:
                source = ROOT/'source/.knowledge'/relative
                digest = base.sha(source)
                base.need(digest == pins['files'][relative], 'fault_source_binding_changed:'+relative)
                destination = testroot/relative; destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, destination)
                report['fault_source_inventory'][relative] = digest
            for name in suites:
                relative = 'tests/'+name+'.test.js'; policy = policies[name]
                base.need(report['fault_source_inventory'][relative] == policy['source_sha256'], 'fault_case_inventory_binding_changed:'+name)
                row, _ = execute(name, [node, '--test', '--test-reporter=tap', '--test-concurrency=1', str(testroot/relative)],
                                 testroot, out, deadline, timeout=300, fixture_tmp=temporary)
                if 'stdout_sha256' in row:
                    native_suite.admit_tap(row, (out/(name+'.stdout.json')).read_text(encoding='utf8'), policy)
                row['tested_runtime'] = 'byte_identical_installed_zip_copy_plus_pinned_test_bodies_and_trace_helper'
                report['fault_checks'].append(row); save()
                base.need(row['status'] == 'PASS_NATIVE_SOURCE_SUITE' and row['cleanup_confirmed'], 'installed_native_faults_failed:'+name)
            base.need(all(base.sha(testroot/name) == digest for name, digest in report['fault_source_inventory'].items()),
                      'fault_test_source_mutated')
            changed = [name for name, entry in contents.items() if base.sha(testroot/name.removeprefix('.knowledge/')) != entry['sha256']]
            base.need(not changed, 'fault_runtime_copy_mutated')
            forced = owned.make_execute(base, system, expected_arch=args.arch, cancel_on_team_native_ready=2)
            row, _ = forced('team-forced-cancel', [node, str(system/'tools/self-test-team-mode.js'), '--keep-temp'],
                            system, out, deadline, timeout=360, fixture_tmp=temporary)
            report['fault_checks'].append(row); save()
            base.need(row['status'] == 'CANCELLED_CLEANUP_CONFIRMED' and row['cleanup_confirmed'] and
                      row.get('cancellation', {}).get('reason') == 'team_native_ready' and
                      row.get('cancellation', {}).get('team_native_scopes_observed') == 2, 'installed_team_cancellation_failed')
        report['selftest_counts'] = {status: sum(row['status'] == status for row in report['selftests'])
                                    for status in sorted({row['status'] for row in report['selftests']})}
        base.need(len(report['selftests']) == 27 and not report['remaining_not_run'] and
                  all(row['status'] in ['PASS_SELFTEST', 'NOT_APPLICABLE'] for row in report['selftests']),
                  'complete_installed_public_shard_required')
        base.need(time.monotonic() < deadline, 'original_cohort_budget_exhausted')
        report['status'] = 'PASS_INSTALLED_PUBLIC_CONTRACT_SHARD'
    except BaseException as error:
        report['error'] = {'type': type(error).__name__, 'message': str(error)}
    finally:
        if system is not None and contents is not None:
            changes = [name for name, entry in contents.items() if not (system/name.removeprefix('.knowledge/')).is_file() or
                       base.sha(system/name.removeprefix('.knowledge/')) != entry['sha256']]
            report['installed_byte_changes'] = changes; report['installed_bytes_unchanged'] = not changes
            if changes:
                report['status'] = 'FAIL_INSTALLED_BYTES_CHANGED'
        report['elapsed_s'] = round(time.monotonic()-started, 3); save()
        print(json.dumps({key: report.get(key) for key in ['status', 'artifact_sha256', 'shard', 'selftest_counts', 'error', 'elapsed_s']}), flush=True)
    return 0 if report['status'] == 'PASS_INSTALLED_PUBLIC_CONTRACT_SHARD' else 1


if __name__ == '__main__':
    sys.exit(main())
