#!/usr/bin/env python3
import copy, hashlib, importlib.util, json, subprocess, sys, tempfile, unittest
from pathlib import Path

target = Path(__file__).with_name('darwin-production-summary.py')
if '--summary-target' in sys.argv:
    index = sys.argv.index('--summary-target');target = Path(sys.argv[index + 1]).resolve();del sys.argv[index:index+2]
spec = importlib.util.spec_from_file_location('production_summary', target)
summary = importlib.util.module_from_spec(spec);spec.loader.exec_module(summary)


class ProductionEvidence(unittest.TestCase):
    def good(self):
        value = {'status': 'PASS_PHYSICAL_PRODUCTION_NORMAL', 'architecture': 'arm64', 'source_unchanged': True,
            'cleanup_confirmed': True, 'cases': [{'name': 'normal', 'status': 'PASS_PHYSICAL_PRODUCTION',
                'controller_exit_code': 0, 'KVE_KVF_ACK_verified': True, 'terminal': {'success': True, 'stage': 'complete'}}],
            'binary_history': [{'kind': 'shipping', 'qa_io_enabled': False, **{key: 'a'*64 for key in
                ('broker_sha256', 'stub_sha256', 'source_sha256', 'stub_source_sha256')}}],
            'native_addon': {'source_sha256': 'a'*64, 'binary_sha256': 'b'*64, 'platform': 'darwin', 'architecture': 'arm64'}}
        cases = []
        for name, required in summary.PROTECTED_CASES.items():
            row = {'name': name, 'required_acceptance': required, 'status': 'PASS_PHYSICAL_PAIRED'}
            for version in ('before', 'after'):
                accepted = False if version == 'before' and name == 'search_only_ancestor' else required
                row[version] = {'accepted': accepted, 'exit_code': 0,
                    'source_sha256': summary.BEFORE_PROTECTED_SOURCE_SHA if version == 'before' else 'a'*64,
                    **({'sha256': hashlib.sha256(b'#!/bin/sh\nexit 0\n').hexdigest()} if accepted else
                        {'code': 'darwin_protected_path_unsafe', 'native_error': 13})}
            cases.append(row)
        value['protected_executable_contract'] = {'status': 'PASS_PHYSICAL_PAIRED', 'cases': cases,
            'write_acl_effects_verified': True, 'before_source_sha256': summary.BEFORE_PROTECTED_SOURCE_SHA,
            'after_source_sha256': 'a'*64, 'before_binary_sha256': 'c'*64, 'after_binary_sha256': 'b'*64}
        return value

    def test_cli_rejects_incomplete_evidence_even_after_zero_controller_exit(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder);private = root/'private';private.mkdir();source = root/'source';source.mkdir()
            (source/'seed.js').write_bytes(b'fixture');(source/'seed.js').chmod(0o600)
            inputs = {'files': [{'path': 'source/seed.js', 'bytes': 7, 'sha256': hashlib.sha256(b'fixture').hexdigest(), 'executable': False}],
                'controller_sha256': 'c'*64, 'lifecycle_sha256': 'd'*64, 'reference_runner_sha256': 'e'*64}
            (private/'INPUTS.json').write_text(json.dumps(inputs))
            values = [('valid', self.good(), 0)]
            for name, mutate in (
                ('missing-case', lambda v: v.update(cases=[])),
                ('duplicate-case', lambda v: v['cases'].append(v['cases'][0])),
                ('unexpected-case', lambda v: v['cases'].append({'name': 'unreviewed-extra-case', 'status': 'FAIL'})),
                ('nonobject-case', lambda v: v['cases'].append(None)),
                ('failed-case-caller', lambda v: v['cases'][0].update(controller_exit_code=1)),
                ('no-cleanup', lambda v: v.update(cleanup_confirmed=False)),
                ('source-drift', lambda v: v.update(source_unchanged=False)),
                ('wrong-arch', lambda v: v.update(architecture='x86_64')),
                ('qa-build', lambda v: v['binary_history'][0].update(qa_io_enabled=True)),
                ('missing-addon', lambda v: v.update(native_addon={})),
                ('missing-ack', lambda v: v['cases'][0].update(KVE_KVF_ACK_verified=False)),
                ('unaccepted', lambda v: v['cases'][0]['terminal'].update(success=False)),
                ('missing-protected-pair', lambda v: v['protected_executable_contract']['cases'].pop()),
                ('duplicate-protected-pair', lambda v: v['protected_executable_contract']['cases'].append(v['protected_executable_contract']['cases'][0])),
                ('unproved-acl', lambda v: v['protected_executable_contract'].update(write_acl_effects_verified=False)),
                ('wrong-protected-binary', lambda v: v['protected_executable_contract'].update(after_binary_sha256='f'*64)),
                ('new-search-refused', lambda v: v['protected_executable_contract']['cases'][0]['after'].update(accepted=False)),
                ('old-search-unreproduced', lambda v: v['protected_executable_contract']['cases'][0]['before'].update(accepted=True))):
                value = self.good();mutate(value);values.append((name, value, 1))
            for name, value, expected in values:
                with self.subTest(name=name):
                    (private/'SUMMARY.json').write_text(json.dumps(value));public = root/name
                    result = subprocess.run([sys.executable, str(target), '--private', str(private), '--public', str(public),
                        '--source', str(source), '--controller-status', '0', '--expected-arch', 'arm64'], capture_output=True, text=True, timeout=10)
                    self.assertEqual(result.returncode, expected, result.stdout+result.stderr)
                    self.assertEqual(sorted(p.name for p in public.iterdir()), ['stages.json', 'summary.json'])
            (private/'SUMMARY.json').write_text(json.dumps(self.good()))
            for bad in ({}, {**inputs, 'files': inputs['files']*2}, {**inputs, 'files': []}):
                (private/'INPUTS.json').write_text(json.dumps(bad))
                actual, _ = summary.build(private, source, 0, 'arm64');self.assertEqual(actual['status'], 'FAIL_OR_INCOMPLETE')

    def test_diagnostic_enum_is_closed(self):
        labels = ['proof_top_current', 'proof_body_current', 'proof_reply_flags', 'proof_schema', 'proof_source_binding',
            'proof_digest', 'proof_boundary_facts', 'proof_clock', 'proof_terminal', 'proof_command_drain', 'proof_structure',
            'control_input_bound', 'control_descriptor', 'control_capability', 'control_role_identity', 'control_authority_exit']
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); private = root/'private'; private.mkdir(); source = root/'source'; source.mkdir()
            for diagnostic in labels + ['NEVER_PUBLIC_private_data', {'proof_clock': 'secret'}, None, 5]:
                value = self.good(); value['cases'][0]['terminal']['error'] = {'darwin_diagnostic': diagnostic}
                (private/'SUMMARY.json').write_text(json.dumps(value))
                result, _ = summary.build(private, source, 1, 'arm64')
                expected = diagnostic if isinstance(diagnostic, str) and diagnostic in labels else None
                self.assertEqual(result['cases'][0].get('proof_diagnostic'), expected)
                self.assertNotIn('NEVER_PUBLIC', json.dumps(result))

    def test_raw_native_and_payload_fields_cannot_escape(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder);private = root/'private';private.mkdir();source = root/'source';source.mkdir()
            secret = 'NEVER_PUBLIC_native_token_or_payload_value'
            value = self.good();value.update(token=secret, failure=secret, hostname=secret, raw_traceback=secret)
            value['installation_parent'] = {'created': True, 'exists_before': False, 'errno': 2, 'path': secret,
                'identity': {'dev': secret, 'ino': secret}, 'message': secret}
            value['cases'][0]['terminal'].update(token=secret, result=secret, acceptances=secret,
                error_code=secret, error={'message': secret, 'stage': secret, 'containment': {'reason': secret},
                    'teardown': {'status': secret}, 'recovery_required': secret, 'timed_out': secret})
            value['protected_executable_contract'].update(path=secret, raw=secret)
            value['protected_executable_contract']['cases'][0]['after'].update(path=secret, stdout=secret, native_error=secret)
            value['records'] = [{'name': '001-'+secret, 'exit_code': 1, 'stdout': secret}]
            value['diagnostics'] = [{'type': 'ValueError', 'stage': 'execute', 'args': secret,
                'frames': [{'file': 'darwin-production-lifecycle.py', 'line': 200, 'locals': secret}, {'file': secret, 'line': 1}]}]
            (private/'SUMMARY.json').write_text(json.dumps(value))
            public, stages = summary.build(private, source, 1, 'arm64')
            self.assertNotIn(secret, json.dumps([public, stages]));self.assertFalse(public['release_gate_qualified'])
            self.assertIsNone(public['cases'][0]['error_code']);self.assertIsNone(public['cases'][0]['containment_reason'])
            self.assertEqual(stages['stages'][0]['stage'], '001-unclassified-stage')
            self.assertTrue(public['installation_parent']['created']);self.assertFalse(public['installation_parent']['exists_before'])
            self.assertEqual(public['installation_parent']['errno'], 2)

    def test_basic_matrix_requires_exact_cases_real_silence_and_failed_exit7(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder);private = root/'private';private.mkdir();source = root/'source';(source/'tools/lib').mkdir(parents=True)
            code = b"const code = 'verification_command_failed';\n"
            file = source/'tools/lib/verification-darwin-production.js';file.write_bytes(code);file.chmod(0o600)
            inputs = {'files': [{'path': 'source/tools/lib/verification-darwin-production.js', 'bytes': len(code), 'sha256': hashlib.sha256(code).hexdigest(), 'executable': False}],
                **{key: 'c'*64 for key in ('controller_sha256', 'lifecycle_sha256', 'reference_runner_sha256',
                    'matrix_controller_sha256', 'workloads_sha256')}}
            (private/'INPUTS.json').write_text(json.dumps(inputs))
            def good():
                value = self.good();value.update(case_set='basic', status='PASS_PHYSICAL_PRODUCTION_BASIC')
                for name, expected in (('scratch_readonly', 0), ('silent_long', 0), ('exit7', 7)):
                    row = copy.deepcopy(value['cases'][0]);row['name'] = name
                    row['terminal'].update(case_name=name, expected_exit=expected, source_unchanged=True,
                        observed_elapsed_ms=125001 if name == 'silent_long' else 5000,
                        result=[{'record': {'status': 'pass' if expected == 0 else 'fail', 'exit_code': expected}}],
                        finalized={'status': 'accepted'}, acceptances=[{'private_receipt': 'NEVER_PUBLIC_acceptance'}],
                        budget={'no_progress_ms': 500 if name == 'silent_long' else 0,
                            'progress_monitored_operations': ['native_copy_chunk']})
                    if name == 'exit7':
                        row.update(KVE_KVF_ACK_verified=False, failed_observation_verified=True)
                        row['terminal'].update(finalized={'status': 'not_accepted'}, acceptances=[],
                            error_code='verification_command_failed', error={'teardown': {'status': 'completed'},
                                'recovery_required': False, 'timed_out': False}, failed_KVE_verified=True,
                            failed_attempt_no_ACK=True, failed_cleanup_confirmed=True,
                            retry_accepted=True, retry_distinct_attempt=True)
                    value['cases'].append(row)
                return value
            variants = [('valid', good(), 0)]
            for name, mutate in (
                ('missing', lambda v: v['cases'].pop()),
                ('duplicate', lambda v: v['cases'].__setitem__(3, copy.deepcopy(v['cases'][2]))),
                ('extra', lambda v: v['cases'].append({'name': 'unknown'})),
                ('exit7-mislabeled-pass', lambda v: v['cases'][3]['terminal']['result'][0]['record'].update(status='pass')),
                ('exit7-wrong-code', lambda v: v['cases'][3]['terminal']['result'][0]['record'].update(exit_code=0)),
                ('exit7-false-ACK', lambda v: v['cases'][3].update(KVE_KVF_ACK_verified=True)),
                ('exit7-unverified-observation', lambda v: v['cases'][3].update(failed_observation_verified=False)),
                ('exit7-no-durable-KVE', lambda v: v['cases'][3]['terminal'].update(failed_KVE_verified=False)),
                ('exit7-has-ACK', lambda v: v['cases'][3]['terminal'].update(acceptances=[{'signature': 'NEVER_PUBLIC'}])),
                ('exit7-unconfirmed-cleanup', lambda v: v['cases'][3]['terminal'].update(failed_cleanup_confirmed=False)),
                ('exit7-recovery-required', lambda v: v['cases'][3]['terminal']['error'].update(recovery_required=True)),
                ('exit7-wrong-error', lambda v: v['cases'][3]['terminal'].update(error_code='verification_containment_unavailable')),
                ('exit7-retry-failed', lambda v: v['cases'][3]['terminal'].update(retry_accepted=False)),
                ('exit7-retry-reused', lambda v: v['cases'][3]['terminal'].update(retry_distinct_attempt=False)),
                ('short-silence', lambda v: v['cases'][2]['terminal'].update(observed_elapsed_ms=124999)),
                ('disabled-progress-policy', lambda v: v['cases'][2]['terminal']['budget'].update(no_progress_ms=0)),
                ('opaque-progress-policy', lambda v: v['cases'][2]['terminal']['budget'].update(progress_monitored_operations=['command'])),
                ('unfinalized', lambda v: v['cases'][1]['terminal'].update(finalized={'status': 'unconfirmed'}))):
                value = good();mutate(value);variants.append((name, value, 1))
            for name, value, expected in variants:
                with self.subTest(name=name):
                    (private/'SUMMARY.json').write_text(json.dumps(value));public = root/name
                    result = subprocess.run([sys.executable, str(target), '--private', str(private), '--public', str(public),
                        '--source', str(source), '--controller-status', '0', '--expected-arch', 'arm64', '--case-set', 'basic'],
                        capture_output=True, text=True, timeout=10)
                    self.assertEqual(result.returncode, expected, result.stdout+result.stderr)
                    actual = json.loads((public/'summary.json').read_text())
                    self.assertNotIn('NEVER_PUBLIC', json.dumps(actual))
                    self.assertEqual(actual['status'], 'PASS_PRODUCTION_BASIC_MATRIX' if expected == 0 else 'FAIL_OR_INCOMPLETE')
            (private/'SUMMARY.json').write_text(json.dumps(good()))
            actual, _ = summary.build(private, source, 0, 'arm64')
            self.assertEqual(actual['status'], 'FAIL_OR_INCOMPLETE', 'the normal gate must not accept a different case cohort')
            inputs.pop('workloads_sha256');(private/'INPUTS.json').write_text(json.dumps(inputs))
            actual, _ = summary.build(private, source, 0, 'arm64', 'basic')
            self.assertEqual(actual['status'], 'FAIL_OR_INCOMPLETE')

    def test_failure_cohort_requires_every_exact_case_and_native_helper_binding(self):
        fixture_path = Path(__file__).with_name('test-darwin-production-failures.py')
        fixture_spec = importlib.util.spec_from_file_location('failure_fixture', fixture_path)
        fixtures = importlib.util.module_from_spec(fixture_spec);fixture_spec.loader.exec_module(fixtures)
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder);private = root/'private';private.mkdir();source = root/'source'
            lib = source/'tools/lib';lib.mkdir(parents=True)
            code = b"const codes = ['verification_cancelled','verification_darwin_transport_failed'];\n"
            file = lib/'verification-darwin-production.js';file.write_bytes(code);file.chmod(0o600)
            inputs = {'files': [{'path': 'source/tools/lib/verification-darwin-production.js', 'bytes': len(code),
                'sha256': hashlib.sha256(code).hexdigest(), 'executable': False}],
                **{key: 'c'*64 for key in ('controller_sha256', 'lifecycle_sha256', 'reference_runner_sha256')},
                'failure_assets': {name: 'd'*64 for name in summary.FAILURE_ASSETS}}
            (private/'INPUTS.json').write_text(json.dumps(inputs))

            def good():
                value = self.good();value.update(case_set='failures', status='PASS_PHYSICAL_PRODUCTION_FAILURES',
                    failure_helper_pins={name: {'source_sha256': 'd'*64, 'binary_sha256': 'e'*64}
                        for name in ('process_observer_pin', 'signal_pin')})
                value['cases'].extend(fixtures.fixture(name) for name in sorted(summary.FAILURE_CASES))
                return value

            variants = [('valid', good(), 0)]
            for name, mutate in (
                ('missing', lambda v: v['cases'].pop()),
                ('duplicate', lambda v: v['cases'].__setitem__(2, copy.deepcopy(v['cases'][1]))),
                ('unknown-extra', lambda v: v['cases'].append({'name': 'unknown'})),
                ('malformed-extra', lambda v: v['cases'].append(None)),
                ('failed-helper-tail', lambda v: v['cases'][1].update(controller_exit_code=1)),
                ('unconfirmed-cleanup', lambda v: v['cases'][1]['observations'].update(cleanup_confirmed=False)),
                ('alive-authority', lambda v: v['cases'][1]['observations']['authority_exit'].update(state='same_running')),
                ('positive-ACK', lambda v: v['cases'][1]['terminal'].update(acceptances=[{'signature': 'NEVER_PUBLIC_ACK'}])),
                ('no-helper-pins', lambda v: v.update(failure_helper_pins={})),
                ('wrong-helper-source', lambda v: v['failure_helper_pins']['signal_pin'].update(source_sha256='f'*64)),
                ('different-case-set', lambda v: v.update(case_set='basic'))):
                value = good();mutate(value);variants.append((name, value, 1))
            for name, value, expected in variants:
                with self.subTest(name=name):
                    for row in value['cases']:
                        if isinstance(row, dict): row['raw_secret'] = 'NEVER_PUBLIC_RAW_RECEIPT'
                    (private/'SUMMARY.json').write_text(json.dumps(value));public = root/name
                    result = subprocess.run([sys.executable, str(target), '--private', str(private), '--public', str(public),
                        '--source', str(source), '--controller-status', '0', '--expected-arch', 'arm64', '--case-set', 'failures'],
                        capture_output=True, text=True, timeout=10)
                    self.assertEqual(result.returncode, expected, result.stdout+result.stderr)
                    actual = json.loads((public/'summary.json').read_text())
                    self.assertNotIn('NEVER_PUBLIC', json.dumps(actual))
                    self.assertEqual(actual['status'], 'PASS_PRODUCTION_FAILURE_MATRIX' if expected == 0 else 'FAIL_OR_INCOMPLETE')
            (private/'SUMMARY.json').write_text(json.dumps(good()))
            inputs['failure_assets'].pop('darwin-test-signal.c')
            (private/'INPUTS.json').write_text(json.dumps(inputs))
            actual, _ = summary.build(private, source, 0, 'arm64', 'failures')
            self.assertEqual(actual['status'], 'FAIL_OR_INCOMPLETE')

    def test_fixed_policy_error_and_product_phase_are_public_without_message(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder);private = root/'private';private.mkdir();source = root/'source';(source/'tools/lib').mkdir(parents=True)
            (source/'tools/lib/verification-policy.js').write_text("throw requestError('verification_darwin_config_invalid');")
            (source/'tools/lib/inert-data.js').write_text("dataDescriptor('transaction_input_invalid');")
            for code in ('verification_darwin_config_invalid', 'transaction_input_invalid', 'ERR_DLOPEN_FAILED', 'EACCES'):
                value = self.good();value['cases'][0]['terminal'].update(success=False, stage='public-run', error_code=code,
                    error={'stage': 'setup', 'message': 'NEVER_PUBLIC_diagnostic_message', 'timed_out': False,
                        'recovery_required': True, 'teardown': {'status': 'unconfirmed', 'secret': 'NEVER_PUBLIC_teardown'}})
                (private/'SUMMARY.json').write_text(json.dumps(value))
                actual, _ = summary.build(private, source, 1, 'arm64')
                self.assertEqual(actual['cases'][0]['error_code'], code)
                self.assertEqual(actual['cases'][0]['product_stage'], 'setup')
                self.assertEqual(actual['cases'][0]['teardown_status'], 'unconfirmed')
                self.assertIs(actual['cases'][0]['timed_out'], False);self.assertIs(actual['cases'][0]['recovery_required'], True)
                self.assertNotIn('NEVER_PUBLIC', json.dumps(actual));self.assertEqual(actual['status'], 'FAIL_OR_INCOMPLETE')


if __name__ == '__main__': unittest.main()
