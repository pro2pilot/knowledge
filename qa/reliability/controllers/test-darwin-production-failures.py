#!/usr/bin/env python3
"""Reducer fixtures only; never stand in for the native cases they assess."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

path = Path(__file__).with_name('darwin-production-failure-summary.py')
spec = importlib.util.spec_from_file_location('failure_public_summary', path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
CODES = {'verification_cancelled', 'verification_darwin_transport_failed', 'verification_darwin_child_exited'}


def fixture(name):
    observation = {key: True for key in ('execution_observed', 'initial_UID_members_at_least_three',
        'actors_parent_birth_bound', 'native_allocation_bound', 'caller_exit_observed', 'cleanup_confirmed',
        'claim_released', 'no_ACK_verified', 'original_source_unchanged')}
    observation.update(case=name, operation=name, acceptance_released=False,
                       operator_assisted_storage_exit=False,
                       independent_storage_stop_confirmed=True,
                       terminal_outcome='cancelled' if name in ('cancel', 'paused_storage_cancel') else 'failed')
    for key in ('UID_after_stop', 'UID_final'):
        observation[key] = {'empty': True, 'elapsed_ms': 100}
    for key in ('storage_exit', 'storage_guardian_exit', 'authority_exit', 'controller_exit'):
        observation[key] = {'exact_birth_exit_confirmed': True, 'state': 'absent'}
    if name in ('cancel', 'paused_storage_cancel'):
        observation['durable_cancel_observed'] = True
    if name.startswith('paused_storage_') or name == 'double_storage_guardian_controller_death':
        observation['storage_stop_delivered'] = True
    if name == 'double_storage_guardian_controller_death':
        observation.update(storage_guardian_stop_delivered=True, storage_guardian_kill_delivered=True,
                           live_storage_recovery_blocked=True, claim_retained_while_storage_live=True,
                           live_storage_recovery_code='lock_timeout', live_storage_recovery_phase='before_controller_death',
                           controller_stop_delivered=True)
    if name == 'paused_storage_guardian_death':
        observation['storage_guardian_kill_delivered'] = True
    terminal = {'type': 'observation', 'case_name': name, 'stage': 'observed-outcome', 'returned': False,
                'result': None, 'acceptances': [], 'source_unchanged': True,
                'error': {'code': 'verification_cancelled' if name in ('cancel', 'paused_storage_cancel')
                          else 'verification_darwin_transport_failed'}}
    return {'name': name, 'status': 'PASS_PHYSICAL_PRODUCTION_FAILURE', 'elapsed_ms': 1500,
            'controller_exit_code': 0, 'terminal': terminal, 'observations': observation}


class Cases(unittest.TestCase):
    def test_all_exact_fixed_cases(self):
        for name in sorted(module.CASES):
            with self.subTest(name=name):
                self.assertEqual(module.reduce_case(fixture(name), CODES)['status'], 'PASS_PHYSICAL_PRODUCTION_FAILURE')

    def test_incomplete_and_unobserved_results_never_pass(self):
        changes = (
            lambda x: x.update(status='FAIL'),
            lambda x: x.update(controller_exit_code=1),
            lambda x: x.update(elapsed_ms=330000),
            lambda x: x['terminal'].update(returned=True),
            lambda x: x['terminal'].update(result=[{'record': {'status': 'pass'}}]),
            lambda x: x['terminal'].update(acceptances=[{'signature': 'not-an-ACK'}]),
            lambda x: x['terminal'].update(stage='input'),
            lambda x: x['terminal'].update(case_name='another_case'),
            lambda x: x['terminal'].update(source_unchanged=False),
            lambda x: x['terminal']['error'].update(code='ERR_ASSERTION'),
            lambda x: x['observations'].update(actors_parent_birth_bound=False),
            lambda x: x['observations'].update(native_allocation_bound=False),
            lambda x: x['observations'].update(no_ACK_verified='true'),
            lambda x: x['observations'].update(claim_released=False),
            lambda x: x['observations'].update(cleanup_confirmed=False),
            lambda x: x['observations'].update(acceptance_released=True),
            lambda x: x['observations'].update(terminal_outcome='passed'),
            lambda x: x['observations'].update(durable_cancel_observed=False),
            lambda x: x['observations']['UID_after_stop'].update(empty=False),
            lambda x: x['observations']['UID_after_stop'].update(elapsed_ms=60000),
            lambda x: x['observations']['UID_final'].update(elapsed_ms=float('nan')),
            lambda x: x['observations']['storage_exit'].update(state='same_running'),
            lambda x: x['observations']['authority_exit'].update(state='same_zombie'),
            lambda x: x['observations']['storage_guardian_exit'].update(exact_birth_exit_confirmed=False),
            lambda x: x['observations'].update(independent_storage_stop_confirmed=False),
            lambda x: x['observations']['controller_exit'].update(exact_birth_exit_confirmed=False),
        )
        for index, change in enumerate(changes):
            with self.subTest(index=index):
                value = fixture('cancel')
                change(value)
                self.assertEqual(module.reduce_case(value, CODES)['status'], 'FAIL_OR_INCOMPLETE')

    def test_live_writer_fence_then_independent_root_cleanup_no_manual_rescue(self):
        for key, bad in (('storage_stop_delivered', False), ('live_storage_recovery_blocked', False),
                         ('claim_retained_while_storage_live', False), ('live_storage_recovery_code', 'unrelated_error'),
                         ('operator_assisted_storage_exit', True), ('controller_stop_delivered', False),
                         ('live_storage_recovery_phase', 'after_controller_death'),
                         ('independent_storage_stop_confirmed', False)):
            with self.subTest(key=key):
                value = fixture('double_storage_guardian_controller_death')
                value['observations'][key] = bad
                self.assertEqual(module.reduce_case(value, CODES)['status'], 'FAIL_OR_INCOMPLETE')

    def test_raw_proofs_tokens_paths_and_payload_are_not_forwarded(self):
        value = fixture('controller_death')
        secret = 'private-payload-should-never-leave-controller'
        value['terminal']['error'].update(message=secret, stack=secret, token=secret, native_return={'path': secret})
        value['observations'].update(actors={'birth': secret}, private_path=secret, raw_receipt=secret)
        output = module.reduce_case(value, CODES)
        self.assertNotIn(secret, json.dumps(output))
        self.assertEqual(output['status'], 'PASS_PHYSICAL_PRODUCTION_FAILURE')

    def test_recovery_diagnostics_are_enum_only_and_do_not_change_acceptance(self):
        for code in ('verification_cancelled', 'private-token-path-message', {'secret': 'private-token-path-message'}, None):
            with self.subTest(code=code):
                value = fixture('cancel');value['status'] = 'FAIL'
                value['observations']['recovery_return'] = {'ok': False, 'stage': 'recover',
                    'owner_identity_probe': {'status': 'unconfirmed', 'code': code, 'observation': {'token': 'private-token-path-message'}},
                    'error': {'code': code, 'message': 'private-token-path-message', 'native_proof': {'token': 'private-token-path-message'}}}
                value['terminal']['error']['teardown'] = {'status': 'unconfirmed', 'recovery': {'status': 'unconfirmed', 'code': code}}
                output = module.reduce_case(value, CODES)
                self.assertEqual(output['status'], 'FAIL_OR_INCOMPLETE')
                self.assertEqual(output['external_recovery_stage'], 'recover')
                self.assertEqual(output['caller_teardown_status'], 'unconfirmed')
                self.assertEqual(output['external_recovery_error'], code if code == 'verification_cancelled' else None)
                self.assertEqual(output['caller_recovery_error'], code if code == 'verification_cancelled' else None)
                self.assertEqual(output['owner_identity_probe_status'], 'unconfirmed')
                self.assertEqual(output['owner_identity_probe_code'], code if code == 'verification_cancelled' else None)
                self.assertNotIn('private-token-path-message', json.dumps(output))

    def test_query_stage_diagnostics_are_closed_enums_only(self):
        good = {'phase': 'operation_decode', 'exception': 'SyntaxError', 'system_code': 'EACCES'}
        for diagnostic in (good, {key: 'NEVER_PUBLIC_secret' for key in good}, None, 'NEVER_PUBLIC_secret'):
            value = fixture('cancel');value['status'] = 'FAIL'
            value['observations']['recovery_return'] = {'owner_identity_probe': {'query_diagnostic': diagnostic}}
            output = module.reduce_case(value, CODES)
            self.assertEqual(output['status'], 'FAIL_OR_INCOMPLETE')
            for key, expected in (('phase', 'operation_decode'), ('exception', 'SyntaxError'), ('system_code', 'EACCES')):
                self.assertEqual(output['owner_identity_query_'+key], expected if diagnostic == good else None)
            self.assertNotIn('NEVER_PUBLIC', json.dumps(output))


if __name__ == '__main__':
    unittest.main()
