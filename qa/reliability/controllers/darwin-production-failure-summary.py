"""Strict typed reduction of fixed production failure cases; no raw passthrough."""
import math

CASES = {'cancel', 'authority_death', 'controller_death', 'paused_storage_cancel',
         'paused_storage_controller_death', 'paused_storage_guardian_death',
         'double_storage_guardian_controller_death'}


def boolean(value):
    return value if type(value) is bool else None


def number(value):
    return value if type(value) in (int, float) and math.isfinite(value) and value >= 0 else None


def enum(value, allowed):
    return value if isinstance(value, str) and value in allowed else None


def reduce_case(item, codes):
    item = item if isinstance(item, dict) else {}
    name = item.get('name') if item.get('name') in CASES else 'unknown'
    terminal = item.get('terminal') if isinstance(item.get('terminal'), dict) else {}
    observation = item.get('observations') if isinstance(item.get('observations'), dict) else {}
    error = terminal.get('error') if isinstance(terminal.get('error'), dict) else {}
    recovery = observation.get('recovery_return') if isinstance(observation.get('recovery_return'), dict) else {}
    recovery_error = recovery.get('error') if isinstance(recovery.get('error'), dict) else {}
    recovery_result = recovery.get('result') if isinstance(recovery.get('result'), dict) else {}
    identity_probe = recovery.get('owner_identity_probe') if isinstance(recovery.get('owner_identity_probe'), dict) else {}
    query_diagnostic = identity_probe.get('query_diagnostic') if isinstance(identity_probe.get('query_diagnostic'), dict) else {}
    teardown = error.get('teardown') if isinstance(error.get('teardown'), dict) else {}
    inner_recovery = teardown.get('recovery') if isinstance(teardown.get('recovery'), dict) else {}
    row = {'name': name, 'status': 'FAIL_OR_INCOMPLETE',
           'elapsed_ms': number(item.get('elapsed_ms')),
           'caller_exit_code': item.get('controller_exit_code') if type(item.get('controller_exit_code')) is int else None,
           'error_code': error.get('code') if error.get('code') in codes else None,
           'external_recovery_ok': boolean(recovery.get('ok')),
           'external_recovery_error': enum(recovery_error.get('code'), codes),
           'owner_identity_probe_status': enum(identity_probe.get('status'), ('observed', 'unconfirmed')),
           'owner_identity_probe_code': enum(identity_probe.get('code'), codes),
           'owner_identity_query_phase': enum(query_diagnostic.get('phase'), ('source_read', 'protected_broker',
               'probe_transport', 'probe_decode', 'probe_validation', 'operation_transport', 'operation_decode', 'operation_validation')),
           'owner_identity_query_exception': enum(query_diagnostic.get('exception'), ('Error', 'TypeError', 'RangeError', 'SyntaxError')),
           'owner_identity_query_system_code': enum(query_diagnostic.get('system_code'), ('EACCES', 'EPERM', 'ENOENT',
               'ENOTDIR', 'EISDIR', 'ELOOP', 'EBADF', 'EIO', 'EMFILE', 'ENFILE', 'ENOMEM', 'EAGAIN', 'ETIMEDOUT', 'EPIPE',
               'ENOTSUP', 'ENOSYS', 'ERR_INVALID_ARG_TYPE', 'ERR_INVALID_ARG_VALUE', 'ERR_OUT_OF_RANGE', 'ERR_UNKNOWN_ENCODING', 'ERR_DLOPEN_FAILED')),
           'external_recovery_stage': enum(recovery.get('stage'), ('input', 'status', 'cancel', 'recover')),
           'external_recovery_status': enum(recovery_result.get('status'),
               ('failed', 'cancelled', 'already_terminal', 'requires_native_recovery', 'unconfirmed')),
           'caller_teardown_status': enum(teardown.get('status'), ('completed', 'unconfirmed', 'not_required')),
           'caller_recovery_status': enum(inner_recovery.get('status'),
               ('failed', 'cancelled', 'already_terminal', 'requires_native_recovery', 'unconfirmed')),
           'caller_recovery_error': enum(inner_recovery.get('code'), codes),
           'expected_terminal_outcome': 'cancelled' if name in ('cancel', 'paused_storage_cancel') else 'failed',
           'terminal_outcome': observation.get('terminal_outcome') if observation.get('terminal_outcome') in ('failed', 'cancelled') else None,
           'operator_assisted_storage_exit': boolean(observation.get('operator_assisted_storage_exit')),
           'storage_stop_delivered': boolean(observation.get('storage_stop_delivered')),
           'durable_cancel_observed': boolean(observation.get('durable_cancel_observed')),
           'live_storage_recovery_blocked': boolean(observation.get('live_storage_recovery_blocked')),
           'claim_retained_while_storage_live': boolean(observation.get('claim_retained_while_storage_live')),
           'live_storage_recovery_code': observation.get('live_storage_recovery_code') if observation.get('live_storage_recovery_code') == 'lock_timeout' else None,
           'live_storage_recovery_phase': enum(observation.get('live_storage_recovery_phase'), ('before_controller_death',)),
           'caller_returned_result': boolean(terminal.get('returned')),
           'acceptance_count': len(terminal['acceptances']) if isinstance(terminal.get('acceptances'), list) else None,
           'source_unchanged': boolean(terminal.get('source_unchanged'))}
    for key in ('execution_observed', 'initial_UID_members_at_least_three', 'actors_parent_birth_bound',
                'native_allocation_bound', 'caller_exit_observed', 'cleanup_confirmed', 'claim_released',
                'no_ACK_verified', 'original_source_unchanged', 'acceptance_released',
                'independent_storage_stop_confirmed', 'storage_guardian_stop_delivered', 'storage_guardian_kill_delivered',
                'controller_stop_delivered'):
        row[key] = boolean(observation.get(key))
    for key in ('UID_after_stop', 'UID_final'):
        value = observation.get(key) if isinstance(observation.get(key), dict) else {}
        row[key] = {'empty': boolean(value.get('empty')), 'elapsed_ms': number(value.get('elapsed_ms'))}
    for key in ('storage_exit', 'storage_guardian_exit', 'authority_exit', 'controller_exit'):
        value = observation.get(key) if isinstance(observation.get(key), dict) else {}
        row[key] = {'exact_birth_exit_confirmed': boolean(value.get('exact_birth_exit_confirmed')),
                    'state': value.get('state') if value.get('state') in ('absent', 'replaced') else None}
    valid = name in CASES and item.get('status') == 'PASS_PHYSICAL_PRODUCTION_FAILURE' and \
        row['elapsed_ms'] is not None and row['elapsed_ms'] < 330000 and row['caller_exit_code'] == 0 and \
        terminal.get('type') == 'observation' and terminal.get('case_name') == name and terminal.get('stage') == 'observed-outcome' and \
        row['caller_returned_result'] is False and terminal.get('result') is None and row['acceptance_count'] == 0 and \
        row['source_unchanged'] is True and row['error_code'] is not None and \
        observation.get('case') == name and observation.get('operation') == name and \
        row['terminal_outcome'] == row['expected_terminal_outcome'] and row['acceptance_released'] is False and \
        all(row[key] is True for key in ('execution_observed', 'initial_UID_members_at_least_three',
            'actors_parent_birth_bound', 'native_allocation_bound', 'caller_exit_observed', 'cleanup_confirmed',
            'claim_released', 'no_ACK_verified', 'original_source_unchanged')) and \
        all(row[key]['empty'] is True and row[key]['elapsed_ms'] is not None and row[key]['elapsed_ms'] < 60000
            for key in ('UID_after_stop', 'UID_final')) and \
        all(row[key]['exact_birth_exit_confirmed'] is True and row[key]['state'] in ('absent', 'replaced')
            for key in ('storage_exit', 'storage_guardian_exit', 'authority_exit', 'controller_exit'))
    if name in ('cancel', 'paused_storage_cancel'):
        valid = valid and row['durable_cancel_observed'] is True
    if name.startswith('paused_storage_') or name == 'double_storage_guardian_controller_death':
        valid = valid and row['storage_stop_delivered'] is True
    if name == 'double_storage_guardian_controller_death':
        valid = valid and row['operator_assisted_storage_exit'] is False and row['live_storage_recovery_blocked'] is True and \
            row['claim_retained_while_storage_live'] is True and row['live_storage_recovery_code'] == 'lock_timeout' and \
            row['live_storage_recovery_phase'] == 'before_controller_death' and row['controller_stop_delivered'] is True and \
            row['storage_guardian_stop_delivered'] is True and row['storage_guardian_kill_delivered'] is True and \
            row['independent_storage_stop_confirmed'] is True
    else:
        valid = valid and row['operator_assisted_storage_exit'] is False and row['independent_storage_stop_confirmed'] is True
    if name == 'paused_storage_guardian_death':
        valid = valid and row['storage_guardian_kill_delivered'] is True
    if valid:
        row['status'] = 'PASS_PHYSICAL_PRODUCTION_FAILURE'
    return row
