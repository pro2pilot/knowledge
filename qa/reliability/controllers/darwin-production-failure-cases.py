#!/usr/bin/env python3
"""Additional disposable native cases, invoked by the source-pinned runner.

No PID is chosen by a process-name search. The initiating storage process and
registered native actors are captured while alive, with their exact parent
birth and image. A PID-version-bound native helper sends each test signal.
"""
import json
import os
from pathlib import Path
import signal
import subprocess
import time

CASES = ('cancel', 'authority_death', 'controller_death', 'paused_storage_cancel',
         'paused_storage_controller_death', 'paused_storage_guardian_death',
         'double_storage_guardian_controller_death')


def compile_helpers(runner, base, directory):
    result = {}
    for name, filename in (('process_observer', 'darwin-production-process-observer.c'),
                           ('signal', 'darwin-test-signal.c')):
        source = directory / filename
        output = runner.evidence / ('production-' + name.replace('_', '-'))
        command = ['/usr/bin/clang', '-std=c11', '-O2', '-D_DARWIN_C_SOURCE',
                   '-Wall', '-Wextra', '-Werror', str(source), '-o', str(output)]
        observed = runner.run('compile-production-' + name.replace('_', '-'), command, timeout=60)
        runner.check(observed.returncode == 0, 'production_failure_helper_compile_failed')
        result[name] = output
        result[name + '_pin'] = {'source_sha256': base.sha_file(source), 'binary_sha256': base.sha_file(output)}
    return result


def run_case(runner, base, info, directory, helpers, name):
    runner.check(name in CASES, 'production_failure_case_invalid')
    project = runner.evidence / ('project-' + name)
    project.mkdir(mode=0o700)
    caller = directory / 'darwin-production-failure-caller.js'
    controls = directory / 'darwin-production-control.js'
    started = time.monotonic()
    deadline = started + 330
    caller_out = runner.evidence / (name + '.caller.stdout.raw')
    caller_err = runner.evidence / (name + '.caller.stderr.raw')
    runner.public_started = True
    runner.public_completed = False
    observations = {'case': name, 'operation': name, 'operator_assisted_storage_exit': False,
                    'acceptance_released': False}
    actor_births = {}
    process = None
    source_bytes = None
    row = {'name': name, 'status': 'FAIL', 'terminal': None, 'observations': observations}
    runner.case_results.append(row)

    def remaining(maximum):
        left = deadline - time.monotonic()
        runner.check(left > 0, 'production_failure_case_deadline')
        return min(maximum, left)

    def parse(result):
        runner.check(result.returncode is not None, 'production_failure_helper_timeout_preserve_fixture')
        try:
            lines = result.stdout.splitlines()
            runner.check(len(lines) == 1, 'production_failure_helper_protocol')
            value = json.loads(lines[0])
        except (ValueError, TypeError, IndexError):
            raise base.QAError('production_failure_helper_protocol')
        runner.check(isinstance(value, dict), 'production_failure_helper_protocol')
        return value

    def control(op, binding=None, budget_ms=None):
        body = {'source': str(runner.runtime_copy), 'project': str(project), 'op': op}
        if binding:
            body.update(attempt_id=binding['attempt_id'], generation=binding['generation'])
        if budget_ms is not None:
            body['budget_ms'] = budget_ms
        result = runner.run('production-failure-' + op, [str(info['node']), str(controls)],
                            data=base.canonical(body), timeout=remaining((budget_ms or 5000) / 1000 + 10))
        value = parse(result)
        runner.check(value.get('type') == 'control' and type(value.get('ok')) is bool,
                     'production_failure_helper_protocol')
        runner.check(result.returncode == (0 if value['ok'] else 1),
                     'production_failure_helper_exit_mismatch')
        if op == 'recover':
            # Kept in runner-private evidence. The public reducer extracts
            # only fixed error/status enums; no descriptor or proof escapes.
            observations['recovery_return'] = value
        return value

    def process_birth(pid, parent=None, image=None):
        image = str(image or info['node'])
        observed = runner.sudo(str(helpers['process_observer']), str(pid),
                               name='production-failure-capture-parent', timeout=remaining(10))
        value = parse(observed)
        runner.check(observed.returncode == 0 and value.get('schema') == 'knowledge-darwin-qa-process-parent.v1'
                     and value.get('pid') == pid and value.get('ruid') == os.getuid()
                     and value.get('image') == image, 'production_failure_actor_binding')
        if parent:
            runner.check(value.get('parent_pid') == parent['pid']
                         and str(value.get('parent_unique_id')) == str(parent['unique_id']),
                         'production_failure_actor_parent_binding')
        return value

    def send(identity, sig):
        # The helper rechecks all fields and binds the kernel operation to
        # pidversion. The separate capture is not used as a PID-only permit.
        runner.check(identity.get('image') in (str(info['node']), str(info['binary'])), 'production_failure_actor_binding')
        runner.capture_birth(identity, os.getuid(), identity['image'])
        sent = runner.root('production-failure-signal-exact', str(helpers['signal']), str(identity['pid']),
                           str(identity['unique_id']), str(identity['start_sec']), str(identity['start_usec']),
                           str(os.getuid()), str(sig), identity['image'], timeout=remaining(10))
        value = parse(sent)
        runner.check(sent.returncode == 0 and value.get('exact_birth_checked') is True and value.get('signal') == sig
                     and value.get('native_result') == 0, 'production_failure_signal_unconfirmed')

    def uid_members(uid):
        result = runner.sudo(str(runner.uid_scan), str(uid), name='production-failure-uid-observation',
                             timeout=remaining(10))
        value = parse(result)
        runner.check(result.returncode in (0, 1) and value.get('observation_valid') is True
                     and type(value.get('member_count')) is int, 'production_failure_UID_unconfirmed')
        return value['member_count']

    def wait_uid_zero(uid, maximum=60):
        begin = time.monotonic()
        stop = begin + remaining(maximum)
        while time.monotonic() < stop:
            count = uid_members(uid)
            runner.check(time.monotonic() < stop, 'production_failure_UID_cleanup_deadline')
            if count == 0:
                return {'empty': True, 'elapsed_ms': (time.monotonic() - begin) * 1000}
            time.sleep(.1)
        raise base.QAError('production_failure_UID_cleanup_deadline')

    def wait_gone(identity, maximum=60):
        stop = time.monotonic() + remaining(maximum)
        while time.monotonic() < stop:
            value = runner.compare_birth(identity)
            runner.check(time.monotonic() < stop, 'production_failure_actor_exit_unconfirmed')
            if value.get('state') in ('absent', 'replaced'):
                return {'exact_birth_exit_confirmed': True, 'state': value['state']}
            time.sleep(.1)
        raise base.QAError('production_failure_actor_exit_unconfirmed')

    try:
        request = {'source': str(runner.runtime_copy), 'project': str(project), 'case_name': name,
                   'config': {key: str(info[key]) for key in ('binary', 'socket')}}
        with caller_out.open('wb') as output, caller_err.open('wb') as error:
            process = subprocess.Popen([str(info['node']), str(caller)], stdin=subprocess.PIPE,
                                       stdout=output, stderr=error)
            runner.active_monitor = process
            process.stdin.write(base.canonical(request))
            process.stdin.close()
            actor_births['caller'] = process_birth(process.pid)
            # Actual execution readiness, not elapsed time or arbitrary output.
            ready_until = time.monotonic() + remaining(120)
            current = entry = None
            while time.monotonic() < ready_until:
                runner.check(process.poll() is None, 'production_failure_caller_exited_before_action')
                status = control('status')
                current = status.get('status', {}).get('attempt') if status.get('ok') else None
                if current and current.get('phase') == 'running' and current.get('claimed') is True:
                    descriptor = (current.get('containment') or {}).get('descriptor') or {}
                    binding = (descriptor.get('scope') or {}).get('binding') or {}
                    native_id = binding.get('attempt_id')
                    registry = runner.fixture_registry_snapshot()
                    entry = (registry or {}).get('attempts', {}).get(native_id)
                    if entry and entry.get('command_identity'):
                        uid = entry['descriptor']['task_ruid']
                        if uid_members(uid) >= 3:
                            break
                time.sleep(.2)
            runner.check(current and entry and entry.get('command_identity') and uid_members(uid) >= 3,
                         'production_failure_execution_not_observed')
            source_bytes = (project / 'run.js').read_bytes()
            runner.task_uids.add(uid)
            runner.expected_allocation_ids.add(native_id)
            actor_births['controller'] = process_birth(entry['controller']['pid'], actor_births['caller'])
            actor_births['storage'] = process_birth(current['initiator']['pid'])
            actor_births['storage_guardian'] = process_birth(actor_births['storage']['parent_pid'], actor_births['controller'], info['binary'])
            runner.check(str(actor_births['storage']['parent_unique_id']) == str(actor_births['storage_guardian']['unique_id']),
                         'production_failure_actor_parent_binding')
            actor_births['authority'] = process_birth(entry['authority']['pid'], actor_births['controller'])
            for role in ('controller', 'authority'):
                runner.check(all(str(actor_births[role][key]) == str(entry[role][key])
                                 for key in ('pid', 'unique_id', 'start_sec', 'start_usec')),
                             'production_failure_registry_actor_mismatch')
            observations.update(execution_observed=True, initial_UID_members_at_least_three=True,
                                actors_parent_birth_bound=True, native_allocation_bound=True)
            base.private_file(runner.evidence / (name + '.actors.private.json'), base.canonical(actor_births))

            paused = name.startswith('paused_storage_') or name == 'double_storage_guardian_controller_death'
            if name == 'double_storage_guardian_controller_death':
                send(actor_births['storage_guardian'], signal.SIGSTOP)
                observations['storage_guardian_stop_delivered'] = True
            if paused:
                send(actor_births['storage'], signal.SIGSTOP)
                # A running status after SIGSTOP is not a proof of pause. The
                # signal helper confirms that this exact birth received STOP;
                # the experiment records paused scheduling, not kernel I/O.
                observations['storage_stop_delivered'] = True
            if name == 'double_storage_guardian_controller_death':
                # Before either independent ordinary-UID enforcer is killed,
                # a live paused writer must retain its shared-state claim.
                # Once M and G die below, the independent root custody must
                # terminate S automatically; operator rescue is never a pass.
                alive = runner.compare_birth(actor_births['storage'])
                runner.check(alive.get('state') == 'same_running', 'production_failure_paused_writer_missing')
                blocked = control('recover', current, 2000)
                runner.check(blocked.get('ok') is False and blocked.get('stage') == 'recover'
                             and blocked.get('error', {}).get('code') == 'lock_timeout',
                             'production_failure_live_writer_reclaimed')
                retained = control('status')
                attempt = retained.get('status', {}).get('attempt') or {}
                runner.check(retained.get('ok') is True and attempt.get('attempt_id') == current['attempt_id']
                             and attempt.get('generation') == current['generation'] and attempt.get('claimed') is True
                             and attempt.get('terminal') is None, 'production_failure_live_writer_claim_lost')
                observations.update(live_storage_recovery_blocked=True, claim_retained_while_storage_live=True,
                                    live_storage_recovery_code='lock_timeout',
                                    live_storage_recovery_phase='before_controller_death')
            if name in ('cancel', 'paused_storage_cancel'):
                answer = control('cancel', current)
                runner.check(answer.get('ok') is True and answer.get('status', {}).get('attempt', {}).get('cancel', {}).get('requested') is True,
                             'production_failure_cancel_not_durable')
                observations['durable_cancel_observed'] = True
            elif name == 'authority_death':
                send(actor_births['authority'], signal.SIGKILL)
            elif name == 'paused_storage_guardian_death':
                send(actor_births['storage_guardian'], signal.SIGKILL)
                observations['storage_guardian_kill_delivered'] = True
            else:
                if name == 'double_storage_guardian_controller_death':
                    # Freeze M before removing G so M cannot rescue S between
                    # the two exact-birth kills. Root custody may kill G/S as
                    # soon as M dies, so kill G first while M is stopped.
                    send(actor_births['controller'], signal.SIGSTOP)
                    observations['controller_stop_delivered'] = True
                    send(actor_births['storage_guardian'], signal.SIGKILL)
                    observations['storage_guardian_kill_delivered'] = True
                send(actor_births['controller'], signal.SIGKILL)
            observations['UID_after_stop'] = wait_uid_zero(uid)

            observations['storage_exit'] = wait_gone(actor_births['storage'])
            observations['storage_guardian_exit'] = wait_gone(actor_births['storage_guardian'])
            observations['independent_storage_stop_confirmed'] = True
            observations['authority_exit'] = wait_gone(actor_births['authority'])
            process.wait(timeout=remaining(75))
            observations['caller_exit_observed'] = True
            row['controller_exit_code'] = process.returncode
            runner.check(process.returncode == 0, 'production_failure_caller_exit_invalid')
            # All public writers observed by this controller must exit before
            # independent recovery. For alive M, the caller result follows M's
            # actual exit. For killed M, use the same bound kernel observation.
            observations['controller_exit'] = wait_gone(actor_births['controller'])
            runner.check(caller_out.stat().st_size <= 4 * 1024 * 1024 and caller_err.stat().st_size <= 4 * 1024 * 1024,
                         'production_failure_caller_output_oversized')
            events = []
            for line in caller_out.read_bytes().splitlines():
                try:
                    value = json.loads(line)
                except ValueError:
                    raise base.QAError('production_failure_caller_protocol')
                runner.check(isinstance(value, dict), 'production_failure_caller_protocol')
                events.append(value)
            terminal = [event for event in events if event.get('type') == 'observation']
            runner.check(len(events) == 2 and events[0].get('type') == 'started' and len(terminal) == 1,
                         'production_failure_caller_protocol')
            terminal = terminal[0]
            row['terminal'] = terminal
            runner.check(terminal.get('case_name') == name and terminal.get('returned') is False
                         and terminal.get('result') is None and terminal.get('acceptances') == []
                         and isinstance(terminal.get('error'), dict) and terminal.get('source_unchanged') is True,
                         'production_failure_unexpected_acceptance')
            status = control('status')
            attempt = status.get('status', {}).get('attempt') or {}
            runner.check(status.get('ok') is True and attempt.get('attempt_id') == current['attempt_id']
                         and attempt.get('generation') == current['generation'], 'production_failure_attempt_replaced')
            if attempt.get('claimed') is True:
                recovered = control('recover', current, min(60000, max(1, int(remaining(60) * 1000))))
                runner.check(recovered.get('ok') is True, 'production_failure_recovery_failed')
                attempt = recovered.get('status', {}).get('attempt') or {}
            expected_outcome = 'cancelled' if name in ('cancel', 'paused_storage_cancel') else 'failed'
            runner.check(attempt.get('attempt_id') == current['attempt_id'] and attempt.get('generation') == current['generation']
                         and attempt.get('claimed') is False and attempt.get('cleanup', {}).get('status') == 'confirmed'
                         and attempt.get('terminal', {}).get('outcome') == expected_outcome
                         and attempt.get('terminal', {}).get('ack_sha256') is None,
                         'production_failure_terminal_not_confirmed')
            observations.update(terminal_outcome=expected_outcome, cleanup_confirmed=True, claim_released=True,
                                no_ACK_verified=True, UID_final=wait_uid_zero(uid),
                                original_source_unchanged=(project / 'run.js').read_bytes() == source_bytes)
            runner.check(observations['original_source_unchanged'], 'production_failure_project_mutated')
            row['status'] = 'PASS_PHYSICAL_PRODUCTION_FAILURE'
            runner.public_completed = True
    finally:
        if process is not None and process.poll() is None:
            # Only the exact direct child handle is used here. Its exit alone
            # never sets public_completed or authorizes fixture removal.
            process.kill()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                observations['caller_exit_unconfirmed'] = True
        row.update(elapsed_ms=(time.monotonic() - started) * 1000,
                   stdout_sha256=base.sha_file(caller_out) if caller_out.is_file() else None,
                   stderr_sha256=base.sha_file(caller_err) if caller_err.is_file() else None)
        base.private_file(runner.evidence / (name + '.observations.private.json'), base.canonical(observations))
