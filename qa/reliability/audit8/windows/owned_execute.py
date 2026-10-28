"""Use shipped Windows Job custody for an execute()-compatible QA step.

The external deadline is only an emergency bound. A normally responsive QA
controller spends its declared native cleanup allowance and returns kernel
Job/root/EOF/holder proof. An emergency controller kill stays UNCONFIRMED.
"""
import json, math, pathlib, secrets, shutil, subprocess, sys, tempfile, time

P = pathlib.Path
DRIVER = P(__file__).with_name('owned-command.cjs').resolve()


def make_execute(base, source_root, *, expected_arch, setup_s=30, cleanup_s=60, cancel_on_team_native_ready=None,
                 cancel_after_native_ready_ms=None):
    source_root = P(source_root).resolve(strict=True)
    assert sys.platform == 'win32', 'physical Windows is required'
    base.need(expected_arch in ('x64', 'arm64'), 'expected_arch_required')
    native_directory = source_root/'tools/lib/native'/('win32-'+expected_arch)
    native_manifest = base.strict_json((native_directory/'command-windows-job.manifest.json').read_text(encoding='utf8'))
    base.need(native_manifest.get('platform') == 'win32' and native_manifest.get('architecture') == expected_arch and
              native_manifest.get('source_sha256') == base.sha(source_root/'tools/native/command-windows-job.c') and
              native_manifest.get('binary_sha256') == base.sha(native_directory/'command-windows-job.node') and
              native_manifest.get('binary_bytes') == (native_directory/'command-windows-job.node').stat().st_size,
              'native_binary_source_binding')

    def execute(name, argv, cwd, out, deadline, timeout=90, fixture_tmp=None):
        before = time.monotonic(); out = P(out)
        stdout, stderr = out/(name+'.stdout.json'), out/(name+'.stderr.txt')
        receipt_path = out/(name+'.native-ownership.json')
        row = {'name': name, 'argv': argv, 'status': 'FAIL', 'timed_out': False,
               'supervision': 'shipped_native_windows_job', 'cleanup_confirmed': False}
        # Reserve setup and cleanup inside the same overall cohort endpoint.
        # Do not start a scope whose original allowance cannot be observed.
        allowance = min(float(timeout), deadline-before-setup_s-cleanup_s-5)
        if allowance <= 0:
            row.update(status='NOT_RUN_BUDGET_EXHAUSTED'); return row, None
        tmp = P(fixture_tmp if fixture_tmp is not None else tempfile.gettempdir()).resolve(strict=True)
        env = base.fixture_environment(tmp, out)
        # The trusted QA controller must not inherit a case-variant preload.
        denied = {'NODE_OPTIONS','NODE_PATH','NODE_CHANNEL_FD','NODE_CHANNEL_SERIALIZATION_MODE'}
        env = {k:v for k,v in env.items() if k.upper() not in denied and not k.upper().startswith('LD_')}
        executable = str(P(argv[0]).resolve()) if P(argv[0]).is_absolute() else shutil.which(argv[0])
        if not executable:
            row.update(status='FAIL_EXECUTABLE_NOT_FOUND'); return row, None
        command = [executable, *map(str, argv[1:])]
        request = {'nonce': secrets.token_hex(32), 'source_root': str(source_root), 'expected_arch': expected_arch, 'argv': command,
                   'cwd': str(P(cwd).resolve()), 'env': env, 'receipt': str(receipt_path.resolve()),
                   'work_ms': max(1, int(allowance*1000)), 'setup_ms': int(setup_s*1000),
                   'cleanup_ms': int(cleanup_s*1000), 'max_output_bytes': base.MAX_OUTPUT}
        if cancel_on_team_native_ready is not None: request['cancel_on_team_native_ready'] = cancel_on_team_native_ready
        if cancel_after_native_ready_ms is not None: request['cancel_after_native_ready_ms'] = cancel_after_native_ready_ms
        node = shutil.which('node'); base.need(bool(node), 'node_required')
        expires = min(deadline, before+allowance+setup_s+cleanup_s+5)
        print(json.dumps({'event': 'step_start', 'name': name, 'work_cap_s': round(allowance, 3),
                          'setup_cap_s': setup_s, 'cleanup_cap_s': cleanup_s, 'native_job_supervision': True}), flush=True)
        controller_timeout = False
        with stdout.open('wb') as a, stderr.open('wb') as b:
            child = subprocess.Popen([node, str(DRIVER)], cwd=cwd, env=env, stdin=subprocess.PIPE,
                                     stdout=a, stderr=b)
            try:
                child.communicate(json.dumps(request).encode('utf8'), timeout=max(.001, expires-time.monotonic()))
            except subprocess.TimeoutExpired:
                controller_timeout = True
                # This is the creator-owned controller handle, not a PID tree.
                # Its death triggers native backstops but is not closure proof.
                child.kill()
                try: child.wait(timeout=5)
                except subprocess.TimeoutExpired: pass
        row.update(controller_exit_code=child.returncode, elapsed_s=round(time.monotonic()-before, 3),
                   stdout_sha256=base.sha(stdout), stderr_sha256=base.sha(stderr),
                   stdout_bytes=stdout.stat().st_size, stderr_bytes=stderr.stat().st_size)
        if controller_timeout:
            row.update(status='TIMEOUT_CLEANUP_UNCONFIRMED', timed_out=True, controller_timeout=True)
            return row, None
        try:
            proof = base.strict_json(receipt_path.read_text(encoding='utf8'))
            base.need(child.returncode == 0 and proof['schema_version'] == 'knowledge-audit8-windows-owned-command.v1' and
                      proof['nonce'] == request['nonce'] and proof['argv'] == command and
                      proof['cwd'] == request['cwd'] and proof['platform'] == 'win32' and proof['arch'] == expected_arch, 'native_qa_receipt_binding')
            base.need(proof['budgets'] == {k: request[k] for k in ['work_ms', 'setup_ms', 'cleanup_ms']}, 'native_qa_budget_binding')
            for stream in ['stdout', 'stderr']:
                base.need(proof['streams'][stream] == {'bytes': row[stream+'_bytes'], 'sha256': row[stream+'_sha256']}, 'native_qa_output_binding')
            cleanup = proof['result']['cleanup']; scope = proof.get('scope')
            descriptor = (scope or {}).get('descriptor', {})
            base.need(type(proof['elapsed_ms']) in (int, float) and math.isfinite(proof['elapsed_ms']) and
                      0 <= proof['elapsed_ms'] <= sum(request[k] for k in ['work_ms', 'setup_ms', 'cleanup_ms'])+5000 and
                      time.monotonic() < deadline, 'native_qa_original_budget_exhausted')
            if scope:
                native = descriptor.get('native', {})
                base.need(scope.get('schema_version') == 'knowledge-command-scope.v1' and
                          descriptor.get('schema_version') == 'knowledge-windows-command-job.v2' and
                          native.get('architecture') == expected_arch and
                          native.get('source_sha256') == native_manifest['source_sha256'] and
                          native.get('binary_sha256') == native_manifest['binary_sha256'], 'native_qa_scope_source_binding')
            closed = isinstance(scope, dict) and scope.get('backend') == 'windows_job_object' and \
                cleanup.get('status') == 'completed' and cleanup.get('method') == 'windows_job_object' and \
                cleanup.get('active_processes') == 0 and cleanup.get('root_exited') is True and \
                cleanup.get('output_closed') is True and cleanup.get('primary_holder_exited') is True and \
                cleanup.get('secondary_holder_exited') is True and \
                cleanup.get('artifact_cleanup', {}).get('status') == 'completed' and \
                type(cleanup.get('cleanup_duration_ms')) in (int, float) and \
                math.isfinite(cleanup['cleanup_duration_ms']) and 0 <= cleanup['cleanup_duration_ms'] <= request['cleanup_ms']
            row.update(native_receipt_sha256=base.sha(receipt_path), cleanup=cleanup, cleanup_confirmed=closed,
                       exit_code=proof['result']['status'], native_error=proof['result'].get('error'),
                       cancellation=proof.get('cancellation'), scope_id=(scope or {}).get('descriptor', {}).get('scope_id'))
            error_code = (proof['result'].get('error') or {}).get('code')
            row['timed_out'] = error_code in ('command_work_timeout', 'command_setup_timeout', 'command_progress_timeout')
            row['output_limit_exceeded'] = error_code == 'command_output_limit'
            if not closed:
                row['status'] = 'NATIVE_CLEANUP_UNCONFIRMED'
            elif error_code:
                row['status'] = ('TIMEOUT' if row['timed_out'] else 'OUTPUT_LIMIT' if row['output_limit_exceeded'] else
                                 'CANCELLED' if error_code == 'command_cancelled' else 'FAIL') + '_CLEANUP_CONFIRMED'
            else:
                row['status'] = 'PASS_PROCESS' if proof['result']['status'] == 0 and not proof['result']['signal'] else 'FAIL_PROCESS'
        except (OSError, ValueError, KeyError, TypeError, RuntimeError) as error:
            row.update(status='FAIL_NATIVE_QA_RECEIPT', error=str(error), cleanup_confirmed=False)
        value = None
        try: value = base.strict_json(stdout.read_text(encoding='utf8'))
        except (ValueError, UnicodeError): pass
        print(json.dumps({'event': 'step_exit', 'name': name, 'status': row['status'], 'elapsed_s': row['elapsed_s'],
                          'cleanup_confirmed': row['cleanup_confirmed']}), flush=True)
        return row, value
    return execute
