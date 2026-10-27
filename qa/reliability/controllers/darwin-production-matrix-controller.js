#!/usr/bin/env node
'use strict';

// Fixed additional physical public-path cases. Raw results are private to the
// disposable runner. The normal early gate remains its own unchanged caller.
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { workloads } = require('./darwin-production-workloads');
let bytes = 0; const chunks = [];
process.stdin.on('data', chunk => {
  bytes += chunk.length;
  if (bytes > 1024 * 1024) process.exit(2);
  chunks.push(chunk);
});
process.stdin.once('end', () => {
  let stage = 'input';
  let commandError;
  try {
    assert.equal(process.platform, 'darwin');
    const input = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    assert.ok(path.isAbsolute(input.source) && path.isAbsolute(input.project));
    assert.ok(Object.hasOwn(workloads, input.case_name));
    const workload = workloads[input.case_name];
    const lib = path.join(input.source, 'tools', 'lib');
    const supervisor = require(path.join(lib, 'verification-supervisor'));
    const finalization = require(path.join(lib, 'verification-finalization'));
    const control = require(path.join(lib, 'verification-control'));
    const execution = require(path.join(lib, 'verification-execution'));
    const stateRoot = path.join(input.project, '.knowledge');
    fs.mkdirSync(stateRoot, { mode: 0o700 });
    const script = path.join(input.project, 'run.js');
    fs.writeFileSync(script, workload.source, { flag: 'wx', mode: 0o600 });
    const before = fs.readFileSync(script);
    const digest = value => crypto.createHash('sha256').update(value).digest('hex');
    const request = {
      stateRoot, repoRoot: input.project, taskId: 'native-qa-' + input.case_name,
      sessionId: 'native-qa', checkedBy: 'native-qa', sourceFiles: ['run.js'],
      tests: [{ argv: ['node', 'run.js'], cwd: '.', timeout_ms: workload.test_timeout_ms }],
      verificationPolicy: { work_budget_ms: 240000, no_progress_ms: workload.no_progress_ms, cleanup_budget_ms: 60000 },
      nativeExecution: { darwin: { enabled: true, mode: 'isolated_copy',
        broker_path: input.config.binary, broker_socket: input.config.socket, copy: {} } },
    };
    process.stdout.write(JSON.stringify({ type: 'started', case_name: input.case_name, pid: process.pid }) + '\n');
    stage = 'public-run';
    const started = process.hrtime.bigint();
    let result;
    try { result = supervisor.runSupervised(request, 240000); }
    catch (error) { if (input.case_name !== 'exit7') throw error;commandError = error; }
    const elapsed = Number(process.hrtime.bigint() - started) / 1e6;
    stage = 'finalization-reader';
    if (input.case_name === 'exit7') {
      stage = 'failed-command-contract';
      assert.equal(result, undefined);
      assert.equal(commandError?.code, 'verification_command_failed');
      assert.equal(commandError.command_failure?.status, 'fail');
      assert.equal(commandError.command_failure?.exit_code, 7);
      assert.equal(commandError.command_failure?.signal, null);
      stage = 'failed-cleanup-contract';
      assert.equal(commandError.teardown?.status, 'completed');
      assert.equal(commandError.recovery_required, false);
      assert.equal(commandError.timed_out, false);
      stage = 'failed-KVE-reader';
      const id = commandError.command_failure.execution_id;
      const loaded = execution.readExecutionRecord(stateRoot, id);
      assert.ok(loaded, 'the failed KVE must exist physically and validate');
      const observation = execution.validateExecutionObservation(loaded.record);
      assert.equal(observation.ok, true);assert.equal(observation.digest, loaded.expected_digest);
      assert.equal(loaded.record.schema_version, 'knowledge-verification-execution-observation.v1');
      assert.equal(execution.loadExecutionRecord(stateRoot, id), null, 'failed observations cannot satisfy the acceptance reader');
      assert.equal(loaded.record.execution_id, id);
      assert.equal(loaded.record.task_id, request.taskId);
      assert.equal(loaded.record.session_id, request.sessionId);
      assert.deepEqual(loaded.record.command_argv, ['node', 'run.js']);
      assert.equal(loaded.record.status, 'fail');assert.equal(loaded.record.exit_code, 7);
      assert.equal(loaded.record.signal, null);assert.equal(loaded.record.timed_out, false);
      assert.throws(() => finalization.requireFinalizedExecutions(stateRoot, [id], []),
        { code: 'verification_finalization_required' });
      stage = 'failed-control-release';
      const failedStatus = control.readStatus({ stateRoot, repoRoot: input.project });
      assert.equal(failedStatus.attempt.claimed, false);
      assert.equal(failedStatus.attempt.cleanup.status, 'confirmed');
      assert.equal(failedStatus.attempt.terminal.outcome, 'failed');
      assert.equal(failedStatus.attempt.terminal.ack_sha256, null);
      assert.equal(digest(fs.readFileSync(script)), digest(before));
      // The independent next request must work after the failed batch is
      // physically closed. It gets its own attempt, KVE, KVF and ACK.
      stage = 'retry';
      fs.writeFileSync(path.join(input.project, 'retry.js'), "'use strict';\nconsole.log('after-failed-execution');\n",
        { flag: 'wx', mode: 0o600 });
      const retryRequest = { ...request, taskId: 'native-qa-after-exit7', sourceFiles: ['retry.js'],
        tests: [{ argv: ['node', 'retry.js'], cwd: '.', timeout_ms: 180000 }] };
      const retry = supervisor.runSupervised(retryRequest, 240000);
      assert.equal(retry.length, 1);assert.equal(retry[0].record.status, 'pass');
      assert.equal(retry[0].record.exit_code, 0);assert.notEqual(retry[0].record.execution_id, id);
      assert.equal(retry.verification_acceptances.length, 1);
      const retryFinalized = finalization.requireFinalizedExecutions(stateRoot,
        [retry[0].record.execution_id], retry.verification_acceptances);
      assert.equal(retryFinalized.status, 'accepted');
      const retryStatus = control.readStatus({ stateRoot, repoRoot: input.project });
      assert.equal(retryStatus.attempt.claimed, false);
      assert.equal(retryStatus.attempt.cleanup.status, 'confirmed');
      assert.equal(retryStatus.attempt.terminal.outcome, 'passed');
      assert.notEqual(retryStatus.attempt.attempt_id, failedStatus.attempt.attempt_id);
      assert.equal(digest(fs.readFileSync(script)), digest(before));
      stage = 'complete';
      process.stdout.write(JSON.stringify({ type: 'result', success: true, stage,
        case_name: input.case_name, expected_exit: 7, observed_elapsed_ms: elapsed,
        result: [{ record: loaded.record }], acceptances: [], finalized: { status: 'not_accepted' },
        error_code: commandError.code, error: { ...commandError },
        failed_KVE_verified: true, failed_attempt_no_ACK: true, failed_cleanup_confirmed: true,
        retry_accepted: true, retry_distinct_attempt: true, source_unchanged: true,
        failed_status: failedStatus, retry_status: retryStatus }) + '\n');
      return;
    }
    assert.equal(result.length, 1);
    assert.equal(result[0].record.status, workload.expected_exit === 0 ? 'pass' : 'fail');
    assert.equal(result[0].record.exit_code, workload.expected_exit);
    const ids = result.map(row => row.record.execution_id);
    assert.equal(result.verification_acceptances.length, 1);
    const finalized = finalization.requireFinalizedExecutions(stateRoot, ids, result.verification_acceptances);
    assert.equal(finalized.status, 'accepted');
    const status = control.readStatus({ stateRoot, repoRoot: input.project });
    assert.equal(status.attempt.claimed, false);
    assert.equal(status.attempt.cleanup.status, 'confirmed');
    assert.equal(digest(fs.readFileSync(script)), digest(before));
    if (input.case_name === 'silent_long') {
      assert.ok(elapsed >= 125000, 'the real silent interval must actually run');
      assert.equal(result.verification_budget.no_progress_ms, 500);
      assert.deepEqual(result.verification_budget.progress_monitored_operations, ['native_copy_chunk']);
    }
    stage = 'complete';
    process.stdout.write(JSON.stringify({ type: 'result', success: true, stage,
      case_name: input.case_name, expected_exit: workload.expected_exit, observed_elapsed_ms: elapsed,
      result, acceptances: result.verification_acceptances, budget: result.verification_budget,
      finalized, status, source_unchanged: true }) + '\n');
  } catch (error) {
    process.stdout.write(JSON.stringify({ type: 'result', success: false, stage,
      error_code: typeof error.code === 'string' ? error.code : 'controller_assertion_failed',
      failed_command_observation: commandError ? { code: commandError.code,
        teardown_status: commandError.teardown?.status, recovery_required: commandError.recovery_required,
        timed_out: commandError.timed_out, failure_status: commandError.command_failure?.status,
        failure_exit_code: commandError.command_failure?.exit_code } : null,
      error: { message: error.message, stack: error.stack, ...error } }) + '\n');
    process.exitCode = 1;
  }
});
