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
    const result = supervisor.runSupervised(request, 240000);
    const elapsed = Number(process.hrtime.bigint() - started) / 1e6;
    stage = 'finalization-reader';
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
      error: { message: error.message, stack: error.stack, ...error } }) + '\n');
    process.exitCode = 1;
  }
});
