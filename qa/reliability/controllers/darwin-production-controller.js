#!/usr/bin/env node
'use strict';

// Physical QA caller. All output is runner-private; a separate strict
// allowlist produces the two public evidence files. No native token is
// requested or synthesized by this caller.
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const chunks = [];
let size = 0;
process.stdin.on('data', chunk => {
  size += chunk.length;
  if (size > 1024 * 1024) process.exit(2);
  chunks.push(chunk);
});
process.stdin.once('end', () => {
  let stage = 'input';
  try {
    assert.equal(process.platform, 'darwin');
    const input = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    assert.ok(path.isAbsolute(input.source) && path.isAbsolute(input.project));
    const lib = path.join(input.source, 'tools', 'lib');
    const supervisor = require(path.join(lib, 'verification-supervisor'));
    const finalization = require(path.join(lib, 'verification-finalization'));
    const control = require(path.join(lib, 'verification-control'));
    const stateRoot = path.join(input.project, '.knowledge');
    fs.mkdirSync(stateRoot, { mode: 0o700 });
    const before = fs.readFileSync(path.join(input.project, 'run.js'));
    const digest = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
    const request = {
      stateRoot, repoRoot: input.project, taskId: 'native-qa', sessionId: 'native-qa', checkedBy: 'native-qa',
      sourceFiles: ['run.js'], tests: [{ argv: ['node', 'run.js'], cwd: '.', timeout_ms: 180000 }],
      verificationPolicy: { work_budget_ms: 240000, no_progress_ms: 0, cleanup_budget_ms: 60000 },
      nativeExecution: { darwin: { enabled: true, mode: 'isolated_copy',
        broker_path: input.config.binary, broker_socket: input.config.socket, copy: {} } }
    };
    process.stdout.write(JSON.stringify({ type: 'started', pid: process.pid }) + '\n');
    stage = 'public-run';
    const result = supervisor.runSupervised(request, 240000);
    stage = 'finalization-reader';
    assert.equal(result.length, 1);
    assert.equal(result[0].record.status, 'pass');
    assert.equal(result[0].record.exit_code, 0);
    const ids = result.map(row => row.record.execution_id);
    assert.equal(result.verification_acceptances.length, 1);
    const finalized = finalization.requireFinalizedExecutions(stateRoot, ids, result.verification_acceptances);
    assert.equal(finalized.status, 'accepted');
    const status = control.readStatus({ stateRoot, repoRoot: input.project });
    assert.equal(status.attempt.claimed, false);
    assert.equal(status.attempt.cleanup.status, 'confirmed');
    assert.equal(digest(fs.readFileSync(path.join(input.project, 'run.js'))), digest(before));
    stage = 'complete';
    process.stdout.write(JSON.stringify({ type: 'result', success: true, stage,
      result, acceptances: result.verification_acceptances, budget: result.verification_budget,
      finalized, status, source_unchanged: true }) + '\n');
  } catch (error) {
    process.stdout.write(JSON.stringify({ type: 'result', success: false, stage,
      error_code: typeof error.code === 'string' ? error.code : 'controller_assertion_failed',
      error: { message: error.message, stack: error.stack, ...error } }) + '\n');
    process.exitCode = 1;
  }
});
