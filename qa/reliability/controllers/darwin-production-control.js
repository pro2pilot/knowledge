#!/usr/bin/env node
'use strict';

// Test controller only: fixed common-control operations, no dynamic callback,
// caller-supplied native descriptor, PID, proof or force flag. Output stays in
// the runner-private evidence directory and is never uploaded wholesale.
const path = require('node:path');
const assert = require('node:assert/strict');
let count = 0; const chunks = [];
process.stdin.on('data', chunk => { count += chunk.length; if (count > 1024 * 1024) process.exit(2); chunks.push(chunk); });
process.stdin.once('end', () => {
  let stage = 'input';
  try {
    assert.equal(process.platform, 'darwin');
    const input = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    assert.ok(path.isAbsolute(input.source) && path.isAbsolute(input.project));
    assert.ok(['status', 'cancel', 'recover'].includes(input.op));
    const lib = path.join(input.source, 'tools/lib');
    const control = require(path.join(lib, 'verification-control'));
    const context = { stateRoot: path.join(input.project, '.knowledge'), repoRoot: input.project,
      projectKnowledgeRoot: path.join(input.project, '.knowledge'), targetRoot: input.project,
      systemRoot: input.source };
    stage = 'status';
    const before = control.readStatus(context);
    let result = before;
    if (input.op !== 'status') {
      assert.match(input.attempt_id, /^VAT-[a-f0-9]{32}$/);
      assert.match(input.generation, /^[a-f0-9]{32}$/);
      assert.equal(before.attempt?.attempt_id, input.attempt_id);
      assert.equal(before.attempt?.generation, input.generation);
      const binding = { attempt_id: input.attempt_id, generation: input.generation };
      stage = input.op;
      if (input.op === 'cancel') result = control.requestCancel(context, { ...binding, reason_code: 'user_requested' });
      else {
        assert.ok(Number.isSafeInteger(input.budget_ms) && input.budget_ms >= 1 && input.budget_ms <= 60000);
        const deadline = process.hrtime.bigint() + BigInt(input.budget_ms) * 1000000n;
        result = require(path.join(lib, 'verification-recovery')).recoverAttempt(context,
          { ...binding, deadline_ns: String(deadline) });
      }
    }
    process.stdout.write(JSON.stringify({ type: 'control', op: input.op, ok: true,
      result, status: control.readStatus(context) }) + '\n');
  } catch (error) {
    process.stdout.write(JSON.stringify({ type: 'control', ok: false, stage,
      error: { message: error.message, stack: error.stack, ...error } }) + '\n');
    process.exitCode = 1;
  }
});
