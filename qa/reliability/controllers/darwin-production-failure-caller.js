#!/usr/bin/env node
'use strict';

// Fixed disposable-runner caller for production cancellation/crash cases.
// A separate ordinary-UID helper performs status/cancel/recovery. This process
// never fabricates a native receipt and never catches an error as a success.
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const CASES = new Set(['cancel', 'authority_death', 'controller_death', 'paused_storage_cancel', 'paused_storage_controller_death',
  'paused_storage_guardian_death', 'double_storage_guardian_controller_death']);
let count = 0; const chunks = [];
process.stdin.on('data', chunk => { count += chunk.length; if (count > 1024 * 1024) process.exit(2); chunks.push(chunk); });
process.stdin.once('end', () => {
  let stage = 'input';
  try {
    assert.equal(process.platform, 'darwin');
    const input = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    assert.ok(path.isAbsolute(input.source) && path.isAbsolute(input.project));
    assert.ok(CASES.has(input.case_name));
    const supervisor = require(path.join(input.source, 'tools/lib/verification-supervisor'));
    const stateRoot = path.join(input.project, '.knowledge');
    fs.mkdirSync(stateRoot, { mode: 0o700 });
    const script = path.join(input.project, 'run.js');
    // No stdout is needed to prove execution. The physical harness waits for
    // the bound native command birth plus a nonempty fresh UID observation.
    // Descendants detach and close their pipes, exercising the UID authority.
    const grandchild = "setInterval(()=>{},1000);";
    const child = "const{spawn}=require('node:child_process');const g=spawn(process.execPath,['-e'," +
      JSON.stringify(grandchild) + "],{detached:true,stdio:'ignore'});g.unref();setInterval(()=>{},1000);";
    const source = "'use strict';const{spawn}=require('node:child_process');const c=spawn(process.execPath,['-e'," +
      JSON.stringify(child) + "],{detached:true,stdio:'ignore'});c.unref();setInterval(()=>{},1000);\n";
    fs.writeFileSync(script, source, { flag: 'wx', mode: 0o600 });
    const digest = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
    const sourceHash = digest(Buffer.from(source));
    const request = { stateRoot, repoRoot: input.project,
      taskId: 'native-qa-' + input.case_name, sessionId: 'native-qa', checkedBy: 'native-qa',
      sourceFiles: ['run.js'], tests: [{ argv: ['node', 'run.js'], cwd: '.', timeout_ms: 180000 }],
      verificationPolicy: { work_budget_ms: 240000, no_progress_ms: 0, cleanup_budget_ms: 60000 },
      nativeExecution: { darwin: { enabled: true, mode: 'isolated_copy',
        broker_path: input.config.binary, broker_socket: input.config.socket, copy: {} } } };
    process.stdout.write(JSON.stringify({ type: 'started', case_name: input.case_name, pid: process.pid }) + '\n');
    stage = 'public-run';
    const started = process.hrtime.bigint();
    let result, error;
    try { result = supervisor.runSupervised(request, 240000); } catch (cause) { error = cause; }
    const observedElapsedMs = Number(process.hrtime.bigint() - started) / 1e6;
    stage = 'observed-outcome';
    const sourceUnchanged = digest(fs.readFileSync(script)) === sourceHash;
    // The case verdict is produced only by the physical harness after fresh
    // native closure, storage-writer exit and durable non-ACK terminal state.
    // This is deliberately an observation record, not a PASS-shaped result.
    process.stdout.write(JSON.stringify({ type: 'observation', case_name: input.case_name,
      stage, returned: result !== undefined, result: result || null,
      acceptances: result?.verification_acceptances || [],
      budget: result?.verification_budget || error?.verification_budget || null,
      error: error ? { message: error.message, stack: error.stack, ...error } : null,
      observed_elapsed_ms: observedElapsedMs, source_unchanged: sourceUnchanged }) + '\n');
    if (result !== undefined || !error || !sourceUnchanged) process.exitCode = 1;
  } catch (error) {
    process.stdout.write(JSON.stringify({ type: 'caller_failure', stage,
      error: { message: error.message, stack: error.stack, ...error } }) + '\n');
    process.exitCode = 1;
  }
});
