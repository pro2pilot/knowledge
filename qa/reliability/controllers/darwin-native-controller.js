'use strict';

// Explicit native diagnostic fixture. This never creates KVE/KVF/ACK or
// production acceptance, and works with both KVS1 and KVS2 to compare behavior.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { fork, spawn } = require('node:child_process');
const readline = require('node:readline');
const assert = require('node:assert/strict');
const send = value => process.stdout.write(JSON.stringify(value) + '\n');
const hash = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
function canonical(v) {
  if (Array.isArray(v)) return `[${v.map(canonical).join(',')}]`;
  if (v && typeof v === 'object') return `{${Object.keys(v).sort().map(k => JSON.stringify(k) + ':' + canonical(v[k])).join(',')}}`;
  return JSON.stringify(v);
}
function channel(child) {
  const queue = [], waiters = [];let closed = false;
  child.on('message', m => { if (waiters.length) waiters.shift()(m);else queue.push(m); });
  child.on('exit', (code, signal) => { closed = true;while (waiters.length) waiters.shift()({ type: 'exit', code, signal }); });
  return () => queue.length ? Promise.resolve(queue.shift()) : closed ? Promise.resolve({ type: 'exit' }) :
    new Promise(resolve => waiters.push(resolve));
}
// This transport is intentionally independent of production/session validators
// so the same experiment can execute the exact older native implementation.
function rpc(config, input, run = false, output = () => {}, limit = 420000) {
  return new Promise((resolve, reject) => {
    const args = [run ? '--run' : '--request', '--socket=' + config.socket,
      '--lifecycle-timeout-ms=' + limit, '--transport-timeout-ms=30000'];
    const child = spawn(config.binary, args, { stdio: ['pipe', 'pipe', 'pipe', 'pipe'],
      env: { PATH: '/usr/bin:/bin', LANG: 'C', LC_ALL: 'C' } });
    const parts = [];let bytes = 0, error = null;
    const control = run ? child.stdio[3] : child.stdout;
    control.on('data', b => { bytes += b.length;if (bytes > 65536) { error = new Error('control_oversized');child.kill(); }else parts.push(b); });
    if (run) child.stdout.on('data', b => output(b.toString('utf8')));
    child.stderr.on('data', b => process.stderr.write(b));
    if (!run) child.stdio[3].resume();
    child.on('error', e => { error = e; });child.stdin.on('error', e => { error = e; });
    const timeout = setTimeout(() => { error = new Error('test_transport_timeout');child.kill('SIGKILL'); }, limit + 5000);
    child.once('close', (code, signal) => {
      clearTimeout(timeout);if (error) return reject(error);
      let reply;try { reply = JSON.parse(Buffer.concat(parts)); } catch { return reject(new Error('untyped_native_result')); }
      if (code || signal || !reply.ok) return reject(Object.assign(new Error(reply.error || 'native_failed'), { reply }));
      resolve(reply);
    });
    child.stdin.end(JSON.stringify(input));
  });
}
if (process.argv[2] === '--authority') {
  let input;const next = channel(process);
  (async () => {
    input = await next();const { config, auth, command } = input;
    await rpc(config, { op: 'register_authority', ...auth });process.send({ type: 'registered' });
    const go = await next();assert.equal(go.type, 'go');
    const result = await rpc(config, { op: 'run', ...auth, ...command }, true,
      text => process.send({ type: 'output', text }));
    process.send({ type: 'command_result', result });
    const drain = await rpc(config, { op: 'drain_commands', ...auth, cleanup_budget_ms: input.cleanup_ms });
    process.send({ type: 'drained', drain });
    await new Promise(() => {});
  })().catch(error => { process.send?.({ type: 'authority_failed', reason: error.message, reply: error.reply || null });process.exitCode = 1; });
} else {
  let input, prepared, authority, stopped = false, resultSent = false, commandResult, drain, stage = 'request';
  const lines = readline.createInterface({ input: process.stdin });
  let startResolve;const start = new Promise(resolve => { startResolve = resolve; });
  async function stop() {
    stopped = true;if (!prepared) return;
    try { const reply = await rpc(input.config, { op: 'stop', attempt_id: prepared.attempt_id,
      descriptor_sha256: prepared.descriptor_sha256, cleanup_budget_ms: input.cleanup_ms });send({ type: 'stop_reply', reply }); }
    catch (error) { send({ type: 'stop_error', reason: error.message }); }
  }
  lines.on('line', line => {
    let message;try { message = JSON.parse(line); } catch { return; }
    if (!input) { input = message;startResolve(message); }
    else if (message.op === 'stop') stop();
    else if (message.op === 'exit') { lines.close();process.stdin.pause(); }
  });
  process.on('SIGINT', stop);process.on('SIGTERM', stop);
  (async () => {
    await start;
    const isolated = require(path.join(input.source, 'tools/lib/verification-isolated-copy'));
    const nonce = crypto.randomBytes(32).toString('hex');
    const plan = await isolated.planProject(input.project, { required: ['run.js'], cwd: '.' });
    stage = 'prepare';prepared = await rpc(input.config, { op: 'prepare', mode: 'isolated_copy', attempt_nonce: nonce,
      work_budget_ms: input.work_ms, cleanup_budget_ms: input.cleanup_ms });
    assert.equal(hash(canonical(prepared.descriptor)), prepared.descriptor_sha256);
    assert.equal(prepared.descriptor.capability_qualified, false);
    assert.equal(prepared.descriptor.qualification_mode, true);
    send({ type: 'prepared', binding: { attempt_id: prepared.attempt_id, descriptor_sha256: prepared.descriptor_sha256,
      descriptor: prepared.descriptor } });
    const auth = { attempt_id: prepared.attempt_id, token: prepared.token };
    stage = 'copy';await isolated.transferProject(plan, q => rpc(input.config, { ...q, ...auth }));
    const sealed = await rpc(input.config, { op: 'readback_copy', ...auth });
    assert.equal(sealed.manifest_sha256, plan.manifest_sha256);
    stage = 'authority';await rpc(input.config, { op: 'expect_authority', ...auth });
    authority = fork(__filename, ['--authority'], { stdio: ['ignore', 'ignore', 'inherit', 'ipc'],
      env: { PATH: '/usr/bin:/bin', LANG: 'C', LC_ALL: 'C' } });
    const next = channel(authority);
    const command = { argv: [input.config.node, 'run.js'], env: {}, cwd: '.', timeout_ms: input.command_ms };
    authority.send({ config: input.config, auth, command, cleanup_ms: input.cleanup_ms });
    const registered = await next();assert.equal(registered.type, 'registered');
    stage = 'permit';await rpc(input.config, { op: 'permit', ...auth });
    authority.send({ type: 'go' });send({ type: 'permitted' });
    stage = 'run';
    for (;;) {
      const message = await next();
      if (message.type === 'output') send(message);
      else if (message.type === 'command_result') { commandResult = message.result;send(message); }
      else if (message.type === 'drained') { drain = message.drain;break; }
      else throw new Error(message.reason || 'authority_exit_before_drain');
    }
    stage = 'command-validation';assert.equal(commandResult.exit_code, input.expected_exit || 0);
    assert.equal(commandResult.signal, null);assert.equal(commandResult.timed_out, false);
    assert.equal(drain.command_drain_proof.native_command_drain_facts_confirmed, true);
    stage = 'readback';const copied = await rpc(input.config, { op: 'readback_copy', ...auth });
    assert.equal(copied.manifest_sha256, plan.manifest_sha256);
    stage = 'close';const closed = await rpc(input.config, { op: 'close', attempt_id: prepared.attempt_id,
      descriptor_sha256: prepared.descriptor_sha256, cleanup_budget_ms: input.cleanup_ms });
    assert.equal(closed.proof.native_cleanup_facts_confirmed, true);
    assert.equal(closed.proof.cleanup_confirmed, false);
    assert.equal(closed.proof.abort_latched, false);
    assert.equal(closed.proof.cleanup_budget_exceeded, false);
    assert.equal(stopped, false);
    send({ type: 'result', success: true, production_accepted: false, command: commandResult,
      terminal: closed, manifest_sha256: plan.manifest_sha256 });resultSent = true;
  })().catch(async error => {
    await stop();
    let cleanup = null;
    if (prepared) {
      try { cleanup = await rpc(input.config, { op: 'recover', attempt_id: prepared.attempt_id,
        descriptor_sha256: prepared.descriptor_sha256, cleanup_budget_ms: input.cleanup_ms }); } catch {}
    }
    if (!resultSent) send({ type: 'result', success: false, reason: error.message, error_code: error.code || error.reply?.error || null,
      diagnostic_stage: stage, command: commandResult || null, drain: drain || null, terminal: cleanup, production_accepted: false });
  }).finally(() => {
    if (authority && authority.exitCode === null && authority.signalCode === null) authority.kill('SIGKILL');
    lines.close();process.stdin.destroy();
  });
}
