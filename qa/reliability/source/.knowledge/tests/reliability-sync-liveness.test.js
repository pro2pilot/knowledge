'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('child_process');
const crypto = require('crypto');
const legacy = process.env.KNOWLEDGE_TEST_LEGACY_PIPE_READER === '1';
for (const expected of [0, 1]) test(`sync liveness pipe does not block terminal exit ${expected}`, { skip: process.platform !== 'linux' }, () => {
  const reader = legacy
    ? "require('fs').createReadStream(null,{fd:3,autoClose:true})"
    : "new (require('net').Socket)({fd:3,readable:true,writable:false})";
  const code = `const parent=${reader};parent.on('end',()=>process.exit(3));parent.on('error',()=>process.exit(4));parent.resume();process.stdin.resume();process.stdin.on('end',()=>setTimeout(()=>process.stdout.write('terminal',()=>{parent.destroy();process.exit(${expected})}),25));`;
  const result = spawnSync(process.execPath, ['-e', code], { input: 'request', encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe', 'pipe'], timeout: 1000, killSignal: 'SIGKILL' });
  console.log(JSON.stringify({ scenario: 'physical_node_liveness_pipe', legacy_reader: legacy, expected_exit: expected,
    producer_sha256: crypto.createHash('sha256').update(code).digest('hex'), status_observed: result.status,
    signal_observed: result.signal, error_observed: result.error?.code || null, stdout: result.stdout, stderr: result.stderr }));
  assert.equal(result.error, undefined); assert.equal(result.status, expected); assert.equal(result.stdout, 'terminal');
});
