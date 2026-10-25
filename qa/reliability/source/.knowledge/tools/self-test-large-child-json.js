#!/usr/bin/env node
'use strict';
const fs = require('fs');
const os = require('os');
const path = require('path');
const assert = require('assert').strict;
const root = fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge-large-json-'));
const system = path.join(root, '.knowledge');
fs.mkdirSync(path.join(system, 'tools'), { recursive: true });
Object.assign(process.env, { KNOWLEDGE_MODE: 'repo', KNOWLEDGE_TARGET_ROOT: root,
  KNOWLEDGE_SYSTEM_ROOT: system, KNOWLEDGE_PROJECT_KNOWLEDGE_ROOT: system,
  KNOWLEDGE_STATE_ROOT: system, KNOWLEDGE_AGENT_ID: 'large-json-fixture',
  KNOWLEDGE_UPDATE_DISABLE_ON_LAUNCH: '1', GIT_CEILING_DIRECTORIES: root });
const flow = require('./flow');
const harness = require('./evaluation-harness');
const { MAX_CHILD_JSON_BYTES } = require('./lib/semantic-json');
const context = { mode: 'repo', systemRoot: system, targetRoot: root,
  projectKnowledgeRoot: system, stateRoot: system, agentId: 'large-json-fixture' };
const checks = [];
function check(name, action) { action(); checks.push({ name, status: 'pass' }); }
try {
  fs.writeFileSync(path.join(system, 'package.json'), '{"name":"large-json-fixture","version":"0.0.0"}\n');
  fs.writeFileSync(path.join(system, 'tools/large.js'), "process.stdout.write(JSON.stringify({status:'ok',payload:'x'.repeat(2*1024*1024)}));\n");
  fs.writeFileSync(path.join(system, 'tools/oversized.js'), `process.stdout.write(JSON.stringify({status:'ok',payload:'x'.repeat(${MAX_CHILD_JSON_BYTES + 1024 * 1024})}));\n`);
  check('flow accepts a physical multi-megabyte JSON child without truncation', () => {
    const result = flow.runOne('large.js', context);
    assert.equal(result.success, true); assert.equal(result.parsed.payload.length, 2 * 1024 * 1024);
  });
  check('evaluation accepts the same physical multi-megabyte JSON child', () => {
    const result = harness.runCheck({ name: 'large', command: 'tools/large.js' });
    assert.equal(result.status, 'pass'); assert.deepEqual(result.semantic_errors, []);
  });
  check('oversized output fails visibly instead of becoming truncated success', () => {
    const result = flow.runOne('oversized.js', context);
    assert.equal(result.success, false); assert.equal(result.spawn_error.code, 'command_output_limit');
    assert.equal(result.failure_code, 'command_output_limit');
    assert.equal(result.cleanup.status, 'completed'); assert.equal(result.cleanup.active_processes, 0);
  });
  check('evaluation cannot accept a spawn error with misleading exit zero', () => {
    const result = harness.runCheck({ name: 'error', command: 'tools/large.js' }, {
      spawnSync: () => ({ status: 0, signal: null, stdout: '{"status":"ok"}', stderr: '', error: { code: 'ENOBUFS' } })
    });
    assert.equal(result.status, 'fail'); assert.equal(result.failure_code, 'child_spawn_error');
  });
  check('evaluation cannot accept a signal with misleading exit zero', () => {
    const result = harness.runCheck({ name: 'signal', command: 'tools/large.js' }, {
      spawnSync: () => ({ status: 0, signal: 'SIGTERM', stdout: '{"status":"ok"}', stderr: '' })
    });
    assert.equal(result.status, 'fail'); assert.equal(result.failure_code, 'child_signal');
  });
  console.log(JSON.stringify({ status: 'pass', checks_total: checks.length, checks,
    evidence_kind: 'isolated JSON child checks; no release flow or gate executed' }, null, 2));
} finally {
  const resolved = fs.realpathSync(root), parent = fs.realpathSync(os.tmpdir()), rel = path.relative(parent, resolved);
  if (!rel || rel === '..' || rel.startsWith(`..${path.sep}`) || path.isAbsolute(rel)) throw Error('Unsafe fixture cleanup');
  fs.rmSync(resolved, { recursive: true, force: false });
}
