#!/usr/bin/env node
'use strict';
const assert = require('assert').strict;
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const base = fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge-execution-contract-'));
const state = path.join(base, '.knowledge');
Object.assign(process.env, { KNOWLEDGE_MODE: 'repo', KNOWLEDGE_SYSTEM_ROOT: path.resolve(__dirname, '..'),
  KNOWLEDGE_TARGET_ROOT: base, KNOWLEDGE_STATE_ROOT: state, KNOWLEDGE_PROJECT_KNOWLEDGE_ROOT: state,
  KNOWLEDGE_AGENT_ID: 'verification-execution-fixture', KNOWLEDGE_UPDATE_DISABLE_ON_LAUNCH: '1' });
const native = require('./lib/repair-on-touch');
const reader = require('./lib/verification-execution');
const checks = [];
function check(name, action) { action(); checks.push({ name, status: 'pass' }); }
const clone = value => JSON.parse(JSON.stringify(value));
function signed(record) {
  const digest = native.executionDigest(record);
  return { ...record, content_sha256: digest, execution_id: `KVE-${digest}` };
}
try {
  for (const dir of ['src', 'tests', '.knowledge']) fs.mkdirSync(path.join(base, dir), { recursive: true });
  fs.writeFileSync(path.join(base, 'src/value.js'), 'module.exports = 7;\n');
  fs.writeFileSync(path.join(base, 'tests/value.js'), "require('assert').strictEqual(require('../src/value'), 7);\n");
  const executions = native.runVerificationTests({ stateRoot: state, repoRoot: base,
    taskId: 'verification-contract-fixture', sessionId: 'verification-contract-session',
    tests: [{ argv: ['node', 'tests/value.js'], cwd: '.', timeout_ms: 10000 }],
    sourceFiles: [{ path: 'src/value.js' }, { path: 'tests/value.js' }], checkedBy: 'verification-execution-fixture' });
  const id = executions[0].record.execution_id;
  const actual = native.loadExecutionRecord(state, id);
  assert(actual);
  const record = actual.record;
  check('physical fixture execution passed', () => assert.equal(executions[0].record.status, 'pass'));
  check('shared strict reader accepts exact native KVE', () => assert(reader.validateExecutionRecord(record).ok));
  check('shared and writer loaders return same physical bytes', () => assert.deepEqual(reader.loadExecutionRecord(state, id), actual));
  check('digest contract unchanged', () => assert.equal(reader.executionDigest(record), native.executionDigest(record)));
  for (const [name, edit, error] of [
    ['nonpassing execution', { status: 'fail', exit_code: 1 }, 'execution_not_passed'],
    ['timeout', { timed_out: true }, 'execution_timed_out'],
    ['signal', { signal: 'SIGTERM' }, 'execution_signal_invalid'],
    ['negative output length', { stdout_bytes: -1 }, 'execution_output_size_invalid'],
    ['private actor data', { executed_by: 'fixture@example.test' }, 'execution_private_value'],
    ['synthetic credential value', { executed_by: 'sk-' + 'A'.repeat(30) }, 'execution_secret_like_value']
  ]) check(name + ' rejected by both policies', () => {
    const changed = signed({ ...clone(record), ...edit });
    assert(reader.validateExecutionRecord(changed).errors.includes(error));
    assert(native.validateExecutionRecord(changed).errors.includes(error));
  });
  check('same source snapshot mutation is rejected', () => {
    const changed = clone(record); changed.source_snapshot[0].sha256 = 'f'.repeat(64);
    assert(reader.validateExecutionRecord(signed(changed)).errors.some(code => code.startsWith('execution_source_changed_during_verification:')));
  });
  check('malformed digest cannot be admitted', () => assert(!reader.validateExecutionRecord({ ...record, content_sha256: '0'.repeat(64) }).ok));
  check('missing record never creates a store', () => {
    const absent = path.join(base, 'absent');
    assert.equal(reader.loadExecutionRecord(absent, id), null); assert(!fs.existsSync(absent));
  });
  check('invalid state root fails closed', () => assert.equal(reader.loadExecutionRecord(null, id), null));
  check('unexpected filename digest is rejected', () => {
    const target = path.join(state, 'maintenance/verification_executions', '0'.repeat(64) + '.json');
    fs.writeFileSync(target, JSON.stringify(record));
    assert.equal(reader.loadExecutionRecord(state, 'KVE-' + '0'.repeat(64)), null);
  });
  check('malformed JSON is rejected without writes', () => {
    const target = path.join(state, 'maintenance/verification_executions', '1'.repeat(64) + '.json');
    fs.writeFileSync(target, '{');
    const before = crypto.createHash('sha256').update(fs.readFileSync(target)).digest('hex');
    assert.equal(reader.loadExecutionRecord(state, 'KVE-' + '1'.repeat(64)), null);
    assert.equal(crypto.createHash('sha256').update(fs.readFileSync(target)).digest('hex'), before);
  });
  check('reader dependency has no process or state-writing import', () => {
    const body = fs.readFileSync(path.join(__dirname, 'lib/verification-execution.js'), 'utf8');
    assert(!/require\(['"](?:child_process|\.\/repair-on-touch|\.\/recording-blockers|\.\/path-context)['"]\)/.test(body));
    assert(!/fs\.(?:write|append|mkdir|rename|unlink|rm)/.test(body));
  });
  console.log(JSON.stringify({ status: 'pass', checks_total: checks.length, checks,
    evidence_kind: 'physical isolated fixture KVE; no production certification', fixture_execution_id: id }, null, 2));
} finally {
  const resolved = fs.realpathSync(base), parent = fs.realpathSync(os.tmpdir()), rel = path.relative(parent, resolved);
  if (!rel || rel === '..' || rel.startsWith(`..${path.sep}`) || path.isAbsolute(rel)) throw Error('Unsafe fixture cleanup');
  fs.rmSync(resolved, { recursive: true, force: false });
}
