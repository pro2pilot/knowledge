'use strict';

// These are synthetic signed reader fixtures, never proof of native command
// execution or an independent application review. Issuance, physical readers
// and the compare-and-swap transaction are the real product implementations.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const transaction = require('../tools/lib/json-transaction');
const originalCommit = transaction.commitJsonTransaction;
let atCommit = null;
// The issuer captures its transaction dependency when required below. Only a
// physical fixture file is changed here; the real transaction still executes.
transaction.commitJsonTransaction = options => {
  if (atCommit) atCommit(options);
  return originalCommit(options);
};
const { fixture, hash } = require('./helpers/currency-overlay');
const native = require('../tools/lib/repair-on-touch');
const finalization = require('../tools/lib/verification-finalization');
const runtimeRoot = path.resolve(__dirname, '..');
const nodeHash = hash(fs.readFileSync(process.execPath));

async function evidence(f) {
  const checked = f.prepareBatch();
  f.write('tests/synthetic-only.js', '// Reader fixture only; never executed.\n');
  f.write('src/unselected-only.js', '// Not selected as factual evidence.\n');
  const paths = [...new Set([f.batchPath, ...checked.children.map(child => child.path),
    ...checked.pins.filter(pin => !pin.predecessor_receipt_id).map(pin => pin.path), 'tests/synthetic-only.js'])].sort();
  const keys = crypto.generateKeyPairSync('ed25519');
  const publicKey = keys.publicKey.export({ type: 'spki', format: 'der' }).toString('hex');
  const batchId = 'KVB-' + crypto.randomBytes(16).toString('hex');
  const requestHash = finalization.digest({ fixture: 'synthetic_reader_only', taskId: 'overlay-task', sessionId: 'overlay-session' });
  const executions = [paths, ['src/unselected-only.js']].map((files, ordinal) => {
    const snapshot = files.map(file => f.pin(file));
    const record = { schema_version: 'knowledge-verification-execution.v2', task_id: 'overlay-task', session_id: 'overlay-session',
      command_argv: ['node', 'tests/synthetic-only.js'], command: 'node tests/synthetic-only.js', cwd: '.', status: 'pass', exit_code: 0,
      signal: null, timed_out: false, duration_ms: 1, executed_at: new Date().toISOString(), executed_by: 'synthetic-reader-fixture',
      runtime_binding: 'process_exec_path', runtime_sha256: nodeHash, environment_profile: 'sanitized_node',
      stdout_sha256: hash(''), stderr_sha256: hash(''), stdout_bytes: 0, stderr_bytes: 0,
      source_snapshot_before: snapshot, source_snapshot: snapshot, batch_id: batchId, batch_ordinal: ordinal,
      batch_public_key: publicKey, batch_request_sha256: requestHash };
    record.content_sha256 = native.executionDigest(record); record.execution_id = 'KVE-' + record.content_sha256;
    return { record, ...native.saveExecutionRecord(f.state, record) };
  });
  const receipt = { schema_version: finalization.SCHEMA, batch_id: batchId, public_key: publicKey, request_sha256: requestHash,
    task_id: 'overlay-task', session_id: 'overlay-session', status: 'commands_and_teardown_observed', backend: 'windows_job_object',
    teardown: { status: 'completed', method: 'windows_job_object', active_processes: 0, keeper_exited: true }, timeout_ms: 1000, observed_elapsed_ms: 10,
    work_elapsed_ms: 5, cleanup_budget_ms: 1000,
    runtime_sha256: nodeHash,
    implementation: finalization.IMPLEMENTATION_PATHS.map(file => ({ path: file, sha256: hash(fs.readFileSync(path.join(runtimeRoot, file))) })),
    executions: executions.map(item => ({ execution_id: item.record.execution_id, physical_sha256: item.physical_sha256 })) };
  const reference = await finalization.persistFinalization(f.state, receipt);
  const acknowledgement = finalization.acceptFinalization(reference, 1000, 20, keys.privateKey);
  return { executions, finalPath: path.join(f.state, 'maintenance/verification_finalizations', reference.receipt_id.slice(4) + '.json'),
    execution_ids: [executions[0].record.execution_id], verification_acceptances: [acknowledgement] };
}

test('complete native batch dependencies survive currency authorization through commit', async t => {
  t.after(() => { atCommit = null; transaction.commitJsonTransaction = originalCommit; });
  await t.test('unselected KVE is a transaction dependency without becoming selected factual evidence', async t => {
    const f = fixture(t, 'guard-normal'), b = await evidence(f);
    const accepted = finalization.requireFinalizedExecutions(f.state, b.execution_ids, b.verification_acceptances);
    assert.deepEqual(accepted.bindings.map(pin => pin.path).sort(), [...b.executions.map(item => item.path), b.finalPath].sort());
    assert.deepEqual(accepted.bindings.find(pin => pin.path === b.finalPath).execution_ids, b.executions.map(item => item.record.execution_id));
    assert.equal(accepted.execution_records.length, 2);
    const ledgers = f.ledgers(); const result = f.issue(b);
    assert.equal(result.status, 'committed'); assert.deepEqual(result.reused_execution_ids, b.execution_ids);
    assert.deepEqual(f.ledgers(), ledgers);
    const current = f.evaluate(); assert.equal(current.valid, true);
    assert(current.files[f.first.source]); assert.equal(current.files['src/unselected-only.js'], undefined);
  });
  await t.test('unselected KVE changed before authorization rejects the selected subset', async t => {
    const f = fixture(t, 'guard-before'), b = await evidence(f), ledgers = f.ledgers();
    fs.appendFileSync(b.executions[1].path, '\n');
    assert.throws(() => f.issue(b), { code: 'verification_finalization_required' });
    assert(!fs.existsSync(path.join(f.state, 'maintenance/knowledge_currency/index.json'))); assert.deepEqual(f.ledgers(), ledgers);
  });
  for (const kind of ['selected KVE', 'KVF', 'unselected KVE']) await t.test(kind + ' changed exactly at commit is rejected by the real transaction', async t => {
    const f = fixture(t, 'guard-' + kind.replaceAll(' ', '-').toLowerCase()), b = await evidence(f), ledgers = f.ledgers();
    const target = kind === 'KVF' ? b.finalPath : b.executions[kind === 'selected KVE' ? 0 : 1].path;
    let calls = 0, guarded = false;
    atCommit = options => {
      assert.equal(calls++, 0); assert(options.transactionId.startsWith('knowledge-currency-batch-'));
      guarded = options.guards.some(pin => path.resolve(pin.path) === target);
      fs.appendFileSync(target, '\n');
    };
    try { assert.throws(() => f.issue(b), { code: 'transaction_guard_drift' }); }
    finally { atCommit = null; }
    assert.equal(calls, 1); assert.equal(guarded, true, kind + ' must be guarded');
    assert(!fs.existsSync(path.join(f.state, 'maintenance/knowledge_currency/index.json')));
    assert.deepEqual(f.ledgers(), ledgers);
  });
  await t.test('currency fixture update setting is read from the real YAML configuration', t => {
    const f = fixture(t, 'guard-config');
    f.write('.knowledge/tools/check-updates.js', fs.readFileSync(path.join(runtimeRoot, 'tools/check-updates.js'), 'utf8'));
    const script = path.join(f.state, 'tools/check-updates.js');
    const loadedPath = require.resolve(script);
    t.after(() => { delete require.cache[loadedPath]; });
    const updates = require(script);
    assert(fs.existsSync(path.join(f.state, 'config.yaml')));
    assert.equal(updates.getConfig().enabled, false);
    f.write('.knowledge/config.yaml', 'updates:\n  enabled: true\n');
    assert.equal(updates.getConfig().enabled, true);
    f.write('.knowledge/config.yaml', 'updates:\n  enabled: false\n');
    assert.equal(updates.getConfig().enabled, false);
  });
});
