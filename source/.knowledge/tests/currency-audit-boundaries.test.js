'use strict';

// Independent physical fixtures. The hostile values and concurrency hooks are
// synthetic; no application, production review or provider usage is certified.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');
const { fixture, clone, hash } = require('./helpers/currency-overlay');
const currency = require('../tools/lib/knowledge-currency');
const batch = require('../tools/lib/knowledge-currency-batch');
const native = require('../tools/lib/repair-on-touch');
const reader = require('../tools/lib/verification-execution');
const blockers = require('../tools/lib/recording-blockers');

const jsonBytes = value => Buffer.from(JSON.stringify(value, null, 2) + '\n');
function make(t, name) {
  const f = fixture(t, name);
  f.write('.knowledge/config.json', { updates: { enabled: false } });
  return f;
}
function savedManifest(f, receiptId) {
  return JSON.parse(fs.readFileSync(path.join(f.state, 'maintenance/knowledge_currency/receipts', receiptId.slice(5) + '.json')));
}
function outputSnapshot(f) {
  const base = path.join(f.state, 'maintenance/knowledge_currency');
  const result = {};
  function walk(directory) {
    if (!fs.existsSync(directory)) return;
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      const file = path.join(directory, entry.name);
      if (entry.isDirectory()) walk(file);
      else result[path.relative(base, file)] = hash(fs.readFileSync(file));
    }
  }
  walk(base);
  return result;
}
function interrupt(f, executions, point = 'after_commit_marker') {
  const directory = path.join(f.state, 'maintenance/transactions');
  const existing = new Set(fs.existsSync(directory) ? fs.readdirSync(directory) : []);
  const previous = process.env.KNOWLEDGE_TRANSACTION_FAULT;
  process.env.KNOWLEDGE_TRANSACTION_FAULT = point;
  try { assert.throws(() => f.issue(executions), { code: 'transaction_fault_injected' }); }
  finally {
    if (previous === undefined) delete process.env.KNOWLEDGE_TRANSACTION_FAULT;
    else process.env.KNOWLEDGE_TRANSACTION_FAULT = previous;
  }
  const added = fs.readdirSync(directory).filter(name => !existing.has(name));
  assert.equal(added.length, 1);
  return path.join(directory, added[0]);
}
function rewriteJournalOutput(txRoot, suffix, mutate) {
  const manifestFile = path.join(txRoot, 'manifest.json');
  const manifest = JSON.parse(fs.readFileSync(manifestFile));
  const entry = manifest.writes.find(row => row.target.replace(/\\/g, '/').endsWith(suffix));
  assert(entry, 'the real interrupted transaction must own this exact output');
  const changed = mutate(JSON.parse(fs.readFileSync(path.join(txRoot, entry.staged))), manifest);
  const payload = jsonBytes(changed);
  fs.writeFileSync(path.join(txRoot, entry.staged), payload);
  entry.new_sha256 = hash(payload);
  manifest.intent.writes.find(row => row.target === entry.target).new_sha256 = entry.new_sha256;
  manifest.intent_sha256 = currency.currencyDigest(manifest.intent);
  const bytes = jsonBytes(manifest);
  fs.writeFileSync(manifestFile, bytes);
  fs.writeFileSync(path.join(txRoot, 'prepared.json'), bytes);
  const commitFile = path.join(txRoot, 'commit.json');
  const marker = JSON.parse(fs.readFileSync(commitFile));
  marker.manifest_sha256 = hash(bytes);
  fs.writeFileSync(commitFile, jsonBytes(marker));
}

for (const [name, mutate] of [
  ['occurrence', row => { row.occurrence = 2; row.reopened_at = new Date().toISOString(); }],
  ['observation date', row => { row.opened_at = '2026-01-01T00:00:01.000Z'; }],
  ['terminal status', row => { row.status = 'closed'; row.resolution_evidence = { type: 'unverified_legacy' }; }]
]) test('currency audit: native ' + name + ' drift revokes only its authenticated factual scope', t => {
  const f = make(t, 'scope-alpha'); const beta = f.addUnit('scope-beta');
  f.issue(f.verify());
  mutate(f.first.row); f.persist();
  const ledgers = f.ledgers();
  const result = f.evaluate();
  assert.equal(result.valid, true, JSON.stringify(result.issues));
  assert.equal(result.files[f.first.source], undefined);
  assert(result.files[beta.source]);
  const issue = result.issues.find(row => row.code === 'currency_native_finding_mismatch');
  assert(issue && currency.isNativeScopedCurrencyIssue(issue));
  assert.equal(issue.impact, 'scope');
  assert.equal(currency.isNativeScopedCurrencyIssue(clone(issue)), false);
  assert.deepEqual(f.ledgers(), ledgers);
  assert.equal(result.assurance.grants_assurance, false);
});

test('currency audit: a missing native identity still rejects global authority despite forged caller projections', t => {
  const f = make(t, 'native-identity'); f.addUnit('native-independent'); f.issue(f.verify());
  const forged = clone(f.findings);
  f.findings.splice(f.findings.indexOf(f.first.row), 1); f.persist();
  const result = currency.evaluateCurrency(f.context, { staleItems: { items: forged }, repairQueue: { queue: forged } });
  assert.equal(result.valid, false);
  assert.deepEqual(Object.keys(result.files), []);
  const issue = result.issues.find(row => row.code === 'currency_native_finding_mismatch');
  assert(issue && issue.impact === 'global');
  assert.equal(currency.isNativeScopedCurrencyIssue(issue), false);
});

test('currency audit: a final physical read rejection clears valid and all positive manifest output', t => {
  const f = make(t, 'final-read'); const issued = f.issue(f.verify());
  const manifest = savedManifest(f, issued.receipt_ids[0]);
  const source = path.join(f.root, f.first.source);
  const original = fs.openSync; let reads = 0; let result;
  fs.openSync = function (file, ...args) {
    if (file === source && ++reads === 2) fs.writeFileSync(source, 'module.exports = 9;\n');
    return original.call(this, file, ...args);
  };
  try { result = currency.validateCurrencyManifest(f.context, manifest); }
  finally { fs.openSync = original; }
  assert(reads >= 2, 'the source must physically change during the final guard read');
  assert.equal(result.valid, false);
  assert.deepEqual(Object.keys(result.coverage.files), []);
  assert.deepEqual(Object.keys(result.coverage.findings), []);
  assert.deepEqual(result.source_files, []);
  assert(result.issues.some(row => ['currency_file_changed_during_read', 'currency_assessment_changed'].includes(row.code)));
});

test('currency audit: malformed JSON and filesystem errors never echo private values from the CLI', t => {
  const f = make(t, 'cli-errors');
  const privateValue = 'sk-' + 'Q'.repeat(30);
  for (const [relative, expectedCode, bytes] of [
    [f.batchPath, 'currency_json_malformed', privateValue],
    ['.knowledge/evidence/' + privateValue + '.json', 'ENOENT', null]
  ]) {
    if (bytes !== null) f.write(relative, bytes);
    const args = [path.join(f.context.systemRoot, 'tools/knowledge-currency.js'), 'prepare-batch', '--request=' + relative,
      '--system-root=' + f.context.systemRoot, '--target-root=' + f.root,
      '--project-knowledge-root=' + f.context.projectKnowledgeRoot, '--state-root=' + f.state];
    const result = spawnSync(process.execPath, args, { cwd: f.root, encoding: 'utf8', timeout: 30000,
      env: { ...process.env, KNOWLEDGE_DISABLE_GIT_DISCOVERY: '1', KNOWLEDGE_USER_LANGUAGE: 'ru' } });
    assert.equal(result.error, undefined, 'the child must physically execute; a spawn failure is not a privacy result');
    assert.equal(result.status, 1);
    const publicText = String(result.stdout || '') + String(result.stderr || '');
    assert.equal(publicText.includes(privateValue.slice(0, 9)), false);
    assert.equal(publicText.includes(f.root), false);
    const payload = JSON.parse(result.stderr.trim());
    assert.equal(payload.code, expectedCode);
    assert.equal(payload.status, 'failed');
    assert.deepEqual(outputSnapshot(f), {});
  }
});

test('currency audit: recording APIs admit all input and context before traps, locks or registry creation', t => {
  const f = make(t, 'blocker-admission'); let calls = 0;
  const proxy = new Proxy({}, { get() { calls++; throw Error('getter must not execute'); }, ownKeys() { calls++; return []; } });
  const revoked = Proxy.revocable({}, {}); revoked.revoke();
  const hostile = [Object.defineProperty({}, 'kind', { enumerable: true, get() { calls++; return 'suspected_secret'; } }),
    proxy, revoked.proxy, Object.create({ kind: 'suspected_secret' }), Object.defineProperty({}, 'hidden', { value: 1 })];
  const before = fs.readdirSync(f.state).sort();
  for (const input of hostile) {
    for (const fn of [blockers.registerBlocker, blockers.resolveBlocker, blockers.revokeOverride]) {
      assert.throws(() => fn(f.context, input), { code: 'transaction_input_invalid' });
    }
    assert.throws(() => blockers.listBlockers(input), { code: 'transaction_input_invalid' });
    assert.throws(() => blockers.approvedRepositoryPath(input, 'src/value.js', null), { code: 'transaction_input_invalid' });
  }
  const argv = Object.defineProperty([], '0', { enumerable: true, configurable: true, get() { calls++; return 'list'; } });
  assert.throws(() => require('../tools/recording-blockers').main(argv), { code: 'transaction_input_invalid' });
  assert.equal(calls, 0);
  assert.deepEqual(fs.readdirSync(f.state).sort(), before);
  assert.equal(fs.existsSync(path.join(f.state, 'maintenance/recording_blockers.json')), false);
});

test('currency audit: shared and writer KVE validation reject executable caller data without callbacks', t => {
  let calls = 0;
  const getter = Object.defineProperty({}, 'task_id', { enumerable: true, get() { calls++; return 'hostile'; } });
  const proxy = new Proxy({}, { get() { calls++; return 'hostile'; }, ownKeys() { calls++; return []; } });
  const revoked = Proxy.revocable({}, {}); revoked.revoke();
  const cycle = {}; cycle.self = cycle;
  for (const value of [getter, proxy, revoked.proxy, cycle]) {
    for (const validate of [reader.validateExecutionRecord, native.validateExecutionRecord]) {
      const result = validate(value);
      assert.deepEqual(result, { ok: false, errors: ['execution_input_invalid'] });
    }
  }
  assert.equal(calls, 0);
  const f = make(t, 'native-depth');
  f.stateWrite('maintenance/verification_executions/' + 'a'.repeat(64) + '.json', {});
  fs.writeFileSync(path.join(f.state, 'maintenance/verification_executions', 'a'.repeat(64) + '.json'), '{"x":'.repeat(10000) + '0' + '}'.repeat(10000));
  assert.equal(reader.loadExecutionRecord(f.state, 'KVE-' + 'a'.repeat(64)), null);
});

test('currency audit: shared KVE reads reject hardlink aliases and replacement during a physical read', t => {
  const f = make(t, 'native-physical'); const ids = f.verify();
  const file = path.join(f.state, 'maintenance/verification_executions', ids.execution_ids[0].slice(4) + '.json');
  assert(reader.loadExecutionRecord(f.state, ids.execution_ids[0]));
  const alias = path.join(f.root, 'hardlink-kve.json'); fs.linkSync(file, alias);
  assert.equal(reader.loadExecutionRecord(f.state, ids.execution_ids[0]), null);
  assert.equal(native.loadExecutionRecord(f.state, ids.execution_ids[0]), null);
  fs.unlinkSync(alias); assert(reader.loadExecutionRecord(f.state, ids.execution_ids[0]));
  const bytes = fs.readFileSync(file);
  const originalOpen = fs.openSync, originalRead = fs.readSync, originalReadFile = fs.readFileSync;
  const owned = new Set(); let changed = false;
  const replace = () => {
    if (changed) return;
    changed = true;
    fs.renameSync(file, file + '.old'); fs.writeFileSync(file, bytes);
  };
  fs.openSync = function (target, ...args) {
    const fd = originalOpen.call(this, target, ...args);
    if (target === file) owned.add(fd);
    return fd;
  };
  fs.readSync = function (fd, ...args) {
    const result = originalRead.call(this, fd, ...args);
    if (owned.has(fd)) replace();
    return result;
  };
  fs.readFileSync = function (target, ...args) {
    const result = originalReadFile.call(this, target, ...args);
    if (target === file) replace();
    return result;
  };
  let loaded;
  try { loaded = reader.loadExecutionRecord(f.state, ids.execution_ids[0]); }
  finally { fs.openSync = originalOpen; fs.readSync = originalRead; fs.readFileSync = originalReadFile; }
  assert.equal(changed, true, 'replace an actual native KVE inode during the read');
  assert.equal(loaded, null);
});

test('currency audit: recovery rejects alternate index bytes on the exact allowed path before any promotion', t => {
  const f = make(t, 'index-payload'); const ids = f.verify();
  const txRoot = interrupt(f, ids); const ledgers = f.ledgers(); const before = outputSnapshot(f);
  rewriteJournalOutput(txRoot, '/knowledge_currency/index.json', index => ({ ...index, receipt_ids: [] }));
  assert.throws(() => f.issue(ids), { code: 'currency_batch_recovery_binding_invalid' });
  assert.deepEqual(outputSnapshot(f), before);
  assert.deepEqual(f.ledgers(), ledgers);
});

test('currency audit: recovery cannot discard a preserved independent unit through a valid-looking index', t => {
  const f = make(t, 'retained-alpha'); const beta = f.addUnit('retained-beta');
  const preserved = f.issue(f.verify([beta]));
  const ids = f.verify([f.first]); const txRoot = interrupt(f, ids);
  const before = outputSnapshot(f), ledgers = f.ledgers();
  rewriteJournalOutput(txRoot, '/knowledge_currency/index.json', (index, manifest) => ({ ...index, receipt_ids: manifest.metadata.receipt_ids }));
  assert.throws(() => f.issue(ids), { code: 'currency_batch_recovery_binding_invalid' });
  assert.deepEqual(outputSnapshot(f), before);
  assert.deepEqual(f.ledgers(), ledgers);
  assert.deepEqual(JSON.parse(fs.readFileSync(path.join(f.state, 'maintenance/knowledge_currency/index.json'))).receipt_ids, preserved.receipt_ids);
});

test('currency audit: recovery authenticates operation result bytes before a forged assurance claim can be recorded', t => {
  const f = make(t, 'operation-payload'); const ids = f.verify(); const txRoot = interrupt(f, ids);
  const manifest = JSON.parse(fs.readFileSync(path.join(txRoot, 'manifest.json')));
  const suffix = '/knowledge_currency/batches/' + manifest.metadata.operation_id.slice(6) + '.json';
  const before = outputSnapshot(f), ledgers = f.ledgers();
  rewriteJournalOutput(txRoot, suffix, operation => {
    operation.result.security_certificate = true;
    operation.result.application_risks_closed = 1;
    const body = { ...operation }; delete body.operation_id; delete body.content_sha256;
    operation.content_sha256 = currency.currencyDigest(body);
    return operation;
  });
  assert.throws(() => f.issue(ids), { code: 'currency_batch_recovery_binding_invalid' });
  assert.deepEqual(outputSnapshot(f), before);
  assert.deepEqual(f.ledgers(), ledgers);
});

test('currency audit: a mismatched finish binding is rejected before interrupted outputs are replayed', t => {
  const f = make(t, 'finish-binding'); const ids = f.verify(); const checked = batch.checkBatch(f.context, f.batchPath);
  const binding = batch.prepareBatchForFinish(f.context, f.batchPath, { taskId: 'overlay-task', sessionId: 'overlay-session',
    sourceFiles: [f.batchPath, ...checked.children.map(child => child.path), ...checked.pins.filter(pin => !pin.predecessor_receipt_id).map(pin => pin.path)] });
  interrupt(f, ids); const before = outputSnapshot(f); const changed = clone(binding); changed.pins = [];
  assert.throws(() => batch.issueBatch(f.context, f.batchPath, ids.execution_ids, changed, ids.verification_acceptances), { code: 'currency_finish_input_drift' });
  assert.deepEqual(outputSnapshot(f), before);
});

for (const point of ['after_initial_manifest', 'after_stage_0', 'after_stage_1', 'after_stage_2',
  'after_prepare_manifest', 'after_commit_marker', 'after_promote_0', 'after_promote_1', 'after_promote_2']) {
  test('currency audit: genuine interrupted issuance recovers at ' + point, t => {
    const f = make(t, 'stage-' + point.replaceAll('_', '-')); const ids = f.verify(); const ledgers = f.ledgers();
    interrupt(f, ids, point);
    const result = f.issue(ids);
    assert.equal(result.status, 'committed');
    assert.equal(result.security_certificate, false);
    assert.equal(result.application_risks_closed, 0);
    assert.equal(f.evaluate().valid, true);
    assert.deepEqual(f.ledgers(), ledgers);
    assert.deepEqual(f.issue(ids), result);
  });
}

test('currency audit: bundled KVE schema is a shared authority pin with no independent factual coverage', t => {
  const f = make(t, 'schema-authority'); f.addUnit('schema-independent'); f.issue(f.verify());
  const schema = '.knowledge/schemas/verification-execution.schema.json';
  const before = f.evaluate();
  assert.equal(before.files[schema], undefined);
  fs.appendFileSync(path.join(f.root, schema), '\n');
  const after = f.evaluate();
  assert.equal(after.valid, false);
  assert.deepEqual(Object.keys(after.files), []);
  assert(after.issues.some(row => row.code === 'currency_authority_changed'));
});

test('currency audit: cached batch operations cannot forge assurance, identity or immutable binding fields', t => {
  const f = make(t, 'cached-operation'); const ids = f.verify(); const issued = f.issue(ids);
  const relative = 'maintenance/knowledge_currency/batches/' + issued.operation_id.slice(6) + '.json';
  const original = JSON.parse(fs.readFileSync(path.join(f.state, relative)));
  const ledgers = f.ledgers();
  for (const mutate of [
    operation => { operation.result.security_certificate = true; },
    operation => { operation.result.application_risks_closed = 1; },
    operation => { operation.result.open_application_risks = 0; },
    operation => { operation.result.lifecycle_effect = 'closed'; },
    operation => { operation.result.reused_execution_ids = []; },
    operation => { operation.task_id = 'foreign-task'; },
    operation => { operation.binding.pins = []; }
  ]) {
    const changed = clone(original); mutate(changed);
    const body = { ...changed }; delete body.operation_id; delete body.content_sha256;
    changed.content_sha256 = currency.currencyDigest(body);
    f.stateWrite(relative, changed);
    assert.throws(() => batch.validateBatchOperation(f.context, f.batchPath, ids.execution_ids), { code: 'currency_batch_operation_invalid' });
    assert.deepEqual(f.ledgers(), ledgers);
  }
  f.stateWrite(relative, original);
  assert.deepEqual(batch.validateBatchOperation(f.context, f.batchPath, ids.execution_ids), original);
  // The saved open-risk count is historical reporting. A new unrelated unit
  // must not make an unchanged prior result cease to be idempotent.
  f.addUnit('later-unrelated');
  assert.deepEqual(batch.validateBatchOperation(f.context, f.batchPath, ids.execution_ids), original);
  assert.deepEqual(f.issue(ids), issued);
});
