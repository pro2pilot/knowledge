#!/usr/bin/env node
'use strict';
const assert = require('assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const native = require('./lib/repair-on-touch');
const core = require('./lib/verification-execution');
const final = require('./lib/verification-finalization');
const { removeTempDirStrict } = require('./lib/strict-temp-cleanup');
const root = fs.mkdtempSync(path.join(os.tmpdir(), 'k-final-'));
const state = path.join(root, '.knowledge'); fs.mkdirSync(state);
const checks = [];
function check(name, fn) { fn(); checks.push({ name, status: 'pass' }); }
function deny(fn) { assert.throws(fn, error => error.code === 'verification_finalization_required'); }
const clone = value => JSON.parse(JSON.stringify(value));
const request = tests => ({ stateRoot: state, repoRoot: root, taskId: 'finalization-test', sessionId: 'finalization-session',
  checkedBy: 'finalization-test', tests: tests.map(file => ({ argv: ['node', file], cwd: '.', timeout_ms: 10000 })),
  timeoutMs: 20000, sourceFiles: ['pass.js', 'fail.js'] });
function portableReaderFixture(legacyPaths = null) {
  // Signed data exercises the production semantic reader on every platform.
  // These records are explicitly synthetic; no native command ran here.
  const keys = crypto.generateKeyPairSync('ed25519');
  const key = keys.publicKey.export({ type: 'spki', format: 'der' }).toString('hex');
  const batchId = 'KVB-' + crypto.randomBytes(16).toString('hex');
  const runtime = final.hash(fs.readFileSync(process.execPath));
  const requestHash = final.digest({ taskId: 'synthetic-reader-task', sessionId: 'synthetic-reader-session' });
  const snapshot = [{ path: 'pass.js', sha256: final.hash(fs.readFileSync(path.join(root, 'pass.js'))) }];
  function save(record) {
    record.content_sha256 = native.executionDigest(record); record.execution_id = 'KVE-' + record.content_sha256;
    const body = Buffer.from(JSON.stringify(record) + '\n');
    const directory = path.join(state, 'maintenance/verification_executions'); fs.mkdirSync(directory, { recursive: true });
    const file = path.join(directory, record.content_sha256 + '.json'); fs.writeFileSync(file, body);
    return { record, path: file, physical_sha256: final.hash(body) };
  }
  const executions = [0, 1].map(ordinal => save({ schema_version: 'knowledge-verification-execution.v2',
    task_id: 'synthetic-reader-task', session_id: 'synthetic-reader-session', command_argv: ['node', 'pass.js'], command: 'node pass.js',
    cwd: '.', status: 'pass', exit_code: 0, signal: null, timed_out: false, duration_ms: 1,
    executed_at: new Date().toISOString(), executed_by: 'synthetic-reader-fixture', runtime_binding: 'process_exec_path',
    runtime_sha256: runtime, environment_profile: 'sanitized_node', stdout_sha256: final.hash(''), stderr_sha256: final.hash(''),
    stdout_bytes: 0, stderr_bytes: 0, source_snapshot_before: snapshot, source_snapshot: snapshot,
    batch_id: batchId, batch_ordinal: ordinal, batch_public_key: key, batch_request_sha256: requestHash }));
  const receipt = { schema_version: legacyPaths ? final.LEGACY_SCHEMA : final.SCHEMA, batch_id: batchId, public_key: key, request_sha256: requestHash,
    task_id: 'synthetic-reader-task', session_id: 'synthetic-reader-session', status: 'commands_and_teardown_observed',
    backend: 'windows_job_object', teardown: { status: 'completed', method: 'windows_job_object', active_processes: 0, ...(!legacyPaths ? {keeper_exited:true} : {}) },
    timeout_ms: 1000, observed_elapsed_ms: legacyPaths ? 10 : 900, runtime_sha256: runtime,
    ...(!legacyPaths ? {work_elapsed_ms:800,cleanup_budget_ms:400} : {}),
    implementation: (legacyPaths || final.IMPLEMENTATION_PATHS).map(file => ({ path: file, sha256: final.hash(fs.readFileSync(path.join(__dirname, '..', file))) })),
    executions: executions.map(item => ({ execution_id: item.record.execution_id, physical_sha256: item.physical_sha256 })) };
  function accept(edit = () => {}) {
    const value = clone(receipt); edit(value);
    const digest = final.digest(value), body = Buffer.from(JSON.stringify(value) + '\n');
    const directory = path.join(state, 'maintenance/verification_finalizations'); fs.mkdirSync(directory, { recursive: true });
    const file = path.join(directory, digest + '.json'); fs.writeFileSync(file, body);
    const reference = { receipt_id: 'KVF-' + digest, physical_sha256: final.hash(body), batch_id: value.batch_id };
    const unsigned={schema_version:final.LEGACY_ACK_SCHEMA,...reference,timeout_ms:1000,accepted_elapsed_ms:20};
    const stable=value=>JSON.stringify(value,(_,item)=>item&&typeof item==='object'&&!Array.isArray(item)?Object.fromEntries(Object.keys(item).sort().map(key=>[key,item[key]])):item);
    const ack=legacyPaths ? {...unsigned,signature:crypto.sign(null,Buffer.from(stable(unsigned)),keys.privateKey).toString('hex')}
      : final.acceptFinalization(reference,1000,1100,keys.privateKey,{work_elapsed_ms:receipt.work_elapsed_ms,cleanup_budget_ms:receipt.cleanup_budget_ms});
    return { file, reference, ack };
  }
  return { executions, ids: executions.map(item => item.record.execution_id), receipt, keys, save, accept };
}
try {
  fs.writeFileSync(path.join(root, 'pass.js'), 'process.stdout.write("ok");\n');
  fs.writeFileSync(path.join(root, 'fail.js'), 'process.exitCode=3;\n');
  const portable = portableReaderFixture(), accepted = portable.accept();
  check('synthetic selected subset retains every physical batch dependency', () => {
    const loaded = final.requireFinalizedExecutions(state, [portable.ids[0]], [accepted.ack]);
    assert.equal(loaded.status, 'accepted'); assert.equal(loaded.execution_records.length, 2);
    assert.deepEqual(loaded.bindings.map(pin => pin.path).sort(), [...portable.executions.map(item => item.path), accepted.file].sort());
    assert.deepEqual(loaded.bindings.find(pin => pin.path === accepted.file).execution_ids, portable.ids);
  });
  check('synthetic persisted batch without terminal ACK has no authority', () => deny(() => final.requireFinalizedExecutions(state, portable.ids, [])));
  check('synthetic v2 work and cleanup boundaries remain separate', () => {
    const timing={work_elapsed_ms:800,cleanup_budget_ms:400};
    for (const elapsed of [1200,1201]) deny(() => final.acceptFinalization(accepted.reference,1000,elapsed,portable.keys.privateKey,timing));
    for(const work_elapsed_ms of [1000,1001])deny(()=>final.acceptFinalization(accepted.reference,1000,1100,portable.keys.privateKey,{work_elapsed_ms,cleanup_budget_ms:400}));
    const timely = final.acceptFinalization(accepted.reference,1000,1100,portable.keys.privateKey,timing);
    assert(timely.accepted_elapsed_ms > timely.timeout_ms);
    assert.equal(final.requireFinalizedExecutions(state, portable.ids, [timely]).status, 'accepted');
  });
  for(const paths of [final.LEGACY_IMPLEMENTATION_PATHS,final.PREVIOUS_IMPLEMENTATION_PATHS])check('legacy v1 exact '+paths.length+'-pin reader format keeps its original timing',()=>{
    const legacy=portableReaderFixture(paths),acceptedLegacy=legacy.accept();
    assert.equal(final.requireFinalizedExecutions(state,legacy.ids,[acceptedLegacy.ack]).status,'accepted');
    const unsigned={...acceptedLegacy.ack,accepted_elapsed_ms:1000};delete unsigned.signature;
    const stable=value=>JSON.stringify(value,(_,item)=>item&&typeof item==='object'&&!Array.isArray(item)?Object.fromEntries(Object.keys(item).sort().map(key=>[key,item[key]])):item);
    const late={...unsigned,signature:crypto.sign(null,Buffer.from(stable(unsigned)),legacy.keys.privateKey).toString('hex')};
    deny(()=>final.requireFinalizedExecutions(state,legacy.ids,[late]));
  });
  for (const [name, edit] of [
    ['wrong ordinal', record => { record.batch_ordinal = 0; }],
    ['wrong request hash', record => { record.batch_request_sha256 = '0'.repeat(64); }],
    ['wrong public key', record => { record.batch_public_key = crypto.generateKeyPairSync('ed25519').publicKey.export({ type: 'spki', format: 'der' }).toString('hex'); }],
    ['failed later sibling', record => { record.status = 'fail'; record.exit_code = 3; }]
  ]) check('synthetic selected subset rejects ' + name, () => {
    const record = clone(portable.executions[1].record); edit(record); const changed = portable.save(record);
    const acknowledgement = portable.accept(receipt => { receipt.executions[1] = { execution_id: changed.record.execution_id, physical_sha256: changed.physical_sha256 }; });
    deny(() => final.requireFinalizedExecutions(state, [portable.ids[0]], [acknowledgement.ack]));
  });
  check('synthetic unselected physical KVE drift invalidates the subset', () => {
    const file = portable.executions[1].path, original = fs.readFileSync(file); fs.appendFileSync(file, '\n');
    try { deny(() => final.requireFinalizedExecutions(state, [portable.ids[0]], [accepted.ack])); }
    finally { fs.writeFileSync(file, original); }
  });
  if (process.platform !== 'win32') {
    check('unsupported native backend refuses before execution', () => assert.throws(() => native.runVerificationTests(request(['pass.js'])), e => e.code === 'verification_containment_unavailable'));
  } else {
    check('real numeric identities match KVE and KVF while raw request remains pinned', () => {
      const input = { ...request(['pass.js']), taskId: 7, sessionId: 19 };
      const result = native.runVerificationTests(input);
      assert.equal(result[0].record.task_id, '7'); assert.equal(result[0].record.session_id, '19');
      const acknowledgement = result.verification_acceptances;
      const receipt = core.readNativeRecord(state, acknowledgement[0].receipt_id.slice(4), 'verification_finalizations').record;
      assert.equal(receipt.task_id, '7'); assert.equal(receipt.session_id, '19');
      assert.equal(receipt.request_sha256, final.digest(input));
      assert.equal(final.requireFinalizedExecutions(state, [result[0].record.execution_id], acknowledgement).status, 'accepted');
    });
    const result = native.runVerificationTests(request(['pass.js', 'pass.js']));
    const ids = result.map(item => item.record.execution_id), acks = result.verification_acceptances;
    check('public crypto encodings cannot resemble private paths or secret prefixes', () => {
      assert.match(acks[0].signature, /^[a-f0-9]{128}$/);
      assert.match(result[0].record.batch_public_key, /^[a-f0-9]{88}$/);
      assert.deepEqual(core.privateValuePaths(acks), []); assert.deepEqual(core.secretPaths(acks), []);
      // This was a possible encoding of public signature bytes, not a path.
      const bytes = Buffer.alloc(64); bytes[0] = 252; bytes[6] = 255;
      assert(core.privateValuePaths({ signature: bytes.toString('base64') }).length);
      assert.deepEqual(core.privateValuePaths({ signature: bytes.toString('hex') }), []);
    });
    check('real two-command batch has distinct ordinal-bound KVE', () => assert.equal(new Set(ids).size, 2));
    check('real complete batch accepted after Windows job teardown', () => assert.equal(final.requireFinalizedExecutions(state, ids, acks).status, 'accepted'));
    check('selected KVE reuse still validates entire batch', () => assert.equal(final.requireFinalizedExecutions(state, [ids[0]], acks).status, 'accepted'));
    check('persisted receipt alone cannot authorize lost terminal response', () => deny(() => final.requireFinalizedExecutions(state, ids, [])));
    check('shared reader explicitly requires acceptance', () => assert.equal(core.loadExecutionRecord(state, ids[0]).finalization_attestation, 'acceptance_required'));
    check('acceptance outside cleanup allowance fails', () => deny(() => final.requireFinalizedExecutions(state, ids, [{ ...acks[0], accepted_elapsed_ms: acks[0].work_elapsed_ms+acks[0].cleanup_budget_ms }])));
    check('wrong batch acceptance fails', () => deny(() => final.requireFinalizedExecutions(state, ids, [{ ...acks[0], batch_id: 'KVB-' + '0'.repeat(32) }])));
    check('wrong physical receipt hash fails', () => deny(() => final.requireFinalizedExecutions(state, ids, [{ ...acks[0], physical_sha256: '0'.repeat(64) }])));
    check('synthesized unsigned acceptance cannot promote persisted receipt', () => { const invented = { ...acks[0] }; delete invented.signature; deny(() => final.requireFinalizedExecutions(state, ids, [invented])); });
    check('duplicate acceptance fails', () => deny(() => final.requireFinalizedExecutions(state, ids, [acks[0], acks[0]])));
    for (const [name, signature] of [['base64', Buffer.from(acks[0].signature, 'hex').toString('base64')], ['odd length', acks[0].signature.slice(1)], ['nonhex', 'z'.repeat(128)]]) {
      check(name + ' signature encoding fails', () => deny(() => final.requireFinalizedExecutions(state, ids, [{ ...acks[0], signature }])));
    }
    const receipt = core.readNativeRecord(state, acks[0].receipt_id.slice(4), 'verification_finalizations').record;
    // Reader-semantic negatives use an explicitly synthetic, signed fixture,
    // so a signature mismatch cannot mask a missing semantic check.
    const fixtureKeys = crypto.generateKeyPairSync('ed25519');
    const fixtureKey = fixtureKeys.publicKey.export({ type: 'spki', format: 'der' }).toString('hex');
    const synthetic = clone(receipt); synthetic.public_key = fixtureKey;
    synthetic.executions = result.map(item => {
      const record = { ...clone(item.record), batch_public_key: fixtureKey };
      record.content_sha256 = native.executionDigest(record); record.execution_id = 'KVE-' + record.content_sha256;
      const saved = native.saveExecutionRecord(state, record);
      return { execution_id: record.execution_id, physical_sha256: saved.physical_sha256 };
    });
    const syntheticIds = synthetic.executions.map(item => item.execution_id);
    check('invented signature cannot authorize original real batch', () => {
      const forged = final.acceptFinalization({ receipt_id: acks[0].receipt_id, physical_sha256: acks[0].physical_sha256, batch_id: acks[0].batch_id }, acks[0].timeout_ms, acks[0].accepted_elapsed_ms, fixtureKeys.privateKey,
        {work_elapsed_ms:acks[0].work_elapsed_ms,cleanup_budget_ms:acks[0].cleanup_budget_ms});
      deny(() => final.requireFinalizedExecutions(state, ids, [forged]));
    });
    function changedReceipt(edit) {
      const value = clone(synthetic); edit(value);
      const digest = final.digest(value), body = Buffer.from(JSON.stringify(value) + '\n');
      const file = path.join(state, 'maintenance/verification_finalizations', digest + '.json');
      fs.writeFileSync(file, body);
      return [final.acceptFinalization({ receipt_id: 'KVF-' + digest, physical_sha256: final.hash(body), batch_id: value.batch_id }, acks[0].timeout_ms, acks[0].accepted_elapsed_ms, fixtureKeys.privateKey,
        {work_elapsed_ms:acks[0].work_elapsed_ms,cleanup_budget_ms:acks[0].cleanup_budget_ms})];
    }
    check('synthetic signature control reaches semantic reader', () => assert.equal(final.requireFinalizedExecutions(state, syntheticIds, changedReceipt(() => {})).status, 'accepted'));
    check('strict batch privacy includes unselected members; policy deferral is explicit', () => {
      const record = { ...clone(result[1].record), batch_public_key: fixtureKey };
      const shaped = 'docs/' + ['sk', 'live', 'J'.repeat(37)].join('_') + '.md'; // Deliberately artificial privacy fixture; never a provider credential.
      record.source_snapshot[0].path = shaped; record.source_snapshot_before[0].path = shaped;
      record.content_sha256 = native.executionDigest(record); record.execution_id = 'KVE-' + record.content_sha256;
      const body = Buffer.from(JSON.stringify(record) + '\n');
      fs.writeFileSync(path.join(state, 'maintenance/verification_executions', record.content_sha256 + '.json'), body);
      assert.deepEqual(core.validateExecutionRecord(record).errors, ['execution_secret_like_value']);
      const ack = changedReceipt(r => { r.executions[1] = { execution_id: record.execution_id, physical_sha256: final.hash(body) }; });
      deny(() => final.requireFinalizedExecutions(state, [syntheticIds[0]], ack));
      const structural = final.requireFinalizedExecutions(state, [syntheticIds[0]], ack, 'caller_policy_required');
      assert.equal(structural.status, 'cryptographically_finalized'); assert.equal(structural.privacy_status, 'not_evaluated');
      assert.equal(structural.execution_records.length, 2);
      assert.equal(core.loadExecutionRecord(state, record.execution_id), null);
    });
    for (const [name, edit] of [
      ['unconfirmed teardown', r => { r.teardown.status = 'unconfirmed'; }],
      ['surviving job member', r => { r.teardown.active_processes = 1; }],
      ['missing keeper exit', r => { delete r.teardown.keeper_exited; }],
      ['unconfirmed keeper exit', r => { r.teardown.keeper_exited = false; }],
      ['work at its deadline', r => { r.work_elapsed_ms = r.timeout_ms; }],
      ['work timing differs from ACK', r => { r.work_elapsed_ms += 1; }],
      ['cleanup timing differs from ACK', r => { r.cleanup_budget_ms += 1; }],
      ['reordered commands', r => { r.executions.reverse(); }],
      ['wrong runtime identity', r => { r.runtime_sha256 = '0'.repeat(64); }],
      ['wrong task identity', r => { r.task_id = 'other'; }],
      ['base64 public key', r => { r.public_key = Buffer.from(r.public_key, 'hex').toString('base64'); }],
      ['odd-length public key', r => { r.public_key = r.public_key.slice(1); }],
      ['nonhex public key', r => { r.public_key = 'z'.repeat(88); }],
      ['missing implementation pin', r => { r.implementation.pop(); }],
      ['extra implementation pin', r => { r.implementation.push(r.implementation[0]); }],
      ['duplicated implementation path', r => { r.implementation[1].path = r.implementation[0].path; }],
      ['reordered implementation paths', r => { r.implementation.reverse(); }],
      ['receipt observed after acceptance', r => { r.observed_elapsed_ms = acks[0].accepted_elapsed_ms + 1; }]
    ]) check(name + ' cannot certify', () => deny(() => final.requireFinalizedExecutions(state, syntheticIds, changedReceipt(edit))));
    check('legacy command evidence stays readable but unattested', () => {
      const record = clone(result[0].record); record.schema_version = 'knowledge-verification-execution.v1';
      delete record.batch_id; delete record.batch_ordinal; delete record.batch_public_key; delete record.batch_request_sha256;
      record.content_sha256 = native.executionDigest(record); record.execution_id = 'KVE-' + record.content_sha256;
      native.saveExecutionRecord(state, record);
      assert.equal(core.loadExecutionRecord(state, record.execution_id).finalization_attestation, 'legacy_unattested');
      deny(() => final.requireFinalizedExecutions(state, [record.execution_id], acks));
    });
    // Physical signing/readback/receipt-I/O stalls are exercised through the
    // current authority process in tests/native-watchdog-deadline.test.js.
    check('later command failure leaves partial KVE without usable acceptance', () => {
      let error; try { native.runVerificationTests(request(['pass.js', 'fail.js'])); } catch (caught) { error = caught; }
      assert(error); assert.equal(error.completed_executions.length, 1);
      const partial = error.completed_executions[0].execution_id;
      assert(core.loadExecutionRecord(state, partial));
      deny(() => final.requireFinalizedExecutions(state, [partial], acks));
    });
  }
  console.log(JSON.stringify({ status: 'pass', checks_total: checks.length, checks,
    evidence_kind: process.platform === 'win32'
      ? 'synthetic signed reader checks plus isolated physical native Windows execution'
      : 'synthetic signed reader checks plus actual POSIX containment refusal; no native command execution' }, null, 2));
} finally { removeTempDirStrict(root); }
