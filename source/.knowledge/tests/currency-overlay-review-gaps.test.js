'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { spawnSync } = require('child_process');
const { fixture, clone, hash } = require('./helpers/currency-overlay');
const blockers = require('../tools/lib/recording-blockers');

const cliPath = path.resolve(__dirname, '../tools/knowledge-currency.js');
const stable = value => {
  if (Array.isArray(value)) return `[${value.map(stable).join(',')}]`;
  if (value && typeof value === 'object') return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${stable(value[key])}`).join(',')}}`;
  return JSON.stringify(value);
};
const jsonBytes = value => Buffer.from(JSON.stringify(value, null, 2) + '\n');
const writeJson = (file, value) => fs.writeFileSync(file, jsonBytes(value));
function txDirectory(f) {
  const parent = path.join(f.state, 'maintenance/transactions');
  const entries = fs.readdirSync(parent, { withFileTypes:true }).filter(row => row.isDirectory());
  assert.equal(entries.length, 1, 'expected exactly one owned transaction journal');
  return path.join(parent, entries[0].name);
}
function ownedJson(file) { return JSON.parse(fs.readFileSync(file, 'utf8')); }
function interrupt(f, executions, point = 'after_commit_marker') {
  const previous = process.env.KNOWLEDGE_TRANSACTION_FAULT;
  process.env.KNOWLEDGE_TRANSACTION_FAULT = point;
  try {
    assert.throws(() => f.issue(executions), error => error.code === 'transaction_fault_injected');
  } finally {
    if (previous === undefined) delete process.env.KNOWLEDGE_TRANSACTION_FAULT;
    else process.env.KNOWLEDGE_TRANSACTION_FAULT = previous;
  }
  return txDirectory(f);
}
function cliArgs(f) {
  return [
    `--system-root=${f.context.systemRoot}`,
    `--target-root=${f.context.targetRoot}`,
    `--project-knowledge-root=${f.context.projectKnowledgeRoot}`,
    `--state-root=${f.context.stateRoot}`,
    '--agent-id=a344-rc2-local-baseline'
  ];
}
function runCli(f, command, extras = []) {
  const env = { ...process.env, KNOWLEDGE_AGENT_ID:'a344-rc2-local-baseline', KNOWLEDGE_DISABLE_GIT_DISCOVERY:'1' };
  delete env.KNOWLEDGE_TRANSACTION_FAULT;
  const result = spawnSync(process.execPath, [cliPath, command, `--request=${f.batchPath}`, ...extras, ...cliArgs(f)], {
    cwd:f.root, env, encoding:'utf8', windowsHide:true, timeout:60000
  });
  return result;
}
function replaceJournalReceiptIds(txRoot, replacement) {
  const manifestPath = path.join(txRoot, 'manifest.json');
  const preparedPath = path.join(txRoot, 'prepared.json');
  const manifest = ownedJson(manifestPath);
  manifest.metadata.receipt_ids = replacement;
  manifest.intent.metadata = clone(manifest.metadata);
  manifest.intent_sha256 = hash(Buffer.from(stable(manifest.intent)));
  const bytes = jsonBytes(manifest);
  fs.writeFileSync(manifestPath, bytes);
  fs.writeFileSync(preparedPath, bytes);
  const markerPath = path.join(txRoot, 'commit.json');
  const marker = ownedJson(markerPath);
  marker.manifest_sha256 = hash(bytes);
  writeJson(markerPath, marker);
}

test('opened_at-only drift with unchanged identity and occurrence invalidates previous currency', t => {
  const f = fixture(t, 'date-only');
  const executions = f.verify();
  f.issue(executions);
  const before = f.findings.map(row => ({ lifecycle_id:row.lifecycle_id, identity_sha256:row.identity_sha256, occurrence:row.occurrence }));
  const row = f.findings.find(item => item.code === 'tracked_file_needs_recheck');
  assert(row);
  row.opened_at = '2026-01-01T00:00:01.000Z';
  f.persist();
  const after = f.findings.filter(item => item.lifecycle_id === row.lifecycle_id);
  assert.equal(after.length, 1);
  assert.equal(after[0].identity_sha256, before.find(item => item.lifecycle_id === row.lifecycle_id).identity_sha256);
  assert.equal(after[0].occurrence, before.find(item => item.lifecycle_id === row.lifecycle_id).occurrence);
  const evaluation = f.evaluate();
  assert.equal(evaluation.valid, false);
  assert(evaluation.issues.some(issue => ['currency_finding_binding_changed','currency_scope_drift','currency_native_finding_mismatch'].includes(issue.code)));
});

test('physical child-process CLI issue-batch commits native batch and preserves raw ledgers', t => {
  const f = fixture(t, 'cli-issue');
  const verification = f.verify();
  const before = f.ledgers();
  const verificationResult = '.knowledge/maintenance/native-verification-result.json';
  f.write(verificationResult, { verification_acceptances: verification.verification_acceptances });
  const result = runCli(f, 'issue-batch', [
    `--execution=${verification.execution_ids.join(',')}`,
    `--verification-result=${verificationResult}`
  ]);
  assert.equal(result.error, undefined);
  assert.equal(result.status, 0);
  const output = JSON.parse(result.stdout.trim());
  assert.equal(output.status, 'committed');
  assert.equal(output.lifecycle_effect, 'none');
  assert.deepEqual(f.ledgers(), before);
  assert.equal(f.evaluate().valid, true);
});

test('physical child-process CLI emits masked Russian blocker with no secret in output, registry, or receipt', t => {
  const f = fixture(t, 'cli-private');
  f.prepareBatch();
  const secret = 'synthetic_private_value_DO_NOT_LEAK_93b1';
  const risk = f.findings.find(row => row.code === 'security_finding');
  assert(risk);
  risk.reason = `password=${secret}`;
  f.persist();
  const previousLanguage = process.env.KNOWLEDGE_USER_LANGUAGE;
  process.env.KNOWLEDGE_USER_LANGUAGE = 'ru';
  let result;
  try { result = runCli(f, 'prepare-batch'); }
  finally {
    if (previousLanguage === undefined) delete process.env.KNOWLEDGE_USER_LANGUAGE;
    else process.env.KNOWLEDGE_USER_LANGUAGE = previousLanguage;
  }
  assert.equal(result.error, undefined);
  assert.equal(result.status, 1);
  const outputText = `${result.stdout || ''}\n${result.stderr || ''}`;
  assert(!outputText.includes(secret), 'child CLI output leaked synthetic private text');
  const payload = JSON.parse((result.stderr || result.stdout).trim());
  assert.equal(payload.code, 'currency_recording_blocked');
  assert.match(payload.chat_notice, /заблокирована/i);
  assert.match(payload.chat_notice, /Inspector/i);
  const registry = blockers.listBlockers(f.context);
  assert(!JSON.stringify(registry).includes(secret), 'recording registry leaked synthetic private text');
  assert.equal(registry.blockers.length, 1);
  assert.equal(registry.blockers[0].preview, '********');
  assert.equal(registry.blockers[0].notice_language, 'ru');
  assert(!fs.existsSync(path.join(f.state, 'maintenance/knowledge_currency/receipts')));
  assert(!fs.existsSync(path.join(f.state, 'maintenance/knowledge_currency/index.json')));
});

test('self-consistent hostile journal receipt_ids cannot choose replacement receipt outputs', t => {
  const f = fixture(t, 'journal-metadata');
  const executions = f.verify();
  const before = f.ledgers();
  const txRoot = interrupt(f, executions);
  const replacement = ['KCUR-' + 'f'.repeat(64)];
  replaceJournalReceiptIds(txRoot, replacement);
  assert.throws(() => f.issue(executions), error => error.code === 'currency_batch_recovery_binding_invalid');
  assert.deepEqual(f.ledgers(), before);
  assert(!fs.existsSync(path.join(f.state, 'maintenance/knowledge_currency/index.json')));
  assert(!fs.existsSync(path.join(f.state, 'maintenance/knowledge_currency/receipts', 'f'.repeat(64) + '.json')));
});

test('same transaction ID with a different valid journal intent cannot replay foreign output paths', t => {
  const f = fixture(t, 'swap-a');
  const foreignUnit = f.addUnit('swap-b');
  const aExecutions = f.verify([f.first]);
  const aBefore = f.ledgers();
  const aTx = interrupt(f, aExecutions);
  const aId = path.basename(aTx);
  const batchPath = path.join(f.root, f.batchPath);
  const aBatch = fs.readFileSync(batchPath);
  const bExecutions = f.verify([foreignUnit]);
  const bInterrupted = (() => {
    const previous = process.env.KNOWLEDGE_TRANSACTION_FAULT;
    process.env.KNOWLEDGE_TRANSACTION_FAULT = 'after_commit_marker';
    try { assert.throws(() => f.issue(bExecutions), error => error.code === 'transaction_fault_injected'); }
    finally { if (previous === undefined) delete process.env.KNOWLEDGE_TRANSACTION_FAULT; else process.env.KNOWLEDGE_TRANSACTION_FAULT = previous; }
    return true;
  })();
  assert(bInterrupted);
  fs.writeFileSync(batchPath, aBatch);
  const transactionDirs = fs.readdirSync(path.join(f.state, 'maintenance/transactions'), { withFileTypes:true })
    .filter(row => row.isDirectory()).map(row => path.join(f.state, 'maintenance/transactions', row.name));
  const actualBTx = transactionDirs.find(dir => dir !== aTx);
  assert(actualBTx, 'expected a second owned transaction journal');
  const aIntent = ownedJson(path.join(aTx, 'manifest.json')).intent_sha256;
  const bManifest = ownedJson(path.join(actualBTx, 'manifest.json'));
  assert.notEqual(aId, path.basename(actualBTx));
  assert.notEqual(bManifest.intent_sha256, aIntent);
  fs.cpSync(actualBTx, aTx, { recursive:true, force:true });
  const swapped = ownedJson(path.join(aTx, 'manifest.json'));
  swapped.transaction_id = aId;
  const bytes = jsonBytes(swapped);
  fs.writeFileSync(path.join(aTx, 'manifest.json'), bytes);
  fs.writeFileSync(path.join(aTx, 'prepared.json'), bytes);
  const commitPath = path.join(aTx, 'commit.json');
  const commit = ownedJson(commitPath);
  commit.transaction_id = aId;
  commit.manifest_sha256 = hash(bytes);
  writeJson(commitPath, commit);
  assert.equal(ownedJson(path.join(aTx, 'manifest.json')).transaction_id, aId);
  assert.equal(ownedJson(path.join(aTx, 'manifest.json')).intent_sha256, bManifest.intent_sha256);
  assert.throws(() => f.issue(aExecutions), error => error.code === 'transaction_write_policy_denied');
  assert.deepEqual(f.ledgers(), aBefore);
  assert(!fs.existsSync(path.join(f.state, 'maintenance/knowledge_currency/index.json')));
});
