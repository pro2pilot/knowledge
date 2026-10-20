#!/usr/bin/env node
'use strict';

// Records reviewed factual currency. It never certifies application safety.
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { resolveKnowledgeContext } = require('./lib/path-context');
const { assertSafeContainedPath } = require('./lib/json-store');
const { copyInertData } = require('./lib/json-transaction');
const { canonicalPath, lifecycleById } = require('./lib/queue-lifecycle');
const currency = require('./lib/knowledge-currency');

const INDEX = 'maintenance/knowledge_currency/index.json';
const RECEIPTS = 'maintenance/knowledge_currency/receipts';
const hash = (bytes) => crypto.createHash('sha256').update(bytes).digest('hex');
const jsonBytes = (value) => Buffer.from(JSON.stringify(value, null, 2) + '\n');
function fail(code, message) { const e = new Error(message); e.code = code; throw e; }
function artifactJson(body) {
  try { return JSON.parse(body.toString('utf8').replace(/^\uFEFF/, '')); }
  catch { fail('currency_json_malformed', 'A currency dependency is not valid JSON; raw dependency values are omitted.'); }
}
function physical(root, relative, allowMissing = false) {
  const clean = canonicalPath(relative);
  if (clean === '.' || clean === 'unknown' || clean !== String(relative).replace(/\\/g, '/')) fail('currency_path_invalid', 'Use a canonical relative file path.');
  const absolute = path.resolve(root, clean);
  assertSafeContainedPath(root, absolute, { allowMissing });
  let stat;
  try { stat = fs.lstatSync(absolute); } catch (e) { if (allowMissing && e.code === 'ENOENT') return absolute; throw e; }
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || stat.size > 16 * 1024 * 1024) fail('currency_file_unsafe', 'Currency artifacts must be bounded physical files.');
  return absolute;
}
function sourceLocation(context, relative) {
  return relative.startsWith('.knowledge/')
    ? { root: context.projectKnowledgeRoot, relative: relative.slice(11) }
    : { root: context.targetRoot, relative };
}
function readSource(context, relative) {
  const loc = sourceLocation(context, relative);
  const file = physical(loc.root, loc.relative);
  const body = fs.readFileSync(file);
  return { path: file, containmentRoot: loc.root, expected_sha256: hash(body), body };
}
function readState(context, relative, fallback) {
  const file = physical(context.stateRoot, relative, true);
  if (!fs.existsSync(file)) return { value: fallback, guard: { path: file, containmentRoot: context.stateRoot, expected_exists: false } };
  const body = fs.readFileSync(file);
  return { value: artifactJson(body), guard: { path: file, containmentRoot: context.stateRoot, expected_sha256: hash(body) } };
}
function stateInputs(context) {
  const stale = readState(context, 'maintenance/stale_items.json', { items: [] });
  const repair = readState(context, 'maintenance/repair_queue.json', { queue: [] });
  const registryFile = readSource(context, '.knowledge/modules/module_registry.json');
  const registry = artifactJson(registryFile.body);
  // Both views must describe the same identities before any mutation.
  lifecycleById(stale.value, repair.value);
  return { stale, repair, registry, registryFile,
    projections: { staleItems: stale.value, repairQueue: repair.value, registry } };
}
function readRequest(context, relative) {
  const input = readSource(context, relative);
  const request = artifactJson(input.body);
  if (!request || typeof request !== 'object' || Array.isArray(request)) fail('currency_request_invalid', 'A currency request object is required.');
  return { input, request };
}
function collectPins(value, output = []) {
  if (!value || typeof value !== 'object') return output;
  if (typeof value.path === 'string' && /^[a-f0-9]{64}$/.test(String(value.sha256 || ''))) output.push({ path: value.path, sha256: value.sha256 });
  for (const child of Object.values(value)) if (child && typeof child === 'object') collectPins(child, output);
  return output;
}
function uniqueGuards(rows) {
  const byPath = new Map();
  for (const row of rows) {
    const key = process.platform === 'win32' ? path.resolve(row.path).toLowerCase() : path.resolve(row.path);
    const clean = { path: row.path, containmentRoot: row.containmentRoot,
      ...(row.expected_exists === false ? { expected_exists: false } : { expected_sha256: row.expected_sha256 }) };
    const old = byPath.get(key);
    if (old && (old.expected_sha256 !== clean.expected_sha256 || old.expected_exists !== clean.expected_exists)) fail('currency_guard_conflict', 'Conflicting transaction guards.');
    byPath.set(key, clean);
  }
  return [...byPath.values()];
}
function check(context, relative, expectedScope, expectedRisks) {
  const { request } = readRequest(context, relative);
  const inputs = stateInputs(context);
  const prepared = currency.validateCurrencyReview(context, request, inputs.projections);
  if (prepared.scope_sha256 !== expectedScope || prepared.protected_risks_sha256 !== expectedRisks) fail('currency_scope_changed', 'Current source, claims, module scope, or risk inventory differs from the reviewed scope.');
  return { status: 'pass', scope_sha256: expectedScope, protected_risks_sha256: expectedRisks,
    security_certificate: false, routing_cap: 'routing_trusted' };
}
function parse(argv) {
  const [command, ...rest] = argv; const flags = {};
  for (const arg of rest) {
    const m = /^--([a-z-]+)=(.+)$/.exec(arg);
    if (!m || flags[m[1]] !== undefined) fail('currency_argument_invalid', 'Use unique --name=value arguments.');
    flags[m[1]] = m[2];
  }
  if (!['prepare', 'check', 'status', 'prepare-batch', 'check-batch', 'issue-batch'].includes(command)) fail('currency_command_invalid', 'Use prepare, check, status, prepare-batch, check-batch, or issue-batch.');
  const allowed = { prepare: ['request'], check: ['request', 'scope', 'risk-scope'], issue: ['request', 'execution', 'supersede'], status: [],
    'prepare-batch': ['request'], 'check-batch': ['request'], 'issue-batch': ['request', 'execution', 'verification-result'] }[command];
  if (command.endsWith('-batch')) allowed.push('system-root', 'target-root', 'project-knowledge-root', 'state-root', 'team-root', 'workspace-id', 'agent-id');
  if (Object.keys(flags).some((key) => !allowed.includes(key))) fail('currency_argument_invalid', 'Unsupported argument.');
  return { command, flags };
}
function main(argv = process.argv.slice(2), suppliedContext = null) {
  argv = copyInertData(argv);
  if (suppliedContext) suppliedContext = copyInertData(suppliedContext);
  const { command, flags } = parse(argv);
  const context = suppliedContext || resolveKnowledgeContext({ ...flags, __skipCli: true });
  if (command === 'status') return currency.evaluateCurrency(context);
  if (!flags.request) fail('currency_request_required', 'A request file is required.');
  if (command.endsWith('-batch')) {
    const batch = require('./lib/knowledge-currency-batch');
    if (command === 'prepare-batch') return batch.prepareBatch(context, flags.request);
    if (command === 'check-batch') return batch.checkBatch(context, flags.request);
    if (!flags['verification-result']) fail('verification_finalization_required', 'Pass --verification-result=<native-verify-result.json>.');
    const verified = readRequest(context, flags['verification-result']).request;
    return batch.issueBatch(context, flags.request, String(flags.execution || '').split(',').filter(Boolean), null, verified.verification_acceptances);
  }
  if (command === 'prepare') {
    const { request } = readRequest(context, flags.request);
    return currency.prepareCurrencyScope(context, request, stateInputs(context).projections);
  }
  if (command === 'check') return check(context, flags.request, flags.scope, flags['risk-scope']);
  fail('currency_command_invalid', 'Issuance requires an exact-input-bound batch request.');
}
function publicMain(argv = process.argv.slice(2), suppliedContext = null) {
  try { return main(argv, suppliedContext); }
  catch (error) {
    if (error.code === 'currency_recording_blocked') {
      const context = suppliedContext || resolveKnowledgeContext();
      const blockers = require('./lib/recording-blockers');
      const registered = blockers.registerBlocker(context, { field:'currency_evidence', value:'masked currency evidence',
        session_id:process.env.KNOWLEDGE_SESSION_ID, language:blockers.language(context) });
      error.chat_notice = registered.chat_notice + (registered.blocker.notice_language === 'ru' ? ' Поля currency: ' : ' Currency fields: ') + error.blocked_fields.join(', ');
      error.recording_blocker_id = registered.blocker.id;
    }
    throw error;
  }
}
module.exports = { main: publicMain, check, collectPins, uniqueGuards,
  __batchPrimitives: { physical, readSource, readState, stateInputs, readRequest, fail, hash, jsonBytes, INDEX, RECEIPTS } };

// Batch commands import these primitives while main is executing. Publish the
// complete interface first, for both require() callers and native CLI children.
if (require.main === module) {
  try { console.log(JSON.stringify(publicMain(), null, 2)); }
  catch (e) { console.error(JSON.stringify({ status: 'failed', code: e.code || 'currency_failed',
    // Filesystem and parser errors may contain a private path or raw JSON.
    // Keep the diagnosis code; only the intentionally masked notice is public.
    message: 'Currency command failed. Inspect the issue code and any masked recording notice; raw dependency values are omitted.',
    ...(e.chat_notice ? {chat_notice:e.chat_notice,recording_blocker_id:e.recording_blocker_id} : {}) })); process.exitCode = 1; }
}

