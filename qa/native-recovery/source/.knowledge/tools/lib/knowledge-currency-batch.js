'use strict';

// Native factual currency only. Reviews are supplied independently, never made
// here. Shared predecessors may split into disjoint children; supporting engine
// pins may be shared, but factual closure/claim/module ownership may not.
const fs = require('fs');
const path = require('path');
const currency = require('./knowledge-currency');
const cli = require('../knowledge-currency');
const { physical, readSource, readState, stateInputs, readRequest, fail, hash, jsonBytes, INDEX, RECEIPTS } = cli.__batchPrimitives;
const { lifecycleById } = require('./queue-lifecycle');
const { loadExecutionRecord } = require('./verification-execution');
const { withContainedLock } = require('./contained-lock-manager');
const { LOCKS } = require('./lock-policy');
const { withResourceAvailable } = require('./verification-control');
const { commitJsonTransaction, inspectTransaction, recoverOne, copyInertData } = require('./json-transaction');
const { assertSafeContainedPath } = require('./json-store');

const BATCH_SCHEMA = 'knowledge-currency-batch-request.v1';
const OPERATION_SCHEMA = 'knowledge-currency-batch-operation.v1';
const BINDING_SCHEMA = 'knowledge-currency-finish-binding.v1';
const MAX_CHILDREN = 64;
const HASH = /^[a-f0-9]{64}$/;
const KCUR = /^KCUR-[a-f0-9]{64}$/;
const KVE = /^KVE-[a-f0-9]{64}$/;
const OPERATIONS = 'maintenance/knowledge_currency/batches';
const same = (a, b) => currency.canonicalJson(a) === currency.canonicalJson(b);
function requireThat(value, code, message) { if (!value) fail(code, message || code); }
function object(value) { return value !== null && typeof value === 'object' && !Array.isArray(value); }
function strict(value, keys, code) {
  requireThat(object(value) && Object.keys(value).length === keys.length && keys.every(key => Object.prototype.hasOwnProperty.call(value, key)), code);
}
function relative(value) {
  requireThat(typeof value === 'string' && value.length > 0 && value === value.trim() &&
    !/[\\\x00-\x1f\x7f:*?]/.test(value) && !value.startsWith('/') &&
    value.split('/').every(part => part && part !== '.' && part !== '..' && part === part.trim() && !/[. ]$/.test(part)), 'currency_batch_path_invalid');
  return value;
}
function identity(value) {
  requireThat(typeof value === 'string' && value.length > 0 && value === value.trim() && !/[\x00-\x1f\x7f]/.test(value), 'currency_batch_identity_invalid');
  return value;
}
function unique(values, key, code) {
  const seen = new Set();
  for (const value of values) { const item = key(value); requireThat(!seen.has(item), code); seen.add(item); }
  return values;
}
function ids(value, pattern, code, nonempty = false) {
  requireThat(Array.isArray(value) && value.length <= MAX_CHILDREN && (!nonempty || value.length > 0) && value.every(id => typeof id === 'string' && pattern.test(id)), code);
  return unique([...value], id => id, code).sort();
}
function readBatch(context, relativePath) {
  const requestPath = relative(relativePath);
  const loaded = readRequest(context, requestPath);
  strict(loaded.request, ['schema_version', 'task_id', 'session_id', 'requests', 'supersedes'], 'currency_batch_schema_invalid');
  const batch = loaded.request;
  requireThat(batch.schema_version === BATCH_SCHEMA, 'currency_batch_schema_invalid');
  identity(batch.task_id); identity(batch.session_id);
  requireThat(Array.isArray(batch.requests) && batch.requests.length > 0 && batch.requests.length <= MAX_CHILDREN, 'currency_batch_size_invalid');
  const children = batch.requests.map(ref => {
    strict(ref, ['path', 'sha256'], 'currency_batch_child_reference_invalid');
    relative(ref.path); requireThat(HASH.test(ref.sha256), 'currency_batch_child_reference_invalid');
    requireThat(ref.path.toLowerCase() !== requestPath.toLowerCase(), 'currency_batch_request_collision');
    const child = readRequest(context, ref.path);
    requireThat(child.input.expected_sha256 === ref.sha256, 'currency_batch_child_hash_mismatch');
    requireThat(child.request.schema_version === currency.REQUEST_SCHEMA, 'currency_batch_child_schema_invalid');
    requireThat(child.request.task_id === batch.task_id && child.request.session_id === batch.session_id, 'currency_batch_child_identity_mismatch');
    requireThat(child.request.test_execution_ids === undefined || (Array.isArray(child.request.test_execution_ids) && child.request.test_execution_ids.length === 0), 'currency_batch_child_execution_forbidden', 'Pass native executions to issue-batch, not to the immutable reviewed child request.');
    return { ...child, path: ref.path, sha256: ref.sha256 };
  });
  unique(children, child => child.path.toLowerCase(), 'currency_batch_request_collision');
  unique(children, child => child.sha256, 'currency_batch_hash_collision');
  unique(children, child => relative(child.request.review_path).toLowerCase(), 'currency_batch_review_collision');
  const supersedes = ids(batch.supersedes, KCUR, 'currency_batch_supersedes_invalid');
  const union = [...new Set(children.flatMap(child => ids(child.request.supersedes || [], KCUR, 'currency_batch_supersedes_invalid')))].sort();
  requireThat(same(union, supersedes), 'currency_batch_supersession_union_mismatch');
  return { input: loaded.input, requestPath, batch, children, supersedes };
}
function indexAndManifests(context) {
  const index = readState(context, INDEX, { schema_version: 'knowledge-currency-index.v1', receipt_ids: [] });
  requireThat(index.value.schema_version === 'knowledge-currency-index.v1', 'currency_index_invalid');
  const receiptIds = idsUnbounded(index.value.receipt_ids);
  const active = receiptIds.map(id => {
    const loaded = readState(context, RECEIPTS + '/' + id.slice(5) + '.json', null);
    requireThat(loaded.value && loaded.value.receipt_id === id && loaded.value.content_sha256 === currency.manifestDigest(loaded.value) && id === 'KCUR-' + loaded.value.content_sha256, 'currency_index_receipt_mismatch');
    return loaded;
  });
  return { index, active };
}
function idsUnbounded(value) {
  requireThat(Array.isArray(value) && value.every(id => typeof id === 'string' && KCUR.test(id)), 'currency_index_invalid');
  return unique([...value], id => id, 'currency_index_invalid').sort();
}
function ownership(scopes, preserved = []) {
  const owners = { findings: new Map(), files: new Map(), modules: new Map() };
  for (const entry of [...preserved, ...scopes]) {
    const scope = entry.scope;
    requireThat(object(scope) && Array.isArray(scope.findings) && Array.isArray(scope.claims) && Array.isArray(scope.modules), 'currency_batch_scope_invalid');
    const values = { findings: scope.findings.map(row => row.lifecycle_id), files: [...new Set(scope.claims.map(row => row.path))], modules: scope.modules.map(row => row.module_id) };
    for (const kind of Object.keys(owners)) for (const value of values[kind]) {
      const key = identity(value).toLowerCase();
      requireThat(!owners[kind].has(key), 'currency_batch_ownership_overlap', 'Factual ' + kind + ' ownership overlaps: ' + value);
      owners[kind].set(key, entry.owner);
    }
  }
}
function guardPin(context, pin, predecessors) {
  const predecessor = predecessors.get(pin.path);
  const loaded = predecessor
    ? readState(context, RECEIPTS + '/' + predecessor.receipt_id.slice(5) + '.json', null).guard
    : readSource(context, relative(pin.path));
  requireThat(loaded.expected_sha256 === pin.sha256, 'currency_source_drift', 'A pinned currency dependency changed: ' + pin.path);
  return loaded;
}
function scopeGuards(context, scope, review = null) {
  const predecessors = new Map((scope.supersedes || []).map(pin => [pin.path, pin]));
  return cli.collectPins(scope).concat(review ? [review] : []).map(pin => guardPin(context, pin, predecessors));
}
function observedSourceGuard(context, file) {
  relative(file);
  const root = file.startsWith('.knowledge/') ? context.projectKnowledgeRoot : context.targetRoot;
  const source = physical(root, file.startsWith('.knowledge/') ? file.slice(11) : file, true);
  try { return { path: source, containmentRoot: root, expected_sha256: hash(fs.readFileSync(source)) }; }
  catch (error) {
    if (error.code !== 'ENOENT') throw error;
    return { path: source, containmentRoot: root, expected_exists: false };
  }
}
function manifestGuards(context, manifest, preserved = false) {
  const predecessors = new Map((manifest.scope.supersedes || []).map(pin => [pin.path, pin]));
  // Preserved local dependencies may be stale, but their actual observations
  // must survive CAS. Historical review, execution, predecessor and shared
  // engine authority remain strict; absence is allowed only for local files.
  const guards = preserved ? cli.collectPins(manifest.scope).map(pin =>
    predecessors.has(pin.path) || currency.AUTHORITY_FILES.includes(pin.path)
      ? guardPin(context, pin, predecessors) : observedSourceGuard(context, pin.path))
    .concat(guardPin(context, manifest.review, predecessors)) : scopeGuards(context, manifest.scope, manifest.review);
  const finalized = require('./verification-finalization').requireFinalizedExecutions(context.stateRoot, manifest.verification.map(item => item.execution_id), manifest.verification_acceptances);
  guards.push(...finalized.bindings.map(pin => ({ path: pin.path, containmentRoot: context.stateRoot, expected_sha256: pin.physical_sha256 })));
  for (const execution of manifest.verification) {
    const loaded = loadExecutionRecord(context.stateRoot, execution.execution_id);
    requireThat(loaded && loaded.physical_sha256 === execution.physical_sha256, 'currency_execution_drift');
    guards.push({ path: loaded.path, containmentRoot: context.stateRoot, expected_sha256: loaded.physical_sha256 });
  }
  return guards;
}
function requireCurrentReceipts(evaluated, currentIds, code) {
  const required = new Set(currentIds);
  const localDebt = issue => issue.impact === 'scope' && issue.authenticated === true && !required.has(issue.receipt_id);
  requireThat(evaluated.valid && evaluated.issues.every(localDebt) &&
    currentIds.every(id => evaluated.receipts.some(receipt => receipt.receipt_id === id && receipt.valid)) &&
    evaluated.receipts.every(receipt => receipt.valid || evaluated.issues.some(issue => issue.receipt_id === receipt.receipt_id && localDebt(issue))),
  code, JSON.stringify(evaluated.issues));
}
function bindingPins(scope, review) {
  const predecessors = new Map((scope.supersedes || []).map(pin => [pin.path, pin]));
  return cli.collectPins(scope).concat(review ? [review] : []).map(pin => ({ path: pin.path, sha256: pin.sha256,
    ...(predecessors.has(pin.path) ? { predecessor_receipt_id: predecessors.get(pin.path).receipt_id } : {}) }));
}
function batchBinding(loaded, children) {
  const pinned = new Map();
  for (const pin of children.flatMap(child => bindingPins(child.prepared.scope, child.review))) {
    const key = pin.path.toLowerCase(); const prior = pinned.get(key);
    requireThat(!prior || same(prior, pin), 'currency_batch_pin_collision'); pinned.set(key, pin);
  }
  return {
    schema_version: BINDING_SCHEMA, request_path: loaded.requestPath, request_sha256: loaded.input.expected_sha256,
    task_id: loaded.batch.task_id, session_id: loaded.batch.session_id, supersedes: loaded.supersedes,
    children: children.map(child => ({ path: child.path, sha256: child.sha256,
      scope_sha256: child.prepared.scope_sha256, protected_risks_sha256: child.prepared.protected_risks_sha256, review: child.review })),
    pins: [...pinned.values()].sort((a, b) => a.path.localeCompare(b.path))
  };
}
function inspectBatch(context, relativePath, reviewed) {
  const loaded = readBatch(context, relativePath);
  const inputs = stateInputs(context);
  const store = indexAndManifests(context);
  for (const id of loaded.supersedes) requireThat(store.index.value.receipt_ids.includes(id), 'currency_supersede_missing');
  const children = loaded.children.map(child => {
    const prepared = reviewed ? currency.validateCurrencyReview(context, child.request, inputs.projections) : currency.prepareCurrencyScope(context, child.request, inputs.projections);
    const reviewInput = reviewed ? readSource(context, relative(child.request.review_path)) : null;
    return { ...child, prepared, review: reviewInput ? { path: child.request.review_path, sha256: reviewInput.expected_sha256 } : null };
  });
  const preserved = store.active.filter(entry => !loaded.supersedes.includes(entry.value.receipt_id));
  ownership(children.map(child => ({ scope: child.prepared.scope, owner: child.path })), preserved.map(entry => ({ scope: entry.value.scope, owner: entry.value.receipt_id })));
  // Supersession cannot silently drop previously reviewed facts or module ownership.
  const nextFiles = new Set(children.flatMap(child => child.prepared.scope.claims.map(claim => claim.path)));
  const nextModules = new Set(children.flatMap(child => child.prepared.scope.modules.map(module => module.module_id)));
  for (const predecessor of store.active.filter(entry => loaded.supersedes.includes(entry.value.receipt_id))) {
    requireThat(predecessor.value.scope.claims.every(claim => nextFiles.has(claim.path)) &&
      predecessor.value.scope.modules.every(module => nextModules.has(module.module_id)), 'currency_supersession_orphan');
  }
  const binding = batchBinding(loaded, children);
  const guards = [loaded.input, ...children.map(child => child.input), inputs.stale.guard, inputs.repair.guard, inputs.registryFile, store.index.guard,
    ...store.active.map(entry => entry.guard), ...children.flatMap(child => scopeGuards(context, child.prepared.scope, child.review))];
  // CAS retains every independent read's SHA; conflicts fail closed.
  cli.uniqueGuards(guards);
  return { ...loaded, inputs, store, preserved, children, binding, guards };
}
function publicPrepared(prepared, status) {
  return { status, ...prepared.binding, children: prepared.children.map(child => ({ ...prepared.binding.children.find(ref => ref.path === child.path), scope: child.prepared.scope })),
    security_certificate: false, routing_cap: 'routing_trusted' };
}
function prepareBatch(context, relativePath) { return publicPrepared(inspectBatch(context, relativePath, false), 'prepared'); }
function checkBatch(context, relativePath) { return publicPrepared(inspectBatch(context, relativePath, true), 'pass'); }
function prepareBatchForFinish(context, relativePath, { taskId, sessionId, sourceFiles }) {
  const prepared = inspectBatch(context, relativePath, true);
  requireThat(prepared.batch.task_id === taskId && prepared.batch.session_id === sessionId, 'currency_finish_identity_mismatch');
  requireThat(Array.isArray(sourceFiles), 'currency_finish_source_coverage_missing');
  const covered = new Set(sourceFiles.map(relative));
  // Every computed pin, including automatically added AUTHORITY_FILES, must be
  // physically verified. State-only historical predecessors are CAS proof,
  // not checkout sources; they remain explicit pins in the immutable binding.
  const required = [prepared.requestPath, ...prepared.children.map(child => child.path), ...prepared.binding.pins.filter(pin => !pin.predecessor_receipt_id).map(pin => pin.path)];
  const missing = [...new Set(required)].filter(file => !covered.has(file)).sort();
  requireThat(!missing.length, 'currency_finish_source_coverage_missing', 'Add all computed currency pins to source_files: ' + missing.join(', '));
  return prepared.binding;
}
function assertBatchBindingCurrent(context, binding) {
  requireThat(object(binding) && binding.schema_version === BINDING_SCHEMA, 'currency_finish_binding_invalid');
  const loaded = readBatch(context, binding.request_path);
  requireThat(loaded.input.expected_sha256 === binding.request_sha256 && loaded.batch.task_id === binding.task_id && loaded.batch.session_id === binding.session_id &&
    same(loaded.children.map(child => ({ path: child.path, sha256: child.sha256 })), binding.children.map(child => ({ path: child.path, sha256: child.sha256 }))), 'currency_finish_input_drift');
  for (const pin of binding.pins) {
    const predecessor = pin.predecessor_receipt_id ? new Map([[pin.path, { receipt_id: pin.predecessor_receipt_id }]]) : new Map();
    guardPin(context, pin, predecessor);
  }
  return binding;
}
function operationIdentity(requestSha, executions) {
  return currency.currencyDigest({ schema_version: OPERATION_SCHEMA, request_sha256: requestSha, test_execution_ids: executions });
}
function operationDigest(operation) {
  const body = { ...operation }; delete body.operation_id; delete body.content_sha256; return currency.currencyDigest(body);
}
function operationPayload(prepared, executions, manifests, openRiskCount) {
  const intent = operationIdentity(prepared.input.expected_sha256, executions);
  const result = { status: 'committed', operation_id: 'KCURB-' + intent, receipt_ids: manifests.map(manifest => manifest.receipt_id).sort(),
    reused_execution_ids: executions, covered_factual_findings: manifests.flatMap(manifest => manifest.scope.findings.map(row => row.lifecycle_id)).sort(), closed_factual_findings: [], lifecycle_effect: 'none', superseded_receipts: prepared.supersedes,
    application_risks_closed: 0, open_application_risks: openRiskCount, security_certificate: false, routing_cap: 'routing_trusted' };
  const body = { schema_version: OPERATION_SCHEMA, request_sha256: prepared.input.expected_sha256,
    task_id: prepared.batch.task_id, session_id: prepared.batch.session_id, test_execution_ids: executions, binding: prepared.binding,
    receipts: manifests.map((manifest, i) => ({ request_path: prepared.children[i].path, receipt_id: manifest.receipt_id, sha256: hash(jsonBytes(manifest)) })), result };
  const operation = { ...body, operation_id: result.operation_id, content_sha256: operationDigest(body) };
  const metadata = { type: 'knowledge_currency_batch_issuance', operation_id: result.operation_id, receipt_ids: result.receipt_ids,
    superseded_receipts: prepared.supersedes, closed_factual_findings: result.closed_factual_findings, application_risks_closed: 0, security_certificate: false };
  return { result, operation, metadata };
}
function nativeInputGuards(context, loaded, executions) {
  // Request bytes are physical KVE inputs, not claims about themselves. Their
  // hashes are derived here, outside the immutable request documents, so no
  // self-referential request/provenance hash is necessary.
  const required = [{ path: loaded.requestPath, sha256: loaded.input.expected_sha256 },
    ...loaded.children.map(child => ({ path: child.path, sha256: child.sha256 }))];
  const covered = new Set();
  function snapshot(rows) {
    requireThat(Array.isArray(rows), 'currency_kve_invalid');
    const pins = new Map();
    for (const pin of rows) {
      requireThat(object(pin) && typeof pin.sha256 === 'string' && HASH.test(pin.sha256), 'currency_kve_invalid');
      const file = relative(pin.path); const alias = file.toLowerCase();
      requireThat(!pins.has(alias), 'currency_batch_kve_input_ambiguous', 'Duplicate or case-aliased native KVE source pin: ' + file);
      pins.set(alias, { path: file, sha256: pin.sha256 });
    }
    return pins;
  }
  const guards = executions.map(executionId => {
    const execution = loadExecutionRecord(context.stateRoot, executionId);
    requireThat(execution && HASH.test(execution.physical_sha256) && execution.record?.execution_id === executionId,
      'currency_kve_invalid');
    const record = execution.record;
    requireThat(record.task_id === loaded.batch.task_id && record.session_id === loaded.batch.session_id, 'currency_kve_scope_mismatch');
    requireThat(record.status === 'pass' && record.exit_code === 0 && !record.timed_out && !record.signal, 'currency_kve_invalid');
    const before = snapshot(record.source_snapshot_before); const after = snapshot(record.source_snapshot);
    for (const expected of required) {
      const alias = expected.path.toLowerCase(); const left = before.get(alias); const right = after.get(alias);
      if (!left && !right) continue;
      requireThat(left && right, 'currency_batch_kve_input_missing', 'Required request pin is absent from a native KVE before/after snapshot: ' + expected.path);
      requireThat(left.path === expected.path && right.path === expected.path, 'currency_batch_kve_input_ambiguous', 'Request pin uses a different path spelling: ' + expected.path);
      requireThat(left.sha256 === expected.sha256 && right.sha256 === expected.sha256,
        'currency_batch_kve_input_mismatch', 'Native KVE did not verify the exact request bytes: ' + expected.path);
      covered.add(expected.path);
    }
    requireThat(before.size === after.size && [...before].every(([alias, pin]) => same(pin, after.get(alias) || null)), 'currency_kve_invalid');
    return { path: execution.path, containmentRoot: context.stateRoot, expected_sha256: execution.physical_sha256 };
  });
  const missing = required.filter(pin => !covered.has(pin.path)).map(pin => pin.path);
  requireThat(!missing.length, 'currency_batch_kve_input_missing', 'Native KVE must physically pin batch and child request bytes: ' + missing.join(', '));
  return guards;
}
function currentOperation(context, loaded, executions, operation) {
  const intent = operationIdentity(loaded.input.expected_sha256, executions);
  requireThat(operation.schema_version === OPERATION_SCHEMA && operation.operation_id === 'KCURB-' + intent &&
    operation.content_sha256 === operationDigest(operation) && operation.request_sha256 === loaded.input.expected_sha256 &&
    same(operation.test_execution_ids, executions), 'currency_batch_operation_invalid');
  nativeInputGuards(context, loaded, executions);
  assertBatchBindingCurrent(context, operation.binding);
  const inputs = stateInputs(context); const store = indexAndManifests(context);
  requireThat(Array.isArray(operation.receipts) && operation.receipts.length === loaded.children.length, 'currency_batch_operation_invalid');
  unique(operation.receipts, entry => entry.receipt_id, 'currency_batch_receipt_collision');
  requireThat(same(operation.receipts.map(entry => entry.request_path), loaded.children.map(child => child.path)), 'currency_batch_operation_invalid');
  const manifests = [];
  for (const entry of operation.receipts) {
    requireThat(loaded.children.some(child => child.path === entry.request_path) && store.index.value.receipt_ids.includes(entry.receipt_id), 'currency_batch_not_sustained');
    const active = store.active.find(row => row.value.receipt_id === entry.receipt_id);
    requireThat(active.guard.expected_sha256 === entry.sha256, 'currency_batch_receipt_drift');
    requireThat(same(active.value.verification.map(row => row.execution_id).sort(), executions), 'currency_batch_operation_invalid');
    manifests.push(active.value);
  }
  requireThat(loaded.supersedes.every(id => !store.index.value.receipt_ids.includes(id)), 'currency_batch_supersession_collision');
  ownership(store.active.map(entry => ({ scope: entry.value.scope, owner: entry.value.receipt_id })));
  const evaluated = currency.evaluateCurrency(context, { ...inputs.projections, manifests: store.active.map(entry => entry.value) });
  requireCurrentReceipts(evaluated, operation.receipts.map(entry => entry.receipt_id), 'currency_batch_not_sustained');
  const riskCount = operation.result?.open_application_risks;
  const knownOpenRisks = new Set(manifests.flatMap(manifest => manifest.scope.protected_risks)
    .filter(risk => !['closed', 'resolved'].includes(risk.status))
    .map(risk => risk.lifecycle_id || currency.currencyDigest(risk)));
  requireThat(Number.isSafeInteger(riskCount) && riskCount >= knownOpenRisks.size, 'currency_batch_operation_invalid');
  const children = loaded.children.map((child, index) => ({ ...child, prepared: manifests[index],
    review: { path: manifests[index].review.path, sha256: manifests[index].review.sha256 } }));
  const binding = batchBinding(loaded, children);
  // A mutable operation's self-hash is an integrity check, not authority for
  // arbitrary result fields. Reconstruct every invariant from native receipts.
  // Keep the historical total risk count; unrelated later risks do not change
  // this immutable issuance result or invalidate an independent current unit.
  const planned = operationPayload({ ...loaded, children, binding }, executions, manifests, riskCount);
  requireThat(same(operation, planned.operation), 'currency_batch_operation_invalid');
  return operation;
}
function validateBatchOperation(context, relativePath, executionIds) {
  const loaded = readBatch(context, relativePath);
  const executions = ids(executionIds, KVE, 'currency_execution_required', true);
  const intent = operationIdentity(loaded.input.expected_sha256, executions);
  const saved = readState(context, OPERATIONS + '/' + intent + '.json', null);
  return saved.value ? currentOperation(context, loaded, executions, saved.value) : null;
}
function issueBatchUnlocked(context, relativePath, executionIds, expectedBinding = null, acceptances = null) {
  const loaded = readBatch(context, relativePath);
  const executions = ids(executionIds, KVE, 'currency_execution_required', true);
  // Also runs before journal recovery: invalid request-input evidence cannot
  // cause new issuance, replay an interrupted write, or accept an old operation.
  const finalized = require('./verification-finalization').requireFinalizedExecutions(context.stateRoot, executions, acceptances);
  const inputGuards = nativeInputGuards(context, loaded, executions).concat(finalized.bindings.map(pin => ({ path: pin.path, containmentRoot: context.stateRoot, expected_sha256: pin.physical_sha256 })));
  const intent = operationIdentity(loaded.input.expected_sha256, executions);
  const transactionId = 'knowledge-currency-batch-' + intent;
  const allowedContainmentRoots = [context.targetRoot, context.projectKnowledgeRoot, context.stateRoot];
  const txRoot = path.join(context.stateRoot, 'maintenance', 'transactions', transactionId);
  assertSafeContainedPath(context.stateRoot, txRoot, { allowMissing: true });
  if (fs.existsSync(txRoot)) {
    // Reconstruct receipt identities from independently verified request/KVE
    // inputs. Journal metadata cannot choose its own permitted output files.
    const native = stateInputs(context);
    const expected = loaded.children.map(child => currency.createCurrencyReceipt(context,
      { ...child.request, test_execution_ids: executions, verification_acceptances: acceptances }, native.projections, true));
    const exactWritePaths = [path.join(context.stateRoot, INDEX), path.join(context.stateRoot, OPERATIONS, intent + '.json'),
      ...expected.map(manifest => path.join(context.stateRoot, RECEIPTS, manifest.content_sha256 + '.json'))];
    const policy = { allowedGuardRoots: allowedContainmentRoots, allowedWriteRoots: [context.stateRoot], exactWritePaths,
      expectedTransactionId: transactionId };
    const inspected = inspectTransaction(txRoot, policy);
    if (!inspected.terminal) {
      const journal = inspected.manifest;
      const expectedIds = new Set(expected.map(manifest => manifest.receipt_id));
      const store = indexAndManifests(context);
      // The live index may be old or already promoted. Taking this union is
      // idempotent in both states and preserves every unrelated current unit.
      const preserved = store.active.filter(entry => !loaded.supersedes.includes(entry.value.receipt_id) && !expectedIds.has(entry.value.receipt_id));
      const all = [...preserved.map(entry => entry.value), ...expected];
      ownership(all.map(manifest => ({ scope: manifest.scope, owner: manifest.receipt_id })));
      const evaluated = currency.evaluateCurrency(context, { ...native.projections, manifests: all });
      requireCurrentReceipts(evaluated, [...expectedIds], 'currency_batch_recovery_binding_invalid');
      const children = loaded.children.map((child, index) => ({ ...child, prepared: expected[index],
        review: { path: expected[index].review.path, sha256: expected[index].review.sha256 } }));
      const binding = batchBinding(loaded, children);
      if (expectedBinding) {
        assertBatchBindingCurrent(context, expectedBinding);
        requireThat(same(expectedBinding, binding), 'currency_finish_input_drift');
      }
      const planned = operationPayload({ ...loaded, children, binding }, executions, expected, evaluated.assurance.open_findings.length);
      requireThat(same(journal.metadata, planned.metadata), 'currency_batch_recovery_binding_invalid');
      const outputs = [...expected.map(manifest => ({ path: path.join(context.stateRoot, RECEIPTS, manifest.content_sha256 + '.json'), value: manifest })),
        { path: path.join(context.stateRoot, INDEX), value: { schema_version: currency.INDEX_SCHEMA, receipt_ids: all.map(manifest => manifest.receipt_id).sort() } },
        { path: path.join(context.stateRoot, OPERATIONS, intent + '.json'), value: planned.operation }];
      // Exact paths alone are insufficient: an internally consistent mutable
      // journal must not choose alternate index or operation bytes either.
      for (const output of outputs) {
        // The complete intent exists even when staging was interrupted before
        // all entries were written; inspection binds each present entry to it.
        const write = journal.intent.writes.find(write => path.resolve(write.target) === path.resolve(output.path));
        requireThat(write?.new_sha256 === hash(jsonBytes(output.value)), 'currency_batch_recovery_binding_invalid');
      }
      recoverOne(txRoot, { ...policy, expectedIntentSha256: journal.intent_sha256,
        expectedManifestSha256: inspected.manifest_sha256 });
    }
  }
  const saved = readState(context, OPERATIONS + '/' + intent + '.json', null);
  if (saved.value) {
    const operation = currentOperation(context, loaded, executions, saved.value);
    if (expectedBinding) requireThat(same(expectedBinding, operation.binding), 'currency_finish_input_drift');
    return operation.result;
  }
  const prepared = inspectBatch(context, relativePath, true);
  requireThat(prepared.input.expected_sha256 === loaded.input.expected_sha256, 'currency_finish_input_drift');
  if (expectedBinding) {
    assertBatchBindingCurrent(context, expectedBinding);
    requireThat(same(expectedBinding, prepared.binding), 'currency_finish_input_drift');
  }
  const manifests = prepared.children.map(child => currency.createCurrencyReceipt(context, { ...child.request, test_execution_ids: executions, verification_acceptances: acceptances }, prepared.inputs.projections));
  unique(manifests, manifest => manifest.receipt_id, 'currency_batch_receipt_collision');
  ownership(manifests.map(manifest => ({ scope: manifest.scope, owner: manifest.receipt_id })), prepared.preserved.map(entry => ({ scope: entry.value.scope, owner: entry.value.receipt_id })));
  const staleItems = prepared.inputs.stale.value;
  const repairQueue = prepared.inputs.repair.value;
  const all = [...prepared.preserved.map(entry => entry.value), ...manifests];
  // Capture preserved observations before evaluation, so drift during native
  // authentication or between evaluation and commit cannot escape CAS.
  const receiptGuards = [...prepared.preserved.flatMap(entry => manifestGuards(context, entry.value, true)),
    ...manifests.flatMap(manifest => manifestGuards(context, manifest))];
  const evaluated = currency.evaluateCurrency(context, { staleItems, repairQueue, registry: prepared.inputs.registry, manifests: all });
  requireCurrentReceipts(evaluated, manifests.map(manifest => manifest.receipt_id), 'currency_batch_merged_invalid');
  const targets = manifests.map(manifest => readState(context, RECEIPTS + '/' + manifest.content_sha256 + '.json', null));
  requireThat(targets.every(target => target.value === null), 'currency_receipt_exists');
  const guards = [...prepared.guards, ...inputGuards, saved.guard, ...targets.map(target => target.guard), ...receiptGuards];
  const receiptIds = all.map(manifest => manifest.receipt_id).sort();
  const { result, operation, metadata } = operationPayload(prepared, executions, manifests, evaluated.assurance.open_findings.length);
  const write = (guard, body) => ({ path: guard.path, containmentRoot: guard.containmentRoot, body: jsonBytes(body) });
  const writes = [...manifests.map((manifest, i) => write(targets[i].guard, manifest)),
    write(prepared.store.index.guard, { schema_version: 'knowledge-currency-index.v1', receipt_ids: receiptIds }),
    write(saved.guard, operation)];
  commitJsonTransaction({ stateRoot: context.stateRoot, transactionId, allowedGuardRoots: allowedContainmentRoots, allowedWriteRoots: [context.stateRoot], exactWritePaths: writes.map(write => write.path), guards: cli.uniqueGuards(guards), writes,
    metadata });
  return result;
}
function issueBatch(context, relativePath, executions, expectedBinding = null, acceptances = null) {
  return withResourceAvailable(context, () =>
    withContainedLock({ context, rootKind: 'state', rootPath: context.stateRoot, lockName: 'repair-on-touch', purpose: LOCKS['repair-on-touch'].purpose },
      () => issueBatchUnlocked(context, relativePath, executions, expectedBinding, acceptances)));
}
function checkBatchArgv(context, relativePath) {
  relative(relativePath);
  // Native KVE accepts only physical repository-relative script paths. Keep
  // that policy intact and fail closed for a system CLI outside the checkout.
  const script = path.relative(path.resolve(context.targetRoot),
    path.resolve(context.systemRoot, 'tools', 'knowledge-currency.js')).replace(/\\/g, '/');
  relative(script);
  // The verifier accepts a bare executable and binds Node execution to its
  // own process.execPath and executable hash. Never bypass that runtime guard.
  const argv = ['node', script, 'check-batch', '--request=' + relativePath];
  for (const [flag, value] of [['system-root', context.systemRoot], ['target-root', context.targetRoot], ['project-knowledge-root', context.projectKnowledgeRoot], ['state-root', context.stateRoot], ['team-root', context.teamRoot], ['workspace-id', context.workspaceId], ['agent-id', context.agentId]]) {
    if (value) argv.push('--' + flag + '=' + value);
  }
  return argv;
}
const admit = fn => (...args) => {
  const clean = [];
  for (let index = 0; index < args.length; index++) clean[index] = copyInertData(args[index]);
  return fn(...clean);
};
module.exports = { BATCH_SCHEMA, OPERATION_SCHEMA, BINDING_SCHEMA, MAX_CHILDREN,
  prepareBatch: admit(prepareBatch), checkBatch: admit(checkBatch), prepareBatchForFinish: admit(prepareBatchForFinish),
  assertBatchBindingCurrent: admit(assertBatchBindingCurrent), validateBatchOperation: admit(validateBatchOperation),
  issueBatch: admit(issueBatch), issueBatchUnlocked: admit(issueBatch), checkBatchArgv: admit(checkBatchArgv) };
