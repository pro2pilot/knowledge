#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { ensureDir, readJson, appendNdjson, getAgentId } = require('./lib/json-store');
const { withContainedLock } = require('./lib/contained-lock-manager');
const { LOCKS } = require('./lib/lock-policy');
const {
  closeFindings,
  canonicalPath,
  canonicalCode,
  canonicalModule,
  dedicatedRequirementFor,
  lifecycleById
} = require('./lib/queue-lifecycle');
const {
  commitJsonTransaction,
  recoverTransactions,
  inspectTransaction
} = require('./lib/json-transaction');
const { resolveKnowledgeContext } = require('./lib/path-context');
const {
  loadDedicatedReceipt,
  verifyDedicatedEvidence
} = require('./lib/dedicated-verification');
const {
  validateReceipt,
  saveReceipt,
  loadReceipt,
  loadExecutionRecord,
  taskReadiness,
  resolvePolicy,
  policyAllowsReceiptMode,
  restrictPolicyBudgets,
  parseRepositoryRepairSettings,
  teamPolicyCap,
  loadRepairPlan,
  GENERATED_REPAIR_CLASSES,
  MODE_RANK,
  validateRepairPlanArtifact,
  stableJson
} = require('./lib/repair-on-touch');

const context = resolveKnowledgeContext();
const stateRoot = context.stateRoot;
const knowledgeRoot = context.projectKnowledgeRoot;
const repoRoot = context.targetRoot;
const RECERTIFY_LOCK = Object.freeze({
  context,
  rootKind: 'state',
  rootPath: stateRoot,
  lockName: 'recertify',
  purpose: LOCKS.recertify.purpose
});
const ALLOWED_HASH_PREDICATES = new Set([
  'source_and_tests_match_pinned_hashes',
  'source_tests_and_evidence_match_pinned_hashes'
]);

function hash(file) { return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex'); }
function nowIso() { return new Date().toISOString(); }
function readRegularFileSnapshot(
  file,
  containmentRoot,
  errorCode = 'repair_read_set_invalid'
) {
  let descriptor = null;
  try {
    const pathBefore = fs.lstatSync(file);
    if (!pathBefore.isFile() || pathBefore.isSymbolicLink()) {
      const error = new Error(
        `Authoritative input is not a safe regular file: ${file}`
      );
      error.code = errorCode;
      throw error;
    }
    descriptor = fs.openSync(file, 'r');
    const opened = fs.fstatSync(descriptor);
    if (!opened.isFile()) {
      const error = new Error(
        `Authoritative input is not a regular file: ${file}`
      );
      error.code = errorCode;
      throw error;
    }
    const body = fs.readFileSync(descriptor);
    const openedAfter = fs.fstatSync(descriptor);
    const pathAfter = fs.lstatSync(file);
    const identityChanged = (
      opened.dev !== openedAfter.dev ||
      opened.ino !== openedAfter.ino ||
      opened.size !== openedAfter.size ||
      opened.mtimeMs !== openedAfter.mtimeMs ||
      opened.dev !== pathAfter.dev ||
      opened.ino !== pathAfter.ino
    );
    if (
      identityChanged ||
      !pathAfter.isFile() ||
      pathAfter.isSymbolicLink() ||
      openedAfter.size !== body.length
    ) {
      const error = new Error(
        `Authoritative input changed while it was read: ${file}`
      );
      error.code = errorCode;
      throw error;
    }
    const expectedSha256 =
      crypto.createHash('sha256').update(body).digest('hex');
    return {
      path: file,
      body,
      expected_sha256: expectedSha256,
      guard: {
        path: file,
        expected_sha256: expectedSha256,
        containmentRoot
      }
    };
  } catch (error) {
    if (!error.code || error.code === 'ENOENT') error.code = errorCode;
    throw error;
  } finally {
    if (descriptor !== null) fs.closeSync(descriptor);
  }
}
function cloneFallback(value) {
  return value === undefined
    ? undefined
    : JSON.parse(JSON.stringify(value));
}
function readJsonWithGuard(file, fallback, containmentRoot) {
  let stat;
  try {
    stat = fs.lstatSync(file);
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
    return {
      value: cloneFallback(fallback),
      guard: {
        path: file,
        expected_exists: false,
        containmentRoot
      }
    };
  }
  if (!stat.isFile() || stat.isSymbolicLink()) {
    const error = new Error(
      `Authoritative JSON input is not a safe regular file: ${file}`
    );
    error.code = 'repair_read_set_invalid';
    throw error;
  }
  const snapshot = readRegularFileSnapshot(
    file,
    containmentRoot,
    'repair_read_set_invalid'
  );
  return {
    value: JSON.parse(
      snapshot.body.toString('utf8').replace(/^\uFEFF/, '')
    ),
    guard: snapshot.guard
  };
}
function fileGuardSnapshot(file, containmentRoot) {
  let stat;
  try {
    stat = fs.lstatSync(file);
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
    return {
      path: file,
      expected_exists: false,
      containmentRoot
    };
  }
  if (!stat.isFile() || stat.isSymbolicLink()) {
    const error = new Error(
      `Authoritative input is not a safe regular file: ${file}`
    );
    error.code = 'repair_read_set_invalid';
    throw error;
  }
  return readRegularFileSnapshot(
    file,
    containmentRoot,
    'repair_read_set_invalid'
  ).guard;
}
function sameGuardState(left, right) {
  return (
    left.expected_exists === right.expected_exists &&
    left.expected_sha256 === right.expected_sha256
  );
}
function clean(rel) { return String(rel || '').replace(/^\.knowledge[\\/]/, ''); }
function contained(candidate, root) {
  const resolved = path.resolve(candidate);
  const base = path.resolve(root);
  return resolved === base || resolved.startsWith(`${base}${path.sep}`);
}
function pathIdentity(value) {
  const resolved = path.resolve(value);
  return process.platform === 'win32'
    ? resolved.toLowerCase()
    : resolved;
}
function resolveArtifact(rel) {
  let relative;
  try {
    relative = canonicalPath(rel);
  } catch {
    return null;
  }
  if (!relative || relative === 'unknown') return null;
  const knowledgeRelative = relative.startsWith('.knowledge/');
  const containmentRoot = knowledgeRelative ? knowledgeRoot : repoRoot;
  const candidate = knowledgeRelative
    ? path.join(knowledgeRoot, clean(relative))
    : path.join(repoRoot, ...relative.split('/'));
  if (!contained(candidate, containmentRoot)) return null;
  let stat;
  try {
    stat = fs.lstatSync(candidate);
  } catch {
    return null;
  }
  if (!stat.isFile() || stat.isSymbolicLink()) return null;
  try {
    const actual = fs.realpathSync(candidate);
    if (
      pathIdentity(actual) !== pathIdentity(candidate) ||
      !contained(actual, containmentRoot) ||
      !fs.statSync(actual).isFile()
    ) {
      return null;
    }
    return actual;
  } catch {
    return null;
  }
}

function semanticSha256(value) {
  return crypto.createHash('sha256')
    .update(stableJson(value))
    .digest('hex');
}

function buildTrustElevationAuthority(
  receipt,
  cardRelative,
  card,
  plannedPolicy
) {
  if (
    !plannedPolicy ||
    typeof plannedPolicy !== 'object' ||
    Array.isArray(plannedPolicy)
  ) {
    const error = new Error(
      'Trust elevation requires the frozen repair policy'
    );
    error.code = 'trust_elevation_policy_missing';
    throw error;
  }
  const authority = {
    schema_version: 'knowledge-trust-elevation-authority.v2',
    receipt_id: receipt.receipt_id,
    receipt_sha256: receipt.content_sha256,
    finding_id: receipt.finding_id,
    module_id: receipt.module_id,
    task_id: receipt.task_id,
    session_id: receipt.session_id,
    card_path: canonicalPath(cardRelative),
    target_trust_level: card.target_trust_level,
    card_semantic_sha256: semanticSha256(card),
    planned_policy_sha256: semanticSha256(plannedPolicy)
  };
  return {
    ...authority,
    authority_sha256: semanticSha256(authority)
  };
}

function sameTrustElevationAuthority(left, right) {
  return Boolean(
    left &&
    right &&
    typeof left === 'object' &&
    typeof right === 'object' &&
    stableJson(left) === stableJson(right) &&
    /^[a-f0-9]{64}$/.test(String(left.authority_sha256 || '')) &&
    left.authority_sha256 === semanticSha256(
      Object.fromEntries(
        Object.entries(left).filter(([key]) =>
          key !== 'authority_sha256')
      )
    )
  );
}

function appendReceiptExecutionGuards(
  receipt,
  guardSnapshots,
  errors
) {
  for (const test of receipt.tests_run || []) {
    const execution = loadExecutionRecord(
      stateRoot,
      test.execution_id
    );
    if (!execution) {
      errors.push(
        `test_execution_not_found:${test.execution_id || 'missing'}`
      );
      continue;
    }
    const expectedPath = path.relative(
      stateRoot,
      execution.path
    ).replace(/\\/g, '/');
    if (
      execution.record.execution_id !== test.execution_id ||
      execution.record.content_sha256 !== test.execution_sha256 ||
      expectedPath !==
        String(test.execution_path || '').replace(/\\/g, '/')
    ) {
      errors.push(
        `test_execution_mismatch:${test.execution_id || 'missing'}`
      );
      continue;
    }
    if (guardSnapshots) {
      guardSnapshots.push({
        path: execution.path,
        expected_sha256: execution.physical_sha256,
        containmentRoot: stateRoot
      });
    }
  }
}
function hashMap(value) {
  if (Array.isArray(value)) return Object.fromEntries(value.map((item) => [item.path || item.file, item.sha256 || item.hash]));
  return value && typeof value === 'object' ? value : {};
}
function timestampOf(file) {
  try {
    const json = readJson(file, null);
    return json && (json.verified_at || json.generated_at || json.updated_at || json.created_at) || null;
  } catch {
    return null;
  }
}
function evidenceIsStale(file, maxAgeDays, now) {
  const stamp = timestampOf(file);
  const time = stamp ? Date.parse(stamp) : NaN;
  return !Number.isFinite(time) || now - time > maxAgeDays * 86400000;
}
function verificationDigest(moduleId, expected, resolves) {
  return crypto.createHash('sha256').update(JSON.stringify({ moduleId, expected, resolves })).digest('hex');
}
function lifecycleRecords(stale, repair) {
  return lifecycleById(stale, repair);
}
function openModuleItems(stale, repair, moduleId) {
  return Array.from(lifecycleRecords(stale, repair).values())
    .filter((item) => item.module_id === moduleId && !['closed', 'resolved'].includes(item.status));
}
function reasonHasValues(value) {
  if (Array.isArray(value)) return value.length > 0;
  if (value && typeof value === 'object') return Object.values(value).some(reasonHasValues);
  return value !== null && value !== undefined && value !== '' && value !== false && value !== 0;
}
function resolveTrustReasons(report, moduleId, verifiedArtifacts = []) {
  report.module_statuses = Array.isArray(report.module_statuses) ? report.module_statuses : [];
  const index = report.module_statuses.findIndex((item) => item.module_id === moduleId);
  const current = index === -1 ? { module_id: moduleId, reasons: {} } : report.module_statuses[index];
  const reasons = current.reasons && typeof current.reasons === 'object'
    ? JSON.parse(JSON.stringify(current.reasons))
    : {};
  const verified = new Set(verifiedArtifacts.map(canonicalPath));
  if (Array.isArray(reasons.changed_or_missing_important_files)) {
    reasons.changed_or_missing_important_files = reasons.changed_or_missing_important_files
      .filter((item) => !verified.has(canonicalPath(typeof item === 'string' ? item : item?.path || item?.file)));
  }
  const next = { ...current, reasons };
  if (index === -1) report.module_statuses.push(next);
  else report.module_statuses[index] = next;
  return {
    status: next,
    has_blockers: Object.values(reasons).some(reasonHasValues)
  };
}
function updateTrustReport(report, moduleId, targetTrust, timestamp, agentId, verifiedArtifacts = []) {
  const allowed = ['trusted', 'near_trusted', 'routing_trusted', 'advisory_only'];
  if (!allowed.includes(targetTrust)) throw new Error(`Unsafe recertification target trust: ${targetTrust}`);
  const resolved = resolveTrustReasons(report, moduleId, verifiedArtifacts);
  if (resolved.has_blockers) throw new Error(`Open trust-report reasons remain for ${moduleId}`);
  const index = report.module_statuses.findIndex((item) => item.module_id === moduleId);
  const current = report.module_statuses[index];
  const next = {
    ...current,
    trust_status: targetTrust,
    freshness_status: 'fresh',
    recertified_at: timestamp,
    recertified_by: agentId
  };
  report.module_statuses[index] = next;
  report.modules = report.modules || {};
  for (const group of allowed.concat(['suspect', 'low_confidence'])) {
    report.modules[group] = report.module_statuses
      .filter((item) => item.trust_status === group)
      .map((item) => item.module_id)
      .sort();
  }
  report.modules_total = report.module_statuses.length;
  report.modules_low_confidence = report.modules.low_confidence.length;
  report.generated_at = timestamp;
  report.generated_by = agentId;
  return report;
}
function event(result) {
  appendNdjson(path.join(stateRoot, 'maintenance', 'events', `${result.timestamp.slice(0, 10)}.ndjson`), { type: 'recertification', ...result });
}
function parseRequestArgs(argv) {
  const request = { lifecycleIds: [] };
  for (const arg of argv) {
    if (arg.startsWith('--lifecycle-id=')) request.lifecycleIds.push(arg.slice('--lifecycle-id='.length));
    else if (arg.startsWith('--request=')) request.requestPath = arg.slice('--request='.length);
    else if (arg.startsWith('--fault-at=')) request.faultAt = arg.slice('--fault-at='.length);
  }
  if (request.requestPath) {
    const body = readJson(path.resolve(request.requestPath), null);
    if (!body || typeof body !== 'object') throw new Error('Unable to read recertification request JSON.');
    request.lifecycleIds.push(...(body.lifecycle_ids || body.lifecycleIds || []));
  }
  request.lifecycleIds = Array.from(new Set(request.lifecycleIds.filter(Boolean).map(String)));
  return request;
}
function policyCoverage(policy, request) {
  const declared = Array.isArray(policy.resolves) ? policy.resolves : [];
  const selected = request.lifecycleIds.length ? declared.filter((item) => request.lifecycleIds.includes(String(item.lifecycle_id))) : declared;
  const declaredIds = new Set(declared.map((item) => String(item.lifecycle_id)));
  return { declared, selected, undeclared: request.lifecycleIds.filter((id) => !declaredIds.has(id)) };
}
function makeTransactionId(moduleId, timestamp, digest) {
  return `recert-${timestamp.replace(/[-:.TZ]/g, '').slice(0, 17)}-${canonicalCode(moduleId)}-${digest.slice(0, 12)}`;
}

function receiptIndexEntry(receipt, relativePath, timestamp) {
  return {
    receipt_id: receipt.receipt_id,
    content_sha256: receipt.content_sha256,
    finding_id: receipt.finding_id,
    module_id: receipt.module_id,
    task_id: receipt.task_id,
    session_id: receipt.session_id,
    checked_at: receipt.checked_at,
    committed_at: timestamp,
    path: relativePath.replace(/\\/g, '/')
  };
}

function validateClosedReceiptSources(receipt, finding, options = {}) {
  const errors = [];
  const guardSnapshots = Array.isArray(options.guardSnapshots)
    ? options.guardSnapshots
    : null;
  appendReceiptExecutionGuards(
    receipt,
    guardSnapshots,
    errors
  );
  const parseSnapshotJson = (snapshot) => JSON.parse(
    snapshot.body.toString('utf8').replace(/^\uFEFF/, '')
  );
  const transactionProofPaths = (transactionRoot, inspection) => [
    path.join(transactionRoot, 'manifest.json'),
    path.join(transactionRoot, 'prepared.json'),
    path.join(transactionRoot, 'commit.json'),
    path.join(transactionRoot, 'terminal.json'),
    ...(inspection.entries || []).flatMap((entry) => [
      entry.staged,
      ...(entry.backup ? [entry.backup] : [])
    ])
  ];
  const captureTransactionProof = (transactionRoot, inspection) => {
    const snapshots = new Map();
    for (const target of transactionProofPaths(
      transactionRoot,
      inspection
    )) {
      const snapshot = readRegularFileSnapshot(
        target,
        stateRoot,
        'closure_transaction_unstable'
      );
      const identity = process.platform === 'win32'
        ? path.resolve(target).toLowerCase()
        : path.resolve(target);
      if (snapshots.has(identity)) {
        const error = new Error(
          `Transaction proof path is duplicated: ${target}`
        );
        error.code = 'closure_transaction_unstable';
        throw error;
      }
      snapshots.set(identity, snapshot);
    }
    return snapshots;
  };
  const assertSameTransactionProof = (before, after) => {
    if (before.size !== after.size) {
      const error = new Error(
        'Transaction proof file set changed during validation.'
      );
      error.code = 'closure_transaction_unstable';
      throw error;
    }
    for (const [identity, snapshot] of before) {
      const current = after.get(identity);
      if (
        !current ||
        current.expected_sha256 !== snapshot.expected_sha256
      ) {
        const error = new Error(
          `Transaction proof changed during validation: ${snapshot.path}`
        );
        error.code = 'closure_transaction_unstable';
        throw error;
      }
    }
  };
  const registryPath = path.join(
    knowledgeRoot,
    'modules',
    'module_registry.json'
  );
  const registrySnapshot = readJsonWithGuard(
    registryPath,
    { modules: [] },
    knowledgeRoot
  );
  const registry = registrySnapshot.value;
  if (guardSnapshots) guardSnapshots.push(registrySnapshot.guard);
  const moduleInfo = (registry.modules || []).find((item) =>
    canonicalModule(item.module_id) === canonicalModule(finding.module_id));
  const cardRelative = moduleInfo?.card ? canonicalPath(moduleInfo.card) : null;
  const transactionId = `repair-${receipt.content_sha256.slice(0, 40)}`;
  const transactionRoot = path.join(
    stateRoot,
    'maintenance',
    'transactions',
    transactionId
  );
  let manifest = null;
  let inspection = null;
  let transactionProof = null;
  try {
    const inspectionOptions = {
      allowedContainmentRoots: [stateRoot, knowledgeRoot, repoRoot]
    };
    const initialInspection = inspectTransaction(
      transactionRoot,
      inspectionOptions
    );
    const proofBefore = captureTransactionProof(
      transactionRoot,
      initialInspection
    );
    inspection = inspectTransaction(transactionRoot, inspectionOptions);
    transactionProof = captureTransactionProof(
      transactionRoot,
      inspection
    );
    assertSameTransactionProof(proofBefore, transactionProof);
    manifest = inspection.manifest;
    if (guardSnapshots) {
      for (const snapshot of transactionProof.values()) {
        guardSnapshots.push(snapshot.guard);
      }
    }
    if (
      inspection.terminal?.status !== 'committed' ||
      manifest?.metadata?.type !== 'repair_on_touch_recertification' ||
      manifest?.metadata?.receipt_id !== receipt.receipt_id ||
      manifest?.metadata?.lifecycle_id !== finding.lifecycle_id
    ) {
      errors.push('closure_transaction_not_committed');
    }
  } catch (error) {
    errors.push(`closure_transaction_invalid:${error.code || 'unavailable'}`);
  }
  if (inspection?.terminal?.status === 'committed') {
    try {
      const identity = (value) => (
        process.platform === 'win32'
          ? path.resolve(value).toLowerCase()
          : path.resolve(value)
      );
      const stagedByTarget = new Map(
        inspection.entries.map((entry) => [
          identity(entry.target),
          parseSnapshotJson(transactionProof.get(identity(entry.staged)))
        ])
      );
      const stagedRecords = lifecycleRecords(
        stagedByTarget.get(identity(
          path.join(stateRoot, 'maintenance', 'stale_items.json')
        )) || { items: [] },
        stagedByTarget.get(identity(
          path.join(stateRoot, 'maintenance', 'repair_queue.json')
        )) || { queue: [] }
      );
      const stagedFinding = stagedRecords.get(finding.lifecycle_id);
      const stagedEvidence = stagedFinding?.resolution_evidence || {};
      if (
        !stagedFinding ||
        !['closed', 'resolved'].includes(stagedFinding.status) ||
        stagedEvidence.receipt_id !== receipt.receipt_id ||
        stagedEvidence.receipt_sha256 !== receipt.content_sha256 ||
        stagedEvidence.task_id !== receipt.task_id ||
        stagedEvidence.session_id !== receipt.session_id
      ) {
        errors.push('closure_transaction_evidence_mismatch');
      }
    } catch {
      errors.push('closure_transaction_evidence_invalid');
    }
  }
  for (const source of receipt.source_files_checked || []) {
    const relative = canonicalPath(source.path);
    const absolute = resolveArtifact(relative);
    if (!absolute) {
      errors.push(`source_missing_or_unsafe:${relative}`);
      continue;
    }
    let sourceSnapshot;
    try {
      sourceSnapshot = readRegularFileSnapshot(
        absolute,
        contained(absolute, repoRoot) ? repoRoot : knowledgeRoot,
        'closure_source_unstable'
      );
    } catch (error) {
      errors.push(
        `source_missing_or_unsafe:${relative}:${error.code || 'unavailable'}`
      );
      continue;
    }
    if (guardSnapshots) guardSnapshots.push(sourceSnapshot.guard);
    const actual = sourceSnapshot.expected_sha256;
    if (actual === String(source.sha256).toLowerCase()) continue;
    const absoluteIdentity = process.platform === 'win32'
      ? path.resolve(absolute).toLowerCase()
      : path.resolve(absolute);
    const committedEntry = (manifest?.writes || []).find((entry) => {
      const targetIdentity = process.platform === 'win32'
        ? path.resolve(entry.target).toLowerCase()
        : path.resolve(entry.target);
      return targetIdentity === absoluteIdentity;
    });
    if (
      relative !== cardRelative ||
      !committedEntry
    ) {
      errors.push(`source_hash_current_mismatch:${relative}`);
      continue;
    }
    let currentCard = null;
    try {
      currentCard = parseSnapshotJson(sourceSnapshot);
    } catch {
      errors.push(`source_hash_current_mismatch:${relative}`);
      continue;
    }
    const retainedReceipt = (
      currentCard?.verification?.receipts || []
    ).some((item) =>
      item?.receipt_id === receipt.receipt_id &&
      item?.finding_id === finding.lifecycle_id
    );
    if (!retainedReceipt) {
      errors.push(`source_hash_current_mismatch:${relative}`);
    }
  }
  return errors;
}

function validatePriorModuleClosures(
  records,
  moduleId,
  excludeLifecycleId,
  guardSnapshots = []
) {
  const errors = [];
  for (const record of records.values()) {
    if (
      canonicalModule(record.module_id) !== canonicalModule(moduleId) ||
      record.lifecycle_id === excludeLifecycleId ||
      !['closed', 'resolved'].includes(record.status)
    ) {
      continue;
    }
    const evidence = record.resolution_evidence || {};
    try {
      const loaded = loadReceipt(stateRoot, evidence.receipt_id, {
        finding: record
      });
      guardSnapshots.push({
        path: loaded.path,
        expected_sha256: loaded.physical_sha256,
        containmentRoot: stateRoot
      });
      if (
        evidence.receipt_id !== loaded.receipt.receipt_id ||
        evidence.receipt_sha256 !== loaded.receipt.content_sha256 ||
        evidence.receipt_path !== loaded.relative_path ||
        evidence.task_id !== loaded.receipt.task_id ||
        evidence.session_id !== loaded.receipt.session_id
      ) {
        throw new Error('prior closure KVR evidence mismatch');
      }
      const sourceErrors = validateClosedReceiptSources(
        loaded.receipt,
        record,
        { guardSnapshots }
      );
      if (sourceErrors.length) {
        const error = new Error(sourceErrors.join(', '));
        error.code = 'prior_closure_source_stale';
        throw error;
      }
      if (dedicatedRequirementFor(record)) {
        const dedicated = verifyDedicatedEvidence({
          stateRoot,
          evidence,
          verificationReceipt: loaded.receipt,
          finding: record
        });
        const dedicatedPath = path.join(
          stateRoot,
          dedicated.receipt_path
        );
        guardSnapshots.push({
          path: dedicated.physical_path || dedicatedPath,
          expected_sha256:
            dedicated.physical_sha256 || hash(dedicatedPath),
          containmentRoot: stateRoot
        });
      }
    } catch (error) {
      errors.push({
        lifecycle_id: record.lifecycle_id,
        reason: error.code || 'prior_closure_provenance_invalid'
      });
    }
  }
  return errors;
}

function compensateTrustElevation(receipt, result) {
  if (result?.trust_elevated !== true) {
    return { status: 'not_required' };
  }
  const transactionId =
    result.trust_finalization?.transaction_id ||
    result.transaction?.transaction_id;
  if (!transactionId) {
    const error = new Error(
      'Trust elevation cannot be compensated without its transaction'
    );
    error.code = 'trust_compensation_transaction_missing';
    throw error;
  }
  const transactionRoot = path.join(
    stateRoot,
    'maintenance',
    'transactions',
    transactionId
  );
  const inspection = inspectTransaction(transactionRoot, {
    allowedContainmentRoots: [stateRoot, knowledgeRoot, repoRoot]
  });
  if (inspection.terminal?.status !== 'committed') {
    const error = new Error(
      'Trust elevation transaction is not committed'
    );
    error.code = 'trust_compensation_transaction_invalid';
    throw error;
  }
  const trustReportPath = path.join(
    stateRoot,
    'maintenance',
    'trust_report.json'
  );
  const registry = readJson(
    path.join(knowledgeRoot, 'modules', 'module_registry.json'),
    { modules: [] }
  );
  const moduleInfo = (registry.modules || []).find((item) =>
    canonicalModule(item.module_id) === canonicalModule(receipt.module_id));
  const cardPath = moduleInfo?.card
    ? resolveArtifact(moduleInfo.card)
    : null;
  const wanted = new Set(
    [cardPath, trustReportPath]
      .filter(Boolean)
      .map((item) => path.resolve(item))
  );
  const writes = [];
  const guards = [];
  const restoreFields = (target, previous, keys) => {
    for (const key of keys) {
      if (Object.prototype.hasOwnProperty.call(previous, key)) {
        target[key] = JSON.parse(JSON.stringify(previous[key]));
      } else {
        delete target[key];
      }
    }
  };
  for (const entry of inspection.entries || []) {
    if (!wanted.has(path.resolve(entry.target))) continue;
    if (!entry.old_exists || !entry.backup) {
      const error = new Error(
        `Trust compensation backup is unavailable: ${entry.target}`
      );
      error.code = 'trust_compensation_backup_missing';
      throw error;
    }
    const previous = readJson(entry.backup, null);
    if (!previous || typeof previous !== 'object') {
      const error = new Error(
        `Trust compensation backup is invalid: ${entry.target}`
      );
      error.code = 'trust_compensation_backup_invalid';
      throw error;
    }
    const current = readJson(entry.target, null);
    if (!current || typeof current !== 'object') {
      const error = new Error(
        `Current trust state is invalid: ${entry.target}`
      );
      error.code = 'trust_compensation_target_invalid';
      throw error;
    }
    let compensatedValue = current;
    if (cardPath && path.resolve(entry.target) === path.resolve(cardPath)) {
      restoreFields(compensatedValue, previous, [
        'current_trust_level',
        'verification_status',
        'last_recertification_at',
        'last_recertification_by',
        'last_recertification_id'
      ]);
    } else if (
      path.resolve(entry.target) === path.resolve(trustReportPath)
    ) {
      const currentStatuses = Array.isArray(
        compensatedValue.module_statuses
      ) ? compensatedValue.module_statuses : [];
      const previousStatuses = Array.isArray(previous.module_statuses)
        ? previous.module_statuses
        : [];
      const currentStatus = currentStatuses.find((item) =>
        canonicalModule(item.module_id) ===
        canonicalModule(receipt.module_id));
      const previousStatus = previousStatuses.find((item) =>
        canonicalModule(item.module_id) ===
        canonicalModule(receipt.module_id));
      if (!currentStatus || !previousStatus) {
        const error = new Error(
          'Trust compensation module status is unavailable'
        );
        error.code = 'trust_compensation_module_status_missing';
        throw error;
      }
      restoreFields(currentStatus, previousStatus, [
        'trust_status',
        'freshness_status',
        'recertified_at',
        'recertified_by'
      ]);
      const groups = [
        'trusted',
        'near_trusted',
        'routing_trusted',
        'advisory_only',
        'suspect',
        'low_confidence'
      ];
      compensatedValue.modules =
        compensatedValue.modules &&
        typeof compensatedValue.modules === 'object'
          ? compensatedValue.modules
          : {};
      for (const group of groups) {
        compensatedValue.modules[group] = currentStatuses
          .filter((item) => item.trust_status === group)
          .map((item) => item.module_id)
          .sort();
      }
      compensatedValue.modules_total = currentStatuses.length;
      compensatedValue.modules_low_confidence =
        compensatedValue.modules.low_confidence.length;
      compensatedValue.generated_at = nowIso();
      compensatedValue.generated_by = getAgentId();
    }
    writes.push({
      path: entry.target,
      value: compensatedValue,
      containmentRoot: contained(entry.target, stateRoot)
        ? stateRoot
        : knowledgeRoot
    });
    guards.push({
      path: entry.target,
      expected_sha256: hash(entry.target),
      containmentRoot: contained(entry.target, stateRoot)
        ? stateRoot
        : knowledgeRoot
    });
  }
  if (!writes.length) {
    const error = new Error(
      'Trust elevation transaction did not contain compensable trust writes'
    );
    error.code = 'trust_compensation_writes_missing';
    throw error;
  }
  const compensated = commitJsonTransaction({
    stateRoot,
    transactionId:
      `repair-reopen-${receipt.content_sha256.slice(0, 40)}`,
    allowedContainmentRoots: [stateRoot, knowledgeRoot, repoRoot],
    guards,
    metadata: {
      type: 'repair_on_touch_trust_compensation',
      lifecycle_id: receipt.finding_id,
      receipt_id: receipt.receipt_id,
      compensates_transaction_id: transactionId
    },
    writes
  });
  return {
    status: compensated.status,
    transaction_id: compensated.transaction_id,
    writes: compensated.writes?.length || writes.length
  };
}

function completedTrustElevation(receipt) {
  const transactionId =
    `repair-trust-${receipt.content_sha256.slice(0, 40)}`;
  const transactionRoot = path.join(
    stateRoot,
    'maintenance',
    'transactions',
    transactionId
  );
  if (!fs.existsSync(transactionRoot)) return false;
  try {
    const inspection = inspectTransaction(transactionRoot, {
      allowedContainmentRoots: [stateRoot, knowledgeRoot, repoRoot],
      validateTerminalTargets: true
    });
    return Boolean(
      inspection.terminal?.status === 'committed' &&
      inspection.manifest?.metadata?.type ===
        'repair_on_touch_trust_finalization' &&
      inspection.manifest?.metadata?.receipt_id === receipt.receipt_id &&
      inspection.manifest?.metadata?.lifecycle_id ===
        receipt.finding_id &&
      inspection.manifest?.metadata?.module_id === receipt.module_id
    );
  } catch {
    return false;
  }
}

function finalizeTrustElevation(receipt, result) {
  if (result?.trust_elevation_pending !== true) {
    return {
      status: 'not_required',
      trust_elevated: false
    };
  }
  if (
    !receipt ||
    typeof receipt !== 'object' ||
    Array.isArray(receipt)
  ) {
    return {
      status: 'not_eligible',
      reason: 'phase_two_identity_mismatch',
      trust_elevated: false
    };
  }
  const timestamp = result.timestamp || nowIso();
  const agentId = result.agent_id || getAgentId();
  const stalePath = path.join(
    stateRoot,
    'maintenance',
    'stale_items.json'
  );
  const queuePath = path.join(
    stateRoot,
    'maintenance',
    'repair_queue.json'
  );
  const staleSnapshot = readJsonWithGuard(
    stalePath,
    { items: [] },
    stateRoot
  );
  const queueSnapshot = readJsonWithGuard(
    queuePath,
    { queue: [] },
    stateRoot
  );
  const phaseTwoReadGuards = [
    staleSnapshot.guard,
    queueSnapshot.guard
  ];
  const records = lifecycleRecords(
    staleSnapshot.value,
    queueSnapshot.value
  );
  const finding = records.get(receipt.finding_id);
  const evidence = finding?.resolution_evidence || {};
  if (
    !finding ||
    !['closed', 'resolved'].includes(finding.status) ||
    evidence.receipt_id !== receipt.receipt_id ||
    evidence.receipt_sha256 !== receipt.content_sha256
  ) {
    return {
      status: 'not_eligible',
      reason: 'current_closure_not_sustained',
      trust_elevated: false
    };
  }
  const loaded = loadReceipt(stateRoot, evidence.receipt_id, {
    finding
  });
  if (
    evidence.receipt_path !== loaded.relative_path ||
    evidence.task_id !== loaded.receipt.task_id ||
    evidence.session_id !== loaded.receipt.session_id
  ) {
    return {
      status: 'not_eligible',
      reason: 'current_closure_provenance_invalid',
      trust_elevated: false
    };
  }
  if (
    stableJson(receipt) !== stableJson(loaded.receipt) ||
    result.receipt_id !== loaded.receipt.receipt_id ||
    result.receipt_sha256 !== loaded.receipt.content_sha256 ||
    result.lifecycle_id !== loaded.receipt.finding_id ||
    result.module_id !== loaded.receipt.module_id ||
    result.task_id !== loaded.receipt.task_id ||
    result.session_id !== loaded.receipt.session_id
  ) {
    return {
      status: 'not_eligible',
      reason: 'phase_two_identity_mismatch',
      trust_elevated: false
    };
  }
  receipt = loaded.receipt;
  const guardSnapshots = [{
    path: loaded.path,
    expected_sha256: loaded.physical_sha256,
    containmentRoot: stateRoot
  }];
  const currentSourceErrors = validateClosedReceiptSources(
    loaded.receipt,
    finding,
    { guardSnapshots }
  );
  if (dedicatedRequirementFor(finding)) {
    try {
      const dedicated = verifyDedicatedEvidence({
        stateRoot,
        evidence,
        verificationReceipt: loaded.receipt,
        finding
      });
      const dedicatedPath = path.join(
        stateRoot,
        dedicated.receipt_path
      );
      guardSnapshots.push({
        path: dedicated.physical_path || dedicatedPath,
        expected_sha256:
          dedicated.physical_sha256 || hash(dedicatedPath),
        containmentRoot: stateRoot
      });
    } catch (error) {
      currentSourceErrors.push(
        error.code || 'dedicated_evidence_invalid'
      );
    }
  }
  const phaseOneTransactionId =
    `repair-${receipt.content_sha256.slice(0, 40)}`;
  const phaseOneTransactionRoot = path.join(
    stateRoot,
    'maintenance',
    'transactions',
    phaseOneTransactionId
  );
  let phaseOneAuthority = null;
  try {
    const phaseOneInspection = inspectTransaction(
      phaseOneTransactionRoot,
      {
        allowedContainmentRoots: [
          stateRoot,
          knowledgeRoot,
          repoRoot
        ]
      }
    );
    const metadata = phaseOneInspection.manifest?.metadata || {};
    if (
      phaseOneInspection.terminal?.status !== 'committed' ||
      metadata.type !== 'repair_on_touch_recertification' ||
      metadata.receipt_id !== receipt.receipt_id ||
      metadata.lifecycle_id !== receipt.finding_id ||
      metadata.module_id !== receipt.module_id
    ) {
      throw new Error('phase one transaction identity mismatch');
    }
    phaseOneAuthority = metadata.trust_elevation_authority || null;
  } catch (error) {
    currentSourceErrors.push(
      error.code || 'phase_one_transaction_invalid'
    );
  }
  const priorErrors = validatePriorModuleClosures(
    records,
    receipt.module_id,
    receipt.finding_id,
    guardSnapshots
  );
  if (currentSourceErrors.length || priorErrors.length) {
    return {
      status: 'not_eligible',
      reason: 'module_closure_provenance_invalid',
      errors: [
        ...currentSourceErrors,
        ...priorErrors.map((item) =>
          `${item.lifecycle_id}:${item.reason}`)
      ],
      trust_elevated: false
    };
  }
  if (Array.from(records.values()).some((item) =>
    canonicalModule(item.module_id) ===
      canonicalModule(receipt.module_id) &&
    !['closed', 'resolved'].includes(item.status)
  )) {
    return {
      status: 'not_eligible',
      reason: 'module_has_open_findings',
      trust_elevated: false
    };
  }
  let currentPlan;
  try {
    currentPlan = loadRepairPlan(
      stateRoot,
      receipt.task_id,
      receipt.session_id
    );
  } catch (error) {
    return {
      status: 'not_eligible',
      reason: error.code || 'repair_plan_invalid',
      trust_elevated: false
    };
  }
  const currentPlanItem = (
    currentPlan.artifact?.opportunities || []
  ).find((item) => item.lifecycle_id === receipt.finding_id);
  const trustAlreadyCommitted =
    completedTrustElevation(receipt);
  if (
    !currentPlan.path ||
    !currentPlanItem ||
    currentPlanItem.status !== 'repaired' ||
    currentPlanItem.receipt_id !== receipt.receipt_id ||
    (
      currentPlanItem.trust_elevation_pending !== true &&
      !trustAlreadyCommitted
    )
  ) {
    return {
      status: 'not_eligible',
      reason: 'repair_plan_trust_elevation_not_pending',
      trust_elevated: false
    };
  }
  if (
    !sameTrustElevationAuthority(
      phaseOneAuthority,
      result.trust_elevation_authority
    ) ||
    !sameTrustElevationAuthority(
      phaseOneAuthority,
      currentPlanItem.trust_elevation_authority
    )
  ) {
    return {
      status: 'not_eligible',
      reason: 'trust_elevation_authority_mismatch',
      trust_elevated: false
    };
  }
  phaseTwoReadGuards.push({
    path: currentPlan.path,
    expected_sha256: currentPlan.content_sha256,
    containmentRoot: stateRoot
  });
  const livePolicySnapshot = livePolicyWithReadSet(
    receipt,
    receipt.repair_mode === 'dedicated'
      ? {
          explicitDedicatedApply: true,
          dedicatedRun: true
        }
      : {}
  );
  const plannedPhaseTwoPolicy =
    currentPlan.artifact?.repair_on_touch;
  const strictPhaseTwoPolicy = restrictPolicyBudgets(
    plannedPhaseTwoPolicy,
    livePolicySnapshot.policy
  );
  if (
    !policyAllowsReceiptMode(
      livePolicySnapshot.policy,
      receipt.repair_mode
    ) ||
    !policyAllowsReceiptMode(
      plannedPhaseTwoPolicy,
      receipt.repair_mode
    )
  ) {
    return {
      status: 'not_eligible',
      reason: 'repair_mode_blocked_by_live_policy',
      trust_elevated: false
    };
  }
  phaseTwoReadGuards.push(...livePolicySnapshot.guards);
  if (
    GENERATED_REPAIR_CLASSES.has(finding.repair_class) &&
    strictPhaseTwoPolicy.effective
      ?.rebuild_generated_artifacts !== true
  ) {
    return {
      status: 'not_eligible',
      reason: 'generated_rebuild_disabled',
      trust_elevated: false
    };
  }
  const registryPath = path.join(
    knowledgeRoot,
    'modules',
    'module_registry.json'
  );
  const registrySnapshot = readJsonWithGuard(
    registryPath,
    { modules: [] },
    knowledgeRoot
  );
  const registry = registrySnapshot.value;
  phaseTwoReadGuards.push(registrySnapshot.guard);
  const moduleInfo = (registry.modules || []).find((item) =>
    canonicalModule(item.module_id) === canonicalModule(receipt.module_id));
  const cardPath = moduleInfo?.card
    ? resolveArtifact(moduleInfo.card)
    : null;
  const trustReportPath = path.join(
    stateRoot,
    'maintenance',
    'trust_report.json'
  );
  const cardSnapshot = cardPath
    ? readJsonWithGuard(
        cardPath,
        null,
        contained(cardPath, knowledgeRoot)
          ? knowledgeRoot
          : repoRoot
      )
    : null;
  const trustSnapshot = readJsonWithGuard(
    trustReportPath,
    null,
    stateRoot
  );
  const card = cardSnapshot?.value || null;
  const trustReport = trustSnapshot.value;
  if (cardSnapshot) phaseTwoReadGuards.push(cardSnapshot.guard);
  phaseTwoReadGuards.push(trustSnapshot.guard);
  if (
    !card ||
    !trustReport ||
    ![
      'trusted',
      'near_trusted',
      'routing_trusted',
      'advisory_only'
    ].includes(card.target_trust_level)
  ) {
    return {
      status: 'not_eligible',
      reason: 'module_trust_target_invalid',
      trust_elevated: false
    };
  }
  let currentAuthority;
  try {
    currentAuthority = buildTrustElevationAuthority(
      receipt,
      moduleInfo.card,
      card,
      plannedPhaseTwoPolicy
    );
  } catch {
    currentAuthority = null;
  }
  if (
    (
      !trustAlreadyCommitted &&
      !sameTrustElevationAuthority(
        phaseOneAuthority,
        currentAuthority
      )
    ) ||
    (
      trustAlreadyCommitted &&
      (
        canonicalPath(moduleInfo.card) !==
          phaseOneAuthority.card_path ||
        card.target_trust_level !==
          phaseOneAuthority.target_trust_level ||
        card.current_trust_level !==
          phaseOneAuthority.target_trust_level
      )
    )
  ) {
    return {
      status: 'not_eligible',
      reason: 'module_trust_authority_changed',
      trust_elevated: false
    };
  }
  const phaseTwoValidation = validateReceipt(receipt, {
    finding,
    scope: currentPlan.artifact.task_scope,
    policyResolution: strictPhaseTwoPolicy,
    stateRoot,
    requireIdentity: true
  });
  if (phaseTwoValidation.ok) {
    let usage;
    try {
      usage = priorRepairBudgetUsage(
        records,
        receipt,
        guardSnapshots
      );
    } catch (error) {
      return {
        status: 'not_eligible',
        reason:
          error.code || 'repair_budget_provenance_invalid',
        trust_elevated: false
      };
    }
    const limits = strictPhaseTwoPolicy.effective;
    const currentWork = receipt.additional_work || {};
    if (usage.findings + 1 > limits.max_findings_per_task) {
      phaseTwoValidation.errors.push(
        'finding_budget_exceeded'
      );
    }
    if (
      usage.wall_time_ms +
        Number(currentWork.wall_time_ms || 0) >
      limits.max_extra_minutes * 60000
    ) {
      phaseTwoValidation.errors.push('time_budget_exceeded');
    }
    if (
      usage.context_percent +
        Number(currentWork.context_percent || 0) >
      limits.max_extra_context_percent
    ) {
      phaseTwoValidation.errors.push(
        'context_budget_exceeded'
      );
    }
    phaseTwoValidation.ok =
      phaseTwoValidation.errors.length === 0;
  }
  if (!phaseTwoValidation.ok) {
    const budgetError = phaseTwoValidation.errors.some(
      (error) => [
        'finding_budget_exceeded',
        'time_budget_exceeded',
        'context_budget_exceeded'
      ].includes(error)
    );
    return {
      status: 'not_eligible',
      reason: budgetError
        ? 'repair_budget_exceeded_live_policy'
        : 'verification_receipt_invalid',
      errors: phaseTwoValidation.errors,
      trust_elevated: false
    };
  }
  const verifiedArtifacts = (
    loaded.receipt.source_files_checked || []
  ).map((item) => item.path);
  const trustReasonState = resolveTrustReasons(
    trustReport,
    receipt.module_id,
    verifiedArtifacts
  );
  if (trustReasonState.has_blockers) {
    return {
      status: 'not_eligible',
      reason: 'module_trust_reasons_remain',
      trust_elevated: false
    };
  }
  const cardWasAtTarget =
    card.current_trust_level === card.target_trust_level;
  const reportWasAtTarget = (
    trustReport.module_statuses || []
  ).some((item) =>
    canonicalModule(item.module_id) ===
      canonicalModule(receipt.module_id) &&
    item.trust_status === card.target_trust_level
  );
  card.current_trust_level = card.target_trust_level;
  card.verification_status =
    receipt.verification_status || 'code_and_tests_verified';
  card.last_recertification_at = timestamp;
  card.last_recertification_by = agentId;
  card.last_recertification_id =
    `RCERT-${receipt.content_sha256.slice(0, 20)}`;
  updateTrustReport(
    trustReport,
    receipt.module_id,
    card.target_trust_level,
    timestamp,
    agentId,
    verifiedArtifacts
  );
  const transactionId =
    `repair-trust-${receipt.content_sha256.slice(0, 40)}`;
  const transactionRoot = path.join(
    stateRoot,
    'maintenance',
    'transactions',
    transactionId
  );
  if (fs.existsSync(transactionRoot)) {
    const inspection = inspectTransaction(transactionRoot, {
      allowedContainmentRoots: [stateRoot, knowledgeRoot, repoRoot],
      validateTerminalTargets: true
    });
    if (
      inspection.terminal?.status === 'committed' &&
      inspection.manifest?.metadata?.receipt_id === receipt.receipt_id &&
      inspection.manifest?.metadata?.lifecycle_id ===
        receipt.finding_id &&
      inspection.manifest?.metadata?.module_id === receipt.module_id &&
      sameTrustElevationAuthority(
        inspection.manifest?.metadata?.trust_elevation_authority,
        phaseOneAuthority
      ) &&
      cardWasAtTarget &&
      reportWasAtTarget
    ) {
      return {
        status: 'committed',
        transaction_id: transactionId,
        idempotent: true,
        trust_elevated: true
      };
    }
  }
  guardSnapshots.push(...phaseTwoReadGuards);
  const guardsByTarget = new Map();
  for (const guard of guardSnapshots) {
    const identity = process.platform === 'win32'
      ? path.resolve(guard.path).toLowerCase()
      : path.resolve(guard.path);
    const existing = guardsByTarget.get(identity);
    if (existing && !sameGuardState(existing, guard)) {
      const error = new Error(
        `Trust finalization guard conflict: ${guard.path}`
      );
      error.code = 'trust_finalization_guard_conflict';
      throw error;
    }
    if (!existing) guardsByTarget.set(identity, guard);
  }
  const committed = commitJsonTransaction({
    stateRoot,
    transactionId,
    allowedContainmentRoots: [stateRoot, knowledgeRoot, repoRoot],
    guards: Array.from(guardsByTarget.values()),
    metadata: {
      type: 'repair_on_touch_trust_finalization',
      lifecycle_id: receipt.finding_id,
      receipt_id: receipt.receipt_id,
      module_id: receipt.module_id,
      task_id: receipt.task_id,
      session_id: receipt.session_id,
      trust_elevation_authority: phaseOneAuthority,
      actor: agentId
    },
    writes: [
      {
        path: cardPath,
        value: card,
        containmentRoot: knowledgeRoot
      },
      {
        path: trustReportPath,
        value: trustReport,
        containmentRoot: stateRoot
      }
    ]
  });
  return {
    status: committed.status,
    transaction_id: committed.transaction_id,
    idempotent: Boolean(committed.idempotent),
    trust_elevated: true
  };
}

function priorRepairBudgetUsage(
  records,
  receipt,
  guardSnapshots = []
) {
  const usage = {
    findings: 0,
    wall_time_ms: 0,
    context_percent: 0
  };
  for (const record of records.values()) {
    if (!['closed', 'resolved'].includes(record.status)) continue;
    if (record.lifecycle_id === receipt.finding_id) continue;
    const evidence = record.resolution_evidence || {};
    if (
      evidence.task_id !== receipt.task_id ||
      evidence.session_id !== receipt.session_id
    ) {
      continue;
    }
    const loaded = loadReceipt(stateRoot, evidence.receipt_id, {
      finding: record
    });
    guardSnapshots.push({
      path: loaded.path,
      expected_sha256: loaded.physical_sha256,
      containmentRoot: stateRoot
    });
    for (const test of loaded.receipt.tests_run || []) {
      const execution = loadExecutionRecord(
        stateRoot,
        test.execution_id
      );
      if (!execution) {
        const error = new Error(
          `Prior repair execution provenance is invalid: ${record.lifecycle_id}`
        );
        error.code = 'repair_budget_provenance_invalid';
        throw error;
      }
      guardSnapshots.push({
        path: execution.path,
        expected_sha256: execution.physical_sha256,
        containmentRoot: stateRoot
      });
    }
    if (
      evidence.receipt_sha256 !== loaded.receipt.content_sha256 ||
      evidence.receipt_path !== loaded.relative_path ||
      loaded.receipt.task_id !== receipt.task_id ||
      loaded.receipt.session_id !== receipt.session_id
    ) {
      const error = new Error(
        `Prior repair receipt provenance is invalid: ${record.lifecycle_id}`
      );
      error.code = 'repair_budget_provenance_invalid';
      throw error;
    }
    usage.findings += 1;
    usage.wall_time_ms += Number(
      loaded.receipt.additional_work?.wall_time_ms || 0
    );
    usage.context_percent += Number(
      loaded.receipt.additional_work?.context_percent || 0
    );
  }
  return usage;
}

function livePolicyForApply(receipt, request = {}) {
  const explicitDedicatedOverride =
    request.explicitDedicatedApply === true &&
    request.dedicatedRun === true &&
    receipt?.repair_mode === 'dedicated';
  return resolvePolicy({
    context,
    ...(explicitDedicatedOverride
      ? { perRun: { mode: 'dedicated', enabled: true } }
      : {})
  });
}

function livePolicyWithReadSet(receipt, request = {}) {
  const configPath = path.join(knowledgeRoot, 'config.yaml');
  const operatorPath = path.join(
    knowledgeRoot,
    'settings',
    'operator-profile.json'
  );
  const statePolicyPath = path.join(
    stateRoot,
    'maintenance',
    'concurrency_policy.json'
  );
  const projectPolicyPath = path.join(
    knowledgeRoot,
    'maintenance',
    'concurrency_policy.json'
  );
  const configGuard = fileGuardSnapshot(configPath, knowledgeRoot);
  const configText = configGuard.expected_exists === false
    ? ''
    : fs.readFileSync(configPath, 'utf8');
  if (
    configGuard.expected_exists !== false &&
    crypto.createHash('sha256').update(configText).digest('hex') !==
      configGuard.expected_sha256
  ) {
    const error = new Error(
      'Repository repair policy changed while it was read'
    );
    error.code = 'repair_policy_drift';
    throw error;
  }
  const operatorSnapshot = readJsonWithGuard(
    operatorPath,
    {},
    knowledgeRoot
  );
  const statePolicySnapshot = readJsonWithGuard(
    statePolicyPath,
    {},
    stateRoot
  );
  const samePolicyFile =
    path.resolve(statePolicyPath) === path.resolve(projectPolicyPath);
  const projectPolicySnapshot = samePolicyFile
    ? statePolicySnapshot
    : readJsonWithGuard(
        projectPolicyPath,
        {},
        knowledgeRoot
      );
  const stateCap = teamPolicyCap(statePolicySnapshot.value);
  const projectCap = samePolicyFile
    ? null
    : teamPolicyCap(projectPolicySnapshot.value);
  const caps = [
    ...(stateCap
      ? [{
          cap: stateCap,
          source: 'workspace team/security policy'
        }]
      : []),
    ...(projectCap
      ? [{
          cap: projectCap,
          source: 'repository team/security policy'
        }]
      : [])
  ];
  const selected = caps.reduce((strictest, candidate) =>
    !strictest ||
    MODE_RANK[candidate.cap] < MODE_RANK[strictest.cap]
      ? candidate
      : strictest
  , null);
  const explicitDedicatedOverride =
    request.explicitDedicatedApply === true &&
    request.dedicatedRun === true &&
    receipt?.repair_mode === 'dedicated';
  const policy = resolvePolicy({
    context,
    repository: parseRepositoryRepairSettings(configText),
    operator: operatorSnapshot.value,
    team: {
      cap: selected?.cap || null,
      source: selected?.source || null,
      sources: caps,
      raw: {
        workspace: statePolicySnapshot.value,
        ...(samePolicyFile
          ? {}
          : { repository: projectPolicySnapshot.value })
      }
    },
    ...(explicitDedicatedOverride
      ? { perRun: { mode: 'dedicated', enabled: true } }
      : {})
  });
  return {
    policy,
    guards: [
      configGuard,
      operatorSnapshot.guard,
      statePolicySnapshot.guard,
      ...(samePolicyFile ? [] : [projectPolicySnapshot.guard])
    ]
  };
}

function applyVerificationReceipt(receipt, request = {}) {
  const timestamp = request.timestamp || nowIso();
  const agentId = request.agentId || getAgentId();
  const stalePath = path.join(stateRoot, 'maintenance', 'stale_items.json');
  const queuePath = path.join(stateRoot, 'maintenance', 'repair_queue.json');
  const freshnessPath = path.join(stateRoot, 'freshness.json');
  const trustReportPath = path.join(stateRoot, 'maintenance', 'trust_report.json');
  const latestOpportunitiesPath = path.join(
    stateRoot,
    'maintenance',
    'repair_opportunities.json'
  );
  const receiptIndexPath = path.join(stateRoot, 'maintenance', 'verification_receipts', 'index.json');
  const readSetGuards = [];
  const staleSnapshot = readJsonWithGuard(
    stalePath,
    { items: [] },
    stateRoot
  );
  const queueSnapshot = readJsonWithGuard(
    queuePath,
    { queue: [] },
    stateRoot
  );
  const staleItems = staleSnapshot.value;
  const repairQueue = queueSnapshot.value;
  readSetGuards.push(staleSnapshot.guard, queueSnapshot.guard);
  const records = lifecycleRecords(staleItems, repairQueue);
  const finding = records.get(String(receipt?.finding_id || ''));
  const base = {
    schema_version: 'knowledge-recertification.v2',
    action: 'apply_verification_receipt',
    timestamp,
    agent_id: agentId,
    receipt_id: receipt?.receipt_id || null,
    receipt_sha256: receipt?.content_sha256 || null,
    lifecycle_id: receipt?.finding_id || null,
    module_id: receipt?.module_id || null,
    task_id: receipt?.task_id || null,
    session_id: receipt?.session_id || null
  };
  if (!finding) return { ...base, status: 'rejected', reason: 'lifecycle_not_found' };
  let plan;
  try {
    plan = loadRepairPlan(
      stateRoot,
      receipt?.task_id,
      receipt?.session_id
    );
  } catch (error) {
    return {
      ...base,
      status: 'rejected',
      reason: error.code || 'repair_plan_invalid',
      errors: error.validation?.errors || []
    };
  }
  const opportunities = plan.artifact;
  const opportunitiesPath = plan.path;
  const scope = opportunities?.task_scope || null;
  if (!opportunities || !scope || !opportunitiesPath) {
    return { ...base, status: 'rejected', reason: 'repair_plan_not_found' };
  }
  readSetGuards.push({
    path: opportunitiesPath,
    expected_sha256: plan.content_sha256,
    containmentRoot: stateRoot
  });
  const findingAlreadyClosed = ['closed', 'resolved'].includes(finding.status);
  if (findingAlreadyClosed) {
    const validation = validateReceipt(receipt, {
      finding,
      scope,
      stateRoot,
      requireIdentity: true
    });
    validation.errors.push(...validateClosedReceiptSources(receipt, finding));
    validation.ok = validation.errors.length === 0;
    if (!validation.ok) {
      return {
        ...base,
        status: 'rejected',
        reason: 'verification_receipt_invalid',
        errors: validation.errors
      };
    }
    const dedicatedRequirement = dedicatedRequirementFor(finding);
    let dedicatedLoaded = null;
    if (dedicatedRequirement) {
      if (
        request.explicitDedicatedApply !== true ||
        request.dedicatedRun !== true ||
        request.confirmedFindingId !== finding.lifecycle_id
      ) {
        return {
          ...base,
          status: 'rejected',
          reason: 'protected_finding_requires_exact_dedicated_replay'
        };
      }
      try {
        dedicatedLoaded = loadDedicatedReceipt(
          stateRoot,
          request.dedicatedReceiptId,
          { verificationReceipt: receipt, finding }
        );
      } catch (error) {
        return {
          ...base,
          status: 'rejected',
          reason: 'dedicated_verification_receipt_invalid',
          errors: [
            error.code || 'dedicated_verification_receipt_invalid',
            ...(error.validation?.errors || [])
          ]
        };
      }
    }
    const evidence = finding.resolution_evidence || {};
    if (
      evidence.receipt_id === receipt.receipt_id &&
      evidence.receipt_sha256 === receipt.content_sha256 &&
      evidence.task_id === receipt.task_id &&
      evidence.session_id === receipt.session_id &&
      (
        !dedicatedRequirement ||
        (
          evidence.dedicated_receipt_id ===
            dedicatedLoaded.receipt.receipt_id &&
          evidence.dedicated_receipt_sha256 ===
            dedicatedLoaded.receipt.content_sha256
        )
      )
    ) {
      const generatedRepair = GENERATED_REPAIR_CLASSES.has(
        finding.repair_class
      );
      const plannedFinding = (
        opportunities.opportunities || []
      ).find((item) =>
        item.lifecycle_id === finding.lifecycle_id);
      const trustElevationPending = Boolean(
        plannedFinding?.trust_elevation_pending
      );
      const trustElevated = Boolean(
        plannedFinding?.trust_elevated &&
        completedTrustElevation(receipt)
      );
      return {
        ...base,
        status: generatedRepair
          ? 'generated_artifact_repaired'
          : trustElevated
            ? 'recertified'
            : trustElevationPending
              ? 'recertified_pending_trust'
              : 'recertified_with_open_findings',
        idempotent: true,
        trust_elevated: trustElevated,
        trust_elevation_pending: trustElevationPending,
        trust_elevation_authority:
          plannedFinding?.trust_elevation_authority || null,
        closed_lifecycle_ids: [finding.lifecycle_id],
        ...(dedicatedLoaded
          ? { dedicated_receipt_id: dedicatedLoaded.receipt.receipt_id }
          : {})
      };
    }
    return {
      ...base,
      status: 'rejected',
      reason: 'finding_already_closed_by_other_evidence'
    };
  }
  const plannedPolicy = opportunities.repair_on_touch || resolvePolicy({ context });
  const livePolicy = livePolicyForApply(receipt, request);
  const policyResolution = restrictPolicyBudgets(plannedPolicy, livePolicy);
  const plannedFinding = (opportunities.opportunities || []).find(
    (item) => item.lifecycle_id === finding.lifecycle_id
  );
  const validation = validateReceipt(receipt, {
    finding,
    scope,
    policyResolution,
    repoRoot,
    stateRoot,
    requireIdentity: true
  });
  if (validation.ok) {
    let usage;
    try {
      usage = priorRepairBudgetUsage(
        records,
        receipt,
        readSetGuards
      );
    } catch (error) {
      return {
        ...base,
        status: 'rejected',
        reason: error.code || 'repair_budget_provenance_invalid'
      };
    }
    const limits = policyResolution.effective;
    const currentWork = receipt.additional_work || {};
    if (usage.findings + 1 > limits.max_findings_per_task) {
      validation.errors.push('finding_budget_exceeded');
    }
    if (
      usage.wall_time_ms + Number(currentWork.wall_time_ms || 0) >
      limits.max_extra_minutes * 60000
    ) {
      validation.errors.push('time_budget_exceeded');
    }
    if (
      usage.context_percent + Number(currentWork.context_percent || 0) >
      limits.max_extra_context_percent
    ) {
      validation.errors.push('context_budget_exceeded');
    }
    validation.ok = validation.errors.length === 0;
  }
  if (!validation.ok) {
    const budgetError = validation.errors.some((error) =>
      [
        'finding_budget_exceeded',
        'time_budget_exceeded',
        'context_budget_exceeded'
      ].includes(error)
    );
    return {
      ...base,
      status: 'rejected',
      reason: budgetError
        ? 'repair_budget_exceeded_live_policy'
        : 'verification_receipt_invalid',
      errors: validation.errors
    };
  }
  if (!plannedFinding || plannedFinding.status !== 'selected') {
    return {
      ...base,
      status: 'rejected',
      reason: 'finding_not_selected_in_current_plan',
      decision_reason:
        plannedFinding?.decision_reason || 'finding_not_planned'
    };
  }
  if (receipt.repair_mode === 'off') {
    return { ...base, status: 'rejected', reason: 'repair_mode_cannot_close_trust_finding' };
  }
  const safeOnlyGenerated =
    receipt.repair_mode === 'safe-only' &&
    GENERATED_REPAIR_CLASSES.has(finding.repair_class);
  const generatedRepair = GENERATED_REPAIR_CLASSES.has(
    finding.repair_class
  );
  if (receipt.repair_mode === 'safe-only' && !safeOnlyGenerated) {
    return {
      ...base,
      status: 'rejected',
      reason: 'safe_only_curated_repair_forbidden'
    };
  }
  if (
    generatedRepair &&
    policyResolution.effective?.rebuild_generated_artifacts !== true
  ) {
    return {
      ...base,
      status: 'rejected',
      reason: 'generated_rebuild_disabled'
    };
  }
  const dedicatedRequirement = dedicatedRequirementFor(finding);
  if (
    dedicatedRequirement &&
    request.explicitDedicatedApply !== true
  ) {
    return {
      ...base,
      status: 'rejected',
      reason: 'protected_finding_requires_explicit_dedicated_apply'
    };
  }
  if (!policyAllowsReceiptMode(livePolicy, receipt.repair_mode)) {
    return {
      ...base,
      status: 'rejected',
      reason: receipt.repair_mode === 'dedicated'
        ? 'dedicated_mode_blocked_by_policy'
        : 'repair_mode_blocked_by_live_policy'
    };
  }
  if (!policyAllowsReceiptMode(plannedPolicy, receipt.repair_mode)) {
    return {
      ...base,
      status: 'rejected',
      reason: 'repair_mode_not_authorized_by_plan'
    };
  }
  let dedicatedLoaded = null;
  if (dedicatedRequirement) {
    if (request.dedicatedRun !== true) {
      return { ...base, status: 'rejected', reason: 'dedicated_run_required' };
    }
    if (request.confirmedFindingId !== finding.lifecycle_id) {
      return {
        ...base,
        status: 'rejected',
        reason: 'dedicated_exact_confirmation_required'
      };
    }
    if (receipt.repair_mode !== 'dedicated') {
      return {
        ...base,
        status: 'rejected',
        reason: 'dedicated_verification_receipt_requires_dedicated_mode'
      };
    }
    if (!policyAllowsReceiptMode(livePolicy, 'dedicated')) {
      return {
        ...base,
        status: 'rejected',
        reason: 'dedicated_mode_blocked_by_policy'
      };
    }
    try {
      dedicatedLoaded = loadDedicatedReceipt(
        stateRoot,
        request.dedicatedReceiptId,
        { verificationReceipt: receipt, finding }
      );
    } catch (error) {
      return {
        ...base,
        status: 'rejected',
        reason: 'dedicated_verification_receipt_invalid',
        errors: [
          error.code || 'dedicated_verification_receipt_invalid',
          ...(error.validation?.errors || [])
        ]
      };
    }
  } else if (request.explicitDedicatedApply === true) {
    return { ...base, status: 'rejected', reason: 'dedicated_receipt_not_required' };
  } else if (receipt.repair_mode === 'dedicated' && request.dedicatedRun !== true) {
    return { ...base, status: 'rejected', reason: 'dedicated_run_required' };
  }
  const savedReceipt = saveReceipt(stateRoot, receipt);
  const currentEvidenceGuardSnapshots = [{
    path: savedReceipt.path,
    expected_sha256: savedReceipt.physical_sha256,
    containmentRoot: stateRoot
  }];
  for (const test of receipt.tests_run || []) {
    const execution = loadExecutionRecord(
      stateRoot,
      test.execution_id
    );
    if (!execution) {
      return {
        ...base,
        status: 'rejected',
        reason: 'verification_execution_not_found'
      };
    }
    currentEvidenceGuardSnapshots.push({
      path: execution.path,
      expected_sha256: execution.physical_sha256,
      containmentRoot: stateRoot
    });
  }
  if (dedicatedLoaded) {
    currentEvidenceGuardSnapshots.push({
      path: dedicatedLoaded.path,
      expected_sha256: dedicatedLoaded.physical_sha256,
      containmentRoot: stateRoot
    });
  }
  const relativeReceipt = path.relative(stateRoot, savedReceipt.path);
  const resolutionEvidence = [{
    lifecycle_id: finding.lifecycle_id,
    code: finding.code,
    artifact: finding.artifact,
    predicate: receipt.resolution_predicate,
    predicate_result: true,
    verifier_type: 'repair_on_touch_verification',
    verifier_id: receipt.receipt_id,
    verifier_result: 'pass',
    receipt_id: receipt.receipt_id,
    receipt_sha256: receipt.content_sha256,
    receipt_path: relativeReceipt.replace(/\\/g, '/'),
    task_id: receipt.task_id,
    session_id: receipt.session_id,
    ...(dedicatedLoaded ? {
      dedicated_verifier_type: dedicatedLoaded.receipt.dedicated_verifier_type,
      dedicated_verifier_id: dedicatedLoaded.receipt.dedicated_verifier_id,
      dedicated_predicate: dedicatedLoaded.receipt.dedicated_predicate,
      dedicated_result: dedicatedLoaded.receipt.dedicated_result,
      dedicated_receipt_id: dedicatedLoaded.receipt.receipt_id,
      dedicated_receipt_sha256: dedicatedLoaded.receipt.content_sha256,
      dedicated_receipt_path: dedicatedLoaded.relative_path
    } : {})
  }];
  const dedicatedEvidenceVerifier = dedicatedLoaded
    ? ({ evidence }) => verifyDedicatedEvidence({
      stateRoot,
      evidence,
      verificationReceipt: receipt,
      finding
    })
    : null;
  const projection = closeFindings({
    staleItems,
    repairQueue,
    lifecycleIds: [finding.lifecycle_id],
    allowedCodes: [finding.code],
    verifiedArtifacts: (receipt.source_files_checked || []).map((item) => item.path),
    resolutionEvidence,
    recertificationId: `RCERT-${receipt.content_sha256.slice(0, 20)}`,
    agentId,
    timestamp,
    verifyDedicatedEvidence: dedicatedEvidenceVerifier
  });
  if (projection.rejected_lifecycle_ids.length || projection.closed_lifecycle_ids.length !== 1) {
    return {
      ...base,
      status: 'rejected',
      reason: 'finding_specific_closure_rejected',
      rejected_lifecycle_ids: projection.rejected_lifecycle_ids
    };
  }

  const registryPath = path.join(
    knowledgeRoot,
    'modules',
    'module_registry.json'
  );
  const registrySnapshot = readJsonWithGuard(
    registryPath,
    { modules: [] },
    knowledgeRoot
  );
  const registry = registrySnapshot.value;
  readSetGuards.push(registrySnapshot.guard);
  const moduleInfo = (registry.modules || []).find((item) => item.module_id === receipt.module_id);
  const writes = [
    { path: stalePath, value: staleItems, containmentRoot: stateRoot },
    { path: queuePath, value: repairQueue, containmentRoot: stateRoot }
  ];
  let card = null;
  let cardPath = null;
  if (moduleInfo?.card && !safeOnlyGenerated) {
    cardPath = resolveArtifact(moduleInfo.card);
    if (!cardPath) return { ...base, status: 'rejected', reason: 'module_card_missing_or_unsafe' };
    const cardSnapshot = readJsonWithGuard(
      cardPath,
      null,
      contained(cardPath, knowledgeRoot)
        ? knowledgeRoot
        : repoRoot
    );
    card = cardSnapshot.value;
    readSetGuards.push(cardSnapshot.guard);
    if (!card) return { ...base, status: 'rejected', reason: 'module_card_invalid' };
    card.verification = card.verification && typeof card.verification === 'object' ? card.verification : {};
    const refs = Array.isArray(card.verification.receipts) ? card.verification.receipts : [];
    if (!refs.some((item) => item.receipt_id === receipt.receipt_id)) {
      refs.push({
        receipt_id: receipt.receipt_id,
        finding_id: receipt.finding_id,
        checked_at: receipt.checked_at,
        path: relativeReceipt.replace(/\\/g, '/'),
        ...(dedicatedLoaded ? {
          dedicated_receipt_id: dedicatedLoaded.receipt.receipt_id,
          dedicated_receipt_path: dedicatedLoaded.relative_path
        } : {})
      });
    }
    card.verification.receipts = refs;
    card.last_verified_at = receipt.checked_at;
    card.last_verified_by = receipt.checked_by;
  }

  const remainingForModule = openModuleItems(staleItems, repairQueue, receipt.module_id);
  const verifiedArtifacts = (receipt.source_files_checked || []).map((item) => item.path);
  const trustSnapshot = readJsonWithGuard(
    trustReportPath,
    {},
    stateRoot
  );
  const trustReport = trustSnapshot.value;
  readSetGuards.push(trustSnapshot.guard);
  const trustReasonState = safeOnlyGenerated
    ? { has_blockers: true }
    : resolveTrustReasons(
      trustReport,
      receipt.module_id,
      verifiedArtifacts
    );
  const priorClosureGuardSnapshots = [];
  const priorClosureProvenanceErrors = safeOnlyGenerated
    ? []
    : validatePriorModuleClosures(
      records,
      receipt.module_id,
      finding.lifecycle_id,
      priorClosureGuardSnapshots
    );
  const trustElevationPending = Boolean(
    card &&
    remainingForModule.length === 0 &&
    priorClosureProvenanceErrors.length === 0 &&
    !trustReasonState.has_blockers &&
    [
      'trusted',
      'near_trusted',
      'routing_trusted',
      'advisory_only'
    ].includes(card.target_trust_level)
  );
  const trustElevationAuthority = trustElevationPending
    ? buildTrustElevationAuthority(
        receipt,
        moduleInfo.card,
        card,
        plannedPolicy
      )
    : null;
  if (card && cardPath) writes.push({ path: cardPath, value: card, containmentRoot: knowledgeRoot });

  const freshnessSnapshot = readJsonWithGuard(
    freshnessPath,
    { tracked_files: [], artifact_statuses: {} },
    stateRoot
  );
  const freshness = freshnessSnapshot.value;
  readSetGuards.push(freshnessSnapshot.guard);
  let freshnessChanged = false;
  for (const source of receipt.source_files_checked || []) {
    const tracked = (freshness.tracked_files || []).find((item) => canonicalPath(item.path) === canonicalPath(source.path));
    if (!tracked) continue;
    tracked.sha256 = source.sha256;
    tracked.status = 'clean';
    tracked.last_scanned_at = timestamp;
    tracked.verification_receipt_id = receipt.receipt_id;
    delete tracked.reason;
    freshnessChanged = true;
  }
  if (freshnessChanged) {
    freshness.generated_at = timestamp;
    writes.push({ path: freshnessPath, value: freshness, containmentRoot: stateRoot });
  }

  const receiptIndexSnapshot = readJsonWithGuard(
    receiptIndexPath,
    {
      schema_version: 'knowledge-verification-receipt-index.v1',
      receipts: []
    },
    stateRoot
  );
  const receiptIndex = receiptIndexSnapshot.value;
  readSetGuards.push(receiptIndexSnapshot.guard);
  if (!(receiptIndex.receipts || []).some((item) => item.receipt_id === receipt.receipt_id)) {
    receiptIndex.receipts = [
      ...(receiptIndex.receipts || []),
      receiptIndexEntry(receipt, relativeReceipt, timestamp)
    ];
  }
  receiptIndex.generated_at = timestamp;
  writes.push({ path: receiptIndexPath, value: receiptIndex, containmentRoot: stateRoot });

  let updatedOpportunities = null;
  if (opportunities && Array.isArray(opportunities.opportunities)) {
    updatedOpportunities = JSON.parse(JSON.stringify(opportunities));
    for (const item of updatedOpportunities.opportunities) {
      if (item.lifecycle_id === finding.lifecycle_id) {
        item.status = 'repaired';
        item.decision_reason = 'verified_and_exact_finding_closed';
        item.receipt_id = receipt.receipt_id;
        item.receipt_path = relativeReceipt.replace(/\\/g, '/');
        if (dedicatedLoaded) {
          item.dedicated_receipt_id =
            dedicatedLoaded.receipt.receipt_id;
          item.dedicated_receipt_path =
            dedicatedLoaded.relative_path;
          item.dedicated_receipt_sha256 =
            dedicatedLoaded.receipt.content_sha256;
        }
        item.closed_at = timestamp;
        item.trust_elevation_pending = trustElevationPending;
        if (trustElevationAuthority) {
          item.trust_elevation_authority =
            trustElevationAuthority;
        } else {
          delete item.trust_elevation_authority;
        }
      }
    }
    const findingsAfter = updatedOpportunities.opportunities.map((item) => ({
      ...item,
      status: item.status === 'repaired' ? 'closed' : item.status
    }));
    updatedOpportunities.task_readiness_after = taskReadiness(findingsAfter, updatedOpportunities.task_scope);
    updatedOpportunities.global_after_pending_doctor = true;
    updatedOpportunities.updated_at = timestamp;
    const updatedPlanValidation =
      validateRepairPlanArtifact(updatedOpportunities);
    if (!updatedPlanValidation.ok) {
      return {
        ...base,
        status: 'rejected',
        reason: 'repair_plan_schema_invalid',
        errors: updatedPlanValidation.errors
      };
    }
    writes.push({ path: opportunitiesPath, value: updatedOpportunities, containmentRoot: stateRoot });
    const latestSnapshot = readJsonWithGuard(
      latestOpportunitiesPath,
      null,
      stateRoot
    );
    const latest = latestSnapshot.value;
    readSetGuards.push(latestSnapshot.guard);
    if (
      path.resolve(opportunitiesPath) !== path.resolve(latestOpportunitiesPath) &&
      latest?.task_scope?.task_id === receipt.task_id &&
      latest?.task_scope?.session_id === receipt.session_id
    ) {
      writes.push({
        path: latestOpportunitiesPath,
        value: updatedOpportunities,
        containmentRoot: stateRoot
      });
    }
  }

  const transactionId = `repair-${receipt.content_sha256.slice(0, 40)}`;
  const sourceGuards = (receipt.source_files_checked || []).map((source) => {
    const absolute = resolveArtifact(source.path);
    if (!absolute) {
      const error = new Error(`Verified source disappeared before commit: ${source.path}`);
      error.code = 'transaction_guard_drift';
      throw error;
    }
    return {
      path: absolute,
      expected_sha256: String(source.sha256).toLowerCase(),
      containmentRoot: contained(absolute, repoRoot) ? repoRoot : knowledgeRoot
    };
  });
  const livePolicySnapshot = livePolicyWithReadSet(receipt, request);
  const livePolicyAtCommit = livePolicySnapshot.policy;
  readSetGuards.push(...livePolicySnapshot.guards);
  const strictPolicyAtCommit = restrictPolicyBudgets(
    plannedPolicy,
    livePolicyAtCommit
  );
  if (
    !policyAllowsReceiptMode(livePolicyAtCommit, receipt.repair_mode) ||
    !policyAllowsReceiptMode(plannedPolicy, receipt.repair_mode)
  ) {
    return {
      ...base,
      status: 'rejected',
      reason: 'repair_mode_blocked_by_live_policy'
    };
  }
  if (
    generatedRepair &&
    strictPolicyAtCommit.effective?.rebuild_generated_artifacts !== true
  ) {
    return {
      ...base,
      status: 'rejected',
      reason: 'generated_rebuild_disabled'
    };
  }
  const commitValidation = validateReceipt(receipt, {
    finding,
    scope,
    policyResolution: strictPolicyAtCommit,
    repoRoot,
    stateRoot
  });
  if (!commitValidation.ok) {
    return {
      ...base,
      status: 'rejected',
      reason: commitValidation.errors.some((error) =>
        ['time_budget_exceeded', 'context_budget_exceeded'].includes(error))
        ? 'repair_budget_exceeded_live_policy'
        : 'verification_receipt_invalid',
      errors: commitValidation.errors
    };
  }
  const transactionGuards = [];
  const guardsByTarget = new Map();
  for (const guard of [
    ...sourceGuards,
    ...currentEvidenceGuardSnapshots,
    ...priorClosureGuardSnapshots,
    ...readSetGuards
  ]) {
    const identity = process.platform === 'win32'
      ? path.resolve(guard.path).toLowerCase()
      : path.resolve(guard.path);
    const existing = guardsByTarget.get(identity);
    if (existing) {
      if (!sameGuardState(existing, guard)) {
        const error = new Error(
          `Repair transaction read-set conflict: ${guard.path}`
        );
        error.code = 'repair_read_set_conflict';
        throw error;
      }
      continue;
    }
    guardsByTarget.set(identity, guard);
    transactionGuards.push(guard);
  }
  const txResult = commitJsonTransaction({
    stateRoot,
    transactionId,
    allowedContainmentRoots: [stateRoot, knowledgeRoot, repoRoot],
    guards: transactionGuards,
    faultAt: request.faultAt || null,
    metadata: {
      type: 'repair_on_touch_recertification',
      lifecycle_id: finding.lifecycle_id,
      receipt_id: receipt.receipt_id,
      dedicated_receipt_id: dedicatedLoaded?.receipt?.receipt_id || null,
      module_id: receipt.module_id,
      task_id: receipt.task_id,
      session_id: receipt.session_id,
      trust_elevation_authority: trustElevationAuthority,
      actor: agentId
    },
    writes
  });
  const result = {
    ...base,
    status: safeOnlyGenerated
      ? 'generated_artifact_repaired'
      : trustElevationPending
        ? 'recertified_pending_trust'
        : 'recertified_with_open_findings',
    idempotent: Boolean(txResult.idempotent),
    receipt_path: relativeReceipt.replace(/\\/g, '/'),
    dedicated_receipt_id: dedicatedLoaded?.receipt?.receipt_id || null,
    dedicated_receipt_path: dedicatedLoaded?.relative_path || null,
    closed_lifecycle_ids: projection.closed_lifecycle_ids,
    untouched_open_findings: projection.untouched_open_findings,
    trust_elevated: false,
    trust_elevation_pending: trustElevationPending,
    trust_elevation_authority: trustElevationAuthority,
    prior_closure_provenance_errors: priorClosureProvenanceErrors,
    ...(priorClosureProvenanceErrors.length
      ? {
          trust_elevation_reason:
            'module_closure_provenance_invalid',
          trust_elevation_errors:
            priorClosureProvenanceErrors.map((item) =>
              `${item.lifecycle_id}:${item.reason}`)
        }
      : {}),
    transaction: {
      transaction_id: txResult.transaction_id,
      status: txResult.status,
      writes: txResult.writes?.length || writes.length
    },
    task_readiness_after: updatedOpportunities?.task_readiness_after || null
  };
  event(result);
  return result;
}

function run(moduleId, request = {}) {
  const timestamp = nowIso();
  const agentId = getAgentId();
  const registry = readJson(path.join(knowledgeRoot, 'modules', 'module_registry.json'), { modules: [] });
  const moduleInfo = (registry.modules || []).find((item) => item.module_id === moduleId);
  const base = { schema_version: 'knowledge-recertification.v2', action: 'recertify', module_id: moduleId, timestamp, agent_id: agentId };
  if (!moduleInfo) return { ...base, status: 'rejected', reason: 'module_not_found' };
  const cardPath = resolveArtifact(moduleInfo.card);
  if (!cardPath) return { ...base, status: 'rejected', reason: 'module_card_missing_or_unsafe', artifact: moduleInfo.card };
  const card = readJson(cardPath, null);
  const policy = card?.recertification || card?.verification?.recertification;
  if (!policy || typeof policy !== 'object') return { ...base, status: 'rejected', reason: 'recertification_policy_missing', artifact: moduleInfo.card };

  const expectedSources = hashMap(policy.source_hashes || policy.sources);
  const expectedEvidence = hashMap(policy.evidence_hashes || policy.evidence);
  const expectedTests = hashMap(policy.test_hashes || policy.tests);
  const errors = [];
  const targetTrust = card.target_trust_level;
  const verificationStatus = policy.verification_status;
  if (!['trusted', 'near_trusted', 'routing_trusted', 'advisory_only'].includes(targetTrust)) errors.push('target_trust_level_missing_or_unsafe');
  if (!verificationStatus || /placeholder|unknown|docs-only|partial_from_docs_only/i.test(String(verificationStatus))) errors.push('verification_status_missing_or_unsafe');
  const requiredSources = Array.from(new Set(card.key_files || []));
  const requiredEvidence = Array.from(new Set(card.evidence_files || []));
  if (!requiredSources.length || !requiredEvidence.length || !Object.keys(expectedTests).length) errors.push('verification_policy_incomplete');
  for (const file of requiredSources) {
    const expected = expectedSources[file];
    const absolute = resolveArtifact(file);
    if (!expected) errors.push(`source_hash_missing:${file}`);
    else if (!absolute) errors.push(`source_missing_or_unsafe:${file}`);
    else if (hash(absolute) !== expected) errors.push(`source_hash_mismatch:${file}`);
  }
  for (const file of requiredEvidence) {
    const expected = expectedEvidence[file];
    const absolute = resolveArtifact(file);
    if (!expected) errors.push(`evidence_hash_missing:${file}`);
    else if (!absolute) errors.push(`evidence_missing_or_unsafe:${file}`);
    else if (hash(absolute) !== expected) errors.push(`evidence_hash_mismatch:${file}`);
    else if (evidenceIsStale(absolute, Number(policy.max_evidence_age_days || 30), Date.now())) errors.push(`evidence_stale:${file}`);
  }
  for (const [file, expected] of Object.entries(expectedTests)) {
    const absolute = resolveArtifact(file);
    if (!expected) errors.push(`test_hash_missing:${file}`);
    else if (!absolute) errors.push(`test_missing_or_unsafe:${file}`);
      else if (hash(absolute) !== expected) errors.push(`test_hash_mismatch:${file}`);
  }
  // Unsafe paths are rejected above by the physical resolver. Return the
  // structured verification failure before canonical lifecycle matching so a
  // malicious policy path cannot turn a safe rejection into an uncaught error.
  if (errors.length) return { ...base, status: 'rejected', reason: 'verification_failed', errors };
  const staleItems = readJson(path.join(stateRoot, 'maintenance', 'stale_items.json'), { items: [] });
  const repairQueue = readJson(path.join(stateRoot, 'maintenance', 'repair_queue.json'), { queue: [] });
  const recordsBefore = lifecycleRecords(staleItems, repairQueue);
  const coverage = policyCoverage(policy, request);
  if (!coverage.selected.length) errors.push('exact_lifecycle_resolution_required');
  errors.push(...coverage.undeclared.map((id) => `lifecycle_not_declared_by_policy:${id}`));
  const protectedLifecycleIds = coverage.selected
    .map((entry) => String(entry.lifecycle_id || ''))
    .filter((lifecycleId) => {
      const lifecycle = recordsBefore.get(lifecycleId);
      return lifecycle && dedicatedRequirementFor(lifecycle);
    });
  if (protectedLifecycleIds.length) {
    return {
      ...base,
      status: 'rejected',
      reason: 'protected_finding_requires_explicit_dedicated_apply',
      lifecycle_ids: protectedLifecycleIds
    };
  }
  const verifiedByPolicy = new Set([
    ...Object.keys(expectedSources),
    ...Object.keys(expectedEvidence),
    ...Object.keys(expectedTests)
  ].map(canonicalPath));
  for (const entry of coverage.selected) {
    if (!entry.lifecycle_id || !entry.code || !entry.artifact || !entry.predicate) errors.push(`resolution_policy_invalid:${entry.lifecycle_id || 'missing_id'}`);
    else if (!ALLOWED_HASH_PREDICATES.has(String(entry.predicate))) errors.push(`resolution_predicate_not_supported:${entry.lifecycle_id}:${entry.predicate}`);
    const lifecycle = recordsBefore.get(String(entry.lifecycle_id || ''));
    if (!lifecycle) {
      errors.push(`lifecycle_not_found:${entry.lifecycle_id || 'missing_id'}`);
      continue;
    }
    if (canonicalModule(lifecycle.module_id) !== canonicalModule(moduleId)) {
      errors.push(`lifecycle_module_mismatch:${entry.lifecycle_id}`);
    }
    if (canonicalCode(lifecycle.code) !== canonicalCode(entry.code)) {
      errors.push(`lifecycle_code_mismatch:${entry.lifecycle_id}`);
    }
    if (canonicalPath(lifecycle.artifact || lifecycle.primary_artifact) !== canonicalPath(entry.artifact)) {
      errors.push(`lifecycle_artifact_mismatch:${entry.lifecycle_id}`);
    }
    if (lifecycle.resolution_predicate &&
        String(lifecycle.resolution_predicate) !== String(entry.predicate)) {
      errors.push(`lifecycle_predicate_mismatch:${entry.lifecycle_id}`);
    }
    for (const artifact of [
      lifecycle.artifact,
      ...(lifecycle.affected_artifacts || [])
    ].filter(Boolean).map(canonicalPath)) {
      if (!verifiedByPolicy.has(artifact)) errors.push(`lifecycle_affected_artifact_unverified:${entry.lifecycle_id}:${artifact}`);
    }
  }
  if (errors.length) return { ...base, status: 'rejected', reason: 'verification_failed', errors };

  const freshnessPath = path.join(stateRoot, 'freshness.json');
  const freshness = readJson(freshnessPath, { tracked_files: [], artifact_statuses: {} });
  const expectations = { ...expectedSources, ...expectedEvidence, ...expectedTests };
  for (const [file, expected] of Object.entries(expectations)) {
    const entry = (freshness.tracked_files || []).find((item) => item.path === file);
    if (!entry) errors.push(`freshness_record_missing:${file}`);
    else if (entry.status === 'missing') errors.push(`freshness_missing:${file}`);
    else {
      const absolute = resolveArtifact(file);
      if (!absolute || hash(absolute) !== expected) errors.push(`freshness_hash_mismatch:${file}`);
    }
  }
  if (errors.length) return { ...base, status: 'rejected', reason: 'freshness_verification_failed', errors };

  const expected = {
    source_hashes: expectedSources,
    evidence_hashes: expectedEvidence,
    test_hashes: expectedTests,
    max_evidence_age_days: Number(policy.max_evidence_age_days || 30)
  };
  const resolves = coverage.selected.map((item) => ({
    lifecycle_id: String(item.lifecycle_id),
    code: canonicalCode(item.code),
    artifact: canonicalPath(item.artifact),
    predicate: String(item.predicate)
  }));
  const digest = verificationDigest(moduleId, expected, resolves);
  const receiptsPath = path.join(stateRoot, 'maintenance', 'recertifications.json');
  const receipts = readJson(receiptsPath, { schema_version: 'knowledge-recertification.v2', receipts: [] });
  const prior = (receipts.receipts || []).find((item) => item.module_id === moduleId
    && item.verification_digest === digest
    && resolves.every((entry) => item.closed_lifecycle_ids?.includes(entry.lifecycle_id)
      || ['closed', 'resolved'].includes(recordsBefore.get(entry.lifecycle_id)?.status)));
  if (prior) return { ...base, status: prior.status || 'recertified', idempotent: true, verification_digest: digest, receipt: prior };
  const alreadyClosed = resolves
    .filter((entry) => ['closed', 'resolved'].includes(recordsBefore.get(entry.lifecycle_id)?.status))
    .map((entry) => entry.lifecycle_id);
  if (alreadyClosed.length) {
    return {
      ...base,
      status: 'rejected',
      reason: 'lifecycle_already_closed_without_matching_recertification',
      lifecycle_ids: alreadyClosed
    };
  }

  for (const [file, expectedHash] of Object.entries(expectations)) {
    const entry = freshness.tracked_files.find((item) => item.path === file);
    entry.sha256 = expectedHash;
    entry.status = 'clean';
    entry.last_scanned_at = timestamp;
    delete entry.reason;
  }
  freshness.artifact_statuses = freshness.artifact_statuses || {};
  delete freshness.artifact_statuses[moduleInfo.card];
  freshness.generated_at = timestamp;

  const resolutionEvidence = resolves.map((entry) => ({
    ...entry,
    predicate_result: true,
    verifier_type: 'first_party_hash_recertification',
    source_hashes: expectedSources,
    evidence_hashes: expectedEvidence,
    test_hashes: expectedTests
  }));
  const recertificationId = `RCERT-${digest.slice(0, 20)}`;
  const projection = closeFindings({
    staleItems,
    repairQueue,
    lifecycleIds: resolves.map((item) => item.lifecycle_id),
    allowedCodes: resolves.map((item) => item.code),
    verifiedArtifacts: Object.keys(expectations),
    resolutionEvidence,
    recertificationId,
    agentId,
    timestamp
  });
  const remainingForModule = openModuleItems(staleItems, repairQueue, moduleId);
  const trustReportPath = path.join(stateRoot, 'maintenance', 'trust_report.json');
  const trustReport = readJson(trustReportPath, {});
  const trustReasonState = resolveTrustReasons(trustReport, moduleId, Object.keys(expectations));
  const trustElevated = remainingForModule.length === 0 &&
    projection.rejected_lifecycle_ids.length === 0 &&
    projection.closed_lifecycle_ids.length === resolves.length &&
    !trustReasonState.has_blockers;
  if (trustElevated) {
    card.current_trust_level = targetTrust;
    card.verification_status = verificationStatus;
    card.last_verified_at = timestamp;
    card.last_verified_by = agentId;
  }
  card.last_recertification_at = timestamp;
  card.last_recertification_by = agentId;
  card.last_recertification_id = recertificationId;

  const transaction = makeTransactionId(moduleId, timestamp, digest);
  const receiptStatus = trustElevated ? 'recertified' : 'recertified_with_open_findings';
  const receipt = {
    schema_version: 'knowledge-recertification-receipt.v2',
    recertification_id: recertificationId,
    module_id: moduleId,
    status: receiptStatus,
    target_trust_level: targetTrust,
    verification_status: verificationStatus,
    verification_digest: digest,
    requested_lifecycle_ids: projection.requested_lifecycle_ids,
    verified_lifecycle_ids: projection.verified_lifecycle_ids,
    closed_lifecycle_ids: projection.closed_lifecycle_ids,
    rejected_lifecycle_ids: projection.rejected_lifecycle_ids,
    untouched_open_findings: projection.untouched_open_findings,
    predicate_results: resolutionEvidence.map((item) => ({
      lifecycle_id: item.lifecycle_id,
      code: item.code,
      artifact: item.artifact,
      predicate: item.predicate,
      result: item.predicate_result
    })),
    source_hashes: expectedSources,
    test_hashes: expectedTests,
    evidence_hashes: expectedEvidence,
    trust_elevated: trustElevated,
    recertified_at: timestamp,
    actor: agentId,
    transaction_id: transaction,
    policy: expected
  };
  receipts.schema_version = 'knowledge-recertification.v2';
  receipts.generated_at = timestamp;
  receipts.receipts = [...(receipts.receipts || []), receipt];
  if (trustElevated) updateTrustReport(trustReport, moduleId, targetTrust, timestamp, agentId, Object.keys(expectations));
  else {
    trustReport.generated_at = timestamp;
    trustReport.generated_by = agentId;
  }

  const txResult = commitJsonTransaction({
    stateRoot,
    transactionId: transaction,
    allowedContainmentRoots: [stateRoot, knowledgeRoot, repoRoot],
    guards: Object.entries(expectations).map(([relative, expected]) => {
      const absolute = resolveArtifact(relative);
      if (!absolute) {
        const error = new Error(`Verified artifact disappeared before commit: ${relative}`);
        error.code = 'transaction_guard_drift';
        throw error;
      }
      return {
        path: absolute,
        expected_sha256: expected,
        containmentRoot: contained(absolute, repoRoot) ? repoRoot : knowledgeRoot
      };
    }),
    faultAt: request.faultAt || null,
    metadata: { type: 'recertification', module_id: moduleId, recertification_id: recertificationId, actor: agentId },
    writes: [
      { path: freshnessPath, value: freshness, containmentRoot: stateRoot },
      { path: cardPath, value: card, containmentRoot: knowledgeRoot },
      { path: path.join(stateRoot, 'maintenance', 'stale_items.json'), value: staleItems, containmentRoot: stateRoot },
      { path: path.join(stateRoot, 'maintenance', 'repair_queue.json'), value: repairQueue, containmentRoot: stateRoot },
      { path: receiptsPath, value: receipts, containmentRoot: stateRoot },
      { path: trustReportPath, value: trustReport, containmentRoot: stateRoot }
    ]
  });
  const result = {
    ...base,
    status: receiptStatus,
    idempotent: false,
    verification_digest: digest,
    transaction: { transaction_id: txResult.transaction_id, status: txResult.status, writes: txResult.writes.length },
    receipt,
    queue_transitions: projection.events
  };
  event(result);
  return result;
}

function main() {
  const args = process.argv.slice(2);
  const moduleId = args.find((arg) => !arg.startsWith('--'));
  if (!moduleId) throw new Error('Usage: node .knowledge/tools/recertify.js <module-id> [--lifecycle-id=<id>] [--request=<json>] [--fault-at=<point>] [--json]');
  ensureDir(path.join(stateRoot, 'maintenance'));
  const request = parseRequestArgs(args);
  const result = withContainedLock(RECERTIFY_LOCK, () => {
    const recoveredTransactions = recoverTransactions(stateRoot, {
      allowedContainmentRoots: [stateRoot, knowledgeRoot, repoRoot],
      transactionIdPrefixes: ['recert-']
    });
    const outcome = run(moduleId, request);
    outcome.recovered_transactions = recoveredTransactions;
    if (!String(outcome.status).startsWith('recertified')) event(outcome);
    return outcome;
  });
  console.log(JSON.stringify(result, null, 2));
  return result;
}

module.exports = {
  run,
  main,
  applyVerificationReceipt,
  validateClosedReceiptSources,
  validatePriorModuleClosures,
  completedTrustElevation,
  finalizeTrustElevation,
  __test: {
    verificationDigest,
    evidenceIsStale,
    stableHash: hash,
    policyCoverage,
    parseRequestArgs,
    makeTransactionId,
    openModuleItems,
    receiptIndexEntry
  }
};

if (require.main === module) {
  try {
    const result = main();
    if (!String(result.status).startsWith('recertified')) process.exit(2);
  } catch (error) {
    console.error(error.stack || error.message);
    process.exit(1);
  }
}
