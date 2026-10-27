'use strict';

// Read-only factual currency. This module neither certifies application safety
// nor changes lifecycle records. The caller owns persistence and transactions.
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { types: { isProxy } } = require('node:util');
const { assertSafeContainedPath, assertSafeContainmentRoot, containedPath } = require('./json-store');
const { loadExecutionRecord, secretPaths, privateValuePaths } = require('./verification-execution');
const { normalizedFinding, identitySha256, stableId, findingOccurrence, dedicatedRequirementFor } = require('./queue-lifecycle');
const { moduleOwnershipBoundaries, normalizedOwnershipPaths, normalizedConditionalDependencies,
  validatedModuleRegistry, validatedOwnObject, validatedOwnArray, pathComparisonIdentity, mergeModuleDeclaration } = require('./module-ownership');

const SCHEMA_VERSION = 'knowledge-currency-receipt.v3';
const REQUEST_SCHEMA = 'knowledge-currency-request.v3';
const { copyInertData } = require('./json-transaction');
// Shared validators constrain every independent unit; they never confer
// factual coverage merely by being included in a verification snapshot.
const LEGACY_AUTHORITY_FILES = Object.freeze([
  ".knowledge/schemas/verification-execution.schema.json",
  ".knowledge/schemas/verification-execution-v2.schema.json",
  ".knowledge/tools/doctor.js",
  ".knowledge/tools/knowledge-currency.js",
  ".knowledge/tools/lib/agent-task-workflow.js",
  ".knowledge/tools/lib/contained-lock-manager.js",
  ".knowledge/tools/lib/inert-data.js",
  ".knowledge/tools/lib/json-store.js",
  ".knowledge/tools/lib/json-transaction.js",
  ".knowledge/tools/lib/knowledge-currency-batch.js",
  ".knowledge/tools/lib/knowledge-currency.js",
  ".knowledge/tools/lib/lock-policy.js",
  ".knowledge/tools/lib/module-ownership.js",
  ".knowledge/tools/lib/path-context.js",
  ".knowledge/tools/lib/queue-lifecycle.js",
  ".knowledge/tools/lib/repair-on-touch.js",
  ".knowledge/tools/lib/task-routing.js",
  ".knowledge/tools/lib/verification-execution.js",
  ".knowledge/tools/lib/verification-finalization.js",
  ".knowledge/tools/lib/verification-policy.js",
  ".knowledge/tools/lib/verification-progress.js",
  ".knowledge/tools/lib/verification-control.js",
  ".knowledge/verification-policy.json",
  ".knowledge/tools/lib/verification-supervisor.js",
  ".knowledge/tools/lib/verification-watchdog.js",
  ".knowledge/tools/lib/verification-worker.js",
  ".knowledge/tools/lib/verification-windows-job.js",
  ".knowledge/tools/lib/verification-windows-job.ps1",
  ".knowledge/tools/lib/verification-linux-namespace.js",
  ".knowledge/tools/lib/verification-linux-namespace.c",
  ".knowledge/tools/lib/verification-recovery.js",
  ".knowledge/tools/lib/verification-windows-recovery.js",
  ".knowledge/tools/lib/verification-windows-recovery.ps1",
  ".knowledge/tools/repair-on-touch.js"
]);
const { PROFILE: AUTHORITY_PROFILE, INVOCATION_PATHS } = require('./runtime-authority-profile');
// Old receipts retain their stored bytes. They cannot grant current coverage
// under a wider authority profile without a new physical verification.
const AUTHORITY_FILES = Object.freeze([...new Set([...LEGACY_AUTHORITY_FILES,
  ...INVOCATION_PATHS.map(name => '.knowledge/' + name),
  ...require('./verification-darwin-finalization').IMPLEMENTATION_PATHS.map(name => '.knowledge/' + name)
])]);
const REVIEW_SCHEMA = 'knowledge-currency-review.v1';
const INDEX_SCHEMA = 'knowledge-currency-index.v1';
const FACTUAL_PREDICATE = 'current_facts_confirmed_routing_only'; // Factual evidence; never lifecycle resolution.
const ALLOWED_CODES = Object.freeze(['tracked_file_needs_recheck', 'tracked_file_changed', 'suspect_module', 'low_confidence_module']);
const HASH = /^[a-f0-9]{64}$/;
const RECEIPT_ID = /^KCUR-[a-f0-9]{64}$/;
const MAX_BYTES = 32 * 1024 * 1024;
// Only historical native authentication may register an issue. The public
// predicate checks its exact semantics; there is deliberately no trust setter.
const nativeScopedIssueAuthority = new WeakMap();

function rememberNativeScopedIssue(issue) {
  nativeScopedIssueAuthority.set(issue, currencyDigest(issue));
  return issue;
}
function isNativeScopedCurrencyIssue(issue) {
  const fingerprint = issue && nativeScopedIssueAuthority.get(issue);
  if (!fingerprint) return false;
  try { return currencyDigest(issue) === fingerprint; }
  catch { return false; }
}

function fail(code, message) { const error = new Error(message || code); error.code = code; throw error; }
function requireThat(value, code, message) { if (!value) fail(code, message); }
function credentialAssignment(value) {
  return typeof value === 'string' && /\b(?:api[_-]?key|secret|token|password|authorization|private[_-]?key)\s*[:=]\s*["']?(?!null\b|undefined\b|false\b|true\b|<redacted>|\*{4})[^\s,;"']+/i.test(value);
}
function privacyCheck(value) {
  // JSON pointers are typed addresses, not absolute filesystem paths. They
  // remain subject to the secret scan and full provenance validation.
  const publicSurface = JSON.parse(JSON.stringify(value));
  const scope = publicSurface.scope || publicSurface;
  if (Array.isArray(scope.claims)) for (const claim of scope.claims) {
    if (Array.isArray(claim.provenance)) for (const reference of claim.provenance) delete reference.pointer;
  }
  const assignments = [];
  function walk(item, at = '$') {
    if (typeof item === 'string' && credentialAssignment(item)) assignments.push(at);
    else if (Array.isArray(item)) item.forEach((child,index)=>walk(child,`${at}[${index}]`));
    else if (object(item)) for (const [key,child] of Object.entries(item)) {
      if (secretPaths(key).length || privateValuePaths(key).length || credentialAssignment(key)) assignments.push(`${at}.${key}`);
      walk(child,`${at}.${key}`);
    }
  }
  walk(value);
  const fields = [...new Set([...secretPaths(value), ...privateValuePaths(publicSurface), ...assignments])];
  if (fields.length) {
    const error = new Error('Currency evidence is blocked because it contains a possible secret or private value (********). Review the source field; no receipt was issued.');
    error.code = 'currency_recording_blocked';
    error.blocked_fields = fields.map(field => /^[a-zA-Z0-9_$.[\]-]{1,160}$/.test(field) && !secretPaths(field).length ? field : 'currency_evidence');
    throw error;
  }
}
function safeRiskDetails(rows) {
  function mask(value) {
    if (typeof value === 'string') return secretPaths(value).length || privateValuePaths(value).length || credentialAssignment(value) ? '********' : value;
    if (Array.isArray(value)) return value.map(mask);
    if (object(value)) return Object.fromEntries(Object.entries(value).map(([key, child]) =>
      [secretPaths(key).length || privateValuePaths(key).length || credentialAssignment(key) ? 'masked_field' : key,
        secretPaths({ [key]:child }).length ? '********' : mask(child)]));
    return value;
  }
  return rows.map(mask);
}
function assuranceProjection(risks) {
  const safe = safeRiskDetails(risks);
  const open = safe.filter(row => !terminal(row));
  return { status:open.length ? 'open_risks' : 'not_assessed', open_findings:open,
    terminal_findings_not_assessed:safe.filter(terminal),
    note:'Currency does not verify terminal application closures or their security evidence.',
    grants_assurance:false };
}
function object(value) { return value !== null && typeof value === 'object' && !Array.isArray(value); }
function canonicalJson(value) {
  if (Array.isArray(value)) return '[' + value.map(canonicalJson).join(',') + ']';
  if (object(value)) return '{' + Object.keys(value).sort().map(key => JSON.stringify(key) + ':' + canonicalJson(value[key])).join(',') + '}';
  requireThat(value === null || ['string', 'boolean', 'number'].includes(typeof value), 'currency_json_invalid');
  requireThat(typeof value !== 'number' || Number.isFinite(value), 'currency_json_invalid');
  return JSON.stringify(value);
}
function sha256(value) { return crypto.createHash('sha256').update(value).digest('hex'); }
function currencyDigest(value) { return sha256(canonicalJson(value)); }
function manifestDigest(manifest) {
  const body = { ...manifest }; delete body.receipt_id; delete body.content_sha256;
  return currencyDigest(body);
}
function same(a, b) { return canonicalJson(a) === canonicalJson(b); }
function id(value, code = 'currency_identity_invalid') {
  requireThat(typeof value === 'string' && value.length > 0 && value === value.trim() && !/[\x00-\x1f\x7f]/.test(value), code);
  return value;
}
function relative(value) {
  requireThat(typeof value === 'string' && value.length > 0, 'currency_path_invalid');
  const normalized = value.replace(/\\/g, '/');
  requireThat(!/[\x00-\x1f\x7f:*?]/.test(normalized) && !normalized.startsWith('/') && normalized === normalized.trim(), 'currency_path_invalid');
  requireThat(normalized.split('/').every(part => part && part !== '.' && part !== '..' && part === part.trim() && !/[. ]$/.test(part)), 'currency_path_invalid');
  return normalized;
}
function unique(values, key = value => value) {
  const seen = new Set();
  for (const value of values) {
    const identity = key(value);
    requireThat(!seen.has(identity), 'currency_scope_collision'); seen.add(identity);
  }
  return values;
}
function list(value, code) { requireThat(Array.isArray(value), code); return value; }
function jsonFile(reader, root, file, optional = false) {
  const pin = reader(root, file, optional);
  if (!pin) return null;
  try { return { pin, value: JSON.parse(pin.body.toString('utf8').replace(/^\uFEFF/, '')) }; }
  catch { fail('currency_json_malformed', 'A currency dependency is not valid JSON.'); }
}
function makeReader() {
  const identities = new Map();
  const captured = new Map();
  const stats = { physical_reads: 0, cache_hits: 0, guard_reads: 0 };
  function read(root, file, optional = false, fresh = false) {
    const rel = relative(file); const absolute = path.resolve(root, rel);
    const key = path.resolve(root).toLowerCase() + '/' + rel.toLowerCase();
    requireThat(!identities.has(key) || identities.get(key) === rel, 'currency_scope_collision');
    identities.set(key, rel);
    if (!fresh && captured.has(key)) { stats.cache_hits++; return captured.get(key).pin; }
    assertSafeContainedPath(root, absolute, { allowMissing: optional });
    let stat;
    try { stat = fs.lstatSync(absolute); }
    catch (error) {
      if (optional && error.code === 'ENOENT') { captured.set(key, { root, rel, optional, pin: null }); return null; }
      throw error;
    }
    requireThat(stat.isFile() && !stat.isSymbolicLink() && stat.nlink === 1 && stat.size <= MAX_BYTES, 'currency_file_unsafe');
    const fd = fs.openSync(absolute, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
    let body;
    try {
      const before = fs.fstatSync(fd);
      requireThat(before.isFile() && before.nlink === 1 && before.dev === stat.dev && before.ino === stat.ino, 'currency_file_changed_during_read');
      body = fs.readFileSync(fd);
      stats.physical_reads++;
      const after = fs.fstatSync(fd);
      requireThat(after.nlink === 1 && before.size === after.size && before.mtimeMs === after.mtimeMs && before.ctimeMs === after.ctimeMs && body.length <= MAX_BYTES, 'currency_file_changed_during_read');
    } finally { fs.closeSync(fd); }
    assertSafeContainedPath(root, absolute);
    const final = fs.lstatSync(absolute);
    requireThat(final.nlink === 1 && final.ino === stat.ino && final.dev === stat.dev && final.size === body.length && final.mtimeMs === stat.mtimeMs && final.ctimeMs === stat.ctimeMs, 'currency_file_changed_during_read');
    const pin = { path: rel, sha256: sha256(body), body };
    if (!fresh) captured.set(key, { root, rel, optional, pin });
    return pin;
  }
  read.verify = () => {
    for (const entry of captured.values()) {
      stats.guard_reads++;
      const live = read(entry.root, entry.rel, entry.optional, true);
      requireThat((live?.sha256 || null) === (entry.pin?.sha256 || null), 'currency_assessment_changed');
    }
  };
  read.stats = stats;
  return read;
}
function roots(context) {
  requireThat(context && typeof context.targetRoot === 'string' && typeof context.stateRoot === 'string', 'currency_context_invalid');
  return { target: assertSafeContainmentRoot(context.targetRoot), state: assertSafeContainmentRoot(context.stateRoot) };
}
function storage(context) {
  return {
    index: relative(context.currency?.indexPath || 'maintenance/knowledge_currency/index.json'),
    receipts: relative(context.currency?.receiptDirectory || 'maintenance/knowledge_currency/receipts')
  };
}
function stateReference(root, target, file) {
  const absolute = path.resolve(root, file);
  return containedPath(target, absolute) ? path.relative(target, absolute).replace(/\\/g, '/') : 'state/' + relative(file);
}
function pinOnly(pin) { return { path: pin.path, sha256: pin.sha256 }; }
function rows(value, field) {
  if (Array.isArray(value)) return value;
  requireThat(object(value) && Array.isArray(value[field]), 'currency_projection_invalid');
  return value[field];
}
function registryRows(registry) {
  if (registry == null) return [];
  const data = validatedOwnObject(registry);
  const lifecycle = data.lifecycle ? validatedOwnObject(data.lifecycle) : null;
  const records = data.records || data.findings || lifecycle?.records;
  if (!records) return [];
  requireThat(!isProxy(records), 'module_ownership_invalid');
  return Array.isArray(records) ? validatedOwnArray(records) : Object.values(validatedOwnObject(records));
}
function isCurrencyEligibleFinding(row) {
  if (!object(row) || !ALLOWED_CODES.includes(row.code)) return false;
  if (['protected', 'manual_review_required', 'policy_violation', 'incident', 'conflict', 'requires_dedicated_verifier'].some(key => row[key] === true)) return false;
  try { return !dedicatedRequirementFor({ ...row, security_sensitive: false }) && row.repair_class === 'verify_on_touch'; } catch { return false; }
}
function binding(row) {
  requireThat(object(row), 'currency_finding_invalid');
  const normalized = normalizedFinding(row);
  // Detector wording changes after a scan; factual claims and risk impact
  // descriptions have their own separately bound provenance.
  delete normalized.reason;
  requireThat(row.lifecycle_id === stableId('LC', row) && row.identity_sha256 === identitySha256(row), 'currency_finding_identity_mismatch');
  requireThat(!row.artifact || !row.primary_artifact || relative(row.artifact) === relative(row.primary_artifact), 'currency_finding_identity_mismatch');
  requireThat(!row.stale_id || row.stale_id === stableId('STALE', row), 'currency_finding_identity_mismatch');
  requireThat(!row.repair_id || row.repair_id === stableId('RQ', row), 'currency_finding_identity_mismatch');
  requireThat(typeof row.status === 'string' && row.status.length > 0, 'currency_finding_status_invalid');
  const occurrence = findingOccurrence(row);
  return {
    lifecycle_id: row.lifecycle_id, identity_sha256: row.identity_sha256,
    ...normalized, required_checks: [...normalized.required_checks].sort(),
    occurrence: occurrence.occurrence, occurred_at: occurrence.occurred_at,
    protection: {
      protected: row.protected === true, manual_review_required: row.manual_review_required === true,
      policy_violation: row.policy_violation === true, incident: row.incident === true,
      conflict: row.conflict === true, requires_dedicated_verifier: row.requires_dedicated_verifier === true
    }
  };
}
function terminal(row) { return ['closed', 'resolved'].includes(row.status); }
function isAssuranceRisk(row) {
  // A CLOSED label is not proof of application assurance. Bind terminal
  // protected rows as well, but report them separately from genuinely OPEN
  // rows. No historical closure verifier is impersonated by this module.
  if (!object(row) || isCurrencyEligibleFinding(row)) return false;
  const explicitProtection = ['protected', 'manual_review_required', 'policy_violation', 'incident', 'conflict', 'requires_dedicated_verifier'].some(key => row[key] === true);
  const observationCode = [...ALLOWED_CODES, 'artifact_needs_recheck', 'tracked_file_missing', 'tracked_file_suspect', 'missing_module_card'].includes(row.code);
  // A sensitive path on a freshness observation is not itself a vulnerability.
  // This does not make the observation eligible for a factual receipt.
  if (observationCode && !explicitProtection && !dedicatedRequirementFor({ ...row, security_sensitive: false })) return false;
  return Boolean(dedicatedRequirementFor(row)) || explicitProtection;
}
function riskSnapshot(row) {
  // Retain all semantic risk fields, including extensions. Projection IDs and
  // observation timestamps are not changes to the risk itself.
  const body = { ...row };
  if (row.artifact || row.primary_artifact) {
    const artifact = relative(row.primary_artifact || row.artifact);
    requireThat(!row.artifact || relative(row.artifact) === artifact, 'currency_risk_location_conflict');
    body.primary_artifact = artifact;
  }
  for (const key of ['id', 'artifact', 'subject', 'last_seen_at', 'detected_at', 'detected_by']) delete body[key];
  if (object(body.sources)) body.sources = Object.fromEntries(Object.entries(body.sources).map(([producer, observation]) => {
    const semantic = { ...observation }; delete semantic.observed_at; return [producer, semantic];
  }));
  return body;
}
function currentAssuranceRisks(context, risks, reader, resolved) {
  // Physical assurance is mandatory even when the caller supplies no risks.
  // Keep pair admission outside the optional-history fallback: unreadable or
  // inconsistent native state cannot certify an empty/current risk catalog.
  const lifecycle = require('./queue-lifecycle');
  const stalePath = 'maintenance/stale_items.json';
  const repairPath = 'maintenance/repair_queue.json';
  const nativeStale = jsonFile(reader, resolved.state, stalePath);
  const nativeRepair = jsonFile(reader, resolved.state, repairPath);
  const staleRows = rows(nativeStale.value, 'items');
  const repairRows = rows(nativeRepair.value, 'queue');
  lifecycle.lifecycleById(nativeStale.value, nativeRepair.value);
  const nativeRisks = new Map();
  for (const group of [staleRows, repairRows]) for (const row of group) {
    requireThat(object(row), 'currency_finding_invalid');
    if (!isAssuranceRisk(row)) continue;
    const snapshot = riskSnapshot(row);
    const key = row.lifecycle_id || 'legacy-' + currencyDigest(snapshot);
    if (nativeRisks.has(key)) requireThat(same(nativeRisks.get(key), snapshot), 'currency_risk_projection_mismatch');
    else nativeRisks.set(key, snapshot);
  }
  const complete = new Map(nativeRisks);
  const callerMismatches = new Set();
  for (const [key, snapshot] of risks) {
    if (nativeRisks.has(key)) {
      if (!same(nativeRisks.get(key), snapshot)) callerMismatches.add(key);
    } else complete.set(key, snapshot);
  }
  // All unresolved history remains visible; factual proof has no disposition authority.
  return complete;
}

function inputs(context, projections, reader, resolved) {
  const stale = projections.staleItems === undefined ? jsonFile(reader, resolved.state, 'maintenance/stale_items.json').value : projections.staleItems;
  const repair = projections.repairQueue === undefined ? jsonFile(reader, resolved.state, 'maintenance/repair_queue.json').value : projections.repairQueue;
  const groups = [rows(stale, 'items'), rows(repair, 'queue'), registryRows(projections.registry)];
  const maps = groups.map(group => {
    const out = new Map();
    for (const row of group) {
      requireThat(object(row), 'currency_finding_invalid');
      if (!row.lifecycle_id) continue;
      requireThat(!out.has(row.lifecycle_id), 'currency_projection_collision');
      out.set(row.lifecycle_id, { row, binding: binding(row) });
    }
    return out;
  });
  const live = new Map();
  for (const map of maps) for (const [key, item] of map) {
    if (live.has(key)) {
      const prior = live.get(key);
      requireThat(same(prior.binding, item.binding) && prior.row.status === item.row.status && same(prior.row.resolution_evidence || null, item.row.resolution_evidence || null), 'currency_projection_mismatch');
    } else live.set(key, item);
  }
  for (const [key, item] of live) {
    const left = maps[0].get(key); const right = maps[1].get(key);
    requireThat(Boolean(left) === Boolean(right), 'currency_projection_missing');
    requireThat(terminal(item.row) || Boolean(left && right), 'currency_projection_missing');
  }
  const risks = new Map();
  for (const group of groups) for (const row of group) {
    if (!isAssuranceRisk(row)) continue;
    const snapshot = riskSnapshot(row);
    const key = row.lifecycle_id || 'legacy-' + currencyDigest(snapshot);
    if (risks.has(key)) requireThat(same(risks.get(key), snapshot), 'currency_risk_projection_mismatch');
    else risks.set(key, snapshot);
  }
  // Derived routing/card unions are useful for selection, never registry
  // authority. Reconstruct factual module bindings from the physical registry.
  const registry = jsonFile(reader, resolved.target, '.knowledge/modules/module_registry.json').value;
  // Always retain the complete physical-plus-pending risk inventory. No
  // rebaseline, inactive flag or caller projection may retire its history.
  const assuranceRisks = currentAssuranceRisks(context, risks, reader, resolved);
  return { live, risks: [...assuranceRisks.values()].sort((a, b) => canonicalJson(a).localeCompare(canonicalJson(b))), registry };
}
function pointerValue(document, pointer) {
  requireThat(typeof pointer === 'string' && (pointer === '' || pointer.startsWith('/')), 'currency_provenance_pointer_invalid');
  let value = document;
  if (pointer !== '') for (const raw of pointer.slice(1).split('/')) {
    requireThat(!/~(?![01])/.test(raw), 'currency_provenance_pointer_invalid');
    const key = raw.replace(/~1/g, '/').replace(/~0/g, '~');
    requireThat(value !== null && typeof value === 'object' && Object.prototype.hasOwnProperty.call(value, key), 'currency_provenance_pointer_missing');
    value = value[key];
  }
  return value;
}
function verifyAddress(manifest) {
  requireThat(object(manifest) && manifest.schema_version === SCHEMA_VERSION && HASH.test(manifest.content_sha256) && RECEIPT_ID.test(manifest.receipt_id), 'currency_manifest_schema_invalid');
  requireThat(manifest.content_sha256 === manifestDigest(manifest) && manifest.receipt_id === 'KCUR-' + manifest.content_sha256, 'currency_manifest_content_mismatch');
  requireThat(manifest.routing_cap === 'routing_trusted' && manifest.security_certificate === false && manifest.lifecycle_effect === 'none', 'currency_assurance_escalation');
}
function readPredecessors(context, request, reader, resolved, issuance) {
  const ids = unique(list(request.supersedes || [], 'currency_supersedes_invalid').map(value => {
    requireThat(typeof value === 'string' && RECEIPT_ID.test(value), 'currency_supersedes_invalid'); return value;
  })).sort();
  if (!ids.length) return [];
  const store = storage(context);
  if (issuance) {
    const index = jsonFile(reader, resolved.state, store.index);
    requireThat(index.value.schema_version === INDEX_SCHEMA && Array.isArray(index.value.receipt_ids), 'currency_index_invalid');
    for (const receiptId of ids) requireThat(index.value.receipt_ids.includes(receiptId), 'currency_predecessor_not_active');
  }
  return ids.map(receiptId => {
    const statePath = store.receipts + '/' + receiptId.slice(5) + '.json';
    const predecessor = jsonFile(reader, resolved.state, statePath);
    verifyAddress(predecessor.value);
    requireThat(predecessor.value.receipt_id === receiptId && Array.isArray(predecessor.value.scope?.findings), 'currency_predecessor_invalid');
    return { receipt_id: receiptId, path: stateReference(resolved.state, resolved.target, statePath), sha256: predecessor.pin.sha256, manifest: predecessor.value };
  });
}
function prepare(context, request, projections, issuance, assessment = null) {
  requireThat(object(request), 'currency_request_invalid');
  id(request.author_id); id(request.task_id); id(request.session_id);
  requireThat(request.schema_version === REQUEST_SCHEMA, 'currency_request_schema_invalid');
  const resolved = assessment?.resolved || roots(context); const reader = assessment?.reader || makeReader();
  const live = assessment?.current || inputs(context, projections, reader, resolved);
  const explicitSources = unique(list(request.source_files, 'currency_sources_required').map(value => relative(typeof value === 'string' ? value : value.path)), value => value.toLowerCase());
  requireThat(explicitSources.length > 0, 'currency_sources_required');
  const sourcePaths = unique([...new Set([...explicitSources, ...AUTHORITY_FILES])], value => value.toLowerCase()).sort();
  requireThat(sourcePaths.length > 0, 'currency_sources_required');
  const pins = new Map();
  function pin(file) {
    const rel = relative(file);
    if (!pins.has(rel)) pins.set(rel, pinOnly(reader(resolved.target, rel)));
    return pins.get(rel);
  }
  sourcePaths.forEach(pin);
  const claimIds = new Set();
  const claims = list(request.claims, 'currency_claims_required').map(raw => {
    requireThat(object(raw), 'currency_claim_invalid');
    const claimId = id(raw.claim_id); requireThat(!claimIds.has(claimId), 'currency_claim_collision'); claimIds.add(claimId);
    const file = relative(raw.path); requireThat(sourcePaths.includes(file), 'currency_claim_source_missing');
    const description = id(raw.description, 'currency_claim_description_required');
    const moduleId = raw.module_id == null ? null : id(raw.module_id);
    const evidence = unique(list(raw.evidence_paths, 'currency_claim_evidence_required').map(relative), value => value.toLowerCase()).sort().map(pin);
    requireThat(evidence.length > 0, 'currency_claim_evidence_required');
    const provenance = list(raw.provenance, 'currency_claim_provenance_required').map(ref => {
      requireThat(object(ref), 'currency_claim_provenance_required');
      const document = jsonFile(reader, resolved.target, relative(ref.path));
      pin(ref.path);
      const value = pointerValue(document.value, ref.pointer);
      if (typeof value === 'string') requireThat(value === description, 'currency_claim_provenance_mismatch');
      else {
        requireThat(object(value) && value.description === description && relative(value.path) === file, 'currency_claim_provenance_mismatch');
        if (value.source_sha256 !== undefined) requireThat(value.source_sha256 === pin(file).sha256, 'currency_claim_provenance_source_mismatch');
        if (value.module_id !== undefined) requireThat(value.module_id === moduleId, 'currency_claim_provenance_module_mismatch');
      }
      return { ...pin(ref.path), pointer: ref.pointer };
    }).sort((a, b) => (a.path + '#' + a.pointer).localeCompare(b.path + '#' + b.pointer));
    requireThat(provenance.length > 0, 'currency_claim_provenance_required');
    unique(provenance, ref => ref.path.toLowerCase() + '#' + ref.pointer);
    const claim = { claim_id: claimId, path: file, module_id: moduleId, description, source_sha256: pin(file).sha256, evidence, provenance };
    return { ...claim, claim_sha256: currencyDigest(claim) };
  }).sort((a, b) => a.claim_id.localeCompare(b.claim_id));
  requireThat(claims.length > 0, 'currency_claims_required');
  list(request.provenance_paths || [], 'currency_provenance_invalid').map(relative).forEach(pin);
  const modules = unique(list(request.modules || [], 'currency_modules_invalid').map(raw => {
    requireThat(object(raw), 'currency_module_invalid');
    const moduleId = id(raw.module_id); const cardPath = relative(raw.card_path);
    const card = jsonFile(reader, resolved.target, cardPath);
    requireThat(card.value.module_id === moduleId && Array.isArray(card.value.key_files) && Array.isArray(card.value.evidence_files), 'currency_module_card_invalid');
    const entries = validatedModuleRegistry(live.registry, true).modules;
    const matches = entries.filter(entry => entry.module_id === moduleId);
    requireThat(matches.length === 1, 'currency_module_registry_mismatch');
    const entry = mergeModuleDeclaration(matches[0], card.value);
    moduleOwnershipBoundaries(entry);
    const conditionalDependencies = normalizedConditionalDependencies(entry);
    requireThat(conditionalDependencies.every(edge => entries.filter(candidate => object(candidate) &&
      (candidate.module_id || candidate.id) === edge.module_id).length === 1), 'currency_module_registry_mismatch');
    const dependencies = [...new Set(['dependencies', 'depends_on'].flatMap(key => list(entry[key] || [], 'currency_module_registry_mismatch'))
      .map(value => id(typeof value === 'string' ? value : value?.module_id || value?.id)))].sort();
    requireThat(dependencies.every(dependency => entries.filter(candidate => candidate.module_id === dependency).length === 1), 'currency_module_registry_mismatch');
    requireThat(relative(entry.card) === cardPath && Array.isArray(entry.key_files) && Array.isArray(entry.evidence_files), 'currency_module_registry_mismatch');
    const registryScope = { module_id: moduleId, card: cardPath, path: entry.path || '.',
      ...(Object.prototype.hasOwnProperty.call(entry, 'ownership_paths')
        ? { ownership_paths: normalizedOwnershipPaths(entry) } : {}),
      ...(Object.prototype.hasOwnProperty.call(entry, 'conditional_dependencies')
        ? { conditional_dependencies: conditionalDependencies } : {}),
      key_files: unique(entry.key_files.map(relative)).sort(),
      evidence_files: unique(entry.evidence_files.map(relative)).sort(),
      dependencies,
      entry_points: unique((entry.entry_points || []).map(relative)).sort() };
    const requiredPaths = [...new Set([cardPath, ...card.value.key_files.map(relative), ...card.value.evidence_files.map(relative),
      ...registryScope.key_files, ...registryScope.evidence_files, ...registryScope.entry_points])].sort();
    requireThat(claims.some(claim => claim.module_id === moduleId), 'currency_module_claim_missing');
    for (const file of requiredPaths) {
      requireThat(sourcePaths.includes(file) || pins.has(file) || file === cardPath, 'currency_module_incomplete');
      pin(file);
    }
    return { module_id: moduleId, card_path: cardPath, card_sha256: pin(cardPath).sha256, required_paths: requiredPaths, registry_scope: registryScope };
  }), module => module.module_id.toLowerCase()).sort((a, b) => a.module_id.localeCompare(b.module_id));
  const predecessors = readPredecessors(context, request, reader, resolved, issuance);
  const filesWithClaims = new Set(claims.map(claim => claim.path));
  const moduleIds = new Set(modules.map(module => module.module_id));
  const findings = [];
  for (const item of live.live.values()) {
    if (!isCurrencyEligibleFinding(item.row)) continue;
    const moduleFinding = ['suspect_module', 'low_confidence_module'].includes(item.row.code);
    const covered = moduleFinding ? moduleIds.has(item.row.module_id) && item.binding.affected_artifacts.every(file => pins.has(file)) : filesWithClaims.has(item.binding.primary_artifact) && item.binding.affected_artifacts.every(file => pins.has(file));
    if (!covered) continue;
    if (terminal(item.row)) continue;
    requireThat(['open', 'needs_recheck'].includes(item.row.status) && !item.row.resolution_evidence, 'currency_finding_status_invalid');
    findings.push(item.binding);
  }
  findings.sort((a, b) => a.lifecycle_id.localeCompare(b.lifecycle_id));
  // An explicit predecessor may be refreshed or split only into overlapping factual scope.
  if (issuance) for (const predecessor of predecessors) requireThat(
    predecessor.manifest.scope.claims.some(prior => claims.some(claim => claim.path === prior.path)) ||
    predecessor.manifest.scope.modules.some(prior => modules.some(module => module.module_id === prior.module_id)),
    'currency_supersede_unused');
  unique([...pins.values()], pinValue => pinValue.path.toLowerCase());
  const riskScope = {
    module_ids: [...new Set([...claims.map(claim => claim.module_id).filter(Boolean), ...modules.map(module => module.module_id)])].sort(),
    artifact_paths: [...new Set([...claims.flatMap(claim => [claim.path, ...claim.evidence.map(pin => pin.path)]),
      ...modules.flatMap(module => module.required_paths)])].sort()
  };
  const scopedRisks = live.risks.filter(risk => riskTouchesScope(risk, riskScope));
  const scope = {
    dependency_model: 'independent_overlay_units.v3',
    authority_profile: AUTHORITY_PROFILE,
    authority_files: AUTHORITY_FILES.map(file => pins.get(file)), risk_scope: riskScope,
    source_files: sourcePaths.map(file => pins.get(file)),
    supporting_files: [...pins.values()].filter(value => !sourcePaths.includes(value.path)).sort((a, b) => a.path.localeCompare(b.path)),
    claims, modules, findings, protected_risks: scopedRisks,
    supersedes: predecessors.map(({ receipt_id, path: file, sha256: hash }) => ({ receipt_id, path: file, sha256: hash }))
  };
  privacyCheck({ scope, author_id:request.author_id, task_id:request.task_id, session_id:request.session_id });
  return { scope, scope_sha256: currencyDigest(scope), protected_risks_sha256: currencyDigest(scope.protected_risks), reader, resolved, live };
}
function prepareCurrencyScope(context, request, projections = {}) {
  const prepared = prepare(context, request, projections, true);
  prepared.reader.verify();
  return { scope: prepared.scope, scope_sha256: prepared.scope_sha256, protected_risks_sha256: prepared.protected_risks_sha256 };
}
function timestamp(value, code) {
  const parsed = Date.parse(value);
  requireThat(typeof value === 'string' && Number.isFinite(parsed) && parsed <= Date.now() + 300000, code);
  return parsed;
}
function checkReview(prepared, request, expected = null) {
  const loaded = jsonFile(prepared.reader, prepared.resolved.target, relative(request.review_path));
  const review = loaded.value;
  privacyCheck(review);
  requireThat(object(review) && review.schema_version === REVIEW_SCHEMA, 'currency_review_schema_invalid');
  const reviewerId = id(review.reviewer_id); const authorId = id(request.author_id);
  requireThat(review.author_id === authorId && reviewerId.normalize('NFC').toLowerCase() !== authorId.normalize('NFC').toLowerCase(), 'currency_review_not_independent');
  requireThat(review.scope_sha256 === prepared.scope_sha256 && review.protected_risks_sha256 === prepared.protected_risks_sha256, 'currency_review_scope_mismatch');
  requireThat(review.result === 'confirmed' && review.method === 'source_and_claim_review' && review.routing_only === true && review.security_certificate === false, 'currency_review_not_factual');
  timestamp(review.reviewed_at, 'currency_review_timestamp_invalid');
  const checks = list(review.claims, 'currency_review_claims_missing');
  unique(checks, check => id(check.claim_id));
  requireThat(checks.length === prepared.scope.claims.length, 'currency_review_claims_mismatch');
  const checked = new Set();
  for (const claim of prepared.scope.claims) {
    const check = checks.find(value => value.claim_id === claim.claim_id);
    requireThat(check && check.claim_sha256 === claim.claim_sha256 && check.result === 'confirmed' && typeof check.notes === 'string' && check.notes.trim().length >= 12, 'currency_review_claim_not_confirmed');
    const paths = unique(list(check.checked_paths, 'currency_review_paths_missing').map(relative), value => value.toLowerCase());
    for (const file of [claim.path, ...claim.evidence.map(value => value.path), ...claim.provenance.map(value => value.path)]) requireThat(paths.includes(file), 'currency_review_dependency_missing');
    paths.forEach(file => checked.add(file));
  }
  // Extra engine pins constrain lifetime but confer no factual file coverage.
  for (const module of prepared.scope.modules) for (const file of module.required_paths)
    requireThat(checked.has(file), 'currency_review_dependency_missing');
  const bindingValue = { ...pinOnly(loaded.pin), reviewer_id: reviewerId };
  if (expected) requireThat(same(bindingValue, expected), 'currency_review_binding_changed');
  return { binding: bindingValue, reviewed_at: review.reviewed_at };
}
function validateCurrencyReview(context, request, projections = {}) {
  const prepared = prepare(context, request, projections, true);
  checkReview(prepared, request);
  prepared.reader.verify();
  return { scope: prepared.scope, scope_sha256: prepared.scope_sha256, protected_risks_sha256: prepared.protected_risks_sha256 };
}
function checkVerification(context, prepared, request, review, expected = null, historical = false) {
  const executionIds = unique(list(request.test_execution_ids, 'currency_kve_required').map(value => {
    requireThat(typeof value === 'string' && /^KVE-[a-f0-9]{64}$/.test(value), 'currency_kve_reference_invalid'); return value;
  })).sort();
  requireThat(executionIds.length > 0, 'currency_kve_required');
  const finalized = require('./verification-finalization').requireFinalizedExecutions(prepared.resolved.state, executionIds, request.verification_acceptances);
  for (const pin of finalized.bindings) {
    const file = path.relative(prepared.resolved.state, pin.path).replace(/\\/g, '/');
    requireThat(prepared.reader(prepared.resolved.state, file).sha256 === pin.physical_sha256, 'currency_finalization_drift');
  }
  const required = new Map([...prepared.scope.source_files, ...prepared.scope.supporting_files, review.binding].map(pin => [pin.path, pin.sha256]));
  const covered = new Set(); const paths = []; const timestamps = [];
  const verification = executionIds.map(executionId => {
    const statePath = 'maintenance/verification_executions/' + executionId.slice(4) + '.json';
    const physical = prepared.reader(prepared.resolved.state, statePath);
    const loaded = loadExecutionRecord(prepared.resolved.state, executionId);
    requireThat(loaded && loaded.physical_sha256 === physical.sha256 && loaded.record.execution_id === executionId, 'currency_kve_invalid');
    const record = loaded.record;
    requireThat(record.task_id === request.task_id && record.session_id === request.session_id, 'currency_kve_scope_mismatch');
    const before = new Map(record.source_snapshot_before.map(pin => [relative(pin.path), pin.sha256]));
    const after = new Map(record.source_snapshot.map(pin => [relative(pin.path), pin.sha256]));
    requireThat(before.size === after.size && before.size === record.source_snapshot_before.length && after.size === record.source_snapshot.length, 'currency_kve_source_collision');
    unique(record.source_snapshot, pin => relative(pin.path).toLowerCase());
    for (const [file, hash] of after) {
      requireThat(before.get(file) === hash, 'currency_kve_source_changed');
      if (required.has(file)) {
        if (!historical) requireThat(prepared.reader(prepared.resolved.target, file).sha256 === hash, 'currency_kve_source_drift');
        requireThat(required.get(file) === hash, 'currency_kve_source_mismatch'); covered.add(file);
      }
    }
    const executedAt = timestamp(record.executed_at, 'currency_kve_timestamp_invalid');
    requireThat(executedAt >= Date.parse(review.reviewed_at), 'currency_kve_precedes_review');
    timestamps.push(executedAt);
    paths.push(stateReference(prepared.resolved.state, prepared.resolved.target, statePath));
    return { execution_id: executionId, physical_sha256: physical.sha256 };
  });
  for (const file of required.keys()) requireThat(covered.has(file), 'currency_kve_dependency_missing');
  if (expected) requireThat(same(verification, expected), 'currency_kve_binding_changed');
  return { verification, paths, timestamps };
}
function createCurrencyReceipt(context, request, projections = {}, historical = false) {
  const prepared = prepare(context, request, projections, !historical);
  const review = checkReview(prepared, request);
  const checked = checkVerification(context, prepared, request, review);
  const manifest = {
    // The effective evidence time makes retries reconstruct the same receipt
    // from the exact request and physical KVE, independently of a journal.
    schema_version: SCHEMA_VERSION, lifecycle_effect: 'none', issued_at: new Date(Math.max(...checked.timestamps)).toISOString(),
    author_id: request.author_id, task_id: request.task_id, session_id: request.session_id,
    scope: prepared.scope, scope_sha256: prepared.scope_sha256, protected_risks_sha256: prepared.protected_risks_sha256,
    verification: checked.verification, verification_acceptances: request.verification_acceptances, review: review.binding,
    routing_cap: 'routing_trusted', security_certificate: false
  };
  requireThat(checked.timestamps.every(value => value <= Date.parse(manifest.issued_at)), 'currency_kve_after_issuance');
  const digest = manifestDigest(manifest);
  prepared.reader.verify();
  return { ...manifest, content_sha256: digest, receipt_id: 'KCUR-' + digest };
}
function emptyCoverage() { return { files: Object.create(null), modules: Object.create(null), findings: Object.create(null) }; }
function errorIssue(error) { return { code: error.code || 'currency_validation_failed', message: 'Currency evidence could not be validated. Inspect the issue code and masked recording notice; raw dependency values are omitted.' }; }
function recoverRisks(projections) {
  let registryRecords = [];
  try { registryRecords = registryRows(projections.registry); }
  catch { /* inputs retries validation and fails closed; retain other live risks. */ }
  const candidates = [projections.staleItems?.items || projections.staleItems, projections.repairQueue?.queue || projections.repairQueue, registryRecords];
  const risks = new Map();
  for (const group of candidates) if (Array.isArray(group)) for (const row of group) if (isAssuranceRisk(row)) {
    let snapshot;
    try { snapshot = riskSnapshot(row); }
    catch (error) { snapshot = { ...row, currency_risk_normalization_error: error.code || 'invalid' }; }
    risks.set(row.lifecycle_id || currencyDigest(snapshot), snapshot);
  }
  return [...risks.values()];
}

function riskTouchesScope(risk, scope) {
  if (risk.module_id && scope.module_ids.includes(risk.module_id)) return true;
  const paths = [risk.primary_artifact || risk.artifact, ...(risk.affected_artifacts || [])].filter(Boolean);
  if (!risk.module_id && !paths.length) return true;
  return paths.some(file => scope.artifact_paths.some(candidate => {
    const fileIdentity = pathComparisonIdentity(file);
    const candidateIdentity = pathComparisonIdentity(candidate);
    return fileIdentity === candidateIdentity || fileIdentity.startsWith(candidateIdentity + '/') ||
      candidateIdentity.startsWith(fileIdentity + '/');
  }));
}

// Validate historical authority BEFORE allowing an ordinary dependency change
// to be treated as local staleness. Historical snapshots are not substituted
// for current code when granting coverage: full live validation still follows.
function authenticateIndependent(context, manifest, request, reader, resolved, issuedAt) {
  const scope = manifest.scope;
  requireThat(scope.dependency_model === 'independent_overlay_units.v3', 'currency_dependency_model_invalid');
  requireThat(scope.authority_profile === AUTHORITY_PROFILE, 'currency_authority_profile_unsupported');
  requireThat(scope.protected_risks && currencyDigest(scope.protected_risks) === manifest.protected_risks_sha256, 'currency_risk_scope_hash_mismatch');
  const pins = [...list(scope.source_files, 'currency_scope_schema_invalid'), ...list(scope.supporting_files, 'currency_scope_schema_invalid')];
  unique(pins, pin => relative(pin.path).toLowerCase());
  const pinMap = new Map(pins.map(pin => {
    requireThat(HASH.test(pin.sha256), 'currency_scope_schema_invalid');
    return [relative(pin.path), pin.sha256];
  }));
  const authorities = list(scope.authority_files, 'currency_authority_pins_missing');
  requireThat(same(authorities.map(pin => pin.path), AUTHORITY_FILES), 'currency_authority_pins_missing');
  for (const pin of authorities) {
    requireThat(pinMap.get(pin.path) === pin.sha256, 'currency_authority_pins_missing');
    requireThat(reader(resolved.target, pin.path).sha256 === pin.sha256, 'currency_authority_changed');
  }
  unique(scope.claims, claim => id(claim.claim_id));
  requireThat(scope.claims.length > 0, 'currency_claims_required');
  const checkPin = pin => requireThat(pinMap.get(relative(pin.path)) === pin.sha256, 'currency_scope_pin_mismatch');
  for (const claim of scope.claims) {
    const body = { ...claim }; delete body.claim_sha256;
    requireThat(currencyDigest(body) === claim.claim_sha256 && pinMap.get(relative(claim.path)) === claim.source_sha256, 'currency_claim_hash_mismatch');
    list(claim.evidence, 'currency_claim_evidence_required').forEach(checkPin);
    list(claim.provenance, 'currency_claim_provenance_required').forEach(checkPin);
  }
  unique(scope.modules, module => id(module.module_id));
  for (const module of scope.modules) {
    requireThat(pinMap.get(relative(module.card_path)) === module.card_sha256, 'currency_module_pin_mismatch');
    for (const file of list(module.required_paths, 'currency_module_incomplete')) requireThat(pinMap.has(relative(file)), 'currency_module_incomplete');
  }
  unique(scope.findings, finding => id(finding.lifecycle_id));
  for (const finding of scope.findings) {
    requireThat(ALLOWED_CODES.includes(finding.code) && finding.repair_class === 'verify_on_touch' &&
      !Object.values(finding.protection || {}).some(Boolean), 'currency_finding_not_factual');
  }
  const expectedRiskScope = {
    module_ids: [...new Set([...scope.claims.map(claim => claim.module_id).filter(Boolean), ...scope.modules.map(module => module.module_id)])].sort(),
    artifact_paths: [...new Set([...scope.claims.flatMap(claim => [claim.path, ...claim.evidence.map(pin => pin.path)]),
      ...scope.modules.flatMap(module => module.required_paths)])].sort()
  };
  requireThat(same(scope.risk_scope, expectedRiskScope), 'currency_risk_scope_invalid');
  const prepared = { scope, scope_sha256: manifest.scope_sha256,
    protected_risks_sha256: manifest.protected_risks_sha256, reader, resolved };
  const review = checkReview(prepared, request, manifest.review);
  const checked = checkVerification(context, prepared, request, review, manifest.verification, true);
  requireThat(checked.timestamps.every(value => value <= issuedAt), 'currency_kve_after_issuance');
  const predecessors = readPredecessors(context, request, reader, resolved, false);
  for (const prior of scope.supersedes) {
    const actual = predecessors.find(item => item.receipt_id === prior.receipt_id);
    requireThat(actual && actual.path === prior.path && actual.sha256 === prior.sha256, 'currency_predecessor_binding_changed');
  }
  const changed = [];
  for (const pin of pins) {
    if (AUTHORITY_FILES.includes(pin.path)) continue;
    try { if (reader(resolved.target, pin.path).sha256 !== pin.sha256) changed.push(pin.path); }
    catch (error) {
      if (error.code !== 'ENOENT') throw error;
      changed.push(pin.path);
    }
  }
  return {
    impact: 'scope', authenticated: true,
    lifecycle_ids: scope.findings.map(finding => finding.lifecycle_id).sort(),
    module_ids: expectedRiskScope.module_ids,
    affected_artifacts: [...new Set([...expectedRiskScope.artifact_paths,
      ...scope.findings.flatMap(finding => finding.affected_artifacts || [])])].sort(),
    changed_paths: changed.sort()
  };
}
const LOCAL_STALE_CODES = new Set([
  'currency_scope_drift', 'currency_finding_coverage_mismatch', 'currency_finding_binding_changed',
  'currency_finding_missing_or_protected', 'currency_finding_lifecycle_changed', 'currency_native_finding_mismatch', 'currency_risk_catalog_changed',
  'currency_provenance_pointer_missing', 'currency_claim_provenance_mismatch', 'currency_claim_provenance_source_mismatch',
  'currency_claim_provenance_module_mismatch', 'currency_module_card_invalid', 'currency_module_registry_mismatch',
  'currency_module_incomplete', 'currency_json_malformed', 'ENOENT'
]);

function validateCurrencyManifest(context, manifest, projections = {}, assessment = null) {
  const out = { valid: false, issues: [], coverage: emptyCoverage(), assurance_open_risks: recoverRisks(projections), source_files: [] };
  let authenticated = null;
  try {
    verifyAddress(manifest);
    privacyCheck(manifest);
    const issuedAt = timestamp(manifest.issued_at, 'currency_manifest_timestamp_invalid');
    requireThat(object(manifest.scope) && HASH.test(manifest.scope_sha256) && manifest.scope_sha256 === currencyDigest(manifest.scope), 'currency_scope_hash_mismatch');
    requireThat(Array.isArray(manifest.scope.findings) && Array.isArray(manifest.scope.supersedes), 'currency_scope_schema_invalid');
    const request = {
      schema_version: REQUEST_SCHEMA,
      author_id: manifest.author_id, task_id: manifest.task_id, session_id: manifest.session_id,
      source_files: manifest.scope.source_files.map(pin => pin.path),
      claims: manifest.scope.claims.map(claim => ({ claim_id: claim.claim_id, path: claim.path, module_id: claim.module_id, description: claim.description, evidence_paths: claim.evidence.map(pin => pin.path), provenance: claim.provenance.map(pin => ({ path: pin.path, pointer: pin.pointer })) })),
      modules: manifest.scope.modules.map(module => ({ module_id: module.module_id, card_path: module.card_path })),
      provenance_paths: manifest.scope.supporting_files.map(pin => pin.path),
      supersedes: manifest.scope.supersedes.map(pin => pin.receipt_id),
      verification_acceptances: manifest.verification_acceptances, review_path: manifest.review.path, test_execution_ids: manifest.verification.map(item => item.execution_id)
    };
    // Actual native rows remain open. Their identity/occurrence must match;
    // no simulated closure or caller projection grants factual coverage.
    const resolved = assessment?.resolved || roots(context); const reader = assessment?.reader || makeReader();
    const current = assessment?.current || inputs(context, projections, reader, resolved);
    const physical = assessment?.physical || inputs(context, {}, reader, resolved);
    const nativeFindings = manifest.scope.findings.map(captured => {
      const native = physical.live.get(captured.lifecycle_id);
      // Require a real native identity before granting historical issue scope.
      // A missing row or a caller-invented identity remains a global error.
      requireThat(native && native.binding.identity_sha256 === captured.identity_sha256,
        'currency_native_finding_mismatch');
      return { native, captured };
    });
    out.assurance_open_risks = current.risks;
    authenticated = authenticateIndependent(context, manifest, request, reader, resolved, issuedAt);
    for (const { native, captured } of nativeFindings) {
      // An authenticated old occurrence grants no current coverage, but its
      // ordinary lifecycle drift must not revoke independent reviewed units.
      requireThat(same(native.binding, captured) && ['open', 'needs_recheck'].includes(native.row.status) && !native.row.resolution_evidence,
        'currency_native_finding_mismatch');
    }
    const prepared = prepare(context, request, projections, false, { resolved, reader, current });
    requireThat(same(prepared.scope.findings, manifest.scope.findings), 'currency_finding_coverage_mismatch');
    prepared.scope_sha256 = currencyDigest(prepared.scope);
    requireThat(same(prepared.scope, manifest.scope) && prepared.scope_sha256 === manifest.scope_sha256, 'currency_scope_drift');
    requireThat(prepared.protected_risks_sha256 === manifest.protected_risks_sha256 && same(prepared.scope.protected_risks, manifest.scope.protected_risks), 'currency_risk_catalog_changed');
    const review = checkReview(prepared, request, manifest.review);
    const checked = checkVerification(context, prepared, request, review, manifest.verification);
    requireThat(checked.timestamps.every(value => value <= issuedAt), 'currency_kve_after_issuance');
    unique(manifest.scope.findings, finding => finding.lifecycle_id);
    for (const captured of manifest.scope.findings) {
      const live = current.live.get(captured.lifecycle_id);
      requireThat(live && isCurrencyEligibleFinding(live.row), 'currency_finding_missing_or_protected');
      const expectedBinding = { ...captured }; delete expectedBinding.predecessor_receipt_id;
      requireThat(same(live.binding, expectedBinding), 'currency_finding_binding_changed');
      requireThat(['open', 'needs_recheck'].includes(live.row.status) && !live.row.resolution_evidence, 'currency_finding_lifecycle_changed');
      out.coverage.findings[captured.lifecycle_id] = {
        lifecycle_id: captured.lifecycle_id, identity_sha256: captured.identity_sha256, code: captured.code,
        primary_artifact: captured.primary_artifact, affected_artifacts: captured.affected_artifacts,
        occurrence: captured.occurrence, receipt_id: manifest.receipt_id, scope_sha256: manifest.scope_sha256,
        factual_predicate: FACTUAL_PREDICATE, routing_cap: 'routing_trusted'
      };
    }
    for (const claim of manifest.scope.claims) {
      const prior = out.coverage.files[claim.path];
      out.coverage.files[claim.path] = { path: claim.path, sha256: claim.source_sha256, claim_ids: [...(prior?.claim_ids || []), claim.claim_id], receipt_id: manifest.receipt_id, scope_sha256: manifest.scope_sha256, routing_cap: 'routing_trusted' };
    }
    for (const module of manifest.scope.modules) out.coverage.modules[module.module_id] = { ...module, receipt_id: manifest.receipt_id, scope_sha256: manifest.scope_sha256, routing_cap: 'routing_trusted' };
    out.source_files = [...new Set([...manifest.scope.source_files, ...manifest.scope.supporting_files, manifest.review].map(pin => pin.path).concat(checked.paths))].sort();
    out.valid = true;
    if (!assessment) reader.verify();
  } catch (error) {
    out.valid = false;
    out.coverage = emptyCoverage();
    out.source_files = [];
    const local = authenticated && LOCAL_STALE_CODES.has(error.code);
    const issue = { ...errorIssue(error), ...(local ? authenticated : { impact: 'global' }) };
    out.issues.push(local ? rememberNativeScopedIssue(issue) : issue);
  }
  out.assurance_open_risks = safeRiskDetails(out.assurance_open_risks);
  return out;
}
function evaluateCurrency(context, projections = {}) {
  const out = { enabled: false, valid: false, ...emptyCoverage(), receipts: [], issues: [], assurance: assuranceProjection(recoverRisks(projections)), source_files: [] };
  let manifests = projections.manifests; const receiptPaths = new Map();
  try {
    const resolved = roots(context); const reader = makeReader();
    const store = storage(context);
    const index = manifests === undefined ? jsonFile(reader, resolved.state, store.index, true) : null;
    if (manifests === undefined && !index) {
      // Optional currency must not turn an unconfigured legacy repository
      // into a new authority error. No positive factual claim is available.
      try {
        const legacy = inputs(context, projections, reader, resolved);
        out.assurance = assuranceProjection(legacy.risks);
      } catch { out.assurance.status = 'unavailable'; }
      reader.verify(); out.read_stats = { ...reader.stats };
      out.assurance.open_findings = safeRiskDetails(out.assurance.open_findings);
      return out;
    }
    out.enabled = manifests === undefined || manifests.length > 0;
    const current = inputs(context, projections, reader, resolved);
    const physical = inputs(context, {}, reader, resolved);
    const assessment = { resolved, reader, current, physical };
    out.assurance = assuranceProjection(current.risks);
    if (manifests === undefined) {
      requireThat(index.value.schema_version === INDEX_SCHEMA, 'currency_index_invalid');
      const ids = unique(list(index.value.receipt_ids, 'currency_index_invalid'));
      manifests = ids.map(receiptId => {
        requireThat(typeof receiptId === 'string' && RECEIPT_ID.test(receiptId), 'currency_index_invalid');
        const file = store.receipts + '/' + receiptId.slice(5) + '.json';
        const loaded = jsonFile(reader, resolved.state, file);
        requireThat(loaded.value.receipt_id === receiptId, 'currency_index_receipt_mismatch');
        receiptPaths.set(receiptId, stateReference(resolved.state, resolved.target, file));
        return loaded.value;
      });
      out.source_files.push(stateReference(resolved.state, resolved.target, store.index));
    } else { list(manifests, 'currency_manifests_invalid'); out.enabled = manifests.length > 0; }
    unique(manifests, manifest => manifest?.receipt_id);
    const accepted = [];
    for (const manifest of manifests) {
      const validation = validateCurrencyManifest(context, manifest, projections, assessment);
      out.receipts.push({ receipt_id: manifest?.receipt_id || null, valid: validation.valid, scope_sha256: manifest?.scope_sha256 || null });
      out.issues.push(...validation.issues.map(issue => {
        const owned = { ...issue, receipt_id: manifest?.receipt_id || null };
        return isNativeScopedCurrencyIssue(issue) ? rememberNativeScopedIssue(owned) : owned;
      }));
      if (validation.valid) accepted.push({ manifest, validation });
    }
    // Legacy receipts remain strict. Only authenticated v2 local staleness
    // permits unrelated current units to retain their own authority.
    if (out.issues.some(issue => issue.impact !== 'scope' || issue.authenticated !== true)) {
      out.valid = false; Object.assign(out, emptyCoverage()); out.assurance.open_findings = safeRiskDetails(out.assurance.open_findings); return out;
    }
    const aliases = new Map(); const claimIds = new Map();
    for (const { manifest, validation } of accepted) {
      for (const claim of manifest.scope.claims) {
        requireThat(!claimIds.has(claim.claim_id) || claimIds.get(claim.claim_id) === claim.claim_sha256, 'currency_claim_collision'); claimIds.set(claim.claim_id, claim.claim_sha256);
        const alias = claim.path.toLowerCase(); requireThat(!aliases.has(alias) || aliases.get(alias) === claim.path, 'currency_scope_collision'); aliases.set(alias, claim.path);
      }
      for (const kind of ['files', 'modules', 'findings']) for (const [key, coverage] of Object.entries(validation.coverage[kind])) {
        if (out[kind][key]) {
          const prior = out[kind][key];
          requireThat(kind !== 'modules' || prior.card_sha256 === coverage.card_sha256, 'currency_scope_collision');
          requireThat(kind !== 'files' || prior.sha256 === coverage.sha256, 'currency_scope_collision');
          requireThat(kind !== 'findings' || prior.identity_sha256 === coverage.identity_sha256 && prior.occurrence === coverage.occurrence, 'currency_scope_collision');
        }
        out[kind][key] = coverage;
      }
      out.source_files.push(...validation.source_files);
      if (receiptPaths.has(manifest.receipt_id)) out.source_files.push(receiptPaths.get(manifest.receipt_id));
    }
    out.source_files = [...new Set(out.source_files)].sort();
    out.valid = accepted.length > 0;
    reader.verify();
    out.read_stats = { ...reader.stats };
  } catch (error) {
    out.valid = false; Object.assign(out, emptyCoverage()); out.issues.push(errorIssue(error));
  }
  if (out.assurance.open_findings.length) out.assurance.status = 'open_risks';
  out.assurance.open_findings = safeRiskDetails(out.assurance.open_findings);
  return out;
}

const admit = fn => (...args) => {
  const clean = [];
  for (let index = 0; index < args.length; index++) clean[index] = copyInertData(args[index]);
  return fn(...clean);
};
module.exports = {
  SCHEMA_VERSION, REQUEST_SCHEMA, AUTHORITY_FILES, AUTHORITY_PROFILE, LEGACY_AUTHORITY_FILES, REVIEW_SCHEMA, INDEX_SCHEMA, FACTUAL_PREDICATE, ALLOWED_CODES,
  prepareCurrencyScope: admit(prepareCurrencyScope), createCurrencyReceipt: admit(createCurrencyReceipt), issueCurrencyManifest: admit(createCurrencyReceipt),
  validateCurrencyManifest: admit(validateCurrencyManifest), validateCurrencyReview: admit(validateCurrencyReview), evaluateCurrency: admit(evaluateCurrency),
  isCurrencyEligibleFinding: admit(isCurrencyEligibleFinding), isNativeScopedCurrencyIssue,
  canonicalJson, currencyDigest, manifestDigest
};
