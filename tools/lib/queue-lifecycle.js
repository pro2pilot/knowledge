'use strict';

// The repair and stale views are projections of the same lifecycle records.
// Keep the implementation here so every producer uses identical IDs and
// transition semantics instead of independently appending queue entries.
const crypto = require('crypto');
const path = require('path');

const HASH_RECERTIFICATION_BLOCKED_CODES = new Set([
  'open_contradiction',
  'security_finding',
  'policy_violation',
  'incident',
  'manual_review_required',
  'unresolved_architecture_conflict'
]);
const FINDING_CODE_ALIASES = Object.freeze({
  contradiction: 'open_contradiction',
  security: 'security_finding',
  security_issue: 'security_finding',
  policy: 'policy_violation',
  incident_finding: 'incident',
  manual_review: 'manual_review_required',
  architecture_conflict: 'unresolved_architecture_conflict'
});
const DEDICATED_VERIFIER_TYPES = new Set([
  'dedicated_finding_verifier',
  'security_review',
  'policy_review',
  'incident_resolution',
  'manual_review',
  'architecture_conflict_resolution'
]);
const DEDICATED_REQUIREMENTS = Object.freeze({
  open_contradiction: Object.freeze({
    verifier_type: 'dedicated_finding_verifier',
    predicate: 'dedicated_contradiction_review_passed'
  }),
  security_finding: Object.freeze({
    verifier_type: 'security_review',
    predicate: 'dedicated_security_review_passed'
  }),
  policy_violation: Object.freeze({
    verifier_type: 'policy_review',
    predicate: 'dedicated_policy_review_passed'
  }),
  incident: Object.freeze({
    verifier_type: 'incident_resolution',
    predicate: 'dedicated_incident_resolution_passed'
  }),
  manual_review_required: Object.freeze({
    verifier_type: 'manual_review',
    predicate: 'dedicated_manual_review_passed'
  }),
  unresolved_architecture_conflict: Object.freeze({
    verifier_type: 'architecture_conflict_resolution',
    predicate: 'dedicated_architecture_conflict_resolution_passed'
  })
});
const RESOLUTION_EVIDENCE_RESERVED_FIELDS = new Set([
  'type',
  'recertification_id',
  'verified_at',
  'verified_by',
  'dedicated_verifier_validated',
  'dedicated_authority_id'
]);

function invalidIdentity(code, message) {
  const error = new Error(message);
  error.code = code;
  return error;
}

function canonicalPath(value) {
  const original = String(value || '');
  if (/[\0-\x1f\x7f]/.test(original)) {
    throw invalidIdentity('finding_artifact_unsafe', `Finding artifact contains a control character: ${JSON.stringify(value)}`);
  }
  const raw = original.replace(/\\/g, '/');
  if (!raw) return 'unknown';
  if (/^[a-z]:/i.test(raw) || raw.startsWith('/')) {
    throw invalidIdentity('finding_artifact_unsafe', `Finding artifact must be repository-relative: ${raw}`);
  }
  const normalized = path.posix.normalize(raw.replace(/^\.\//, ''));
  if (normalized === '..' || normalized.startsWith('../') || path.posix.isAbsolute(normalized)) {
    throw invalidIdentity('finding_artifact_unsafe', `Finding artifact escapes the repository root: ${raw}`);
  }
  // Repository paths are case-sensitive identities even when the current
  // checkout happens to live on a case-insensitive filesystem.
  return normalized || 'unknown';
}

function canonicalCode(value) {
  const normalized = String(value || 'unknown').trim().toLowerCase().replace(/[\s-]+/g, '_');
  if (/[\0-\x1f\x7f]/.test(normalized)) {
    throw invalidIdentity('finding_code_invalid', `Finding code contains a control character: ${JSON.stringify(value)}`);
  }
  return FINDING_CODE_ALIASES[normalized] || normalized;
}

function requiresDedicatedVerifier(value) {
  return HASH_RECERTIFICATION_BLOCKED_CODES.has(canonicalCode(value));
}

function dedicatedRequirementFor(recordOrCode) {
  const record = recordOrCode && typeof recordOrCode === 'object'
    ? recordOrCode
    : { code: recordOrCode };
  const code = canonicalCode(record.code);
  const explicit = DEDICATED_REQUIREMENTS[code];
  if (explicit) {
    return {
      ...explicit,
      required: true,
      source: 'finding_code',
      code
    };
  }
  if (record.security_sensitive === true) {
    return {
      ...DEDICATED_REQUIREMENTS.security_finding,
      required: true,
      source: 'security_sensitive',
      code
    };
  }
  const requiredChecks = new Set((record.required_checks || []).map(String));
  if (
    ['manual_review', 'dedicated_action_required'].includes(String(record.repair_class || '')) ||
    requiredChecks.has('dedicated_review')
  ) {
    return {
      ...DEDICATED_REQUIREMENTS.manual_review_required,
      required: true,
      source: 'repair_policy',
      code
    };
  }
  return null;
}

function dedicatedResolutionVerdict({ evidence, code, record, verifyDedicatedEvidence }) {
  const requirement = dedicatedRequirementFor(record || { code });
  if (!requirement || !evidence) return { ok: false, reason: 'dedicated_verifier_required' };
  const receiptSha256 = String(evidence.dedicated_receipt_sha256 || '').toLowerCase();
  const receiptId = String(evidence.dedicated_receipt_id || '');
  const receiptPath = String(evidence.dedicated_receipt_path || '');
  if (
    !DEDICATED_VERIFIER_TYPES.has(String(evidence.dedicated_verifier_type || '')) ||
    String(evidence.dedicated_verifier_type || '') !== requirement.verifier_type ||
    String(evidence.dedicated_predicate || '') !== requirement.predicate ||
    typeof evidence.dedicated_verifier_id !== 'string' ||
    !evidence.dedicated_verifier_id.trim() ||
    evidence.dedicated_result !== 'pass'
  ) {
    return { ok: false, reason: 'dedicated_verifier_mismatch' };
  }
  if (
    !/^[a-f0-9]{64}$/.test(receiptSha256) ||
    receiptId !== `KDVR-${receiptSha256}` ||
    receiptPath !== `maintenance/dedicated_verification_receipts/${receiptSha256}.json` ||
    typeof verifyDedicatedEvidence !== 'function'
  ) {
    return { ok: false, reason: 'dedicated_verifier_untrusted' };
  }
  try {
    const result = verifyDedicatedEvidence(Object.freeze({
      finding: Object.freeze({
        lifecycle_id: record?.lifecycle_id || null,
        identity_sha256: record?.identity_sha256 || null,
        module_id: record?.module_id || null,
        code: canonicalCode(code),
        artifact: record?.artifact || record?.primary_artifact || null,
        affected_artifacts: Array.from(new Set(
          (record?.affected_artifacts || []).map(canonicalPath)
        )).sort()
      }),
      evidence: Object.freeze({ ...evidence })
    }));
    if (
      !result ||
      result.ok !== true ||
      String(result.receipt_id || '') !== receiptId ||
      String(result.receipt_path || '') !== receiptPath ||
      String(result.receipt_sha256 || '').toLowerCase() !== receiptSha256
    ) {
      return { ok: false, reason: 'dedicated_verifier_untrusted' };
    }
    return {
      ok: true,
      authority_id: String(result.authority_id || 'trusted_dedicated_verifier'),
      receipt_id: receiptId,
      receipt_path: receiptPath,
      receipt_sha256: receiptSha256
    };
  } catch {
    return { ok: false, reason: 'dedicated_verifier_untrusted' };
  }
}

function hasDedicatedResolutionEvidence(evidence, code, verifyDedicatedEvidence, record) {
  return dedicatedResolutionVerdict({ evidence, code, record, verifyDedicatedEvidence }).ok;
}

function canonicalModule(value) {
  const normalized = String(value || 'root').trim().toLowerCase();
  if (!normalized || /[\0-\x20\x7f/\\]/.test(normalized) || normalized === '.' || normalized === '..') {
    throw invalidIdentity('module_id_invalid', `Module ID is invalid or path-like: ${JSON.stringify(value)}`);
  }
  // Hyphens and underscores are distinct valid module-ID characters. Do not
  // collapse them or turn path separators into module ownership aliases.
  return normalized;
}

function normalizedFinding(finding) {
  const affected = Array.from(new Set(
    (finding.affected_artifacts || [])
      .concat(finding.artifact || [], finding.primary_artifact || [])
      .filter(Boolean)
      .map(canonicalPath)
  )).sort();
  const explicitPrimary = finding.primary_artifact || finding.artifact;
  const artifact = explicitPrimary ? canonicalPath(explicitPrimary) : (affected[0] || 'unknown');
  if (!affected.includes(artifact)) affected.push(artifact);
  affected.sort();
  return {
    module_id: canonicalModule(finding.module_id),
    code: canonicalCode(finding.code),
    artifact,
    primary_artifact: artifact,
    reason: String(finding.reason || finding.message || finding.code || 'Unknown trust finding.'),
    priority: finding.priority || (finding.severity === 'critical' || finding.severity === 'high' ? 'high' : 'medium'),
    affected_artifacts: affected,
    severity: finding.severity || 'medium',
    score_cost: Number.isFinite(Number(finding.score_cost)) ? Number(finding.score_cost) : null,
    repair_class: finding.repair_class || null,
    required_checks: Array.from(new Set((finding.required_checks || []).map(String))),
    resolution_predicate: finding.resolution_predicate || null,
    safe_during_current_task: finding.safe_during_current_task !== false,
    critical_path: Boolean(finding.critical_path),
    security_sensitive: Boolean(finding.security_sensitive),
    estimated_additional_work: finding.estimated_additional_work || null
  };
}

function stableId(prefix, rawFinding) {
  // Reasons often contain changing counters or prose. Identity follows the
  // canonical module, code, explicit primary artifact, and sorted artifact set.
  return `${prefix}-${identitySha256(rawFinding).slice(0, 16)}`;
}

function identitySha256(rawFinding) {
  const finding = normalizedFinding(rawFinding);
  const basis = [
    finding.module_id,
    finding.code,
    finding.primary_artifact,
    ...finding.affected_artifacts
  ].join('\u001f');
  return crypto.createHash('sha256').update(basis).digest('hex');
}

function findingOccurrence(rawFinding) {
  const occurrence = Number(rawFinding?.occurrence);
  const occurredAt = String(rawFinding?.reopened_at || rawFinding?.opened_at || '');
  if (
    !Number.isInteger(occurrence) ||
    occurrence < 1 ||
    !occurredAt ||
    !Number.isFinite(Date.parse(occurredAt))
  ) {
    throw invalidIdentity(
      'finding_occurrence_invalid',
      'Finding occurrence requires a positive occurrence and valid opened_at/reopened_at'
    );
  }
  return {
    occurrence,
    occurred_at: occurredAt,
    sha256: crypto.createHash('sha256').update(stableJson({
      lifecycle_id: String(rawFinding?.lifecycle_id || ''),
      finding_identity_sha256: identitySha256(rawFinding),
      occurrence,
      occurred_at: occurredAt
    })).digest('hex')
  };
}

function stableJson(value) {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) =>
      `${JSON.stringify(key)}:${stableJson(value[key])}`
    ).join(',')}}`;
  }
  return JSON.stringify(value);
}

function lifecycleIntegrityError(code, lifecycleId, message, details = {}) {
  const error = new Error(message);
  error.code = code;
  error.lifecycle_id = lifecycleId;
  Object.assign(error, details);
  return error;
}

function lifecycleIdentity(record, identitySource = null) {
  const effective = {
    ...record,
    artifact: record.artifact ||
      record.primary_artifact ||
      identitySource?.artifact ||
      identitySource?.primary_artifact
  };
  return identitySha256(effective);
}

function projectionFingerprint(record, identitySource = null) {
  const effectiveArtifact = canonicalPath(
    record.artifact ||
    record.primary_artifact ||
    identitySource?.artifact ||
    identitySource?.primary_artifact
  );
  return crypto.createHash('sha256').update(stableJson({
    lifecycle_id: record.lifecycle_id,
    stale_id: record.stale_id,
    repair_id: record.repair_id,
    identity_sha256: lifecycleIdentity(record, identitySource),
    module_id: canonicalModule(record.module_id),
    code: canonicalCode(record.code),
    artifact: effectiveArtifact,
    affected_artifacts: Array.from(new Set(
      (record.affected_artifacts || []).map(canonicalPath)
    )).sort(),
    status: record.status,
    reason: record.reason,
    severity: record.severity,
    score_cost: record.score_cost,
    repair_class: record.repair_class,
    required_checks: Array.from(new Set((record.required_checks || []).map(String))).sort(),
    resolution_predicate: record.resolution_predicate || null,
    safe_during_current_task: record.safe_during_current_task,
    critical_path: record.critical_path,
    security_sensitive: record.security_sensitive,
    occurrence: Number.isInteger(record.occurrence) && record.occurrence > 0
      ? record.occurrence
      : 1,
    opened_at: record.opened_at || null,
    last_seen_at: record.last_seen_at || null,
    reopened_at: record.reopened_at || null,
    closed_at: record.closed_at || null,
    resolution_evidence: record.resolution_evidence || null,
    sources: record.sources || {}
  })).digest('hex');
}

function validateLifecycleIdentity(record, identitySource = null) {
  const lifecycleId = String(record.lifecycle_id || '');
  const actualIdentity = lifecycleIdentity(record, identitySource);
  if (record.identity_sha256 && record.identity_sha256 !== actualIdentity) {
    throw lifecycleIntegrityError(
      'lifecycle_identity_hash_mismatch',
      lifecycleId,
      `Lifecycle identity hash does not match its record: ${lifecycleId}`,
      {
        declared_identity_sha256: record.identity_sha256,
        actual_identity_sha256: actualIdentity
      }
    );
  }
  const expectedId = `LC-${actualIdentity.slice(0, 16)}`;
  if (lifecycleId !== expectedId) {
    throw lifecycleIntegrityError(
      'lifecycle_id_collision',
      lifecycleId,
      `Lifecycle ID does not match its canonical identity: ${lifecycleId}`,
      { expected_lifecycle_id: expectedId, actual_identity_sha256: actualIdentity }
    );
  }
  return actualIdentity;
}

function lifecycleById(stale, repair) {
  const records = new Map();
  for (const item of (stale.items || [])) {
    if (!item.lifecycle_id) continue;
    validateLifecycleIdentity(item);
    const current = records.get(item.lifecycle_id);
    if (current &&
        projectionFingerprint(current) !== projectionFingerprint(item, current)) {
      throw lifecycleIntegrityError(
        'lifecycle_projection_conflict',
        item.lifecycle_id,
        `Duplicate stale lifecycle projections disagree: ${item.lifecycle_id}`
      );
    }
    if (!current) records.set(item.lifecycle_id, item);
  }
  for (const item of (repair.queue || [])) {
    if (!item.lifecycle_id) continue;
    const current = records.get(item.lifecycle_id);
    validateLifecycleIdentity(item, current);
    if (current &&
        projectionFingerprint(current) !== projectionFingerprint(item, current)) {
      throw lifecycleIntegrityError(
        'lifecycle_projection_conflict',
        item.lifecycle_id,
        `Stale and repair lifecycle projections disagree: ${item.lifecycle_id}`
      );
    }
    if (!current) records.set(item.lifecycle_id, item);
  }
  return records;
}

function project(record, kind) {
  const common = {
    id: kind === 'stale' ? record.stale_id : record.repair_id,
    lifecycle_id: record.lifecycle_id,
    stale_id: record.stale_id,
    repair_id: record.repair_id,
    module_id: record.module_id,
    code: record.code,
    status: record.status,
    reason: record.reason,
    affected_artifacts: record.affected_artifacts,
    severity: record.severity,
    score_cost: record.score_cost,
    repair_class: record.repair_class,
    required_checks: record.required_checks,
    resolution_predicate: record.resolution_predicate,
    safe_during_current_task: record.safe_during_current_task,
    critical_path: record.critical_path,
    security_sensitive: record.security_sensitive,
    estimated_additional_work: record.estimated_additional_work,
    occurrence: Number.isInteger(record.occurrence) && record.occurrence > 0
      ? record.occurrence
      : 1,
    opened_at: record.opened_at,
    last_seen_at: record.last_seen_at,
    reopened_at: record.reopened_at || null,
    closed_at: record.closed_at || null,
    resolution_evidence: record.resolution_evidence || null,
    identity_sha256: record.identity_sha256 || identitySha256(record),
    primary_artifact: record.primary_artifact || record.artifact,
    sources: record.sources
  };
  if (kind === 'stale') return { ...common, artifact: record.artifact, priority: record.priority };
  return { ...common, priority: record.priority, subject: `Resolve ${record.code}: ${record.reason}` };
}

function reconcile({ staleItems, repairQueue, findings = [], source, agentId, timestamp }) {
  if (!source) throw new Error('queue lifecycle source is required');
  staleItems.items = Array.isArray(staleItems.items) ? staleItems.items : [];
  repairQueue.queue = Array.isArray(repairQueue.queue) ? repairQueue.queue : [];
  const old = lifecycleById(staleItems, repairQueue);
  const records = new Map(old);
  const seen = new Set();
  const events = [];

  for (const raw of findings) {
    const finding = normalizedFinding(raw);
    const lifecycle_id = stableId('LC', finding);
    const identity_sha256 = identitySha256(finding);
    seen.add(lifecycle_id);
    let record = records.get(lifecycle_id);
    if (!record) {
      record = {
        lifecycle_id,
        stale_id: stableId('STALE', finding),
        repair_id: stableId('RQ', finding),
        ...finding,
        identity_sha256,
        status: 'open',
        occurrence: 1,
        opened_at: timestamp,
        last_seen_at: timestamp,
        sources: {}
      };
      events.push({ transition: 'open', lifecycle_id, module_id: finding.module_id, code: finding.code });
    } else {
      record.occurrence = Number.isInteger(record.occurrence) && record.occurrence > 0
        ? record.occurrence
        : 1;
      const existingIdentity = identitySha256(record);
      if (existingIdentity !== identity_sha256) {
        const error = new Error(`Lifecycle ID collision for ${lifecycle_id}`);
        error.code = 'lifecycle_id_collision';
        error.lifecycle_id = lifecycle_id;
        error.existing_identity_sha256 = existingIdentity;
        error.incoming_identity_sha256 = identity_sha256;
        throw error;
      }
    }
    if (record.status === 'closed' || record.status === 'resolved') {
      record.status = 'open';
      record.occurrence += 1;
      record.reopened_at = timestamp;
      record.closed_at = null;
      record.resolution_evidence = null;
      events.push({ transition: 'reopen', lifecycle_id, module_id: finding.module_id, code: finding.code });
    }
    Object.assign(record, finding, { identity_sha256, last_seen_at: timestamp });
    record.sources = record.sources || {};
    record.sources[source] = { active: true, observed_at: timestamp, agent_id: agentId };
    records.set(lifecycle_id, record);
  }

  for (const record of records.values()) {
    if (!record.sources || !Object.prototype.hasOwnProperty.call(record.sources, source) || seen.has(record.lifecycle_id)) continue;
    const wasActive = record.sources[source]?.active === true;
    record.sources[source] = { ...record.sources[source], active: false, observed_at: timestamp, agent_id: agentId };
    if (wasActive && record.status !== 'closed' && record.status !== 'resolved') {
      // Detector disappearance is not verification. Keep debt open until an
      // exact lifecycle closure carries a completed resolution predicate.
      record.last_absent_at = timestamp;
      events.push({
        transition: 'observation_absent',
        lifecycle_id: record.lifecycle_id,
        module_id: record.module_id,
        code: record.code,
        status: record.status
      });
    }
  }

  const lifecycle = Array.from(records.values()).sort((a, b) => a.lifecycle_id.localeCompare(b.lifecycle_id));
  const unmanagedStale = staleItems.items.filter((item) => !item.lifecycle_id);
  const unmanagedRepair = repairQueue.queue.filter((item) => !item.lifecycle_id);
  staleItems.items = [...unmanagedStale, ...lifecycle.map((record) => project(record, 'stale'))];
  repairQueue.queue = [...unmanagedRepair, ...lifecycle.map((record) => project(record, 'repair'))];
  staleItems.generated_at = timestamp;
  repairQueue.generated_at = timestamp;
  return { events, lifecycle };
}

function closeFindings({
  staleItems,
  repairQueue,
  lifecycleIds = [],
  allowedCodes = [],
  verifiedArtifacts = [],
  resolutionEvidence = [],
  recertificationId,
  agentId,
  timestamp,
  verifyDedicatedEvidence = null
}) {
  const records = lifecycleById(staleItems, repairQueue);
  const requested = Array.from(new Set(lifecycleIds.map(String)));
  const allowed = new Set(allowedCodes.map(canonicalCode));
  const artifacts = new Set(verifiedArtifacts.map(canonicalPath));
  const evidenceById = new Map();
  const duplicateEvidenceIds = new Set();
  for (const item of (Array.isArray(resolutionEvidence) ? resolutionEvidence : Object.values(resolutionEvidence || {}))) {
    if (!item || !item.lifecycle_id) continue;
    const lifecycleId = String(item.lifecycle_id);
    if (evidenceById.has(lifecycleId)) duplicateEvidenceIds.add(lifecycleId);
    evidenceById.set(lifecycleId, item);
  }
  const events = [];
  const verified = [];
  const closed = [];
  const rejected = [];

  for (const lifecycleId of requested) {
    const record = records.get(lifecycleId);
    if (!record) {
      rejected.push({ lifecycle_id: lifecycleId, reason: 'lifecycle_not_found' });
      continue;
    }
    const code = canonicalCode(record.code);
    const artifact = canonicalPath(record.artifact || record.primary_artifact || record.affected_artifacts?.[0]);
    const affectedArtifacts = Array.from(new Set([
      artifact,
      ...(record.affected_artifacts || [])
    ].map(canonicalPath)));
    const evidence = evidenceById.get(lifecycleId);
    if (artifact === 'unknown' || artifact === '.') {
      rejected.push({
        lifecycle_id: lifecycleId,
        code,
        artifact,
        reason: 'finding_artifact_not_specific'
      });
      continue;
    }
    if (duplicateEvidenceIds.has(lifecycleId)) {
      rejected.push({ lifecycle_id: lifecycleId, code, artifact, reason: 'duplicate_resolution_evidence' });
      continue;
    }
    if (!allowed.has(code)) {
      rejected.push({ lifecycle_id: lifecycleId, code, artifact, reason: 'finding_code_not_allowed' });
      continue;
    }
    const reservedFields = evidence
      ? Object.keys(evidence).filter((key) => RESOLUTION_EVIDENCE_RESERVED_FIELDS.has(key))
      : [];
    if (reservedFields.length) {
      rejected.push({
        lifecycle_id: lifecycleId,
        code,
        artifact,
        reserved_fields: reservedFields.sort(),
        reason: 'resolution_evidence_reserved_field'
      });
      continue;
    }
    const missingArtifacts = affectedArtifacts.filter((item) => !artifacts.has(item));
    if (missingArtifacts.length) {
      rejected.push({
        lifecycle_id: lifecycleId,
        code,
        artifact,
        affected_artifacts: affectedArtifacts,
        missing_artifacts: missingArtifacts,
        reason: 'artifact_not_verified'
      });
      continue;
    }
    let evidenceMatches = false;
    try {
      evidenceMatches = Boolean(
        evidence &&
        String(evidence.lifecycle_id) === lifecycleId &&
        canonicalCode(evidence.code) === code &&
        canonicalPath(evidence.artifact) === artifact
      );
    } catch {
      evidenceMatches = false;
    }
    if (!evidenceMatches) {
      rejected.push({ lifecycle_id: lifecycleId, code, artifact, reason: 'resolution_evidence_mismatch' });
      continue;
    }
    if (record.resolution_predicate && String(evidence.predicate || '') !== String(record.resolution_predicate)) {
      rejected.push({
        lifecycle_id: lifecycleId,
        code,
        artifact,
        reason: 'resolution_predicate_mismatch',
        predicate: evidence.predicate || null
      });
      continue;
    }
    let dedicatedValidation = null;
    if (dedicatedRequirementFor(record)) {
      dedicatedValidation = dedicatedResolutionVerdict({
        evidence,
        code,
        record,
        verifyDedicatedEvidence
      });
      if (!dedicatedValidation.ok) {
        rejected.push({ lifecycle_id: lifecycleId, code, artifact, reason: dedicatedValidation.reason });
        continue;
      }
    }
    if (!evidence.predicate || evidence.predicate_result !== true) {
      rejected.push({ lifecycle_id: lifecycleId, code, artifact, reason: 'resolution_predicate_failed', predicate: evidence?.predicate || null });
      continue;
    }
    verified.push(lifecycleId);
    if (record.status === 'closed' || record.status === 'resolved') continue;
    record.status = 'closed';
    record.closed_at = timestamp;
    record.resolution_evidence = {
      ...evidence,
      lifecycle_id: record.lifecycle_id,
      code,
      artifact,
      type: 'finding_specific_recertification',
      recertification_id: recertificationId,
      verified_at: timestamp,
      verified_by: agentId,
      ...(dedicatedValidation ? {
        dedicated_verifier_validated: true,
        dedicated_authority_id: dedicatedValidation.authority_id,
        dedicated_receipt_id: dedicatedValidation.receipt_id,
        dedicated_receipt_path: dedicatedValidation.receipt_path,
        dedicated_receipt_sha256: dedicatedValidation.receipt_sha256
      } : {})
    };
    for (const source of Object.keys(record.sources || {})) record.sources[source] = { ...record.sources[source], active: false, observed_at: timestamp, agent_id: agentId };
    closed.push(lifecycleId);
    events.push({
      transition: 'closed',
      lifecycle_id: record.lifecycle_id,
      module_id: record.module_id,
      code: record.code,
      artifact,
      reason: 'finding_specific_recertification',
      recertification_id: recertificationId
    });
  }
  const lifecycle = Array.from(records.values()).sort((a, b) => a.lifecycle_id.localeCompare(b.lifecycle_id));
  staleItems.items = [...staleItems.items.filter((item) => !item.lifecycle_id), ...lifecycle.map((record) => project(record, 'stale'))];
  repairQueue.queue = [...repairQueue.queue.filter((item) => !item.lifecycle_id), ...lifecycle.map((record) => project(record, 'repair'))];
  staleItems.generated_at = timestamp;
  repairQueue.generated_at = timestamp;
  const untouchedOpen = lifecycle
    .filter((record) => !['closed', 'resolved'].includes(record.status))
    .map((record) => ({
      lifecycle_id: record.lifecycle_id,
      module_id: record.module_id,
      code: record.code,
      artifact: record.artifact,
      status: record.status
    }));
  return {
    requested_lifecycle_ids: requested,
    verified_lifecycle_ids: verified,
    closed_lifecycle_ids: closed,
    rejected_lifecycle_ids: rejected,
    untouched_open_findings: untouchedOpen,
    events,
    lifecycle
  };
}

module.exports = {
  reconcile,
  closeFindings,
  stableId,
  normalizedFinding,
  canonicalPath,
  canonicalCode,
  canonicalModule,
  HASH_RECERTIFICATION_BLOCKED_CODES,
  FINDING_CODE_ALIASES,
  DEDICATED_VERIFIER_TYPES,
  DEDICATED_REQUIREMENTS,
  RESOLUTION_EVIDENCE_RESERVED_FIELDS,
  requiresDedicatedVerifier,
  dedicatedRequirementFor,
  hasDedicatedResolutionEvidence,
  dedicatedResolutionVerdict,
  identitySha256,
  findingOccurrence,
  lifecycleById
};
