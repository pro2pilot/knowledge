'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { writeFileAtomic } = require('./json-store');
const {
  canonicalPath,
  canonicalCode,
  canonicalModule,
  identitySha256,
  findingOccurrence,
  dedicatedRequirementFor,
  DEDICATED_REQUIREMENTS
} = require('./queue-lifecycle');

const DEDICATED_RECEIPT_SCHEMA = 'knowledge-dedicated-verification-receipt.v1';
const DEDICATED_AUTHORITY_ID = 'first_party_content_addressed_dedicated_receipt_loader.v1';
const MAX_RECEIPT_BYTES = 64 * 1024;
const SHA256_PATTERN = /^[a-f0-9]{64}$/;
const LIFECYCLE_PATTERN = /^LC-[a-f0-9]{16}$/;
const REVIEW_ID_PATTERN = /^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,126}[A-Za-z0-9])?$/;
const RECEIPT_KEYS = Object.freeze([
  'schema_version',
  'receipt_id',
  'content_sha256',
  'verification_receipt_id',
  'verification_receipt_sha256',
  'lifecycle_id',
  'finding_identity_sha256',
  'finding_occurrence_sha256',
  'module_id',
  'code',
  'artifact',
  'affected_artifacts',
  'resolution_predicate',
  'resolution_result',
  'dedicated_verifier_type',
  'dedicated_verifier_id',
  'dedicated_predicate',
  'dedicated_result',
  'confirmed_lifecycle_id',
  'reviewed_at',
  'reviewed_by'
]);

function stableJson(value) {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) =>
      `${JSON.stringify(key)}:${stableJson(value[key])}`
    ).join(',')}}`;
  }
  return JSON.stringify(value);
}

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function canonicalReceiptInput(raw) {
  const copy = JSON.parse(JSON.stringify(raw || {}));
  delete copy.receipt_id;
  delete copy.content_sha256;
  return copy;
}

function receiptDigest(raw) {
  return sha256(stableJson(canonicalReceiptInput(raw)));
}

function receiptError(code, message, validation = null) {
  const error = new Error(message);
  error.code = code;
  if (validation) error.validation = validation;
  return error;
}

function canonicalAffected(finding) {
  return Array.from(new Set([
    finding?.artifact,
    finding?.primary_artifact,
    ...(finding?.affected_artifacts || [])
  ].filter(Boolean).map(canonicalPath))).sort();
}

function allowedDedicatedPair(type, predicate) {
  return Object.values(DEDICATED_REQUIREMENTS).some((requirement) =>
    requirement.verifier_type === type && requirement.predicate === predicate);
}

function validateDedicatedReceipt(raw, options = {}) {
  const errors = [];
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    return { ok: false, errors: ['dedicated_receipt_object_required'], digest: null };
  }
  const keys = Object.keys(raw).sort();
  const expectedKeys = [...RECEIPT_KEYS].sort();
  for (const key of expectedKeys) {
    if (!Object.prototype.hasOwnProperty.call(raw, key)) {
      errors.push(`dedicated_receipt_field_missing:${key}`);
    }
  }
  for (const key of keys) {
    if (!RECEIPT_KEYS.includes(key)) errors.push(`dedicated_receipt_field_unknown:${key}`);
  }
  if (raw.schema_version !== DEDICATED_RECEIPT_SCHEMA) {
    errors.push('dedicated_receipt_schema_invalid');
  }
  if (!LIFECYCLE_PATTERN.test(String(raw.lifecycle_id || ''))) {
    errors.push('dedicated_lifecycle_id_invalid');
  }
  if (raw.confirmed_lifecycle_id !== raw.lifecycle_id) {
    errors.push('dedicated_lifecycle_confirmation_mismatch');
  }
  if (!SHA256_PATTERN.test(String(raw.finding_identity_sha256 || ''))) {
    errors.push('dedicated_finding_identity_invalid');
  }
  if (!SHA256_PATTERN.test(String(raw.finding_occurrence_sha256 || ''))) {
    errors.push('dedicated_finding_occurrence_hash_invalid');
  }
  if (!/^KVR-[a-f0-9]{64}$/.test(String(raw.verification_receipt_id || '')) ||
      !SHA256_PATTERN.test(String(raw.verification_receipt_sha256 || '')) ||
      raw.verification_receipt_id !== `KVR-${raw.verification_receipt_sha256}`) {
    errors.push('dedicated_verification_receipt_identity_invalid');
  }
  let moduleId = null;
  let code = null;
  let artifact = null;
  let affected = [];
  try {
    moduleId = canonicalModule(raw.module_id);
    code = canonicalCode(raw.code);
    artifact = canonicalPath(raw.artifact);
    affected = (raw.affected_artifacts || []).map(canonicalPath);
  } catch {
    errors.push('dedicated_finding_identity_unsafe');
  }
  if (moduleId !== raw.module_id) errors.push('dedicated_module_id_noncanonical');
  if (code !== raw.code) errors.push('dedicated_code_noncanonical');
  if (artifact !== raw.artifact) errors.push('dedicated_artifact_noncanonical');
  if (
    !Array.isArray(raw.affected_artifacts) ||
    raw.affected_artifacts.length === 0 ||
    new Set(affected).size !== affected.length ||
    stableJson(affected) !== stableJson([...affected].sort()) ||
    !affected.includes(artifact)
  ) {
    errors.push('dedicated_affected_artifacts_noncanonical');
  }
  if (typeof raw.resolution_predicate !== 'string' || !raw.resolution_predicate) {
    errors.push('dedicated_resolution_predicate_invalid');
  }
  if (raw.resolution_result !== 'pass') errors.push('dedicated_resolution_result_not_pass');
  if (
    !allowedDedicatedPair(raw.dedicated_verifier_type, raw.dedicated_predicate)
  ) {
    errors.push('dedicated_verifier_requirement_invalid');
  }
  if (!REVIEW_ID_PATTERN.test(String(raw.dedicated_verifier_id || ''))) {
    errors.push('dedicated_verifier_id_invalid');
  }
  if (!REVIEW_ID_PATTERN.test(String(raw.reviewed_by || ''))) {
    errors.push('dedicated_reviewer_id_invalid');
  }
  if (raw.dedicated_result !== 'pass') errors.push('dedicated_result_not_pass');
  if (
    typeof raw.reviewed_at !== 'string' ||
    !Number.isFinite(Date.parse(raw.reviewed_at))
  ) {
    errors.push('dedicated_reviewed_at_invalid');
  } else if (Date.parse(raw.reviewed_at) > Date.now() + 5 * 60 * 1000) {
    errors.push('dedicated_reviewed_at_in_future');
  }

  const finding = options.finding || null;
  let occurrence = null;
  if (finding) {
    const requirement = dedicatedRequirementFor(finding);
    const expectedAffected = canonicalAffected(finding);
    const expectedIdentity = identitySha256(finding);
    try {
      occurrence = findingOccurrence(finding);
    } catch {
      errors.push('dedicated_finding_occurrence_invalid');
    }
    if (!requirement) errors.push('dedicated_receipt_not_required');
    if (raw.lifecycle_id !== finding.lifecycle_id) errors.push('dedicated_lifecycle_id_mismatch');
    if (moduleId !== canonicalModule(finding.module_id)) errors.push('dedicated_module_id_mismatch');
    if (code !== canonicalCode(finding.code)) errors.push('dedicated_code_mismatch');
    if (artifact !== canonicalPath(finding.artifact || finding.primary_artifact)) {
      errors.push('dedicated_artifact_mismatch');
    }
    if (stableJson(affected) !== stableJson(expectedAffected)) {
      errors.push('dedicated_affected_artifacts_mismatch');
    }
    if (raw.finding_identity_sha256 !== expectedIdentity) {
      errors.push('dedicated_finding_identity_mismatch');
    }
    if (occurrence &&
        raw.finding_occurrence_sha256 !== occurrence.sha256) {
      errors.push('dedicated_finding_occurrence_mismatch');
    }
    if (raw.resolution_predicate !== String(finding.resolution_predicate || '')) {
      errors.push('dedicated_resolution_predicate_mismatch');
    }
    if (
      requirement &&
      (
        raw.dedicated_verifier_type !== requirement.verifier_type ||
        raw.dedicated_predicate !== requirement.predicate
      )
    ) {
      errors.push('dedicated_verifier_requirement_mismatch');
    }
  }

  const verificationReceipt = options.verificationReceipt || null;
  if (verificationReceipt) {
    if (
      raw.verification_receipt_id !== verificationReceipt.receipt_id ||
      raw.verification_receipt_sha256 !== verificationReceipt.content_sha256
    ) {
      errors.push('dedicated_verification_receipt_mismatch');
    }
    if (raw.lifecycle_id !== verificationReceipt.finding_id) {
      errors.push('dedicated_verification_lifecycle_mismatch');
    }
    if (
      raw.finding_occurrence_sha256 !==
      verificationReceipt.finding_occurrence_sha256
    ) {
      errors.push('dedicated_verification_occurrence_mismatch');
    }
    if (moduleId !== canonicalModule(verificationReceipt.module_id)) {
      errors.push('dedicated_verification_module_mismatch');
    }
    if (raw.resolution_predicate !== verificationReceipt.resolution_predicate ||
        verificationReceipt.predicate_result !== 'pass') {
      errors.push('dedicated_verification_predicate_mismatch');
    }
    const checkedAtMs = Date.parse(String(verificationReceipt.checked_at || ''));
    const reviewedAtMs = Date.parse(String(raw.reviewed_at || ''));
    if (!Number.isFinite(checkedAtMs)) {
      errors.push('dedicated_verification_checked_at_invalid');
    }
    if (Number.isFinite(checkedAtMs) &&
        Number.isFinite(reviewedAtMs) &&
        reviewedAtMs < checkedAtMs) {
      errors.push('dedicated_review_before_verification');
    }
    if (occurrence &&
        Number.isFinite(checkedAtMs) &&
        checkedAtMs < Date.parse(occurrence.occurred_at)) {
      errors.push('dedicated_verification_predates_occurrence');
    }
    if (occurrence &&
        Number.isFinite(reviewedAtMs) &&
        reviewedAtMs < Date.parse(occurrence.occurred_at)) {
      errors.push('dedicated_review_predates_occurrence');
    }
    if (String(raw.reviewed_by || '') === String(verificationReceipt.checked_by || '')) {
      errors.push('dedicated_reviewer_not_independent');
    }
  }

  const digest = receiptDigest(raw);
  if (!SHA256_PATTERN.test(String(raw.content_sha256 || '')) ||
      raw.content_sha256 !== digest) {
    errors.push('dedicated_receipt_content_hash_mismatch');
  }
  if (raw.receipt_id !== `KDVR-${digest}`) {
    errors.push('dedicated_receipt_id_content_mismatch');
  }
  return { ok: errors.length === 0, errors: Array.from(new Set(errors)), digest };
}

function createDedicatedReceipt({
  verificationReceipt,
  finding,
  confirmedLifecycleId,
  dedicatedVerifierId,
  reviewedBy,
  reviewedAt = new Date().toISOString()
}) {
  const requirement = dedicatedRequirementFor(finding);
  if (!requirement) {
    throw receiptError(
      'dedicated_receipt_not_required',
      `Finding does not require dedicated verification: ${finding?.lifecycle_id || 'unknown'}`
    );
  }
  if (confirmedLifecycleId !== finding.lifecycle_id) {
    throw receiptError(
      'dedicated_lifecycle_confirmation_mismatch',
      `Exact lifecycle confirmation is required for ${finding.lifecycle_id}`
    );
  }
  const occurrence = findingOccurrence(finding);
  const base = {
    schema_version: DEDICATED_RECEIPT_SCHEMA,
    verification_receipt_id: verificationReceipt.receipt_id,
    verification_receipt_sha256: verificationReceipt.content_sha256,
    lifecycle_id: finding.lifecycle_id,
    finding_identity_sha256: identitySha256(finding),
    finding_occurrence_sha256: occurrence.sha256,
    module_id: canonicalModule(finding.module_id),
    code: canonicalCode(finding.code),
    artifact: canonicalPath(finding.artifact || finding.primary_artifact),
    affected_artifacts: canonicalAffected(finding),
    resolution_predicate: String(finding.resolution_predicate || ''),
    resolution_result: 'pass',
    dedicated_verifier_type: requirement.verifier_type,
    dedicated_verifier_id: String(dedicatedVerifierId || ''),
    dedicated_predicate: requirement.predicate,
    dedicated_result: 'pass',
    confirmed_lifecycle_id: confirmedLifecycleId,
    reviewed_at: reviewedAt,
    reviewed_by: String(reviewedBy || '')
  };
  const digest = receiptDigest(base);
  const receipt = {
    ...base,
    receipt_id: `KDVR-${digest}`,
    content_sha256: digest
  };
  const validation = validateDedicatedReceipt(receipt, {
    verificationReceipt,
    finding
  });
  if (!validation.ok) {
    throw receiptError(
      'dedicated_verification_receipt_invalid',
      `Dedicated verification receipt rejected: ${validation.errors.join(', ')}`,
      validation
    );
  }
  return receipt;
}

function receiptDirectory(stateRoot) {
  return path.join(stateRoot, 'maintenance', 'dedicated_verification_receipts');
}

function secureReceiptDirectory(stateRoot, { create = false } = {}) {
  const absoluteStateRoot = path.resolve(stateRoot);
  let stateStat;
  try {
    stateStat = fs.lstatSync(absoluteStateRoot);
  } catch {
    throw receiptError(
      'dedicated_receipt_store_unsafe',
      'Dedicated receipt state root does not exist'
    );
  }
  if (!stateStat.isDirectory() || stateStat.isSymbolicLink()) {
    throw receiptError(
      'dedicated_receipt_store_unsafe',
      'Dedicated receipt state root must be a real directory'
    );
  }
  const realStateRoot = fs.realpathSync(absoluteStateRoot);
  let current = absoluteStateRoot;
  for (const component of ['maintenance', 'dedicated_verification_receipts']) {
    current = path.join(current, component);
    if (!fs.existsSync(current)) {
      if (!create) {
        throw receiptError(
          'dedicated_receipt_store_missing',
          'Dedicated receipt store does not exist'
        );
      }
      try {
        fs.mkdirSync(current);
      } catch (error) {
        if (error.code !== 'EEXIST') throw error;
      }
    }
    const stat = fs.lstatSync(current);
    if (!stat.isDirectory() || stat.isSymbolicLink()) {
      throw receiptError(
        'dedicated_receipt_store_unsafe',
        'Dedicated receipt store components must be real directories'
      );
    }
  }
  const realDirectory = fs.realpathSync(current);
  const relative = path.relative(realStateRoot, realDirectory);
  if (
    relative.replace(/\\/g, '/') !==
      'maintenance/dedicated_verification_receipts' ||
    relative.startsWith('..') ||
    path.isAbsolute(relative)
  ) {
    throw receiptError(
      'dedicated_receipt_store_unsafe',
      'Dedicated receipt store escaped the state root'
    );
  }
  return realDirectory;
}

function saveDedicatedReceipt(stateRoot, receipt, options = {}) {
  const validation = validateDedicatedReceipt(receipt, options);
  if (!validation.ok) {
    throw receiptError(
      'dedicated_verification_receipt_invalid',
      `Dedicated verification receipt rejected: ${validation.errors.join(', ')}`,
      validation
    );
  }
  const directory = secureReceiptDirectory(stateRoot, { create: true });
  const target = path.join(directory, `${receipt.content_sha256}.json`);
  const body = `${JSON.stringify(receipt, null, 2)}\n`;
  if (Buffer.byteLength(body) > MAX_RECEIPT_BYTES) {
    throw receiptError(
      'dedicated_receipt_too_large',
      'Dedicated verification receipt exceeds the bounded content-store limit'
    );
  }
  if (fs.existsSync(target)) {
    const stat = fs.lstatSync(target);
    if (!stat.isFile() || stat.isSymbolicLink() || fs.readFileSync(target, 'utf8') !== body) {
      throw receiptError(
        'dedicated_verification_receipt_immutable',
        'Content-addressed dedicated verification receipt is immutable'
      );
    }
    return {
      path: target,
      relative_path:
        `maintenance/dedicated_verification_receipts/${receipt.content_sha256}.json`,
      idempotent: true,
      physical_sha256: sha256(Buffer.from(body))
    };
  }
  writeFileAtomic(target, body);
  return {
    path: target,
    relative_path:
      `maintenance/dedicated_verification_receipts/${receipt.content_sha256}.json`,
    idempotent: false,
    physical_sha256: sha256(Buffer.from(body))
  };
}

function loadDedicatedReceipt(stateRoot, reference, options = {}) {
  const rawReference = String(reference || '');
  if (rawReference.length > 80) {
    throw receiptError(
      'dedicated_receipt_reference_invalid',
      'Dedicated receipt reference is too long'
    );
  }
  const match = rawReference.match(/^(?:KDVR-)?([a-f0-9]{64})$/);
  if (!match) {
    throw receiptError(
      'dedicated_receipt_reference_invalid',
      'Dedicated receipt reference must be a KDVR ID or a 64-character digest'
    );
  }
  const digest = match[1];
  const directory = secureReceiptDirectory(stateRoot);
  const candidate = path.join(directory, `${digest}.json`);
  let stat;
  try {
    stat = fs.lstatSync(candidate);
  } catch {
    throw receiptError(
      'dedicated_receipt_not_found',
      `Dedicated verification receipt not found: KDVR-${digest}`
    );
  }
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size <= 0 || stat.size > MAX_RECEIPT_BYTES) {
    throw receiptError(
      'dedicated_receipt_file_invalid',
      `Dedicated verification receipt is not a safe regular file: KDVR-${digest}`
    );
  }
  const real = fs.realpathSync(candidate);
  const relative = path.relative(directory, real);
  if (
    relative !== `${digest}.json` ||
    relative.startsWith('..') ||
    path.isAbsolute(relative)
  ) {
    throw receiptError(
      'dedicated_receipt_path_invalid',
      `Dedicated verification receipt escaped its content-addressed store: KDVR-${digest}`
    );
  }
  let receipt;
  let body;
  try {
    body = fs.readFileSync(real);
    receipt = JSON.parse(
      body.toString('utf8').replace(/^\uFEFF/, '')
    );
  } catch {
    throw receiptError(
      'dedicated_receipt_json_invalid',
      `Dedicated verification receipt is invalid JSON: KDVR-${digest}`
    );
  }
  const validation = validateDedicatedReceipt(receipt, options);
  if (!validation.ok || receipt.content_sha256 !== digest) {
    throw receiptError(
      'dedicated_verification_receipt_invalid',
      `Dedicated verification receipt failed validation: ${validation.errors.join(', ')}`,
      validation
    );
  }
  return {
    receipt,
    path: real,
    relative_path: `maintenance/dedicated_verification_receipts/${digest}.json`,
    physical_sha256: sha256(body)
  };
}

function verifyDedicatedEvidence({
  stateRoot,
  evidence,
  verificationReceipt,
  finding
}) {
  const loaded = loadDedicatedReceipt(
    stateRoot,
    evidence?.dedicated_receipt_id,
    { verificationReceipt, finding }
  );
  const receipt = loaded.receipt;
  if (
    evidence.dedicated_receipt_id !== receipt.receipt_id ||
    evidence.dedicated_receipt_sha256 !== receipt.content_sha256 ||
    evidence.dedicated_receipt_path !== loaded.relative_path ||
    evidence.dedicated_verifier_type !== receipt.dedicated_verifier_type ||
    evidence.dedicated_verifier_id !== receipt.dedicated_verifier_id ||
    evidence.dedicated_predicate !== receipt.dedicated_predicate ||
    evidence.dedicated_result !== receipt.dedicated_result
  ) {
    throw receiptError(
      'dedicated_evidence_mismatch',
      'Resolution evidence does not match the physical dedicated receipt'
    );
  }
  return {
    ok: true,
    authority_id: DEDICATED_AUTHORITY_ID,
    receipt_id: receipt.receipt_id,
    receipt_path: loaded.relative_path,
    receipt_sha256: receipt.content_sha256,
    physical_path: loaded.path,
    physical_sha256: loaded.physical_sha256
  };
}

module.exports = {
  DEDICATED_RECEIPT_SCHEMA,
  DEDICATED_AUTHORITY_ID,
  MAX_RECEIPT_BYTES,
  REVIEW_ID_PATTERN,
  RECEIPT_KEYS,
  stableJson,
  receiptDigest,
  findingOccurrence,
  validateDedicatedReceipt,
  createDedicatedReceipt,
  saveDedicatedReceipt,
  loadDedicatedReceipt,
  verifyDedicatedEvidence,
  receiptDirectory,
  secureReceiptDirectory
};
