'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { assertSafeContainedPath } = require('../json-store');
const { scanEnglishLanguage, scanPublication } = require('./redactor');

const SCHEMA_VERSION = 'knowledge-field-report-task-results.v1';
const OUTCOMES = new Set(['pass', 'pass_with_warnings', 'fail', 'incomplete', 'not_verified']);
const STATUSES = new Set(['pass', 'warning', 'fail', 'not_run', 'unavailable']);
const CATEGORIES = new Set([
  'build', 'typecheck', 'tests', 'lint', 'security', 'migration', 'data_quality',
  'ui', 'links_assets', 'package', 'deployment', 'documentation', 'other'
]);
const EVIDENCE_KINDS = new Set([
  'automated_report', 'command_log', 'receipt', 'manual_review', 'other'
]);
const ROOT_KINDS = new Set(['repository', 'state']);
const MAX_EVIDENCE_BYTES = 16 * 1024 * 1024;
const MAX_RESULTS = 24;
const MAX_EVIDENCE_PER_RESULT = 8;

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) =>
      `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function canonicalHash(value) {
  return crypto.createHash('sha256').update(canonicalJson(value)).digest('hex');
}

function sha256File(file) {
  return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
}

function publicationText(value, name, maximum, errors, { required = true } = {}) {
  const text = String(value ?? '').replace(/\s+/g, ' ').trim();
  if (!text) {
    if (required) errors.push(`${name} is required`);
    return null;
  }
  if (/[\u0000-\u001F\u007F]/.test(text)) errors.push(`${name} contains control characters`);
  if (Array.from(text).length > maximum) errors.push(`${name} exceeds ${maximum} characters`);
  if (scanEnglishLanguage(text).status !== 'pass') errors.push(`${name} must be publication-ready English`);
  const privacy = scanPublication({ body: text }, false, { requireEnglish: true });
  if (privacy.report.status === 'blocked' || privacy.body !== text) {
    errors.push(`${name} contains private or unsafe publication text`);
  }
  return text;
}

function safeRelative(value, name, errors) {
  const raw = String(value || '').replace(/\\/g, '/').replace(/^\.\//, '').replace(/\/+/g, '/');
  const segments = raw.split('/');
  const basename = segments[segments.length - 1] || '';
  if (!raw || path.posix.isAbsolute(raw) || /^[A-Za-z]:/.test(raw) ||
      segments.includes('..') || segments.includes('')) {
    errors.push(`${name} must be a safe repository-relative path`);
    return null;
  }
  if ((/^\.env(?:\.|$)/i.test(basename) && !/^\.env\.(?:example|sample|template)$/i.test(basename)) ||
      /\.(?:pem|p12|pfx|key)$/i.test(basename) ||
      /^(?:credentials?|secrets?)(?:\.|$)/i.test(basename)) {
    errors.push(`${name} points to a secret-like file`);
    return null;
  }
  return segments.join('/');
}

function rootFor(context, rootKind) {
  return rootKind === 'state' ? context.stateRoot : context.targetRoot;
}

function containedFile(context, rootKind, relative, errors) {
  const root = path.resolve(rootFor(context, rootKind));
  const absolute = path.resolve(root, ...relative.split('/'));
  try {
    assertSafeContainedPath(root, absolute);
    const stat = fs.lstatSync(absolute);
    if (!stat.isFile() || stat.isSymbolicLink() ||
        (Number.isInteger(stat.nlink) && stat.nlink > 1)) {
      errors.push(`evidence path is not a safe regular file: ${relative}`);
      return null;
    }
    if (stat.size > MAX_EVIDENCE_BYTES) {
      errors.push(`evidence file exceeds ${MAX_EVIDENCE_BYTES} bytes: ${relative}`);
      return null;
    }
    const realRoot = fs.realpathSync(root);
    const realFile = fs.realpathSync(absolute);
    if (realFile !== realRoot && !realFile.startsWith(`${realRoot}${path.sep}`)) {
      errors.push(`evidence path escaped physical ${rootKind} root`);
      return null;
    }
  } catch {
    errors.push(`evidence file is unavailable or unsafe: ${relative}`);
    return null;
  }
  return absolute;
}

function normalizeObservedStatus(value) {
  const status = String(value || '').trim().toLowerCase().replace(/-/g, '_');
  if (['pass', 'passed', 'ok', 'success', 'successful', 'ready', 'healthy'].includes(status)) return 'pass';
  if (['warning', 'warnings', 'pass_with_warnings', 'ready_with_warnings', 'usable_with_warnings'].includes(status)) return 'warning';
  if (['fail', 'failed', 'error', 'blocked', 'broken', 'needs_repair'].includes(status)) return 'fail';
  if (['not_run', 'skipped', 'not_performed', 'not_applicable'].includes(status)) return 'not_run';
  if (['unavailable', 'unknown', 'not_verified'].includes(status)) return 'unavailable';
  return null;
}

function inferAutomatedStatus(value) {
  if (!value || typeof value !== 'object') return null;
  const direct = normalizeObservedStatus(value.status || value.result || value.conclusion);
  if (direct) return direct;
  if (Number.isFinite(value.exit_code)) return Number(value.exit_code) === 0 ? 'pass' : 'fail';
  if (Number.isFinite(value.failed)) return Number(value.failed) === 0 ? 'pass' : 'fail';
  if (Number.isFinite(value.checks_failed)) return Number(value.checks_failed) === 0 ? 'pass' : 'fail';
  if (value.pass === true || value.ok === true) return 'pass';
  if (value.pass === false || value.ok === false) return 'fail';
  return null;
}

function normalizeMetrics(value, name, errors) {
  if (value === undefined || value === null) return null;
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    errors.push(`${name} must be an object`);
    return null;
  }
  const result = {};
  for (const key of ['passed', 'failed', 'warnings', 'total']) {
    if (value[key] === undefined || value[key] === null) continue;
    const count = Number(value[key]);
    if (!Number.isInteger(count) || count < 0) errors.push(`${name}.${key} must be a non-negative integer`);
    else result[key] = count;
  }
  if (value.value !== undefined && value.value !== null) {
    const number = Number(value.value);
    if (!Number.isFinite(number)) errors.push(`${name}.value must be finite`);
    else result.value = number;
  }
  if (value.unit !== undefined && value.unit !== null) {
    result.unit = publicationText(value.unit, `${name}.unit`, 40, errors);
  }
  if (Number.isInteger(result.total)) {
    const classified = (result.passed || 0) + (result.failed || 0) + (result.warnings || 0);
    if (classified > result.total) errors.push(`${name} classified counts exceed total`);
  }
  if (Number.isInteger(result.failed) && result.failed > 0 && Number.isInteger(result.passed) && result.passed > 0) {
    // Mixed results are allowed, but the row status cannot claim a clean pass.
  }
  return Object.keys(result).length ? result : null;
}

function validateEvidenceItem(evidence, row, context, errors, prefix) {
  if (!evidence || typeof evidence !== 'object' || Array.isArray(evidence)) {
    errors.push(`${prefix} must be an object`);
    return null;
  }
  const kind = String(evidence.kind || 'automated_report').trim();
  if (!EVIDENCE_KINDS.has(kind)) errors.push(`${prefix}.kind is invalid`);
  const label = publicationText(evidence.label, `${prefix}.label`, 100, errors);
  const rootKind = String(evidence.root_kind || 'repository').trim();
  if (!ROOT_KINDS.has(rootKind)) errors.push(`${prefix}.root_kind is invalid`);
  const relative = safeRelative(evidence.path, `${prefix}.path`, errors);
  const expectedSha = String(evidence.sha256 || '').toLowerCase();
  if (!/^[a-f0-9]{64}$/.test(expectedSha)) errors.push(`${prefix}.sha256 is invalid`);

  let actualSha = null;
  let inferredStatus = null;
  let evidenceJson = null;
  let sizeBytes = null;
  if (relative && ROOT_KINDS.has(rootKind)) {
    const absolute = containedFile(context, rootKind, relative, errors);
    if (absolute) {
      const stat = fs.lstatSync(absolute);
      sizeBytes = stat.size;
      actualSha = sha256File(absolute);
      if (expectedSha && actualSha !== expectedSha) errors.push(`${prefix}.sha256 does not match the file`);
      if (kind === 'automated_report' || kind === 'receipt') {
        try {
          evidenceJson = JSON.parse(fs.readFileSync(absolute, 'utf8').replace(/^\uFEFF/, ''));
        } catch {
          errors.push(`${prefix} must be valid JSON for ${kind}`);
        }
      }
    }
  }

  if (kind === 'automated_report' && evidenceJson) {
    inferredStatus = inferAutomatedStatus(evidenceJson);
    if (!inferredStatus) errors.push(`${prefix} automated status is unresolved`);
  }
  if (kind === 'receipt' && evidenceJson) {
    const schema = String(evidenceJson.schema_version || '');
    const pass = schema === 'knowledge-verification-receipt.v1'
      ? evidenceJson.predicate_result === 'pass'
      : schema === 'knowledge-dedicated-verification-receipt.v1'
        ? evidenceJson.dedicated_result === 'pass' && evidenceJson.resolution_result === 'pass'
        : false;
    inferredStatus = pass ? 'pass' : null;
    if (!pass) errors.push(`${prefix} is not a passing supported verification receipt`);
  }
  if (kind === 'command_log') {
    if (!Number.isInteger(evidence.exit_code)) errors.push(`${prefix}.exit_code is required for command_log`);
    else inferredStatus = evidence.exit_code === 0 ? 'pass' : 'fail';
  }
  if (kind === 'manual_review') {
    publicationText(evidence.reviewer, `${prefix}.reviewer`, 100, errors);
    const checkedAt = String(evidence.checked_at || '');
    if (!Number.isFinite(Date.parse(checkedAt))) errors.push(`${prefix}.checked_at must be an ISO timestamp`);
  }

  return {
    kind,
    label,
    root_kind: rootKind,
    path: relative,
    sha256: expectedSha,
    actual_sha256: actualSha,
    size_bytes: sizeBytes,
    exit_code: Number.isInteger(evidence.exit_code) ? evidence.exit_code : null,
    reviewer: kind === 'manual_review' ? String(evidence.reviewer || '').trim() : null,
    checked_at: kind === 'manual_review' ? String(evidence.checked_at || '').trim() : null,
    inferred_status: inferredStatus
  };
}

function validateEvidence(value, row, context, errors, prefix) {
  if (value === undefined || value === null) return [];
  const items = Array.isArray(value) ? value : [value];
  if (items.length > MAX_EVIDENCE_PER_RESULT) {
    errors.push(`${prefix} contains more than ${MAX_EVIDENCE_PER_RESULT} evidence items`);
  }
  const normalized = items.slice(0, MAX_EVIDENCE_PER_RESULT)
    .map((item, index) => validateEvidenceItem(item, row, context, errors, `${prefix}[${index}]`))
    .filter(Boolean);

  const inferred = normalized.map((item) => item.inferred_status).filter(Boolean);
  if (inferred.includes('fail') && row.status !== 'fail') {
    errors.push(`${prefix} contains failing evidence but row status is ${row.status}`);
  }
  if (!inferred.includes('fail') && inferred.length > 0 && row.status === 'fail') {
    errors.push(`${prefix} does not support a failed row status`);
  }
  if (inferred.every((status) => status === 'pass') && inferred.length > 0 &&
      !['pass', 'warning'].includes(row.status)) {
    errors.push(`${prefix} passing evidence conflicts with row status ${row.status}`);
  }
  return normalized;
}

function factValue(facts, id) {
  const item = facts?.values?.[id];
  return item && item.kind !== 'unavailable' ? item.value : null;
}

function snapshotFromFacts(facts) {
  const semantic = {
    basis: factValue(facts, 'repository_profile_basis'),
    status: factValue(facts, 'repository_snapshot_status'),
    head_sha: factValue(facts, 'head_sha'),
    tracked_changes: factValue(facts, 'repository_dirty_tracked_changes'),
    untracked_files: factValue(facts, 'repository_dirty_untracked_files'),
    conflicts: factValue(facts, 'repository_dirty_conflicts'),
    tracked_files: factValue(facts, 'repository_tracked_files'),
    tracked_bytes: factValue(facts, 'repository_tracked_bytes'),
    source_files: factValue(facts, 'repository_source_files'),
    source_bytes: factValue(facts, 'repository_source_bytes')
  };
  return { ...semantic, snapshot_sha256: canonicalHash(semantic) };
}

function deriveOutcome(rows) {
  const relevantRows = rows.filter((row) => row.outcome_relevant !== false);
  const statuses = relevantRows.map((row) => row.status);
  const pass = statuses.filter((status) => status === 'pass').length;
  const warnings = statuses.filter((status) => status === 'warning').length;
  const failures = statuses.filter((status) => status === 'fail').length;
  const unresolved = statuses.filter((status) => ['not_run', 'unavailable'].includes(status)).length;
  // A failed engineering check makes the task outcome fail even if other checks passed.
  // `incomplete` is reserved for partially assessed work with warnings but no clean pass.
  if (failures > 0) return 'fail';
  if (pass > 0 && (warnings > 0 || unresolved > 0)) return 'pass_with_warnings';
  if (pass > 0) return 'pass';
  if (warnings > 0) return 'incomplete';
  return 'not_verified';
}

function validateSnapshot(input, facts, errors, { captureSnapshot = false, requireSnapshotCurrent = false } = {}) {
  const current = facts ? snapshotFromFacts(facts) : null;
  if (captureSnapshot) return current;
  const snapshot = input && typeof input === 'object' && !Array.isArray(input) ? input : null;
  if (!snapshot || !/^[a-f0-9]{64}$/.test(String(snapshot.snapshot_sha256 || ''))) {
    errors.push('snapshot is missing or invalid');
    return snapshot;
  }
  if (requireSnapshotCurrent && current && snapshot.snapshot_sha256 !== current.snapshot_sha256) {
    errors.push('task results repository snapshot is stale');
  }
  return snapshot;
}

function validateTaskResults(input, {
  context,
  reportId,
  facts = null,
  captureSnapshot = false,
  requireSnapshotCurrent = false
} = {}) {
  const errors = [];
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    return { valid: false, errors: ['task results must be an object'], value: null };
  }
  if (!context || !context.targetRoot || !context.stateRoot) errors.push('task results require a resolved repository context');
  if (input.schema_version !== SCHEMA_VERSION) errors.push(`schema_version must be ${SCHEMA_VERSION}`);
  if (input.report_id !== reportId) errors.push('task results report_id does not match the Field Report');

  const task = input.task && typeof input.task === 'object' && !Array.isArray(input.task) ? input.task : {};
  const title = publicationText(task.title, 'task.title', 80, errors);
  if (title) {
    const words = title.split(/\s+/).filter(Boolean);
    if (Array.from(title).length < 8 || words.length < 2 ||
        /^(?:engineering task|repository update|project work|task|work)$/i.test(title)) {
      errors.push('task.title must be a concise, specific engineering outcome title');
    }
  }
  const summary = publicationText(task.summary, 'task.summary', 500, errors);
  const rows = Array.isArray(input.results) ? input.results : null;
  if (!rows || rows.length < 1 || rows.length > MAX_RESULTS) {
    errors.push(`results must contain 1 to ${MAX_RESULTS} rows`);
  }

  const ids = new Set();
  const normalizedRows = [];
  for (const [index, raw] of (rows || []).entries()) {
    const prefix = `results[${index}]`;
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
      errors.push(`${prefix} must be an object`);
      continue;
    }
    const id = String(raw.id || '').trim();
    if (!/^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$/.test(id)) errors.push(`${prefix}.id is invalid`);
    if (ids.has(id)) errors.push(`${prefix}.id is duplicated`);
    ids.add(id);
    const label = publicationText(raw.label, `${prefix}.label`, 80, errors);
    const category = String(raw.category || 'other').trim();
    if (!CATEGORIES.has(category)) errors.push(`${prefix}.category is invalid`);
    const status = String(raw.status || '').trim();
    if (!STATUSES.has(status)) errors.push(`${prefix}.status is invalid`);
    const publicSummary = publicationText(raw.public_summary || raw.summary, `${prefix}.public_summary`, 240, errors);
    const interpretation = publicationText(raw.interpretation, `${prefix}.interpretation`, 320, errors);
    const isPublic = raw.public !== false;
    const outcomeRelevant = raw.outcome_relevant !== false;
    if (raw.outcome_relevant !== undefined && typeof raw.outcome_relevant !== 'boolean') {
      errors.push(`${prefix}.outcome_relevant must be a boolean`);
    }
    const metrics = normalizeMetrics(raw.metrics, `${prefix}.metrics`, errors);
    if (metrics) {
      const failed = Number(metrics.failed || 0);
      const warnings = Number(metrics.warnings || 0);
      if (failed > 0 && status !== 'fail') {
        errors.push(`${prefix}.metrics reports failures but row status is ${status}`);
      }
      if (failed === 0 && warnings > 0 && status === 'pass') {
        errors.push(`${prefix}.metrics reports warnings but row status is pass`);
      }
      if (failed === 0 && warnings === 0 && status === 'fail' &&
          (Number.isInteger(metrics.total) || Number.isInteger(metrics.passed))) {
        errors.push(`${prefix}.metrics does not support a failed row status`);
      }
    }
    const row = {
      id,
      label,
      category,
      status,
      public_summary: publicSummary,
      interpretation,
      public: isPublic,
      outcome_relevant: outcomeRelevant,
      metrics
    };
    const evidence = validateEvidence(raw.evidence, row, context, errors, `${prefix}.evidence`);
    if (isPublic && !['not_run', 'unavailable'].includes(status) && evidence.length === 0) {
      errors.push(`${prefix}.evidence is required for a public ${status} result`);
    }
    normalizedRows.push({ ...row, evidence });
  }

  const derivedOutcome = deriveOutcome(normalizedRows);
  const requestedOutcome = String(task.outcome || '').trim();
  if (!OUTCOMES.has(requestedOutcome)) errors.push('task.outcome is invalid');
  if (OUTCOMES.has(requestedOutcome) && requestedOutcome !== derivedOutcome) {
    errors.push(`task.outcome ${requestedOutcome} conflicts with evidence-derived outcome ${derivedOutcome}`);
  }

  const generatedAt = input.generated_at && Number.isFinite(Date.parse(input.generated_at))
    ? String(input.generated_at)
    : new Date().toISOString();
  const snapshot = validateSnapshot(input.snapshot, facts, errors, { captureSnapshot, requireSnapshotCurrent });
  const valueWithoutHash = {
    schema_version: SCHEMA_VERSION,
    report_id: reportId,
    task: { title, outcome: derivedOutcome, summary },
    results: normalizedRows,
    snapshot,
    generated_at: generatedAt
  };
  const contentHash = canonicalHash(valueWithoutHash);
  if (input.content_sha256 && input.content_sha256 !== contentHash) {
    errors.push('task results content_sha256 does not match');
  }
  const value = { ...valueWithoutHash, content_sha256: contentHash };
  return { valid: errors.length === 0, errors: [...new Set(errors)], value, hash: contentHash };
}

function inspectTaskResults(context, facts, input) {
  const validation = validateTaskResults(input, {
    context,
    reportId: input?.report_id,
    facts,
    requireSnapshotCurrent: true
  });
  if (validation.valid) {
    return { status: 'current', reason: null, errors: [], value: validation.value };
  }
  const errors = validation.errors || [];
  const snapshotStale = errors.some((error) => error.includes('repository snapshot is stale'));
  const evidenceStale = errors.some((error) =>
    error.includes('sha256 does not match') || error.includes('evidence file is unavailable or unsafe'));
  return {
    status: snapshotStale || evidenceStale ? 'stale' : 'invalid',
    reason: snapshotStale
      ? 'repository_snapshot_changed'
      : evidenceStale
        ? 'evidence_changed_or_unavailable'
        : 'task_results_invalid',
    errors,
    value: validation.value
  };
}

function taskResultsTemplate(reportId) {
  return {
    schema_version: SCHEMA_VERSION,
    report_id: reportId,
    task: {
      title: 'Concise engineering task title',
      outcome: 'not_verified',
      summary: 'One factual English sentence describing the evidence-backed engineering outcome.'
    },
    results: [
      {
        id: 'build',
        label: 'Production build',
        category: 'build',
        status: 'unavailable',
        public_summary: 'No build result has been attached yet.',
        interpretation: 'Attach a content-addressed report before claiming a build result.',
        public: true,
        outcome_relevant: true,
        metrics: null,
        evidence: []
      }
    ],
    snapshot: null,
    generated_at: null,
    content_sha256: null
  };
}

function fact(value, kind, source, schemaPath, collectedAt, confidence = 'high', warning = null) {
  return { value, kind, source, schema_path: schemaPath, collected_at: collectedAt, confidence, warning };
}

function metricText(metrics) {
  if (!metrics || typeof metrics !== 'object') return '';
  const parts = [];
  if (Number.isInteger(metrics.passed) && Number.isInteger(metrics.total)) {
    parts.push(`${metrics.passed}/${metrics.total} passed`);
  } else if (Number.isInteger(metrics.total)) {
    parts.push(`${metrics.total} checked`);
  }
  if (Number.isInteger(metrics.failed) && metrics.failed > 0) parts.push(`${metrics.failed} failed`);
  if (Number.isInteger(metrics.warnings) && metrics.warnings > 0) {
    parts.push(`${metrics.warnings} ${metrics.warnings === 1 ? 'warning' : 'warnings'}`);
  }
  if (Number.isFinite(metrics.value)) parts.push(`${metrics.value}${metrics.unit ? ` ${metrics.unit}` : ''}`);
  return parts.join(', ');
}

function mergeTaskResultsFacts(facts, taskResults, source = 'reports/field-reports/task-results.json') {
  if (!taskResults) return facts;
  const collectedAt = new Date().toISOString();
  const rows = (taskResults.results || []).map((row) => {
    const metric = metricText(row.metrics);
    const evidenceCount = Array.isArray(row.evidence) ? row.evidence.length : 0;
    return {
      id: row.id,
      label: row.label,
      category: row.category,
      status: row.status,
      public_summary: `${row.public_summary}${metric ? ` (${metric})` : ''}`,
      interpretation: row.outcome_relevant === false
        ? `${row.interpretation} This informational row is not included in the overall task outcome.`
        : row.interpretation,
      public: row.public,
      outcome_relevant: row.outcome_relevant !== false,
      evidence: {
        label: evidenceCount
          ? `${evidenceCount} content-addressed evidence ${evidenceCount === 1 ? 'item' : 'items'}`
          : 'No evidence attached'
      }
    };
  });
  const counts = Object.fromEntries([...STATUSES].map((status) => [
    status,
    rows.filter((row) => row.status === status).length
  ]));
  const values = {
    ...(facts.values || {}),
    task_result_title: fact(taskResults.task.title, 'observed', source, '$.task.title', collectedAt),
    task_result_outcome: fact(taskResults.task.outcome, 'derived', source, '$.task.outcome', collectedAt),
    task_result_summary: fact(taskResults.task.summary, 'observed', source, '$.task.summary', collectedAt),
    task_verification_results: fact(rows, 'observed', source, '$.results', collectedAt),
    task_verification_results_total: fact(rows.length, 'derived', source, '$.results.length', collectedAt),
    task_verification_results_passed: fact(counts.pass, 'derived', source, '$.results[status=pass]', collectedAt),
    task_verification_results_warnings: fact(counts.warning, 'derived', source, '$.results[status=warning]', collectedAt),
    task_verification_results_failed: fact(counts.fail, 'derived', source, '$.results[status=fail]', collectedAt),
    task_verification_results_not_run: fact(counts.not_run, 'derived', source, '$.results[status=not_run]', collectedAt),
    task_results_snapshot: fact(taskResults.snapshot, 'observed', source, '$.snapshot', collectedAt),
    task_results_hash: fact(taskResults.content_sha256 || canonicalHash(taskResults), 'derived', source, '$.content_sha256', collectedAt)
  };
  const all = Object.values(values);
  return {
    ...facts,
    values,
    facts_observed: all.filter((item) => item.kind === 'observed').length,
    facts_derived: all.filter((item) => item.kind === 'derived').length,
    facts_unavailable: all.filter((item) => item.kind === 'unavailable').length,
    facts_with_warnings: all.filter((item) => Boolean(item.warning)).length
  };
}

module.exports = {
  SCHEMA_VERSION,
  canonicalHash,
  deriveOutcome,
  inferAutomatedStatus,
  inspectTaskResults,
  mergeTaskResultsFacts,
  metricText,
  snapshotFromFacts,
  taskResultsTemplate,
  validateTaskResults
};
