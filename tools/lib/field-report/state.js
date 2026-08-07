'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const {
  ensureDir,
  readJson,
  writeJsonAtomic
} = require('../json-store');
const { withContainedLock } = require('../contained-lock-manager');
const { LOCKS } = require('../lock-policy');
const {
  CONTRACT_VERSION,
  SCHEMA_VERSION,
  STATES,
  canonicalHash,
  normalizeLanguageTag,
  normalizePublicLanguage,
  translationRequired
} = require('./contract');

const FILES = Object.freeze({
  manifest: 'manifest.json',
  facts: 'facts.json',
  questions: 'questions.json',
  answers_template: 'answers.template.json',
  answers_original: 'answers.original.json',
  answers_translated: 'answers.translated.json',
  answers_public: 'answers.public.json',
  translation_provenance: 'translation-provenance.json',
  translation_review: 'translation-review.json',
  provenance: 'provenance.json',
  draft: 'draft.md',
  public: 'public.md',
  discussion_title: 'discussion-title.txt',
  discussion_body: 'discussion-body.md',
  discussion_payload: 'discussion-payload.json',
  redaction_report: 'redaction-report.json',
  publication_preview: 'publication-preview.json',
  publication_helpers: 'publication-helpers.json',
  publication: 'publication.json'
});
const REPORT_ID_PATTERN = /^fr_[0-9]{8}_[a-f0-9]{8}$/;
const GITHUB_OWNER_PATTERN = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$/;
const GITHUB_REPOSITORY_PATTERN = /^[A-Za-z0-9_.-]{1,100}$/;
const DISCUSSION_CATEGORY_PATTERN = /^[a-z0-9](?:[a-z0-9-]{0,79})$/;
const TESTER_ACTOR_PATTERN = GITHUB_OWNER_PATTERN;
const FIELD_REPORT_LOCK_STALE_MS = 24 * 60 * 60 * 1000;

const LEGAL_TRANSITIONS = Object.freeze({
  collecting: ['needs_user_input', 'cancelled'],
  needs_user_input: ['translation_required', 'draft_ready', 'cancelled'],
  translation_required: ['translation_ready', 'needs_user_input', 'cancelled'],
  translation_ready: ['translation_required', 'draft_ready', 'needs_user_input', 'cancelled'],
  draft_ready: ['redaction_required', 'approved', 'needs_user_input', 'translation_required', 'cancelled'],
  redaction_required: ['draft_ready', 'needs_user_input', 'translation_required', 'cancelled'],
  approved: ['preview_ready', 'draft_ready', 'needs_user_input', 'cancelled'],
  preview_ready: [
    'publishing',
    'reconciliation_required',
    'published',
    'publish_failed',
    'draft_ready',
    'needs_user_input',
    'cancelled'
  ],
  publish_failed: [
    'preview_ready',
    'publishing',
    'reconciliation_required',
    'published',
    'draft_ready',
    'needs_user_input',
    'cancelled'
  ],
  publishing: ['published', 'publish_failed', 'reconciliation_required'],
  reconciliation_required: ['publishing', 'published', 'publish_failed'],
  published: [],
  cancelled: []
});

function reportRoot(context) {
  return path.join(context.stateRoot, 'reports', 'field-reports');
}

function validateReportId(reportId) {
  const value = String(reportId || '');
  if (!REPORT_ID_PATTERN.test(value)) {
    const error = new Error(`Invalid Field Report ID: ${JSON.stringify(reportId)}`);
    error.code = 'field_report_id_invalid';
    throw error;
  }
  return value;
}

function validatePublicationTarget(target = {}) {
  const repository = String(target.repository || '').trim();
  const categorySlug = String(target.category_slug || '').trim();
  const parts = repository.split('/');
  if (parts.length !== 2 ||
      !GITHUB_OWNER_PATTERN.test(parts[0]) ||
      !GITHUB_REPOSITORY_PATTERN.test(parts[1]) ||
      parts[1] === '.' ||
      parts[1] === '..') {
    const error = new Error('Field Report publication repository must be a safe GitHub owner/name.');
    error.code = 'field_report_target_invalid';
    throw error;
  }
  if (!DISCUSSION_CATEGORY_PATTERN.test(categorySlug)) {
    const error = new Error('Field Report Discussion category must be a lowercase GitHub slug.');
    error.code = 'field_report_target_invalid';
    throw error;
  }
  return { repository, category_slug: categorySlug };
}

function validateTesterActor(actor) {
  const value = String(actor || '').trim();
  if (!TESTER_ACTOR_PATTERN.test(value)) {
    const error = new Error('Field Report tester actor must be a valid GitHub login.');
    error.code = 'field_report_actor_invalid';
    throw error;
  }
  return value;
}

function validateRoutingTaskId(value) {
  if (value === undefined || value === null || value === '') return null;
  const taskId = String(value).trim();
  if (!/^[a-f0-9]{64}$/.test(taskId)) {
    const error = new Error('Field Report routing task id must be a canonical SHA-256 hash.');
    error.code = 'field_report_routing_task_invalid';
    throw error;
  }
  return taskId;
}

function paths(context, reportId) {
  reportId = validateReportId(reportId);
  const root = path.join(reportRoot(context), reportId);
  const result = { root };
  for (const [key, name] of Object.entries(FILES)) result[key] = path.join(root, name);
  return result;
}

function newId() {
  return `fr_${new Date().toISOString().slice(0, 10).replace(/-/g, '')}_` +
    `${crypto.randomBytes(4).toString('hex')}`;
}

function latest(context, incomplete = false) {
  const root = reportRoot(context);
  if (!fs.existsSync(root)) return null;
  return fs.readdirSync(root, { withFileTypes: true })
    .filter((entry) => entry.isDirectory() && REPORT_ID_PATTERN.test(entry.name))
    .map((entry) => readJson(paths(context, entry.name).manifest, null))
    .filter(Boolean)
    .filter((manifest) => manifest.repo_id === context.repoId)
    .filter((manifest) => !incomplete || !['published', 'cancelled'].includes(manifest.status))
    .sort((left, right) => String(right.updated_at).localeCompare(String(left.updated_at)))[0] || null;
}

function translationStatus(language, publicLanguage) {
  return translationRequired(language, publicLanguage)
    ? 'translation_required'
    : 'translation_not_required';
}

function create(context, flags = {}) {
  const reportId = newId();
  const reportPaths = paths(context, reportId);
  const now = new Date().toISOString();
  const publicLanguage = normalizePublicLanguage(flags.publicLanguage || 'en');
  const language = normalizeLanguageTag(
    flags.language === undefined || flags.language === null || flags.language === ''
      ? 'auto'
      : flags.language,
    { allowAuto: true }
  );
  const target = validatePublicationTarget({
    repository: flags.discussionRepo || 'pro2pilot/knowledge',
    category_slug: flags.discussionCategory || 'field-reports'
  });
  ensureDir(reportPaths.root);
  const manifest = {
    schema_version: SCHEMA_VERSION,
    contract_version: CONTRACT_VERSION,
    report_id: reportId,
    repo_id: context.repoId,
    status: 'collecting',
    created_at: now,
    updated_at: now,
    mode: context.mode,
    routing_task_id: validateRoutingTaskId(flags.routingTaskId),
    anonymized: Boolean(flags.anonymize),
    language,
    public_language: publicLanguage,
    tester_actor: flags.testerActor || null,
    translation: {
      status: translationStatus(language, publicLanguage),
      source_language: language,
      target_language: publicLanguage,
      original_hash: null,
      exported_answers_hash: null,
      translated_hash: null,
      translator: null,
      reviewer: null,
      approved_by_tester: false,
      approved_at: null
    },
    approval: {
      approved_by_tester: false,
      approved_at: null,
      content_hash: null
    },
    preview: {
      preview_hash: null,
      created_at: null,
      actor: null
    },
    target,
    warnings: []
  };
  writeJsonAtomic(reportPaths.manifest, manifest);
  return manifest;
}

function load(context, reportId) {
  reportId = validateReportId(reportId);
  const manifest = readJson(paths(context, reportId).manifest, null);
  if (!manifest) {
    const error = new Error(`Field Report not found: ${reportId}`);
    error.code = 'not_found';
    throw error;
  }
  if (manifest.report_id !== reportId) {
    const error = new Error(`Field Report manifest identity mismatch: ${reportId}`);
    error.code = 'field_report_id_mismatch';
    throw error;
  }
  validateRoutingTaskId(manifest.routing_task_id);
  const target = validatePublicationTarget(manifest.target);
  if (target.repository !== manifest.target.repository ||
      target.category_slug !== manifest.target.category_slug) {
    const error = new Error(`Field Report publication target is not canonical: ${reportId}`);
    error.code = 'field_report_target_invalid';
    throw error;
  }
  return manifest;
}

function save(context, manifest) {
  manifest.updated_at = new Date().toISOString();
  writeJsonAtomic(paths(context, manifest.report_id).manifest, manifest);
  return manifest;
}

function transition(manifest, nextStatus) {
  if (!STATES.includes(nextStatus)) {
    throw new Error(`Unknown Field Report state: ${nextStatus}`);
  }
  if (manifest.status === nextStatus) return manifest;
  const allowed = LEGAL_TRANSITIONS[manifest.status] || [];
  if (!allowed.includes(nextStatus)) {
    const error = new Error(`Illegal Field Report transition: ${manifest.status} -> ${nextStatus}`);
    error.code = 'invalid_transition';
    throw error;
  }
  manifest.status = nextStatus;
  return manifest;
}

function invalidatePreview(manifest) {
  manifest.preview = {
    preview_hash: null,
    created_at: null,
    actor: null
  };
  if (manifest.status === 'preview_ready' || manifest.status === 'publish_failed') {
    transition(manifest, 'draft_ready');
  }
}

function invalidateApproval(manifest) {
  manifest.approval = {
    approved_by_tester: false,
    approved_at: null,
    content_hash: null
  };
  invalidatePreview(manifest);
  if (manifest.status === 'approved') transition(manifest, 'draft_ready');
}

function hashFileSet(namedFiles, overrides = {}) {
  const hash = crypto.createHash('sha256');
  for (const [name, file] of namedFiles) {
    hash.update(name);
    hash.update('\0');
    const overridden = Object.prototype.hasOwnProperty.call(overrides, name);
    const body = overridden
      ? overrides[name]
      : fs.existsSync(file)
        ? fs.readFileSync(file)
        : Buffer.alloc(0);
    hash.update(Buffer.isBuffer(body) ? body : Buffer.from(String(body), 'utf8'));
    hash.update('\0');
  }
  return hash.digest('hex');
}

const VOLATILE_FACT_KEYS = new Set([
  'generated_at', 'created_at', 'updated_at', 'collected_at', 'timestamp',
  'duration', 'duration_ms', 'pid', 'log_path', 'temporary_path', 'temp_path',
  'observed_at', 'recorded_at', 'started_at', 'finished_at', 'published_at',
  'last_seen_at', 'first_seen_at', 'detected_at', 'resolved_at'
]);
function semanticFactsProjection(value, parentKey = '') {
  if (Array.isArray(value)) return value.map((item) => semanticFactsProjection(item, parentKey));
  if (!value || typeof value !== 'object') return value;
  const entries = Object.keys(value).sort().filter((key) => {
    if (VOLATILE_FACT_KEYS.has(key)) return false;
    if (parentKey === 'values' && /(?:^|_)(?:timestamp|duration(?:_ms)?|pid|log_path|temp(?:orary)?_path|[a-z]+_at)$/.test(key)) return false;
    return true;
  });
  return Object.fromEntries(entries.map((key) => [key, semanticFactsProjection(value[key], key)]));
}
function semanticFactsBody(file) {
  if (!fs.existsSync(file)) return Buffer.alloc(0);
  try {
    const parsed = JSON.parse(fs.readFileSync(file, 'utf8').replace(/^\uFEFF/, ''));
    return Buffer.from(JSON.stringify(semanticFactsProjection(parsed)), 'utf8');
  } catch {
    return fs.readFileSync(file);
  }
}
function semanticFactsHash(file) {
  return crypto.createHash('sha256').update(semanticFactsBody(file)).digest('hex');
}

function hashFiles(reportPaths, overrides = {}) {
  const semanticOverrides = Object.prototype.hasOwnProperty.call(overrides, 'facts.json')
    ? overrides
    : { ...overrides, 'facts.json': semanticFactsBody(reportPaths.facts) };
  return hashFileSet([
    ['facts.json', reportPaths.facts],
    ['provenance.json', reportPaths.provenance],
    ['answers.original.json', reportPaths.answers_original],
    ['answers.translated.json', reportPaths.answers_translated],
    ['answers.public.json', reportPaths.answers_public],
    ['translation-provenance.json', reportPaths.translation_provenance],
    ['translation-review.json', reportPaths.translation_review],
    ['draft.md', reportPaths.draft],
    ['public.md', reportPaths.public],
    ['discussion-title.txt', reportPaths.discussion_title],
    ['discussion-body.md', reportPaths.discussion_body],
    ['discussion-payload.json', reportPaths.discussion_payload],
    ['publication-helpers.json', reportPaths.publication_helpers],
    ['redaction-report.json', reportPaths.redaction_report],
  ], semanticOverrides);
}

function bodyHash(title, body) {
  return crypto.createHash('sha256')
    .update(String(title || ''))
    .update('\0')
    .update(String(body || ''))
    .digest('hex');
}

function previewHash(preview) {
  const copy = { ...preview };
  delete copy.preview_hash;
  return canonicalHash(copy);
}

function lock(context, reportId, fn) {
  reportId = validateReportId(reportId);
  return withContainedLock({
    context,
    rootKind: 'state',
    rootPath: context.stateRoot,
    lockName: 'field-report',
    purpose: LOCKS['field-report'].purpose,
    staleMs: FIELD_REPORT_LOCK_STALE_MS
  }, fn);
}

module.exports = {
  FILES,
  LEGAL_TRANSITIONS,
  bodyHash,
  create,
  hashFiles,
  semanticFactsHash,
  semanticFactsProjection,
  invalidateApproval,
  invalidatePreview,
  latest,
  load,
  lock,
  paths,
  previewHash,
  REPORT_ID_PATTERN,
  reportRoot,
  save,
  transition,
  translationStatus,
  validatePublicationTarget,
  validateReportId,
  validateTesterActor,
  validateRoutingTaskId
};
