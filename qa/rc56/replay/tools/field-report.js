#!/usr/bin/env node
'use strict';

const childProcess = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const readline = require('readline/promises');
const { parseCliArgs, resolveKnowledgeContext } = require('./lib/path-context');
const {
  readJson,
  writeFileAtomic,
  writeJsonAtomic
} = require('./lib/json-store');
const {
  commitJsonTransaction,
  recoverTransactions
} = require('./lib/json-transaction');
const state = require('./lib/field-report/state');
const { collect } = require('./lib/field-report/collector');
const {
  CONTRACT_VERSION,
  SCHEMA_VERSION,
  canonicalHash,
  identityKey,
  missingQuestions,
  normalizeLanguageTag,
  translationRequired,
  unwrap,
  validateAnswers,
  validateContract,
  validateTranslatorIdentity,
  validateTranslationPayload
} = require('./lib/field-report/contract');
const { render } = require('./lib/field-report/renderer');
const { scanPublication } = require('./lib/field-report/redactor');
const publisher = require('./lib/field-report/publisher');

function fail(message, exitCode = 2, code = 'field_report_error') {
  const error = new Error(message);
  error.exitCode = exitCode;
  error.code = code;
  throw error;
}

const FIELD_REPORT_FLAGS = new Set([
  'help', 'anonymize', 'answers', 'confirm-preview', 'discussion-category',
  'discussion-repo', 'dry-run', 'json', 'language', 'new', 'no-color',
  'project-knowledge-root', 'public-language', 'quiet', 'reason', 'report-id',
  'resume', 'routing-task-id', 'state-root', 'system-root', 'target-root',
  'tester-actor', 'verify-remote', 'yes', 'mode', 'team-root', 'workspace-id',
  'agent-id'
]);
function validateCliFlags(argv) {
  for (const arg of argv) {
    if (!arg.startsWith('--')) continue;
    const name = arg.slice(2).split('=', 1)[0];
    if (!FIELD_REPORT_FLAGS.has(name)) fail(`Unknown flag: --${name}`, 2, 'field_report_unknown_flag');
  }
}
function helpResult() {
  return {
    schema_version: SCHEMA_VERSION,
    status: 'ok',
    usage: 'field-report <start|questions|ingest|render|approve|publish|status|cancel|copy|open> [options]',
    side_effects: 'none'
  };
}

function sha256(value) {
  return crypto.createHash('sha256').update(String(value || '')).digest('hex');
}

function locate(context, flags, createWhenMissing) {
  if (flags.reportId) return state.load(context, flags.reportId);
  const found = state.latest(context, true);
  if (found && !flags.new) return found;
  if (!createWhenMissing) {
    fail('A report id is required, and no unfinished Field Report exists.');
  }
  return state.create(context, flags);
}

function wrapAnswers(answers, kind = 'tester', source = 'tester_answer') {
  return Object.fromEntries(Object.entries(answers || {}).map(([id, raw]) => {
    const wrapped = raw && typeof raw === 'object' &&
      Object.prototype.hasOwnProperty.call(raw, 'value');
    return [id, {
      ...(wrapped ? raw : {}),
      value: wrapped ? raw.value : raw,
      kind,
      source
    }];
  }));
}

function answerTemplate(manifest, questions) {
  return {
    schema_version: SCHEMA_VERSION,
    contract_version: CONTRACT_VERSION,
    report_id: manifest.report_id,
    instructions: [
      'Answer only from actual observations.',
      'Do not infer accuracy from doctor score or response speed from flow duration.',
      'Positive response-speed-percent means faster; negative means slower.',
      'Optional fields may be omitted.'
    ],
    answers: Object.fromEntries(questions.map((question) => [question.id, null]))
  };
}

function initialise(context, manifest) {
  const reportPaths = state.paths(context, manifest.report_id);
  const facts = collect(context, { routingTaskId: manifest.routing_task_id });
  const questions = missingQuestions({});
  writeJsonAtomic(reportPaths.facts, facts);
  writeJsonAtomic(reportPaths.provenance, {
    schema_version: 'knowledge-field-report-provenance.v2',
    contract_version: CONTRACT_VERSION,
    collected_at: facts.collected_at,
    facts_source: 'facts.json',
    fact_kinds: ['observed', 'derived', 'unavailable'],
    answer_kinds: ['tester', 'agent_assisted'],
    ordinary_workflow_telemetry: false
  });
  writeJsonAtomic(reportPaths.questions, {
    schema_version: SCHEMA_VERSION,
    report_id: manifest.report_id,
    questions
  });
  writeJsonAtomic(reportPaths.answers_template, answerTemplate(manifest, questions));
  state.transition(manifest, 'needs_user_input');
  manifest.warnings = facts.warnings;
  state.save(context, manifest);
}

function nextAction(manifest, questions, reportPaths) {
  const prefix = 'node .knowledge/tools/field-report.js';
  const report = `--report-id=${manifest.report_id}`;
  if (manifest.status === 'cancelled' || manifest.status === 'published') return null;
  if (questions.length) {
    return `${prefix} ingest ${report} --answers=${reportPaths.answers_template}`;
  }
  if (manifest.translation?.status === 'translation_required') {
    return manifest.language === 'auto'
      ? `${prefix} translation-export ${report} --language=<source-bcp47> --json`
      : `${prefix} translation-export ${report} --json`;
  }
  if (manifest.translation?.status === 'translation_ready') {
    return `${prefix} translation-approve ${report} --yes`;
  }
  if (manifest.status === 'redaction_required') {
    return `${prefix} ingest ${report} --answers=<corrected-answers.json>`;
  }
  if (manifest.status === 'draft_ready') {
    return `${prefix} approve ${report} --yes --tester-actor=` +
      `${manifest.tester_actor || '<github-login>'}`;
  }
  if (manifest.status === 'approved') {
    return `${prefix} publish ${report} --dry-run --yes --tester-actor=<github-login>`;
  }
  if (manifest.status === 'preview_ready') {
    return `${prefix} publish ${report} --yes --confirm-preview=${manifest.preview?.preview_hash}`;
  }
  if (manifest.status === 'publish_failed') {
    return `${prefix} publish ${report} --dry-run --yes --tester-actor=${manifest.tester_actor || '<github-login>'}`;
  }
  if (manifest.status === 'publishing' ||
      manifest.status === 'reconciliation_required') {
    return `${prefix} publish ${report} --yes ` +
      `--confirm-preview=${manifest.preview?.preview_hash}`;
  }
  return `${prefix} render ${report}`;
}

function questionResult(context, manifest) {
  const reportPaths = state.paths(context, manifest.report_id);
  const answers = readJson(reportPaths.answers_original, {});
  const questions = missingQuestions(answers);
  const facts = readJson(reportPaths.facts, {
    facts_observed: 0,
    facts_derived: 0,
    facts_unavailable: 0,
    facts_with_warnings: 0,
    warnings: []
  });
  writeJsonAtomic(reportPaths.questions, {
    schema_version: SCHEMA_VERSION,
    report_id: manifest.report_id,
    questions
  });
  writeJsonAtomic(reportPaths.answers_template, answerTemplate(manifest, questions));
  return {
    schema_version: SCHEMA_VERSION,
    contract_version: CONTRACT_VERSION,
    status: questions.length ? 'needs_user_input' : manifest.status,
    report_id: manifest.report_id,
    facts_observed: facts.facts_observed,
    facts_derived: facts.facts_derived,
    facts_unavailable: facts.facts_unavailable,
    facts_with_warnings: facts.facts_with_warnings,
    collector_warnings: facts.warnings,
    missing_required_fields: questions.length,
    questions,
    answer_template_path: reportPaths.answers_template,
    next_command: nextAction(manifest, questions, reportPaths)
  };
}

function readJsonInput(file) {
  try {
    return JSON.parse(fs.readFileSync(path.resolve(file), 'utf8').replace(/^\uFEFF/, ''));
  } catch {
    fail('Unable to read answers JSON.', 2, 'answers_unavailable');
  }
}

function assertReportMutable(manifest, action) {
  if (['publishing', 'reconciliation_required'].includes(manifest.status)) {
    fail(
      `Cannot ${action} while the remote publication outcome requires reconciliation.`,
      2,
      'publication_reconciliation_required'
    );
  }
}

function resetTranslation(manifest, reportPaths, originalAnswers) {
  const needed = translationRequired(manifest.language, manifest.public_language);
  const oldReview = readJson(reportPaths.translation_review, null);
  if (oldReview) {
    writeJsonAtomic(reportPaths.translation_review, {
      ...oldReview,
      status: 'invalidated',
      invalidated_at: new Date().toISOString(),
      reason: 'original_answers_changed'
    });
  }
  manifest.translation = {
    status: needed ? 'translation_required' : 'translation_not_required',
    source_language: manifest.language,
    target_language: manifest.public_language,
    original_hash: canonicalHash(originalAnswers),
    translated_hash: null,
    translator: null,
    reviewer: null,
    approved_by_tester: false,
    approved_at: null
  };
}

function ingestValues(context, manifest, input) {
  if (['published', 'cancelled'].includes(manifest.status)) {
    fail(`Cannot edit a ${manifest.status} Field Report.`);
  }
  assertReportMutable(manifest, 'edit');
  const reportPaths = state.paths(context, manifest.report_id);
  const current = readJson(reportPaths.answers_original, {});
  const supplied = input?.answers || input;
  const merged = { ...current, ...supplied };
  const validation = validateAnswers(merged, { allowMissing: true, partial: true });
  if (!validation.valid) fail(validation.errors.join('; '), 2, 'answers_invalid');
  const wrapped = wrapAnswers(validation.answers);
  writeJsonAtomic(reportPaths.answers_original, wrapped);
  resetTranslation(manifest, reportPaths, wrapped);
  state.invalidateApproval(manifest);
  const questions = missingQuestions(wrapped);
  const nextStatus = questions.length
    ? 'needs_user_input'
    : manifest.translation.status === 'translation_required'
      ? 'translation_required'
      : 'needs_user_input';
  state.transition(manifest, nextStatus);
  manifest.answer_migrations = validation.migrations;
  state.save(context, manifest);
  return questionResult(context, manifest);
}

function ingest(context, flags, manifest, injected) {
  const input = injected.answers || (flags.answers ? readJsonInput(flags.answers) : null);
  if (!input) fail('--answers=<path> is required for ingest.');
  return ingestValues(context, manifest, input);
}

function requireCompleteOriginal(reportPaths) {
  const original = readJson(reportPaths.answers_original, {});
  const validation = validateAnswers(original);
  if (!validation.valid) fail(validation.errors.join('; '), 2, 'answers_incomplete');
  return { original, validation };
}

function translationExport(context, flags, manifest) {
  const reportPaths = state.paths(context, manifest.report_id);
  const { original, validation } = requireCompleteOriginal(reportPaths);
  const exportBody = JSON.stringify(validation.answers);
  const exportPrivacy = scanPublication({ body: exportBody }, manifest.anonymized);
  if (
    exportPrivacy.report.status === 'blocked' ||
    exportPrivacy.body !== exportBody
  ) {
    fail(
      'Translation export contains data that must be removed or redacted before it leaves the workspace.',
      2,
      'translation_export_privacy_blocked'
    );
  }
  if (manifest.language === 'auto') {
    if (!flags.language || String(flags.language).toLowerCase() === 'auto') {
      fail(
        'Automatic source language is unresolved; provide --language=<source-bcp47>.',
        2,
        'language_unresolved'
      );
    }
    manifest.language = normalizeLanguageTag(flags.language);
    manifest.translation.source_language = manifest.language;
    manifest.translation.status = translationRequired(
      manifest.language,
      manifest.public_language
    )
      ? 'translation_required'
      : 'translation_not_required';
  } else if (flags.language &&
      normalizeLanguageTag(flags.language).toLowerCase() !== manifest.language.toLowerCase()) {
    fail('The source language is immutable after it has been resolved.', 2, 'language_immutable');
  }
  if (!translationRequired(manifest.language, manifest.public_language)) {
    manifest.translation = {
      status: 'translation_not_required',
      source_language: manifest.language,
      target_language: manifest.public_language,
      original_hash: canonicalHash(validation.answers),
      translated_hash: null,
      translator: null,
      reviewer: null,
      approved_by_tester: false,
      approved_at: null
    };
    state.invalidateApproval(manifest);
    if (manifest.status === 'translation_required') {
      state.transition(manifest, 'needs_user_input');
    }
    state.save(context, manifest);
    return {
      schema_version: SCHEMA_VERSION,
      status: 'translation_not_required',
      report_id: manifest.report_id,
      source_language: manifest.language,
      target_language: manifest.public_language,
      next_command:
        `node .knowledge/tools/field-report.js render --report-id=${manifest.report_id}`
    };
  }
  const originalHash = canonicalHash(validation.answers);
  manifest.translation.status = 'translation_required';
  manifest.translation.original_hash = originalHash;
  manifest.translation.translated_hash = null;
  manifest.translation.approved_by_tester = false;
  state.invalidateApproval(manifest);
  state.transition(manifest, 'translation_required');
  writeJsonAtomic(reportPaths.translation_provenance, {
    schema_version: 'knowledge-field-report-translation.v1',
    report_id: manifest.report_id,
    status: 'translation_required',
    source_language: manifest.language,
    target_language: manifest.public_language,
    original_hash: originalHash,
    exported_at: new Date().toISOString(),
    rules: [
      'Translate text fields only.',
      'Do not add facts.',
      'Do not soften negative answers.',
      'Preserve uncertainty.',
      'Return every original field and do not add fields.'
    ]
  });
  state.save(context, manifest);
  return {
    schema_version: SCHEMA_VERSION,
    translation_contract: 'knowledge-field-report-translation.v1',
    status: 'translation_required',
    report_id: manifest.report_id,
    source_language: manifest.language,
    target_language: manifest.public_language,
    original_hash: originalHash,
    original_answers: original,
    expected_response: {
      original_hash: originalHash,
      translator: {
        provider: '<provider-or-runtime>',
        model: '<model-name>',
        actor: '<agent-or-person>'
      },
      attestations: {
        adds_no_facts: true,
        negative_answers_not_softened: true,
        uncertainty_preserved: true
      },
      translated_answers: Object.fromEntries(
        Object.keys(validation.answers).map((id) => [id, null])
      )
    },
    next_command:
      `node .knowledge/tools/field-report.js translation-ingest ` +
      `--report-id=${manifest.report_id} --answers=<translation.json>`
  };
}

function translationIngest(context, flags, manifest, injected) {
  if (!translationRequired(manifest.language, manifest.public_language)) {
    fail('Translation is not required for this report.');
  }
  if (!['translation_required', 'translation_ready'].includes(manifest.status)) {
    fail('Export the current original answers before ingesting a translation.');
  }
  const input = injected.translation || (flags.answers ? readJsonInput(flags.answers) : null);
  if (!input) fail('--answers=<translation.json> is required.');
  const reportPaths = state.paths(context, manifest.report_id);
  const { original, validation: originalValidation } = requireCompleteOriginal(reportPaths);
  const result = validateTranslationPayload(original, input);
  if (!result.valid) fail(result.errors.join('; '), 2, 'translation_invalid');
  const expectedOriginalHash = canonicalHash(originalValidation.answers);
  if (!input.original_hash || input.original_hash !== expectedOriginalHash ||
      result.original_hash !== expectedOriginalHash) {
    fail(
      'Translation original_hash does not match the immutable original answers.',
      2,
      'translation_stale'
    );
  }
  const wrapped = wrapAnswers(result.translated_answers, 'agent_assisted', 'translation');
  writeJsonAtomic(reportPaths.answers_translated, wrapped);
  writeJsonAtomic(reportPaths.translation_provenance, {
    schema_version: 'knowledge-field-report-translation.v1',
    report_id: manifest.report_id,
    status: 'translation_ready',
    source_language: manifest.language,
    target_language: manifest.public_language,
    original_hash: expectedOriginalHash,
    translated_hash: canonicalHash(wrapped),
    translated_at: new Date().toISOString(),
    translator: result.translator,
    attestations: input.attestations
  });
  writeJsonAtomic(reportPaths.translation_review, {
    schema_version: 'knowledge-field-report-translation-review.v1',
    report_id: manifest.report_id,
    status: 'translation_ready',
    original_hash: expectedOriginalHash,
    translated_hash: canonicalHash(wrapped),
    translator: result.translator,
    approved_by_tester: false,
    approved_at: null,
    reviewer: null
  });
  state.invalidateApproval(manifest);
  manifest.translation = {
    status: 'translation_ready',
    source_language: manifest.language,
    target_language: manifest.public_language,
    original_hash: expectedOriginalHash,
    translated_hash: canonicalHash(wrapped),
    translator: result.translator,
    reviewer: null,
    approved_by_tester: false,
    approved_at: null
  };
  state.transition(manifest, 'translation_ready');
  state.save(context, manifest);
  return {
    schema_version: SCHEMA_VERSION,
    status: 'translation_ready',
    report_id: manifest.report_id,
    translated_answers_path: reportPaths.answers_translated,
    review_path: reportPaths.translation_review,
    next_command:
      `node .knowledge/tools/field-report.js translation-approve ` +
      `--report-id=${manifest.report_id} --yes --tester-actor=<github-login>`
  };
}

function translationApprove(context, flags, manifest, injected = {}) {
  if (!flags.yes) fail('Translation approval requires explicit --yes confirmation.');
  const alreadyApproved = manifest.translation?.status === 'translation_approved';
  if (!alreadyApproved && manifest.translation?.status !== 'translation_ready') {
    fail('A translation must be ready before tester approval.');
  }
  const reportPaths = state.paths(context, manifest.report_id);
  const original = readJson(reportPaths.answers_original, null);
  const translated = readJson(reportPaths.answers_translated, null);
  const provenance = readJson(reportPaths.translation_provenance, null);
  const review = readJson(reportPaths.translation_review, null);
  if (!original || !translated || !provenance || !review) {
    fail('Translation files are incomplete.');
  }
  const translatorResult = validateTranslatorIdentity(provenance.translator);
  if (!translatorResult.valid) {
    fail(translatorResult.errors.join('; '), 2, 'translation_identity_invalid');
  }
  const translatedValidation = validateTranslationPayload(original, {
    original_hash: provenance.original_hash,
    translator: provenance.translator,
    attestations: provenance.attestations,
    translated_answers: translated
  });
  if (!translatedValidation.valid) {
    fail(translatedValidation.errors.join('; '), 2, 'translation_invalid');
  }
  const reviewStateValid = alreadyApproved
    ? review.status === 'translation_approved' &&
      review.approved_by_tester === true &&
      typeof review.approved_at === 'string' &&
      review.approved_at === manifest.translation.approved_at &&
      canonicalHash(review.reviewer) === canonicalHash(manifest.translation.reviewer)
    : review.status === 'translation_ready' &&
      review.approved_by_tester === false &&
      review.approved_at === null &&
      review.reviewer === null;
  if (
    provenance.schema_version !== 'knowledge-field-report-translation.v1' ||
    provenance.report_id !== manifest.report_id ||
    provenance.status !== 'translation_ready' ||
    provenance.source_language !== manifest.language ||
    provenance.target_language !== manifest.public_language ||
    review.schema_version !== 'knowledge-field-report-translation-review.v1' ||
    review.report_id !== manifest.report_id ||
    !reviewStateValid
  ) {
    fail('Translation review artifacts are not in the expected pre-approval state.', 2, 'translation_stale');
  }
  let reviewer;
  try {
    reviewer = state.validateTesterActor(flags.testerActor || manifest.tester_actor);
  } catch {
    fail(
      'Translation approval requires an explicit valid --tester-actor.',
      2,
      'translation_reviewer_required'
    );
  }
  if (identityKey(reviewer) === identityKey(translatorResult.translator.actor)) {
    fail(
      'The translation reviewer must be independent from the translator.',
      2,
      'translation_reviewer_not_independent'
    );
  }
  const originalValidation = validateAnswers(original);
  if (!originalValidation.valid) fail(originalValidation.errors.join('; '));
  const originalHash = canonicalHash(originalValidation.answers);
  const translatedHash = canonicalHash(translated);
  if (originalHash !== review.original_hash || translatedHash !== review.translated_hash ||
      originalHash !== provenance.original_hash ||
      translatedHash !== provenance.translated_hash ||
      canonicalHash(review.translator) !== canonicalHash(translatorResult.translator)) {
    fail('Translation changed after review preparation.', 2, 'translation_stale');
  }
  if (alreadyApproved) {
    if (reviewer !== manifest.translation.reviewer ||
        manifest.tester_actor !== reviewer ||
        manifest.translation.approved_by_tester !== true) {
      fail('Translation approval actor binding is inconsistent.', 2, 'translation_stale');
    }
    return {
      schema_version: SCHEMA_VERSION,
      status: 'translation_approved',
      report_id: manifest.report_id,
      idempotent: true,
      next_command:
        `node .knowledge/tools/field-report.js render --report-id=${manifest.report_id}`
    };
  }
  const approvedAt = new Date().toISOString();
  const approvedReview = {
    ...review,
    status: 'translation_approved',
    approved_by_tester: true,
    approved_at: approvedAt,
    reviewer
  };
  manifest.tester_actor = reviewer;
  manifest.translation = {
    ...manifest.translation,
    status: 'translation_approved',
    original_hash: originalHash,
    translated_hash: translatedHash,
    translator: translatorResult.translator,
    reviewer,
    approved_by_tester: true,
    approved_at: approvedAt
  };
  state.invalidateApproval(manifest);
  state.transition(manifest, 'translation_ready');
  manifest.updated_at = approvedAt;
  const transactionId = `field-report-translation-approval-${manifest.report_id}-` +
    `${canonicalHash({
      reviewer,
      approved_at: approvedAt,
      original_hash: originalHash,
      translated_hash: translatedHash
    }).slice(0, 24)}`;
  commitJsonTransaction({
    stateRoot: context.stateRoot,
    transactionId,
    allowedContainmentRoots: [context.stateRoot],
    faultAt: injected.translationApprovalFaultAt || null,
    metadata: {
      type: 'field_report_translation_approval',
      report_id: manifest.report_id,
      actor: reviewer
    },
    writes: [
      {
        path: reportPaths.translation_review,
        value: approvedReview,
        containmentRoot: context.stateRoot
      },
      {
        path: reportPaths.manifest,
        value: manifest,
        containmentRoot: context.stateRoot
      }
    ]
  });
  return {
    schema_version: SCHEMA_VERSION,
    status: 'translation_approved',
    report_id: manifest.report_id,
    next_command:
      `node .knowledge/tools/field-report.js render --report-id=${manifest.report_id}`
  };
}

function answersForRender(manifest, reportPaths) {
  const { original } = requireCompleteOriginal(reportPaths);
  if (!translationRequired(manifest.language, manifest.public_language)) return original;
  if (manifest.translation?.status !== 'translation_approved' ||
      !manifest.translation?.approved_by_tester) {
    fail('Public-language rendering requires tester-approved translation.');
  }
  const translated = readJson(reportPaths.answers_translated, null);
  const provenance = readJson(reportPaths.translation_provenance, null);
  const review = readJson(reportPaths.translation_review, null);
  if (!translated || !provenance || review?.status !== 'translation_approved') {
    fail('Approved translation artifacts are incomplete.');
  }
  const translatorResult = validateTranslatorIdentity(provenance.translator);
  const attestations = provenance.attestations || {};
  const translationValidation = validateTranslationPayload(original, {
    original_hash: provenance.original_hash,
    translator: provenance.translator,
    attestations,
    translated_answers: translated
  });
  if (!translatorResult.valid ||
      !translationValidation.valid ||
      canonicalHash(review.translator) !== canonicalHash(translatorResult.translator) ||
      typeof review.reviewer !== 'string' || !review.reviewer.trim() ||
      identityKey(review.reviewer) === identityKey(translatorResult.translator.actor) ||
      review.reviewer !== manifest.translation?.reviewer ||
      review.schema_version !== 'knowledge-field-report-translation-review.v1' ||
      review.report_id !== manifest.report_id ||
      review.status !== 'translation_approved' ||
      review.approved_by_tester !== true ||
      typeof review.approved_at !== 'string' ||
      Number.isNaN(Date.parse(review.approved_at)) ||
      review.approved_at !== manifest.translation?.approved_at ||
      provenance.schema_version !== 'knowledge-field-report-translation.v1' ||
      provenance.report_id !== manifest.report_id ||
      provenance.status !== 'translation_ready' ||
      provenance.source_language !== manifest.language ||
      provenance.target_language !== manifest.public_language ||
      attestations.adds_no_facts !== true ||
      attestations.negative_answers_not_softened !== true ||
      attestations.uncertainty_preserved !== true) {
    fail('Approved translation identities are invalid.', 2, 'translation_identity_invalid');
  }
  if (canonicalHash(original) !== review.original_hash ||
      canonicalHash(translated) !== review.translated_hash ||
      review.original_hash !== provenance.original_hash ||
      review.translated_hash !== provenance.translated_hash) {
    fail('Approved translation hashes no longer match.', 2, 'translation_stale');
  }
  const validation = validateAnswers(translated);
  if (!validation.valid) fail(validation.errors.join('; '), 2, 'translation_invalid');
  return translated;
}

function discussionUrl(manifest) {
  const target = state.validatePublicationTarget(manifest.target);
  const [owner, name] = target.repository.split('/');
  const url = new URL(
    `https://github.com/${encodeURIComponent(owner)}/${encodeURIComponent(name)}/discussions/new`
  );
  url.searchParams.set('category', target.category_slug);
  return url.toString();
}

function publicationMaterial(manifest, title, sourceBody) {
  const target = state.validatePublicationTarget(manifest.target);
  const identity = {
    schema_version: 'knowledge-field-report-idempotency.v2',
    report_id: manifest.report_id,
    target_repository: target.repository,
    discussion_category: target.category_slug,
    title_sha256: sha256(title),
    source_body_sha256: sha256(sourceBody)
  };
  const idempotencyKey = canonicalHash(identity);
  const idempotencyMarker =
    `<!-- knowledge-field-report-idempotency:${idempotencyKey} -->`;
  const body = `${sourceBody}${sourceBody.endsWith('\n') ? '' : '\n'}\n` +
    `${idempotencyMarker}\n`;
  return {
    identity,
    source_body: sourceBody,
    source_body_sha256: identity.source_body_sha256,
    body,
    body_sha256: sha256(body),
    idempotency_key: idempotencyKey,
    idempotency_marker: idempotencyMarker
  };
}

function renderApprovalHash(title, material) {
  return canonicalHash({
    title,
    source_body_sha256: material.source_body_sha256,
    body_sha256: material.body_sha256,
    idempotency_key: material.idempotency_key
  });
}

function routingAttestation(manifest, facts, reportPaths) {
  if (!manifest.routing_task_id) return null;
  const values = facts?.values || {};
  const value = (name) => values[name]?.value ?? null;
  return {
    routing_task_id: manifest.routing_task_id,
    routing_scope: value('routing_scope'),
    routing_task_bound_to_report: value('routing_task_bound_to_report'),
    routing_scope_comparable: value('routing_scope_comparable'),
    routing_claim_eligible: value('routing_claim_eligible'),
    routing_claim_ineligible_reason: value('routing_claim_ineligible_reason'),
    routing_pointer_consistent: value('routing_pointer_consistent'),
    routing_live_inputs_match: value('routing_live_inputs_match'),
    routing_current_status: value('routing_current_status'),
    routing_snapshot_hash: value('routing_snapshot_hash'),
    routing_baseline_hash: value('routing_baseline_hash'),
    routing_metrics_comparison_hash: value('routing_metrics_comparison_hash'),
    routing_live_input_digest: value('routing_live_input_digest'),
    routing_task_readiness: value('routing_task_readiness'),
    routing_continuation_required: value('routing_continuation_required'),
    routing_continuation_digest: value('routing_continuation_digest'),
    semantic_facts_sha256: reportPaths ? state.semanticFactsHash(reportPaths.facts) : null
  };
}

function invalidateRoutingApproval(context, manifest) {
  if (!manifest.approval?.approved_by_tester) return;
  if (['publishing', 'reconciliation_required'].includes(manifest.status)) return;
  state.invalidateApproval(manifest);
  state.save(context, manifest);
}

function refreshLiveRouting(context, manifest, reportPaths, action) {
  if (!manifest.routing_task_id) {
    return {
      facts: readJson(reportPaths.facts, { values: {}, warnings: [], mode: context.mode }),
      attestation: null
    };
  }
  const facts = collect(context, { routingTaskId: manifest.routing_task_id });
  writeJsonAtomic(reportPaths.facts, facts);
  const attestation = routingAttestation(manifest, facts, reportPaths);
  const reasons = [];
  if (attestation.routing_task_bound_to_report !== true) reasons.push('routing_task_not_bound');
  if (attestation.routing_pointer_consistent !== true) reasons.push('routing_pointer_inconsistent');
  if (attestation.routing_live_inputs_match !== true) reasons.push('live_relevant_input_drift');
  if (reasons.length) {
    invalidateRoutingApproval(context, manifest);
    fail(
      `Field Report ${action} is blocked by live routing state: ${reasons.join(', ')}.`,
      2,
      'routing_live_state_stale'
    );
  }
  if (manifest.approval?.routing_attestation &&
      !exactJson(manifest.approval.routing_attestation, attestation)) {
    invalidateRoutingApproval(context, manifest);
    fail(
      `Field Report ${action} is blocked because the approved routing attestation is stale.`,
      2,
      'routing_live_state_stale'
    );
  }
  return { facts, attestation };
}

function renderedPayload(manifest, title, material, approval = {}) {
  return {
    schema_version: 'knowledge-field-report-publication.v3',
    report_id: manifest.report_id,
    repository: manifest.target.repository,
    category_slug: manifest.target.category_slug,
    title,
    body_path: 'discussion-body.md',
    source_body_sha256: material.source_body_sha256,
    body_sha256: material.body_sha256,
    idempotency_key: material.idempotency_key,
    idempotency_marker: material.idempotency_marker,
    approved: Boolean(approval.approved),
    approved_at: approval.approved_at || null,
    approved_by: approval.approved_by || null,
    routing_attestation: approval.routing_attestation || null
  };
}

function renderedHelpers(manifest, material) {
  return {
    schema_version: 'knowledge-field-report-publication-helpers.v2',
    report_id: manifest.report_id,
    target_repository: manifest.target.repository,
    discussion_category: manifest.target.category_slug,
    discussion_url: discussionUrl(manifest),
    title_path: 'discussion-title.txt',
    body_path: 'discussion-body.md',
    idempotency_key: material.idempotency_key,
    idempotency_marker: material.idempotency_marker,
    copy_command:
      `node .knowledge/tools/field-report.js copy --report-id=${manifest.report_id} ` +
      '--confirm-preview=<preview-hash>',
    open_command:
      `node .knowledge/tools/field-report.js open --report-id=${manifest.report_id} --yes`
  };
}

function renderArtifacts(manifest, facts, answers) {
  const output = render(manifest, facts, answers);
  const material = publicationMaterial(manifest, output.title, output.public);
  return {
    output,
    material,
    payload: renderedPayload(manifest, output.title, material),
    helpers: renderedHelpers(manifest, material)
  };
}

function exactJson(value, expected) {
  return canonicalHash(value) === canonicalHash(expected);
}

function assertRenderedArtifacts(reportPaths, expected) {
  const checks = [
    ['answers.public.json', exactJson(readJson(reportPaths.answers_public, null), expected.output.answers)],
    ['redaction-report.json', exactJson(readJson(reportPaths.redaction_report, null), expected.output.redaction)],
    ['draft.md', fs.existsSync(reportPaths.draft) &&
      fs.readFileSync(reportPaths.draft, 'utf8') === expected.output.draft],
    ['public.md', fs.existsSync(reportPaths.public) &&
      fs.readFileSync(reportPaths.public, 'utf8') === expected.output.public],
    ['discussion-title.txt', fs.existsSync(reportPaths.discussion_title) &&
      fs.readFileSync(reportPaths.discussion_title, 'utf8') === `${expected.output.title}\n`],
    ['discussion-body.md', fs.existsSync(reportPaths.discussion_body) &&
      fs.readFileSync(reportPaths.discussion_body, 'utf8') === expected.material.body],
    ['discussion-payload.json',
      exactJson(readJson(reportPaths.discussion_payload, null), expected.payload)],
    ['publication-helpers.json',
      exactJson(readJson(reportPaths.publication_helpers, null), expected.helpers)]
  ];
  const drift = checks.filter(([, matches]) => !matches).map(([name]) => name);
  if (drift.length) {
    fail(
      `Rendered Field Report artifacts drifted before approval: ${drift.join(', ')}.`,
      2,
      'approval_render_drift'
    );
  }
}

function renderReport(context, flags, manifest) {
  if (['published', 'cancelled'].includes(manifest.status)) {
    fail(`Cannot render a ${manifest.status} Field Report.`);
  }
  assertReportMutable(manifest, 'render');
  const reportPaths = state.paths(context, manifest.report_id);
  const answers = answersForRender(manifest, reportPaths);
  const { facts } = refreshLiveRouting(context, manifest, reportPaths, 'render');
  state.transition(manifest, 'draft_ready');
  const expected = renderArtifacts(manifest, facts, answers);
  const { output, material } = expected;
  writeJsonAtomic(reportPaths.answers_public, output.answers);
  writeJsonAtomic(reportPaths.redaction_report, output.redaction);
  writeFileAtomic(reportPaths.draft, output.draft);
  writeFileAtomic(reportPaths.public, output.public);
  writeFileAtomic(reportPaths.discussion_title, `${output.title}\n`);
  writeFileAtomic(reportPaths.discussion_body, material.body);
  writeJsonAtomic(reportPaths.discussion_payload, expected.payload);
  writeJsonAtomic(reportPaths.publication_helpers, expected.helpers);
  state.invalidateApproval(manifest);
  if (output.redaction.status === 'blocked') state.transition(manifest, 'redaction_required');
  state.save(context, manifest);
  return {
    schema_version: SCHEMA_VERSION,
    status: manifest.status,
    report_id: manifest.report_id,
    draft_path: reportPaths.draft,
    public_path: reportPaths.public,
    title_path: reportPaths.discussion_title,
    body_path: reportPaths.discussion_body,
    redaction: output.redaction,
    speed_metric: output.speed_metric,
    title: output.title,
    next_command: nextAction(manifest, [], reportPaths)
  };
}

function approve(context, flags, manifest, injected = {}) {
  const reportPaths = state.paths(context, manifest.report_id);
  const liveRouting = refreshLiveRouting(context, manifest, reportPaths, 'approval');
  const redaction = readJson(reportPaths.redaction_report, { status: 'blocked' });
  if (manifest.status === 'approved' && manifest.approval?.approved_by_tester === true) {
    const actor = state.validateTesterActor(
      flags.testerActor || manifest.approval.approved_by
    );
    if (actor !== manifest.approval.approved_by) {
      fail(
        'Approval actor does not match the tester who approved this report.',
        2,
        'approval_actor_mismatch'
      );
    }
    if (manifest.approval.content_hash !== state.hashFiles(reportPaths)) {
      fail('Approved Field Report artifacts changed after approval.', 2, 'approval_content_mismatch');
    }
    const inputs = publicationInputs(manifest, reportPaths);
    return {
      schema_version: SCHEMA_VERSION,
      status: 'approved',
      report_id: manifest.report_id,
      content_hash: manifest.approval.content_hash,
      approved_by: actor,
      approved_at: manifest.approval.approved_at,
      title: inputs.title,
      body_sha256: inputs.material.body_sha256,
      draft_path: reportPaths.draft,
      public_path: reportPaths.public,
      redaction_status: redaction.status,
      publication_target: manifest.target,
      idempotent: true,
      next_command: nextAction(manifest, [], reportPaths)
    };
  }
  if (manifest.status !== 'draft_ready' || redaction.status === 'blocked') {
    fail('Approval is blocked until a complete, reviewed, non-blocked draft is rendered.');
  }
  if (translationRequired(manifest.language, manifest.public_language) &&
      manifest.translation?.status !== 'translation_approved') {
    fail('Approval is blocked until the translation is approved by the tester.');
  }
  if (!flags.yes) fail('Approval requires explicit --yes confirmation.');
  const actor = state.validateTesterActor(flags.testerActor || manifest.tester_actor);
  const answers = answersForRender(manifest, reportPaths);
  const { facts, attestation } = liveRouting;
  const expected = renderArtifacts(manifest, facts, answers);
  assertRenderedArtifacts(reportPaths, expected);
  if (expected.output.redaction.status === 'blocked') {
    fail('Approval is blocked by the current render-time redaction result.', 2, 'redaction_blocked');
  }
  const approvedAt = new Date().toISOString();
  const approvalIdentity = {
    schema_version: 'knowledge-field-report-approval-identity.v3',
    title_sha256: sha256(expected.output.title),
    body_sha256: expected.material.body_sha256,
    source_body_sha256: expected.material.source_body_sha256,
    semantic_facts_sha256: state.semanticFactsHash(reportPaths.facts),
    routing_attestation: attestation,
    translation_sha256: canonicalHash(manifest.translation || {}),
    redaction_sha256: canonicalHash(readJson(reportPaths.redaction_report, {}))
  };
  const payload = renderedPayload(manifest, expected.output.title, expected.material, {
    approved: true,
    approved_at: approvedAt,
    approved_by: actor,
    routing_attestation: attestation
  });
  const payloadBody = `${JSON.stringify(payload, null, 2)}\n`;
  manifest.tester_actor = actor;
  manifest.approval = {
    approved_by_tester: true,
    approved_by: actor,
    approved_at: approvedAt,
    render_sha256: renderApprovalHash(expected.output.title, expected.material),
    routing_attestation: attestation,
    semantic_facts_sha256: approvalIdentity.semantic_facts_sha256,
    approval_identity: approvalIdentity,
    content_hash: state.hashFiles(reportPaths, {
      'discussion-payload.json': payloadBody
    })
  };
  state.transition(manifest, 'approved');
  manifest.updated_at = approvedAt;
  const transactionId = `field-report-approval-${manifest.report_id}-` +
    `${canonicalHash({
      approved_by: actor,
      approved_at: approvedAt,
      content_hash: manifest.approval.content_hash
    }).slice(0, 24)}`;
  commitJsonTransaction({
    stateRoot: context.stateRoot,
    transactionId,
    allowedContainmentRoots: [context.stateRoot],
    faultAt: injected.approvalFaultAt || null,
    metadata: {
      type: 'field_report_approval',
      report_id: manifest.report_id,
      actor
    },
    writes: [
      {
        path: reportPaths.discussion_payload,
        value: payload,
        containmentRoot: context.stateRoot
      },
      {
        path: reportPaths.manifest,
        value: manifest,
        containmentRoot: context.stateRoot
      }
    ]
  });
  return {
    schema_version: SCHEMA_VERSION,
    status: 'approved',
    report_id: manifest.report_id,
    content_hash: manifest.approval.content_hash,
    approved_by: actor,
    approved_at: approvedAt,
    title: expected.output.title,
    body_sha256: expected.material.body_sha256,
    draft_path: reportPaths.draft,
    public_path: reportPaths.public,
    redaction_status: redaction.status,
    publication_target: manifest.target,
    next_command: nextAction(manifest, [], reportPaths)
  };
}

function publicationInputs(manifest, reportPaths) {
  const title = fs.readFileSync(reportPaths.discussion_title, 'utf8').trim();
  const body = fs.readFileSync(reportPaths.discussion_body, 'utf8');
  const sourceBody = fs.readFileSync(reportPaths.public, 'utf8');
  const answers = readJson(reportPaths.answers_public, {});
  const helpers = readJson(reportPaths.publication_helpers, {});
  const payload = readJson(reportPaths.discussion_payload, {});
  const material = publicationMaterial(manifest, title, sourceBody);
  const approvedRenderSha256 = renderApprovalHash(title, material);
  if (manifest.approval?.render_sha256 !== approvedRenderSha256) {
    fail(
      'Approved render identity no longer matches the publication artifacts.',
      2,
      'approval_render_mismatch'
    );
  }
  if (body !== material.body) {
    fail(
      'Discussion body or its deterministic idempotency marker no longer matches public.md.',
      2,
      'publication_artifact_mismatch'
    );
  }
  const expectedPayload = renderedPayload(manifest, title, material, {
    approved: true,
    approved_at: manifest.approval?.approved_at,
    approved_by: manifest.approval?.approved_by,
    routing_attestation: manifest.approval?.routing_attestation || null
  });
  const expectedHelpers = renderedHelpers(manifest, material);
  if (!exactJson(payload, expectedPayload) || !exactJson(helpers, expectedHelpers)) {
    fail(
      'Publication payload/helpers no longer match the approved report identity and target.',
      2,
      'publication_artifact_mismatch'
    );
  }
  const answerEnvelope = JSON.stringify(answers);
  const scan = scanPublication({
    title,
    body,
    supporting_material: `${unwrap(answers['supporting-material']) || ''}\n${answerEnvelope}`,
    generated_links: []
  }, manifest.anonymized);
  const trustedLinkScan = scanPublication({
    generated_links: helpers.discussion_url ? [helpers.discussion_url] : []
  }, false);
  if (scan.report.status === 'blocked' || trustedLinkScan.report.status === 'blocked') {
    fail(
      'Publication is blocked by the final title/body/link redaction scan.',
      2,
      'redaction_blocked'
    );
  }
  if (
    scan.title !== title ||
    scan.body !== body ||
    scan.supporting_material !==
      `${unwrap(answers['supporting-material']) || ''}\n${answerEnvelope}` ||
    trustedLinkScan.generated_links.join('\n') !== String(helpers.discussion_url || '')
  ) {
    fail(
      'Final redaction changed publication content. Render and approve the sanitized content again.',
      2,
      'redaction_changed_content'
    );
  }
  return {
    title,
    body,
    sourceBody,
    answers,
    helpers,
    payload,
    material,
    approvedRenderSha256,
    scan
  };
}

function ensurePublishable(context, manifest, reportPaths) {
  if (!manifest.approval?.approved_by_tester) fail('Publication requires tester approval.');
  if (manifest.approval.content_hash !== state.hashFiles(reportPaths)) {
    if (['publishing', 'reconciliation_required'].includes(manifest.status)) {
      fail(
        'Publication evidence changed while the remote outcome is unresolved.',
        2,
        'publication_reconciliation_conflict'
      );
    }
    state.invalidateApproval(manifest);
    state.save(context, manifest);
    fail('Publication content changed after approval; approval was invalidated.');
  }
  const answers = readJson(reportPaths.answers_public, {});
  if (unwrap(answers['github-publication-permission']) !== 'github_publication_allowed') {
    fail('Tester selected local draft only; GitHub publication is blocked.');
  }
  const redaction = readJson(reportPaths.redaction_report, { status: 'blocked' });
  if (redaction.status === 'blocked') {
    fail('Publication is blocked by unresolved redaction findings.');
  }
}

function authenticateForPreview(manifest, flags, adapter) {
  let approvedActor;
  try {
    approvedActor = state.validateTesterActor(manifest.approval?.approved_by);
  } catch {
    fail(
      'Publication requires a valid actor bound to the tester approval.',
      2,
      'approval_actor_missing'
    );
  }
  if (manifest.tester_actor && manifest.tester_actor !== approvedActor) {
    fail(
      'Manifest tester actor does not match the actor bound to approval.',
      2,
      'approval_actor_mismatch'
    );
  }
  if (flags.testerActor) {
    const requestedActor = state.validateTesterActor(flags.testerActor);
    if (requestedActor !== approvedActor) {
      fail(
        `Requested tester actor ${requestedActor} does not match approved actor ${approvedActor}.`,
        2,
        'approval_actor_mismatch'
      );
    }
  }
  const payload = {
    repository: manifest.target.repository,
    category_slug: manifest.target.category_slug
  };
  if (flags.dryRun && !flags.verifyRemote) {
    return {
      actor: approvedActor,
      repository: payload.repository,
      category_slug: payload.category_slug,
      offline: true
    };
  }
  const authentication = publisher.authenticate(payload, { adapter });
  if (authentication.repository !== manifest.target.repository ||
      authentication.category_slug !== manifest.target.category_slug) {
    fail(
      'Authenticated publication target does not match the report target.',
      2,
      'target_mismatch'
    );
  }
  if (authentication.actor !== approvedActor) {
    fail(
      `Authenticated actor ${authentication.actor} does not match approved actor ${approvedActor}.`,
      2,
      'actor_mismatch'
    );
  }
  return authentication;
}

function publicationEnvelope(manifest, actor, inputs) {
  const identity = {
    schema_version: 'knowledge-field-report-publication-identity.v2',
    report_id: manifest.report_id,
    target_repository: manifest.target.repository,
    discussion_category: manifest.target.category_slug,
    authenticated_actor: actor,
    approval_content_sha256: manifest.approval.content_hash,
    approval_render_sha256: manifest.approval.render_sha256,
    idempotency_key: inputs.material.idempotency_key,
    title_sha256: sha256(inputs.title),
    source_body_sha256: inputs.material.source_body_sha256,
    body_sha256: inputs.material.body_sha256
  };
  const idempotencyKey = inputs.material.idempotency_key;
  const idempotencyMarker = inputs.material.idempotency_marker;
  const body = inputs.body;
  const payload = {
    repository: manifest.target.repository,
    category_slug: manifest.target.category_slug,
    title: inputs.title,
    body,
    report_id: manifest.report_id,
    idempotency_key: idempotencyKey,
    idempotency_marker: idempotencyMarker
  };
  return {
    identity,
    idempotency_key: idempotencyKey,
    idempotency_marker: idempotencyMarker,
    payload,
    hashes: {
      approval_content_sha256: manifest.approval.content_hash,
      approval_render_sha256: manifest.approval.render_sha256,
      title_sha256: sha256(inputs.title),
      source_body_sha256: inputs.material.source_body_sha256,
      body_sha256: sha256(body),
      payload_sha256: canonicalHash(payload)
    }
  };
}

function publicationTuple(preview, envelope) {
  return {
    preview_hash: preview.preview_hash,
    idempotency_key: envelope.idempotency_key,
    approval_content_sha256: envelope.hashes.approval_content_sha256,
    approval_render_sha256: envelope.hashes.approval_render_sha256,
    title_sha256: envelope.hashes.title_sha256,
    source_body_sha256: envelope.hashes.source_body_sha256,
    body_sha256: envelope.hashes.body_sha256,
    payload_sha256: envelope.hashes.payload_sha256
  };
}

function validatePublicationJournal(journal, manifest, preview, envelope) {
  if (!journal || journal.schema_version !== 'knowledge-field-report-publication.v3') {
    fail('Publication reconciliation journal is missing or invalid.', 2, 'publish_reconcile');
  }
  const expected = publicationTuple(preview, envelope);
  for (const [key, value] of Object.entries(expected)) {
    if (journal[key] !== value) {
      fail(
        `Publication reconciliation journal hash mismatch: ${key}.`,
        2,
        'publication_reconciliation_conflict'
      );
    }
  }
  if (journal.report_id !== manifest.report_id ||
      journal.actor !== preview.authenticated_actor ||
      journal.target_repository !== manifest.target.repository ||
      journal.discussion_category !== manifest.target.category_slug) {
    fail(
      'Publication reconciliation journal actor or target mismatch.',
      2,
      'publication_reconciliation_conflict'
    );
  }
  return journal;
}

function normalizeRemotePublication(result, authentication, envelope, options = {}) {
  if (!result?.discussion_id || !result?.url || !result?.actor) {
    fail(
      'Publisher result is incomplete; the remote outcome requires reconciliation.',
      3,
      'publish_outcome_unknown'
    );
  }
  if (result.actor !== authentication.actor ||
      result.repository !== envelope.payload.repository ||
      result.category_slug !== envelope.payload.category_slug) {
    fail(
      'Publisher result actor or target does not match the approved publication.',
      3,
      'publication_reconciliation_conflict'
    );
  }
  if (options.fromLookup &&
      (result.title !== envelope.payload.title ||
       sha256(result.body) !== envelope.hashes.body_sha256)) {
    fail(
      'Reconciled Discussion content does not match the approved payload.',
      3,
      'publication_reconciliation_conflict'
    );
  }
  return {
    discussion_id: String(result.discussion_id),
    url: String(result.url),
    actor: result.actor,
    repository: envelope.payload.repository,
    category_slug: envelope.payload.category_slug
  };
}

function writePublishingJournal(context, reportPaths, manifest, preview, envelope, extras = {}) {
  const current = readJson(reportPaths.publication, null);
  const journal = {
    schema_version: 'knowledge-field-report-publication.v3',
    status: 'publishing',
    report_id: manifest.report_id,
    actor: preview.authenticated_actor,
    target_repository: manifest.target.repository,
    discussion_category: manifest.target.category_slug,
    ...publicationTuple(preview, envelope),
    attempt_started_at: current?.attempt_started_at || new Date().toISOString(),
    ...extras
  };
  writeJsonAtomic(reportPaths.publication, journal);
  state.transition(manifest, 'publishing');
  state.save(context, manifest);
  return journal;
}

function markReconciliationRequired(context, manifest, reportPaths, journal, error) {
  const next = {
    ...journal,
    status: 'reconciliation_required',
    outcome_unknown_at: new Date().toISOString(),
    error_code: String(error?.code || 'publish_outcome_unknown')
  };
  writeJsonAtomic(reportPaths.publication, next);
  state.transition(manifest, 'reconciliation_required');
  state.save(context, manifest);
  return next;
}

function finalizePublished(context, manifest, reportPaths, journal, remote, reconciled) {
  const publishedAt = journal.published_at || new Date().toISOString();
  const receipt = {
    ...journal,
    schema_version: 'knowledge-field-report-publication.v3',
    status: 'published',
    published_at: publishedAt,
    reconciled: Boolean(reconciled),
    remote
  };
  delete receipt.error_code;
  delete receipt.outcome_unknown_at;
  writeJsonAtomic(reportPaths.publication, receipt);
  state.transition(manifest, 'published');
  manifest.published_at = publishedAt;
  state.save(context, manifest);
  return {
    schema_version: SCHEMA_VERSION,
    status: 'published',
    report_id: manifest.report_id,
    reconciled: Boolean(reconciled),
    publication: remote
  };
}

function createPreview(context, flags, manifest, adapter) {
  if (!flags.yes) fail('Publication preview requires explicit --yes confirmation.');
  if (!['approved', 'preview_ready', 'publish_failed'].includes(manifest.status)) {
    fail('Publication preview requires an approved report.');
  }
  const reportPaths = state.paths(context, manifest.report_id);
  refreshLiveRouting(context, manifest, reportPaths, 'preview');
  ensurePublishable(context, manifest, reportPaths);
  const inputs = publicationInputs(manifest, reportPaths);
  const authentication = authenticateForPreview(manifest, flags, adapter);
  const envelope = publicationEnvelope(manifest, authentication.actor, inputs);
  const preview = {
    schema_version: 'knowledge-field-report-publication-preview.v2',
    authenticated_actor: authentication.actor,
    target_repository: manifest.target.repository,
    discussion_category: manifest.target.category_slug,
    title: inputs.title,
    title_sha256: envelope.hashes.title_sha256,
    source_body_sha256: envelope.hashes.source_body_sha256,
    body_hash: envelope.hashes.body_sha256,
    body_sha256: envelope.hashes.body_sha256,
    payload_sha256: envelope.hashes.payload_sha256,
    idempotency_key: envelope.idempotency_key,
    content_hash: manifest.approval.content_hash,
    approval_content_sha256: manifest.approval.content_hash,
    approval_render_sha256: manifest.approval.render_sha256,
    report_id: manifest.report_id,
    timestamp: new Date().toISOString(),
    redaction_status: inputs.scan.report.status
  };
  preview.preview_hash = state.previewHash(preview);
  writeJsonAtomic(reportPaths.publication_preview, preview);
  manifest.preview = {
    preview_hash: preview.preview_hash,
    created_at: preview.timestamp,
    actor: preview.authenticated_actor
  };
  state.transition(manifest, 'preview_ready');
  state.save(context, manifest);
  return {
    schema_version: SCHEMA_VERSION,
    status: 'preview_ready',
    dry_run: true,
    report_id: manifest.report_id,
    preview_hash: preview.preview_hash,
    preview_path: reportPaths.publication_preview,
    authenticated_actor: preview.authenticated_actor,
    target: manifest.target,
    next_command:
      `node .knowledge/tools/field-report.js publish --report-id=${manifest.report_id} ` +
      `--yes --confirm-preview=${preview.preview_hash}`
  };
}

function validatePreview(manifest, flags, reportPaths, inputs) {
  const preview = readJson(reportPaths.publication_preview, null);
  if (!preview) fail('Publication preview is missing.');
  if (preview.schema_version !== 'knowledge-field-report-publication-preview.v2') {
    fail('Publication preview uses an unsupported contract.', 2, 'preview_stale');
  }
  const expectedHash = state.previewHash(preview);
  if (!flags.confirmPreview || flags.confirmPreview !== expectedHash ||
      manifest.preview?.preview_hash !== expectedHash) {
    fail(
      'Final publication requires --confirm-preview=<exact-preview-hash>.',
      2,
      'preview_mismatch'
    );
  }
  const envelope = publicationEnvelope(manifest, preview.authenticated_actor, inputs);
  if (preview.report_id !== manifest.report_id ||
      preview.authenticated_actor !== manifest.approval.approved_by ||
      preview.target_repository !== manifest.target.repository ||
      preview.discussion_category !== manifest.target.category_slug ||
      preview.title !== inputs.title ||
      preview.title_sha256 !== envelope.hashes.title_sha256 ||
      preview.source_body_sha256 !== envelope.hashes.source_body_sha256 ||
      preview.body_sha256 !== envelope.hashes.body_sha256 ||
      preview.body_hash !== envelope.hashes.body_sha256 ||
      preview.payload_sha256 !== envelope.hashes.payload_sha256 ||
      preview.idempotency_key !== envelope.idempotency_key ||
      preview.content_hash !== manifest.approval.content_hash ||
      preview.approval_content_sha256 !== manifest.approval.content_hash ||
      preview.approval_render_sha256 !== manifest.approval.render_sha256) {
    fail(
      'Publication preview no longer matches actor/target/content.',
      2,
      'preview_stale'
    );
  }
  return { preview, envelope };
}

function ciEnvironmentDetected(environment = process.env) {
  const truthy = (value) => new Set(['1', 'true', 'yes', 'on']).has(
    String(value || '').trim().toLowerCase()
  );
  if (truthy(environment.CI)) return true;
  return [
    'GITHUB_ACTIONS',
    'GITLAB_CI',
    'CIRCLECI',
    'BUILDKITE',
    'TF_BUILD'
  ].some((key) => truthy(environment[key])) ||
    Boolean(String(environment.JENKINS_URL || '').trim()) ||
    Boolean(String(environment.BUILD_BUILDID || '').trim());
}

function finalPublish(context, flags, manifest, adapter) {
  if (manifest.status === 'published') {
    fail('This report was already published; duplicate publication is blocked.');
  }
  if (![
    'preview_ready',
    'publish_failed',
    'publishing',
    'reconciliation_required'
  ].includes(manifest.status)) {
    fail('Run publish --dry-run to create an actor-bound preview first.');
  }
  if (!flags.yes) fail('Final publication requires explicit --yes confirmation.');
  const testOnlyPublisher = publisher.adapterIsTestOnly(adapter);
  if (ciEnvironmentDetected() && !testOnlyPublisher) {
    fail(
      'Real publication is blocked in CI; only an explicit test-only injected publisher is allowed.'
    );
  }
  const reportPaths = state.paths(context, manifest.report_id);
  refreshLiveRouting(context, manifest, reportPaths, 'final publication');
  ensurePublishable(context, manifest, reportPaths);
  const inputs = publicationInputs(manifest, reportPaths);
  const validated = validatePreview(manifest, flags, reportPaths, inputs);
  const { preview, envelope } = validated;
  const existingJournal = readJson(reportPaths.publication, null);
  if (existingJournal?.status === 'published') {
    validatePublicationJournal(existingJournal, manifest, preview, envelope);
    const remote = normalizeRemotePublication(
      existingJournal.remote,
      { actor: preview.authenticated_actor },
      envelope
    );
    return finalizePublished(
      context,
      manifest,
      reportPaths,
      existingJournal,
      remote,
      true
    );
  }
  if (['publishing', 'reconciliation_required'].includes(manifest.status) &&
      !['publishing', 'reconciliation_required'].includes(existingJournal?.status)) {
    fail(
      'Publication state requires reconciliation but its durable journal is missing.',
      3,
      'publish_reconcile'
    );
  }
  const authentication = authenticateForPreview(
    manifest,
    flags,
    adapter
  );
  if (authentication.actor !== preview.authenticated_actor) {
    fail('Authenticated actor changed after preview.', 2, 'actor_mismatch');
  }
  let journal = existingJournal;
  if (['publishing', 'reconciliation_required'].includes(journal?.status)) {
    validatePublicationJournal(journal, manifest, preview, envelope);
    let found;
    try {
      found = publisher.lookup(envelope.payload, authentication, {
        adapter,
        idempotencyKey: envelope.idempotency_key,
        idempotencyMarker: envelope.idempotency_marker
      });
    } catch (error) {
      markReconciliationRequired(context, manifest, reportPaths, journal, error);
      fail(
        'Publication reconciliation did not complete; no new Discussion was created.',
        3,
        String(error.code || 'publish_reconcile')
      );
    }
    if (found) {
      let remote;
      try {
        remote = normalizeRemotePublication(found, authentication, envelope, {
          fromLookup: true
        });
      } catch (error) {
        markReconciliationRequired(context, manifest, reportPaths, journal, error);
        throw error;
      }
      return finalizePublished(context, manifest, reportPaths, journal, remote, true);
    }
    markReconciliationRequired(
      context,
      manifest,
      reportPaths,
      journal,
      { code: 'publication_reconciliation_pending' }
    );
    fail(
      'No exact remote match is visible yet. The prior outcome remains unknown; automatic creation is permanently blocked for this report.',
      3,
      'publication_reconciliation_pending'
    );
  } else {
    journal = writePublishingJournal(context, reportPaths, manifest, preview, envelope);
  }
  let result;
  try {
    result = publisher.publish(envelope.payload, authentication, {
      adapter,
      idempotencyKey: envelope.idempotency_key,
      idempotencyMarker: envelope.idempotency_marker
    });
  } catch (error) {
    markReconciliationRequired(context, manifest, reportPaths, journal, error);
    fail(
      'GitHub publication outcome is uncertain. Reconcile before any retry.',
      3,
      String(error.code || 'publish_outcome_unknown')
    );
  }
  let remote;
  try {
    remote = normalizeRemotePublication(result, authentication, envelope);
  } catch (error) {
    markReconciliationRequired(context, manifest, reportPaths, journal, error);
    throw error;
  }
  return finalizePublished(context, manifest, reportPaths, journal, remote, false);
}

function publishReport(context, flags, manifest, injected) {
  const adapter = injected.publisher || publisher.githubAdapter;
  return flags.dryRun
    ? createPreview(context, flags, manifest, adapter)
    : finalPublish(context, flags, manifest, adapter);
}

function cancel(context, flags, manifest) {
  if (manifest.status === 'published') fail('A published report cannot be cancelled.');
  assertReportMutable(manifest, 'cancel');
  if (manifest.status === 'cancelled') {
    return {
      schema_version: SCHEMA_VERSION,
      status: 'cancelled',
      report_id: manifest.report_id
    };
  }
  state.transition(manifest, 'cancelled');
  manifest.cancelled_at = new Date().toISOString();
  manifest.cancel_reason = flags.reason || null;
  state.save(context, manifest);
  return {
    schema_version: SCHEMA_VERSION,
    status: 'cancelled',
    report_id: manifest.report_id
  };
}

function statusResult(context, manifest) {
  const reportPaths = state.paths(context, manifest.report_id);
  const questions = missingQuestions(readJson(reportPaths.answers_original, {}));
  return {
    schema_version: SCHEMA_VERSION,
    contract_version: CONTRACT_VERSION,
    report_id: manifest.report_id,
    status: manifest.status,
    translation_status: manifest.translation?.status,
    approved: Boolean(manifest.approval?.approved_by_tester),
    preview_hash: manifest.preview?.preview_hash || null,
    target: manifest.target,
    tester_actor: manifest.tester_actor,
    missing_required_fields: questions.length,
    warnings: manifest.warnings,
    paths: Object.fromEntries(
      Object.entries(reportPaths)
        .filter(([key]) => key !== 'root')
        .map(([key, value]) => [key, value])
    ),
    next_command: nextAction(manifest, questions, reportPaths)
  };
}

function copyResult(context, flags, manifest) {
  const reportPaths = state.paths(context, manifest.report_id);
  if (!['preview_ready', 'reconciliation_required'].includes(manifest.status)) {
    fail('Manual copy requires an approved, actor-bound publication preview.');
  }
  ensurePublishable(context, manifest, reportPaths);
  const inputs = publicationInputs(manifest, reportPaths);
  const { preview, envelope } = validatePreview(manifest, flags, reportPaths, inputs);
  let journal = readJson(reportPaths.publication, null);
  if (journal) {
    if (journal.status === 'published') {
      fail('This report was already published; duplicate manual publication is blocked.');
    }
    validatePublicationJournal(journal, manifest, preview, envelope);
    if (journal.manual_copy_exposed_at) {
      fail(
        'Manual publication payload was already exposed; reconcile the existing attempt instead of copying again.',
        3,
        'manual_publication_already_exposed'
      );
    }
  } else {
    journal = writePublishingJournal(
      context,
      reportPaths,
      manifest,
      preview,
      envelope,
      { manual_copy_exposed_at: new Date().toISOString() }
    );
    journal = markReconciliationRequired(
      context,
      manifest,
      reportPaths,
      journal,
      { code: 'manual_publication_pending' }
    );
  }
  return {
    schema_version: SCHEMA_VERSION,
    status: 'copy_ready',
    report_id: manifest.report_id,
    title: inputs.title,
    body: inputs.body,
    idempotency_key: envelope.idempotency_key,
    reconciliation_required: true,
    title_path: reportPaths.discussion_title,
    body_path: reportPaths.discussion_body,
    next_command:
      `node .knowledge/tools/field-report.js publish --report-id=${manifest.report_id} ` +
      `--yes --confirm-preview=${preview.preview_hash}`
  };
}

function openResult(context, flags, manifest, injected) {
  if (!['preview_ready', 'reconciliation_required'].includes(manifest.status)) {
    fail('Opening the Discussion helper requires an actor-bound publication preview.');
  }
  const reportPaths = state.paths(context, manifest.report_id);
  ensurePublishable(context, manifest, reportPaths);
  publicationInputs(manifest, reportPaths);
  const url = discussionUrl(manifest);
  let opened = false;
  if (flags.yes) {
    if (typeof injected.openUrl === 'function') {
      injected.openUrl(url);
      opened = true;
    } else {
      const command = openCommand(url);
      const child = childProcess.spawn(command.file, command.args, {
        detached: true,
        stdio: 'ignore',
        windowsHide: true
      });
      child.unref();
      opened = true;
    }
  }
  return {
    schema_version: SCHEMA_VERSION,
    status: opened ? 'discussion_url_opened' : 'discussion_url_ready',
    report_id: manifest.report_id,
    discussion_url: url,
    opened
  };
}

function openCommand(url, platform = process.platform) {
  if (platform === 'win32') {
    return { file: 'rundll32.exe', args: ['url.dll,FileProtocolHandler', url] };
  }
  if (platform === 'darwin') return { file: 'open', args: [url] };
  return { file: 'xdg-open', args: [url] };
}

function run(argv = process.argv.slice(2), injected = {}) {
  validateCliFlags(argv);
  const { flags, positional } = parseCliArgs(argv);
  const command = positional[0] || 'start';
  if (flags.help || command === 'help' || command === '--help') return helpResult();
  const context = injected.context || resolveKnowledgeContext({
    ...flags,
    __skipCli: true
  });
  const contract = validateContract(context.systemRoot);
  if (!contract.valid) {
    fail(`Field Report schema contract is invalid: ${contract.errors.join('; ')}`);
  }
  const existing = !flags.reportId && !flags.new ? state.latest(context, true) : null;
  if (command === 'start' && existing && !flags.resume) {
    return {
      schema_version: SCHEMA_VERSION,
      status: 'resume_available',
      resume_available: true,
      report_id: existing.report_id,
      next_command:
        `node .knowledge/tools/field-report.js start --resume ` +
        `--report-id=${existing.report_id}`
    };
  }
  let manifest = locate(context, flags, ['start', 'questions'].includes(command));
  return state.lock(context, manifest.report_id, () => {
    recoverTransactions(context.stateRoot, {
      allowedContainmentRoots: [context.stateRoot, context.projectKnowledgeRoot],
      transactionIdPrefixes: [
        `field-report-approval-${manifest.report_id}-`,
        `field-report-translation-approval-${manifest.report_id}-`
      ]
    });
    manifest = state.load(context, manifest.report_id);
    if (['start', 'questions'].includes(command) && manifest.status === 'collecting') {
      initialise(context, manifest);
      manifest = state.load(context, manifest.report_id);
    }
    if (command === 'start' || command === 'questions') {
      return questionResult(context, manifest);
    }
    if (command === 'status') return statusResult(context, manifest);
    if (command === 'ingest') return ingest(context, flags, manifest, injected);
    if (command === 'translation-export' || command === 'translate') {
      return translationExport(context, flags, manifest);
    }
    if (command === 'translation-ingest') {
      return translationIngest(context, flags, manifest, injected);
    }
    if (command === 'translation-approve' || command === 'translation-review') {
      return translationApprove(context, flags, manifest, injected);
    }
    if (command === 'render') return renderReport(context, flags, manifest);
    if (command === 'approve') return approve(context, flags, manifest, injected);
    if (command === 'publish') return publishReport(context, flags, manifest, injected);
    if (command === 'cancel') return cancel(context, flags, manifest);
    if (command === 'copy') return copyResult(context, flags, manifest);
    if (command === 'open') return openResult(context, flags, manifest, injected);
    fail(`Unknown command: ${command}`);
  });
}

function coerceInteractiveAnswer(question, raw) {
  const text = String(raw || '').trim();
  if (question.options?.length) {
    const byNumber = Number(text);
    if (Number.isInteger(byNumber) && byNumber >= 1 && byNumber <= question.options.length) {
      return question.options[byNumber - 1].value;
    }
    const option = question.options.find((item) =>
      item.value === text || item.label.toLowerCase() === text.toLowerCase()
    );
    return option ? option.value : text;
  }
  if (question.type === 'number' || question.type === 'integer') return Number(text);
  return text;
}

async function interactiveInterview(initial, context) {
  let result = initial;
  const terminal = readline.createInterface({ input: process.stdin, output: process.stdout });
  try {
    while (result.questions?.length) {
      const answers = {};
      for (const question of result.questions) {
        process.stdout.write(`\n${question.prompt}\n`);
        if (question.options?.length) {
          question.options.forEach((option, index) => {
            process.stdout.write(`  ${index + 1}. ${option.label} [${option.value}]\n`);
          });
        }
        const raw = await terminal.question('> ');
        answers[question.id] = coerceInteractiveAnswer(question, raw);
      }
      result = run(
        ['ingest', `--report-id=${result.report_id}`],
        { context, answers }
      );
    }
    return result;
  } finally {
    terminal.close();
  }
}

function humanOutput(value) {
  const lines = [
    `Field Report ${value.report_id || ''}`.trim(),
    `Status: ${value.status}`
  ];
  if (Number.isFinite(value.missing_required_fields)) {
    lines.push(`Missing judgments: ${value.missing_required_fields}`);
  }
  if (value.translation_status) lines.push(`Translation: ${value.translation_status}`);
  if (value.public_path) lines.push(`Public draft: ${value.public_path}`);
  if (value.preview_hash) lines.push(`Preview hash: ${value.preview_hash}`);
  if (value.discussion_url) lines.push(`Discussion URL: ${value.discussion_url}`);
  if (value.next_command) lines.push(`Next: ${value.next_command}`);
  return `${lines.join('\n')}\n`;
}

async function main() {
  const argv = process.argv.slice(2);
  try {
    validateCliFlags(argv);
    const { flags, positional } = parseCliArgs(argv);
    if (flags.help || positional[0] === 'help' || positional[0] === '--help') {
      const value = helpResult();
      if (flags.json) process.stdout.write(`${JSON.stringify(value)}\n`);
      else process.stdout.write(`${value.usage}\n`);
      return;
    }
    const context = resolveKnowledgeContext({
      ...flags,
      __skipCli: true
    });
    let value = run(argv, { context });
    const command = positional[0] || 'start';
    if (!flags.json && !flags.quiet && process.stdin.isTTY && process.stdout.isTTY &&
        ['start', 'questions'].includes(command) && value.questions?.length) {
      value = await interactiveInterview(value, context);
    }
    if (flags.json) process.stdout.write(`${JSON.stringify(value)}\n`);
    else if (!flags.quiet) process.stdout.write(humanOutput(value));
  } catch (error) {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = error.exitCode ||
      (String(error.code || '').startsWith('publish') ? 3 : 1);
  }
}

if (require.main === module) main();

module.exports = {
  approve,
  createPreview,
  finalPublish,
  ingestValues,
  renderReport,
  run,
  translationApprove,
  translationExport,
  translationIngest,
  __test: {
    ciEnvironmentDetected,
    openCommand,
    publicationMaterial
  }
};
