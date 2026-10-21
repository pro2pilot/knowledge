'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const DEFAULT_SYSTEM_ROOT = path.resolve(__dirname, '..', '..', '..');
const SCHEMA_PATH = path.join('schemas', 'field-report.schema.json');
const ANSWER_ALIASES = Object.freeze({
  'accuracy-evidence': 'accuracy-example',
  'response-speed': 'response-speed-change',
  publication_permission: 'github-publication-permission',
  external_reuse_permission: 'publication-permission',
  baseline_duration_ms: 'baseline-duration-ms',
  knowledge_duration_ms: 'knowledge-duration-ms'
});
const STATES = Object.freeze([
  'collecting',
  'needs_user_input',
  'translation_required',
  'translation_ready',
  'draft_ready',
  'redaction_required',
  'approved',
  'preview_ready',
  'publish_failed',
  'publishing',
  'reconciliation_required',
  'published',
  'cancelled'
]);

function readSchema(systemRoot = DEFAULT_SYSTEM_ROOT) {
  const file = path.join(systemRoot, SCHEMA_PATH);
  const schema = JSON.parse(fs.readFileSync(file, 'utf8').replace(/^\uFEFF/, ''));
  if (!schema || !Array.isArray(schema.fields)) {
    throw new Error(`Invalid Field Report contract: ${file}`);
  }
  return schema;
}

const DEFAULT_SCHEMA = readSchema();
const SCHEMA_VERSION = DEFAULT_SCHEMA.schema_version;
const CONTRACT_VERSION = DEFAULT_SCHEMA.contract_version;
const PUBLIC_LANGUAGE = 'en';
const PUBLIC_IDS = Object.freeze(
  DEFAULT_SCHEMA.fields.filter((field) => field.github_form).map((field) => field.id)
);
const FIELDS = Object.freeze(
  DEFAULT_SCHEMA.fields.map((field) => Object.freeze({
    ...field,
    options: Array.isArray(field.allowed_values) ? [...field.allowed_values] : null,
    prompt: field.agent_prompt,
    reason: field.agent_prompt
      ? 'This judgment must come from the tester and is not inferred from repository metrics.'
      : null,
    follow_up: field.agent_prompt
      ? 'Ask at most one concrete follow-up when the answer is vague or lacks evidence.'
      : null
  }))
);

function unwrap(value) {
  return value && typeof value === 'object' && Object.prototype.hasOwnProperty.call(value, 'value')
    ? value.value
    : value;
}

function empty(value) {
  const unwrapped = unwrap(value);
  return unwrapped === undefined || unwrapped === null ||
    (typeof unwrapped === 'string' && unwrapped.trim() === '');
}

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) =>
      `${JSON.stringify(key)}:${canonicalJson(value[key])}`
    ).join(',')}}`;
  }
  return JSON.stringify(value);
}

function canonicalHash(value) {
  return crypto.createHash('sha256').update(canonicalJson(value)).digest('hex');
}

function normalizeLanguageTag(value, options = {}) {
  const raw = String(value ?? '').trim();
  if (!raw) {
    const error = new Error('Language must be a non-empty BCP47 tag.');
    error.code = 'language_invalid';
    throw error;
  }
  if (raw.toLowerCase() === 'auto') {
    if (options.allowAuto) return 'auto';
    const error = new Error('Automatic language detection is unresolved; provide an explicit BCP47 tag.');
    error.code = 'language_unresolved';
    throw error;
  }
  try {
    const [canonical] = Intl.getCanonicalLocales(raw);
    if (!canonical) throw new Error('empty locale');
    return canonical;
  } catch {
    const error = new Error(`Invalid BCP47 language tag: ${raw}`);
    error.code = 'language_invalid';
    throw error;
  }
}


function normalizePublicLanguage(value = PUBLIC_LANGUAGE) {
  const normalized = normalizeLanguageTag(value || PUBLIC_LANGUAGE);
  const primary = normalized.toLowerCase().split('-')[0];
  if (primary !== 'en') {
    const error = new Error('Field Report public output language is fixed to English.');
    error.code = 'public_language_must_be_english';
    throw error;
  }
  return PUBLIC_LANGUAGE;
}

function languageFamily(value, options = {}) {
  const normalized = normalizeLanguageTag(value, options);
  return normalized === 'auto' ? 'auto' : normalized.toLowerCase().split('-')[0];
}

function identityKey(value) {
  return String(value || '').trim().toLocaleLowerCase('en-US');
}

function validateTranslatorIdentity(input) {
  const errors = [];
  const translator = {};
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    return {
      valid: false,
      errors: ['translation requires an explicit translator identity'],
      translator: null
    };
  }
  for (const key of ['provider', 'model', 'actor']) {
    const value = input[key];
    if (typeof value !== 'string' || !value.trim()) {
      errors.push(`translator.${key} must be a non-empty string`);
      continue;
    }
    if (/[\u0000-\u001F\u007F]/.test(value) || value.trim().length > 200) {
      errors.push(`translator.${key} contains invalid characters or is too long`);
      continue;
    }
    translator[key] = value.trim();
  }
  return {
    valid: errors.length === 0,
    errors,
    translator: errors.length ? null : translator
  };
}

function migrateAnswers(input = {}) {
  const source = input && input.answers ? input.answers : input;
  if (!source || typeof source !== 'object' || Array.isArray(source)) {
    return { answers: null, errors: ['answers must be an object'], migrations: [] };
  }
  const answers = {};
  const errors = [];
  const migrations = [];
  for (const [rawId, value] of Object.entries(source)) {
    const id = ANSWER_ALIASES[rawId] || rawId;
    if (Object.prototype.hasOwnProperty.call(answers, id) &&
        canonicalJson(unwrap(answers[id])) !== canonicalJson(unwrap(value))) {
      errors.push(`conflicting values supplied for ${id}`);
      continue;
    }
    answers[id] = value;
    if (id !== rawId) migrations.push({ from: rawId, to: id });
  }
  return { answers, errors, migrations };
}

function normalizePrimitive(field, rawValue) {
  const value = unwrap(rawValue);
  if (empty(value)) return value;
  if (field.type === 'integer') {
    const number = Number(String(value).trim());
    return Number.isInteger(number) ? number : value;
  }
  if (field.type === 'number') {
    const number = Number(String(value).trim().replace(/%$/, ''));
    return Number.isFinite(number) ? number : value;
  }
  return typeof value === 'string' ? value.trim() : value;
}

function normalizeAnswers(input = {}) {
  const migrated = migrateAnswers(input);
  if (!migrated.answers) return migrated;
  const fields = new Map(FIELDS.map((field) => [field.id, field]));
  const answers = {};
  for (const [id, raw] of Object.entries(migrated.answers)) {
    const field = fields.get(id);
    const value = field ? normalizePrimitive(field, raw) : unwrap(raw);
    answers[id] = raw && typeof raw === 'object' &&
      Object.prototype.hasOwnProperty.call(raw, 'value')
      ? { ...raw, value }
      : value;
  }
  return { ...migrated, answers };
}

function missingQuestions(input = {}) {
  const normalized = normalizeAnswers(input);
  const answers = normalized.answers || {};
  const questions = FIELDS
    .filter((field) => field.required && field.agent_prompt && empty(answers[field.id]))
    .map((field) => ({
      id: field.id,
      type: field.type,
      required: true,
      prompt: field.agent_prompt,
      reason: field.reason,
      options: field.options
        ? field.options.map((value) => ({
          value,
          label: field.human_labels?.[value] || value
        }))
        : null,
      minimum: field.minimum ?? null,
      maximum: field.maximum ?? null,
      follow_up: field.follow_up
    }));
  if (unwrap(answers['response-speed-basis']) === 'measured') {
    for (const id of [
      'response-speed-sample-count',
      'baseline-duration-ms',
      'knowledge-duration-ms'
    ]) {
      if (!empty(answers[id]) || questions.some((question) => question.id === id)) continue;
      const field = FIELDS.find((item) => item.id === id);
      questions.push({
        id: field.id,
        type: field.type,
        required: true,
        prompt: field.agent_prompt,
        reason: 'Measured speed requires the raw comparable durations and sample count.',
        options: null,
        minimum: field.minimum ?? null,
        maximum: field.maximum ?? null,
        follow_up: field.follow_up
      });
    }
  }
  return questions;
}

function validateField(field, value, errors) {
  if (empty(value)) return;
  const primitive = unwrap(value);
  if (field.type === 'string' && typeof primitive !== 'string') {
    errors.push(`${field.id} must be a string`);
  }
  if (field.type === 'enum' && !field.allowed_values.includes(primitive)) {
    errors.push(`invalid value for ${field.id}`);
  }
  if (field.type === 'integer' && !Number.isInteger(primitive)) {
    errors.push(`${field.id} must be an integer`);
  }
  if (field.type === 'number' && !Number.isFinite(primitive)) {
    errors.push(`${field.id} must be a finite number`);
  }
  if (Number.isFinite(primitive) && field.minimum !== undefined && primitive < field.minimum) {
    errors.push(`${field.id} must be at least ${field.minimum}`);
  }
  if (Number.isFinite(primitive) && field.maximum !== undefined && primitive > field.maximum) {
    errors.push(`${field.id} must be at most ${field.maximum}`);
  }
}

function validateSpeed(answers, errors) {
  const change = unwrap(answers['response-speed-change']);
  const basis = unwrap(answers['response-speed-basis']);
  const percent = unwrap(answers['response-speed-percent']);
  const baseline = unwrap(answers['baseline-duration-ms']);
  const knowledge = unwrap(answers['knowledge-duration-ms']);
  const samples = unwrap(answers['response-speed-sample-count']);
  const hasPercent = !empty(percent);
  const hasBaseline = !empty(baseline);
  const hasKnowledge = !empty(knowledge);
  const slower = new Set(['much_slower', 'slightly_slower']);
  const faster = new Set(['much_faster', 'slightly_faster']);

  if (hasPercent && percent > 0 && slower.has(change)) {
    errors.push('positive response-speed-percent means faster and cannot describe a slower result');
  }
  if (hasPercent && percent < 0 && faster.has(change)) {
    errors.push('negative response-speed-percent means slower and cannot describe a faster result');
  }
  if (hasPercent && percent === 0 && (slower.has(change) || faster.has(change))) {
    errors.push('zero response-speed-percent cannot describe a faster or slower result');
  }
  if (hasPercent && change === 'no_clear_change' && Math.abs(percent) > 0.5) {
    errors.push('no_clear_change cannot include a material signed speed percent');
  }
  if (basis === 'measured') {
    if (!hasBaseline || !hasKnowledge) {
      errors.push(
        'measured speed requires raw durations: baseline-duration-ms and knowledge-duration-ms'
      );
    }
    if (empty(samples)) {
      errors.push('measured speed requires response-speed-sample-count');
    }
    if (hasBaseline && baseline <= 0) {
      errors.push('baseline-duration-ms must be greater than zero for measured speed');
    }
    if (hasBaseline && hasKnowledge && baseline > 0) {
      const derived = ((baseline - knowledge) / baseline) * 100;
      if (slower.has(change) && derived > 0.0001) {
        errors.push('measured durations indicate faster performance but the selected change is slower');
      }
      if (faster.has(change) && derived < -0.0001) {
        errors.push('measured durations indicate slower performance but the selected change is faster');
      }
      if ((slower.has(change) || faster.has(change)) && Math.abs(derived) <= 0.0001) {
        errors.push('equal measured durations cannot describe a faster or slower result');
      }
      if (change === 'no_clear_change' && Math.abs(derived) > 0.5) {
        errors.push('measured durations show a material speed change but no_clear_change was selected');
      }
      if (hasPercent && Math.abs(percent - derived) > 0.5) {
        errors.push('response-speed-percent does not match the measured durations');
      }
    }
  } else if (hasBaseline || hasKnowledge) {
    errors.push('raw durations may only be supplied when response-speed-basis is measured');
  }
  if (basis === 'not_enough_data' &&
      (hasPercent || hasBaseline || hasKnowledge || !empty(samples))) {
    errors.push('not_enough_data cannot include a percent, raw durations, or sample count');
  }
  if (change === 'not_enough_data' && basis !== 'not_enough_data') {
    errors.push('not_enough_data speed change requires not_enough_data basis');
  }
  if (basis === 'not_enough_data' && change !== 'not_enough_data') {
    errors.push('not_enough_data speed basis requires not_enough_data change');
  }
}

function validateAccuracy(answers, errors) {
  const change = unwrap(answers['accuracy-change']);
  const basis = unwrap(answers['accuracy-basis']);
  const samples = unwrap(answers['accuracy-sample-count']);
  if (basis === 'not_enough_data' && change !== 'not_enough_evidence') {
    errors.push('not_enough_data accuracy basis requires not_enough_evidence accuracy change');
  }
  if (change === 'not_enough_evidence' && basis !== 'not_enough_data') {
    errors.push('not_enough_evidence accuracy change requires not_enough_data basis');
  }
  if (basis === 'not_enough_data' && !empty(samples)) {
    errors.push('not_enough_data accuracy basis cannot include a sample count');
  }
  if (['measured', 'objective_test_result', 'comparable_tasks'].includes(basis) &&
      empty(samples)) {
    errors.push(`${basis} accuracy basis requires accuracy-sample-count`);
  }
}

function validateAnswers(input, options = {}) {
  const normalized = normalizeAnswers(input);
  if (!normalized.answers) {
    return {
      valid: false,
      errors: normalized.errors,
      answers: null,
      migrations: normalized.migrations
    };
  }
  const answers = normalized.answers;
  const errors = [...normalized.errors];
  const knownIds = new Set(FIELDS.map((field) => field.id));
  for (const id of Object.keys(answers)) {
    if (!knownIds.has(id)) errors.push(`unknown Field Report answer: ${id}`);
  }
  for (const field of FIELDS) {
    if (!options.allowMissing && field.required && empty(answers[field.id])) {
      errors.push(`missing required answer: ${field.id}`);
    }
    validateField(field, answers[field.id], errors);
  }
  if (!options.partial) {
    validateAccuracy(answers, errors);
    validateSpeed(answers, errors);
  }
  return {
    valid: errors.length === 0,
    errors,
    answers,
    migrations: normalized.migrations
  };
}

function fieldById(id, schema = DEFAULT_SCHEMA) {
  return schema.fields.find((field) => field.id === id) || null;
}

function humanValue(id, rawValue, schema = DEFAULT_SCHEMA) {
  const value = unwrap(rawValue);
  const field = fieldById(id, schema);
  if (!field || empty(value)) return value;
  return field.human_labels?.[value] || value;
}

function yamlString(value) {
  return JSON.stringify(String(value ?? ''));
}

function generateGithubForm(schema = DEFAULT_SCHEMA) {
  const lines = [
    `name: ${yamlString('Field report')}`,
    `description: ${yamlString('Share evidence from real .knowledge use.')}`,
    `title: ${yamlString(schema.github_form.title)}`,
    'labels:',
    `  - ${yamlString('field-report')}`,
    'body:',
    '  - type: markdown',
    '    attributes:',
    `      value: ${yamlString(schema.github_form.introduction)}`
  ];
  for (const field of schema.fields.filter((item) => item.github_form)) {
    const form = field.github_form;
    lines.push(
      `  - type: ${form.type}`,
      `    id: ${form.id}`,
      '    attributes:',
      `      label: ${yamlString(form.label)}`
    );
    if (form.description) lines.push(`      description: ${yamlString(form.description)}`);
    if (form.placeholder) lines.push(`      placeholder: ${yamlString(form.placeholder)}`);
    if (form.type === 'dropdown') {
      lines.push('      options:');
      for (const value of field.allowed_values || []) {
        lines.push(`        - ${yamlString(field.human_labels?.[value] || value)}`);
      }
    }
    lines.push('    validations:', `      required: ${form.required ? 'true' : 'false'}`);
  }
  return `${lines.join('\n')}\n`;
}

function findForm(systemRoot) {
  return [
    path.join(systemRoot, '.github', 'DISCUSSION_TEMPLATE', 'field-reports.yml'),
    path.resolve(systemRoot, '..', '.github', 'DISCUSSION_TEMPLATE', 'field-reports.yml')
  ].find((candidate) => fs.existsSync(candidate)) || null;
}

function unquoteYaml(value) {
  const text = String(value || '').trim();
  if (!text) return '';
  if (text.startsWith('"')) {
    try { return JSON.parse(text); } catch {}
  }
  if (text.startsWith("'") && text.endsWith("'")) {
    return text.slice(1, -1).replace(/''/g, "'");
  }
  return text;
}

function parseGithubForm(text) {
  const fields = [];
  const blocks = String(text).split(/(?=^  - type: )/m);
  for (const block of blocks) {
    const type = block.match(/^  - type:\s*([^\s]+)\s*$/m)?.[1];
    const id = block.match(/^    id:\s*([A-Za-z0-9_-]+)\s*$/m)?.[1];
    if (!type || !id) continue;
    const label = block.match(/^      label:\s*(.+)\s*$/m)?.[1];
    const required = block.match(/^      required:\s*(true|false)\s*$/m)?.[1];
    const options = [];
    const optionBlock = block.match(/^      options:\s*$([\s\S]*?)(?=^    validations:|^  - type:|\z)/m)?.[1] || '';
    for (const match of optionBlock.matchAll(/^        -\s*(.+)\s*$/gm)) {
      options.push(unquoteYaml(match[1]));
    }
    fields.push({
      id,
      type,
      label: unquoteYaml(label),
      required: required === 'true',
      options
    });
  }
  return fields;
}

function validateSchema(schema) {
  const errors = [];
  if (schema.schema_version !== 'knowledge-field-report.v2') {
    errors.push(`unexpected schema_version: ${schema.schema_version}`);
  }
  if (schema.product_version !== '3.3.0') {
    errors.push(`unexpected product_version: ${schema.product_version}`);
  }
  const ids = schema.fields.map((field) => field.id);
  if (new Set(ids).size !== ids.length) errors.push('field IDs must be unique');
  for (const field of schema.fields) {
    for (const key of [
      'id', 'type', 'required', 'human_label', 'agent_prompt', 'github_form',
      'renderer', 'public_section', 'redaction_policy', 'omission_policy'
    ]) {
      if (!Object.prototype.hasOwnProperty.call(field, key)) {
        errors.push(`${field.id || '<unknown>'} is missing ${key}`);
      }
    }
    if (field.type === 'enum') {
      if (!Array.isArray(field.allowed_values) || !field.allowed_values.length) {
        errors.push(`${field.id} enum is missing allowed_values`);
      }
      for (const value of field.allowed_values || []) {
        if (!field.human_labels?.[value]) {
          errors.push(`${field.id} is missing a human label for ${value}`);
        }
      }
    }
    if (!field.renderer?.section || !field.renderer?.label ||
        !Number.isFinite(field.renderer?.order)) {
      errors.push(`${field.id} has an incomplete renderer mapping`);
    }
    if (field.github_form && field.github_form.id !== field.id) {
      errors.push(`${field.id} GitHub mapping uses a different id`);
    }
    if (field.github_form &&
        Boolean(field.github_form.required) !== Boolean(field.required)) {
      errors.push(`${field.id} required flag differs between schema and GitHub form`);
    }
  }
  return errors;
}

function validateContract(systemRoot = DEFAULT_SYSTEM_ROOT) {
  let schema;
  try {
    schema = readSchema(systemRoot);
  } catch (error) {
    return { valid: false, errors: [error.message], form_status: 'schema_invalid' };
  }
  const errors = validateSchema(schema);
  const formPath = findForm(systemRoot);
  if (!formPath) {
    return {
      valid: errors.length === 0,
      errors,
      schema_version: schema.schema_version,
      contract_version: schema.contract_version,
      form_status: 'form_not_bundled'
    };
  }
  const actualText = fs.readFileSync(formPath, 'utf8').replace(/^\uFEFF/, '').replace(/\r\n/g, '\n');
  const expectedText = generateGithubForm(schema);
  const actualFields = parseGithubForm(actualText);
  const expectedFields = parseGithubForm(expectedText);
  const actualIds = actualFields.map((field) => field.id);
  const expectedIds = expectedFields.map((field) => field.id);
  const unknown = actualIds.filter((id) => !expectedIds.includes(id));
  const missing = expectedIds.filter((id) => !actualIds.includes(id));
  const drift = [];
  for (const expected of expectedFields) {
    const actual = actualFields.find((field) => field.id === expected.id);
    if (actual && canonicalJson(actual) !== canonicalJson(expected)) {
      drift.push({ id: expected.id, expected, actual });
    }
  }
  if (unknown.length) errors.push(`GitHub form has unknown fields: ${unknown.join(', ')}`);
  if (missing.length) errors.push(`GitHub form is missing fields: ${missing.join(', ')}`);
  if (drift.length) errors.push(`GitHub form mappings drifted for: ${drift.map((item) => item.id).join(', ')}`);
  if (actualText !== expectedText) errors.push('GitHub form is not the canonical schema projection');
  return {
    valid: errors.length === 0,
    errors,
    missing,
    unknown,
    drift,
    canonical_form_match: actualText === expectedText,
    schema_version: schema.schema_version,
    contract_version: schema.contract_version,
    form_status: 'validated',
    form_path: path.relative(systemRoot, formPath).replace(/\\/g, '/')
  };
}

function translationRequired(language, publicLanguage = PUBLIC_LANGUAGE) {
  const source = languageFamily(language || 'auto', { allowAuto: true });
  const target = languageFamily(normalizePublicLanguage(publicLanguage));
  return source === 'auto' || source !== target;
}

function validateTranslationPayload(originalInput, payload) {
  const original = normalizeAnswers(originalInput);
  const translated = normalizeAnswers(payload?.translated_answers || payload?.answers || {});
  const translatorResult = validateTranslatorIdentity(payload?.translator);
  const errors = [
    ...(original.errors || []),
    ...(translated.errors || []),
    ...translatorResult.errors
  ];
  if (!original.answers || !translated.answers) {
    return { valid: false, errors, translated_answers: null };
  }
  const originalKeys = Object.keys(original.answers).sort();
  const translatedKeys = Object.keys(translated.answers).sort();
  if (canonicalJson(originalKeys) !== canonicalJson(translatedKeys)) {
    errors.push('translation must contain exactly the original answer fields');
  }
  const fieldMap = new Map(FIELDS.map((field) => [field.id, field]));
  for (const id of originalKeys) {
    const field = fieldMap.get(id);
    const before = unwrap(original.answers[id]);
    const after = unwrap(translated.answers[id]);
    if (!field) continue;
    if (field.type !== 'string' && canonicalJson(before) !== canonicalJson(after)) {
      errors.push(`translation cannot change non-text value: ${id}`);
    }
    if (!empty(before) && empty(after)) errors.push(`translation cannot omit original text: ${id}`);
  }
  const attestations = payload?.attestations || {};
  for (const key of [
    'adds_no_facts',
    'negative_answers_not_softened',
    'uncertainty_preserved'
  ]) {
    if (attestations[key] !== true) errors.push(`translation attestation required: ${key}`);
  }
  return {
    valid: errors.length === 0,
    errors,
    translated_answers: translated.answers,
    translator: translatorResult.translator,
    original_hash: canonicalHash(original.answers),
    translated_hash: canonicalHash(translated.answers)
  };
}

module.exports = {
  ANSWER_ALIASES,
  CONTRACT_VERSION,
  DEFAULT_SCHEMA,
  FIELDS,
  PUBLIC_IDS,
  PUBLIC_LANGUAGE,
  SCHEMA_VERSION,
  STATES,
  canonicalHash,
  canonicalJson,
  fieldById,
  findForm,
  generateGithubForm,
  humanValue,
  identityKey,
  migrateAnswers,
  missingQuestions,
  normalizeLanguageTag,
  normalizePublicLanguage,
  normalizeAnswers,
  parseGithubForm,
  readSchema,
  translationRequired,
  unwrap,
  validateAnswers,
  validateContract,
  validateTranslatorIdentity,
  validateTranslationPayload
};
