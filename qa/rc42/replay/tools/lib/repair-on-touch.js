'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');
const {
  readJson,
  writeJsonAtomic,
  writeFileAtomic
} = require('./json-store');
const {
  stableId,
  canonicalPath,
  canonicalCode,
  canonicalModule,
  requiresDedicatedVerifier,
  dedicatedRequirementFor,
  findingOccurrence
} = require('./queue-lifecycle');

const RECEIPT_SCHEMA = 'knowledge-verification-receipt.v1';
const EXECUTION_SCHEMA = 'knowledge-verification-execution.v1';
const OPPORTUNITIES_SCHEMA = 'knowledge-repair-opportunities.v1';
const SETTINGS_SCHEMA = 'knowledge-repair-on-touch-settings.v1';
const MODES = Object.freeze(['off', 'safe-only', 'dedicated', 'scoped', 'aggressive']);
const MODE_RANK = Object.freeze({
  off: 0,
  'safe-only': 1,
  dedicated: 2,
  scoped: 3,
  aggressive: 4
});
const MODE_LABELS = Object.freeze({
  off: 'Off',
  'safe-only': 'Safe generated artifacts only',
  dedicated: 'Dedicated maintenance only',
  scoped: 'Scoped repair',
  aggressive: 'Extended repair'
});
const MODE_ALIASES = Object.freeze({
  extended: 'aggressive',
  'safe_only': 'safe-only',
  safe: 'safe-only'
});
const DEFAULT_REPAIR_POLICY = Object.freeze({
  enabled: true,
  mode: 'scoped',
  max_findings_per_task: 2,
  max_extra_minutes: 5,
  max_extra_context_percent: 10,
  rebuild_generated_artifacts: true,
  edit_curated_knowledge: 'verified_only',
  require_confirmation_for_critical_paths: true,
  require_confirmation_for_security_findings: true,
  include_task_readiness: true,
  show_final_maintenance_summary: true
});
const HARD_SAFETY = Object.freeze({
  edit_source_for_health: false,
  score_is_derived_only: true,
  exact_lifecycle_closure_only: true
});
const GENERATED_REPAIR_CLASSES = new Set([
  'rebuild_generated_artifact',
  'regenerate_index',
  'regenerate_graph',
  'regenerate_report'
]);
const GENERATED_REBUILD_TOOLS = new Set([
  '.knowledge/tools/build-routing-bundle.js',
  '.knowledge/tools/build-search-index.js',
  '.knowledge/tools/build-wiki-graph.js'
]);
function exactGeneratedProducerArgv(argv, expectedTool = null) {
  if (!Array.isArray(argv)) return false;
  const executable = path.basename(String(argv[0] || ''))
    .toLowerCase();
  if (!['node', 'node.exe'].includes(executable)) return false;
  let tool;
  try {
    tool = canonicalPath(argv[1] || '');
  } catch {
    return false;
  }
  if (
    !GENERATED_REBUILD_TOOLS.has(tool) ||
    (expectedTool && tool !== expectedTool)
  ) {
    return false;
  }
  return argv.length === 2 ||
    (argv.length === 3 && argv[2] === '--quiet');
}
const GENERATED_REBUILD_DEPENDENCIES = Object.freeze({
  '.knowledge/tools/build-search-index.js': Object.freeze([
    '.knowledge/install-manifest.json',
    '.knowledge/package.json',
    '.knowledge/tools/build-search-index.js',
    '.knowledge/tools/lib/contained-lock-manager.js',
    '.knowledge/tools/lib/git-context.js',
    '.knowledge/tools/lib/json-store.js',
    '.knowledge/tools/lib/lock-owner-schema.js',
    '.knowledge/tools/lib/lock-policy.js',
    '.knowledge/tools/lib/path-context.js',
    '.knowledge/tools/lib/strict-temp-cleanup.js',
    '.knowledge/tools/lib/system-version.js',
    '.knowledge/tools/lib/token-estimate.js'
  ]),
  '.knowledge/tools/build-routing-bundle.js': Object.freeze([
    '.knowledge/install-manifest.json',
    '.knowledge/package.json',
    '.knowledge/tools/build-routing-bundle.js',
    '.knowledge/tools/lib/adaptive-routing.js',
    '.knowledge/tools/lib/contained-artifact.js',
    '.knowledge/tools/lib/contained-lock-manager.js',
    '.knowledge/tools/lib/git-context.js',
    '.knowledge/tools/lib/json-store.js',
    '.knowledge/tools/lib/lock-owner-schema.js',
    '.knowledge/tools/lib/lock-policy.js',
    '.knowledge/tools/lib/path-context.js',
    '.knowledge/tools/lib/strict-temp-cleanup.js',
    '.knowledge/tools/lib/system-version.js',
    '.knowledge/tools/lib/task-routing.js',
    '.knowledge/tools/lib/workspace-baseline.js',
    '.knowledge/tools/lib/wiki-status.js'
  ]),
  '.knowledge/tools/build-wiki-graph.js': Object.freeze([
    '.knowledge/install-manifest.json',
    '.knowledge/tools/build-wiki-graph.js',
    '.knowledge/tools/lib/contained-lock-manager.js',
    '.knowledge/tools/lib/git-context.js',
    '.knowledge/tools/lib/json-store.js',
    '.knowledge/tools/lib/lock-owner-schema.js',
    '.knowledge/tools/lib/lock-policy.js',
    '.knowledge/tools/lib/path-context.js',
    '.knowledge/tools/lib/strict-temp-cleanup.js'
  ])
});
const PROTECTED_CODES = new Set([
  'open_contradiction',
  'security_finding',
  'policy_violation',
  'incident',
  'unresolved_architecture_conflict',
  'manual_review_required'
]);
const PLAN_DECISION_REASONS = new Set([
  'task_relevant_and_within_budget',
  'mode_off',
  'generated_rebuild_disabled',
  'generated_producer_unmapped',
  'dedicated_blocked_by_policy_cap',
  'dedicated_run_required',
  'dedicated_action_required',
  'dedicated_exact_confirmation_required',
  'safe_only_curated_repair_forbidden',
  'not_safe_during_current_task',
  'critical_path_confirmation_required',
  'security_confirmation_required',
  'outside_task_scope',
  'dependency_not_essential',
  'essential_dependency_reason_missing',
  'budget_exhausted_max_findings',
  'budget_exhausted_time',
  'budget_exhausted_context',
  'verification_did_not_clear_finding',
  'verified_and_exact_finding_closed'
]);
const REQUIRED_POLICY_KEYS = Object.freeze(Object.keys(DEFAULT_REPAIR_POLICY));
const SECRET_KEY_PATTERN = /(api[_-]?key|secret|token|password|authorization|private[_-]?key)/i;
const SECRET_VALUE_PATTERN = /\b(?:sk|pk|ghp|github_pat|m0sk|pcsk|eyJ)[A-Za-z0-9_./+=-]{18,}\b/;
const EMAIL_VALUE_PATTERN = /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/i;
const WINDOWS_ABSOLUTE_PATH_PATTERN = /(?:^|[\s"'`(])(?:[A-Z]:[\\/]|\\\\[^\\/\s]+[\\/])/i;
const POSIX_ABSOLUTE_PATH_PATTERN = /(?:^|[\s"'`(])\/(?!\/)(?:[^\s"'`,;)}\]]+\/)+[^\s"'`,;)}\]]+/i;
const MAX_REPAIR_PLAN_BYTES = 1024 * 1024;
const MAX_VERIFICATION_RECEIPT_BYTES = 256 * 1024;
const MAX_VERIFICATION_EXECUTION_BYTES = 256 * 1024;
const SCHEMA_CACHE = new Map();
const SUPPORTED_SCHEMA_KEYWORDS = new Set([
  '$schema',
  '$id',
  'title',
  'description',
  'type',
  'const',
  'enum',
  'properties',
  'required',
  'additionalProperties',
  'items',
  'minItems',
  'uniqueItems',
  'minLength',
  'pattern',
  'minimum',
  'maximum',
  'format'
]);

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function stableJson(value) {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableJson(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function bundledSchema(filename) {
  if (SCHEMA_CACHE.has(filename)) return SCHEMA_CACHE.get(filename);
  const directory = path.resolve(__dirname, '..', '..', 'schemas');
  const target = path.join(directory, filename);
  const stat = fs.lstatSync(target);
  if (
    !stat.isFile() ||
    stat.isSymbolicLink() ||
    stat.size <= 0 ||
    stat.size > 256 * 1024 ||
    path.relative(directory, fs.realpathSync(target)).replace(/\\/g, '/') !==
      filename
  ) {
    throw contentStoreError(
      'verification_schema_unsafe',
      `Bundled verification schema is not a safe regular file: ${filename}`
    );
  }
  const schema = JSON.parse(
    fs.readFileSync(target, 'utf8').replace(/^\uFEFF/, '')
  );
  SCHEMA_CACHE.set(filename, schema);
  return schema;
}

function schemaTypeMatches(value, expected) {
  if (expected === 'null') return value === null;
  if (expected === 'array') return Array.isArray(value);
  if (expected === 'object') {
    return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
  }
  if (expected === 'integer') return Number.isInteger(value);
  if (expected === 'number') {
    return typeof value === 'number' && Number.isFinite(value);
  }
  return typeof value === expected;
}

function validateSchemaNode(schema, value, at, errors) {
  if (!schema || typeof schema !== 'object' || Array.isArray(schema)) {
    errors.push(`${at}:schema_node_invalid`);
    return;
  }
  for (const keyword of Object.keys(schema)) {
    if (!SUPPORTED_SCHEMA_KEYWORDS.has(keyword)) {
      errors.push(`${at}:unsupported_keyword:${keyword}`);
    }
  }
  const expectedTypes = Array.isArray(schema.type)
    ? schema.type
    : schema.type
      ? [schema.type]
      : [];
  if (
    expectedTypes.length &&
    !expectedTypes.some((type) => schemaTypeMatches(value, type))
  ) {
    errors.push(`${at}:type`);
    return;
  }
  if (
    Object.prototype.hasOwnProperty.call(schema, 'const') &&
    stableJson(value) !== stableJson(schema.const)
  ) {
    errors.push(`${at}:const`);
  }
  if (
    Array.isArray(schema.enum) &&
    !schema.enum.some((item) => stableJson(item) === stableJson(value))
  ) {
    errors.push(`${at}:enum`);
  }
  if (typeof value === 'string') {
    if (
      Number.isInteger(schema.minLength) &&
      value.length < schema.minLength
    ) {
      errors.push(`${at}:minLength`);
    }
    if (schema.pattern && !new RegExp(schema.pattern).test(value)) {
      errors.push(`${at}:pattern`);
    }
    if (
      schema.format === 'date-time' &&
      (
        !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/.test(value) ||
        !Number.isFinite(Date.parse(value))
      )
    ) {
      errors.push(`${at}:format:date-time`);
    }
  }
  if (typeof value === 'number' && Number.isFinite(value)) {
    if (schema.minimum !== undefined && value < schema.minimum) {
      errors.push(`${at}:minimum`);
    }
    if (schema.maximum !== undefined && value > schema.maximum) {
      errors.push(`${at}:maximum`);
    }
  }
  if (Array.isArray(value)) {
    if (
      Number.isInteger(schema.minItems) &&
      value.length < schema.minItems
    ) {
      errors.push(`${at}:minItems`);
    }
    if (
      schema.uniqueItems === true &&
      new Set(value.map(stableJson)).size !== value.length
    ) {
      errors.push(`${at}:uniqueItems`);
    }
    if (schema.items) {
      value.forEach((item, index) =>
        validateSchemaNode(schema.items, item, `${at}[${index}]`, errors));
    }
  }
  if (value && typeof value === 'object' && !Array.isArray(value)) {
    const properties = schema.properties || {};
    for (const required of schema.required || []) {
      if (!Object.prototype.hasOwnProperty.call(value, required)) {
        errors.push(`${at}.${required}:required`);
      }
    }
    for (const [key, item] of Object.entries(value)) {
      if (properties[key]) {
        validateSchemaNode(properties[key], item, `${at}.${key}`, errors);
      } else if (schema.additionalProperties === false) {
        errors.push(`${at}.${key}:additionalProperties`);
      }
    }
  }
}

function validateBundledSchema(filename, value) {
  const errors = [];
  let schema;
  try {
    schema = bundledSchema(filename);
  } catch (error) {
    return {
      ok: false,
      errors: [`$:schema_unavailable:${error.code || 'invalid'}`]
    };
  }
  validateSchemaNode(schema, value, '$', errors);
  return { ok: errors.length === 0, errors: Array.from(new Set(errors)) };
}

function contained(candidate, root) {
  const absolute = path.resolve(candidate);
  const base = path.resolve(root);
  return absolute === base || absolute.startsWith(`${base}${path.sep}`);
}

function safeRelativeFile(root, relative) {
  const raw = String(relative || '');
  if (!raw || raw.includes('\0') || path.isAbsolute(raw) || /^[a-z]:/i.test(raw)) return null;
  const candidate = path.resolve(root, raw);
  if (!contained(candidate, root)) return null;
  let stat;
  try {
    stat = fs.lstatSync(candidate);
  } catch {
    return null;
  }
  if (!stat.isFile() || stat.isSymbolicLink()) return null;
  try {
    const real = fs.realpathSync(candidate);
    return contained(real, root) && fs.statSync(real).isFile() ? real : null;
  } catch {
    return null;
  }
}

function physicalPathIdentity(value) {
  const resolved = path.resolve(value);
  return process.platform === 'win32'
    ? resolved.toLowerCase()
    : resolved;
}

function nodeExecutableKind(value) {
  const executable = path.basename(String(value || ''))
    .toLowerCase();
  if (['node', 'node.exe'].includes(executable)) return 'canonical';
  const windowsAlias = executable.replace(/[. ]+$/g, '');
  return ['node', 'node.exe'].includes(windowsAlias)
    ? 'windows_alias'
    : 'other';
}

function rejectNodeExecutableAlias(value) {
  if (nodeExecutableKind(value) !== 'windows_alias') return;
  const error = new Error(
    'Windows Node executable aliases are not accepted'
  );
  error.code = 'verification_node_executable_alias_unsafe';
  throw error;
}

function nodeInvocationDescriptor(argv) {
  if (
    !Array.isArray(argv) ||
    nodeExecutableKind(argv[0]) !== 'canonical'
  ) {
    return null;
  }
  const safeScriptArgument = (value) => {
    const raw = String(value || '');
    return Boolean(raw) &&
      !raw.includes('\0') &&
      !raw.startsWith('-') &&
      !path.isAbsolute(raw) &&
      !/^[a-z]:/i.test(raw) &&
      !raw.split(/[\\/]/).includes('..');
  };
  if (argv[1] === '--test') {
    return argv.length === 3 && safeScriptArgument(argv[2])
      ? {
          valid: true,
          mode: 'test',
          script: canonicalPath(argv[2]),
          scriptIndex: 2
        }
      : { valid: false, mode: 'test' };
  }
  return safeScriptArgument(argv[1])
    ? {
        valid: true,
        mode: 'script',
        script: canonicalPath(argv[1]),
        scriptIndex: 1
      }
    : { valid: false, mode: 'script' };
}

function safeRelativeDirectory(root, relative = '.') {
  const raw = String(relative || '.');
  if (raw.includes('\0') || path.isAbsolute(raw) || /^[a-z]:/i.test(raw)) return null;
  const candidate = path.resolve(root, raw);
  if (!contained(candidate, root)) return null;
  let stat;
  try {
    stat = fs.lstatSync(candidate);
  } catch {
    return null;
  }
  if (!stat.isDirectory() || stat.isSymbolicLink()) return null;
  try {
    const real = fs.realpathSync(candidate);
    return contained(real, root) && fs.statSync(real).isDirectory() ? real : null;
  } catch {
    return null;
  }
}

function contentStoreError(code, message) {
  const error = new Error(message);
  error.code = code;
  return error;
}

function secureStateStore(stateRoot, relativeStore, { create = false } = {}) {
  const normalizedStore = String(relativeStore || '').replace(/\\/g, '/');
  if (
    !normalizedStore ||
    normalizedStore === '.' ||
    normalizedStore.startsWith('../') ||
    normalizedStore.includes('/../') ||
    path.posix.isAbsolute(normalizedStore)
  ) {
    throw contentStoreError(
      'verification_store_unsafe',
      `Verification store path is unsafe: ${relativeStore}`
    );
  }
  const absoluteStateRoot = path.resolve(stateRoot);
  let stateStat;
  try {
    stateStat = fs.lstatSync(absoluteStateRoot);
  } catch {
    throw contentStoreError(
      'verification_store_unsafe',
      'Verification state root does not exist'
    );
  }
  if (!stateStat.isDirectory() || stateStat.isSymbolicLink()) {
    throw contentStoreError(
      'verification_store_unsafe',
      'Verification state root must be a real directory'
    );
  }
  const realStateRoot = fs.realpathSync(absoluteStateRoot);
  let current = absoluteStateRoot;
  for (const component of normalizedStore.split('/')) {
    current = path.join(current, component);
    if (!fs.existsSync(current)) {
      if (!create) {
        throw contentStoreError(
          'verification_store_missing',
          `Verification store does not exist: ${normalizedStore}`
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
      throw contentStoreError(
        'verification_store_unsafe',
        `Verification store contains a symlink or non-directory: ${normalizedStore}`
      );
    }
  }
  const realDirectory = fs.realpathSync(current);
  const relative = path.relative(realStateRoot, realDirectory).replace(/\\/g, '/');
  if (relative !== normalizedStore) {
    throw contentStoreError(
      'verification_store_unsafe',
      `Verification store escaped the state root: ${normalizedStore}`
    );
  }
  return realDirectory;
}

function executionDigest(raw) {
  const copy = JSON.parse(JSON.stringify(raw || {}));
  delete copy.execution_id;
  delete copy.content_sha256;
  delete copy.execution_path;
  return sha256(stableJson(copy));
}

function executionRecordPath(stateRoot, digest) {
  return path.join(stateRoot, 'maintenance', 'verification_executions', `${digest}.json`);
}

function validateExecutionRecord(record) {
  const errors = [];
  if (!record || typeof record !== 'object' || Array.isArray(record)) return { ok: false, errors: ['execution_record_required'] };
  const schemaValidation = validateBundledSchema(
    'verification-execution.schema.json',
    record
  );
  errors.push(...schemaValidation.errors.map((item) =>
    `execution_schema_contract:${item}`));
  if (secretPaths(record).length) errors.push('execution_secret_like_value');
  if (privateValuePaths(record).length) errors.push('execution_private_value');
  if (record.schema_version !== EXECUTION_SCHEMA) errors.push('execution_schema_invalid');
  if (!record.task_id) errors.push('execution_task_id_required');
  if (!record.session_id) errors.push('execution_session_id_required');
  if (!Array.isArray(record.command_argv) || !record.command_argv.length ||
      record.command_argv.some((item) => typeof item !== 'string' || item.includes('\0'))) {
    errors.push('execution_argv_invalid');
  }
  if (record.status !== 'pass' || record.exit_code !== 0) errors.push('execution_not_passed');
  if (record.timed_out !== false) errors.push('execution_timed_out');
  if (record.signal !== null) errors.push('execution_signal_invalid');
  if (
    typeof record.cwd !== 'string' ||
    record.cwd.includes('\0') ||
    path.isAbsolute(record.cwd) ||
    /^[a-z]:/i.test(record.cwd) ||
    record.cwd.split(/[\\/]/).includes('..')
  ) {
    errors.push('execution_cwd_invalid');
  }
  if (
    !record.command ||
    typeof record.command !== 'string' ||
    !record.executed_by ||
    typeof record.executed_by !== 'string'
  ) {
    errors.push('execution_metadata_invalid');
  }
  const executableKind = nodeExecutableKind(
    record.command_argv?.[0]
  );
  if (executableKind === 'windows_alias') {
    errors.push('execution_node_executable_alias_invalid');
  }
  const nodeCommand = executableKind === 'canonical';
  const nodeInvocation = nodeCommand
    ? nodeInvocationDescriptor(record.command_argv)
    : null;
  if (nodeCommand && !nodeInvocation?.valid) {
    errors.push('execution_node_invocation_invalid');
  }
  if (
    nodeCommand &&
    (
      record.runtime_binding !== 'process_exec_path' ||
      !/^[a-f0-9]{64}$/i.test(
        String(record.runtime_sha256 || '')
      ) ||
      ![
        'sanitized_node',
        'sanitized_node_no_git'
      ].includes(record.environment_profile)
    )
  ) {
    errors.push('execution_node_runtime_binding_invalid');
  }
  if (
    nodeCommand &&
    exactGeneratedProducerArgv(record.command_argv) &&
    record.cwd !== '.'
  ) {
    errors.push('execution_generated_producer_cwd_invalid');
  }
  if (
    !nodeCommand &&
    (
      record.runtime_binding !== 'command_argv' ||
      record.runtime_sha256 !== null ||
      record.environment_profile !== 'inherited_command'
    )
  ) {
    errors.push('execution_command_runtime_binding_invalid');
  }
  const executedAt = Date.parse(String(record.executed_at || ''));
  if (
    !Number.isFinite(executedAt) ||
    executedAt > Date.now() + 5 * 60 * 1000
  ) {
    errors.push('execution_timestamp_invalid');
  }
  if (!Number.isFinite(Number(record.duration_ms)) || Number(record.duration_ms) < 0) errors.push('execution_duration_invalid');
  if (!/^[a-f0-9]{64}$/i.test(String(record.stdout_sha256 || ''))) errors.push('execution_stdout_hash_invalid');
  if (!/^[a-f0-9]{64}$/i.test(String(record.stderr_sha256 || ''))) errors.push('execution_stderr_hash_invalid');
  if (!Array.isArray(record.source_snapshot) || !record.source_snapshot.length ||
      record.source_snapshot.some((item) =>
        !item ||
        typeof item !== 'object' ||
        !item.path ||
        path.isAbsolute(String(item.path)) ||
        String(item.path).split(/[\\/]/).includes('..') ||
        !/^[a-f0-9]{64}$/i.test(String(item.sha256 || '')))) {
    errors.push('execution_source_snapshot_invalid');
  }
  if (
    Array.isArray(record.source_snapshot) &&
    record.source_snapshot.every((item) => item && typeof item === 'object') &&
    new Set(record.source_snapshot.map((item) => canonicalPath(item.path))).size !==
      record.source_snapshot.length
  ) {
    errors.push('execution_source_snapshot_noncanonical');
  }
  if (
    !Array.isArray(record.source_snapshot_before) ||
    record.source_snapshot_before.some((item) =>
      !item ||
      typeof item !== 'object' ||
      !item.path ||
      path.isAbsolute(String(item.path)) ||
      String(item.path).split(/[\\/]/).includes('..') ||
      !/^[a-f0-9]{64}$/i.test(String(item.sha256 || '')))
  ) {
    errors.push('execution_source_snapshot_before_invalid');
  }
  if (
    Array.isArray(record.source_snapshot_before) &&
    record.source_snapshot_before.every((item) =>
      item && typeof item === 'object') &&
    new Set(record.source_snapshot_before.map((item) =>
      canonicalPath(item.path))).size !==
      record.source_snapshot_before.length
  ) {
    errors.push('execution_source_snapshot_before_noncanonical');
  }
  if (
    !Number.isInteger(record.stdout_bytes) ||
    record.stdout_bytes < 0 ||
    !Number.isInteger(record.stderr_bytes) ||
    record.stderr_bytes < 0
  ) {
    errors.push('execution_output_size_invalid');
  }
  const digest = executionDigest(record);
  if (record.content_sha256 !== digest) errors.push('execution_content_hash_mismatch');
  if (record.execution_id !== `KVE-${digest}`) errors.push('execution_id_content_address_mismatch');
  return { ok: errors.length === 0, errors: Array.from(new Set(errors)), digest };
}

function saveExecutionRecord(stateRoot, record) {
  const validation = validateExecutionRecord(record);
  if (!validation.ok) {
    const error = new Error(`Verification execution rejected: ${validation.errors.join(', ')}`);
    error.code = 'verification_execution_invalid';
    throw error;
  }
  const directory = secureStateStore(
    stateRoot,
    'maintenance/verification_executions',
    { create: true }
  );
  const target = path.join(directory, `${validation.digest}.json`);
  const body = `${JSON.stringify(record, null, 2)}\n`;
  if (Buffer.byteLength(body) > MAX_VERIFICATION_EXECUTION_BYTES) {
    const error = new Error('Verification execution exceeds the bounded content-store limit');
    error.code = 'verification_execution_too_large';
    throw error;
  }
  if (fs.existsSync(target)) {
    const stat = fs.lstatSync(target);
    if (!stat.isFile() || stat.isSymbolicLink() || fs.readFileSync(target, 'utf8') !== body) {
      const error = new Error('Content-addressed verification execution is immutable');
      error.code = 'verification_execution_immutable';
      throw error;
    }
    return {
      path: target,
      idempotent: true,
      physical_sha256: sha256(Buffer.from(body))
    };
  }
  writeFileAtomic(target, body);
  return {
    path: target,
    idempotent: false,
    physical_sha256: sha256(Buffer.from(body))
  };
}

function loadExecutionRecord(stateRoot, reference) {
  const raw = String(reference || '').replace(/^KVE-/, '');
  const digest = /^[a-f0-9]{64}$/i.test(raw)
    ? raw.toLowerCase()
    : path.basename(raw, '.json').toLowerCase();
  if (!/^[a-f0-9]{64}$/.test(digest)) return null;
  let directory;
  try {
    directory = secureStateStore(
      stateRoot,
      'maintenance/verification_executions'
    );
  } catch {
    return null;
  }
  const target = path.join(directory, `${digest}.json`);
  let stat;
  try {
    stat = fs.lstatSync(target);
  } catch {
    return null;
  }
  if (
    !stat.isFile() ||
    stat.isSymbolicLink() ||
    stat.size <= 0 ||
    stat.size > MAX_VERIFICATION_EXECUTION_BYTES
  ) return null;
  const real = fs.realpathSync(target);
  if (path.relative(directory, real) !== `${digest}.json`) return null;
  const body = fs.readFileSync(real);
  let record;
  try {
    record = JSON.parse(
      body.toString('utf8').replace(/^\uFEFF/, '')
    );
  } catch {
    return null;
  }
  const validation = validateExecutionRecord(record);
  if (!validation.ok || validation.digest !== digest) return null;
  return {
    record,
    path: real,
    physical_sha256: sha256(body)
  };
}

function runVerificationTests({
  stateRoot,
  repoRoot,
  taskId,
  sessionId,
  tests = [],
  sourceFiles = [],
  checkedBy = 'unknown'
}) {
  if (!taskId || !sessionId) throw new Error('Verification execution requires taskId and sessionId');
  if (!Array.isArray(tests) || !tests.length) throw new Error('At least one verification test command is required');
  const generatedExecutionSources = tests.flatMap((test) => {
    const argv = Array.isArray(test?.argv) ? test.argv.map(String) : [];
    rejectNodeExecutableAlias(argv[0]);
    if (nodeExecutableKind(argv[0]) !== 'canonical') return [];
    const invocation = nodeInvocationDescriptor(argv);
    if (!invocation?.valid) {
      const error = new Error(
        'Node verification requires a repository script or one exact node --test file'
      );
      error.code = 'verification_node_invocation_unsafe';
      throw error;
    }
    return [
      invocation.script,
      ...(invocation.mode === 'script'
        ? generatedProducerDependencyClosure(invocation.script)
        : [])
    ];
  });
  const sourcePaths = Array.from(new Set([
    ...sourceFiles.map((item) =>
      canonicalPath(String(item.path || item))),
    ...generatedExecutionSources
  ]))
    .sort();
  if (!sourcePaths.length) {
    throw new Error(
      'Verification execution requires a non-empty source snapshot'
    );
  }
  const sourceSnapshot = (allowMissing = false) => sourcePaths
    .map((relative) => {
      const absolute = safeRelativeFile(repoRoot, relative);
      if (!absolute) {
        if (allowMissing) return null;
        throw new Error(
          `Verification source is missing or unsafe: ${relative}`
        );
      }
      return {
        path: relative,
        sha256: sha256(fs.readFileSync(absolute))
      };
    })
    .filter(Boolean);

  return tests.map((test) => {
    const argv = Array.isArray(test.argv) ? test.argv.map(String) : [];
    if (!argv.length || !/^[A-Za-z0-9_.-]+$/.test(argv[0]) || argv.some((item) => item.includes('\0'))) {
      throw new Error('Verification commands must use a basename executable and an argv array');
    }
    if (secretPaths(argv).length || privateValuePaths(argv).length) {
      const error = new Error(
        'Verification command arguments contain private or secret-like data'
      );
      error.code = 'verification_command_private';
      throw error;
    }
    const cwdRelative = String(test.cwd || '.').replace(/\\/g, '/');
    const cwd = safeRelativeDirectory(repoRoot, cwdRelative);
    if (!cwd) throw new Error(`Verification cwd is missing or unsafe: ${cwdRelative}`);
    const timeoutMs = Math.min(300000, Math.max(1000, Number(test.timeout_ms || 120000)));
    const sourceSnapshotBefore = sourceSnapshot(true);
    rejectNodeExecutableAlias(argv[0]);
    const nodeCommand =
      nodeExecutableKind(argv[0]) === 'canonical';
    const nodeInvocation = nodeCommand
      ? nodeInvocationDescriptor(argv)
      : null;
    if (nodeCommand && !nodeInvocation?.valid) {
      const error = new Error(
        'Node verification requires a repository script or one exact node --test file'
      );
      error.code = 'verification_node_invocation_unsafe';
      throw error;
    }
    const nodeScriptPhysical = nodeCommand
      ? safeRelativeFile(repoRoot, nodeInvocation.script)
      : null;
    if (nodeCommand && !nodeScriptPhysical) {
      const error = new Error(
        'Node verification scripts must be safe physical repository files'
      );
      error.code = 'verification_node_script_unsafe';
      throw error;
    }
    if (
      nodeCommand &&
      fs.statSync(nodeScriptPhysical).nlink !== 1
    ) {
      const error = new Error(
        'Node verification scripts must not have hardlink aliases'
      );
      error.code = 'verification_node_script_hardlink_unsafe';
      throw error;
    }
    let generatedProducerToolPath = null;
    if (nodeCommand) {
      for (const approvedTool of GENERATED_REBUILD_TOOLS) {
        const approvedPhysical = safeRelativeFile(
          repoRoot,
          approvedTool
        );
        if (
          approvedPhysical &&
          physicalPathIdentity(approvedPhysical) ===
            physicalPathIdentity(nodeScriptPhysical)
        ) {
          generatedProducerToolPath = approvedTool;
          break;
        }
      }
    }
    const requestedGeneratedProducer =
      Boolean(generatedProducerToolPath);
    if (
      requestedGeneratedProducer &&
      !exactGeneratedProducerArgv(
        argv,
        generatedProducerToolPath
      )
    ) {
      const error = new Error(
        'Approved generated producers require exact bounded argv'
      );
      error.code = 'generated_producer_argv_invalid';
      throw error;
    }
    if (requestedGeneratedProducer && cwdRelative !== '.') {
      const error = new Error(
        'Approved generated producers must run from the repository root'
      );
      error.code = 'generated_producer_cwd_invalid';
      throw error;
    }
    const generatedProducer = requestedGeneratedProducer;
    const generatedProjectKnowledgeRoot = generatedProducer
      ? safeRelativeDirectory(repoRoot, '.knowledge')
      : null;
    if (generatedProducer && !generatedProjectKnowledgeRoot) {
      const error = new Error(
        'Approved generated producers require a physical project knowledge root'
      );
      error.code = 'generated_producer_context_invalid';
      throw error;
    }
    const executable = nodeCommand ? process.execPath : argv[0];
    const executableArgv = nodeCommand
      ? nodeInvocation.mode === 'test'
        ? ['--test', nodeScriptPhysical]
        : [nodeScriptPhysical, ...argv.slice(2)]
      : argv.slice(1);
    const executionEnvironment = nodeCommand
      ? Object.fromEntries([
          'SystemRoot',
          'WINDIR',
          'ComSpec',
          'PATHEXT',
          'PATH',
          'TEMP',
          'TMP',
          'LANG',
          'LC_ALL',
          'HOME',
          'USERPROFILE'
        ].filter((key) => process.env[key] !== undefined)
          .map((key) => [key, process.env[key]])
          .concat(generatedProducer
            ? [
                ['KNOWLEDGE_DISABLE_GIT_DISCOVERY', '1'],
                ['KNOWLEDGE_SYSTEM_ROOT', generatedProjectKnowledgeRoot],
                ['KNOWLEDGE_TARGET_ROOT', path.resolve(repoRoot)],
                [
                  'KNOWLEDGE_PROJECT_KNOWLEDGE_ROOT',
                  generatedProjectKnowledgeRoot
                ],
                ['KNOWLEDGE_STATE_ROOT', path.resolve(stateRoot)]
              ]
            : []))
      : process.env;
    const startedAt = new Date().toISOString();
    const started = Date.now();
    const result = spawnSync(executable, executableArgv, {
      cwd,
      env: executionEnvironment,
      encoding: null,
      windowsHide: true,
      timeout: timeoutMs,
      maxBuffer: 16 * 1024 * 1024,
      shell: false
    });
    const stdout = Buffer.isBuffer(result.stdout) ? result.stdout : Buffer.from(result.stdout || '');
    const stderr = Buffer.isBuffer(result.stderr) ? result.stderr : Buffer.from(result.stderr || '');
    const sourceSnapshotAfter = sourceSnapshot(false);
    const base = {
      schema_version: EXECUTION_SCHEMA,
      task_id: String(taskId),
      session_id: String(sessionId),
      command_argv: argv,
      command: argv.map((item) => JSON.stringify(item)).join(' '),
      cwd: cwdRelative === '.' ? '.' : canonicalPath(cwdRelative),
      status: result.status === 0 ? 'pass' : 'fail',
      exit_code: Number.isInteger(result.status) ? result.status : null,
      signal: result.signal || null,
      timed_out: result.error?.code === 'ETIMEDOUT',
      duration_ms: Date.now() - started,
      executed_at: startedAt,
      executed_by: String(checkedBy || 'unknown'),
      runtime_binding:
        nodeCommand ? 'process_exec_path' : 'command_argv',
      runtime_sha256: nodeCommand
        ? sha256(fs.readFileSync(process.execPath))
        : null,
      environment_profile:
        nodeCommand
          ? generatedProducer
            ? 'sanitized_node_no_git'
            : 'sanitized_node'
          : 'inherited_command',
      stdout_sha256: sha256(stdout),
      stderr_sha256: sha256(stderr),
      stdout_bytes: stdout.length,
      stderr_bytes: stderr.length,
      source_snapshot_before: sourceSnapshotBefore,
      source_snapshot: sourceSnapshotAfter
    };
    const digest = executionDigest(base);
    const record = {
      ...base,
      execution_id: `KVE-${digest}`,
      content_sha256: digest
    };
    const saved = saveExecutionRecord(stateRoot, record);
    return {
      record,
      path: saved.path,
      relative_path: path.relative(stateRoot, saved.path).replace(/\\/g, '/'),
      idempotent: saved.idempotent
    };
  });
}

function canonicalMode(value, fallback = null) {
  if (value === undefined || value === null || value === '') return fallback;
  const normalized = String(value).trim().toLowerCase().replace(/\s+/g, '-');
  const mode = MODE_ALIASES[normalized] || normalized;
  if (!MODES.includes(mode)) {
    const error = new Error(`Unsupported repair-on-touch mode: ${value}`);
    error.code = 'repair_mode_invalid';
    throw error;
  }
  return mode;
}

function policyAllowsReceiptMode(policyResolution, receiptMode) {
  const mode = canonicalMode(receiptMode, null);
  const effectiveMode = canonicalMode(policyResolution?.effective_mode, null);
  if (
    !mode ||
    !effectiveMode ||
    policyResolution?.effective?.enabled !== true
  ) {
    return false;
  }
  const cap = policyResolution.policy_cap || {};
  if (mode === 'dedicated') {
    return effectiveMode === 'dedicated' &&
      (!cap.active || ['dedicated', 'aggressive'].includes(cap.max_mode));
  }
  return MODE_RANK[effectiveMode] >= MODE_RANK[mode];
}

function restrictPolicyBudgets(plannedResolution, liveResolution) {
  const planned = plannedResolution?.effective || {};
  const live = liveResolution?.effective || {};
  const limit = (key, fallback) => {
    const plannedValue = Number(planned[key]);
    const liveValue = Number(live[key]);
    const safePlanned = Number.isFinite(plannedValue) && plannedValue >= 0
      ? plannedValue
      : fallback;
    const safeLive = Number.isFinite(liveValue) && liveValue >= 0
      ? liveValue
      : fallback;
    return Math.min(safePlanned, safeLive);
  };
  const booleanValue = (source, key, fallback) =>
    typeof source[key] === 'boolean' ? source[key] : fallback;
  return {
    ...(plannedResolution || liveResolution || {}),
    effective: {
      ...(plannedResolution?.effective || liveResolution?.effective || {}),
      max_findings_per_task: limit(
        'max_findings_per_task',
        DEFAULT_REPAIR_POLICY.max_findings_per_task
      ),
      max_extra_minutes: limit(
        'max_extra_minutes',
        DEFAULT_REPAIR_POLICY.max_extra_minutes
      ),
      max_extra_context_percent: limit(
        'max_extra_context_percent',
        DEFAULT_REPAIR_POLICY.max_extra_context_percent
      ),
      rebuild_generated_artifacts:
        booleanValue(
          planned,
          'rebuild_generated_artifacts',
          DEFAULT_REPAIR_POLICY.rebuild_generated_artifacts
        ) &&
        booleanValue(
          live,
          'rebuild_generated_artifacts',
          DEFAULT_REPAIR_POLICY.rebuild_generated_artifacts
        ),
      require_confirmation_for_critical_paths:
        booleanValue(
          planned,
          'require_confirmation_for_critical_paths',
          DEFAULT_REPAIR_POLICY.require_confirmation_for_critical_paths
        ) ||
        booleanValue(
          live,
          'require_confirmation_for_critical_paths',
          DEFAULT_REPAIR_POLICY.require_confirmation_for_critical_paths
        ),
      require_confirmation_for_security_findings:
        booleanValue(
          planned,
          'require_confirmation_for_security_findings',
          DEFAULT_REPAIR_POLICY.require_confirmation_for_security_findings
        ) ||
        booleanValue(
          live,
          'require_confirmation_for_security_findings',
          DEFAULT_REPAIR_POLICY.require_confirmation_for_security_findings
        )
    },
    budget_sources: {
      rule: 'minimum_of_planned_and_current',
      planned: {
        max_findings_per_task: planned.max_findings_per_task ?? null,
        max_extra_minutes: planned.max_extra_minutes ?? null,
        max_extra_context_percent: planned.max_extra_context_percent ?? null
      },
      current: {
        max_findings_per_task: live.max_findings_per_task ?? null,
        max_extra_minutes: live.max_extra_minutes ?? null,
        max_extra_context_percent: live.max_extra_context_percent ?? null
      }
    }
  };
}

function booleanValue(value, fallback, name) {
  if (value === undefined || value === null || value === '') return fallback;
  if (typeof value === 'boolean') return value;
  if (String(value).toLowerCase() === 'true') return true;
  if (String(value).toLowerCase() === 'false') return false;
  const error = new Error(`${name} must be boolean`);
  error.code = 'repair_setting_invalid';
  throw error;
}

function boundedInteger(value, fallback, name, min, max) {
  if (value === undefined || value === null || value === '') return fallback;
  const number = Number(value);
  if (!Number.isInteger(number) || number < min || number > max) {
    const error = new Error(`${name} must be an integer from ${min} to ${max}`);
    error.code = 'repair_setting_invalid';
    throw error;
  }
  return number;
}

function rejectSourceHealthOverride(raw) {
  if (!raw || typeof raw !== 'object') return;
  if (Object.prototype.hasOwnProperty.call(raw, 'edit_source_for_health')) {
    const error = new Error('edit_source_for_health is a hard safety invariant and cannot be configured');
    error.code = 'repair_source_health_override_forbidden';
    throw error;
  }
}

function normalizePolicy(raw = {}, base = DEFAULT_REPAIR_POLICY) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    const error = new Error('repair_on_touch settings must be an object');
    error.code = 'repair_setting_invalid';
    throw error;
  }
  rejectSourceHealthOverride(raw);
  const current = { ...DEFAULT_REPAIR_POLICY, ...(base || {}) };
  const policy = {
    enabled: booleanValue(raw.enabled, current.enabled, 'enabled'),
    mode: canonicalMode(raw.mode, canonicalMode(current.mode, 'scoped')),
    max_findings_per_task: boundedInteger(raw.max_findings_per_task, current.max_findings_per_task, 'max_findings_per_task', 0, 100),
    max_extra_minutes: boundedInteger(raw.max_extra_minutes, current.max_extra_minutes, 'max_extra_minutes', 0, 1440),
    max_extra_context_percent: boundedInteger(raw.max_extra_context_percent, current.max_extra_context_percent, 'max_extra_context_percent', 0, 100),
    rebuild_generated_artifacts: booleanValue(raw.rebuild_generated_artifacts, current.rebuild_generated_artifacts, 'rebuild_generated_artifacts'),
    edit_curated_knowledge: raw.edit_curated_knowledge === undefined
      ? current.edit_curated_knowledge
      : String(raw.edit_curated_knowledge),
    require_confirmation_for_critical_paths: booleanValue(
      raw.require_confirmation_for_critical_paths,
      current.require_confirmation_for_critical_paths,
      'require_confirmation_for_critical_paths'
    ),
    require_confirmation_for_security_findings: booleanValue(
      raw.require_confirmation_for_security_findings,
      current.require_confirmation_for_security_findings,
      'require_confirmation_for_security_findings'
    ),
    include_task_readiness: booleanValue(raw.include_task_readiness, current.include_task_readiness, 'include_task_readiness'),
    show_final_maintenance_summary: booleanValue(
      raw.show_final_maintenance_summary,
      current.show_final_maintenance_summary,
      'show_final_maintenance_summary'
    )
  };
  if (policy.edit_curated_knowledge !== 'verified_only') {
    const error = new Error('edit_curated_knowledge must remain verified_only');
    error.code = 'repair_curated_edit_policy_invalid';
    throw error;
  }
  return policy;
}

function parseYamlScalar(raw) {
  const value = String(raw || '').trim().replace(/\s+#.*$/, '');
  if (/^(true|false)$/i.test(value)) return value.toLowerCase() === 'true';
  if (/^-?\d+$/.test(value)) return Number(value);
  return value.replace(/^['"]|['"]$/g, '');
}

function parseRepositoryRepairSettings(yamlText) {
  const output = {};
  const stack = [];
  for (const line of String(yamlText || '').split(/\r?\n/)) {
    if (!line.trim() || /^\s*#/.test(line)) continue;
    const match = line.match(/^(\s*)([A-Za-z0-9_-]+):(?:\s*(.*))?$/);
    if (!match) continue;
    const indent = match[1].length;
    const key = match[2];
    const rawValue = match[3];
    while (stack.length && stack[stack.length - 1].indent >= indent) stack.pop();
    const parents = stack.map((item) => item.key);
    if (rawValue === undefined || rawValue === '') {
      stack.push({ indent, key });
      continue;
    }
    if (parents.join('.') === 'maintenance.repair_on_touch') output[key] = parseYamlScalar(rawValue);
  }
  return output;
}

function readRepositoryRepairSettings(projectKnowledgeRoot) {
  const configPath = path.join(projectKnowledgeRoot, 'config.yaml');
  if (!fs.existsSync(configPath)) return {};
  return parseRepositoryRepairSettings(fs.readFileSync(configPath, 'utf8'));
}

function operatorRepairSettings(profile = {}) {
  return profile?.maintenance?.repair_on_touch || {};
}

function teamPolicyCap(raw = {}) {
  const candidates = [
    raw?.team_policy?.repair_on_touch?.max_mode,
    raw?.security_policy?.repair_on_touch?.max_mode,
    raw?.maintenance?.repair_on_touch?.max_mode,
    raw?.repair_on_touch?.max_mode,
    raw?.team_policy_max_mode
  ];
  const declared = candidates
    .filter((item) => item !== undefined && item !== null && item !== '')
    .map((item) => canonicalMode(item));
  if (!declared.length) return null;
  return declared.reduce((strictest, candidate) =>
    MODE_RANK[candidate] < MODE_RANK[strictest] ? candidate : strictest
  );
}

function readTeamPolicy(context) {
  const statePolicy = readJson(path.join(context.stateRoot, 'maintenance', 'concurrency_policy.json'), {});
  const projectPolicy = context.stateRoot === context.projectKnowledgeRoot
    ? statePolicy
    : readJson(path.join(context.projectKnowledgeRoot, 'maintenance', 'concurrency_policy.json'), {});
  const stateCap = teamPolicyCap(statePolicy);
  const projectCap = teamPolicyCap(projectPolicy);
  const caps = [
    ...(stateCap ? [{ cap: stateCap, source: 'workspace team/security policy' }] : []),
    ...(projectCap && context.stateRoot !== context.projectKnowledgeRoot
      ? [{ cap: projectCap, source: 'repository team/security policy' }]
      : [])
  ];
  const selected = caps.reduce((strictest, candidate) =>
    !strictest || MODE_RANK[candidate.cap] < MODE_RANK[strictest.cap]
      ? candidate
      : strictest
  , null);
  return {
    cap: selected?.cap || null,
    source: selected?.source || null,
    sources: caps,
    raw: {
      workspace: statePolicy,
      ...(context.stateRoot !== context.projectKnowledgeRoot
        ? { repository: projectPolicy }
        : {})
    }
  };
}

function mergeSource(base, next, source, trace) {
  if (!next || typeof next !== 'object' || !Object.keys(next).length) return base;
  const normalized = normalizePolicy(next, base);
  for (const key of REQUIRED_POLICY_KEYS) {
    if (Object.prototype.hasOwnProperty.call(next, key)) trace[key] = source;
  }
  return normalized;
}

function capMode(configured, cap) {
  if (!cap) return configured;
  return MODE_RANK[configured] > MODE_RANK[cap] ? cap : configured;
}

function resolvePolicy({
  context,
  repository = null,
  operator = null,
  perRun = null,
  team = null
} = {}) {
  if (!context && (!repository || !operator)) throw new Error('context or explicit policy sources are required');
  const repositoryRaw = repository || readRepositoryRepairSettings(context.projectKnowledgeRoot);
  const operatorProfile = operator || readJson(path.join(context.projectKnowledgeRoot, 'settings', 'operator-profile.json'), {});
  const operatorRaw = operatorRepairSettings(operatorProfile);
  const teamInfo = team || readTeamPolicy(context);
  const trace = Object.fromEntries(REQUIRED_POLICY_KEYS.map((key) => [key, 'built-in default']));
  let configured = normalizePolicy(DEFAULT_REPAIR_POLICY);
  configured = mergeSource(configured, repositoryRaw, 'repository setting', trace);
  configured = mergeSource(configured, operatorRaw, 'operator/workspace setting', trace);
  configured = mergeSource(configured, perRun || {}, 'per-run override', trace);
  const configuredMode = configured.enabled ? configured.mode : 'off';
  const effectiveMode = capMode(configuredMode, teamInfo.cap || null);
  const capped = effectiveMode !== configuredMode;
  return {
    schema_version: SETTINGS_SCHEMA,
    configured: { ...configured, mode: configuredMode },
    configured_mode: configuredMode,
    effective: { ...configured, enabled: effectiveMode !== 'off', mode: effectiveMode },
    effective_mode: effectiveMode,
    effective_mode_label: MODE_LABELS[effectiveMode],
    effective_mode_source: capped ? 'team/security policy cap' : trace.mode,
    setting_sources: trace,
    policy_cap: {
      active: Boolean(teamInfo.cap),
      max_mode: teamInfo.cap || null,
      source: teamInfo.source || null,
      restricted: capped
    },
    hard_safety: HARD_SAFETY
  };
}

function saveOperatorRepairSettings(context, raw = {}, options = {}) {
  const settingsPath = path.join(context.projectKnowledgeRoot, 'settings', 'operator-profile.json');
  const profile = readJson(settingsPath, {
    schema_version: '3.3.0',
    user_mode: 'simple',
    first_run_onboarding_completed: false,
    connected_agents: [],
    agent_overrides: {}
  });
  const policy = options.reset
    ? normalizePolicy(DEFAULT_REPAIR_POLICY)
    : normalizePolicy(raw, operatorRepairSettings(profile)?.mode ? operatorRepairSettings(profile) : DEFAULT_REPAIR_POLICY);
  profile.schema_version = '3.3.0';
  profile.maintenance = {
    ...(profile.maintenance || {}),
    repair_on_touch: {
      ...policy,
      updated_at: options.updatedAt || new Date().toISOString(),
      updated_by: options.updatedBy || 'operator'
    }
  };
  writeJsonAtomic(settingsPath, profile);
  return {
    profile,
    policy: resolvePolicy({ context, operator: profile, perRun: options.perRun || null })
  };
}

function severityCost(severity) {
  if (severity === 'critical') return 25;
  if (severity === 'high') return 15;
  if (severity === 'medium') return 7;
  return 3;
}

function defaultRepairClass(code, artifact) {
  const normalized = canonicalCode(code);
  if (PROTECTED_CODES.has(normalized) || requiresDedicatedVerifier(normalized)) return 'dedicated_action_required';
  if (/routing_bundle|search_index|wiki_graph|generated|runtime_file|report/.test(normalized) ||
      /\/(routing_bundle|index|wiki_graph|quality_report)\.(json|md)$/i.test(String(artifact || ''))) {
    return 'rebuild_generated_artifact';
  }
  if (/low_confidence|suspect|needs_recheck|stale|tracked_file/.test(normalized)) return 'verify_on_touch';
  return 'manual_review';
}

function requiredChecksFor(repairClass) {
  if (GENERATED_REPAIR_CLASSES.has(repairClass)) return ['rebuild_with_first_party_tool', 'validate_generated_artifact'];
  if (repairClass === 'verify_on_touch') return ['read_current_source', 'run_relevant_tests', 'compare_existing_claims'];
  return [
    'read_current_source',
    'run_relevant_tests',
    'compare_existing_claims',
    'dedicated_review'
  ];
}

function generatedProducerTool(rawFinding = {}) {
  const code = canonicalCode(rawFinding.code || 'unknown');
  const artifact = canonicalPath(
    rawFinding.artifact ||
    rawFinding.primary_artifact ||
    rawFinding.affected_artifacts?.[0]
  );
  if (
    artifact === '.knowledge/search/index.json' ||
    code === 'search_index_missing' ||
    code === 'search_index_stale'
  ) {
    return '.knowledge/tools/build-search-index.js';
  }
  if (
    artifact === '.knowledge/maintenance/routing_bundle.json' ||
    code === 'routing_bundle_missing' ||
    code === 'routing_bundle_stale'
  ) {
    return '.knowledge/tools/build-routing-bundle.js';
  }
  if (
    artifact === '.knowledge/maps/wiki_graph.json' ||
    code === 'wiki_graph_missing' ||
    code === 'wiki_graph_stale'
  ) {
    return '.knowledge/tools/build-wiki-graph.js';
  }
  return null;
}

function generatedProducerDependencyClosure(toolPath) {
  const normalized = canonicalPath(toolPath || '');
  return [...(GENERATED_REBUILD_DEPENDENCIES[normalized] || [])];
}

function granularFinding(raw = {}) {
  const code = canonicalCode(raw.code || 'unknown');
  const moduleId = canonicalModule(raw.module_id || 'root');
  const affected = Array.from(new Set(
    [...(raw.affected_artifacts || []), raw.artifact].filter(Boolean).map((item) => canonicalPath(item))
  )).sort();
  const artifact = canonicalPath(
    raw.artifact ||
    raw.primary_artifact ||
    affected[0] ||
    '.knowledge/maintenance/quality_report.json'
  );
  if (!affected.includes(artifact)) affected.unshift(artifact);
  const repairClass = raw.repair_class || defaultRepairClass(code, artifact);
  const findingForId = {
    module_id: moduleId,
    code,
    artifact,
    affected_artifacts: affected
  };
  return {
    lifecycle_id: raw.lifecycle_id || stableId('LC', findingForId),
    code,
    module_id: moduleId,
    artifact,
    affected_artifacts: affected,
    message: privacySafeText(raw.message || raw.reason || code),
    severity: raw.severity || 'low',
    score_cost: Number.isFinite(Number(raw.score_cost)) ? Number(raw.score_cost) : severityCost(raw.severity || 'low'),
    repair_class: repairClass,
    required_checks: Array.from(new Set(raw.required_checks || requiredChecksFor(repairClass))),
    resolution_predicate: raw.resolution_predicate || (
      GENERATED_REPAIR_CLASSES.has(repairClass)
        ? 'first_party_rebuild_and_validation_pass'
        : repairClass === 'verify_on_touch'
          ? 'source_and_relevant_tests_confirm_claim'
          : 'dedicated_review_required'
    ),
    safe_during_current_task: raw.safe_during_current_task !== false &&
      repairClass !== 'dedicated_action_required' &&
      !PROTECTED_CODES.has(code),
    critical_path: Boolean(raw.critical_path),
    security_sensitive: Boolean(raw.security_sensitive || code === 'security_finding'),
    status: raw.status || 'open',
    estimated_additional_work: {
      minutes: Math.max(0, Number(raw.estimated_additional_work?.minutes ?? (GENERATED_REPAIR_CLASSES.has(repairClass) ? 1 : 2))),
      context_percent: Math.max(0, Number(raw.estimated_additional_work?.context_percent ?? (GENERATED_REPAIR_CLASSES.has(repairClass) ? 1 : 4)))
    },
    ...(raw.occurrence !== undefined ? { occurrence: Number(raw.occurrence) } : {}),
    ...(raw.opened_at ? { opened_at: String(raw.opened_at) } : {}),
    ...(raw.reopened_at ? { reopened_at: String(raw.reopened_at) } : {})
  };
}

function normalizeList(values, mapper = (item) => String(item)) {
  return Array.from(new Set(
    (values || []).filter(Boolean).map(mapper).filter(Boolean)
  )).sort();
}

function moduleIdentifier(value) {
  if (typeof value === 'string' || typeof value === 'number') return value;
  if (!value || typeof value !== 'object') return null;
  return value.module_id ?? value.moduleId ?? value.id ?? value.name ?? null;
}

function canonicalScopeModule(value) {
  // Task scope and lifecycle identity must agree exactly. Human-facing aliases
  // are resolved by routing before this boundary; collapsing '-' and '_' here
  // would let one valid registry module authorize work on another.
  return canonicalModule(value);
}

function scopeHasModule(values, moduleId) {
  const wanted = canonicalScopeModule(moduleId);
  return (values || []).some((value) => canonicalScopeModule(moduleIdentifier(value)) === wanted);
}

function normalizeModules(values) {
  return normalizeList(values, (item) => {
    const identifier = moduleIdentifier(item);
    return identifier === null || identifier === undefined || identifier === ''
      ? null
      : canonicalScopeModule(identifier);
  });
}

function routingModules(routing = {}) {
  return normalizeModules([
    ...(routing.selected_modules || []),
    ...(routing.modules || []),
    ...(routing.routing?.selected_modules || [])
  ]);
}

function changedPathsFromDiff(diff = '') {
  const files = [];
  for (const line of String(diff || '').split(/\r?\n/)) {
    const match = line.match(/^(?:\+\+\+|---)\s+(?:[ab]\/)?(.+)$/);
    if (match && match[1] !== '/dev/null') files.push(match[1]);
  }
  return normalizeList(files, canonicalPath);
}

function buildTaskScope(raw = {}) {
  const directModules = normalizeModules([
    ...(raw.selected_modules || []),
    ...(raw.modules || []),
    ...routingModules(raw.routing),
    ...(raw.pr_impact?.affected_modules || [])
  ]);
  const directArtifacts = normalizeList([
    ...(raw.changed_files || []),
    ...(raw.files || []),
    ...(raw.pr_impact?.changed_files || []),
    ...changedPathsFromDiff(raw.diff)
  ], canonicalPath);
  const dependencyModules = normalizeModules([
    ...(raw.dependency_modules || []),
    ...(raw.dependency_neighborhood?.modules || [])
  ]);
  const dependencyArtifacts = normalizeList([
    ...(raw.dependency_files || []),
    ...(raw.dependency_neighborhood?.files || [])
  ], canonicalPath);
  const criticalPaths = normalizeList([
    ...(raw.critical_paths || []),
    ...(raw.critical_path_map?.files || []).map((item) => item.path || item.file || item)
  ], canonicalPath);
  if (
    secretPaths([
      directModules,
      directArtifacts,
      dependencyModules,
      dependencyArtifacts,
      criticalPaths
    ]).length ||
    privateValuePaths([
      directModules,
      directArtifacts,
      dependencyModules,
      dependencyArtifacts,
      criticalPaths
    ]).length
  ) {
    const error = new Error(
      'Task scope paths and module IDs must be repository-relative and privacy-safe'
    );
    error.code = 'repair_scope_private_path';
    throw error;
  }
  const taskText = String(raw.user_task || raw.task || '').trim();
  const requestedTaskId = String(
    raw.task_id ||
    raw.taskId ||
    `task-${sha256(taskText || stableJson(raw)).slice(0, 16)}`
  );
  const requestedSessionId = String(
    raw.session_id ||
    raw.sessionId ||
    `session-${crypto.randomUUID()}`
  );
  if (
    secretPaths([requestedTaskId, requestedSessionId]).length ||
    privateValuePaths([requestedTaskId, requestedSessionId]).length
  ) {
    const error = new Error(
      'Task and session identifiers cannot contain private or secret-like data'
    );
    error.code = 'repair_scope_private_identity';
    throw error;
  }
  const taskWords = new Set(taskText.toLowerCase().split(/[^a-z0-9_-]+/).filter((word) => word.length > 2));
  for (const moduleId of [...dependencyModules]) {
    if (taskWords.has(moduleId) && !directModules.includes(moduleId)) directModules.push(moduleId);
  }
  directModules.sort();
  const scope = {
    schema_version: 'knowledge-task-scope.v1',
    task_id: requestedTaskId,
    session_id: requestedSessionId,
    user_task: privacySafeText(taskText),
    direct_modules: directModules,
    direct_artifacts: directArtifacts,
    dependency_modules: dependencyModules,
    dependency_artifacts: dependencyArtifacts,
    essential_dependency_modules: normalizeModules(raw.essential_dependency_modules || []),
    essential_dependency_reason: privacySafeText(
      raw.essential_dependency_reason || ''
    ),
    critical_paths: criticalPaths,
    agent_plan: (
      Array.isArray(raw.agent_plan)
        ? raw.agent_plan
        : raw.agent_plan
          ? [raw.agent_plan]
          : []
    ).map(privacySafeText),
    source_signals: {
      user_task: Boolean(taskText),
      routing: Boolean(raw.routing),
      changed_files: directArtifacts.length,
      diff: Boolean(raw.diff),
      pr_impact: Boolean(raw.pr_impact),
      selected_modules: directModules.length,
      critical_paths: criticalPaths.length,
      dependency_neighborhood: dependencyModules.length + dependencyArtifacts.length,
      agent_plan: Boolean(raw.agent_plan)
    }
  };
  scope.scope_hash = taskScopeDigest(scope);
  return scope;
}

function taskScopeDigest(scope) {
  const canonical = JSON.parse(JSON.stringify(scope || {}));
  delete canonical.scope_hash;
  return sha256(stableJson(canonical));
}

function validateTaskScope(scope) {
  const errors = [];
  if (!scope || typeof scope !== 'object' || Array.isArray(scope)) {
    return { ok: false, errors: ['task_scope_object_required'], digest: null };
  }
  if (scope.schema_version !== 'knowledge-task-scope.v1') {
    errors.push('task_scope_schema_invalid');
  }
  if (!scope.task_id) errors.push('task_scope_task_id_required');
  if (!scope.session_id) errors.push('task_scope_session_id_required');
  for (const field of [
    'direct_modules',
    'direct_artifacts',
    'dependency_modules',
    'dependency_artifacts',
    'essential_dependency_modules',
    'critical_paths',
    'agent_plan'
  ]) {
    if (!Array.isArray(scope[field])) errors.push(`task_scope_field_invalid:${field}`);
  }
  const digest = taskScopeDigest(scope);
  if (
    !/^[a-f0-9]{64}$/.test(String(scope.scope_hash || '')) ||
    scope.scope_hash !== digest
  ) {
    errors.push('task_scope_hash_invalid');
  }
  return { ok: errors.length === 0, errors, digest };
}

function repairSessionKey(taskId, sessionId) {
  const task = String(taskId || '');
  const session = String(sessionId || '');
  if (!task || !session) {
    const error = new Error('Repair session identity requires task_id and session_id');
    error.code = 'repair_plan_scope_required';
    throw error;
  }
  return sha256(stableJson({ task_id: task, session_id: session }));
}

function repairSessionPlanRelative(taskId, sessionId) {
  return `maintenance/repair_sessions/${repairSessionKey(taskId, sessionId)}.json`;
}

function repairPlanError(code, message, validation = null) {
  const error = new Error(message);
  error.code = code;
  if (validation) error.validation = validation;
  return error;
}

function validateRepairPlanArtifact(artifact) {
  const errors = [];
  if (!artifact || typeof artifact !== 'object' || Array.isArray(artifact)) {
    return { ok: false, errors: ['repair_plan_object_required'] };
  }
  const schemaValidation = validateBundledSchema(
    'repair-opportunities.schema.json',
    artifact
  );
  errors.push(...schemaValidation.errors.map((item) =>
    `repair_plan_schema_contract:${item}`));
  if (secretPaths(artifact).length) {
    errors.push('repair_plan_secret_like_value');
  }
  if (privateValuePaths(artifact).length) {
    errors.push('repair_plan_private_value');
  }
  if (
    Buffer.byteLength(`${JSON.stringify(artifact, null, 2)}\n`) >
    MAX_REPAIR_PLAN_BYTES
  ) {
    errors.push('repair_plan_size_exceeded');
  }
  const scopeValidation = validateTaskScope(artifact.task_scope);
  errors.push(...scopeValidation.errors);
  const policy = artifact.repair_on_touch;
  const effective = policy?.effective;
  let effectiveMode = null;
  try {
    effectiveMode = canonicalMode(policy?.effective_mode, null);
  } catch {
    errors.push('repair_plan_effective_mode_invalid');
  }
  if (
    !policy ||
    typeof policy !== 'object' ||
    !effective ||
    typeof effective !== 'object' ||
    !effectiveMode ||
    effective.mode !== effectiveMode ||
    typeof effective.enabled !== 'boolean'
  ) {
    errors.push('repair_plan_policy_invalid');
  }
  const limits = artifact.budget?.limits;
  const numericLimits = [
    ['max_findings_per_task', 100],
    ['max_extra_minutes', 1440],
    ['max_extra_context_percent', 100]
  ];
  for (const [key, maximum] of numericLimits) {
    const value = effective?.[key];
    if (!Number.isInteger(value) || value < 0 || value > maximum) {
      errors.push(`repair_plan_policy_limit_invalid:${key}`);
    }
    if (limits?.[key] !== value) {
      errors.push(`repair_plan_budget_limit_mismatch:${key}`);
    }
  }
  const opportunities = Array.isArray(artifact.opportunities)
    ? artifact.opportunities
    : [];
  if (!Array.isArray(artifact.opportunities)) {
    errors.push('repair_plan_opportunities_invalid');
  }
  const lifecycleIds = new Set();
  let selectedCount = 0;
  let selectedMinutes = 0;
  let selectedContext = 0;
  let deferredCount = 0;
  for (const item of opportunities) {
    if (!item || typeof item !== 'object' || Array.isArray(item)) {
      errors.push('repair_plan_opportunity_invalid');
      continue;
    }
    if (
      !/^LC-[a-f0-9]{16}$/.test(String(item.lifecycle_id || '')) ||
      lifecycleIds.has(item.lifecycle_id)
    ) {
      errors.push('repair_plan_lifecycle_id_noncanonical');
    }
    lifecycleIds.add(item.lifecycle_id);
    if (!['selected', 'deferred', 'repaired', 'rejected'].includes(item.status)) {
      errors.push(`repair_plan_status_invalid:${item.lifecycle_id || 'missing'}`);
    }
    if (!PLAN_DECISION_REASONS.has(String(item.decision_reason || ''))) {
      errors.push(
        `repair_plan_decision_reason_invalid:${item.lifecycle_id || 'missing'}`
      );
    }
    if (
      item.confirmation_evidence !== undefined &&
      (
        !item.confirmation_evidence ||
        typeof item.confirmation_evidence !== 'object' ||
        Array.isArray(item.confirmation_evidence) ||
        typeof item.confirmation_evidence.critical_path !== 'boolean' ||
        typeof item.confirmation_evidence.security_finding !== 'boolean' ||
        typeof item.confirmation_evidence.exact_finding !== 'boolean'
      )
    ) {
      errors.push(
        `repair_plan_confirmation_evidence_invalid:${item.lifecycle_id || 'missing'}`
      );
    }
    if (
      !Array.isArray(item.required_checks) ||
      !item.required_checks.length ||
      new Set(item.required_checks.map(String)).size !==
        item.required_checks.length
    ) {
      errors.push(
        `repair_plan_required_checks_invalid:${item.lifecycle_id || 'missing'}`
      );
    }
    const minutes = Number(item.estimated_additional_work?.minutes);
    const contextPercent = Number(
      item.estimated_additional_work?.context_percent
    );
    if (
      !Number.isFinite(minutes) ||
      minutes < 0 ||
      !Number.isFinite(contextPercent) ||
      contextPercent < 0 ||
      contextPercent > 100
    ) {
      errors.push(
        `repair_plan_estimate_invalid:${item.lifecycle_id || 'missing'}`
      );
    }
    if (['selected', 'repaired'].includes(item.status)) {
      selectedCount += 1;
      selectedMinutes += Number.isFinite(minutes) ? minutes : 0;
      selectedContext += Number.isFinite(contextPercent)
        ? contextPercent
        : 0;
    }
    if (item.status === 'deferred') deferredCount += 1;
  }
  const summary = artifact.summary || {};
  if (
    summary.findings_considered !== opportunities.length ||
    summary.findings_selected !== selectedCount ||
    summary.findings_deferred !== deferredCount
  ) {
    errors.push('repair_plan_summary_mismatch');
  }
  const selected = artifact.budget?.selected || {};
  if (
    selected.findings !== selectedCount ||
    selected.estimated_minutes !== selectedMinutes ||
    selected.estimated_context_percent !== selectedContext ||
    typeof artifact.budget?.exhausted !== 'boolean'
  ) {
    errors.push('repair_plan_budget_selected_mismatch');
  }
  for (const readiness of [
    artifact.task_readiness,
    artifact.task_readiness_after
  ].filter(Boolean)) {
    if (
      !Number.isFinite(readiness.score) ||
      readiness.score < 0 ||
      readiness.score > 100 ||
      !['ready', 'ready_with_warnings', 'needs_verification'].includes(
        readiness.status
      )
    ) {
      errors.push('repair_plan_readiness_invalid');
    }
  }
  return { ok: errors.length === 0, errors: Array.from(new Set(errors)) };
}

function readRepairPlanFile(
  directory,
  filename,
  taskId,
  sessionId,
  relativePath,
  { ignoreScopeMismatch = false } = {}
) {
  const target = path.join(directory, filename);
  let stat;
  try {
    stat = fs.lstatSync(target);
  } catch (error) {
    if (error.code === 'ENOENT') return null;
    throw error;
  }
  if (
    !stat.isFile() ||
    stat.isSymbolicLink() ||
    stat.size <= 0 ||
    stat.size > MAX_REPAIR_PLAN_BYTES
  ) {
    throw repairPlanError(
      'repair_plan_file_invalid',
      `Repair plan is not a safe bounded regular file: ${relativePath}`
    );
  }
  const real = fs.realpathSync(target);
  if (path.relative(directory, real).replace(/\\/g, '/') !== filename) {
    throw repairPlanError(
      'repair_plan_path_invalid',
      `Repair plan escaped its trusted store: ${relativePath}`
    );
  }
  let artifact;
  let body;
  try {
    body = fs.readFileSync(real);
    artifact = JSON.parse(body.toString('utf8').replace(/^\uFEFF/, ''));
  } catch {
    throw repairPlanError(
      'repair_plan_file_invalid',
      `Repair plan is not valid JSON: ${relativePath}`
    );
  }
  const planValidation = validateRepairPlanArtifact(artifact);
  if (!planValidation.ok) {
    throw repairPlanError(
      'repair_plan_schema_invalid',
      `Repair plan has an invalid schema: ${relativePath}`,
      planValidation
    );
  }
  const validation = validateTaskScope(artifact.task_scope);
  if (!validation.ok) {
    throw repairPlanError(
      'repair_plan_scope_invalid',
      `Repair plan has an invalid task scope: ${relativePath}`,
      validation
    );
  }
  if (
    String(artifact.task_scope.task_id) !== String(taskId) ||
    String(artifact.task_scope.session_id) !== String(sessionId)
  ) {
    if (ignoreScopeMismatch) return null;
    throw repairPlanError(
      'repair_plan_scope_invalid',
      `Repair plan does not bind the requested task/session: ${relativePath}`,
      validation
    );
  }
  return {
    artifact,
    path: real,
    relative_path: relativePath,
    content_sha256: sha256(body)
  };
}

function loadRepairPlan(
  stateRoot,
  taskId,
  sessionId,
  { allowExactLegacy = true } = {}
) {
  const key = repairSessionKey(taskId, sessionId);
  const relative = repairSessionPlanRelative(taskId, sessionId);
  let scoped = null;
  try {
    const directory = secureStateStore(
      stateRoot,
      'maintenance/repair_sessions'
    );
    scoped = readRepairPlanFile(
      directory,
      `${key}.json`,
      taskId,
      sessionId,
      relative
    );
  } catch (error) {
    if (error.code !== 'verification_store_missing') throw error;
  }
  if (scoped) {
    return {
      plan_id: `KRPS-${key}`,
      ...scoped,
      legacy: false
    };
  }
  if (allowExactLegacy) {
    const maintenance = secureStateStore(stateRoot, 'maintenance');
    const legacy = readRepairPlanFile(
      maintenance,
      'repair_opportunities.json',
      taskId,
      sessionId,
      'maintenance/repair_opportunities.json',
      { ignoreScopeMismatch: true }
    );
    if (legacy) {
      return {
        plan_id: `KRPS-${key}`,
        ...legacy,
        legacy: true
      };
    }
  }
  return {
    plan_id: `KRPS-${key}`,
    relative_path: relative,
    path: null,
    artifact: null,
    legacy: false
  };
}

function pathOverlaps(left, right) {
  const a = canonicalPath(left);
  const b = canonicalPath(right);
  return a === b || a.startsWith(`${b}/`) || b.startsWith(`${a}/`);
}

function relationToTask(rawFinding, scope) {
  const finding = granularFinding(rawFinding);
  if (scopeHasModule(scope.direct_modules, finding.module_id) ||
      finding.affected_artifacts.some((artifact) => scope.direct_artifacts.some((candidate) => pathOverlaps(artifact, candidate)))) {
    return 'direct_overlap';
  }
  if (scopeHasModule(scope.dependency_modules, finding.module_id) ||
      finding.affected_artifacts.some((artifact) => scope.dependency_artifacts.some((candidate) => pathOverlaps(artifact, candidate)))) {
    return 'dependency_overlap';
  }
  return 'no_overlap';
}

function confirmationRequired(finding, policy, confirmations = {}) {
  const exactFindingConfirmed = Boolean(
    confirmations[finding.lifecycle_id] ||
    (Array.isArray(confirmations.findings) &&
      confirmations.findings.map(String).includes(finding.lifecycle_id))
  );
  if (finding.security_sensitive && policy.require_confirmation_for_security_findings &&
      !confirmations.security_findings && !exactFindingConfirmed) return 'security_confirmation_required';
  if (finding.critical_path && policy.require_confirmation_for_critical_paths &&
      !confirmations.critical_paths && !exactFindingConfirmed) return 'critical_path_confirmation_required';
  return null;
}

function selectOpportunities({
  findings = [],
  scope,
  policyResolution,
  dedicatedRun = false,
  confirmations = {}
}) {
  const policy = policyResolution?.effective || normalizePolicy(DEFAULT_REPAIR_POLICY);
  const mode = policy.mode;
  const normalized = findings.map(granularFinding)
    .filter((finding) => !['closed', 'resolved'].includes(finding.status))
    .map((finding) => ({ ...finding, relation_to_current_task: relationToTask(finding, scope) }))
    .sort((a, b) => {
      const relationOrder = { direct_overlap: 0, dependency_overlap: 1, no_overlap: 2 };
      const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
      return relationOrder[a.relation_to_current_task] - relationOrder[b.relation_to_current_task] ||
        severityOrder[a.severity] - severityOrder[b.severity] ||
        a.lifecycle_id.localeCompare(b.lifecycle_id);
    });
  let selectedCount = 0;
  let selectedMinutes = 0;
  let selectedContext = 0;
  const opportunities = [];
  for (const finding of normalized) {
    let status = 'selected';
    let decisionReason = 'task_relevant_and_within_budget';
    const protectedFinding = Boolean(dedicatedRequirementFor(finding));
    const exactConfirmed = Boolean(
      confirmations[finding.lifecycle_id] ||
      (Array.isArray(confirmations.findings)
        ? confirmations.findings.map(String)
        : []).includes(finding.lifecycle_id)
    );
    const confirmationEvidence = {
      critical_path: Boolean(
        finding.critical_path &&
        (confirmations.critical_paths || exactConfirmed)
      ),
      security_finding: Boolean(
        finding.security_sensitive &&
        (confirmations.security_findings || exactConfirmed)
      ),
      exact_finding: exactConfirmed
    };
    const dedicatedPolicyBlocked = Boolean(
      policyResolution?.policy_cap?.active &&
      !['dedicated', 'aggressive'].includes(policyResolution.policy_cap.max_mode)
    );
    const confirmation = confirmationRequired(finding, policy, confirmations);
    if (mode === 'off') {
      status = 'deferred';
      decisionReason = 'mode_off';
    } else if (
      GENERATED_REPAIR_CLASSES.has(finding.repair_class) &&
      policy.rebuild_generated_artifacts === false
    ) {
      status = 'deferred';
      decisionReason = 'generated_rebuild_disabled';
    } else if (
      GENERATED_REPAIR_CLASSES.has(finding.repair_class) &&
      !generatedProducerTool(finding)
    ) {
      status = 'deferred';
      decisionReason = 'generated_producer_unmapped';
    } else if (protectedFinding && dedicatedPolicyBlocked) {
      status = 'deferred';
      decisionReason = 'dedicated_blocked_by_policy_cap';
    } else if (mode === 'dedicated' && !dedicatedRun) {
      status = 'deferred';
      decisionReason = 'dedicated_run_required';
    } else if (protectedFinding && !(mode === 'dedicated' && dedicatedRun)) {
      status = 'deferred';
      decisionReason = 'dedicated_action_required';
    } else if (protectedFinding && !exactConfirmed) {
      status = 'deferred';
      decisionReason = 'dedicated_exact_confirmation_required';
    } else if (mode === 'safe-only' && !GENERATED_REPAIR_CLASSES.has(finding.repair_class)) {
      status = 'deferred';
      decisionReason = 'safe_only_curated_repair_forbidden';
    } else if (!finding.safe_during_current_task &&
      !(protectedFinding && mode === 'dedicated' && dedicatedRun && exactConfirmed)) {
      status = 'deferred';
      decisionReason = 'not_safe_during_current_task';
    } else if (confirmation) {
      status = 'deferred';
      decisionReason = confirmation;
    } else if (finding.relation_to_current_task === 'no_overlap' && !(mode === 'dedicated' && dedicatedRun)) {
      status = 'deferred';
      decisionReason = 'outside_task_scope';
    } else if (finding.relation_to_current_task === 'dependency_overlap' && mode === 'scoped' &&
      !scopeHasModule(scope.essential_dependency_modules, finding.module_id)) {
      status = 'deferred';
      decisionReason = 'dependency_not_essential';
    } else if (finding.relation_to_current_task === 'dependency_overlap' && mode === 'scoped' &&
      !scope.essential_dependency_reason) {
      status = 'deferred';
      decisionReason = 'essential_dependency_reason_missing';
    } else if (selectedCount >= policy.max_findings_per_task) {
      status = 'deferred';
      decisionReason = 'budget_exhausted_max_findings';
    } else if (selectedMinutes + finding.estimated_additional_work.minutes > policy.max_extra_minutes) {
      status = 'deferred';
      decisionReason = 'budget_exhausted_time';
    } else if (selectedContext + finding.estimated_additional_work.context_percent > policy.max_extra_context_percent) {
      status = 'deferred';
      decisionReason = 'budget_exhausted_context';
    }
    if (status === 'selected') {
      selectedCount += 1;
      selectedMinutes += finding.estimated_additional_work.minutes;
      selectedContext += finding.estimated_additional_work.context_percent;
    }
    opportunities.push({
      ...finding,
      status,
      decision_reason: decisionReason,
      requires_confirmation: Boolean(confirmation),
      confirmation_evidence: confirmationEvidence,
      safe_during_current_task: finding.safe_during_current_task && !protectedFinding
    });
  }
  return {
    opportunities,
    budget: {
      limits: {
        max_findings_per_task: policy.max_findings_per_task,
        max_extra_minutes: policy.max_extra_minutes,
        max_extra_context_percent: policy.max_extra_context_percent
      },
      selected: {
        findings: selectedCount,
        estimated_minutes: selectedMinutes,
        estimated_context_percent: selectedContext
      },
      exhausted: opportunities.some((item) => item.decision_reason.startsWith('budget_exhausted'))
    }
  };
}

function taskReadiness(findings, scope) {
  const relevant = findings.map(granularFinding).filter((finding) => {
    const relation = relationToTask(finding, scope);
    return relation === 'direct_overlap' ||
      (relation === 'dependency_overlap' &&
        scopeHasModule(scope.essential_dependency_modules, finding.module_id));
  });
  const open = relevant.filter((finding) => !['closed', 'resolved', 'repaired'].includes(finding.status));
  const closed = relevant.length - open.length;
  const score = Math.max(0, 100 - open.reduce((sum, finding) => sum + finding.score_cost, 0));
  return {
    score,
    status: open.length === 0 ? 'ready' : score >= 80 ? 'ready_with_warnings' : 'needs_verification',
    relevant_findings_open: open.length,
    relevant_findings_closed: closed,
    relevant_lifecycle_ids: relevant.map((finding) => finding.lifecycle_id),
    excluded_unrelated_findings: Math.max(0, findings.length - relevant.length)
  };
}

function buildOpportunitiesArtifact({
  findings = [],
  scope,
  policyResolution,
  doctorScore = null,
  dedicatedRun = false,
  confirmations = {},
  generatedAt = new Date().toISOString(),
  generatedBy = 'unknown'
}) {
  const selection = selectOpportunities({ findings, scope, policyResolution, dedicatedRun, confirmations });
  const readiness = taskReadiness(findings, scope);
  return {
    schema_version: OPPORTUNITIES_SCHEMA,
    generated_at: generatedAt,
    generated_by: privacySafeText(generatedBy),
    task_scope: scope,
    repair_on_touch: policyResolution,
    global: {
      score: doctorScore,
      status: doctorScore === null ? 'unknown' : doctorScore >= 90 ? (findings.length ? 'healthy_with_debt' : 'healthy') : 'usable_with_warnings'
    },
    task_readiness: readiness,
    deferred_unrelated_findings: selection.opportunities.filter((item) =>
      item.status === 'deferred' && item.relation_to_current_task === 'no_overlap').length,
    summary: {
      findings_considered: selection.opportunities.length,
      findings_selected: selection.opportunities.filter((item) => item.status === 'selected').length,
      findings_deferred: selection.opportunities.filter((item) => item.status === 'deferred').length
    },
    budget: selection.budget,
    opportunities: selection.opportunities
  };
}

function secretPaths(value, at = '$', output = []) {
  if (Array.isArray(value)) {
    value.forEach((item, index) => secretPaths(item, `${at}[${index}]`, output));
    return output;
  }
  if (value && typeof value === 'object') {
    for (const [key, item] of Object.entries(value)) {
      if (SECRET_KEY_PATTERN.test(key) &&
          (typeof item === 'string' || (item && typeof item === 'object')) &&
          item !== '' && item !== '<redacted>') {
        output.push(`${at}.${key}`);
      }
      secretPaths(item, `${at}.${key}`, output);
    }
    return output;
  }
  if (typeof value === 'string' && SECRET_VALUE_PATTERN.test(value) && !/^<.*>$/.test(value)) output.push(at);
  return output;
}

function privateValuePaths(value, at = '$', output = []) {
  if (Array.isArray(value)) {
    value.forEach((item, index) => privateValuePaths(item, `${at}[${index}]`, output));
    return output;
  }
  if (value && typeof value === 'object') {
    for (const [key, item] of Object.entries(value)) privateValuePaths(item, `${at}.${key}`, output);
    return output;
  }
  if (typeof value !== 'string') return output;
  if (EMAIL_VALUE_PATTERN.test(value) ||
      WINDOWS_ABSOLUTE_PATH_PATTERN.test(value) ||
      POSIX_ABSOLUTE_PATH_PATTERN.test(value) ||
      /\b(?:127\.0\.0\.1|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b/.test(value)) {
    output.push(at);
  }
  return output;
}

function privacySafeText(value) {
  const text = String(value || '');
  return secretPaths(text).length || privateValuePaths(text).length
    ? '<redacted>'
    : text;
}

function canonicalReceiptInput(raw) {
  const copy = JSON.parse(JSON.stringify(raw || {}));
  delete copy.receipt_id;
  delete copy.content_sha256;
  delete copy.receipt_path;
  return copy;
}

function receiptDigest(raw) {
  return sha256(stableJson(canonicalReceiptInput(raw)));
}

function checkedPathMap(items = []) {
  return new Map(items
    .filter((item) => item && typeof item === 'object' && (item.path || item.file))
    .map((item) => [canonicalPath(item.path || item.file), item]));
}

function validateReceipt(raw, options = {}) {
  const errors = [];
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return { ok: false, errors: ['receipt_object_required'] };
  const identityBoundary =
    options.requireIdentity === true ||
    raw.receipt_id !== undefined ||
    raw.content_sha256 !== undefined;
  if (identityBoundary) {
    const schemaValidation = validateBundledSchema(
      'verification-receipt.schema.json',
      raw
    );
    errors.push(...schemaValidation.errors.map((item) =>
      `receipt_schema_contract:${item}`));
  }
  if (raw.schema_version !== RECEIPT_SCHEMA) errors.push('receipt_schema_invalid');
  if (!raw.finding_id) errors.push('finding_id_required');
  if (!raw.module_id) errors.push('module_id_required');
  if (!raw.task_id) errors.push('task_id_required');
  if (!raw.session_id) errors.push('session_id_required');
  if (!raw.task_scope || typeof raw.task_scope !== 'object') errors.push('task_scope_required');
  let mode = null;
  try { mode = canonicalMode(raw.repair_mode); } catch { errors.push('repair_mode_invalid'); }
  if (!mode) errors.push('repair_mode_required');
  const finding = options.finding ? granularFinding(options.finding) : null;
  let occurrence = null;
  if (!/^[a-f0-9]{64}$/.test(String(raw.finding_occurrence_sha256 || ''))) {
    errors.push('finding_occurrence_hash_required');
  }
  if (finding) {
    try {
      occurrence = findingOccurrence(finding);
      if (raw.finding_occurrence_sha256 !== occurrence.sha256) {
        errors.push('finding_occurrence_mismatch');
      }
    } catch {
      errors.push('finding_occurrence_invalid');
    }
  }
  if (finding && String(raw.finding_id) !== finding.lifecycle_id) errors.push('finding_id_mismatch');
  if (finding && canonicalModule(raw.module_id) !== finding.module_id) errors.push('module_id_mismatch');
  if (finding && String(raw.resolution_predicate || '') !== finding.resolution_predicate) errors.push('resolution_predicate_mismatch');
  if (raw.predicate_result !== 'pass' && raw.predicate_result !== true) errors.push('predicate_result_not_pass');
  const sourceFiles = Array.isArray(raw.source_files_checked) ? raw.source_files_checked : [];
  const tests = Array.isArray(raw.tests_run) ? raw.tests_run : [];
  const claims = Array.isArray(raw.claims_checked) ? raw.claims_checked : [];
  const executionTimestamps = [];
  const executionRecords = new Map();
  if (!sourceFiles.length) errors.push('source_files_checked_required');
  for (const item of sourceFiles) {
    if (
      !item ||
      typeof item !== 'object' ||
      !item.path ||
      !/^[a-f0-9]{64}$/i.test(String(item.sha256 || ''))
    ) {
      errors.push(`source_hash_invalid:${item?.path || 'missing'}`);
    }
  }
  if (!tests.length) errors.push('tests_run_required');
  for (const test of tests) {
    if (!test || typeof test !== 'object' ||
        !test.command || test.status !== 'pass' || Number(test.tests_passed) < 1 || Number(test.duration_ms) < 0 ||
        !/^KVE-[a-f0-9]{64}$/i.test(String(test.execution_id || '')) ||
        !/^[a-f0-9]{64}$/i.test(String(test.execution_sha256 || '')) ||
        !test.execution_path) {
      errors.push(`test_result_invalid:${test?.command || 'missing'}`);
      continue;
    }
    if (!options.stateRoot) {
      errors.push(`test_execution_state_unavailable:${test.execution_id}`);
      continue;
    }
    const loaded = loadExecutionRecord(options.stateRoot, test.execution_id);
    if (!loaded) {
      errors.push(`test_execution_not_found:${test.execution_id}`);
      continue;
    }
    const execution = loaded.record;
    executionRecords.set(test.execution_id, execution);
    const executedAtMs = Date.parse(String(execution.executed_at || ''));
    if (!Number.isFinite(executedAtMs)) {
      errors.push(`test_execution_timestamp_invalid:${test.execution_id}`);
    } else {
      executionTimestamps.push({
        execution_id: test.execution_id,
        executed_at_ms: executedAtMs
      });
    }
    const expectedPath = path.relative(options.stateRoot, loaded.path).replace(/\\/g, '/');
    if (execution.execution_id !== test.execution_id ||
        execution.content_sha256 !== String(test.execution_sha256).toLowerCase() ||
        expectedPath !== String(test.execution_path).replace(/\\/g, '/') ||
        execution.task_id !== String(raw.task_id) ||
        execution.session_id !== String(raw.session_id) ||
        execution.command !== test.command ||
        stableJson(execution.command_argv) !== stableJson(test.command_argv) ||
        execution.duration_ms !== test.duration_ms ||
        execution.status !== 'pass' ||
        execution.exit_code !== 0 ||
        execution.timed_out !== false ||
        execution.signal !== null ||
        execution.executed_by !== String(raw.checked_by || '') ||
        test.exit_code !== execution.exit_code ||
        String(test.stdout_sha256 || '').toLowerCase() !== execution.stdout_sha256 ||
        String(test.stderr_sha256 || '').toLowerCase() !== execution.stderr_sha256) {
      errors.push(`test_execution_mismatch:${test.execution_id}`);
    }
    const receiptSources = new Map(sourceFiles
      .filter((item) => item && typeof item === 'object' && item.path)
      .map((item) => [
        canonicalPath(item.path),
        String(item.sha256 || '').toLowerCase()
      ]));
    for (const source of execution.source_snapshot || []) {
      if (receiptSources.get(canonicalPath(source.path)) !== String(source.sha256).toLowerCase()) {
        errors.push(`test_source_snapshot_mismatch:${test.execution_id}:${source.path}`);
      }
    }
    for (const [sourcePath, sourceHash] of receiptSources) {
      if (!(execution.source_snapshot || []).some((item) =>
        canonicalPath(item.path) === sourcePath && String(item.sha256).toLowerCase() === sourceHash)) {
        errors.push(`test_source_snapshot_incomplete:${test.execution_id}:${sourcePath}`);
      }
    }
  }
  const checkedAtMs = Date.parse(String(raw.checked_at || ''));
  if (!Number.isFinite(checkedAtMs)) {
    errors.push('checked_at_invalid');
  } else {
    if (checkedAtMs > Date.now() + 5 * 60 * 1000) errors.push('checked_at_in_future');
    for (const execution of executionTimestamps) {
      if (checkedAtMs < execution.executed_at_ms) {
        errors.push(`checked_at_before_execution:${execution.execution_id}`);
      }
    }
    if (occurrence && checkedAtMs < Date.parse(occurrence.occurred_at)) {
      errors.push('verification_predates_finding_occurrence');
    }
  }
  if (!raw.checked_by || typeof raw.checked_by !== 'string') errors.push('checked_by_required');
  if (occurrence) {
    const occurredAtMs = Date.parse(occurrence.occurred_at);
    for (const execution of executionTimestamps) {
      if (execution.executed_at_ms < occurredAtMs) {
        errors.push(`test_execution_predates_finding_occurrence:${execution.execution_id}`);
      }
    }
  }
  if (!claims.length || claims.some((claim) =>
    !claim ||
    typeof claim !== 'object' ||
    !claim.claim_id ||
    !claim.claim ||
    claim.result !== 'confirmed' ||
    !Array.isArray(claim.evidence) ||
    !claim.evidence.length)) {
    errors.push('confirmed_claims_required');
  }
  const claimEvidence = new Set(sourceFiles
    .filter((item) => item && typeof item === 'object' && item.path)
    .map((item) => canonicalPath(item.path)));
  for (const test of tests) {
    if (!test || typeof test !== 'object') continue;
    claimEvidence.add(String(test.execution_id || ''));
    claimEvidence.add(String(test.execution_path || '').replace(/\\/g, '/'));
    for (const item of test.command_argv || []) {
      if (/^[^/\\\0]+(?:[/\\][^/\\\0]+)+$/.test(String(item))) claimEvidence.add(canonicalPath(item));
    }
  }
  for (const claim of claims) {
    if (!claim || typeof claim !== 'object' || !Array.isArray(claim.evidence)) {
      continue;
    }
    if ((claim.evidence || []).some((item) => {
      const rawItem = String(item);
      return !claimEvidence.has(rawItem) && !claimEvidence.has(canonicalPath(rawItem));
    })) {
      errors.push(`claim_evidence_unbound:${claim.claim_id || 'missing'}`);
    }
  }
  const checks = new Set((raw.required_checks_completed || []).map(String));
  const expectedChecks = (finding?.required_checks || [])
    .filter((check) => check !== 'dedicated_review');
  for (const check of expectedChecks) if (!checks.has(check)) errors.push(`required_check_missing:${check}`);
  if (finding) {
    const verifiedPaths = checkedPathMap(sourceFiles);
    const requiredArtifacts = Array.from(new Set([
      finding.artifact,
      ...(finding.affected_artifacts || [])
    ].filter(Boolean).map(canonicalPath)));
    for (const artifact of requiredArtifacts) {
      if (!verifiedPaths.has(artifact)) errors.push(`finding_artifact_not_verified:${artifact}`);
    }
    if (GENERATED_REPAIR_CLASSES.has(finding.repair_class)) {
      const generatedArtifact = canonicalPath(finding.artifact);
      const manifestRelative = '.knowledge/install-manifest.json';
      const manifestPath = options.repoRoot
        ? safeRelativeFile(options.repoRoot, manifestRelative)
        : null;
      let installManifest = null;
      try {
        installManifest = manifestPath
          ? JSON.parse(fs.readFileSync(manifestPath, 'utf8'))
          : null;
      } catch {
        installManifest = null;
      }
      const manifestApprovedTools = new Set(
        Array.isArray(installManifest?.approved_local_rebuild_tools)
          ? installManifest.approved_local_rebuild_tools
            .map((item) => canonicalPath(`.knowledge/${item}`))
          : []
      );
      if (!installManifest || !manifestApprovedTools.size) {
        errors.push('approved_local_rebuild_manifest_required');
      }
      if (!verifiedPaths.has(manifestRelative)) {
        errors.push('approved_local_rebuild_manifest_not_verified');
      }
      const expectedTool = generatedProducerTool(finding);
      if (!expectedTool) {
        errors.push(
          `generated_producer_unmapped:${generatedArtifact}`
        );
      }
      const allowedTools = expectedTool &&
        GENERATED_REBUILD_TOOLS.has(expectedTool) &&
        manifestApprovedTools.has(expectedTool)
        ? [expectedTool]
        : [];
      const rebuildTest = tests.find((test) => {
        const argv = test?.command_argv || [];
        return allowedTools.some((tool) =>
          exactGeneratedProducerArgv(argv, tool));
      });
      if (!rebuildTest) {
        errors.push('generated_rebuild_execution_required');
      } else {
        const rebuildExecution = executionRecords.get(
          rebuildTest.execution_id
        );
        if (!rebuildExecution || rebuildExecution.cwd !== '.') {
          errors.push('generated_rebuild_cwd_invalid');
        }
        const toolPath = canonicalPath(
          rebuildTest.command_argv[1]
        );
        if (!verifiedPaths.has(toolPath)) {
          errors.push(
            `generated_rebuild_tool_not_verified:${toolPath}`
          );
        }
        const execution = executionRecords.get(
          rebuildTest.execution_id
        );
        if (
          execution?.cwd !== '.' ||
          execution?.runtime_binding !== 'process_exec_path' ||
          execution?.environment_profile !==
            'sanitized_node_no_git'
        ) {
          errors.push('approved_local_rebuild_execution_context_invalid');
        }
        const before = new Map(
          (execution?.source_snapshot_before || []).map((item) => [
            canonicalPath(item.path),
            String(item.sha256 || '').toLowerCase()
          ])
        );
        const after = new Map(
          (execution?.source_snapshot || []).map((item) => [
            canonicalPath(item.path),
            String(item.sha256 || '').toLowerCase()
          ])
        );
        const protectedPaths =
          generatedProducerDependencyClosure(toolPath);
        if (!protectedPaths.length) {
          errors.push(
            `approved_local_rebuild_dependency_closure_missing:${toolPath}`
          );
        }
        for (const protectedPath of protectedPaths) {
          if (!verifiedPaths.has(protectedPath)) {
            errors.push(
              `approved_local_rebuild_dependency_not_verified:${protectedPath}`
            );
          }
          if (
            !before.has(protectedPath) ||
            !after.has(protectedPath)
          ) {
            errors.push(
              `approved_local_rebuild_provenance_missing:${protectedPath}`
            );
          } else if (
            before.get(protectedPath) !== after.get(protectedPath)
          ) {
            errors.push(
              `approved_local_rebuild_input_changed:${protectedPath}`
            );
          }
        }
      }
    }
  }
  const work = raw.additional_work || {};
  if (typeof work.wall_time_ms !== 'number' ||
      !Number.isFinite(work.wall_time_ms) ||
      work.wall_time_ms < 0) errors.push('additional_wall_time_invalid');
  if (typeof work.context_tokens !== 'number' ||
      !Number.isFinite(work.context_tokens) ||
      work.context_tokens < 0) errors.push('additional_context_tokens_invalid');
  if (typeof work.context_percent !== 'number' ||
      !Number.isFinite(work.context_percent) ||
      work.context_percent < 0 ||
      work.context_percent > 100) errors.push('additional_context_percent_invalid');
  if (work.input_tokens !== undefined && work.input_tokens !== null &&
      (typeof work.input_tokens !== 'number' ||
        !Number.isFinite(work.input_tokens) ||
        work.input_tokens < 0)) {
    errors.push('additional_input_tokens_invalid');
  }
  if (work.output_tokens !== undefined && work.output_tokens !== null &&
      (typeof work.output_tokens !== 'number' ||
        !Number.isFinite(work.output_tokens) ||
        work.output_tokens < 0)) {
    errors.push('additional_output_tokens_invalid');
  }
  const observedExecutionWallTime = Array.from(
    executionRecords.values()
  ).reduce(
    (total, execution) =>
      total + Math.max(0, Number(execution.duration_ms || 0)),
    0
  );
  if (
    typeof work.wall_time_ms === 'number' &&
    Number.isFinite(work.wall_time_ms) &&
    work.wall_time_ms < observedExecutionWallTime
  ) {
    errors.push('additional_wall_time_below_execution_evidence');
  }
  if (options.scope && String(raw.task_id || '') !== String(options.scope.task_id || '')) {
    errors.push('task_id_scope_mismatch');
  }
  if (options.scope && String(raw.session_id || '') !== String(options.scope.session_id || '')) {
    errors.push('session_id_scope_mismatch');
  }
  if (options.scope?.scope_hash && !raw.task_scope_hash) {
    errors.push('task_scope_hash_required');
  } else if (raw.task_scope_hash && options.scope?.scope_hash &&
      raw.task_scope_hash !== options.scope.scope_hash) {
    errors.push('task_scope_hash_mismatch');
  }
  if (finding && raw.task_scope && typeof raw.task_scope === 'object') {
    const scopeModules = normalizeModules([
      ...(raw.task_scope.modules || []),
      ...(raw.task_scope.selected_modules || []),
      ...(raw.task_scope.direct_modules || []),
      ...(raw.task_scope.dependency_modules || [])
    ]);
    const scopeArtifacts = normalizeList([
      ...(raw.task_scope.artifacts || []),
      ...(raw.task_scope.files || []),
      ...(raw.task_scope.direct_artifacts || []),
      ...(raw.task_scope.dependency_artifacts || [])
    ], canonicalPath);
    if (!scopeHasModule(scopeModules, finding.module_id) &&
        !scopeArtifacts.some((item) => pathOverlaps(item, finding.artifact))) {
      errors.push('receipt_task_scope_mismatch');
    }
  }
  if (options.scope && finding && relationToTask(finding, options.scope) === 'no_overlap' && mode !== 'dedicated') errors.push('finding_outside_task_scope');
  const secretFindings = secretPaths(raw);
  if (secretFindings.length) errors.push(...secretFindings.map((item) => `secret_like_value:${item}`));
  const privateFindings = privateValuePaths(raw);
  if (privateFindings.length) errors.push(...privateFindings.map((item) => `private_value:${item}`));
  if (options.policyResolution) {
    const policy = options.policyResolution.effective;
    if (Number(work.wall_time_ms) > policy.max_extra_minutes * 60000) errors.push('time_budget_exceeded');
    const contextPercent = Number(work.context_percent ?? 0);
    if (contextPercent > policy.max_extra_context_percent) errors.push('context_budget_exceeded');
    const confirmation = raw.confirmation_evidence || {};
    if (
      finding?.critical_path &&
      policy.require_confirmation_for_critical_paths &&
      confirmation.critical_path !== true &&
      confirmation.exact_finding !== true
    ) {
      errors.push('critical_path_confirmation_required');
    }
    if (
      finding?.security_sensitive &&
      policy.require_confirmation_for_security_findings &&
      confirmation.security_finding !== true &&
      confirmation.exact_finding !== true
    ) {
      errors.push('security_confirmation_required');
    }
  }
  if (options.repoRoot) {
    for (const item of sourceFiles) {
      if (!item || typeof item !== 'object' || !item.path) continue;
      const relative = canonicalPath(item.path);
      const absolute = safeRelativeFile(options.repoRoot, String(item.path).replace(/\\/g, '/'));
      if (!absolute || sha256(fs.readFileSync(absolute)) !== String(item.sha256).toLowerCase()) {
        errors.push(`source_hash_current_mismatch:${relative}`);
      }
    }
  }
  const digest = receiptDigest(raw);
  if (options.requireIdentity && !raw.content_sha256) errors.push('receipt_content_hash_required');
  if (options.requireIdentity && !raw.receipt_id) errors.push('receipt_id_required');
  if (raw.content_sha256 && raw.content_sha256 !== digest) errors.push('receipt_content_hash_mismatch');
  if (raw.receipt_id && raw.receipt_id !== `KVR-${digest}`) errors.push('receipt_id_content_address_mismatch');
  return { ok: errors.length === 0, errors: Array.from(new Set(errors)), digest };
}

function createReceipt(raw, options = {}) {
  const enrichedRaw = JSON.parse(JSON.stringify(raw || {}));
  const checkedSources = Array.isArray(enrichedRaw.source_files_checked)
    ? enrichedRaw.source_files_checked
    : [];
  const checkedByPath = new Map(checkedSources
    .filter((item) => item && typeof item === 'object' && item.path)
    .map((item) => [canonicalPath(item.path), item]));
  if (options.stateRoot) {
    for (const test of enrichedRaw.tests_run || []) {
      const loaded = loadExecutionRecord(
        options.stateRoot,
        test?.execution_id
      );
      for (const source of loaded?.record?.source_snapshot || []) {
        const relative = canonicalPath(source.path);
        if (!checkedByPath.has(relative)) {
          checkedByPath.set(relative, {
            path: relative,
            sha256: String(source.sha256).toLowerCase()
          });
        }
      }
    }
  }
  enrichedRaw.source_files_checked = Array.from(
    checkedByPath.values()
  ).sort((left, right) =>
    canonicalPath(left.path).localeCompare(canonicalPath(right.path)));
  let occurrenceSha256 = raw.finding_occurrence_sha256;
  if (options.finding) {
    occurrenceSha256 = findingOccurrence(options.finding).sha256;
  }
  const base = {
    ...canonicalReceiptInput(enrichedRaw),
    schema_version: RECEIPT_SCHEMA,
    finding_occurrence_sha256: occurrenceSha256,
    checked_at: options.checkedAt || new Date().toISOString(),
    checked_by: options.checkedBy || raw.checked_by || 'unknown'
  };
  const digest = receiptDigest(base);
  const receipt = {
    ...base,
    receipt_id: `KVR-${digest}`,
    content_sha256: digest
  };
  const validation = validateReceipt(receipt, options);
  if (!validation.ok) {
    const error = new Error(`Verification receipt rejected: ${validation.errors.join(', ')}`);
    error.code = 'verification_receipt_invalid';
    error.validation = validation;
    throw error;
  }
  return receipt;
}

function saveReceipt(stateRoot, receipt) {
  const validation = validateReceipt(receipt, { stateRoot, requireIdentity: true });
  if (!validation.ok) {
    const error = new Error(`Verification receipt rejected: ${validation.errors.join(', ')}`);
    error.code = 'verification_receipt_invalid';
    throw error;
  }
  const dir = secureStateStore(
    stateRoot,
    'maintenance/verification_receipts',
    { create: true }
  );
  const target = path.join(dir, `${receipt.content_sha256}.json`);
  const body = `${JSON.stringify(receipt, null, 2)}\n`;
  if (Buffer.byteLength(body) > MAX_VERIFICATION_RECEIPT_BYTES) {
    const error = new Error('Verification receipt exceeds the bounded content-store limit');
    error.code = 'verification_receipt_too_large';
    throw error;
  }
  if (fs.existsSync(target)) {
    const stat = fs.lstatSync(target);
    if (!stat.isFile() || stat.isSymbolicLink() || fs.readFileSync(target, 'utf8') !== body) {
      const error = new Error('Content-addressed verification receipt is immutable');
      error.code = 'verification_receipt_immutable';
      throw error;
    }
    return {
      path: target,
      idempotent: true,
      physical_sha256: sha256(Buffer.from(body))
    };
  }
  writeFileAtomic(target, body);
  return {
    path: target,
    idempotent: false,
    physical_sha256: sha256(Buffer.from(body))
  };
}

function loadReceipt(stateRoot, reference, options = {}) {
  const raw = String(reference || '').replace(/^KVR-/, '');
  if (!/^[a-f0-9]{64}$/i.test(raw)) {
    throw contentStoreError(
      'verification_receipt_reference_invalid',
      'Verification receipt reference must be a KVR ID or digest'
    );
  }
  const digest = raw.toLowerCase();
  const directory = secureStateStore(
    stateRoot,
    'maintenance/verification_receipts'
  );
  const target = path.join(directory, `${digest}.json`);
  let stat;
  try {
    stat = fs.lstatSync(target);
  } catch {
    throw contentStoreError(
      'verification_receipt_not_found',
      `Verification receipt not found: KVR-${digest}`
    );
  }
  if (
    !stat.isFile() ||
    stat.isSymbolicLink() ||
    stat.size <= 0 ||
    stat.size > MAX_VERIFICATION_RECEIPT_BYTES
  ) {
    throw contentStoreError(
      'verification_receipt_file_invalid',
      `Verification receipt is not a safe regular file: KVR-${digest}`
    );
  }
  const real = fs.realpathSync(target);
  if (path.relative(directory, real) !== `${digest}.json`) {
    throw contentStoreError(
      'verification_receipt_path_invalid',
      `Verification receipt escaped its content-addressed store: KVR-${digest}`
    );
  }
  const body = fs.readFileSync(real);
  let receipt;
  try {
    receipt = JSON.parse(
      body.toString('utf8').replace(/^\uFEFF/, '')
    );
  } catch {
    throw contentStoreError(
      'verification_receipt_json_invalid',
      `Verification receipt is invalid JSON: KVR-${digest}`
    );
  }
  const validation = validateReceipt(receipt, {
    ...options,
    stateRoot,
    requireIdentity: true
  });
  if (
    !validation.ok ||
    receipt.content_sha256 !== digest ||
    receipt.receipt_id !== `KVR-${digest}`
  ) {
    const error = contentStoreError(
      'verification_receipt_invalid',
      `Verification receipt failed validation: ${validation.errors.join(', ')}`
    );
    error.validation = validation;
    throw error;
  }
  return {
    receipt,
    path: real,
    relative_path: `maintenance/verification_receipts/${digest}.json`,
    physical_sha256: sha256(body)
  };
}

function maintenanceTelemetry({
  enabled,
  mode,
  opportunities = [],
  receipts = [],
  doctorBefore = null,
  doctorAfter = null,
  taskReadinessBefore = null,
  taskReadinessAfter = null
}) {
  const sumActual = (field) => {
    const values = receipts.map((receipt) => receipt.additional_work?.[field]);
    if (values.some((value) => value === null || value === undefined || !Number.isFinite(Number(value)))) return null;
    return values.reduce((sum, value) => sum + Number(value), 0);
  };
  return {
    repair_on_touch_enabled: Boolean(enabled),
    repair_mode: canonicalMode(mode, 'off'),
    repair_findings_considered: opportunities.length,
    repair_findings_selected: opportunities.filter((item) => ['selected', 'repaired'].includes(item.status)).length,
    repair_findings_closed: opportunities.filter((item) => item.status === 'repaired').length,
    repair_findings_deferred: opportunities.filter((item) => item.status === 'deferred').length,
    repair_lifecycle_ids_considered: opportunities.map((item) => item.lifecycle_id).filter(Boolean).sort(),
    repair_lifecycle_ids_closed: opportunities.filter((item) => item.status === 'repaired').map((item) => item.lifecycle_id).filter(Boolean).sort(),
    repair_extra_wall_time_ms: sumActual('wall_time_ms'),
    repair_extra_input_tokens: sumActual('input_tokens'),
    repair_extra_output_tokens: sumActual('output_tokens'),
    doctor_before: doctorBefore,
    doctor_after: doctorAfter,
    task_readiness_before: taskReadinessBefore,
    task_readiness_after: taskReadinessAfter,
    token_values: 'actual_only'
  };
}

function humanMaintenanceSummary({
  primaryTask = [],
  primaryTests = [],
  opportunities = [],
  receipts = [],
  dedicatedReceipts = [],
  closed = [],
  doctorBefore = null,
  doctorAfter = null,
  readinessBefore = null,
  readinessAfter = null,
  provenanceStatus = 'verified',
  doctorSnapshotAuthority = 'advisory'
} = {}) {
  const humanReason = (reason) => ({
    outside_task_scope: 'outside the current task',
    dedicated_action_required: 'requires dedicated review',
    dedicated_run_required: 'queued for a dedicated maintenance run',
    dedicated_exact_confirmation_required: 'requires exact finding confirmation in a dedicated run',
    dedicated_blocked_by_policy_cap: 'blocked by the team or security policy cap',
    mode_off: 'maintenance is disabled',
    generated_rebuild_disabled: 'generated-artifact rebuilding is disabled',
    generated_producer_unmapped:
      'no approved local producer is mapped to this generated artifact',
    safe_only_curated_repair_forbidden: 'safe mode only rebuilds generated artifacts',
    budget_exhausted_max_findings: 'the finding limit was reached',
    budget_exhausted_time: 'the additional-time limit was reached',
    budget_exhausted_context: 'the additional-context limit was reached',
    critical_path_confirmation_required: 'critical-path confirmation is required',
    security_confirmation_required: 'security confirmation is required',
    verification_did_not_clear_finding:
      'verification did not clear the current finding'
  }[reason] || 'left for later');
  const selected = opportunities.filter((item) => ['selected', 'repaired'].includes(item.status));
  const deferred = opportunities.filter((item) => item.status === 'deferred');
  return [
    'Primary task',
    ...(primaryTask.length ? primaryTask.map((item) => `- ${item}`) : ['- No primary-task summary was supplied.']),
    ...(primaryTests || []).map((item) => `- Test: ${item}`),
    '',
    'Knowledge maintenance performed during the task',
    ...(selected.length ? selected.map((item) => `- Verified ${item.module_id} for the current task.`) : ['- No opportunistic knowledge repair was performed.']),
    ...receipts.map((receipt) => `- Saved verification receipt ${receipt.receipt_id}.`),
    ...dedicatedReceipts.map((receipt) =>
      `- Bound dedicated verification receipt ${receipt.receipt_id}.`),
    ...closed.map((item) => `- Closed exact finding ${item}.`),
    `- Closure provenance: ${provenanceStatus}.`,
    '',
    'Health',
    `- Doctor authority: ${doctorSnapshotAuthority} snapshot.`,
    `- Global Doctor: ${doctorBefore ?? 'not measured'} → ${doctorAfter ?? 'not measured'}`,
    `- Current-task readiness: ${readinessBefore ?? 'not measured'} → ${readinessAfter ?? 'not measured'}`,
    '',
    'Deferred',
    ...(deferred.length
      ? deferred.map((item) => `- ${item.module_id}: ${humanReason(item.decision_reason)}.`)
      : ['- No task-relevant maintenance was deferred.'])
  ].join('\n');
}

module.exports = {
  RECEIPT_SCHEMA,
  EXECUTION_SCHEMA,
  OPPORTUNITIES_SCHEMA,
  SETTINGS_SCHEMA,
  MODES,
  MODE_RANK,
  MODE_LABELS,
  MODE_ALIASES,
  DEFAULT_REPAIR_POLICY,
  HARD_SAFETY,
  GENERATED_REPAIR_CLASSES,
  GENERATED_REBUILD_TOOLS,
  GENERATED_REBUILD_DEPENDENCIES,
  generatedProducerTool,
  generatedProducerDependencyClosure,
  PROTECTED_CODES,
  MAX_REPAIR_PLAN_BYTES,
  MAX_VERIFICATION_RECEIPT_BYTES,
  MAX_VERIFICATION_EXECUTION_BYTES,
  canonicalMode,
  policyAllowsReceiptMode,
  restrictPolicyBudgets,
  normalizePolicy,
  parseRepositoryRepairSettings,
  readRepositoryRepairSettings,
  operatorRepairSettings,
  teamPolicyCap,
  readTeamPolicy,
  resolvePolicy,
  saveOperatorRepairSettings,
  severityCost,
  defaultRepairClass,
  requiredChecksFor,
  granularFinding,
  buildTaskScope,
  taskScopeDigest,
  validateTaskScope,
  repairSessionKey,
  repairSessionPlanRelative,
  loadRepairPlan,
  validateRepairPlanArtifact,
  relationToTask,
  selectOpportunities,
  taskReadiness,
  buildOpportunitiesArtifact,
  validateReceipt,
  createReceipt,
  saveReceipt,
  loadReceipt,
  validateExecutionRecord,
  saveExecutionRecord,
  loadExecutionRecord,
  runVerificationTests,
  executionDigest,
  receiptDigest,
  maintenanceTelemetry,
  humanMaintenanceSummary,
  stableJson,
  sha256,
  secretPaths,
  privateValuePaths,
  safeRelativeFile,
  secureStateStore
};
