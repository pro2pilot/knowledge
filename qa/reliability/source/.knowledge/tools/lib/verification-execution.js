'use strict';

// Shared read-only KVE contract. No task runner, writes, context discovery,
// recording overrides or currency authority belong in this dependency leaf.
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { canonicalPath } = require('./queue-lifecycle');
const { copyInertData } = require('./inert-data');
const EXECUTION_SCHEMA = 'knowledge-verification-execution.v1';
const GENERATED_REBUILD_TOOLS = new Set([
  '.knowledge/tools/build-routing-bundle.js',
  '.knowledge/tools/build-search-index.js',
  '.knowledge/tools/build-wiki-graph.js'
]);
const GENERATED_REBUILD_OUTPUTS = Object.freeze({
  '.knowledge/tools/build-search-index.js': Object.freeze([
    '.knowledge/search/index.json'
  ]),
  '.knowledge/tools/build-routing-bundle.js': Object.freeze([
    '.knowledge/maintenance/routing_bundle.json',
    '.knowledge/maintenance/routing_decision.json',
    '.knowledge/maintenance/workspace_health_summary.json',
    '.knowledge/maintenance/maintenance_debt.json'
  ]),
  '.knowledge/tools/build-wiki-graph.js': Object.freeze([
    '.knowledge/maps/wiki_graph.json'
  ])
});
const SECRET_KEY_PATTERN = /(api[_-]?key|secret|token|password|authorization|private[_-]?key)/i;
// Short key prefixes require a delimiter; "skills/..." is not an sk key.
// Actual key-shaped values embedded in paths remain blocked by default.
const SECRET_VALUE_PATTERN = /\b(?:(?:sk|pk)(?=[_-])|ghp|github_pat|m0sk|pcsk|eyJ)[A-Za-z0-9_./+=-]{18,}\b/;
const EMAIL_VALUE_PATTERN = /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/i;
const WINDOWS_ABSOLUTE_PATH_PATTERN = /(?:^|[\s"'`(])(?:[A-Z]:[\\/]|\\\\[^\\/\s]+[\\/])/i;
const POSIX_ABSOLUTE_PATH_PATTERN = /(?:^|[\s"'`(])\/(?!\/)(?:[^\s"'`,;)}\]]+\/)+[^\s"'`,;)}\]]+/i;
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
function contentStoreError(code, message) {
  const error = new Error(message);
  error.code = code;
  return error;
}
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
function nodeExecutableKind(value) {
  const executable = path.basename(String(value || ''))
    .toLowerCase();
  if (['node', 'node.exe'].includes(executable)) return 'canonical';
  const windowsAlias = executable.replace(/[. ]+$/g, '');
  return ['node', 'node.exe'].includes(windowsAlias)
    ? 'windows_alias'
    : 'other';
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
function executionDigest(raw) {
  const copy = JSON.parse(JSON.stringify(raw || {}));
  delete copy.execution_id;
  delete copy.content_sha256;
  delete copy.execution_path;
  return sha256(stableJson(copy));
}
function validateExecutionRecord(record) {
  try { record = copyInertData(record); }
  catch { return { ok: false, errors: ['execution_input_invalid'] }; }
  const errors = [];
  if (!record || typeof record !== 'object' || Array.isArray(record)) return { ok: false, errors: ['execution_record_required'] };
  const schemaValidation = validateBundledSchema(
    record.schema_version === 'knowledge-verification-execution.v2' ? 'verification-execution-v2.schema.json' : 'verification-execution.schema.json',
    record
  );
  errors.push(...schemaValidation.errors.map((item) =>
    `execution_schema_contract:${item}`));
  if (recordingSecretPaths(record, { sessionId: record.session_id }).length) errors.push('execution_secret_like_value');
  if (privateValuePaths(record).length) errors.push('execution_private_value');
  if (![EXECUTION_SCHEMA, 'knowledge-verification-execution.v2'].includes(record.schema_version)) errors.push('execution_schema_invalid');
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
  // A zero exit code only verifies the bytes the command actually ran against.
  // An ordinary test that rewrites a source (including itself) cannot certify
  // the replacement bytes. Only the exact outputs of a bounded first-party
  // producer may change; its code, dependencies and other inputs stay pinned.
  if (Array.isArray(record.source_snapshot_before) &&
      Array.isArray(record.source_snapshot)) {
    const mutableOutputs = new Set(
      nodeCommand && record.runtime_binding === 'process_exec_path' &&
      record.environment_profile === 'sanitized_node_no_git' &&
      record.cwd === '.' && exactGeneratedProducerArgv(record.command_argv)
        ? GENERATED_REBUILD_OUTPUTS[canonicalPath(record.command_argv[1])] || []
        : []
    );
    const before = new Map(record.source_snapshot_before
      .filter((item) => item && typeof item === 'object' && item.path)
      .map((item) => [canonicalPath(item.path), String(item.sha256 || '').toLowerCase()]));
    const after = new Map(record.source_snapshot
      .filter((item) => item && typeof item === 'object' && item.path)
      .map((item) => [canonicalPath(item.path), String(item.sha256 || '').toLowerCase()]));
    for (const source of new Set([...before.keys(), ...after.keys()])) {
      if (!mutableOutputs.has(source) && before.get(source) !== after.get(source)) {
        errors.push(`execution_source_changed_during_verification:${source}`);
      }
    }
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
function recordingSecretPaths(value) { return secretPaths(value); }

// Read bytes without creating stores or deciding a consumer's privacy policy.
// The result is untrusted until loadExecutionRecord or the native writer's
// existing validation policy accepts it.
function readExecutionRecord(stateRoot, reference) { return readNativeRecord(stateRoot, reference, 'verification_executions'); }

function readNativeRecord(stateRoot, reference, store) {
  if (!['verification_executions', 'verification_finalizations'].includes(store)) return null;
  if (typeof stateRoot !== 'string' || !stateRoot) return null;
  if (typeof reference !== 'string') return null;
  const raw = reference.replace(/^KVE-/, '');
  const digest = /^[a-f0-9]{64}$/i.test(raw) ? raw.toLowerCase() : path.basename(raw, '.json').toLowerCase();
  if (!/^[a-f0-9]{64}$/.test(digest)) return null;
  const root = path.resolve(stateRoot);
  let current = root;
  try {
    const parents = [];
    for (const part of ['', 'maintenance', store]) {
      current = part ? path.join(current, part) : current;
      const stat = fs.lstatSync(current);
      if (!stat.isDirectory() || stat.isSymbolicLink()) return null;
      parents.push({ path: current, dev: stat.dev, ino: stat.ino });
    }
    const directory = fs.realpathSync(current);
    if (path.relative(fs.realpathSync(root), directory).replace(/\\/g, '/') !== 'maintenance/' + store) return null;
    const file = path.join(directory, `${digest}.json`);
    const stat = fs.lstatSync(file);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || stat.size <= 0 || stat.size > 256 * 1024) return null;
    const real = fs.realpathSync(file);
    if (path.relative(directory, real) !== `${digest}.json`) return null;
    const fd = fs.openSync(real, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0) | (fs.constants.O_NONBLOCK || 0));
    let body;
    try {
      const before = fs.fstatSync(fd);
      if (!before.isFile() || before.nlink !== 1 || before.dev !== stat.dev || before.ino !== stat.ino ||
          before.size !== stat.size || before.mtimeMs !== stat.mtimeMs || before.ctimeMs !== stat.ctimeMs) return null;
      // Read at most the observed bounded size plus one byte. Concurrent growth
      // must not turn an otherwise bounded native record into an unbounded read.
      const buffer = Buffer.alloc(before.size + 1);
      let length = 0;
      while (length < buffer.length) {
        const count = fs.readSync(fd, buffer, length, buffer.length - length, null);
        if (count === 0) break;
        length += count;
      }
      if (length !== before.size) return null;
      const after = fs.fstatSync(fd), live = fs.lstatSync(file);
      if (after.nlink !== 1 || after.size !== before.size || after.mtimeMs !== before.mtimeMs || after.ctimeMs !== before.ctimeMs ||
          live.isSymbolicLink() || live.nlink !== 1 || live.dev !== before.dev || live.ino !== before.ino ||
          live.size !== before.size || live.mtimeMs !== before.mtimeMs || live.ctimeMs !== before.ctimeMs) return null;
      body = buffer.subarray(0, length);
    } finally { fs.closeSync(fd); }
    for (const parent of parents) {
      const live = fs.lstatSync(parent.path);
      if (!live.isDirectory() || live.isSymbolicLink() || live.dev !== parent.dev || live.ino !== parent.ino) return null;
    }
    const record = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(body).replace(/^\uFEFF/, ''));
    return { record, path: real, physical_sha256: sha256(body), expected_digest: digest };
  } catch { return null; }
}

function loadExecutionRecord(stateRoot, reference) {
  const loaded = readExecutionRecord(stateRoot, reference);
  if (!loaded) return null;
  const validation = validateExecutionRecord(loaded.record);
  if (!validation.ok || validation.digest !== loaded.expected_digest) return null;
  const { expected_digest, ...result } = loaded;
  return { ...result, finalization_attestation: loaded.record.schema_version === EXECUTION_SCHEMA ? 'legacy_unattested' : 'acceptance_required' };
}

module.exports = { GENERATED_REBUILD_TOOLS, GENERATED_REBUILD_OUTPUTS, exactGeneratedProducerArgv,
  validateBundledSchema, nodeExecutableKind, nodeInvocationDescriptor, executionDigest,
  validateExecutionRecord, readNativeRecord, readExecutionRecord, loadExecutionRecord, secretPaths, privateValuePaths };
