'use strict';
// QA disclosure transport. Authentication binds a run; it does not attest that
// the runner or product was trustworthy. Node built-ins only. See TRANSPORT_SPEC.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const zlib = require('node:zlib');
const { TextDecoder } = require('node:util');

const ROOT_KEY_ID = 'a7b0e9a0f1fe0a908da8aa9798dc4d8a9d2cec7526015e67aaa0989dcb30356b';
const INPUT_SHA256 = '24df61b60ff43899a8e85884acf14bef6eb3a8c4a2537413033f5092b6965407';
const REPOSITORY = 'pro2pilot/knowledge';
const FORMAT = 'knowledge-d5-evidence.v1';
const SCOPE = 'WINDOWS_ARM_NODE24_TEAM_QA_ONLY';
const LIMITS = Object.freeze({ plaintext: 8 * 1024 * 1024, file: 2 * 1024 * 1024,
  files: 32, ciphertext: 8 * 1024 * 1024 + 65536, chunk: 3072, header: 8192,
  log: 16 * 1024 * 1024, jsonDepth: 32, jsonNodes: 65536, request: 512 * 1024, key: 65536 });
const HEX64 = /^[0-9a-f]{64}$/;
const HEX40 = /^[0-9a-f]{40}$/;
const DECIMAL = /^[1-9][0-9]{0,19}$/;
const fail = code => { const error = new Error(code); error.code = code; throw error; };
const sha256 = data => crypto.createHash('sha256').update(data).digest('hex');
const object = x => x !== null && typeof x === 'object' && !Array.isArray(x);
function exactKeys(value, keys, code = 'INVALID_OBJECT_FIELDS') {
  if (!object(value) || Object.keys(value).sort().join('\0') !== [...keys].sort().join('\0')) fail(code);
}
function utf8(data, maximum) {
  if (!Buffer.isBuffer(data) || data.length > maximum) fail('UTF8_LENGTH_LIMIT');
  try { return new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(data); }
  catch { fail('INVALID_UTF8'); }
}

// JSON.parse alone silently accepts duplicate members. This parser rejects
// duplicates (including escaped aliases), excessive depth, unsafe integers,
// nonfinite numbers and prototype-bearing member names before any use.
function parseStrictJSON(input, maximum = LIMITS.plaintext) {
  const text = Buffer.isBuffer(input) ? utf8(input, maximum) : input;
  if (typeof text !== 'string' || Buffer.byteLength(text) > maximum) fail('JSON_LENGTH_LIMIT');
  let at = 0, nodes = 0;
  const whitespace = () => { while (at < text.length && /[\x20\x09\x0a\x0d]/.test(text[at])) at++; };
  function string() {
    if (text[at] !== '"') fail('INVALID_JSON');
    const start = at++;
    let escaped = false;
    while (at < text.length) {
      const c = text.charCodeAt(at++);
      if (c < 32) fail('INVALID_JSON');
      if (escaped) { escaped = false; continue; }
      if (c === 92) { escaped = true; continue; }
      if (c === 34) {
        let value;
        try { value = JSON.parse(text.slice(start, at)); } catch { fail('INVALID_JSON'); }
        // Reject unpaired UTF-16 surrogates; canonical UTF-8 must be unique.
        for (let i = 0; i < value.length; i++) {
          const n = value.charCodeAt(i);
          if (n >= 0xd800 && n <= 0xdbff) {
            const next = value.charCodeAt(++i);
            if (!(next >= 0xdc00 && next <= 0xdfff)) fail('INVALID_JSON_UNICODE');
          } else if (n >= 0xdc00 && n <= 0xdfff) fail('INVALID_JSON_UNICODE');
        }
        return value;
      }
    }
    fail('INVALID_JSON');
  }
  function value(depth) {
    if (depth > LIMITS.jsonDepth) fail('JSON_DEPTH_LIMIT');
    if (++nodes > LIMITS.jsonNodes) fail('JSON_NODE_LIMIT');
    whitespace();
    if (text[at] === '"') return string();
    if (text[at] === '{') {
      at++; whitespace(); const out = Object.create(null); const names = new Set();
      if (text[at] === '}') { at++; return out; }
      while (true) {
        whitespace(); const key = string();
        if (names.has(key)) fail('DUPLICATE_JSON_KEY');
        if (['__proto__', 'prototype', 'constructor'].includes(key)) fail('UNSAFE_JSON_KEY');
        names.add(key); whitespace(); if (text[at++] !== ':') fail('INVALID_JSON');
        out[key] = value(depth + 1); whitespace();
        const c = text[at++]; if (c === '}') return out; if (c !== ',') fail('INVALID_JSON');
      }
    }
    if (text[at] === '[') {
      at++; whitespace(); const out = [];
      if (text[at] === ']') { at++; return out; }
      while (true) {
        out.push(value(depth + 1)); whitespace();
        const c = text[at++]; if (c === ']') return out; if (c !== ',') fail('INVALID_JSON');
      }
    }
    for (const [literal, result] of [['true', true], ['false', false], ['null', null]]) {
      if (text.slice(at, at + literal.length) === literal) { at += literal.length; return result; }
    }
    const match = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/.exec(text.slice(at));
    if (!match) fail('INVALID_JSON');
    at += match[0].length; const number = Number(match[0]);
    if (!Number.isFinite(number) || (Number.isInteger(number) && !Number.isSafeInteger(number))) fail('JSON_NUMBER_RANGE');
    return number;
  }
  const parsed = value(0); whitespace(); if (at !== text.length) fail('TRAILING_JSON'); return parsed;
}

function normalizeMetadata(value, { expectedKeyId = ROOT_KEY_ID, expectedInputSHA = INPUT_SHA256 } = {}) {
  const keys = ['repository', 'run_id', 'run_attempt', 'commit', 'input_sha256', 'key_id'];
  exactKeys(value, Object.hasOwn(value || {}, 'format') ? ['format', ...keys] : keys, 'INVALID_METADATA_FIELDS');
  if ((Object.hasOwn(value, 'format') && value.format !== FORMAT) || value.repository !== REPOSITORY ||
      typeof value.run_id !== 'string' || !DECIMAL.test(value.run_id) ||
      typeof value.run_attempt !== 'string' || !/^[1-9][0-9]{0,5}$/.test(value.run_attempt) ||
      typeof value.commit !== 'string' || !HEX40.test(value.commit) ||
      typeof value.input_sha256 !== 'string' || !HEX64.test(value.input_sha256) || value.input_sha256 !== expectedInputSHA ||
      typeof value.key_id !== 'string' || !HEX64.test(value.key_id) || value.key_id !== expectedKeyId) fail('INVALID_METADATA');
  // This exact insertion order and JSON.stringify form is the AAD wire contract.
  return { format: FORMAT, repository: value.repository, run_id: value.run_id,
    run_attempt: value.run_attempt, commit: value.commit, input_sha256: value.input_sha256, key_id: value.key_id };
}
function canonicalAAD(metadata, options) { return Buffer.from(JSON.stringify(normalizeMetadata(metadata, options)), 'utf8'); }
function keyId(publicOrPrivateKey) {
  let publicKey;
  try { publicKey = crypto.createPublicKey(publicOrPrivateKey); } catch { fail('INVALID_PUBLIC_KEY'); }
  if (publicKey.asymmetricKeyType !== 'rsa' || publicKey.asymmetricKeyDetails?.modulusLength !== 3072 ||
      publicKey.asymmetricKeyDetails?.publicExponent !== 65537n) fail('INVALID_RSA_KEY_PARAMETERS');
  return sha256(publicKey.export({ type: 'spki', format: 'der' }));
}

function safeName(name) {
  if (typeof name !== 'string' || name.length < 1 || name.length > 180 || name.includes('\\') ||
      !/^[A-Za-z0-9_.\/-]+$/.test(name) || name.startsWith('/') || name.endsWith('/')) fail('UNSAFE_FILE_NAME');
  for (const part of name.split('/')) {
    if (!part || ['.', '..'].includes(part) || part.endsWith('.') ||
        /^(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)/i.test(part)) fail('UNSAFE_FILE_NAME');
  }
  if (['result.json', 'verified.json', 'root_review.json'].includes(name.split('/')[0].toLowerCase())) fail('RESERVED_FILE_NAME');
  return name;
}
function validateNames(files) {
  if (!Array.isArray(files) || files.length > LIMITS.files) fail('FILE_COUNT_LIMIT');
  const names = new Set();
  for (const file of files) {
    const name = safeName(file.name).toLowerCase();
    if (names.has(name)) fail('DUPLICATE_FILE_NAME');
    names.add(name);
  }
  for (const name of names) {
    let prefix = name;
    while (prefix.includes('/')) {
      prefix = prefix.slice(0, prefix.lastIndexOf('/'));
      if (names.has(prefix)) fail('FILE_DIRECTORY_COLLISION');
    }
  }
}
function validateResult(result, files) {
  const keys = ['status', 'scope', 'product_started', 'original_child_exit', 'timed_out', 'overflow', 'evidence_complete',
    'tests', 'guard_worker_proof', 'native_custody_complete', 'source_unchanged', 'native_arm_scope_verified'];
  exactKeys(result, Object.hasOwn(result || {}, 'details') ? [...keys, 'details'] : keys, 'INVALID_RESULT_FIELDS');
  if (!['PASS', 'FAIL', 'NOT_RUN', 'UNCERTAIN'].includes(result.status) || result.scope !== SCOPE) fail('INVALID_RESULT_STATUS');
  if (result.product_started !== null && typeof result.product_started !== 'boolean') fail('INVALID_RESULT_BOOLEAN');
  for (const field of ['timed_out', 'overflow', 'evidence_complete', 'guard_worker_proof',
    'native_custody_complete', 'source_unchanged', 'native_arm_scope_verified']) if (typeof result[field] !== 'boolean') fail('INVALID_RESULT_BOOLEAN');
  if (result.original_child_exit !== null && (!Number.isInteger(result.original_child_exit) ||
      result.original_child_exit < -2147483648 || result.original_child_exit > 4294967295)) fail('INVALID_CHILD_EXIT');
  if (!result.product_started && result.original_child_exit !== null) fail('CHILD_EXIT_WITHOUT_START');
  if (result.status === 'NOT_RUN' && result.product_started) fail('NOT_RUN_AFTER_PRODUCT_START');
  if (result.timed_out && !result.product_started) fail('TIMEOUT_WITHOUT_PRODUCT_START');
  exactKeys(result.tests, ['expected', 'passed', 'failed', 'skipped'], 'INVALID_TEST_RESULT');
  if (result.tests.expected !== 2 || !['passed', 'failed', 'skipped'].every(k => Number.isInteger(result.tests[k]) && result.tests[k] >= 0 && result.tests[k] <= 2) ||
      result.tests.passed + result.tests.failed + result.tests.skipped > 2) fail('INVALID_TEST_COUNTS');
  if (!result.product_started && (result.tests.passed || result.tests.failed || result.tests.skipped || result.native_custody_complete)) fail('PRODUCT_FACTS_WITHOUT_START');
  if (Object.hasOwn(result, 'details') && (!object(result.details) || Buffer.byteLength(JSON.stringify(result.details)) > 256 * 1024)) fail('RESULT_DETAILS_LIMIT');
  if (result.product_started === null && (result.status !== 'UNCERTAIN' || result.original_child_exit !== null ||
      result.timed_out !== false || result.evidence_complete !== false || result.tests.passed !== 0 || result.tests.failed !== 0 || result.tests.skipped !== 0 ||
      result.guard_worker_proof !== false || result.native_custody_complete !== false || result.source_unchanged !== false || result.native_arm_scope_verified !== false ||
      result.details?.product_start_knowledge !== 'UNKNOWN_SUPERVISOR_CAPTURE_INCOMPLETE_OR_NO_VALID_RECEIPT')) fail('INVALID_UNKNOWN_PRODUCT_STATE');
  if (result.status === 'PASS') {
    if (!result.product_started || result.original_child_exit !== 0 || result.timed_out || result.overflow || !result.evidence_complete ||
        result.tests.passed !== 2 || result.tests.failed !== 0 || result.tests.skipped !== 0 || !result.guard_worker_proof ||
        !result.native_custody_complete || !result.source_unchanged || !result.native_arm_scope_verified) fail('UNSUPPORTED_PASS');
    for (const name of ['product.stdout', 'product.stderr', 'bootstrap.stdout', 'bootstrap.stderr']) {
      if (!files.some(file => file.name === name && file.kind === 'stream')) fail('PASS_MISSING_STREAM');
    }
    for (const name of ['guard.json', 'native.json', 'analysis.json', 'source-before.json', 'source-after.json', 'observations.ndjson',
      'supervisor.json', 'guard-proof.ndjson', 'preflight-proof.ndjson', 'analysis-run.json', 'bootstrap-capture.json']) {
      if (!files.some(file => file.name === name && file.kind === 'receipt')) fail('PASS_MISSING_RECEIPT');
    }
  }
  if ((result.timed_out || result.overflow) && result.evidence_complete) fail('INCOMPLETE_EVIDENCE_REQUIRED');
  return result;
}
function strictBase64(text, maxBytes, expectedBytes) {
  if (typeof text !== 'string' || text.length > Math.ceil(maxBytes / 3) * 4 || text.length % 4 !== 0 ||
      !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(text)) fail('INVALID_BASE64');
  const data = Buffer.from(text, 'base64');
  if (data.length > maxBytes || (expectedBytes !== undefined && data.length !== expectedBytes) || data.toString('base64') !== text) fail('INVALID_BASE64_LENGTH');
  return data;
}

function physicalDirectory(directory) {
  if (typeof directory !== 'string' || !path.isAbsolute(directory) || directory.startsWith('\\\\')) fail('ABSOLUTE_LOCAL_DIRECTORY_REQUIRED');
  const absolute = path.resolve(directory); let current = path.parse(absolute).root;
  for (const part of absolute.slice(current.length).split(path.sep).filter(Boolean)) {
    current = path.join(current, part); const st = fs.lstatSync(current, { bigint: true });
    if (!st.isDirectory() || st.isSymbolicLink()) fail('NONPHYSICAL_DIRECTORY');
  }
  const real = fs.realpathSync.native(absolute);
  const equal = process.platform === 'win32' ? real.toLowerCase() === absolute.toLowerCase() : real === absolute;
  if (!equal) fail('DIRECTORY_ALIAS');
  const stat = fs.lstatSync(real, { bigint: true });
  return { root: real, dev: stat.dev, ino: stat.ino };
}
function sameRoot(record) {
  const st = fs.lstatSync(record.root, { bigint: true });
  if (!st.isDirectory() || st.isSymbolicLink() || st.dev !== record.dev || st.ino !== record.ino) fail('PRIVATE_ROOT_CHANGED');
}
function readBoundedFile(file, maximum, { singleLink = true } = {}) {
  const before = fs.lstatSync(file, { bigint: true });
  if (!before.isFile() || before.isSymbolicLink() || (singleLink && before.nlink !== 1n) || before.size > BigInt(maximum)) fail('INVALID_BOUNDED_FILE');
  const fd = fs.openSync(file, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
  try {
    const opened = fs.fstatSync(fd, { bigint: true });
    if (opened.dev !== before.dev || opened.ino !== before.ino || opened.size !== before.size || !opened.isFile()) fail('FILE_CHANGED');
    const bytes = Buffer.alloc(Number(before.size) + 1); let used = 0;
    while (used < bytes.length) { const amount = fs.readSync(fd, bytes, used, bytes.length - used, null); if (!amount) break; used += amount; }
    const after = fs.fstatSync(fd, { bigint: true });
    if (used !== Number(before.size) || after.size !== before.size || after.mtimeNs !== before.mtimeNs || after.ctimeNs !== before.ctimeNs) fail('FILE_CHANGED');
    const named = fs.lstatSync(file, { bigint: true });
    if (named.dev !== before.dev || named.ino !== before.ino || named.isSymbolicLink()) fail('FILE_CHANGED');
    return bytes.subarray(0, used);
  } finally { fs.closeSync(fd); }
}
function readContained(record, name) {
  safeName(name); sameRoot(record);
  const parts = name.split('/'); let current = record.root;
  for (const part of parts.slice(0, -1)) {
    current = path.join(current, part); const st = fs.lstatSync(current);
    if (!st.isDirectory() || st.isSymbolicLink()) fail('NONPHYSICAL_FILE_ANCESTOR');
  }
  const file = path.join(current, parts.at(-1));
  const real = fs.realpathSync.native(file); const prefix = record.root + path.sep;
  const inside = process.platform === 'win32' ? real.toLowerCase().startsWith(prefix.toLowerCase()) : real.startsWith(prefix);
  if (!inside) fail('FILE_OUTSIDE_PRIVATE_ROOT');
  const bytes = readBoundedFile(file, LIMITS.file); sameRoot(record); return bytes;
}
function captureRequest(request, options = {}) {
  exactKeys(request, ['schema', 'metadata', 'private_root', 'result', 'files'], 'INVALID_REQUEST_FIELDS');
  if (request.schema !== 'knowledge-d5-evidence-request.v1') fail('INVALID_REQUEST_SCHEMA');
  const metadata = normalizeMetadata(request.metadata, options);
  validateNames(request.files); validateResult(request.result, request.files);
  const root = physicalDirectory(request.private_root); const files = [];
  let serializedBytes = Buffer.byteLength(JSON.stringify({ schema: FORMAT, metadata, result: request.result, files: [] }));
  if (serializedBytes > LIMITS.plaintext) fail('PLAINTEXT_LIMIT');
  for (const file of request.files) {
    exactKeys(file, ['name', 'kind'], 'INVALID_REQUEST_FILE_FIELDS');
    if (!['stream', 'receipt'].includes(file.kind)) fail('INVALID_FILE_KIND');
    const bytes = readContained(root, file.name);
    const captured = { name: file.name, kind: file.kind, bytes: bytes.length, sha256: sha256(bytes), encoding: 'base64', data: bytes.toString('base64') };
    serializedBytes += Buffer.byteLength(JSON.stringify(captured)) + (files.length ? 1 : 0);
    if (serializedBytes > LIMITS.plaintext) fail('PLAINTEXT_LIMIT');
    files.push(captured);
  }
  sameRoot(root);
  const body = { schema: FORMAT, metadata, result: request.result, files };
  validateBody(body, metadata, options);
  return body;
}
function validateBody(body, expectedMetadata, options = {}) {
  exactKeys(body, ['schema', 'metadata', 'result', 'files'], 'INVALID_BODY_FIELDS');
  if (body.schema !== FORMAT) fail('INVALID_BODY_SCHEMA');
  const metadata = normalizeMetadata(body.metadata, options);
  if (!canonicalAAD(metadata, options).equals(canonicalAAD(expectedMetadata, options))) fail('BODY_METADATA_MISMATCH');
  validateNames(body.files); validateResult(body.result, body.files);
  let total = 0; const decoded = [];
  for (const file of body.files) {
    exactKeys(file, ['name', 'kind', 'bytes', 'sha256', 'encoding', 'data'], 'INVALID_BODY_FILE_FIELDS');
    if (!['stream', 'receipt'].includes(file.kind) || file.encoding !== 'base64' || !Number.isInteger(file.bytes) ||
        file.bytes < 0 || file.bytes > LIMITS.file || typeof file.sha256 !== 'string' || !HEX64.test(file.sha256)) fail('INVALID_BODY_FILE');
    const bytes = strictBase64(file.data, LIMITS.file, file.bytes);
    total += bytes.length; if (total > LIMITS.plaintext || sha256(bytes) !== file.sha256) fail('FILE_SHA_OR_TOTAL_MISMATCH');
    decoded.push({ name: file.name, kind: file.kind, bytes });
  }
  if (Buffer.byteLength(JSON.stringify(body)) > LIMITS.plaintext) fail('PLAINTEXT_LIMIT');
  crossCheckSupervisor(body.result, decoded);
  return decoded;
}
function crossCheckSupervisor(result, files) {
  function receipt(name) {
    const file = files.find(f => f.name === name && f.kind === 'receipt');
    if (!file) return null;
    try { return parseStrictJSON(file.bytes, LIMITS.file); }
    catch {
      // A malformed diagnostic receipt is itself useful failure evidence.
      // Preserve its exact bytes on nonPASS; never accept it as a PASS fact.
      if (result.status === 'PASS') fail('INVALID_REQUIRED_RECEIPT');
      return null;
    }
  }
  const supervisor = receipt('supervisor.json'), analysis = receipt('analysis.json'), analysisRun = receipt('analysis-run.json'), bootstrap = receipt('bootstrap-capture.json');
  // The explicit unknown branch carries no asserted product facts. Raw
  // incomplete diagnostics cannot supply trusted child rc or imply NOT_RUN.
  if (result.product_started !== null && supervisor && object(supervisor.product)) {
    const p = supervisor.product;
    if (!Object.hasOwn(p, 'original_child_exit') || p.original_child_exit !== result.original_child_exit ||
        typeof p.started !== 'boolean' || p.started !== result.product_started ||
        p.timed_out === true && !result.timed_out || p.overflow === true && !result.overflow) fail('SUPERVISOR_RESULT_MISMATCH');
    if (result.status === 'PASS') {
      if (p.original_child_exit !== 0 || p.exited !== true || p.stdout_eof !== true || p.stderr_eof !== true ||
          p.timed_out !== false || p.overflow !== false || p.kill_attempted !== false || p.kill_succeeded !== false ||
          p.pipe_failure !== false || p.retained_handle_captured !== true || p.failure_code !== null ||
          !Number.isFinite(p.elapsed_ms) || p.elapsed_ms < 0 || p.elapsed_ms > 650000) fail('UNSUPPORTED_SUPERVISOR_PASS');
      for (const channel of ['stdout', 'stderr']) {
        const stream = files.find(f => f.name === `product.${channel}` && f.kind === 'stream');
        const observed = p[`${channel}_observed_bytes`];
        if (!Number.isSafeInteger(observed) || observed < 0 || !stream || stream.bytes.length !== observed) fail('SUPERVISOR_STREAM_LENGTH_MISMATCH');
      }
    }
  } else if (result.status === 'PASS') fail('MISSING_SUPERVISOR_PRODUCT_FACTS');
  if (result.product_started !== null && analysis && object(analysis.product)) {
    if (!Object.hasOwn(analysis.product, 'original_child_exit') || analysis.product.original_child_exit !== result.original_child_exit) fail('ANALYSIS_CHILD_EXIT_MISMATCH');
  } else if (result.status === 'PASS') fail('MISSING_ANALYSIS_PRODUCT_FACTS');
  if (result.status === 'PASS') {
    const keys = ['schema', 'started', 'exited', 'original_child_exit', 'timed_out', 'overflow', 'stdout_eof', 'stderr_eof',
      'pipe_failure', 'kill_attempted', 'kill_succeeded', 'retained_handle_captured', 'stdout_observed_bytes', 'stderr_observed_bytes',
      'elapsed_ms', 'capture_elapsed_ms', 'failure_code'];
    exactKeys(analysisRun, keys, 'INVALID_ANALYSIS_RUN_FIELDS');
    if (analysisRun.schema !== 'knowledge-d5-analysis-run.v1' || analysisRun.started !== true || analysisRun.exited !== true ||
        analysisRun.original_child_exit !== 0 || analysisRun.timed_out !== false || analysisRun.overflow !== false ||
        analysisRun.stdout_eof !== true || analysisRun.stderr_eof !== true || analysisRun.pipe_failure !== false ||
        analysisRun.kill_attempted !== false || analysisRun.kill_succeeded !== false || analysisRun.retained_handle_captured !== true ||
        analysisRun.failure_code !== null || !Number.isSafeInteger(analysisRun.elapsed_ms) || analysisRun.elapsed_ms < 0 ||
        analysisRun.elapsed_ms > 10000 || !Number.isSafeInteger(analysisRun.capture_elapsed_ms) ||
        analysisRun.capture_elapsed_ms < analysisRun.elapsed_ms || !Number.isSafeInteger(analysisRun.stdout_observed_bytes) ||
        analysisRun.stdout_observed_bytes < 0 || analysisRun.stdout_observed_bytes > LIMITS.file || analysisRun.stderr_observed_bytes !== 0) fail('UNSUPPORTED_ANALYSIS_PROCESS_PASS');
    const details = result.details?.analysis_process;
    exactKeys(details, keys, 'MISSING_ANALYSIS_PROCESS_DETAILS');
    if (!keys.every(key => details[key] === analysisRun[key])) fail('ANALYSIS_PROCESS_DETAILS_MISMATCH');
  }
  const bootstrapKeys = ['schema', 'started', 'exited', 'stdout_eof', 'stderr_eof', 'overflow', 'pipe_failure', 'timed_out',
    'kill_attempted', 'kill_succeeded', 'retained_handle_captured', 'stdout_observed_bytes', 'stderr_observed_bytes', 'elapsed_ms',
    'original_supervisor_exit', 'failure_code'];
  if (result.status === 'PASS') {
    exactKeys(bootstrap, bootstrapKeys, 'INVALID_BOOTSTRAP_CAPTURE_FIELDS');
    if (bootstrap.schema !== 'knowledge-d5-bootstrap-capture.v1' || bootstrap.started !== true || bootstrap.exited !== true ||
        bootstrap.stdout_eof !== true || bootstrap.stderr_eof !== true || bootstrap.retained_handle_captured !== true ||
        bootstrap.overflow !== false || bootstrap.pipe_failure !== false || bootstrap.timed_out !== false ||
        bootstrap.kill_attempted !== false || bootstrap.kill_succeeded !== false || bootstrap.original_supervisor_exit !== 0 ||
        bootstrap.failure_code !== null || !Number.isSafeInteger(bootstrap.elapsed_ms) || bootstrap.elapsed_ms < 0 || bootstrap.elapsed_ms > 740000 ||
        !Number.isSafeInteger(bootstrap.stdout_observed_bytes) || bootstrap.stdout_observed_bytes < 0 || bootstrap.stdout_observed_bytes > LIMITS.file ||
        bootstrap.stderr_observed_bytes !== 0) fail('UNSUPPORTED_BOOTSTRAP_CAPTURE_PASS');
    for (const channel of ['stdout', 'stderr']) {
      const stream = files.find(f => f.name === `bootstrap.${channel}` && f.kind === 'stream');
      if (!stream || stream.bytes.length !== bootstrap[`${channel}_observed_bytes`]) fail('BOOTSTRAP_STREAM_LENGTH_MISMATCH');
    }
    const bootstrapStdout = files.find(f => f.name === 'bootstrap.stdout' && f.kind === 'stream').bytes;
    // PowerShell Console.WriteLine uses CRLF on Windows. Keep those exact raw
    // bytes while accepting only one safe fixed line, with LF or CRLF ending.
    if (!bootstrapStdout.equals(Buffer.from('D5_CANDIDATE PASS REQUEST_READY\n')) &&
        !bootstrapStdout.equals(Buffer.from('D5_CANDIDATE PASS REQUEST_READY\r\n'))) fail('BOOTSTRAP_PASS_SUMMARY_MISMATCH');
    const details = result.details?.supervisor_capture;
    exactKeys(details, bootstrapKeys, 'MISSING_BOOTSTRAP_CAPTURE_DETAILS');
    if (!bootstrapKeys.every(key => details[key] === bootstrap[key])) fail('BOOTSTRAP_CAPTURE_DETAILS_MISMATCH');
  } else if (object(bootstrap) && object(result.details?.supervisor_capture) &&
      bootstrapKeys.every(key => Object.hasOwn(bootstrap, key) && Object.hasOwn(result.details.supervisor_capture, key))) {
    // A complete diagnostic capture may be unsuccessful or truncated. Its
    // saved duplicate must still agree; its PowerShell rc is NEVER product rc.
    if (!bootstrapKeys.every(key => result.details.supervisor_capture[key] === bootstrap[key])) fail('BOOTSTRAP_CAPTURE_DETAILS_MISMATCH');
  }
}

function encryptBody(body, publicPem, options = {}) {
  const expectedKeyId = options.expectedKeyId || ROOT_KEY_ID;
  if (keyId(publicPem) !== expectedKeyId) fail('PUBLIC_KEY_PIN_MISMATCH');
  const metadata = normalizeMetadata(body.metadata, options);
  validateBody(body, metadata, options);
  const plain = Buffer.from(JSON.stringify(body));
  if (plain.length > LIMITS.plaintext) fail('PLAINTEXT_LIMIT');
  const compressed = zlib.gzipSync(plain, { level: 9, mtime: 0 });
  if (compressed.length > LIMITS.ciphertext) fail('CIPHERTEXT_LIMIT');
  const key = crypto.randomBytes(32); const iv = crypto.randomBytes(12); const aad = canonicalAAD(metadata, options);
  let ciphertext, tag, wrapped;
  try {
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv, { authTagLength: 16 });
    cipher.setAAD(aad); ciphertext = Buffer.concat([cipher.update(compressed), cipher.final()]); tag = cipher.getAuthTag();
    wrapped = crypto.publicEncrypt({ key: publicPem, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' }, key);
  } finally { key.fill(0); }
  const count = Math.ceil(ciphertext.length / LIMITS.chunk);
  const header = { schema: 'knowledge-d5-envelope.v1', aad: aad.toString('base64'), compression: 'gzip',
    encryption: 'AES-256-GCM', key_wrap: 'RSA-OAEP-SHA256', wrapped_key: wrapped.toString('base64'),
    iv: iv.toString('base64'), tag: tag.toString('base64'), plaintext_bytes: plain.length,
    ciphertext_bytes: ciphertext.length, ciphertext_sha256: sha256(ciphertext), chunk_bytes: LIMITS.chunk, chunk_count: count };
  const headerBytes = Buffer.from(JSON.stringify(header)); if (headerBytes.length > LIMITS.header) fail('HEADER_LIMIT');
  const lines = [`D5E1 BEGIN ${headerBytes.toString('base64')}`];
  for (let i = 0; i < count; i++) lines.push(`D5E1 CHUNK ${String(i + 1).padStart(6, '0')}/${String(count).padStart(6, '0')} ${ciphertext.subarray(i * LIMITS.chunk, (i + 1) * LIMITS.chunk).toString('base64')}`);
  const framed = lines.join('\n') + '\n';
  lines.push(`D5E1 END ${ciphertext.length} ${sha256(ciphertext)} ${sha256(Buffer.from(framed))}`);
  const log = lines.join('\n') + '\n'; if (Buffer.byteLength(log) > LIMITS.log) fail('LOG_LIMIT');
  return { log, header, body };
}
function encryptRequest(request, publicPem, options = {}) { return encryptBody(captureRequest(request, options), publicPem, options); }

function frameLines(log) {
  const text = Buffer.isBuffer(log) ? utf8(log, LIMITS.log) : log;
  if (typeof text !== 'string' || Buffer.byteLength(text) > LIMITS.log || text.includes('\r') && !/^(?:[^\r]|\r\n)*$/.test(text)) fail('INVALID_LOG');
  // Complete Actions logs contain trusted service prefix lines. Only an exact
  // frame at column zero, or immediately after one ISO UTC timestamp, is used.
  // Lines containing a frame marker elsewhere are refused, not silently lost.
  const found = []; let ended = false;
  for (let line of text.split(/\r?\n/)) {
    line = line.replace(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z /, '');
    if (line.startsWith('D5E1 ')) {
      if (ended) fail('EXTRA_ENVELOPE_OR_FRAME');
      if (line.length > 12000) fail('FRAME_LENGTH_LIMIT');
      found.push(line); if (line.startsWith('D5E1 END ')) ended = true;
    } else if (line.includes('D5E1')) fail('AMBIGUOUS_FRAME_PREFIX');
  }
  if (!found.length || !ended) fail('MISSING_OR_TRUNCATED_ENVELOPE');
  return found;
}
function parseEnvelope(log, expected, options = {}) {
  const metadata = normalizeMetadata(expected, options), aad = canonicalAAD(metadata, options);
  const lines = frameLines(log); const begin = /^D5E1 BEGIN ([A-Za-z0-9+/=]+)$/.exec(lines[0]);
  if (!begin) fail('MISSING_BEGIN');
  const headerBytes = strictBase64(begin[1], LIMITS.header); const header = parseStrictJSON(headerBytes, LIMITS.header);
  exactKeys(header, ['schema', 'aad', 'compression', 'encryption', 'key_wrap', 'wrapped_key', 'iv', 'tag',
    'plaintext_bytes', 'ciphertext_bytes', 'ciphertext_sha256', 'chunk_bytes', 'chunk_count'], 'INVALID_HEADER_FIELDS');
  if (header.schema !== 'knowledge-d5-envelope.v1' || header.compression !== 'gzip' || header.encryption !== 'AES-256-GCM' ||
      header.key_wrap !== 'RSA-OAEP-SHA256' || header.chunk_bytes !== LIMITS.chunk ||
      !Number.isInteger(header.plaintext_bytes) || header.plaintext_bytes < 1 || header.plaintext_bytes > LIMITS.plaintext ||
      !Number.isInteger(header.ciphertext_bytes) || header.ciphertext_bytes < 1 || header.ciphertext_bytes > LIMITS.ciphertext ||
      !Number.isInteger(header.chunk_count) || header.chunk_count !== Math.ceil(header.ciphertext_bytes / LIMITS.chunk) ||
      typeof header.ciphertext_sha256 !== 'string' || !HEX64.test(header.ciphertext_sha256)) fail('INVALID_HEADER');
  const suppliedAAD = strictBase64(header.aad, 1024);
  const suppliedMetadata = parseStrictJSON(suppliedAAD, 1024);
  normalizeMetadata(suppliedMetadata, options);
  if (!suppliedAAD.equals(aad) || !canonicalAAD(suppliedMetadata, options).equals(aad)) fail('EXPECTED_RUN_BINDING_MISMATCH');
  if (lines.length !== header.chunk_count + 2) fail('CHUNK_COUNT_MISMATCH');
  const ciphertextParts = [];
  for (let i = 0; i < header.chunk_count; i++) {
    const match = /^D5E1 CHUNK ([0-9]{6})\/([0-9]{6}) ([A-Za-z0-9+/=]+)$/.exec(lines[i + 1]);
    if (!match || Number(match[1]) !== i + 1 || Number(match[2]) !== header.chunk_count) fail('CHUNK_ORDER_OR_DUPLICATE');
    const expectedBytes = i + 1 === header.chunk_count ? header.ciphertext_bytes - i * LIMITS.chunk : LIMITS.chunk;
    ciphertextParts.push(strictBase64(match[3], LIMITS.chunk, expectedBytes));
  }
  const ciphertext = Buffer.concat(ciphertextParts);
  if (ciphertext.length !== header.ciphertext_bytes || sha256(ciphertext) !== header.ciphertext_sha256) fail('CIPHERTEXT_SHA_MISMATCH');
  const end = /^D5E1 END ([1-9][0-9]{0,8}) ([0-9a-f]{64}) ([0-9a-f]{64})$/.exec(lines.at(-1));
  if (!end || Number(end[1]) !== ciphertext.length || end[2] !== header.ciphertext_sha256 ||
      end[3] !== sha256(Buffer.from(lines.slice(0, -1).join('\n') + '\n'))) fail('OUTER_ENVELOPE_SHA_MISMATCH');
  return { header, ciphertext, metadata, aad, wrapped: strictBase64(header.wrapped_key, 384, 384),
    iv: strictBase64(header.iv, 12, 12), tag: strictBase64(header.tag, 16, 16) };
}
function boundedSingleGzip(compressed) {
  // The producer emits one RFC1952 member, no optional header fields, MTIME=0,
  // level-9 XFL=2. The OS byte is informational (Windows/Linux differ).
  if (compressed.length < 18 || compressed[0] !== 0x1f || compressed[1] !== 0x8b ||
      compressed[2] !== 8 || compressed[3] !== 0 || compressed.readUInt32LE(4) !== 0 || compressed[8] !== 2) fail('INVALID_GZIP_HEADER');
  let decoded;
  try { decoded = zlib.inflateRawSync(compressed.subarray(10), { info: true, maxOutputLength: LIMITS.plaintext }); }
  catch { fail('BOUNDED_GZIP_FAILED'); }
  const footer = 10 + decoded.engine.bytesWritten;
  if (footer + 8 !== compressed.length || decoded.buffer.length > LIMITS.plaintext ||
      compressed.readUInt32LE(footer + 4) !== decoded.buffer.length ||
      typeof zlib.crc32 !== 'function' || compressed.readUInt32LE(footer) !== zlib.crc32(decoded.buffer)) fail('INVALID_SINGLE_GZIP_MEMBER');
  return decoded.buffer;
}
function decryptEnvelope(log, privatePem, expected, options = {}) {
  const expectedKeyId = options.expectedKeyId || ROOT_KEY_ID;
  if (keyId(privatePem) !== expectedKeyId) fail('PRIVATE_KEY_PIN_MISMATCH');
  const envelope = parseEnvelope(log, expected, options); let key, compressed;
  try {
    key = crypto.privateDecrypt({ key: privatePem, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' }, envelope.wrapped);
    if (key.length !== 32) fail('INVALID_UNWRAPPED_KEY');
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, envelope.iv, { authTagLength: 16 });
    decipher.setAAD(envelope.aad); decipher.setAuthTag(envelope.tag);
    compressed = Buffer.concat([decipher.update(envelope.ciphertext), decipher.final()]);
  } catch { fail('ENVELOPE_AUTHENTICATION_FAILED'); }
  finally { if (key) key.fill(0); }
  const plain = boundedSingleGzip(compressed);
  if (plain.length !== envelope.header.plaintext_bytes || plain.length > LIMITS.plaintext) fail('PLAINTEXT_LENGTH_MISMATCH');
  const body = parseStrictJSON(plain, LIMITS.plaintext);
  const files = validateBody(body, envelope.metadata, options);
  return { body, files, header: envelope.header, metadata: envelope.metadata,
    verification: { schema: 'knowledge-d5-decrypt-verification.v1', status: 'AUTHENTICATED_COMPLETE_ENVELOPE',
      product_status: body.result.status, original_child_exit: body.result.original_child_exit,
      scope: SCOPE, run_id: envelope.metadata.run_id, run_attempt: envelope.metadata.run_attempt,
      commit: envelope.metadata.commit, input_sha256: envelope.metadata.input_sha256, key_id: envelope.metadata.key_id,
      ciphertext_bytes: envelope.header.ciphertext_bytes, ciphertext_sha256: envelope.header.ciphertext_sha256,
      files_verified: files.length, replay_policy: 'IDEMPOTENT_SAME_EXPECTED_RUN_ALLOWED_NO_USED_RUN_DATABASE',
      root_acceptance: 'REQUIRES_DECODED_RECEIPT_AND_RAW_REVIEW_NOT_FULL_RELEASE_GATE' } };
}
function writeVerified(verified, output) {
  if (typeof output !== 'string' || !path.isAbsolute(output) || output.startsWith('\\\\')) fail('ABSOLUTE_LOCAL_OUTPUT_REQUIRED');
  const absolute = path.resolve(output); const parent = physicalDirectory(path.dirname(absolute));
  if (fs.existsSync(absolute)) fail('FRESH_OUTPUT_REQUIRED');
  sameRoot(parent); fs.mkdirSync(absolute, { mode: 0o700 }); const root = physicalDirectory(absolute);
  for (const file of verified.files) {
    safeName(file.name); sameRoot(root); let directory = root.root;
    for (const part of file.name.split('/').slice(0, -1)) {
      directory = path.join(directory, part);
      if (!fs.existsSync(directory)) fs.mkdirSync(directory, { mode: 0o700 });
      const st = fs.lstatSync(directory); if (!st.isDirectory() || st.isSymbolicLink()) fail('OUTPUT_DIRECTORY_CHANGED');
    }
    fs.writeFileSync(path.join(root.root, ...file.name.split('/')), file.bytes, { flag: 'wx', mode: 0o600 });
  }
  sameRoot(root);
  fs.writeFileSync(path.join(root.root, 'RESULT.json'), JSON.stringify(verified.body.result, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
  fs.writeFileSync(path.join(root.root, 'VERIFIED.json'), JSON.stringify(verified.verification, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
  sameRoot(root);
  return verified.verification;
}
module.exports = { ROOT_KEY_ID, INPUT_SHA256, REPOSITORY, FORMAT, SCOPE, LIMITS, sha256, parseStrictJSON,
  normalizeMetadata, canonicalAAD, keyId, safeName, validateNames, validateResult, strictBase64,
  readBoundedFile, physicalDirectory, captureRequest, validateBody, encryptBody, encryptRequest,
  frameLines, parseEnvelope, decryptEnvelope, writeVerified };
