'use strict';

// Execute the actual CLI and validator against physical files. Only the named
// failing filesystem/validator operation is injected; archive production and
// successful validation are real. These are local filesystem tests, not proof
// of power-loss durability, hostile same-user containment or another OS.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawnSync } = require('node:child_process');
const { test } = require('node:test');
const source = path.resolve(process.env.KNOWLEDGE_AUDIT_SOURCE_ROOT || path.join(__dirname, '..'));
const { captureTempDirIdentity, removeTempDirStrict } = require(path.join(source, 'tools/lib/strict-temp-cleanup'));
const { validate } = require(path.join(source, 'tools/validate-release-artifact'));
const version = JSON.parse(fs.readFileSync(path.join(source, 'package.json'), 'utf8')).version;
const previous = Buffer.from('PREVIOUS USER OUTPUT MUST SURVIVE BEFORE PUBLICATION\n');
const hash = bytes => crypto.createHash('sha256').update(bytes).digest('hex');

const hook = String.raw`
'use strict';
const fs = require('node:fs'), path = require('node:path'), crypto = require('node:crypto');
const source = process.env.KNOWLEDGE_AUDIT_SOURCE_ROOT;
const output = process.env.KNOWLEDGE_AUDIT_OUTPUT;
const mode = process.env.KNOWLEDGE_AUDIT_FAULT;
const trace = process.env.KNOWLEDGE_AUDIT_TRACE;
const original = {};
for (const name of ['writeFileSync','appendFileSync','readFileSync','existsSync','renameSync','rmdirSync']) original[name] = fs[name].bind(fs);
const hash = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
let stageDirectory = null;
function record(event, extra = {}) {
  original.appendFileSync(trace, JSON.stringify({event, output_sha256: original.existsSync(output) ? hash(original.readFileSync(output)) : null, ...extra}) + '\n');
}
function fault(code, operation) { const e = new Error('audit injected ' + operation); e.code = code; return e; }
fs.writeFileSync = function(file, data, ...rest) {
  if (Buffer.isBuffer(data) && data.length >= 4 && data.readUInt32LE(0) === 0x04034b50) {
    const target = path.resolve(String(file));
    if (target !== output) stageDirectory = path.dirname(target);
    record('zip_write', {target, bytes: data.length});
    if (['partial-write','truncated-write','crash-after-partial-write'].includes(mode)) {
      original.writeFileSync(file, data.subarray(0, 17), ...rest);
      record('partial_write_done', {target});
      if (mode === 'crash-after-partial-write') process.kill(process.pid, 'SIGKILL');
      if (mode === 'partial-write') throw fault('ENOSPC', 'partial write');
      return;
    }
  }
  return original.writeFileSync(file, data, ...rest);
};
const validator = require(path.join(source, 'tools/validate-release-artifact'));
const realValidate = validator.validate;
validator.validate = function(file, options) {
  record('validate_start', {target: path.resolve(file)});
  const result = realValidate(file, options);
  record('validate_return', {status: result.status, violations: result.violations});
  if (result.status === 'ok' && mode === 'validator-reject') return {...result, status: 'failed', violations: [{type: 'audit_injected_validation_failure', entry: '<fixture>', reason: 'forced after real physical validation'}]};
  if (result.status === 'ok' && mode === 'validator-throw') throw fault('EIO', 'validator failure after real physical validation');
  return result;
};
fs.renameSync = function(from, to) {
  if (path.resolve(String(to)) === output) {
    record('rename_start', {from: path.resolve(String(from)), to: output});
    if (mode === 'rename-fail') throw fault('EACCES', 'rename failure');
    const result = original.renameSync(from, to);
    record('rename_return');
    return result;
  }
  return original.renameSync(from, to);
};
fs.rmdirSync = function(directory, ...rest) {
  if (mode === 'cleanup-fail' && path.resolve(String(directory)) === stageDirectory) {
    record('cleanup_failure', {target: stageDirectory});
    throw fault('EBUSY', 'empty staging directory cleanup failure');
  }
  return original.rmdirSync(directory, ...rest);
};
`;

function fixture(t, label, options = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge-publication-audit-'));
  const identity = captureTempDirIdentity(root);
  t.after(() => removeTempDirStrict(root, { expectedIdentity: identity }));
  const outputDirectory = path.join(root, 'output');
  fs.mkdirSync(outputDirectory);
  const output = path.join(outputDirectory, options.name || `knowledge-v${version}.zip`);
  if (options.existing !== false) fs.writeFileSync(output, previous);
  const foreignDirectory = path.join(outputDirectory, '.knowledge-package-foreign');
  fs.mkdirSync(foreignDirectory);
  fs.writeFileSync(path.join(foreignDirectory, 'sentinel'), 'FOREIGN STAGING DIRECTORY\n');
  fs.writeFileSync(path.join(outputDirectory, 'unrelated.tmp'), 'UNRELATED FILE\n');
  const preload = path.join(root, 'preload.cjs'), trace = path.join(root, 'trace.jsonl');
  fs.writeFileSync(preload, hook);
  return { root, output, outputDirectory, foreignDirectory, preload, trace, label, existing: options.existing !== false };
}

function run(f, mode) {
  const argv = ['--require', f.preload, path.join(source, 'tools/package-release.js'), '--json', '--out', f.output];
  const env = { ...process.env };
  delete env.NODE_OPTIONS;
  delete env.NODE_PATH;
  delete env.KNOWLEDGE_RELEASE_ARTIFACT_REL;
  delete env.KNOWLEDGE_RELEASE_ARTIFACT_OUT;
  Object.assign(env, { KNOWLEDGE_AUDIT_SOURCE_ROOT: source, KNOWLEDGE_AUDIT_OUTPUT: f.output, KNOWLEDGE_AUDIT_FAULT: mode, KNOWLEDGE_AUDIT_TRACE: f.trace });
  // The tested CLI starts no children. An intentional crash has a separately
  // asserted SIGKILL receipt; a controller timeout is always a test failure.
  const child = spawnSync(process.execPath, argv, { cwd: f.root, env, encoding: 'utf8', timeout: 60000, killSignal: 'SIGKILL', windowsHide: true, maxBuffer: 8 * 1024 * 1024 });
  const events = fs.existsSync(f.trace) ? fs.readFileSync(f.trace, 'utf8').trim().split('\n').filter(Boolean).map(line => JSON.parse(line)) : [];
  const target = events.find(event => event.event === 'zip_write')?.target || null;
  let summary = null;
  try { summary = JSON.parse(child.stdout); } catch (_) { /* failing baseline may throw before its summary */ }
  const receipt = {
    label: f.label, mode, argv: [process.execPath, ...argv], source, node: process.version, platform: process.platform,
    packager_sha256: hash(fs.readFileSync(path.join(source, 'tools/package-release.js'))),
    validator_sha256: hash(fs.readFileSync(path.join(source, 'tools/validate-release-artifact.js'))),
    test_sha256: hash(fs.readFileSync(__filename)),
    error: child.error ? { code: child.error.code, message: child.error.message } : null,
    exit_code: child.status, signal: child.signal, events, summary,
    output_exists: fs.existsSync(f.output), output_sha256: fs.existsSync(f.output) ? hash(fs.readFileSync(f.output)) : null,
    output_bytes: fs.existsSync(f.output) ? fs.statSync(f.output).size : null,
    output_directory_entries: fs.readdirSync(f.outputDirectory).sort(),
    staging_path: target && target !== f.output ? target : null,
    staging_exists: target && target !== f.output ? fs.existsSync(target) : null
  };
  if (process.env.KNOWLEDGE_AUDIT_EVIDENCE_DIR) {
    const destination = path.join(path.resolve(process.env.KNOWLEDGE_AUDIT_EVIDENCE_DIR), f.label);
    fs.mkdirSync(destination, { recursive: true });
    fs.writeFileSync(path.join(destination, 'RESULT.json'), JSON.stringify(receipt, null, 2) + '\n');
    fs.writeFileSync(path.join(destination, 'stdout.log'), child.stdout || '');
    fs.writeFileSync(path.join(destination, 'stderr.log'), child.stderr || '');
    fs.writeFileSync(path.join(destination, 'preload.cjs'), hook);
  }
  assert.equal(child.error, undefined, child.error?.message);
  if (mode === 'crash-after-partial-write') {
    assert.equal(child.signal, 'SIGKILL', 'The fixture must observe the exit of its own intentionally killed CLI');
    assert.equal(child.status, null);
  } else {
    assert.equal(child.signal, null, 'Timeout or external termination is not a publication result');
  }
  return { child, events, summary, receipt };
}

function foreignIntact(f) {
  assert.equal(fs.readFileSync(path.join(f.foreignDirectory, 'sentinel'), 'utf8'), 'FOREIGN STAGING DIRECTORY\n');
  assert.equal(fs.readFileSync(path.join(f.outputDirectory, 'unrelated.tmp'), 'utf8'), 'UNRELATED FILE\n');
}
function priorIntact(f) {
  if (f.existing) assert(fs.readFileSync(f.output).equals(previous), 'Prepublication failure must preserve the previous output bytes exactly');
  else assert.equal(fs.existsSync(f.output), false, 'Prepublication failure must not expose a partial output');
  foreignIntact(f);
}
function noOwnedStaging(f) {
  assert.deepEqual(fs.readdirSync(f.outputDirectory).sort(), [path.basename(f.foreignDirectory), 'unrelated.tmp', ...(fs.existsSync(f.output) ? [path.basename(f.output)] : [])].sort(), 'Cleanup must remove only this invocation\'s staging path');
}

for (const mode of ['partial-write', 'truncated-write', 'validator-reject', 'validator-throw', 'rename-fail']) {
  test(`publication preserves the existing output on ${mode}`, t => {
    const f = fixture(t, mode), result = run(f, mode);
    assert.notEqual(result.child.status, 0, 'Injected failure must not be reported as successful publication');
    priorIntact(f);
    noOwnedStaging(f);
    if (mode.startsWith('validator-') || mode === 'rename-fail') {
      assert(result.events.some(event => event.event === 'validate_return' && event.status === 'ok'), 'Injection must follow successful real ZIP validation');
    }
    if (mode === 'rename-fail') assert(result.events.some(event => event.event === 'rename_start'), 'The failure must reach the actual publication boundary');
  });
}

test('successful publication validates staged bytes before replacing the previous output', t => {
  const f = fixture(t, 'success'), result = run(f, 'none');
  assert.equal(result.child.status, 0, result.child.stderr);
  assert.equal(result.summary?.status, 'ok');
  assert.equal(result.summary.output_path, f.output);
  for (const event of ['zip_write', 'validate_start', 'validate_return', 'rename_start']) {
    const seen = result.events.find(item => item.event === event);
    assert(seen, `Missing observation: ${event}`);
    assert.equal(seen.output_sha256, hash(previous), 'The old output must remain readable through successful physical validation');
  }
  const staged = result.events.find(item => item.event === 'validate_start').target;
  assert.notEqual(staged, f.output);
  assert.equal(path.basename(staged), path.basename(f.output), 'Staging must preserve real filename/version validation');
  assert.equal(path.dirname(path.dirname(staged)), f.outputDirectory, 'Staging directory must be created alongside the destination');
  assert.equal(validate(f.output).status, 'ok');
  const { buildPackageEntries, createZip } = require(path.join(source, 'tools/package-release'));
  const expected = path.join(f.root, 'expected', path.basename(f.output));
  createZip(buildPackageEntries(source).entries, expected);
  assert(fs.readFileSync(f.output).equals(fs.readFileSync(expected)), 'Atomic publication must preserve the canonical archive bytes exactly');
  foreignIntact(f);
  noOwnedStaging(f);
});

test('real invalid-filename validation preserves the previous output', t => {
  const f = fixture(t, 'invalid-filename', { name: 'invalid-release-name.zip' }), result = run(f, 'none');
  assert.notEqual(result.child.status, 0);
  assert.equal(result.summary?.status, 'failed');
  assert(result.summary.errors.some(error => error.includes('artifact_name_invalid')));
  priorIntact(f);
  noOwnedStaging(f);
});

test('partial write with no previous output never publishes a partial artifact', t => {
  const f = fixture(t, 'absent-output-partial-write', { existing: false }), result = run(f, 'partial-write');
  assert.notEqual(result.child.status, 0);
  priorIntact(f);
  noOwnedStaging(f);
});

test('an observed writer crash during its partial write preserves the previous output', { skip: process.platform === 'win32' ? 'This test requires a native SIGKILL exit receipt; Windows crash semantics are not modeled here' : false }, t => {
  const f = fixture(t, 'crash-after-partial-write'), result = run(f, 'crash-after-partial-write');
  priorIntact(f);
  assert(result.receipt.staging_path, 'A killed writer must have written only its staging file');
  assert.equal(result.receipt.staging_exists, true, 'Crash may leave its own staging artifact; it is not a published result');
  // This test owns the fixture and has observed the sole CLI exit. Its strict
  // fixture cleanup may remove the orphan; the product makes no crash-GC claim.
});

test('staging-directory cleanup failure after publish is a warning with the committed output intact', t => {
  const f = fixture(t, 'cleanup-fail'), result = run(f, 'cleanup-fail');
  assert.equal(result.child.status, 0, result.child.stderr);
  assert.equal(result.summary?.status, 'ok');
  assert(result.summary.warnings.some(warning => /staging.*cleanup/i.test(warning)), 'Postpublication cleanup failure must be visible without claiming publication failed');
  assert(result.events.some(event => event.event === 'rename_return'));
  assert(result.events.some(event => event.event === 'cleanup_failure'));
  assert.equal(validate(f.output).status, 'ok');
  foreignIntact(f);
  assert.equal(result.receipt.staging_exists, false, 'The already published file must not be unlinked by cleanup');
});
