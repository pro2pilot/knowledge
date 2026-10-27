'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const importer = require('./importer');
const currentCopy = require('../../../source/.knowledge/tools/lib/verification-isolated-copy');

const sha = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const cmp = (a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b));

function makeInput(entries = [{ path: 'src/main.js', data: Buffer.from('console.log("slice")\n'), mode: 0o644 }], dirs = ['src']) {
  const files = entries.map(({ path: name, data, mode }) => ({
    path: name, bytes: data.length, mode, sha256: sha(data), data_base64: data.toString('base64')
  })).sort((a, b) => cmp(a.path, b.path));
  dirs = [...dirs].sort(cmp);
  const manifest_sha256 = sha(Buffer.from(JSON.stringify(files.map(({ path: name, bytes, mode, sha256 }) => ({ bytes, mode, path: name, sha256 })))));
  const directories_sha256 = sha(Buffer.from(JSON.stringify(dirs)));
  const value = { schema_version: importer.SCHEMA, directories: dirs, files, manifest_sha256, directories_sha256 };
  return { value, bytes: Buffer.from(JSON.stringify(value)) };
}

function rejectsCode(bytes, code) {
  assert.throws(() => importer.validateImport(bytes), error => error.code === code);
}

test('validates an immutable copy input against current manifest and directory digests', () => {
  const input = makeInput();
  const result = importer.validateImport(input.bytes);
  assert.equal(result.schema_version, importer.SCHEMA);
  assert.equal(result.files.length, 1);
  assert.equal(result.total_bytes, Buffer.byteLength('console.log("slice")\n'));
  assert.equal(result.manifest_sha256, input.value.manifest_sha256);
  assert.equal(result.directories_sha256, input.value.directories_sha256);
  assert.equal(importer.manifestDigest(result.files), currentCopy.manifestDigest(result.files));
  assert.equal(importer.directoriesDigest(result.directories), currentCopy.directoriesDigest(result.directories));
});

test('rejects extra fields, booleans used as integers, and noncanonical wire JSON', () => {
  const extra = makeInput().value;
  extra.untrusted_root = '/tmp/project';
  rejectsCode(Buffer.from(JSON.stringify(extra)), 'import_schema_invalid');

  const bool = makeInput().value;
  bool.files[0].bytes = true;
  rejectsCode(Buffer.from(JSON.stringify(bool)), 'import_file_limit');

  const duplicate = Buffer.from('{"schema_version":"knowledge-linux-service-copy-input.v1","schema_version":"knowledge-linux-service-copy-input.v1"}');
  rejectsCode(duplicate, 'import_wire_noncanonical');
});

test('rejects malformed digests, noncanonical base64, and file payload disagreement', () => {
  for (const encoded of ['YQ', 'YQ===', 'Y Q=']) {
    const input = makeInput([{ path: 'a.js', data: Buffer.from('a'), mode: 0o644 }], []).value;
    input.files[0].data_base64 = encoded;
    rejectsCode(Buffer.from(JSON.stringify(input)), 'import_encoding_invalid');
  }
  const input = makeInput([{ path: 'a.js', data: Buffer.from('a'), mode: 0o644 }], []).value;
  input.files[0].sha256 = 'A'.repeat(64);
  rejectsCode(Buffer.from(JSON.stringify(input)), 'import_encoding_invalid');
});

test('rejects absolute, traversal, non-NFC, unpaired-surrogate, reserved, secret, and runtime-state paths', () => {
  for (const name of ['/tmp/a', '../a', 'a\\b', 'dir/CON.txt', 'a.', 'a/../b', 'e\u0301.txt', '\ud800.js', '.env', 'id_ed25519', 'key.pem', '.knowledge/cache/x.json']) {
    const input = makeInput([{ path: name, data: Buffer.from('x'), mode: 0o644 }], []).value;
    rejectsCode(Buffer.from(JSON.stringify(input)), name === '.env' || name === 'id_ed25519' || name === 'key.pem' || name === '.knowledge/cache/x.json'
      ? 'import_state_excluded' : 'import_path_invalid');
  }
  const replacement = makeInput([{ path: 'replacement-\ufffd.js', data: Buffer.from('x'), mode: 0o644 }], []);
  assert.equal(importer.validateImport(replacement.bytes).files[0].path, 'replacement-\ufffd.js');
  const credentialDir = makeInput([{ path: '.ssh/known_hosts', data: Buffer.from('x'), mode: 0o644 }], ['.ssh']);
  rejectsCode(credentialDir.bytes, 'import_state_excluded');
});

test('rejects duplicate/case-colliding entries, missing parents, and file-directory conflicts', () => {
  const duplicate = makeInput([{ path: 'same.js', data: Buffer.from('1'), mode: 0o644 },
    { path: 'same.js', data: Buffer.from('2'), mode: 0o644 }], []);
  rejectsCode(duplicate.bytes, 'import_path_collision');

  const collision = makeInput([{ path: 'A.js', data: Buffer.from('1'), mode: 0o644 },
    { path: 'a.js', data: Buffer.from('2'), mode: 0o644 }], []);
  rejectsCode(collision.bytes, 'import_path_collision');

  const missing = makeInput([{ path: 'missing/file.js', data: Buffer.from('x'), mode: 0o644 }], []);
  rejectsCode(missing.bytes, 'import_parent_missing');

  const conflict = makeInput([{ path: 'src', data: Buffer.from('x'), mode: 0o644 }], ['src']);
  rejectsCode(conflict.bytes, 'import_path_collision');
});

test('rejects unsupported modes, entry overflow, file overflow, and bad aggregate digests', () => {
  const mode = makeInput([{ path: 'a.js', data: Buffer.from('x'), mode: 0o600 }], []).value;
  rejectsCode(Buffer.from(JSON.stringify(mode)), 'import_mode_invalid');

  const many = makeInput(Array.from({ length: 129 }, (_, i) => ({
    path: `f${String(i).padStart(3, '0')}`, data: Buffer.alloc(0), mode: 0o644
  })), []).bytes;
  rejectsCode(many, 'import_entry_limit');

  const tooLarge = makeInput([{ path: 'big.js', data: Buffer.alloc(64 * 1024 + 1), mode: 0o644 }], []).value;
  rejectsCode(Buffer.from(JSON.stringify(tooLarge)), 'import_file_limit');

  const digest = makeInput();
  digest.value.manifest_sha256 = '0'.repeat(64);
  rejectsCode(Buffer.from(JSON.stringify(digest.value)), 'import_manifest_digest_mismatch');
});

test('imports into fresh POSIX roots with read-only source ownership and a generated private receipt', t => {
  if (process.platform === 'win32') return t.skip('Windows does not provide the POSIX owner/group/mode contract');
  assert.notEqual(process.getuid(), 0, 'real import test must run as a non-root QA authority');
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge-slice-'));
  const sourceDir = path.join(parent, 'source');
  const stateDir = path.join(parent, 'state');
  fs.mkdirSync(sourceDir, { mode: 0o700 });
  fs.mkdirSync(stateDir, { mode: 0o700 });
  const input = makeInput([
    { path: 'src/main.js', data: Buffer.from('main\n'), mode: 0o644 },
    { path: 'tools/run.js', data: Buffer.from('#!/usr/bin/env node\n'), mode: 0o755 }
  ], ['src', 'tools']);
  try {
    const result = importer.importProject(input.bytes, sourceDir, stateDir,
      { authorityUid: process.getuid(), workerGid: process.getgid() });
    assert.equal(result.status, 'IMPORTED_BYTES_UNSEALED');
    assert.equal(result.manifest_sha256, input.value.manifest_sha256);
    assert.equal(result.directories_sha256, input.value.directories_sha256);
    assert.equal(result.files, 2);
    assert.equal(fs.statSync(sourceDir).mode & 0o777, 0o550);
    assert.equal(fs.statSync(path.join(sourceDir, 'src')).mode & 0o777, 0o550);
    assert.equal(fs.statSync(path.join(sourceDir, 'src/main.js')).mode & 0o777, 0o440);
    assert.equal(fs.statSync(path.join(sourceDir, 'tools/run.js')).mode & 0o777, 0o550);
    for (const file of ['src/main.js', 'tools/run.js']) {
      const st = fs.lstatSync(path.join(sourceDir, file));
      assert.equal(st.isSymbolicLink(), false);
      assert.equal(st.nlink, 1);
      assert.equal(st.uid, process.getuid());
      assert.equal(st.gid, process.getgid());
    }
    const receiptPath = path.join(stateDir, result.receipt_name);
    const receiptStat = fs.lstatSync(receiptPath);
    assert.equal(receiptStat.mode & 0o777, 0o600);
    assert.equal(receiptStat.uid, process.getuid());
    const receipt = JSON.parse(fs.readFileSync(receiptPath, 'utf8'));
    assert.equal(receipt.status, 'IMPORTED_BYTES_UNSEALED');
    assert.equal(receipt.manifest_sha256, input.value.manifest_sha256);
    assert.equal(Object.hasOwn(receipt, 'source_path'), false);
  } finally {
    // Test-only cleanup of the exact temporary fixture owned by this process.
    fs.chmodSync(sourceDir, 0o700);
    for (const directory of ['src', 'tools']) fs.chmodSync(path.join(sourceDir, directory), 0o700);
    fs.rmSync(parent, { recursive: true, force: true });
  }
});

test('refuses a nonempty source root and symlinked source path before creating imported entries', t => {
  if (process.platform === 'win32') return t.skip('Windows does not provide the POSIX owner/group/mode contract');
  assert.notEqual(process.getuid(), 0, 'real import test must run as a non-root QA authority');
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge-slice-'));
  const sourceDir = path.join(parent, 'source');
  const stateDir = path.join(parent, 'state');
  fs.mkdirSync(sourceDir, { mode: 0o700 });
  fs.mkdirSync(stateDir, { mode: 0o700 });
  const symlinkDir = path.join(parent, 'source-link');
  fs.symlinkSync(sourceDir, symlinkDir, 'dir');
  const input = makeInput();
  try {
    assert.throws(() => importer.importProject(input.bytes, symlinkDir, stateDir,
      { authorityUid: process.getuid(), workerGid: process.getgid() }), error => error.code === 'import_root_unsafe');
    fs.writeFileSync(path.join(sourceDir, 'unexpected'), 'x');
    assert.throws(() => importer.importProject(input.bytes, sourceDir, stateDir,
      { authorityUid: process.getuid(), workerGid: process.getgid() }), error => error.code === 'import_source_not_fresh');
  } finally { fs.rmSync(parent, { recursive: true, force: true }); }
});
