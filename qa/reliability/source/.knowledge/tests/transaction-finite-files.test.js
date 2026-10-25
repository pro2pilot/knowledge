'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const root = path.resolve(process.env.KNOWLEDGE_AUDIT_SOURCE_ROOT || path.join(__dirname, '..'));
const transaction = require(path.join(root, 'tools/lib/json-transaction'));
const cleanup = require(path.join(root, 'tools/lib/strict-temp-cleanup'));

function fixture(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge-finite-journal-'));
  const identity = cleanup.captureTempDirIdentity(dir);
  t.after(() => cleanup.removeTempDirStrict(dir, { expectedIdentity: identity }));
  const file = path.join(dir, 'value.json');fs.writeFileSync(file, '{}\n');
  return { dir, file };
}
function growDuringRead(file, action) {
  const stat = fs.statSync(file), readFile = fs.readFileSync, read = fs.readSync;
  let injected = false, outer = false, consumed = 0;
  const target = value => typeof value === 'number'
    ? fs.fstatSync(value).ino === stat.ino && fs.fstatSync(value).dev === stat.dev : value === file;
  function grow() { if (!injected) { injected = true;fs.appendFileSync(file, Buffer.alloc(2 * 1024 * 1024, 32)); } }
  fs.readFileSync = function(value) {
    const yes = target(value);if (yes) { grow();outer = true; }
    try { const body = readFile.apply(this, arguments);if (yes) consumed += Buffer.byteLength(body);return body; }
    finally { if (yes) outer = false; }
  };
  fs.readSync = function(value) {
    const yes = target(value);if (yes) grow();
    const count = read.apply(this, arguments);if (yes && !outer) consumed += count;return count;
  };
  let error;
  try { action(); } catch (caught) { error = caught; }
  finally { fs.readFileSync = readFile;fs.readSync = read; }
  assert.equal(injected, true);
  assert.ok(consumed <= stat.size + 1, `A concurrent append must not extend the admitted read (read ${consumed} bytes)`);
  assert.ok(error, 'A changing physical file is not a valid transaction observation');
  return error;
}
test('transaction content hashing does not chase a growing EOF', t => {
  const f = fixture(t);const error = growDuringRead(f.file, () => transaction.__test.fileHash(f.file));
  assert.equal(error.code, 'transaction_file_changed');
});
test('tree guard hashing bounds each file read even when final drift validation rejects it', t => {
  const f = fixture(t);const error = growDuringRead(f.file, () => transaction.treeGuardHash(f.dir));
  assert.equal(error.code, 'transaction_guard_drift');
});
test('preparing an old target snapshot does not chase a growing EOF', t => {
  const f = fixture(t);const error = growDuringRead(f.file, () => transaction.commitJsonTransaction({ stateRoot: f.dir,
    transactionId: 'grow', writes: [{ path: f.file, value: { next: true } }], faultAt: 'after_initial_manifest' }));
  assert.equal(error.code, 'transaction_file_changed');
  assert.equal(fs.existsSync(path.join(transaction.__test.transactionRoot(f.dir), 'grow')), false);
});
test('streamed transaction hashes preserve ordinary large-file content exactly', t => {
  const f = fixture(t);const body = Buffer.alloc(4 * 1024 * 1024 + 17, 71);fs.writeFileSync(f.file, body);
  assert.equal(transaction.__test.fileHash(f.file), crypto.createHash('sha256').update(body).digest('hex'));
});
