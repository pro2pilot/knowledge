'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const source = path.resolve(process.env.KNOWLEDGE_AUDIT_SOURCE_ROOT || path.join(__dirname, '..'));
const transaction = require(path.join(source, 'tools/lib/json-transaction'));
const { captureTempDirIdentity, removeTempDirStrict } = require(path.join(source, 'tools/lib/strict-temp-cleanup'));
test('transaction manifest enforces its byte limit during growth after fstat', t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge-transaction-read-'));
  const identity = captureTempDirIdentity(root);
  t.after(() => removeTempDirStrict(root, { expectedIdentity: identity }));
  const target = path.join(root, 'value.json'); fs.writeFileSync(target, '{}\n');
  assert.throws(() => transaction.commitJsonTransaction({ stateRoot: root, transactionId: 'bounded-manifest',
    writes: [{ path: target, value: { value: 1 } }], faultAt: 'after_initial_manifest' }));
  const tx = path.join(transaction.__test.transactionRoot(root), 'bounded-manifest');
  const file = path.join(tx, 'manifest.json'); const st = fs.statSync(file);
  const rawRead = fs.readFileSync, chunkRead = fs.readSync;
  let injected = false, bytesConsumed = 0;
  const isManifest = fd => typeof fd === 'number' && fs.fstatSync(fd).ino === st.ino && fs.fstatSync(fd).dev === st.dev;
  const grow = () => { if (!injected) { injected = true; fs.appendFileSync(file, Buffer.alloc(34 * 1024 * 1024, 32)); } };
  fs.readFileSync = function(fd) {
    const observed = isManifest(fd); if (observed) grow();
    const body = rawRead.apply(this, arguments); if (observed) bytesConsumed += Buffer.byteLength(body);
    return body;
  };
  fs.readSync = function(fd) {
    const observed = isManifest(fd); if (observed) grow();
    const count = chunkRead.apply(this, arguments); if (observed) bytesConsumed += count;
    return count;
  };
  try { assert.throws(() => transaction.inspectTransaction(tx)); }
  finally { fs.readFileSync = rawRead; fs.readSync = chunkRead; }
  assert.equal(injected, true, 'The mutation must occur after opening and validating the actual manifest');
  assert.ok(bytesConsumed <= 32 * 1024 * 1024 + 1, `The declared 32 MiB limit must bound the read itself (observed ${bytesConsumed} bytes)`);
  assert.equal(fs.readFileSync(target, 'utf8'), '{}\n');
});
