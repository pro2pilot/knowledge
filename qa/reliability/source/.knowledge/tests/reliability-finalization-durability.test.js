'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const root = path.resolve(process.env.KNOWLEDGE_AUDIT_SOURCE_ROOT || path.join(__dirname, '..'));
const finalization = require(path.join(root, 'tools/lib/verification-finalization'));
const cleanup = require(path.join(root, 'tools/lib/strict-temp-cleanup'));

async function scenario(t, failAt) {
  const state = fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge-kvf-durable-'));
  const identity = cleanup.captureTempDirIdentity(state);
  t.after(() => cleanup.removeTempDirStrict(state, { expectedIdentity: identity }));
  const open = fs.promises.open, events = [];
  fs.promises.open = async function(file, ...args) {
    const handle = await open.call(this, file, ...args);
    const type = String(file).endsWith('.json') ? 'file' : 'directory';
    const sync = handle.sync.bind(handle);
    handle.sync = async () => {
      events.push(type);
      if (failAt === type) throw Object.assign(new Error('Injected durability failure'), { code: 'EIO' });
      return sync();
    };
    return handle;
  };
  try {
    const save = finalization.persistFinalization(state, { batch_id: 'KVB-' + '1'.repeat(32), test: true });
    if (failAt) await assert.rejects(save, { code: 'EIO' });
    else {
      const reference = await save;
      assert.match(reference.receipt_id, /^KVF-[a-f0-9]{64}$/);
      assert.equal(events[0], 'file', 'Flush the written receipt before publishing its reference');
      if (process.platform !== 'win32') assert.ok(events.includes('directory'), 'Flush the directory entry before publishing its reference');
    }
  } finally { fs.promises.open = open; }
}
test('KVF reference follows successful file and supported directory durability barriers', t => scenario(t, null));
test('failed receipt fsync cannot produce a KVF reference', t => scenario(t, 'file'));
test('failed directory fsync cannot produce a KVF reference', { skip: process.platform === 'win32' }, t => scenario(t, 'directory'));
