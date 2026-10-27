'use strict';
const test = require('node:test'), assert = require('node:assert/strict');
const fs = require('node:fs'), vm = require('node:vm'), path = require('node:path');
const { EventEmitter } = require('node:events');
const { readyIdentity, watchPolicy } = require('../tools/watch-maintenance');
const { smokeLimits, matchesReadyObservation, probeResult } = require('../tools/watch-smoke');
const epoch = 'a'.repeat(16), attempt = 'b'.repeat(32);
const message = { type: 'ready', controller_pid: 123, worker_pid: 124, epoch_id: epoch,
  attempt_id: attempt, watcher_id: `agent-123-${epoch}` };
const identity = readyIdentity(message, 123, epoch);

test('smoke rejects a foreign attempt even when the OS reused its controller PID', () => {
  assert(identity);
  const row = { running: true, pid: 123, worker_pid: 124, epoch_id: epoch, attempt_id: attempt };
  const state = { active_watchers: { [identity.watcher_id]: row } };
  assert(matchesReadyObservation(state, identity));
  for (const delta of [{ attempt_id: 'c'.repeat(32) }, { epoch_id: 'd'.repeat(16) }, { worker_pid: 125 }, { running: false }]) {
    assert.equal(matchesReadyObservation({ active_watchers: { [identity.watcher_id]: { ...row, ...delta } } }, identity), false);
  }
  assert.equal(matchesReadyObservation(state, null), false, 'disk state cannot replace the private readiness handshake');
  assert.equal(readyIdentity({ ...message, epoch_id: 'd'.repeat(16) }, 123, epoch), null);
  assert.equal(readyIdentity({ ...message, attempt_id: '' }, 123, epoch), null);
});

test('probe completion is one immutable attempt record, independent of unrelated global fields or wall clock rollback', () => {
  const row = { schema_version: 'knowledge-watch-sync.v1', watcher_id: identity.watcher_id, attempt_id: attempt,
    epoch_id: epoch, changed_files: ['unique-probe'], finished_at: '2001-01-01T00:00:00.000Z', ok: true, exit_code: 0 };
  assert.equal(probeResult({ last_watch_sync_result: row, last_sync_exit_code: 9 }, identity, 'unique-probe'), row);
  for (const delta of [{ attempt_id: 'c'.repeat(32) }, { epoch_id: 'd'.repeat(16) }, { changed_files: ['old-probe'] }, { finished_at: 'invalid' }]) {
    assert.equal(probeResult({ last_watch_sync_result: { ...row, ...delta } }, identity, 'unique-probe'), null);
  }
  assert.equal(probeResult({ last_watch_changed_files: ['unique-probe'], last_sync_exit_code: 0 }, identity, 'unique-probe'), null);
});

test('startup, useful work and cleanup retain distinct conservative bounded allowances', () => {
  const budgets = { setupMs: 10000, workMs: 15000, cleanupMs: 5000 };
  assert.equal(watchPolicy({}, { budgets }).startupMs, 20000);
  const limits = smokeLimits({}, { budgets, watchMs: 15000 });
  assert.deepEqual(limits, { readyMs: 30000, watchMs: 15000, cleanupMs: 5000, outerMs: 54000, command: { ...budgets, progressMs: 0 } });
  assert.equal(smokeLimits({}, { budgets }).watchMs, 72500);
  assert.equal(smokeLimits({}, { budgets, debounceMs: 60000 }).watchMs, 131000);
  assert.throws(() => smokeLimits({}, { budgets, debounceMs: NaN }));
  for (const startupMs of [0, -1, NaN, Infinity, '1.5', 2147483647]) {
    assert.throws(() => watchPolicy({}, { budgets, startupMs }), { code: 'watcher_startup_budget_invalid' });
  }
  assert.throws(() => smokeLimits({}, { budgets, watchMs: 2147483647 }));
});

function pendingServer() {
  let callback, accept, closes = 0;
  const server = new EventEmitter();
  server.listen = (port, host, cb) => { callback = cb; };
  server.close = () => { closes++; };
  const mod = { exports: {} };
  const file = path.resolve(__dirname, '../tools/lib/command-holder-channel.js');
  vm.runInNewContext(fs.readFileSync(file, 'utf8'), { module: mod, exports: mod.exports,
    require: name => name === 'net' ? { createServer: cb => { accept = cb; return server; } } : require(name), Buffer, TextDecoder, setTimeout, clearTimeout });
  return { ...mod.exports, lateListen: () => callback(), closes: () => closes,
    peer: socket => accept(socket), lateError: () => server.emit('error', new Error('late listen error')) };
}
test('private endpoint setup timeout closes a pending listener and rejects late activation', async () => {
  const f = pendingServer();
  await assert.rejects(f.createServer({ timeoutMs: 10 }), { code: 'holder_channel_setup_timeout' });
  assert.equal(f.closes(), 1);f.lateListen();assert.equal(f.closes(), 2);
});
test('user cancellation interrupts pending private endpoint setup before any worker exists', async () => {
  const f = pendingServer(), abort = new AbortController();
  const pending = f.createServer({ timeoutMs: 1000, signal: abort.signal });abort.abort();
  await assert.rejects(pending, { code: 'holder_channel_setup_cancelled' });
  assert.equal(f.closes(), 1);f.lateListen();assert.equal(f.closes(), 2);
});
test('setup timeout closes unauthenticated pending peers and safely consumes late listen errors', async () => {
  const f = pendingServer(), peer = new EventEmitter();let destroyed = false;
  peer.destroy = () => { destroyed = true;peer.emit('close'); };
  const pending = f.createServer({ timeoutMs: 10 });f.peer(peer);
  await assert.rejects(pending, { code: 'holder_channel_setup_timeout' });
  assert(destroyed);assert.doesNotThrow(f.lateError);
});
