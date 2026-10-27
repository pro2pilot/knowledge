'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { EventEmitter } = require('events');
const cp = require('child_process');

async function lateRead(phase) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge-smoke-deadline-'));
  const repo = path.join(root, 'repo'), state = path.join(repo, '.state');
  fs.mkdirSync(state, { recursive: true });
  const system = path.resolve(__dirname, '..');
  const entry = require.resolve('../tools/watch-smoke');
  const savedModule = require.cache[entry];
  const original = { spawn: cp.spawn, read: fs.readFileSync, write: fs.writeFileSync, log: console.log,
    watch: process.env.KNOWLEDGE_SMOKE_WATCH_MS };
  const identity = { controller_pid: 12345, worker_pid: 54321, epoch_id: 'a'.repeat(16),
    attempt_id: 'b'.repeat(32), watcher_id: 'critic-12345-' + 'a'.repeat(16) };
  let child, probe, reads = 0, blockedMs = 0, returned, failure;
  process.env.KNOWLEDGE_SMOKE_WATCH_MS = '20';
  cp.spawn = () => {
    child = new EventEmitter();
    Object.assign(child, { pid: identity.controller_pid, exitCode: null, signalCode: null,
      connected: true, stderr: new EventEmitter() });
    child.send = () => {
      child.exitCode = 0;
      child.emit('message', { type: 'knowledge:watch-terminal', status: 'stopped', durable_stop_confirmed: true,
        readiness: identity, cleanup: { status: 'completed', output_closed: true, active_processes: 0 } });
      setImmediate(() => child.emit('close', 0, null));
    };
    queueMicrotask(() => child.emit('message', { type: 'knowledge:watch-ready', ...identity }));
    return child;
  };
  fs.writeFileSync = function (file, ...args) {
    if (String(file).includes('knowledge-smoke-probe-')) probe = path.basename(file);
    return original.write.call(this, file, ...args);
  };
  fs.readFileSync = function (file, ...args) {
    if (path.resolve(String(file)) !== path.join(state, 'maintenance/automation_status.json')) return original.read.call(this, file, ...args);
    reads++;
    const row = { pid: identity.controller_pid, worker_pid: identity.worker_pid, epoch_id: identity.epoch_id,
      attempt_id: identity.attempt_id, running: child.exitCode === null };
    const value = { active_watchers: { [identity.watcher_id]: row } };
    const block = child.exitCode === null && (phase === 'startup' ? reads === 2 : Boolean(probe));
    if (block) {
      const started = performance.now(), end = started + (phase === 'startup' ? 250 : 60);
      while (performance.now() < end) {}
      blockedMs = Math.round(performance.now() - started);
    }
    if (probe && child.exitCode === null) value.last_watch_sync_result = { schema_version: 'knowledge-watch-sync.v1',
      ...identity, changed_files: [probe], finished_at: new Date().toISOString(), ok: true, exit_code: 0,
      signal: null, error_code: null, cleanup: { status: 'completed' } };
    return JSON.stringify(value);
  };
  console.log = () => {};
  try {
    delete require.cache[entry];
    try {
      returned = await require(entry).main([`--target-root=${repo}`, `--state-root=${state}`, `--system-root=${system}`,
        '--setup-timeout-ms=100', '--work-timeout-ms=100', '--cleanup-timeout-ms=100', '--watch-startup-ms=100']);
    } catch (error) { failure = error; }
  } finally {
    cp.spawn = original.spawn;fs.readFileSync = original.read;fs.writeFileSync = original.write;console.log = original.log;
    if (original.watch === undefined) delete process.env.KNOWLEDGE_SMOKE_WATCH_MS;else process.env.KNOWLEDGE_SMOKE_WATCH_MS = original.watch;
    if (savedModule) require.cache[entry] = savedModule;else delete require.cache[entry];
    const probes = fs.readdirSync(repo).filter(name => name.startsWith('knowledge-smoke-probe-'));
    fs.rmSync(root, { recursive: true, force: true });
    assert.equal(probes.length, 0, 'The smoke must remove its own probe after deadline refusal');
  }
  assert(blockedMs >= (phase === 'startup' ? 250 : 60), 'The status read must actually cross the deadline');
  assert.equal(returned, undefined, 'A late matching ready/result cannot produce PASS');
  assert.match(failure?.message || '', phase === 'startup' ? /startup budget exceeded/ : /before the deadline/);
}

test('smoke refuses matching readiness observed by a synchronous read after its absolute deadline', () => lateRead('startup'));
test('smoke refuses matching successful receipt observed by a synchronous read after its absolute deadline', () => lateRead('probe'));
