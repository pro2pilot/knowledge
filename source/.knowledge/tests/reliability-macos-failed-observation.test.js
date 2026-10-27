'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const core = require('../tools/lib/verification-execution');
const writer = require('../tools/lib/repair-on-touch');
const finalization = require('../tools/lib/verification-finalization');
const production = require('../tools/lib/verification-darwin-production');
function bind(record) {
  record.content_sha256 = core.executionDigest(record);record.execution_id = 'KVE-' + record.content_sha256;return record;
}
function observation(patch = {}) {
  const snapshot = [{ path: 'run.js', sha256: 'a'.repeat(64) }];
  return bind({ schema_version: 'knowledge-verification-execution-observation.v1', task_id: 'failed-command', session_id: 'qa',
    command_argv: ['node', 'run.js'], command: '"node" "run.js"', cwd: '.', status: 'fail', exit_code: 7, signal: null,
    timed_out: false, duration_ms: 1, executed_at: new Date().toISOString(), executed_by: 'qa',
    runtime_binding: 'process_exec_path', runtime_sha256: 'b'.repeat(64), environment_profile: 'sanitized_node',
    stdout_sha256: 'c'.repeat(64), stderr_sha256: 'd'.repeat(64), stdout_bytes: 0, stderr_bytes: 7,
    source_snapshot: snapshot, source_snapshot_before: snapshot, batch_id: 'KVB-' + 'e'.repeat(32), batch_ordinal: 0,
    batch_public_key: 'f'.repeat(88), batch_request_sha256: '1'.repeat(64), ...patch });
}

test('failed command observation persists while strict readers and finalization reject acceptance', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'macos-failed-observation-'));
  try {
    const record = observation();assert.deepEqual(core.validateExecutionObservation(record).errors, []);
    const saved = writer.saveExecutionRecord(root, record);assert.ok(fs.statSync(saved.path).isFile());
    const loaded = core.readExecutionRecord(root, record.execution_id);assert.ok(loaded);
    assert.equal(core.validateExecutionObservation(loaded.record).digest, loaded.expected_digest);
    assert.equal(core.loadExecutionRecord(root, record.execution_id), null);
    assert.equal(core.validateExecutionRecord(record).ok, false);
    assert.throws(() => finalization.requireFinalizedExecutions(root, [record.execution_id], []),
      { code: 'verification_finalization_required' });
    const request = { tests: [{ argv: ['node', 'run.js'] }] }, message = { result: [{ record }] };
    const args = [message, request, record.batch_id, record.batch_request_sha256, record.batch_public_key];
    assert.equal(production.completeResult(...args), false);
    assert.deepEqual(production.firstCommandFailure(...args),
      { execution_id: record.execution_id, status: 'fail', exit_code: 7, signal: null });
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('failed observation validation retains exact schema runtime privacy and content checks', () => {
  for (const patch of [{ status: 'pass' }, { exit_code: 0 }, { exit_code: 256 }, { exit_code: true },
    { exit_code: 7.5 }, { signal: 'SIGKILL' }, { timed_out: true }, { runtime_sha256: null },
    { environment_profile: 'inherited_command' }, { cwd: '../escape' }, { source_snapshot: [] },
    { schema_version: 'knowledge-verification-execution.v2' }, { task_id: '/private/user/path' }]) {
    assert.equal(core.validateExecutionObservation(observation(patch)).ok, false, JSON.stringify(patch));
  }
  const changed = observation();changed.stderr_bytes++;
  assert.equal(core.validateExecutionObservation(changed).ok, false);
});

test('failed observation schema cannot be promoted through pass fields or strict writer validation', () => {
  const passLike = observation({ status: 'pass', exit_code: 0 });
  assert.equal(core.validateExecutionObservation(passLike).ok, false);
  assert.equal(core.validateExecutionRecord(passLike).ok, false);
  assert.equal(writer.validateExecutionRecord(passLike).ok, false);
  const failedV2 = observation({ schema_version: 'knowledge-verification-execution.v2' });
  assert.equal(core.validateExecutionRecord(failedV2).ok, false);
  assert.equal(writer.validateExecutionRecord(failedV2).ok, false);
  assert.throws(() => writer.saveExecutionRecord(os.tmpdir(), failedV2), { code: 'verification_execution_invalid' });
});

// Real fixed worker protocol, with a synthetic command core. These tests
// establish commit/error transport semantics, not native process closure.
async function workerProtocol(records) {
  const vm = require('node:vm');
  const messages = []; let handler;
  const source = fs.readFileSync(path.join(__dirname, '../tools/lib/verification-worker.js'), 'utf8');
  vm.runInNewContext(source, {
    require(name) {
      assert.equal(name, './repair-on-touch');
      return { __runVerificationTestsCore: async (_request, hooks) => {
        for (const record of records) await hooks.committed({ record, relative_path: 'fixture.json' });
        return records.map(record => ({ record }));
      } };
    },
    process: { on(name, fn) { assert.equal(name, 'message'); handler = fn; },
      send(message, callback) { messages.push(JSON.parse(JSON.stringify(message))); callback(); } }
  }, { filename: 'verification-worker.js' });
  await handler({ protocol: 'knowledge-verification-supervisor.v1', type: 'run', deadline_ns: '12345', request: {} });
  return messages;
}

test('fixed worker preserves prior successful commit and rejects failed observation before result or ACK', async () => {
  const pass = observation({ schema_version: 'knowledge-verification-execution.v2', status: 'pass', exit_code: 0 });
  const failed = observation();
  const messages = await workerProtocol([pass, failed]);
  assert.deepEqual(messages.map(m => m.type), ['committed', 'error']);
  assert.equal(messages[1].error.code, 'verification_command_failed');
  assert.deepEqual(messages[1].error.command_failure, { execution_id: failed.execution_id, status: 'fail', exit_code: 7, signal: null });
});

test('fixed worker never promotes failed observation using pass status alone', async () => {
  for (const edit of [{}, { status: 'pass' }, { status: 'pass', exit_code: 0 },
    { schema_version: 'knowledge-verification-execution.v2', status: 'pass', exit_code: 0, signal: 'SIGKILL' },
    { schema_version: 'knowledge-verification-execution.v2', status: 'pass', exit_code: 0, timed_out: true }]) {
    const messages = await workerProtocol([observation(edit)]);
    assert.deepEqual(messages.map(m => m.type), ['error']);
    assert.equal(messages[0].error.code, 'verification_command_failed');
  }
});

test('fixed worker still emits complete successful command result after successful commits', async () => {
  const pass = observation({ schema_version: 'knowledge-verification-execution.v2', status: 'pass', exit_code: 0 });
  const messages = await workerProtocol([pass]);
  assert.deepEqual(messages.map(m => m.type), ['committed', 'result']);
  assert.equal(messages[1].result[0].record.status, 'pass');
});

test('authority error envelope preserves typed command failure and prior successful commits', () => {
  const vm = require('node:vm');
  const { EventEmitter } = require('node:events');
  const source = fs.readFileSync(path.join(__dirname, '../tools/lib/verification-watchdog.js'), 'utf8');
  const failed = observation();
  const commandFailure = { execution_id: failed.execution_id, status: 'fail', exit_code: 7, signal: null };
  const completed = [{ execution_id: 'KVE-' + 'a'.repeat(64), status: 'pass' }];
  const worker = new EventEmitter();worker.stdin = new EventEmitter();
  worker.platform = 'win32';
  let envelope, candidate;
  worker.stdout = { write(body, callback) { envelope = JSON.parse(body);callback(); } };
  worker.send = message => { candidate = message; };
  const loaded = { exports: {} };
  vm.runInNewContext(source, {
    module: loaded, Buffer, process: worker,
    require(name) {
      if (name === './verification-supervisor') return { __test: { runAuthority() {
        throw Object.assign(new Error('Verification command did not pass'), {
          code: 'verification_command_failed', command_failure: commandFailure,
          completed_executions: completed, teardown: { status: 'completed' }
        });
      } } };
      return require(name);
    }
  }, { filename: 'verification-watchdog.js' });
  loaded.exports.__test.runAuthority();
  worker.emit('message', { protocol: 'knowledge-verification-supervisor.v1', type: 'run',
    payload: { timeout_ms: 1000, started_ns: '1' } });
  worker.stdin.emit('data', Buffer.from('{}'));
  worker.stdin.emit('end');
  assert.equal(envelope.status, 'failed');
  assert.equal(envelope.error.code, 'verification_command_failed');
  assert.deepEqual(envelope.error.command_failure, commandFailure);
  assert.deepEqual(envelope.error.completed_executions, completed);
  assert.equal(envelope.error.teardown.status, 'completed');
  assert.equal(envelope.acceptances, undefined);
  assert.equal(candidate.status, 'failed');
});
