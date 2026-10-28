'use strict';
// Model only the broker transport; execute the shipped client parser and its
// waiter lifecycle unchanged. This is not physical namespace qualification.
const test = require('node:test'), assert = require('node:assert/strict');
const fs = require('node:fs'), path = require('node:path'), vm = require('node:vm');
const { createRequire } = require('node:module');
const { EventEmitter } = require('node:events');
const { PassThrough, Writable } = require('node:stream');
const turn = () => new Promise(resolve => setImmediate(resolve));
const schema = 'knowledge-linux-native-service.v1';
function model() {
  const child = new EventEmitter(), requests = [], failures = [];
  child.pid = 30500;child.stdout = new PassThrough();child.stderr = new PassThrough();
  let ended = false, inspectRequest = null;
  function close(code, signal) {
    if (ended) return;ended = true;
    child.stdout.end();child.stderr.end();
    setImmediate(() => { child.emit('exit', code, signal);child.emit('close', code, signal); });
  }
  child.stdin = new Writable({ write(bytes, encoding, callback) {
    inspectRequest?.(bytes);requests.push(Buffer.from(bytes));callback();
  } });
  child.stdin.on('finish', () => close(0, null));
  child.kill = () => { close(null, 'SIGKILL');return true; };child.unref = () => {};
  child.stdio = [child.stdin, child.stdout, child.stderr];
  const filename = path.resolve(__dirname, '../tools/lib/verification-linux-service-client.js');
  const actualRequire = createRequire(filename), exported = { exports: {} };
  const modelRequire = name => name === 'node:child_process' ? { spawn: () => child } : actualRequire(name);
  const modelProcess = { platform: 'linux', env: {}, hrtime: process.hrtime };
  vm.compileFunction(fs.readFileSync(filename, 'utf8'), ['require', 'module', 'exports', '__filename', '__dirname', 'process'],
    { filename })(modelRequire, exported, exported.exports, filename, path.dirname(filename), modelProcess);
  const deadline = process.hrtime.bigint() + 3_000_000_000n;
  const client = exported.exports.createClient({ config: { broker_path: exported.exports.BROKER_PATH },
    nonce: 'a'.repeat(64), workDeadline: deadline, cleanupMs: 1000, onFailure: error => failures.push(error.code) });
  function publish(type, value) {
    const body = value === null ? Buffer.alloc(0) : Buffer.from(JSON.stringify(value));
    const header = Buffer.alloc(16);
    [0x4b4c4f31, 1, type, body.length].forEach((number, index) => header.writeUInt32LE(number, index * 4));
    child.stdout.write(Buffer.concat([header, body]));
  }
  const event = (name, values) => publish(1, { schema_version: schema, event: name, ...values });
  return { client, requests, failures, deadline, publish, event, onRequest: callback => { inspectRequest = callback; } };
}
test('Linux modeled writer PID reuse waits for the fresh native request ordinal and birth', async () => {
  const fixture = model(), { client, deadline, event } = fixture;
  try {
    const hello = client.hello();event('capability', { status: 'ready' });await hello;
    let framedOrdinal;
    fixture.onRequest(bytes => {
      if (bytes.readUInt32LE(8) === 2) assert.equal(framedOrdinal, bytes.readUInt32LE(12),
        'registration identity must be retained before its request can reach the broker');
    });
    const first = client.registerWriter(4321, deadline, ordinal => { framedOrdinal = ordinal; });await turn();
    const firstOrdinal = fixture.requests.at(-1).readUInt32LE(12);
    event('writer_registered', { pid: 4321, ordinal: firstOrdinal, birth_ticks: '111' });
    const firstRegistration = await first;
    event('writer_closed', { pid: 4321, registration_ordinal: firstOrdinal, birth_ticks: '111' });
    await client.writerClosed(4321, deadline, firstRegistration);

    let registered = false;
    const second = client.registerWriter(4321, deadline, ordinal => { framedOrdinal = ordinal; })
      .then(value => { registered = true;return value; });
    await turn();
    const secondOrdinal = fixture.requests.at(-1).readUInt32LE(12);
    assert.notEqual(secondOrdinal, firstOrdinal);
    assert.equal(registered, false, 'an earlier lifetime of the same PID cannot satisfy fresh registration');
    event('writer_registered', { pid: 4321, ordinal: secondOrdinal, birth_ticks: '222' });
    const secondRegistration = await second;
    assert.equal(secondRegistration.value.birth_ticks, '222');
    assert.equal(secondRegistration.value.ordinal, secondOrdinal);
    let closed = false;
    const secondClosed = client.writerClosed(4321, deadline, secondRegistration).then(value => { closed = true;return value; });
    await turn();
    assert.equal(closed, false, 'cached closure from the old PID birth cannot close a new writer');
    event('writer_closed', { pid: 4321, registration_ordinal: secondOrdinal, birth_ticks: '222' });
    assert.equal((await secondClosed).value.birth_ticks, '222');
    assert.deepEqual(fixture.failures, []);
  } finally { await client.finish(deadline); }
});
test('Linux modeled empty failure payload preserves subsequent native writer closure frames', async () => {
  const fixture = model(), { client, deadline, event } = fixture;
  try {
    const hello = client.hello();event('capability', { status: 'ready' });await hello;
    event('terminal', { status: 'cancelled', result_bytes: 0 });
    fixture.publish(2, null);
    event('writer_closed', { pid: 4321, registration_ordinal: 2, birth_ticks: '111' });
    const result = await client.event('authority_result', deadline);
    assert.equal(result.value, null);
    assert.equal(result.raw, '');
    assert.equal((await client.event('writer_closed', deadline)).value.birth_ticks, '111');
    assert.deepEqual(fixture.failures, []);
  } finally { await client.finish(deadline); }
});
