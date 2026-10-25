'use strict';
// Real filesystem publication/cleanup through the exact producer source.
// Only Windows descriptor/path grammar and signing are modeled in the first
// three tests on this host. Cryptographic predicates have a separate suite;
// actual Windows path + native holder coverage is a distinct required gate.
const test = require('node:test'), assert = require('node:assert/strict'), fs = require('node:fs'), os = require('node:os'), path = require('node:path');
const Module = require('node:module');
const lib = path.resolve(__dirname, '../tools/lib');
const before = process.env.KNOWLEDGE_TEST_WINDOWS_PUBLICATION_BEFORE;
function load(name, overrides = {}) {
  const filename = path.join(lib, name), input = before ? path.join(before, name) : filename;
  const compiled = new Module(filename, module); compiled.filename = filename; compiled.paths = Module._nodeModulePaths(lib);
  const fallback = Module.createRequire(filename); compiled.require = request => Object.hasOwn(overrides, request) ? overrides[request] : fallback(request);
  compiled._compile(fs.readFileSync(input, 'utf8'), filename); return compiled.exports;
}
function fixture() {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'windows-receipt-model-')), st = fs.lstatSync(directory, { bigint: true });
  const store = { directory, dev: String(st.dev), ino: String(st.ino), scope_id: 'a'.repeat(64) };
  const scope = { descriptor: { secondary: {}, receipt_store: store } }, value = { body: { role: 'primary', scope_id: store.scope_id }, signature: 'modeled-signature' };
  const actual = require('../tools/lib/command-windows-protocol');
  const protocol = { ...actual, validStore: candidate => JSON.stringify(candidate) === JSON.stringify(store),
    validateScope: candidate => candidate === scope, signTerminal: () => value,
    validateTerminal: candidate => JSON.stringify(candidate) === JSON.stringify(value) };
  const producer = load('command-windows-receipts.js', { './command-windows-protocol': protocol });
  return { directory, scope, value, producer, cleanup: () => fs.rmSync(directory, { recursive: true, force: true }) };
}
test('Windows receipt I/O model: first publication creates and reads back the complete owned file', () => {
  const f = fixture();
  try {
    assert.deepEqual(f.producer.publishTerminal(f.scope, 'primary', {}, null), f.value);
    assert.deepEqual(JSON.parse(fs.readFileSync(path.join(f.directory, 'primary.closed.json'))), f.value);
    assert.deepEqual(fs.readdirSync(f.directory), ['primary.closed.json']);
    assert.equal(fs.lstatSync(path.join(f.directory, 'primary.closed.json')).nlink, 1);
  } finally { f.cleanup(); }
});
test('Windows receipt I/O model: an unknown existing final file is retained byte for byte', () => {
  const f = fixture(), file = path.join(f.directory, 'primary.closed.json'), sentinel = Buffer.from('unknown existing receipt\n');
  try {
    fs.writeFileSync(file, sentinel); assert.throws(() => f.producer.publishTerminal(f.scope, 'primary', {}, null));
    assert.equal(fs.readFileSync(file).equals(sentinel), true); assert.deepEqual(fs.readdirSync(f.directory), ['primary.closed.json']);
  } finally { f.cleanup(); }
});
test('Windows receipt I/O model: a failed flush publishes nothing and removes only its owned temporary', () => {
  const f = fixture(), original = fs.fsyncSync;
  fs.writeFileSync(path.join(f.directory, 'unrelated'), 'keep');
  try {
    fs.fsyncSync = () => { throw Object.assign(new Error('modeled flush failure'), { code: 'EIO' }); };
    assert.throws(() => f.producer.publishTerminal(f.scope, 'primary', {}, null), { code: 'EIO' });
    assert.deepEqual(fs.readdirSync(f.directory), ['unrelated']); assert.equal(fs.readFileSync(path.join(f.directory, 'unrelated'), 'utf8'), 'keep');
  } finally { fs.fsyncSync = original; f.cleanup(); }
});
test('Windows helper cleanup: the originally captured empty directory is removable after a pre-file failure', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge-command-native-')), st = fs.lstatSync(directory, { bigint: true });
  const helper = { backend: 'windows_job_object', platform: 'win32', architecture: process.arch,
    source_sha256: 'a'.repeat(64), binary_sha256: 'b'.repeat(64), binary_bytes: 1,
    executable: path.join(directory, 'command-windows-job.node'), snapshot: { directory, dev: String(st.dev), ino: String(st.ino) } };
  try {
    const result = load('command-windows-native.js').cleanupPreparedHelper(helper, { allowIncomplete: true });
    assert.equal(result.status, 'completed', JSON.stringify(result)); assert.equal(fs.existsSync(directory), false);
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
});
