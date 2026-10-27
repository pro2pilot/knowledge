'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const source = path.resolve(process.env.KNOWLEDGE_AUDIT_SOURCE_ROOT || path.join(__dirname, '..'));
const updater = require(path.join(source, 'tools/update-system-files'));
const limit = 64 * 1024 * 1024;
function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge-update-read-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const from = path.join(root, 'from'), to = path.join(root, 'to');
  fs.mkdirSync(from);fs.mkdirSync(to);
  const file = 'README.md';fs.writeFileSync(path.join(from, file), 'old source bytes\n');
  return { root, from, to, file, manifest: { system_paths: [file], system_exclude_paths: [],
    system_remove_paths: [], legacy_compatible_remove_paths: [], project_preserve_paths: [], curated_preserve_paths: [] } };
}
function plan(f) { return updater.planActions(f.from, { targetKnowledgeRoot: f.to, manifest: f.manifest }); }
test('public update planner rejects an oversized sparse source before producing actions', t => {
  const f = fixture(t), file = path.join(f.from, f.file), fd = fs.openSync(file, 'r+');
  fs.ftruncateSync(fd, limit + 1);fs.closeSync(fd);
  assert.throws(() => plan(f), error => error.code === 'stable_file_too_large');
  assert.deepEqual(fs.readdirSync(f.to), []);
});
test('public update planner bounds the existing destination as well as the source', t => {
  const f = fixture(t), file = path.join(f.to, f.file), fd = fs.openSync(file, 'wx');
  fs.ftruncateSync(fd, limit + 1);fs.closeSync(fd);
  assert.throws(() => plan(f), error => error.code === 'stable_file_too_large');
  assert.equal(fs.statSync(file).size, limit + 1);
});
test('same-size source rewrite with restored mtime cannot produce a stale update plan', t => {
  const f = fixture(t), file = path.join(f.from, f.file), epoch = 1700000000;
  fs.utimesSync(file, epoch, epoch);
  const expected = fs.statSync(file, { bigint: true }), originalRead = fs.readSync, originalFileRead = fs.readFileSync;
  let changed = false;
  function mutate(fd) {
    if (changed || typeof fd !== 'number') return;
    const current = fs.fstatSync(fd, { bigint: true });
    if (current.dev !== expected.dev || current.ino !== expected.ino) return;
    changed = true;fs.writeFileSync(file, 'new source bytes\n');fs.utimesSync(file, epoch, epoch);
  }
  fs.readSync = function (fd, ...args) { const result = originalRead.call(fs, fd, ...args);mutate(fd);return result; };
  fs.readFileSync = function (fd, ...args) { const result = originalFileRead.call(fs, fd, ...args);mutate(fd);return result; };
  try {
    assert.throws(() => plan(f), error => error.code === 'stable_file_changed');
    assert(changed, 'the actual opened source was rewritten');
  } finally { fs.readSync = originalRead;fs.readFileSync = originalFileRead; }
  assert.deepEqual(fs.readdirSync(f.to), []);
});
test('ordinary source files remain usable by the public update planner', t => {
  const f = fixture(t), rows = plan(f);
  assert.equal(rows.length, 1);assert.equal(rows[0].action, 'create');assert.equal(rows[0].path, f.file);
  assert.match(rows[0].source_sha256, /^[a-f0-9]{64}$/);assert.deepEqual(fs.readdirSync(f.to), []);
});
