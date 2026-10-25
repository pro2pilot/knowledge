'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { test } = require('node:test');
const { removeTempDirStrict, withTempFixture, captureTempDirIdentity } = require('../tools/lib/strict-temp-cleanup');

function ownBase(t) {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), 'fixture-ownership-test-'));
  const identity = captureTempDirIdentity(base);
  t.after(() => removeTempDirStrict(base, { expectedIdentity: identity }));
  return base;
}
function successor(directory, kind = 'directory') {
  const retired = directory + '-retired'; fs.renameSync(directory, retired);
  if (kind === 'directory') {
    fs.mkdirSync(directory); fs.writeFileSync(path.join(directory, 'sentinel.txt'), 'successor');
    return { retired, sentinel: path.join(directory, 'sentinel.txt') };
  }
  const target = directory + '-target'; fs.mkdirSync(target); fs.writeFileSync(path.join(target, 'sentinel.txt'), 'successor');
  fs.symlinkSync(target, directory, process.platform === 'win32' ? 'junction' : 'dir');
  return { retired, target, sentinel: path.join(target, 'sentinel.txt') };
}

test('normal callback changes contents and cleanup removes its own directory', t => {
  const base = ownBase(t); let directory;
  const value = withTempFixture({ baseDir: base, prefix: 'normal-' }, dir => {
    directory = dir; fs.mkdirSync(path.join(dir, 'nested')); fs.writeFileSync(path.join(dir, 'nested/evidence.txt'), 'owned'); return 42;
  });
  assert.equal(value, 42); assert.equal(fs.existsSync(directory), false);
});

test('genuine missing original root is an already-satisfied cleanup', t => {
  const base = ownBase(t); let directory;
  assert.equal(withTempFixture({ baseDir: base }, dir => {
    directory = dir; fs.rmSync(dir, { recursive: true }); return 'done';
  }), 'done');
  assert.equal(fs.existsSync(directory), false);
});

test('genuine EBUSY retry retains authority and then removes original fixture', t => {
  const base = ownBase(t); let attempts = 0, waits = 0, directory;
  const value = withTempFixture({ baseDir: base, cleanupOptions: {
    remove: dir => { attempts++; if (attempts === 1) throw Object.assign(new Error('Scoped temporary obstruction'), { code: 'EBUSY' }); fs.rmSync(dir, { recursive: true }); },
    sleep: () => { waits++; }
  } }, dir => { directory = dir; return 'ok'; });
  assert.equal(value, 'ok'); assert.equal(attempts, 2); assert.equal(waits, 1); assert.equal(fs.existsSync(directory), false);
});

test('callback success does not authorize deleting a successor at the same path', t => {
  const base = ownBase(t); let replaced, current;
  assert.throws(() => withTempFixture({ baseDir: base }, directory => {
    current = directory; replaced = successor(directory); return 'success';
  }), { code: 'TEMP_FIXTURE_IDENTITY_CHANGED' });
  assert(fs.existsSync(current)); assert(fs.existsSync(replaced.retired)); assert.equal(fs.readFileSync(replaced.sentinel, 'utf8'), 'successor');
});

test('primary callback error and successor cleanup refusal are both preserved', t => {
  const base = ownBase(t), primary = Object.assign(new Error('Primary fixture failure'), { code: 'TEST_PRIMARY' });
  let replaced;
  assert.throws(() => withTempFixture({ baseDir: base }, directory => {
    replaced = successor(directory); throw primary;
  }), error => error.code === 'TEMP_FIXTURE_CALLBACK_AND_CLEANUP_FAILED' && error.callback_error === primary &&
    error.cleanup_error.code === 'TEMP_FIXTURE_IDENTITY_CHANGED');
  assert.equal(fs.readFileSync(replaced.sentinel, 'utf8'), 'successor');
});

test('evidence preservation refuses to copy successor content', t => {
  const base = ownBase(t), evidence = path.join(base, 'preserved'); let replaced;
  assert.throws(() => withTempFixture({ baseDir: base, evidenceDir: evidence }, directory => {
    replaced = successor(directory); throw new Error('Primary fixture failure');
  }), error => error.code === 'TEMP_FIXTURE_CALLBACK_AND_CLEANUP_FAILED' &&
    error.preservation_error.code === 'TEMP_FIXTURE_IDENTITY_CHANGED' && error.cleanup_error.code === 'TEMP_FIXTURE_IDENTITY_CHANGED');
  assert.equal(fs.existsSync(evidence), false); assert.equal(fs.readFileSync(replaced.sentinel, 'utf8'), 'successor');
});

test('successor introduced during retry wait is preserved before the second remove', t => {
  const base = ownBase(t); let current, replaced, calls = 0;
  assert.throws(() => withTempFixture({ baseDir: base, cleanupOptions: {
    remove: () => { calls++; throw Object.assign(new Error('Scoped obstruction'), { code: 'EBUSY' }); },
    sleep: () => { replaced = successor(current); }
  } }, directory => { current = directory; }), error => error.code === 'TEMP_FIXTURE_IDENTITY_CHANGED' &&
    error.cleanup_attempts === 1 && error.cleanup_diagnostics[0].code === 'EBUSY');
  assert.equal(calls, 1); assert.equal(fs.readFileSync(replaced.sentinel, 'utf8'), 'successor');
});

test('standalone cleanup accepts an explicit prior identity and refuses replacement', t => {
  const base = ownBase(t), directory = path.join(base, 'standalone'); fs.mkdirSync(directory);
  const expectedIdentity = captureTempDirIdentity(directory), replaced = successor(directory);
  assert.throws(() => removeTempDirStrict(directory, { expectedIdentity }), { code: 'TEMP_FIXTURE_IDENTITY_CHANGED' });
  assert.equal(fs.readFileSync(replaced.sentinel, 'utf8'), 'successor');
});

test('invalid explicit identity cannot bypass the standalone guard', t => {
  const base = ownBase(t), directory = path.join(base, 'invalid-token'); fs.mkdirSync(directory);
  for (const expectedIdentity of [null, false, {}, [], { type: 'directory' }]) {
    assert.throws(() => removeTempDirStrict(directory, { expectedIdentity }), TypeError); assert(fs.existsSync(directory));
  }
});

test('a symbolic-link replacement is refused while its own target remains untouched', t => {
  const base = ownBase(t); let replaced, current;
  assert.throws(() => withTempFixture({ baseDir: base }, directory => {
    current = directory; replaced = successor(directory, 'symlink');
  }), { code: 'TEMP_FIXTURE_IDENTITY_CHANGED' });
  assert(fs.lstatSync(current).isSymbolicLink()); assert.equal(fs.readFileSync(replaced.sentinel, 'utf8'), 'successor');
});
