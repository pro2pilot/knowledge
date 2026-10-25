'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const native = require('../tools/lib/verification-linux-namespace');
test('snapshot cleanup preserves a byte-identical replacement inode', { skip: process.platform !== 'linux' }, () => {
  const helper = native.preparePackagedHelper({ snapshot: true });
  const backup = fs.mkdtempSync(path.join(os.tmpdir(), 'snapshot-original-')), original = path.join(backup, 'original');
  fs.renameSync(helper.executable, original); fs.copyFileSync(original, helper.executable); fs.chmodSync(helper.executable, 0o500);
  try {
    const receipt = native.cleanupPreparedHelper(helper);
    assert.equal(receipt.status, 'unconfirmed'); assert.equal(receipt.code, 'command_native_snapshot_changed');
    assert.equal(fs.existsSync(helper.executable), true);
  } finally {
    fs.unlinkSync(helper.executable); fs.renameSync(original, helper.executable); fs.rmdirSync(backup);
    assert.equal(native.cleanupPreparedHelper(helper).status, 'completed');
  }
});
test('snapshot cleanup preserves a substituted private directory with identical file bytes', { skip: process.platform !== 'linux' }, () => {
  const helper = native.preparePackagedHelper({ snapshot: true }), directory = helper.snapshot.directory, saved = directory + '-original';
  fs.renameSync(directory, saved); fs.mkdirSync(directory, { mode: 0o700 });
  fs.copyFileSync(path.join(saved, path.basename(helper.executable)), helper.executable); fs.chmodSync(helper.executable, 0o500);
  try {
    const receipt = native.cleanupPreparedHelper(helper);
    assert.equal(receipt.status, 'unconfirmed'); assert.equal(receipt.code, 'command_native_snapshot_changed');
    assert.equal(fs.existsSync(helper.executable), true);
  } finally {
    fs.unlinkSync(helper.executable); fs.rmdirSync(directory); fs.renameSync(saved, directory);
    assert.equal(native.cleanupPreparedHelper(helper).status, 'completed');
  }
});
test('concurrent helper snapshots have distinct ownership and cleanup cannot remove its neighbor', { skip: process.platform !== 'linux' }, () => {
  const a = native.preparePackagedHelper({ snapshot: true }), b = native.preparePackagedHelper({ snapshot: true });
  try {
    assert.notEqual(a.snapshot.directory, b.snapshot.directory); assert.notEqual(a.snapshot.file_ino, b.snapshot.file_ino);
    assert.equal(native.cleanupPreparedHelper(a).status, 'completed');
    assert.equal(fs.existsSync(b.executable), true);
    assert.equal(fs.readFileSync(b.executable).length, b.binary_bytes);
  } finally {
    if (fs.existsSync(a.snapshot.directory)) assert.equal(native.cleanupPreparedHelper(a).status, 'completed');
    assert.equal(native.cleanupPreparedHelper(b).status, 'completed');
  }
});
