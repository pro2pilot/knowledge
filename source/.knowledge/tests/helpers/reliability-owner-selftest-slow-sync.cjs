'use strict';
// Source-only fault scheduler: all reads, descriptors, publication and owner
// decisions remain real. Slow one prepared-owner fsync only when a public
// ownerless/noncanonical generation already exists, plus the timed physical
// transition case. Its fixture index is independently checked against the
// output's exact scenario name by the regression, so reordering cannot
// silently turn this scheduling condition into coverage of a different case.
// No clock is changed.
const fs = require('fs');
const path = require('path');
const { canonicalOwnerText } = require('../../tools/lib/lock-owner-schema');
const original = Object.fromEntries(['openSync', 'closeSync', 'fsyncSync', 'readFileSync', 'lstatSync'].map(name => [name, fs[name]]));
const descriptors = new Map();
const delayed = new Set();
fs.openSync = function(file, ...args) {
  const fd = original.openSync(file, ...args);
  if (typeof file === 'string') descriptors.set(fd, path.resolve(file));
  return fd;
};
fs.closeSync = function(fd, ...args) {
  try { return original.closeSync(fd, ...args); } finally { descriptors.delete(fd); }
};
fs.fsyncSync = function(fd, ...args) {
  const file = descriptors.get(fd);
  if (file && path.basename(file) === 'owner.json' && path.basename(path.dirname(file)).startsWith('publish-sync-') && !delayed.has(file)) {
    const publicPath = path.join(path.dirname(path.dirname(path.dirname(file))), 'sync.lock');
    const fixtureIndex = Number(path.basename(path.resolve(publicPath, '../../../..')));
    let reason = null;
    try {
      if (original.lstatSync(publicPath).isDirectory()) {
        let text;
        try { text = original.readFileSync(path.join(publicPath, 'owner.json'), 'utf8'); }
        catch (error) { if (error.code === 'ENOENT') reason = 'ownerless'; else throw error; }
        if (text !== undefined) {
          try { if (text !== canonicalOwnerText(JSON.parse(text))) reason = 'noncanonical'; }
          catch { reason = 'noncanonical'; }
        }
      }
    } catch (error) { if (error.code !== 'ENOENT') throw error; }
    if (!reason && fixtureIndex === 19 && fs.existsSync(publicPath)) reason = 'timed_physical_transition';
    if (reason) {
      delayed.add(file);
      const started = process.hrtime.bigint();
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 150);
      process.stderr.write(JSON.stringify({ event: 'real_prepared_owner_fsync_delayed', reason,
        fixture_index: fixtureIndex,
        elapsed_ms: Number(process.hrtime.bigint() - started) / 1e6, file }) + '\n');
    }
  }
  return original.fsyncSync(fd, ...args);
};
