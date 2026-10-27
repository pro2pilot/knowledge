'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { publishPreparedLock, closeOwnerLease } = require('../tools/lib/lock-publication');
const options = { skip: process.platform !== 'linux' || process.getuid?.() === 0 };
function fixture(t) {
  const base = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge-search-ancestor-')));
  const ancestor = path.join(base, 'ancestor'), root = path.join(ancestor, 'state');
  const stage = 'publish-team-flow-01234567-89ab-4cde-8fed-0123456789ab.lock';
  const prepared = path.join(root, 'locks/v1/.release', stage);
  fs.mkdirSync(prepared, { recursive: true });
  fs.writeFileSync(path.join(prepared, 'owner.json'), '{"complete":true}\n', { flag: 'wx' });
  let lease;
  t.after(() => {
    if (lease) closeOwnerLease(lease);
    fs.chmodSync(ancestor, 0o700);
    fs.rmSync(base, { recursive: true });
  });
  return { base, ancestor, root, stage, keep: r => { lease = r.lease_id; return r; } };
}
test('Linux atomic publication needs search but no read permission on an ancestor', options, t => {
  const f = fixture(t); fs.chmodSync(f.ancestor, 0o100);
  assert.throws(() => fs.openSync(f.ancestor, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY), { code: 'EACCES' });
  const result = f.keep(publishPreparedLock(f.root, f.stage, 'team-flow.lock'));
  assert.equal(result.status, 'published', JSON.stringify(result));
  assert.equal(result.published, true); assert(result.lease_id > 0);
  assert.equal(fs.readFileSync(path.join(f.root, 'locks/v1/team-flow.lock/owner.json'), 'utf8'), '{"complete":true}\n');
  assert.equal(fs.existsSync(path.join(f.root, 'locks/v1/.release', f.stage)), false);
});
test('Linux search anchors still refuse an ancestor without search permission', options, t => {
  const f = fixture(t); fs.chmodSync(f.ancestor, 0o400);
  const result = f.keep(publishPreparedLock(f.root, f.stage, 'team-flow.lock'));
  assert.equal(result.status, 'failed'); assert.equal(result.published, false);
  fs.chmodSync(f.ancestor, 0o700);
  assert.equal(fs.existsSync(path.join(f.root, 'locks/v1/team-flow.lock')), false);
  assert(fs.existsSync(path.join(f.root, 'locks/v1/.release', f.stage, 'owner.json')));
});
test('Linux search anchors refuse a symbolic ancestor even when its target is valid', options, t => {
  const f = fixture(t), link = path.join(f.base, 'substituted');
  fs.symlinkSync(f.ancestor, link, 'dir');
  const result = f.keep(publishPreparedLock(path.join(link, 'state'), f.stage, 'team-flow.lock'));
  assert.equal(result.status, 'failed'); assert.equal(result.published, false);
  assert.equal(fs.existsSync(path.join(f.root, 'locks/v1/team-flow.lock')), false);
  assert(fs.existsSync(path.join(f.root, 'locks/v1/.release', f.stage, 'owner.json')));
});
