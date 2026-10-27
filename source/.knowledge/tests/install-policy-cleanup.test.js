'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { test } = require('node:test');
const { finalizeInstallPolicyFixture } = require('../tools/self-test-install-policy');
const { captureTempDirIdentity, removeTempDirStrict } = require('../tools/lib/strict-temp-cleanup');

function ownFixture(t) {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), 'install-policy-cleanup-'));
  const baseIdentity = captureTempDirIdentity(base);
  t.after(() => removeTempDirStrict(base, { expectedIdentity: baseIdentity }));
  const directory = path.join(base, 'owned-root');
  fs.mkdirSync(directory);
  fs.writeFileSync(path.join(directory, 'evidence.txt'), 'original evidence');
  return { directory, identity: captureTempDirIdentity(directory) };
}

test('successful final cleanup verifies physical removal and preserves test results', t => {
  const { directory, identity } = ownFixture(t);
  const primary = { name: 'installation checks', status: 'pass', details: { count: 27 } };
  const results = [primary];
  const output = finalizeInstallPolicyFixture(directory, identity, results);
  assert.equal(output.temp_root, null);
  assert.equal(output.temp_root_cleaned, true);
  assert.equal(output.cleanup.status, 'removed');
  assert.equal(fs.existsSync(directory), false);
  assert.deepEqual(results, [primary]);
});

test('a transient ENOTEMPTY is retried within the existing cleanup budget', t => {
  const { directory, identity } = ownFixture(t);
  const results = [{ name: 'installation checks', status: 'pass' }];
  let calls = 0;
  const output = finalizeInstallPolicyFixture(directory, identity, results, { cleanupOptions: {
    remove: target => {
      calls++;
      if (calls === 1) throw Object.assign(new Error('Transient fixture obstruction'), { code: 'ENOTEMPTY' });
      fs.rmSync(target, { recursive: true, force: true });
    },
    sleep: () => {}
  } });
  assert.equal(calls, 2);
  assert.equal(output.cleanup.status, 'removed');
  assert.equal(output.cleanup.diagnostics[0].code, 'ENOTEMPTY');
  assert.equal(results.length, 1);
  assert.equal(fs.existsSync(directory), false);
});

test('persistent cleanup failure retains the original failure and diagnostic fixture path', t => {
  const { directory, identity } = ownFixture(t);
  const primary = { name: 'updater', status: 'fail', message: 'Original semantic failure', details: { exit: 7, stderr: 'retained' } };
  const results = [primary];
  let calls = 0;
  const output = finalizeInstallPolicyFixture(directory, identity, results, { cleanupOptions: {
    attempts: 3,
    remove: () => { calls++; throw Object.assign(new Error('Persistent fixture obstruction'), { code: 'ENOTEMPTY' }); },
    sleep: () => {}
  } });
  assert.equal(calls, 3);
  assert.equal(results[0], primary);
  assert.deepEqual(results[0].details, { exit: 7, stderr: 'retained' });
  assert.equal(results.length, 2);
  assert.equal(results[1].status, 'fail');
  assert.equal(results[1].details.code, 'TEMP_FIXTURE_CLEANUP_FAILED');
  assert.equal(results[1].details.last_error_code, 'ENOTEMPTY');
  assert.equal(output.cleanup.status, 'unconfirmed');
  assert.equal(output.temp_root, directory);
  assert.equal(output.temp_root_cleaned, false);
  assert.equal(fs.readFileSync(path.join(directory, 'evidence.txt'), 'utf8'), 'original evidence');
  assert.doesNotThrow(() => JSON.stringify({ ...output, results }));
});

test('cleanup failure alone cannot turn a passing suite into a clean PASS', t => {
  const { directory, identity } = ownFixture(t);
  const results = [{ name: 'installation checks', status: 'pass' }];
  const output = finalizeInstallPolicyFixture(directory, identity, results, { cleanupOptions: {
    attempts: 1,
    remove: () => { throw Object.assign(new Error('Permission still denied'), { code: 'EACCES' }); }
  } });
  assert.equal(output.cleanup.status, 'unconfirmed');
  assert.equal(results.filter(result => result.status !== 'pass').length, 1);
  assert.equal(results[1].details.last_error_code, 'EACCES');
  assert.equal(fs.existsSync(directory), true);
});

test('same-name physical replacement is retained and recorded as cleanup failure', t => {
  const { directory, identity } = ownFixture(t);
  fs.renameSync(directory, directory + '-retired');
  fs.mkdirSync(directory);
  fs.writeFileSync(path.join(directory, 'successor.txt'), 'successor');
  const results = [{ name: 'installation checks', status: 'pass' }];
  let calls = 0;
  const output = finalizeInstallPolicyFixture(directory, identity, results, { cleanupOptions: {
    remove: () => { calls++; throw new Error('Must not reach a successor'); }
  } });
  assert.equal(calls, 0);
  assert.equal(output.cleanup.code, 'TEMP_FIXTURE_IDENTITY_CHANGED');
  assert.equal(output.cleanup.status, 'unconfirmed');
  assert.equal(results[1].status, 'fail');
  assert.equal(fs.readFileSync(path.join(directory, 'successor.txt'), 'utf8'), 'successor');
  assert.equal(fs.readFileSync(path.join(directory + '-retired', 'evidence.txt'), 'utf8'), 'original evidence');
});

test('explicit --keep retains the owned fixture without inventing a cleanup confirmation', t => {
  const { directory, identity } = ownFixture(t);
  const results = [{ name: 'installation checks', status: 'pass' }];
  const output = finalizeInstallPolicyFixture(directory, identity, results, { keep: true, cleanupOptions: {
    remove: () => { throw new Error('Explicit --keep must not remove the fixture'); }
  } });
  assert.equal(output.cleanup.status, 'kept');
  assert.equal(output.temp_root_cleaned, false);
  assert.equal(output.temp_root, directory);
  assert.equal(results.length, 1);
  assert.equal(fs.readFileSync(path.join(directory, 'evidence.txt'), 'utf8'), 'original evidence');
});
