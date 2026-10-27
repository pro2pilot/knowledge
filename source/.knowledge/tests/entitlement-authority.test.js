'use strict';

// The exported gate must accept entitlement arrays from the real loader and
// reject malformed direct caller data. All license state below is an explicit
// local development fixture; no license service or external bundle is used.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { fixture } = require('./helpers/currency-overlay');
const { canRunAction, loadEntitlements, getAction } = require('../tools/lib/action-registry');
const { runAction } = require('../tools/lib/action-runner');
const action = { risk: 'extension_locked', required_entitlement: 'extension_base' };
const deny = value => assert.deepEqual(canRunAction(action, value), { ok: false, reason: 'missing_entitlement', required_entitlement: 'extension_base' });

test('entitlement gate rejects strings and malformed collections without throwing', () => {
  for (const value of [undefined, null, true, 7, [], {}, { entitlements: null }, { entitlements: {} },
    { entitlements: 'extension_base' }, { entitlements: 'not_extension_base' },
    { entitlements: ['extension_base', null] }, { entitlements: [7] }]) deny(value);
});

test('entitlement gate uses exact string membership and preserves duplicate valid grants', () => {
  assert.deepEqual(canRunAction(action, { entitlements: ['extension_base'] }), { ok: true });
  assert.deepEqual(canRunAction(action, { entitlements: ['extension_base', 'extension_base'] }), { ok: true });
  deny({ entitlements: ['not_extension_base', 'extension_base_extra', ' extension_base'] });
  assert.deepEqual(canRunAction(getAction('doctor.run'), null), { ok: true });
  assert.deepEqual(canRunAction(null, { entitlements: ['extension_base'] }), { ok: false, reason: 'unknown_action' });
});

test('entitlement gate rejects getters, serialization hooks and proxy traps before execution', () => {
  let calls = 0;
  const getter = Object.defineProperty({}, 'entitlements', { enumerable: true, get() { calls++; return ['extension_base']; } });
  const serialization = { entitlements: ['extension_base'], toJSON() { calls++; return { entitlements: ['extension_base'] }; } };
  const includes = { entitlements: { includes() { calls++; return true; } } };
  const proxy = new Proxy({ entitlements: ['extension_base'] }, { get() { calls++; return ['extension_base']; }, ownKeys() { calls++; return ['entitlements']; } });
  const revoked = Proxy.revocable({}, {}); revoked.revoke();
  for (const value of [getter, serialization, includes, proxy, revoked.proxy]) deny(value);
  assert.equal(calls, 0);
});

test('actual local license activation, expiry and deactivation feed the same action gate', t => {
  const f = fixture(t, 'entitlement-lifecycle');
  const source = path.resolve(__dirname, '../tools/pro-license.js');
  f.write('.knowledge/tools/pro-license.js', fs.readFileSync(source, 'utf8'));
  const filename = path.join(f.state, 'tools/pro-license.js');
  const license = require(filename); t.after(() => { delete require.cache[filename]; });
  assert.equal(canRunAction(action, loadEntitlements(f.state, {})).ok, false);
  assert.equal(license.activate({ dev: true }).status, 'active');
  assert.equal(canRunAction(action, loadEntitlements(f.state, {})).ok, true);
  const statePath = path.join(f.state, 'extensions/license.json'), original = fs.readFileSync(statePath);
  const expired = JSON.parse(original); expired.expires_at = '2020-01-01T00:00:00.000Z'; expired.offline_grace_until = expired.expires_at;
  fs.writeFileSync(statePath, JSON.stringify(expired));
  const stale = loadEntitlements(f.state, {}); assert.equal(stale.reason, 'entitlement_expired'); assert.equal(canRunAction(action, stale).ok, false);
  fs.writeFileSync(statePath, original);
  assert.equal(license.deactivateDevice().status, 'deactivated');
  assert.equal(canRunAction(action, loadEntitlements(f.state, {})).ok, false);
});

test('normal action-runner consumers retain local free actions and unknown-action refusal', t => {
  const f = fixture(t, 'entitlement-runner');
  const free = runAction(f.context, 'recording.blockers'); assert.equal(free.status, 'passed');
  const unknown = runAction(f.context, 'synthetic-unknown-action'); assert.equal(unknown.status, 'blocked');
  assert(unknown.errors.some(item => item.reason === 'unknown_action'));
});
