#!/usr/bin/env node
'use strict';
const assert = require('assert/strict');
const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const { spawnSync } = require('child_process');
const { signingPayload, validateExtension } = require('./lib/extension-verification');
const { loadEntitlements } = require('./lib/action-registry');
const systemRoot = path.resolve(__dirname, '..');
const root = fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge-extension-state-'));
const checks = [];
const check = (name, fn) => { fn(); checks.push(name); };
const write = (file, value) => { fs.mkdirSync(path.dirname(file), { recursive: true }); fs.writeFileSync(file, typeof value === 'string' || Buffer.isBuffer(value) ? value : JSON.stringify(value)); };
const fixture = path.join(root, 'project with spaces', '.knowledge');
const env = { ...process.env, KNOWLEDGE_EXTENSION_DEV_ENTITLEMENT: '0', KNOWLEDGE_PRO_DEV_ENTITLEMENT: '0' };
const run = (script, args = [], extra = {}) => {
  const child = spawnSync(process.execPath, [path.join(fixture, 'tools', script), ...args, '--json'], { cwd: root, env: { ...env, ...extra }, encoding: 'utf8', timeout: 15000 });
  assert(!child.error, child.error?.message);
  return { exit: child.status, body: JSON.parse(child.stdout || '{}') };
};
try {
  for (const relative of ['tools/pro-extension.js', 'tools/pro-license.js', 'tools/lib/action-registry.js', 'tools/lib/extension-verification.js', 'tools/lib/json-store.js', 'tools/lib/strict-temp-cleanup.js', 'package.json']) {
    const target = path.join(fixture, relative);
    fs.mkdirSync(path.dirname(target), { recursive: true }); fs.copyFileSync(path.join(systemRoot, relative), target);
  }
  const grant = path.join(fixture, 'extensions/entitlements.json');
  check('JSON null entitlement is inactive and does not crash', () => { write(grant, 'null'); assert.equal(loadEntitlements(fixture, {}).active, false); });
  check('array entitlement metadata is rejected', () => { write(grant, '[]'); assert.equal(loadEntitlements(fixture, {}).reason, 'invalid_entitlement_metadata'); });
  check('expired grants provide no usable entitlements', () => { write(grant, { active: true, entitlements: ['extension_base'], expires_at: '2000-01-01T00:00:00Z' }); const state = loadEntitlements(fixture, {}); assert.equal(state.active, false); assert.deepEqual(state.entitlements, []); });
  check('invalid declared expiry fails closed', () => { write(grant, { active: true, entitlements: ['extension_base'], expires_at: 'not-a-date' }); assert.equal(loadEntitlements(fixture, {}).active, false); });
  check('explicit inactivity overrides a named plan', () => { write(grant, { active: false, plan: 'paid', entitlements: ['extension_base'] }); assert.equal(loadEntitlements(fixture, {}).active, false); });
  check('valid local grace deadline permits offline use', () => { write(grant, { active: true, entitlements: ['extension_base'], expires_at: '2000-01-01T00:00:00Z', offline_grace_until: '2999-01-01T00:00:00Z' }); assert.equal(loadEntitlements(fixture, {}).active, true); });
  fs.rmSync(path.dirname(grant), { recursive: true });
  check('production license activation remains blocked offline', () => { const result = run('pro-license.js', ['activate']); assert.equal(result.exit, 1); assert.equal(result.body.reason, 'license_api_not_configured'); });
  check('explicit false development option cannot activate', () => assert.equal(run('pro-license.js', ['activate', '--dev', 'false']).exit, 1));
  check('explicit development activation persists a usable canonical grant', () => { const activated = run('pro-license.js', ['activate', '--dev']); assert.equal(activated.exit, 0); const state = run('pro-license.js', ['status']).body; assert.equal(state.active, true); assert(state.entitlements.includes('extension_base')); assert(fs.existsSync(grant)); });
  check('offline refresh does not claim network use', () => assert.equal(run('pro-license.js', ['refresh']).body.network_used, false));
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
  const keys = { publisher: publicKey.export({ type: 'spki', format: 'pem' }) };
  const bytes = Buffer.from('authenticated fixture bundle');
  const bundle = path.join(root, 'bundle with spaces.zip');
  const manifest = { extension_id: 'safety', version: '1.0.0', channel: 'stable', key_id: 'publisher', core_versions: [require('../package.json').version], entitlements_required: ['extension_base'], sha256: crypto.createHash('sha256').update(bytes).digest('hex') };
  const sign = (body) => ({ ...body, signature: 'ed25519:' + crypto.sign(null, signingPayload(body), privateKey).toString('base64') });
  write(bundle, bytes); write(bundle + '.manifest.json', sign(manifest)); write(path.join(fixture, 'extensions/trusted-keys.json'), { keys });
  check('missing install-file argument returns structured rejection', () => assert.equal(run('pro-extension.js', ['install-file']).body.reason, 'invalid_bundle_path'));
  check('directory named zip is rejected without a read crash', () => { const dir = path.join(root, 'directory.zip'); fs.mkdirSync(dir); assert.equal(run('pro-extension.js', ['install-file', dir]).body.reason, 'bundle_not_regular_file'); });
  check('extension id arrays do not bypass schema checks', () => assert(validateExtension(sign({ ...manifest, extension_id: ['safety'] }), bytes, { entitlements: ['extension_base'] }, manifest.core_versions[0], keys).includes('invalid_extension_id')));
  check('null trusted-key metadata cannot bypass authentication', () => assert(validateExtension(sign(manifest), bytes, null, manifest.core_versions[0], null).includes('untrusted_signing_key')));
  const outside = path.join(root, 'outside'); fs.mkdirSync(outside);
  const installRoot = path.join(fixture, 'pro/extensions');
  fs.mkdirSync(path.dirname(installRoot), { recursive: true });
  if (process.platform !== 'win32') {
    check('installation parent symlink cannot escape the knowledge root', () => { fs.symlinkSync(outside, installRoot, 'dir'); const result = run('pro-extension.js', ['install-file', bundle]); assert.equal(result.exit, 1); assert.deepEqual(fs.readdirSync(outside), []); fs.unlinkSync(installRoot); });
    check('hardlinked installed bundle is rejected before any overwrite', () => {
      const target = path.join(installRoot, 'safety-1.0.0', path.basename(bundle)); const sentinel = path.join(outside, 'sentinel'); write(sentinel, 'untouched'); fs.mkdirSync(path.dirname(target), { recursive: true }); fs.linkSync(sentinel, target);
      assert.equal(run('pro-extension.js', ['install-file', bundle]).exit, 1); assert.equal(fs.readFileSync(sentinel, 'utf8'), 'untouched'); fs.unlinkSync(target);
    });
  }
  check('signed CLI bundle with spaces installs the exact authenticated bytes', () => { assert.equal(run('pro-extension.js', ['install-file', bundle]).exit, 0); assert.deepEqual(fs.readFileSync(path.join(installRoot, 'safety-1.0.0', path.basename(bundle))), bytes); });
  check('bundle replacement during signature verification cannot change installed bytes', () => {
    const program = `const fs = require('fs'); const crypto = require('crypto'); const original = crypto.verify; crypto.verify = (...args) => { fs.writeFileSync(${JSON.stringify(bundle)}, 'replaced during verification'); return original(...args); }; console.log(JSON.stringify(require(${JSON.stringify(path.join(fixture, 'tools/pro-extension.js'))}).installFile(${JSON.stringify(bundle)})));`;
    const child = spawnSync(process.execPath, ['-e', program], { cwd: root, env, encoding: 'utf8' }); assert.equal(child.status, 0, child.stderr); assert.equal(JSON.parse(child.stdout).ok, true); assert.deepEqual(fs.readFileSync(path.join(installRoot, 'safety-1.0.0', path.basename(bundle))), bytes);
  });
  check('extension status reports an installed current record', () => assert.equal(run('pro-extension.js', ['status']).body.current.extension_id, 'safety'));
  check('corrupt current extension metadata cannot claim installed status', () => { write(path.join(installRoot, 'current.json'), '{}'); const result = run('pro-extension.js', ['status']); assert.equal(result.exit, 1); assert.equal(result.body.installed, false); });
  check('deactivation removes canonical and legacy grant state', () => { write(path.join(fixture, 'pro/entitlements.json'), { active: true, entitlements: ['pro_base'] }); assert.equal(run('pro-license.js', ['deactivate-device']).exit, 0); assert.equal(run('pro-license.js', ['status']).body.active, false); });
  check('legacy-only pro_base grant accepts a current extension_base manifest', () => { write(path.join(fixture, 'pro/entitlements.json'), { active: true, entitlements: ['pro_base'] }); write(bundle, bytes); const result = run('pro-extension.js', ['install-file', bundle]); assert.equal(result.exit, 0, JSON.stringify(result.body)); });
  check('unknown extension and license commands are nonzero', () => { assert.equal(run('pro-extension.js', ['unknown']).exit, 1); assert.equal(run('pro-license.js', ['unknown']).exit, 1); });
  console.log(JSON.stringify({ status: 'pass', checks_total: checks.length, checks, platform: process.platform }, null, 2));
} finally { fs.rmSync(root, { recursive: true, force: true }); }
