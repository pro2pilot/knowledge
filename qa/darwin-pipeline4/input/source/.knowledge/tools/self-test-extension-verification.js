#!/usr/bin/env node
'use strict';
const assert = require('assert/strict');
const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const { spawnSync } = require('child_process');
const { signingPayload, validateExtension } = require('./lib/extension-verification');
const { loadEntitlements, canRunAction, getAction } = require('./lib/action-registry');
const systemRoot = path.resolve(__dirname, '..');
const version = require('../package.json').version;
const root = fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge-extension-verification-'));
const checks = [];
const check = (name, fn) => { fn(); checks.push(name); };
const write = (file, value) => { fs.mkdirSync(path.dirname(file), { recursive: true }); fs.writeFileSync(file, JSON.stringify(value)); };
try {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
  const keys = { publisher: publicKey.export({ type: 'spki', format: 'pem' }) };
  const bytes = Buffer.from('fixture extension bundle');
  const manifest = { extension_id: 'example', version: '1.0.0', channel: 'stable', key_id: 'publisher',
    core_versions: [version], entitlements_required: ['extension_base'],
    sha256: crypto.createHash('sha256').update(bytes).digest('hex') };
  const sign = (body) => ({ ...body, signature: 'ed25519:' + crypto.sign(null, signingPayload(body), privateKey).toString('base64') });
  const signed = sign(manifest);
  const state = loadEntitlements(root, { KNOWLEDGE_EXTENSION_DEV_ENTITLEMENT: '1' });
  const validate = (m, b = bytes, k = keys) => validateExtension(m, b, state, version, k);
  check('valid signature, pinned publisher, hash and core version', () => assert.deepEqual(validate(signed), []));
  check('unsigned manifest reaches signature validation', () => assert(validate(manifest).includes('missing_or_invalid_signature')));
  check('prefix-only ed25519 rejected', () => assert(validate({ ...manifest, signature: 'ed25519:fake' }).includes('missing_or_invalid_signature')));
  check('development signature never bypasses verification', () => assert(validate({ ...manifest, signature: 'dev-signed:fixture' }).includes('missing_or_invalid_signature')));
  check('untrusted signer rejected', () => assert(validate(signed, bytes, {}).includes('untrusted_signing_key')));
  check('metadata tampering rejected', () => assert(validate({ ...signed, version: '2.0.0' }).includes('signature_verification_failed')));
  check('bundle tampering rejected', () => assert(validate(signed, Buffer.from('changed')).includes('sha256_mismatch')));
  check('incompatible core rejected', () => assert(validate(sign({ ...manifest, core_versions: ['0.0.0'] })).includes('incompatible_core_version')));
  check('path traversal rejected even when signed', () => assert(validate(sign({ ...manifest, extension_id: '../escape' })).includes('invalid_extension_id')));
  check('beta entitlement required', () => assert(validate(sign({ ...manifest, channel: 'beta' })).includes('channel_not_allowed:beta')));
  check('malformed entitlements rejected', () => assert(validate(sign({ ...manifest, entitlements_required: 'all' })).includes('invalid_entitlements_required')));
  check('current free action remains accessible', () => assert(canRunAction(getAction('doctor.run'), loadEntitlements(root, {})).ok));
  check('removed action is explicitly unknown', () => assert.equal(canRunAction(getAction('policy.gates.run'), state).reason, 'unknown_action'));
  check('extension entitlement enforcement uses current API', () => {
    const action = { risk: 'extension_locked', required_entitlement: 'extension_base' };
    assert.equal(canRunAction(action, loadEntitlements(root, {})).reason, 'missing_entitlement');
    assert(canRunAction(action, state).ok);
    assert(!canRunAction(action, loadEntitlements(root, { KNOWLEDGE_PRO_DEV_ENTITLEMENT: '1' })).ok);
  });
  const fixture = path.join(root, '.knowledge');
  for (const relative of ['tools/pro-extension.js', 'tools/lib/action-registry.js', 'tools/lib/extension-verification.js',
    'tools/lib/json-store.js', 'tools/lib/strict-temp-cleanup.js', 'package.json']) {
    const target = path.join(fixture, relative);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.copyFileSync(path.join(systemRoot, relative), target);
  }
  const bundle = path.join(root, 'extension.zip');
  fs.writeFileSync(bundle, bytes);
  write(path.join(fixture, 'extensions/trusted-keys.json'), { keys });
  const run = (dev) => {
    const child = spawnSync(process.execPath, [path.join(fixture, 'tools/pro-extension.js'), 'install-file', bundle, '--json'], {
      cwd: root, encoding: 'utf8', windowsHide: true,
      env: { ...process.env, KNOWLEDGE_EXTENSION_DEV_ENTITLEMENT: dev ? '1' : '0', KNOWLEDGE_PRO_DEV_ENTITLEMENT: '0' }
    });
    return { exit: child.status, body: JSON.parse(child.stdout || '{}') };
  };
  check('CLI free user is blocked before verification', () => assert.equal(run(false).body.reason, 'missing_entitlement'));
  check('CLI authorized unsigned bundle is rejected at verification', () => {
    write(bundle + '.manifest.json', manifest);
    const result = run(true);
    assert.equal(result.body.status, 'rejected');
    assert(result.body.errors.includes('missing_or_invalid_signature'));
    assert(!fs.existsSync(path.join(fixture, 'pro/extensions/current.json')));
  });
  check('CLI authenticated bundle installs the exact verified bytes', () => {
    write(bundle + '.manifest.json', signed);
    const result = run(true);
    assert.equal(result.exit, 0);
    assert.equal(result.body.status, 'installed');
    assert.deepEqual(fs.readFileSync(path.join(fixture, 'pro/extensions/example-1.0.0/extension.zip')), bytes);
  });
  console.log(JSON.stringify({ status: 'pass', checks_total: checks.length, checks }, null, 2));
} finally { fs.rmSync(root, { recursive: true, force: true }); }
