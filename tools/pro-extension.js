#!/usr/bin/env node
'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { loadEntitlements } = require('./lib/action-registry');

const knowledgeRoot = path.resolve(__dirname, '..');
const proRoot = path.join(knowledgeRoot, 'pro');

function parseArgs(argv) {
  const args = { _: [] };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg.startsWith('--')) args[arg.slice(2)] = argv[i + 1] && !argv[i + 1].startsWith('--') ? argv[++i] : true;
    else args._.push(arg);
  }
  return args;
}

function readJson(file) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return null; }
}

function sha256File(file) {
  return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
}

function appendEvent(type, payload) {
  fs.mkdirSync(proRoot, { recursive: true });
  fs.appendFileSync(path.join(proRoot, 'license-events.ndjson'), JSON.stringify({ type, at: new Date().toISOString(), ...payload }) + '\n', 'utf8');
}

function status() {
  const current = readJson(path.join(proRoot, 'extensions', 'current.json'));
  return {
    ok: true,
    installed: Boolean(current),
    current,
    channels: ['stable', 'beta', 'internal'],
    manual_install_requires: ['valid_license', 'valid_signature', 'sha256_match', 'compatible_core_version']
  };
}

function companionManifest(bundlePath) {
  const candidates = [`${bundlePath}.manifest.json`, bundlePath.replace(/\.zip$/i, '.manifest.json')];
  return candidates.map((file) => ({ file, manifest: readJson(file) })).find((item) => item.manifest) || null;
}

function validateManifest(manifest, bundlePath, entitlementState) {
  const errors = [];
  if (!manifest) errors.push('missing_manifest');
  else {
    if (!['stable', 'beta', 'internal'].includes(manifest.channel)) errors.push('invalid_channel');
    if (!manifest.signature || !/^(ed25519|dev-signed):/.test(manifest.signature)) errors.push('missing_or_invalid_signature');
    if (!manifest.sha256 || manifest.sha256 !== sha256File(bundlePath)) errors.push('sha256_mismatch');
    for (const required of manifest.entitlements_required || []) {
      if (!entitlementState.entitlements.includes(required)) errors.push(`missing_entitlement:${required}`);
    }
    if (manifest.channel === 'beta' && !entitlementState.entitlements.includes('beta_channel')) errors.push('channel_not_allowed:beta');
    if (manifest.channel === 'internal' && !entitlementState.entitlements.includes('internal_channel')) errors.push('channel_not_allowed:internal');
  }
  return errors;
}

function installFile(bundlePath) {
  const abs = path.resolve(process.cwd(), bundlePath || '');
  const entitlementState = loadEntitlements(knowledgeRoot);
  if (!entitlementState.entitlements.includes('pro_base')) {
    appendEvent('pro_extension_install_failed', { reason: 'missing_entitlement' });
    return { ok: false, status: 'blocked', reason: 'missing_entitlement', required_entitlement: 'pro_base' };
  }
  if (!fs.existsSync(abs)) {
    appendEvent('pro_extension_install_failed', { reason: 'bundle_not_found' });
    return { ok: false, status: 'failed', reason: 'bundle_not_found' };
  }
  const companion = companionManifest(abs);
  const errors = validateManifest(companion?.manifest, abs, entitlementState);
  if (errors.length) {
    appendEvent('pro_extension_install_failed', { reason: errors[0], errors });
    return { ok: false, status: 'rejected', reason: errors[0], errors };
  }
  const manifest = companion.manifest;
  const installDir = path.join(proRoot, 'extensions', `${manifest.extension_id}-${manifest.version}`);
  fs.mkdirSync(installDir, { recursive: true });
  fs.copyFileSync(abs, path.join(installDir, path.basename(abs)));
  fs.writeFileSync(path.join(installDir, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n', 'utf8');
  fs.writeFileSync(path.join(proRoot, 'extensions', 'current.json'), JSON.stringify({
    extension_id: manifest.extension_id,
    version: manifest.version,
    channel: manifest.channel,
    installed_at: new Date().toISOString(),
    manifest: path.relative(knowledgeRoot, path.join(installDir, 'manifest.json')).replace(/\\/g, '/')
  }, null, 2) + '\n', 'utf8');
  appendEvent('pro_extension_installed', { extension_id: manifest.extension_id, version: manifest.version });
  return { ok: true, status: 'installed', extension_id: manifest.extension_id, version: manifest.version };
}

function main(argv = process.argv.slice(2)) {
  const args = parseArgs(argv);
  const command = args._[0] || 'status';
  let output;
  if (command === 'status') output = status();
  else if (command === 'install-file') output = installFile(args._[1]);
  else output = { ok: false, error: 'unknown_command', command };
  if (args.json) console.log(JSON.stringify(output, null, 2));
  else console.log(output.ok ? `${command}: ok` : `${command}: ${output.reason || output.error}`);
  if (!output.ok) process.exit(1);
}

if (require.main === module) main();

module.exports = { status, installFile, validateManifest, main };
