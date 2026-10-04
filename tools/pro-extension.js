#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const { loadEntitlements } = require('./lib/action-registry');
const { validateExtension } = require('./lib/extension-verification');
const { assertSafeContainedPath, writeFileAtomicContained, appendNdjsonContained } = require('./lib/json-store');

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
  try { return JSON.parse(fs.readFileSync(file, 'utf8').replace(/^\uFEFF/, '')); } catch { return null; }
}

function safeOutput(file) {
  assertSafeContainedPath(knowledgeRoot, file, { allowMissing: true });
  if (fs.existsSync(file)) {
    const stat = fs.lstatSync(file);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1) throw new Error(`Unsafe extension file: ${file}`);
  }
  return file;
}

function appendEvent(type, payload) {
  const file = safeOutput(path.join(proRoot, 'license-events.ndjson'));
  appendNdjsonContained(file, { type, at: new Date().toISOString(), ...payload }, knowledgeRoot);
}

function status() {
  const file = safeOutput(path.join(proRoot, 'extensions', 'current.json'));
  const current = readJson(file);
  if (fs.existsSync(file) && (!current || typeof current !== 'object' || Array.isArray(current) ||
      typeof current.extension_id !== 'string' || typeof current.version !== 'string' || typeof current.manifest !== 'string')) {
    return { ok: false, installed: false, status: 'invalid_install_state', reason: 'invalid_current_metadata' };
  }
  return {
    ok: true,
    installed: Boolean(current),
    current,
    channels: ['stable', 'beta', 'internal'],
    manual_install_requires: ['active_local_entitlement', 'trusted_ed25519_signature', 'sha256_match', 'compatible_core_version']
  };
}

function companionManifest(bundlePath) {
  const candidates = [`${bundlePath}.manifest.json`, bundlePath.replace(/\.zip$/i, '.manifest.json')];
  return candidates.map((file) => ({ file, manifest: readJson(file) })).find((item) => item.manifest) || null;
}

function validateManifest(manifest, bundlePath, entitlementState, bytes = fs.readFileSync(bundlePath)) {
  safeOutput(path.join(knowledgeRoot, 'extensions', 'trusted-keys.json'));
  return validateExtension(manifest, bytes, entitlementState,
    readJson(path.join(knowledgeRoot, 'package.json'))?.version,
    readJson(path.join(knowledgeRoot, 'extensions', 'trusted-keys.json'))?.keys || {});
}

function installFile(bundlePath) {
  try { return installFileChecked(bundlePath); }
  catch (error) {
    let eventRecorded = true;
    try { appendEvent('pro_extension_install_failed', { reason: 'extension_io_rejected', error: error.message }); }
    catch { eventRecorded = false; }
    return { ok: false, status: 'failed', reason: 'extension_io_rejected', error: error.message, event_recorded: eventRecorded };
  }
}

function installFileChecked(bundlePath) {
  if (typeof bundlePath !== 'string' || !bundlePath.trim() || !/\.zip$/i.test(bundlePath)) {
    return { ok: false, status: 'rejected', reason: 'invalid_bundle_path', message: 'Provide an existing regular .zip bundle file.' };
  }
  const abs = path.resolve(process.cwd(), bundlePath || '');
  const entitlementState = loadEntitlements(knowledgeRoot);
  if (!entitlementState.active || !entitlementState.entitlements.some((item) => ['extension_base', 'pro_base'].includes(item))) {
    appendEvent('pro_extension_install_failed', { reason: 'missing_entitlement' });
    return { ok: false, status: 'blocked', reason: 'missing_entitlement', required_entitlement: 'extension_base' };
  }
  if (!fs.existsSync(abs)) {
    appendEvent('pro_extension_install_failed', { reason: 'bundle_not_found' });
    return { ok: false, status: 'failed', reason: 'bundle_not_found' };
  }
  const stat = fs.lstatSync(abs, { bigint: true });
  if (!stat.isFile() || stat.isSymbolicLink()) return { ok: false, status: 'rejected', reason: 'bundle_not_regular_file' };
  const companion = companionManifest(abs);
  // Install the same bytes that were authenticated, even if the input changes.
  const descriptor = fs.openSync(abs, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0) | (fs.constants.O_NONBLOCK || 0));
  let bytes;
  try {
    const opened = fs.fstatSync(descriptor, { bigint: true });
    if (!opened.isFile() || opened.dev !== stat.dev || opened.ino !== stat.ino) throw new Error('Bundle changed while opening.');
    bytes = fs.readFileSync(descriptor);
    const after = fs.fstatSync(descriptor, { bigint: true });
    if (after.size !== opened.size || after.mtimeNs !== opened.mtimeNs) throw new Error('Bundle changed while reading.');
  } finally { fs.closeSync(descriptor); }
  const errors = validateManifest(companion?.manifest, abs, entitlementState, bytes);
  if (errors.length) {
    appendEvent('pro_extension_install_failed', { reason: errors[0], errors });
    return { ok: false, status: 'rejected', reason: errors[0], errors };
  }
  const manifest = companion.manifest;
  const installDir = path.join(proRoot, 'extensions', `${manifest.extension_id}-${manifest.version}`);
  const bundleTarget = safeOutput(path.join(installDir, path.basename(abs)));
  const manifestTarget = safeOutput(path.join(installDir, 'manifest.json'));
  const currentTarget = safeOutput(path.join(proRoot, 'extensions', 'current.json'));
  safeOutput(path.join(proRoot, 'license-events.ndjson'));
  writeFileAtomicContained(bundleTarget, bytes, knowledgeRoot);
  writeFileAtomicContained(manifestTarget, JSON.stringify(manifest, null, 2) + '\n', knowledgeRoot);
  writeFileAtomicContained(currentTarget, JSON.stringify({
    extension_id: manifest.extension_id,
    version: manifest.version,
    channel: manifest.channel,
    installed_at: new Date().toISOString(),
    manifest: path.relative(knowledgeRoot, path.join(installDir, 'manifest.json')).replace(/\\/g, '/')
  }, null, 2) + '\n', knowledgeRoot);
  appendEvent('pro_extension_installed', { extension_id: manifest.extension_id, version: manifest.version });
  return { ok: true, status: 'installed', extension_id: manifest.extension_id, version: manifest.version };
}

function main(argv = process.argv.slice(2)) {
  const args = parseArgs(argv);
  const command = args._[0] || 'status';
  let output;
  try {
    if (command === 'status') output = status();
    else if (command === 'install-file') output = installFile(args._[1]);
    else output = { ok: false, error: 'unknown_command', command };
  } catch (error) { output = { ok: false, error: 'extension_io_rejected', message: error.message }; }
  if (args.json) console.log(JSON.stringify(output, null, 2));
  else console.log(output.ok ? `${command}: ok` : `${command}: ${output.reason || output.error}`);
  if (!output.ok) process.exitCode = 1;
}

if (require.main === module) main();

module.exports = { status, installFile, validateManifest, main };
