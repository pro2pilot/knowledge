#!/usr/bin/env node
'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { loadEntitlements } = require('./lib/action-registry');
const { assertSafeContainedPath, writeFileAtomicContained, appendNdjsonContained } = require('./lib/json-store');

const knowledgeRoot = path.resolve(__dirname, '..');
const proRoot = path.join(knowledgeRoot, 'pro');
const licenseRoot = path.join(knowledgeRoot, 'extensions');

function safeFile(file) {
  assertSafeContainedPath(knowledgeRoot, file, { allowMissing: true });
  if (fs.existsSync(file)) {
    const stat = fs.lstatSync(file);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1) throw new Error(`Unsafe license state file: ${file}`);
  }
  return file;
}

function parseArgs(argv) {
  const args = { _: [] };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg.startsWith('--')) {
      const key = arg.slice(2).replace(/-([a-z])/g, (_, c) => c.toUpperCase());
      args[key] = argv[i + 1] && !argv[i + 1].startsWith('--') ? argv[++i] : true;
    } else args._.push(arg);
  }
  return args;
}

function writeJson(rel, value) {
  const file = safeFile(path.join(licenseRoot, rel));
  writeFileAtomicContained(file, JSON.stringify(value, null, 2) + '\n', knowledgeRoot);
}

function appendEvent(type, payload) {
  appendNdjsonContained(safeFile(path.join(proRoot, 'license-events.ndjson')), { type, at: new Date().toISOString(), ...payload }, knowledgeRoot);
}

function hash(value) {
  return crypto.createHash('sha256').update(String(value)).digest('hex');
}

function status() {
  const entitlements = loadEntitlements(knowledgeRoot);
  return {
    ok: true,
    mode: entitlements.active ? 'pro' : 'free',
    active: entitlements.active,
    source: entitlements.source,
    dev_mode: entitlements.dev_mode,
    offline: true,
    backend_configured: false,
    backend_url_present: Boolean(process.env.KNOWLEDGE_PRO_LICENSE_API_URL),
    offline_grace_days: 7,
    entitlements: entitlements.entitlements,
    ...(entitlements.reason ? { entitlement_state_reason: entitlements.reason } : {}),
    local_files: {
      license: '.knowledge/extensions/license.json',
      entitlements: '.knowledge/extensions/entitlements.json',
      events: '.knowledge/pro/license-events.ndjson'
    }
  };
}

function activate(args) {
  const explicitDev = args.dev === true || args.dev === 'true' || args.dev === '1';
  if (process.env.KNOWLEDGE_PRO_DEV_ENTITLEMENT !== '1' && !explicitDev) {
    appendEvent('license_activation_failed', { reason: 'license_api_not_configured' });
    return {
      ok: false,
      status: 'blocked',
      reason: 'license_api_not_configured',
      message: 'Free release does not activate public Pro licenses until the License API is configured.'
    };
  }
  const key = args.licenseKey || 'dev-local-license';
  const now = new Date();
  const expires = new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000);
  const entitlements = [
    'extension_base',
    'pro_base',
    'pr_impact_pro',
    'repair_ownership',
    'policy_gates',
    'team_dashboard',
    'memory_governance',
    'audit_history',
    'client_workspaces',
    'beta_channel',
    'internal_channel'
  ];
  for (const file of [path.join(licenseRoot, 'license.json'), path.join(licenseRoot, 'entitlements.json'), path.join(proRoot, 'license-events.ndjson')]) safeFile(file);
  writeJson('license.json', {
    schema_version: 'pro-license-cache.v1',
    status: 'active',
    plan: 'dev_pro',
    license_key_hash: hash(key),
    activation_id: `act_dev_${hash(key).slice(0, 12)}`,
    machine_fingerprint_hash: hash(`${process.platform}:${process.arch}`),
    issued_at: now.toISOString(),
    expires_at: expires.toISOString(),
    offline_grace_until: expires.toISOString(),
    signed_token: `dev-signed.${hash(key)}`
  });
  writeJson('entitlements.json', {
    schema_version: 'pro-entitlements.v1',
    source: args.dev ? 'explicit-dev-cli' : 'explicit-dev-flag',
    entitlements,
    client_workspaces: []
  });
  appendEvent('license_activation_succeeded', { source: args.dev ? 'explicit-dev-cli' : 'explicit-dev-flag' });
  return { ok: true, status: 'active', dev_mode: true, entitlements };
}

function refresh() {
  appendEvent('license_refresh_succeeded', { mode: 'offline-cache' });
  return { ...status(), refreshed: true, network_used: false };
}

function deactivateDevice() {
  const files = [licenseRoot, proRoot].flatMap((root) => ['license.json', 'entitlements.json'].map((name) => safeFile(path.join(root, name))));
  appendEvent('license_deactivated_device', { mode: 'local' });
  for (const file of files) fs.rmSync(safeFile(file), { force: true });
  return { ok: true, status: 'deactivated' };
}

function main(argv = process.argv.slice(2)) {
  const args = parseArgs(argv);
  const command = args._[0] || 'status';
  let output;
  try {
    if (command === 'status') output = status();
    else if (command === 'activate') output = activate(args);
    else if (command === 'refresh') output = refresh();
    else if (command === 'deactivate-device') output = deactivateDevice();
    else output = { ok: false, error: 'unknown_command', command };
  } catch (error) { output = { ok: false, error: 'license_io_rejected', message: error.message }; }
  if (args.json) console.log(JSON.stringify(output, null, 2));
  else console.log(output.ok ? `${command}: ok` : `${command}: ${output.reason || output.error}`);
  if (!output.ok) process.exitCode = 1;
}

if (require.main === module) main();

module.exports = { status, activate, refresh, deactivateDevice, main };
