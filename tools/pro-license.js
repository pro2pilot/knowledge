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
    if (arg.startsWith('--')) {
      const key = arg.slice(2).replace(/-([a-z])/g, (_, c) => c.toUpperCase());
      args[key] = argv[i + 1] && !argv[i + 1].startsWith('--') ? argv[++i] : true;
    } else args._.push(arg);
  }
  return args;
}

function writeJson(rel, value) {
  const file = path.join(proRoot, rel);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, JSON.stringify(value, null, 2) + '\n', 'utf8');
}

function appendEvent(type, payload) {
  fs.mkdirSync(proRoot, { recursive: true });
  fs.appendFileSync(path.join(proRoot, 'license-events.ndjson'), JSON.stringify({ type, at: new Date().toISOString(), ...payload }) + '\n', 'utf8');
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
    backend_configured: Boolean(process.env.KNOWLEDGE_PRO_LICENSE_API_URL),
    offline_grace_days: 7,
    entitlements: entitlements.entitlements,
    local_files: {
      license: '.knowledge/pro/license.json',
      entitlements: '.knowledge/pro/entitlements.json',
      events: '.knowledge/pro/license-events.ndjson'
    }
  };
}

function activate(args) {
  if (process.env.KNOWLEDGE_PRO_DEV_ENTITLEMENT !== '1' && !args.dev) {
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
  appendEvent('license_deactivated_device', { mode: 'local' });
  try { fs.rmSync(path.join(proRoot, 'license.json'), { force: true }); } catch {}
  try { fs.rmSync(path.join(proRoot, 'entitlements.json'), { force: true }); } catch {}
  return { ok: true, status: 'deactivated' };
}

function main(argv = process.argv.slice(2)) {
  const args = parseArgs(argv);
  const command = args._[0] || 'status';
  let output;
  if (command === 'status') output = status();
  else if (command === 'activate') output = activate(args);
  else if (command === 'refresh') output = refresh();
  else if (command === 'deactivate-device') output = deactivateDevice();
  else output = { ok: false, error: 'unknown_command', command };
  if (args.json) console.log(JSON.stringify(output, null, 2));
  else console.log(output.ok ? `${command}: ok` : `${command}: ${output.reason || output.error}`);
  if (!output.ok) process.exit(1);
}

if (require.main === module) main();

module.exports = { status, activate, refresh, deactivateDevice, main };
