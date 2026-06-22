#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const { listActions, loadEntitlements, canRunAction, getAction } = require('./lib/action-registry');

const root = path.resolve(__dirname, '..');

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function exists(rel) {
  return fs.existsSync(path.join(root, rel));
}

function main() {
  const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
  const workspaceRoot = path.resolve(root, '..');
  assert(pkg.version === '3.2.0', 'free core version must remain 3.2.0');
  assert(!String(pkg.version).startsWith('4.'), 'must not bump to 4.0.0');
  for (const rel of [
    'docs/canonical/15_AGENT_IMPLEMENTATION_PROMPT.md',
    'maintenance/canonical-implementation-map.md',
    'maintenance/canonical-compliance-matrix.json',
    'maintenance/canonical-gap-report.md',
    'models/inspector-action.schema.json',
    'models/pro-license-token.schema.json',
    'models/pro-entitlement.schema.json',
    'models/pro-extension-manifest.schema.json'
  ]) assert(exists(rel), `missing ${rel}`);
  const actions = listActions();
  assert(actions.some((action) => action.id === 'pro.pr_impact_pro' && action.risk === 'pro_only'), 'missing pro-only preview action');
  const freeEntitlements = loadEntitlements(root, {});
  const gate = canRunAction(getAction('pro.pr_impact_pro'), freeEntitlements);
  assert(!gate.ok && gate.reason === 'missing_entitlement', 'free mode must block pro-only actions');
  const source = fs.readFileSync(path.join(root, 'tools', 'serve-inspector.js'), 'utf8');
  assert(source.includes('No prices are shown inside the free Inspector'), 'free Inspector must not show pricing');
  assert(!exists('pro2pilot-inspector'), 'free package must not embed pro2pilot-inspector');
  const checks = ['version 3.2.0', 'canonical docs loaded', 'pro schemas present', 'pro gate blocks free mode', 'no pricing in free inspector'];
  const proPackagePath = path.join(workspaceRoot, 'pro2pilot-inspector', 'package.json');
  if (fs.existsSync(proPackagePath)) {
    const proPkg = JSON.parse(fs.readFileSync(proPackagePath, 'utf8'));
    assert(proPkg.version === '0.1.0', 'Pro Inspector version must remain 0.1.0');
    checks.push('Pro Inspector 0.1.0 boundary');
  }
  const apiPackagePath = path.join(workspaceRoot, 'pro2pilot-license-api', 'package.json');
  if (fs.existsSync(apiPackagePath)) {
    const apiPkg = JSON.parse(fs.readFileSync(apiPackagePath, 'utf8'));
    assert(apiPkg.version === '0.1.0', 'License API preview version must be 0.1.0');
    checks.push('License API 0.1.0 skeleton');
  } else {
    checks.push('License API external to free artifact');
  }
  console.log(JSON.stringify({ schema_version: '3.2.0', status: 'pass', checks }, null, 2));
}

try { main(); } catch (error) { console.error(error.stack || error.message); process.exit(1); }
