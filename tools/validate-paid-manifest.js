#!/usr/bin/env node
'use strict';

const path = require('path');
const { readJson } = require('./lib/json-store');
const { parseCliArgs, resolveKnowledgeContext, jsonContext } = require('./lib/path-context');
const { normalizePaidManifest, validateNoPricingOrPlanBindings } = require('./lib/paid-inspector-model');

function main(argv = process.argv.slice(2)) {
  const args = parseCliArgs(argv);
  const context = resolveKnowledgeContext(args.flags);
  const manifestPath = path.join(context.projectKnowledgeRoot, 'docs', 'product', 'paid-feature-manifest.json');
  const manifest = normalizePaidManifest(readJson(manifestPath, {}));
  const issues = validateNoPricingOrPlanBindings(manifest);
  const out = {
    schema_version: '3.2.1',
    status: issues.length ? 'failed' : 'pass',
    context: jsonContext(context),
    manifest: context.mode === 'repo' ? 'docs/product/paid-feature-manifest.json' : manifestPath,
    capabilities: manifest.capabilities.length,
    conversion_signals: manifest.conversion_signals.length,
    billing_dimensions: manifest.billing_dimensions.length,
    prices_in_free_core: manifest.pricing_policy.prices_in_free_core,
    feature_plan_bindings_in_free_core: manifest.pricing_policy.feature_plan_bindings_in_free_core,
    issues
  };
  console.log(JSON.stringify(out, null, 2));
  if (issues.length) process.exit(2);
  return out;
}

if (require.main === module) {
  try { main(); }
  catch (error) { console.error(error.stack || error.message); process.exit(1); }
}

module.exports = { main };
