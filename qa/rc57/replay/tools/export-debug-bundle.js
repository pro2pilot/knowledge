#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const { parseCliArgs, resolveKnowledgeContext, jsonContext } = require('./lib/path-context');
const { readJson, writeJsonAtomic, ensureDir, getAgentId } = require('./lib/json-store');
const { buildExternalMemoryReport } = require('./lib/memory-providers');
const { systemVersion } = require('./lib/system-version');
const { sanitizeExportValue } = require('./lib/export-sanitizer');

function nowIso() {
  return new Date().toISOString();
}

function safeRead(filePath, fallback) {
  try { return readJson(filePath, fallback); } catch { return fallback; }
}

function sanitizeContext(context) {
  const base = jsonContext(context);
  return {
    ...base,
    targetRoot: '<targetRoot>',
    projectKnowledgeRoot: '<projectKnowledgeRoot>',
    stateRoot: context.mode === 'repo' ? '<projectKnowledgeRoot>' : '<stateRoot>',
    teamRoot: context.teamRoot ? '<teamRoot>' : null
  };
}

function buildBundle(context) {
  const external = buildExternalMemoryReport(context, { write: true });
  const maintenance = path.join(context.stateRoot, 'maintenance');
  const bundle = {
    schema_version: systemVersion(),
    kind: 'debug-bundle',
    generated_at: nowIso(),
    generated_by: getAgentId(),
    context: sanitizeContext(context),
    includes: {
      provider_status: true,
      memory_content: false,
      api_keys: false,
      runtime_databases: false,
      install_receipts: false
    },
    quality_report: safeRead(path.join(maintenance, 'quality_report.json'), {}),
    routing_bundle: safeRead(path.join(maintenance, 'routing_bundle.json'), {}),
    trust_report: safeRead(path.join(maintenance, 'trust_report.json'), {}),
    external_memory_status: {
      ...external,
      providers: (external.providers || []).map((provider) => ({
        provider_id: provider.provider_id,
        status: provider.status,
        runtime_health: provider.runtime_health,
        mode: provider.mode,
        license_spdx: provider.license_spdx,
        version: provider.version || provider.version_pin || null,
        source_of_truth: false,
        trust_effect: 'advisory_only',
        records_count: provider.records_count || 0,
        warnings: provider.warnings || [],
        errors: provider.errors || []
      }))
    }
  };
  return sanitizeExportValue(bundle, {
    redactContentFields: true,
    redactWorkspaceName: true
  });
}

function main(argv = process.argv.slice(2)) {
  const parsed = parseCliArgs(argv);
  const context = resolveKnowledgeContext(parsed.flags);
  const bundle = buildBundle(context);
  ensureDir(path.join(context.stateRoot, 'maintenance'));
  const outPath = path.join(context.stateRoot, 'maintenance', 'debug-bundle.json');
  writeJsonAtomic(outPath, bundle);
  const result = sanitizeExportValue({
    ok: true,
    output: context.mode === 'repo'
      ? 'maintenance/debug-bundle.json'
      : '<stateRoot>/maintenance/debug-bundle.json',
    bundle
  }, {
    redactContentFields: true,
    redactWorkspaceName: true
  });
  if (parsed.flags.json) console.log(JSON.stringify(result, null, 2));
  else console.log(JSON.stringify(result, null, 2));
  return result;
}

if (require.main === module) {
  try { main(); }
  catch (error) { console.error(error.stack || error.message); process.exit(1); }
}

module.exports = main;
