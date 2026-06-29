#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const { parseCliArgs, resolveKnowledgeContext, jsonContext } = require('./lib/path-context');
const { readJson, writeJsonAtomic, ensureDir, getAgentId } = require('./lib/json-store');
const { buildExternalMemoryReport } = require('./lib/memory-providers');

function nowIso() {
  return new Date().toISOString();
}

function safeRead(filePath, fallback) {
  try { return readJson(filePath, fallback); } catch { return fallback; }
}

function sanitizeString(value) {
  return String(value)
    .replace(/[A-Z]:\\(?:Users\\[^\s"',}\\]+|MyProject)[^\s"',}]+/gi, '<local-path>')
    .replace(/\/mnt\/data[^\s"',}]+/gi, '<local-path>')
    .replace(/\/tmp\/knowledge[^\s"',}]+/gi, '<local-path>')
    .replace(/Users\\[^\s"',}\\]+/gi, 'Users\\<local-user>')
    .replace(/Users\/[^\s"',}/]+/gi, 'Users/<local-user>')
    .replace(new RegExp(`knowledge${'-'}kit`, 'gi'), 'workspace');
}

function redact(value) {
  if (typeof value === 'string') {
    return sanitizeString(value)
      .replace(/(api[_-]?key|secret|token|password)(["'\s:=]+)[^"',\s}]+/ig, '$1$2<redacted>')
      .replace(/\b(pcsk|m0sk|sk|pk|eyJ)[A-Za-z0-9_./+=-]{12,}\b/g, '<redacted-secret>');
  }
  if (Array.isArray(value)) return value.map(redact);
  if (value && typeof value === 'object') {
    const out = {};
    for (const [key, item] of Object.entries(value)) {
      if (/^(content|text|memory_body|memory_content)$/i.test(key)) out[key] = '<redacted>';
      else if (/(api[_-]?key|secret|token|password)$/i.test(key) && typeof item === 'string' && item) out[key] = '<redacted>';
      else out[key] = redact(item);
    }
    return out;
  }
  return value;
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
    schema_version: '3.2.1',
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
    external_memory_status: redact({
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
    })
  };
  return redact(bundle);
}

function main(argv = process.argv.slice(2)) {
  const parsed = parseCliArgs(argv);
  const context = resolveKnowledgeContext(parsed.flags);
  const bundle = buildBundle(context);
  ensureDir(path.join(context.stateRoot, 'maintenance'));
  const outPath = path.join(context.stateRoot, 'maintenance', 'debug-bundle.json');
  writeJsonAtomic(outPath, bundle);
  const result = { ok: true, output: context.mode === 'repo' ? 'maintenance/debug-bundle.json' : outPath, bundle };
  if (parsed.flags.json) console.log(JSON.stringify(result, null, 2));
  else console.log(JSON.stringify(result, null, 2));
  return result;
}

if (require.main === module) {
  try { main(); }
  catch (error) { console.error(error.stack || error.message); process.exit(1); }
}

module.exports = main;
