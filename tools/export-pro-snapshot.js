#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const { resolveKnowledgeContext, jsonContext, parseCliArgs } = require('./lib/path-context');
const { readJson, writeJsonAtomic, ensureDir, getAgentId } = require('./lib/json-store');
const { buildExternalMemoryReport } = require('./lib/memory-providers');

function nowIso() {
  return new Date().toISOString();
}

function relPath(root, filePath) {
  const rel = path.relative(root, filePath).replace(/\\/g, '/');
  return rel && !rel.startsWith('..') && !path.isAbsolute(rel) ? rel : path.basename(filePath);
}

function sanitizeContext(context) {
  const json = jsonContext(context);
  return {
    ...json,
    systemRoot: '<systemRoot>',
    targetRoot: '<targetRoot>',
    projectKnowledgeRoot: '<projectKnowledgeRoot>',
    stateRoot: context.mode === 'repo' ? '<projectKnowledgeRoot>' : '<stateRoot>',
    teamRoot: context.teamRoot ? '<teamRoot>' : null
  };
}

function readStateJson(context, rel, fallback) {
  const statePath = path.join(context.stateRoot, rel);
  const projectPath = path.join(context.projectKnowledgeRoot, rel);
  if (fs.existsSync(statePath)) return readJson(statePath, fallback);
  if (fs.existsSync(projectPath)) return readJson(projectPath, fallback);
  return fallback;
}

function buildSnapshot(context) {
  const external = buildExternalMemoryReport(context, { write: true });
  const trust = readStateJson(context, 'maintenance/trust_report.json', {});
  const quality = readStateJson(context, 'maintenance/quality_report.json', {});
  const routing = readStateJson(context, 'maintenance/routing_bundle.json', {});
  const repair = readStateJson(context, 'maintenance/repair_queue.json', { queue: [] });
  const stale = readStateJson(context, 'maintenance/stale_items.json', { items: [] });
  const critical = readStateJson(context, 'maps/file_criticality.json', { files: [] });
  const snapshot = {
    schema_version: '3.3.0',
    kind: 'pro-inspector-snapshot',
    generated_at: nowIso(),
    generated_by: getAgentId(),
    context: sanitizeContext(context),
    source_of_truth_order: routing.source_of_truth_order || [
      'current_code',
      'current_tests',
      '.knowledge/evidence/*.json',
      '.knowledge/modules/*.json',
      '.knowledge/decisions.json',
      '.knowledge/wiki/*.md',
      'external_memory'
    ],
    quality: {
      status: quality.status || 'unknown',
      score: quality.quality_score ?? null,
      issues_total: (quality.issues || []).length
    },
    trust: {
      buckets: trust.modules || {},
      suspect_or_low: [
        ...((trust.modules || {}).suspect || []),
        ...((trust.modules || {}).low_confidence || [])
      ]
    },
    routing: {
      modules: (routing.modules || []).map((module) => ({
        module_id: module.module_id,
        path: module.path,
        trust_status: module.trust_status,
        freshness_status: module.freshness_status
      })),
      high_risk_modules: routing.high_risk_modules || []
    },
    repair_board: {
      items: repair.queue || repair.items || []
    },
    stale_items: stale.items || stale.stale_items || [],
    critical_files: (critical.files || []).filter((file) => ['critical', 'important'].includes(file.classification)),
    memory_governance: {
      source_of_truth_policy: external.source_of_truth_policy,
      recommended_provider: external.recommended_provider,
      providers: (external.providers || []).map((provider) => ({
        provider_id: provider.provider_id,
        status: provider.status,
        runtime_health: provider.runtime_health,
        layer: provider.layer,
        license_spdx: provider.license_spdx,
        version: provider.version || provider.version_pin || null,
        enabled: Boolean(provider.enabled),
        source_of_truth: false,
        trust_effect: 'advisory_only',
        records_count: provider.records_count || 0,
        warnings: provider.warnings || [],
        errors: provider.errors || []
      })),
      legacy_providers_detected: (external.legacy_providers_detected || []).map((provider) => ({
        provider_id: provider.provider_id,
        status: provider.status,
        source_of_truth: false,
        trust_effect: 'advisory_only',
        warnings: provider.warnings || []
      }))
    },
    provenance: {
      generated_from: relPath(context.projectKnowledgeRoot, context.projectKnowledgeRoot),
      secrets_included: false,
      memory_content_included: false
    }
  };
  return snapshot;
}

function main(argv = process.argv.slice(2)) {
  const parsed = parseCliArgs(argv);
  const context = resolveKnowledgeContext(parsed.flags);
  const snapshot = buildSnapshot(context);
  ensureDir(path.join(context.stateRoot, 'maintenance'));
  const outPath = path.join(context.stateRoot, 'maintenance', 'pro-inspector-snapshot.json');
  writeJsonAtomic(outPath, snapshot);
  const result = { ok: true, output: context.mode === 'repo' ? 'maintenance/pro-inspector-snapshot.json' : outPath, snapshot };
  if (parsed.flags.json) console.log(JSON.stringify(result, null, 2));
  else console.log(JSON.stringify(result, null, 2));
  return result;
}

if (require.main === module) {
  try { main(); }
  catch (error) { console.error(error.stack || error.message); process.exit(1); }
}

module.exports = main;
