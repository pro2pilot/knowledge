#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const { ensureDir, readJson, writeJsonAtomic, writeFileAtomic, getAgentId } = require('./lib/json-store');
const { estimateTokens, METHOD_ID } = require('./lib/token-estimate');
const { resolveKnowledgeContext } = require('./lib/path-context');

const context = resolveKnowledgeContext();
const knowledgeRoot = context.projectKnowledgeRoot;
const stateRoot = context.stateRoot;

function bytes(p) { try { return fs.statSync(p).size; } catch { return 0; } }
function count(dir, fn = () => true) {
  let n = 0;
  if (!fs.existsSync(dir)) return 0;
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const a = path.join(dir, e.name);
    if (e.isDirectory()) n += count(a, fn);
    else if (fn(a)) n += 1;
  }
  return n;
}
function readText(filePath) {
  return fs.existsSync(filePath) ? fs.readFileSync(filePath, 'utf8') : '';
}

function canonicalPath(dirPath) {
  let resolved = path.resolve(dirPath);
  try { resolved = fs.realpathSync.native(resolved); }
  catch {}
  return process.platform === 'win32' ? resolved.toLowerCase() : resolved;
}

function isPathWithin(candidatePath, parentPath) {
  return candidatePath === parentPath || candidatePath.startsWith(`${parentPath}${path.sep}`);
}

function fileInventory(dirPath) {
  const files = new Set();
  function walk(currentPath) {
    if (!fs.existsSync(currentPath)) return;
    for (const entry of fs.readdirSync(currentPath, { withFileTypes: true })) {
      const absolutePath = path.join(currentPath, entry.name);
      if (entry.isDirectory()) walk(absolutePath);
      else files.add(canonicalPath(absolutePath));
    }
  }
  walk(dirPath);
  return files;
}

function main() {
  ensureDir(path.join(stateRoot, 'metrics'));
  const canonicalKnowledgeRoot = canonicalPath(knowledgeRoot);
  const canonicalStateRoot = canonicalPath(stateRoot);
  const stateWithinKnowledge = isPathWithin(canonicalStateRoot, canonicalKnowledgeRoot);
  const knowledgeWithinState = isPathWithin(canonicalKnowledgeRoot, canonicalStateRoot);
  const rootsOverlap = stateWithinKnowledge || knowledgeWithinState;
  const rootsRelation = canonicalKnowledgeRoot === canonicalStateRoot
    ? 'same'
    : stateWithinKnowledge
      ? 'state_within_knowledge'
      : knowledgeWithinState
        ? 'knowledge_within_state'
        : 'separate';
  const curatedFiles = fileInventory(knowledgeRoot);
  const stateFiles = fileInventory(stateRoot);
  const runtimeOnlyFiles = new Set([...stateFiles].filter((filePath) => !curatedFiles.has(filePath)));
  const uniqueFiles = new Set([...curatedFiles, ...stateFiles]);
  const curatedTotal = curatedFiles.size;
  const runtimeTotal = runtimeOnlyFiles.size;
  const uniqueJson = [...uniqueFiles].filter((filePath) => filePath.endsWith('.json')).length;
  const uniqueMarkdown = [...uniqueFiles].filter((filePath) => filePath.endsWith('.md')).length;
  const runtimeAccounting = !rootsOverlap
    ? 'separate_state_root'
    : knowledgeWithinState && !stateWithinKnowledge
      ? 'runtime_total_excludes_curated_overlap'
      : 'included_in_curated_total';
  const routePath = path.join(stateRoot, 'maintenance', 'routing_bundle.json');
  const routeText = readText(routePath);
  const multi = [
    path.join(knowledgeRoot, 'project_index.json'),
    path.join(stateRoot, 'maintenance', 'trust_report.json'),
    path.join(stateRoot, 'maintenance', 'handoff_summary.json'),
    path.join(knowledgeRoot, 'maintenance', 'concurrency_policy.json'),
    path.join(knowledgeRoot, 'maps', 'critical_paths.json')
  ].map(readText).join('\n');
  const routeTokens = estimateTokens(routeText);
  const multiTokens = estimateTokens(multi);
  // The global bootstrap and legacy multi-file read-set have different scope.
  // Never turn this convenient local diagnostic into a public savings claim.
  const tokenDelta = multiTokens - routeTokens;
  const percentDelta = multiTokens ? Math.round((1 - routeTokens / multiTokens) * 100) : 0;
  const routingIndex = readJson(path.join(stateRoot, 'routing', 'index.json'), { tasks: [] });
  const externalMemoryReport = readJson(path.join(stateRoot, 'maintenance', 'external_memory_status.json'), { providers: [], metrics: {} });
  const externalMemoryMetrics = readJson(path.join(stateRoot, 'metrics', 'external_memory.json'), externalMemoryReport.metrics || {});
  const metrics = {
    schema_version: '3.3.0',
    generated_at: new Date().toISOString(),
    generated_by: getAgentId(),
    mode: context.mode,
    target_root: context.targetRoot,
    project_knowledge_root: context.projectKnowledgeRoot,
    state_root: context.stateRoot,
    token_estimator: METHOD_ID,
    files: {
      curated_total: curatedTotal,
      runtime_total: runtimeTotal,
      unique_total: uniqueFiles.size,
      json: uniqueJson,
      markdown: uniqueMarkdown,
      roots_overlap: rootsOverlap,
      roots_relation: rootsRelation,
      runtime_total_accounting: runtimeAccounting,
      tools: count(path.join(context.systemRoot, 'tools'), (a) => a.endsWith('.js'))
    },
    routing: {
      bundle_bytes: bytes(routePath),
      bundle_tokens_approx: routeTokens,
      legacy_first_read_tokens_approx: multiTokens,
      estimated_token_delta: tokenDelta,
      estimated_percent_delta: percentDelta,
      signed_delta_tokens: tokenDelta,
      signed_delta_percent: percentDelta,
      estimated_tokens_saved: 0,
      estimated_percent_saved: 0,
      estimated_tokens_overhead: 0,
      estimated_percent_overhead: 0,
      scope_comparable: false,
      claim_eligible: false,
      claim_ineligible_reason: 'baseline_and_routing_scope_differ',
      measurement_kind: 'estimated_local_context',
      assessment: 'not_comparable',
      task_routing_index: 'routing/index.json',
      task_snapshots_total: (routingIndex.tasks || []).length,
      actual_model_usage: { available: false, reason: 'no_provider_telemetry' }
    },
    indexes: {
      search_documents: readJson(path.join(stateRoot, 'search', 'index.json'), { documents: [] }).documents.length,
      wiki_nodes: readJson(path.join(stateRoot, 'maps', 'wiki_graph.json'), { nodes: [] }).nodes.length,
      wiki_edges: readJson(path.join(stateRoot, 'maps', 'wiki_graph.json'), { edges: [] }).edges.length
    },
    health: {
      doctor_score: readJson(path.join(stateRoot, 'maintenance', 'quality_report.json'), {}).quality_score ?? null,
      wiki_lint_score: readJson(path.join(stateRoot, 'maintenance', 'wiki_lint_report.json'), {}).quality_score ?? null
    },
    external_memory: {
      providers: externalMemoryReport.providers || [],
      metrics: externalMemoryMetrics,
      source_of_truth_policy: externalMemoryReport.source_of_truth_policy || {}
    }
  };
  writeJsonAtomic(path.join(stateRoot, 'metrics', 'baseline.json'), metrics);
  writeFileAtomic(path.join(stateRoot, 'metrics', 'README.md'),
`# Metrics

Generated: ${metrics.generated_at}
Mode: ${metrics.mode}
Token estimator: ${metrics.token_estimator}

- Routing bundle tokens (approx): ${metrics.routing.bundle_tokens_approx}
- Legacy first-read tokens (approx): ${metrics.routing.legacy_first_read_tokens_approx}
- Routing comparison: ${metrics.routing.assessment} (${metrics.routing.claim_ineligible_reason})
- Signed diagnostic delta: ${metrics.routing.signed_delta_tokens} (${metrics.routing.signed_delta_percent}%; not a task-comparable claim)
- Task snapshots: ${metrics.routing.task_snapshots_total} (${metrics.routing.task_routing_index})
- Curated-root files: ${metrics.files.curated_total}
- Separate runtime-root files: ${metrics.files.runtime_total}
- Unique files across counted roots: ${metrics.files.unique_total}
- Project/state roots overlap: ${metrics.files.roots_overlap} (${metrics.files.runtime_total_accounting})
- Search documents: ${metrics.indexes.search_documents}
- Wiki graph: ${metrics.indexes.wiki_nodes} nodes / ${metrics.indexes.wiki_edges} edges
- Doctor score: ${metrics.health.doctor_score}
- Wiki lint score: ${metrics.health.wiki_lint_score}

Token numbers are order-of-magnitude and locally estimated.
`);
  console.log(JSON.stringify(metrics, null, 2));
  return metrics;
}

if (require.main === module) main();
module.exports = main;
