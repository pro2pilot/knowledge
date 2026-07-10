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

function main() {
  ensureDir(path.join(stateRoot, 'metrics'));
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
  const tokenDelta = multiTokens - routeTokens;
  const percentDelta = multiTokens ? Math.round((1 - routeTokens / multiTokens) * 100) : 0;
  const externalMemoryReport = readJson(path.join(stateRoot, 'maintenance', 'external_memory_status.json'), { providers: [], metrics: {} });
  const externalMemoryMetrics = readJson(path.join(stateRoot, 'metrics', 'external_memory.json'), externalMemoryReport.metrics || {});
  const metrics = {
    schema_version: '3.2.11',
    generated_at: new Date().toISOString(),
    generated_by: getAgentId(),
    mode: context.mode,
    target_root: context.targetRoot,
    project_knowledge_root: context.projectKnowledgeRoot,
    state_root: context.stateRoot,
    token_estimator: METHOD_ID,
    files: {
      curated_total: count(knowledgeRoot),
      runtime_total: count(stateRoot),
      json: count(knowledgeRoot, (a) => a.endsWith('.json')) + count(stateRoot, (a) => a.endsWith('.json')),
      markdown: count(knowledgeRoot, (a) => a.endsWith('.md')) + count(stateRoot, (a) => a.endsWith('.md')),
      tools: count(path.join(context.systemRoot, 'tools'), (a) => a.endsWith('.js'))
    },
    routing: {
      bundle_bytes: bytes(routePath),
      bundle_tokens_approx: routeTokens,
      legacy_first_read_tokens_approx: multiTokens,
      estimated_token_delta: tokenDelta,
      estimated_percent_delta: percentDelta,
      estimated_tokens_saved: Math.max(0, tokenDelta),
      estimated_percent_saved: Math.max(0, percentDelta),
      assessment: tokenDelta > 0 ? 'estimated_savings' : tokenDelta < 0 ? 'estimated_overhead' : 'neutral'
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
- Estimated tokens saved: ${metrics.routing.estimated_tokens_saved} (${metrics.routing.estimated_percent_saved}%)
- Signed token delta: ${metrics.routing.estimated_token_delta} (${metrics.routing.estimated_percent_delta}%; positive means savings)
- Assessment: ${metrics.routing.assessment}
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
