#!/usr/bin/env node
'use strict';

// (max(words*1.33, chars/4)) so routing bundle, baseline, and assisted
// numbers are derived the same way and remain comparable.

const fs = require('fs');
const path = require('path');
const { ensureDir, readJson, writeJsonAtomic, writeFileAtomic, getAgentId } = require('./lib/json-store');
const { estimateTokens, METHOD_ID } = require('./lib/token-estimate');

const knowledgeRoot = path.resolve(__dirname, '..');

function bytes(p) { try { return fs.statSync(p).size; } catch { return 0; } }
function count(dir, fn = () => true) {
  let n = 0;
  if (!fs.existsSync(dir)) return 0;
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const a = path.join(dir, e.name);
    if (e.isDirectory()) n += count(a, fn);
    else if (fn(a)) n++;
  }
  return n;
}

function main() {
  ensureDir(path.join(knowledgeRoot, 'metrics'));
  const routePath = path.join(knowledgeRoot, 'maintenance', 'routing_bundle.json');
  const routeText = fs.existsSync(routePath) ? fs.readFileSync(routePath, 'utf8') : '';
  const multi = [
    'project_index.json',
    'maintenance/trust_report.json',
    'maintenance/handoff_summary.json',
    'maintenance/concurrency_policy.json',
    'maps/critical_paths.json'
  ].map((f) => fs.existsSync(path.join(knowledgeRoot, f)) ? fs.readFileSync(path.join(knowledgeRoot, f), 'utf8') : '').join('\n');
  const routeTokens = estimateTokens(routeText);
  const multiTokens = estimateTokens(multi);
  const metrics = {
    schema_version: '3.1.9',
    generated_at: new Date().toISOString(),
    generated_by: getAgentId(),
    token_estimator: METHOD_ID,
    files: {
      total: count(knowledgeRoot),
      json: count(knowledgeRoot, (a) => a.endsWith('.json')),
      markdown: count(knowledgeRoot, (a) => a.endsWith('.md')),
      tools: count(path.join(knowledgeRoot, 'tools'), (a) => a.endsWith('.js'))
    },
    routing: {
      bundle_bytes: bytes(routePath),
      bundle_tokens_approx: routeTokens,
      legacy_first_read_tokens_approx: multiTokens,
      estimated_tokens_saved: Math.max(0, multiTokens - routeTokens),
      estimated_percent_saved: multiTokens ? Math.round((1 - routeTokens / multiTokens) * 100) : 0
    },
    indexes: {
      search_documents: readJson(path.join(knowledgeRoot, 'search', 'index.json'), { documents: [] }).documents.length,
      wiki_nodes: readJson(path.join(knowledgeRoot, 'maps', 'wiki_graph.json'), { nodes: [] }).nodes.length,
      wiki_edges: readJson(path.join(knowledgeRoot, 'maps', 'wiki_graph.json'), { edges: [] }).edges.length
    },
    health: {
      doctor_score: readJson(path.join(knowledgeRoot, 'maintenance', 'quality_report.json'), {}).quality_score ?? null,
      wiki_lint_score: readJson(path.join(knowledgeRoot, 'maintenance', 'wiki_lint_report.json'), {}).quality_score ?? null
    }
  };
  writeJsonAtomic(path.join(knowledgeRoot, 'metrics', 'baseline.json'), metrics);
  writeFileAtomic(path.join(knowledgeRoot, 'metrics', 'README.md'),
`# Metrics

Generated: ${metrics.generated_at}
Token estimator: ${metrics.token_estimator}

- Routing bundle tokens (approx): ${metrics.routing.bundle_tokens_approx}
- Legacy first-read tokens (approx): ${metrics.routing.legacy_first_read_tokens_approx}
- Estimated tokens saved: ${metrics.routing.estimated_tokens_saved} (${metrics.routing.estimated_percent_saved}%)
- Search documents: ${metrics.indexes.search_documents}
- Wiki graph: ${metrics.indexes.wiki_nodes} nodes / ${metrics.indexes.wiki_edges} edges
- Doctor score: ${metrics.health.doctor_score}
- Wiki lint score: ${metrics.health.wiki_lint_score}

Token numbers are order-of-magnitude. They are produced by one local
estimator (\`max(ceil(words*1.33), ceil(chars/4))\`) so routing bundle
and baseline are comparable. Tokenizer-specific counts may differ.
`);
  console.log(JSON.stringify(metrics, null, 2));
}

if (require.main === module) main();
