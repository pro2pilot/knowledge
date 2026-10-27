#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const { readJson, writeJsonAtomicContained, writeFileAtomicContained, ensurePhysicalRoot, ensureContainedDir, assertSafeContainedFile, getAgentId } = require('./lib/json-store');
const { estimateTokens, METHOD_ID } = require('./lib/token-estimate');
const { resolveKnowledgeContext } = require('./lib/path-context');
const { systemVersion } = require('./lib/system-version');
const { prepareReportOutput, publishReportGeneration } = require('./lib/report-generation');

const context = resolveKnowledgeContext();
const knowledgeRoot = context.projectKnowledgeRoot;
const stateRoot = context.stateRoot;

function bytes(p) { try { return fs.statSync(p).size; } catch { return 0; } }
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
  const excluded = [];
  let regularAliases = 0;
  const boundary = canonicalPath(dirPath);
  const exclude = (file, reason, error = null) => excluded.push({
    path: path.relative(dirPath, file).split(path.sep).join('/') || '.',
    reason,
    ...(error?.code ? { error_code: error.code } : {})
  });
  function walk(currentPath) {
    let entries;
    try { entries = fs.readdirSync(currentPath, { withFileTypes: true }); }
    catch (error) { exclude(currentPath, 'directory_unavailable', error); return; }
    for (const entry of entries) {
      const absolutePath = path.join(currentPath, entry.name);
      if (entry.isDirectory()) { walk(absolutePath); continue; }
      try {
        if (entry.isSymbolicLink()) {
          const resolved = fs.realpathSync.native(absolutePath);
          const identity = canonicalPath(resolved);
          if (!isPathWithin(identity, boundary)) {
            exclude(absolutePath, 'alias_outside_inventory_root');
            continue;
          }
          if (!fs.lstatSync(resolved).isFile()) {
            exclude(absolutePath, 'nonregular_alias_not_counted');
            continue;
          }
          regularAliases += 1;
          files.add(identity);
        } else if (entry.isFile()) {
          files.add(canonicalPath(absolutePath));
        } else {
          exclude(absolutePath, 'nonregular_entry_not_counted');
        }
      } catch (error) {
        exclude(absolutePath, 'entry_unavailable', error);
      }
    }
  }
  walk(dirPath);
  return { files, excluded, regular_aliases: regularAliases };
}

function main() {
  const outputRoot = ensurePhysicalRoot(stateRoot);
  ensureContainedDir(outputRoot, path.join(stateRoot, 'metrics'));
  prepareReportOutput(outputRoot, path.join(stateRoot, 'metrics'), ['baseline.json', 'README.md']);
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
  const curatedInventory = fileInventory(knowledgeRoot);
  const stateInventory = fileInventory(stateRoot);
  const toolsInventory = fileInventory(path.join(context.systemRoot, 'tools'));
  const curatedFiles = curatedInventory.files;
  const stateFiles = stateInventory.files;
  const inventoryDiagnostics = Object.entries({ curated: curatedInventory, runtime: stateInventory, system_tools: toolsInventory })
    .flatMap(([root_role, inventory]) => inventory.excluded.map((item) => ({ root_role, ...item })));
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
    schema_version: systemVersion(),
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
      tools: [...toolsInventory.files].filter((file) => file.endsWith('.js')).length,
      inventory_complete: inventoryDiagnostics.length === 0,
      inventory_exclusions: inventoryDiagnostics,
      regular_aliases: { curated: curatedInventory.regular_aliases, runtime: stateInventory.regular_aliases, system_tools: toolsInventory.regular_aliases }
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
  const readme =
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
- Unique regular files across counted roots: ${metrics.files.unique_total}
- Inventory complete: ${metrics.files.inventory_complete} (${metrics.files.inventory_exclusions.length} excluded entries; see baseline.json)
- Project/state roots overlap: ${metrics.files.roots_overlap} (${metrics.files.runtime_total_accounting})
- Search documents: ${metrics.indexes.search_documents}
- Wiki graph: ${metrics.indexes.wiki_nodes} nodes / ${metrics.indexes.wiki_edges} edges
- Doctor score: ${metrics.health.doctor_score}
- Wiki lint score: ${metrics.health.wiki_lint_score}

Token numbers are order-of-magnitude and locally estimated.
`;
  const publication = publishReportGeneration(outputRoot, path.join(stateRoot, 'metrics'), {
    'baseline.json': JSON.stringify(metrics, null, 2) + '\n',
    'README.md': readme
  });
  Object.defineProperty(metrics, 'publication', { value: publication, enumerable: true });
  console.log(JSON.stringify(metrics, null, 2));
  return metrics;
}

if (require.main === module) main();
module.exports = main;
