#!/usr/bin/env node
'use strict';

const path = require('path');
const { ensureDir, readJson, writeJsonAtomic, getAgentId, withLock } = require('./lib/json-store');

const repoRoot = path.resolve(__dirname, '..', '..');
const knowledgeRoot = path.resolve(__dirname, '..');
const lockDir = path.join(knowledgeRoot, '.lock');

function nowIso() { return new Date().toISOString(); }
function safeRead(filePath, fallback) { return readJson(filePath, fallback); }
function compactArray(value, max = 20) { return Array.isArray(value) ? value.slice(0, max) : []; }
function normalizeTrustBuckets(trustReport) {
  const modules = trustReport.modules || {};
  return {
    trusted: modules.trusted || [],
    near_trusted: modules.near_trusted || [],
    routing_trusted: modules.routing_trusted || [],
    advisory_only: modules.advisory_only || [],
    suspect: modules.suspect || [],
    low_confidence: modules.low_confidence || []
  };
}

function buildUnlocked(options = {}) {
  ensureDir(path.join(knowledgeRoot, 'maintenance'));
  const generatedAt = nowIso();
  const agentId = getAgentId();

  const projectIndex = safeRead(path.join(knowledgeRoot, 'project_index.json'), {});
  const trustReport = safeRead(path.join(knowledgeRoot, 'maintenance', 'trust_report.json'), {});
  const handoff = safeRead(path.join(knowledgeRoot, 'maintenance', 'handoff_summary.json'), {});
  const concurrency = safeRead(path.join(knowledgeRoot, 'maintenance', 'concurrency_policy.json'), {});
  const quality = safeRead(path.join(knowledgeRoot, 'maintenance', 'quality_report.json'), {});
  const wikiLint = safeRead(path.join(knowledgeRoot, 'maintenance', 'wiki_lint_report.json'), {});
  const wikiGraph = safeRead(path.join(knowledgeRoot, 'maps', 'wiki_graph.json'), {});
  const externalStatus = safeRead(path.join(knowledgeRoot, 'maintenance', 'external_memory_status.json'), {});
  const metrics = safeRead(path.join(knowledgeRoot, 'metrics', 'baseline.json'), {});
  const criticalPaths = safeRead(path.join(knowledgeRoot, 'maps', 'critical_paths.json'), { paths: [] });
  const fileCriticality = safeRead(path.join(knowledgeRoot, 'maps', 'file_criticality.json'), { files: [] });
  const registry = safeRead(path.join(knowledgeRoot, 'modules', 'module_registry.json'), { modules: [] });
  const freshness = safeRead(path.join(knowledgeRoot, 'freshness.json'), { artifact_statuses: {}, tracked_files: [] });

  const statusByModule = new Map((trustReport.module_statuses || []).map((item) => [item.module_id, item]));
  const classificationByPath = new Map((fileCriticality.files || []).map((item) => [item.path, item.classification || 'important']));
  const activeKnowledgeFiles = new Set(
    Object.values(freshness.artifact_dependencies || {})
      .flat()
      .filter(Boolean)
  );
  const modules = (registry.modules || []).map((moduleInfo) => {
    const status = statusByModule.get(moduleInfo.module_id) || {};
    return {
      module_id: moduleInfo.module_id,
      path: moduleInfo.path,
      card: moduleInfo.card,
      confidence: status.confidence || moduleInfo.confidence || 'unknown',
      trust_status: status.trust_status || 'unknown',
      freshness_status: status.freshness_status || 'unknown',
      start_with: compactArray([moduleInfo.card, ...(moduleInfo.key_files || []), ...(moduleInfo.evidence_files || [])].filter(Boolean), 8),
      reasons: status.reasons || {}
    };
  });

  const trust = normalizeTrustBuckets(trustReport);
  const highRiskModules = Array.from(new Set([...(trust.suspect || []), ...(trust.low_confidence || [])]));
  const changedFiles = (freshness.tracked_files || [])
    .filter((entry) => ['changed', 'missing', 'suspect', 'needs_recheck'].includes(entry.status))
    .filter((entry) => activeKnowledgeFiles.size === 0 || activeKnowledgeFiles.has(entry.path))
    .filter((entry) => (classificationByPath.get(entry.path) || 'important') !== 'contextual')
    .map((entry) => ({ path: entry.path, status: entry.status, last_scanned_at: entry.last_scanned_at }))
    .slice(0, 100);

  const bundle = {
    schema_version: '3.1.9',
    generated_at: generatedAt,
    generated_by: agentId,
    purpose: 'Compact first-read routing bundle for agents. Read this before opening larger .knowledge files.',
    source_of_truth_order: ['current_code', 'current_tests', '.knowledge/evidence/*.json', '.knowledge/modules/*.json', '.knowledge/decisions.json', '.knowledge/wiki/*.md', '.knowledge/sessions/*', 'external_retrieved_memory'],
    first_read_strategy: {
      read_first: '.knowledge/maintenance/routing_bundle.json',
      then_read_only_if_needed: [
        '.knowledge/project_index.json',
        '.knowledge/maintenance/trust_report.json',
        '.knowledge/maintenance/handoff_summary.json',
        '.knowledge/wiki/index.md',
        '.knowledge/maps/critical_paths.json',
        '.knowledge/search/index.json'
      ],
      mandatory_code_recheck_when: ['suspect', 'needs_recheck', 'low_confidence', 'missing_card', 'critical_path_change', 'security_sensitive_change']
    },
    project: {
      name: projectIndex.project_name || null,
      summary: projectIndex.summary || handoff.project_operational_summary || null,
      technologies: projectIndex.technologies || [],
      status: projectIndex.status || null
    },
    health: {
      quality_score: quality.quality_score ?? null,
      status: quality.status || 'unknown',
      issues_total: (quality.issues || []).length,
      trust_generated_at: trustReport.generated_at || null,
      freshness_generated_at: freshness.generated_at || null,
      wiki_lint_status: wikiLint.status || 'unknown',
      wiki_lint_score: wikiLint.quality_score ?? null,
      metrics_tokens_saved: metrics.routing?.estimated_tokens_saved ?? null
    },
    concurrency: {
      mode: concurrency.mode || concurrency.write_policy || 'locked_atomic_writes',
      requires_agent_id: concurrency.requires_agent_id ?? true,
      recommended_workspace: concurrency.recommended_workspace || 'one git worktree or branch per bot/agent',
      event_log: '.knowledge/maintenance/events/YYYY-MM-DD.ndjson'
    },
    trust,
    high_risk_modules: highRiskModules,
    changed_or_stale_files: changedFiles,
    modules,
    critical_paths: compactArray((criticalPaths.paths || []).map((item) => ({
      id: item.id,
      name: item.name || item.summary || null,
      modules: item.modules || [],
      test_linkage_status: item.test_linkage?.status || 'unknown',
      start_with: item.start_with || item.entrypoints || []
    })), 30),
    task_routing: compactArray(projectIndex.task_routing || [], 50),
    wiki: {
      index: '.knowledge/wiki/index.md',
      log: '.knowledge/wiki/log.md',
      graph: '.knowledge/maps/wiki_graph.json',
      lint_report: '.knowledge/maintenance/wiki_lint_report.json',
      nodes: wikiGraph.node_count || 0,
      edges: wikiGraph.edge_count || 0,
      broken_edges: wikiGraph.broken_edge_count || 0,
      sections: ['architecture/', 'runbooks/', 'concepts/'],
      trust_level: 'advisory_only_unless_backed_by_evidence'
    },
    search: {
      index: '.knowledge/search/index.json',
      command: 'node .knowledge/tools/search-knowledge.js "<query>"',
      rebuild_command: 'node .knowledge/tools/build-search-index.js'
    },
    external_memory: {
      status: externalStatus.providers?.pinecone?.status || 'unknown',
      mode: externalStatus.providers?.pinecone?.mode || 'disabled',
      source_of_truth: false,
      command: 'node .knowledge/tools/external-memory-status.js'
    },
    maintenance_commands: [
      'node .knowledge/tools/sync-tracked.js',
      'node .knowledge/tools/sync-tracked.js --scan',
      'node .knowledge/tools/sync-tracked.js --scan --discover',
      'node .knowledge/tools/build-wiki-graph.js',
      'node .knowledge/tools/lint-wiki.js',
      'node .knowledge/tools/external-memory-status.js',
      'node .knowledge/tools/build-routing-bundle.js',
      'node .knowledge/tools/build-search-index.js',
      'node .knowledge/tools/doctor.js',
      'node .knowledge/tools/collect-metrics.js'
    ],
    token_economy: {
      intent: 'Read one compact bundle first, then only the relevant module cards and source files.',
      avoid: 'Do not load the entire wiki, search index, or all module cards unless the task requires it.'
    }
  };

  const outPath = path.join(knowledgeRoot, 'maintenance', 'routing_bundle.json');
  writeJsonAtomic(outPath, bundle);
  if (!options.quiet) console.log(JSON.stringify({ written: '.knowledge/maintenance/routing_bundle.json', modules: modules.length, high_risk_modules: highRiskModules.length }, null, 2));
  return bundle;
}

function main(options = {}) {
  if (options.skipLock) return buildUnlocked(options);
  return withLock(lockDir, () => buildUnlocked(options));
}

module.exports = main;

if (require.main === module) {
  try {
    main({ quiet: process.argv.includes('--quiet') });
  } catch (error) {
    console.error(error.stack || error.message);
    process.exit(1);
  }
}
