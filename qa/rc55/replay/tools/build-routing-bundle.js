#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const {
  readJson,
  writeJsonAtomicContained,
  getAgentId,
  appendNdjsonContained,
  assertSafeContainmentRoot,
  assertSafeContainedPath,
  containedPath
} = require('./lib/json-store');
const { withContainedLock } = require('./lib/contained-lock-manager');
const { LOCKS } = require('./lib/lock-policy');
const { resolveKnowledgeContext, jsonContext, parseCliArgs } = require('./lib/path-context');
const { systemVersion } = require('./lib/system-version');
const {
  buildRoutingDecision,
  filterCriticalPaths,
  filterTaskRoutes,
  normalizeWikiStatus,
  repoClass
} = require('./lib/adaptive-routing');
const taskRouting = require('./lib/task-routing');

const context = resolveKnowledgeContext();
const repoRoot = context.targetRoot;
const knowledgeRoot = context.projectKnowledgeRoot;
const stateRoot = context.stateRoot;
const ROUTING_BUNDLE_LOCK = Object.freeze({
  context,
  rootKind: 'state',
  rootPath: stateRoot,
  lockName: 'routing-bundle',
  purpose: LOCKS['routing-bundle'].purpose
});
const SCHEMA_VERSION = systemVersion();

function nowIso() { return new Date().toISOString(); }
function safeRead(filePath, fallback) {
  if (!fs.existsSync(filePath)) return fallback;
  const containmentRoot = containedPath(stateRoot, filePath)
    ? stateRoot
    : containedPath(knowledgeRoot, filePath)
      ? knowledgeRoot
      : null;
  if (!containmentRoot) {
    const error = new Error(
      `Routing input is outside configured roots: ${filePath}`
    );
    error.code = 'routing_input_outside_root';
    throw error;
  }
  assertSafeContainedPath(containmentRoot, filePath);
  const stat = fs.lstatSync(filePath);
  if (!stat.isFile() || stat.isSymbolicLink()) {
    const error = new Error(
      `Routing input is not a physical file: ${filePath}`
    );
    error.code = 'routing_input_reparse_path';
    throw error;
  }
  return readJson(filePath, fallback);
}
function projectPath(relPath) { return path.join(knowledgeRoot, relPath); }
function statePath(relPath) { return path.join(stateRoot, relPath); }
function display(relPath) { return context.mode === 'repo' ? `.knowledge/${relPath}` : path.join(stateRoot, relPath); }
function splitList(value) {
  if (Array.isArray(value)) return value.flatMap(splitList);
  return String(value || '').split(/[;,\r\n]+/).map((item) => item.trim()).filter(Boolean);
}
function targetRelativeGitChangedFiles(git, targetRoot) {
  if (!git?.is_git_repo || !git.worktree_root) return [];
  const relativeTarget = path.relative(
    path.resolve(git.worktree_root),
    path.resolve(targetRoot)
  ).replace(/\\/g, '/').replace(/\/+$/g, '');
  if (
    relativeTarget.startsWith('../') ||
    path.posix.isAbsolute(relativeTarget)
  ) return [];
  const targetIdentity = process.platform === 'win32'
    ? relativeTarget.toLowerCase()
    : relativeTarget;
  return (git.changed_files || []).flatMap((value) => {
    const candidate = String(value || '')
      .replace(/\\/g, '/')
      .replace(/^\.\/+/, '')
      .replace(/\/+$/g, '');
    if (
      !candidate ||
      candidate.includes('\0') ||
      path.posix.isAbsolute(candidate) ||
      path.win32.isAbsolute(candidate) ||
      candidate.split('/').includes('..')
    ) return [];
    if (!relativeTarget) return [candidate];
    const candidateIdentity = process.platform === 'win32'
      ? candidate.toLowerCase()
      : candidate;
    if (candidateIdentity === targetIdentity) return ['.'];
    const prefix = `${targetIdentity}/`;
    return candidateIdentity.startsWith(prefix)
      ? [candidate.slice(relativeTarget.length + 1)]
      : [];
  });
}
function normalizeProviderId(value) {
  const id = String(value || '').trim().toLowerCase().replace(/_/g, '-');
  return id === 'mem0' ? 'mem0-oss' : id;
}
function providerList(value) {
  if (Array.isArray(value)) return value.filter((provider) => provider && typeof provider === 'object');
  if (!value || typeof value !== 'object') return [];
  return Object.entries(value)
    .filter(([, provider]) => provider && typeof provider === 'object')
    .map(([key, provider]) => ({ provider_id: provider.provider_id || provider.provider || key, ...provider }));
}
function providerStatus(externalStatus, providerId) {
  const expected = normalizeProviderId(providerId);
  return providerList(externalStatus.providers).find((provider) => (
    normalizeProviderId(provider.provider_id || provider.provider) === expected
  )) || {};
}
function uniqueRoutingValues(...groups) {
  const seen = new Set();
  const out = [];
  for (const value of groups.flat()) {
    if (value === null || value === undefined || value === '') continue;
    const key = typeof value === 'object'
      ? JSON.stringify(value)
      : String(value);
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(value);
  }
  return out;
}
function routingCardPath(card) {
  const raw = String(card || '').trim().replace(/\\/g, '/');
  if (!raw || path.posix.isAbsolute(raw) || path.win32.isAbsolute(raw) || raw.split('/').includes('..')) return null;
  const relative = raw.replace(/^\.knowledge\//, '');
  if (!relative.startsWith('modules/') || !relative.endsWith('.json')) return null;
  const candidate = path.join(knowledgeRoot, ...relative.split('/'));
  if (!containedPath(knowledgeRoot, candidate)) return null;
  if (!fs.existsSync(candidate)) return candidate;
  try {
    assertSafeContainedPath(knowledgeRoot, candidate);
    const stat = fs.lstatSync(candidate);
    if (!stat.isFile() || stat.isSymbolicLink()) return null;
    return candidate;
  } catch {
    return null;
  }
}
function hydrateRoutingRegistry(registry) {
  const warnings = [];
  const listFields = [
    'dependencies',
    'depends_on',
    'related_modules',
    'keywords',
    'tags',
    'key_files',
    'evidence_files',
    'start_with'
  ];
  const scalarFields = [
    'purpose',
    'summary',
    'description',
    'security_sensitive',
    'critical',
    'critical_path',
    'criticality',
    'zone_importance'
  ];
  const modules = (registry.modules || []).map((moduleInfo) => {
    if (!moduleInfo || typeof moduleInfo !== 'object' || Array.isArray(moduleInfo) ||
        typeof moduleInfo.module_id !== 'string' || !moduleInfo.module_id.trim()) {
      warnings.push({
        code: 'routing_module_registry_entry_invalid',
        module_id: null,
        card: null
      });
      return null;
    }
    const cardPath = routingCardPath(moduleInfo.card);
    if (!cardPath) {
      warnings.push({
        code: 'routing_module_card_unsafe_or_missing_path',
        module_id: moduleInfo.module_id,
        card: moduleInfo.card || null
      });
      return { ...moduleInfo };
    }
    if (!fs.existsSync(cardPath)) {
      warnings.push({
        code: 'routing_module_card_missing',
        module_id: moduleInfo.module_id,
        card: moduleInfo.card
      });
      return { ...moduleInfo };
    }
    let card;
    try {
      card = JSON.parse(fs.readFileSync(cardPath, 'utf8').replace(/^\uFEFF/, ''));
    } catch (error) {
      warnings.push({
        code: 'routing_module_card_invalid_json',
        module_id: moduleInfo.module_id,
        card: moduleInfo.card,
        error: error.message
      });
      return { ...moduleInfo };
    }
    if (card.module_id !== moduleInfo.module_id) {
      warnings.push({
        code: 'routing_module_card_id_mismatch',
        module_id: moduleInfo.module_id,
        card_module_id: card.module_id,
        card: moduleInfo.card
      });
      return { ...moduleInfo };
    }
    const hydrated = {
      ...card,
      ...moduleInfo,
      module_id: moduleInfo.module_id,
      card: moduleInfo.card,
      path: moduleInfo.path || card.path,
      name: moduleInfo.name || card.name
    };
    for (const field of listFields) {
      hydrated[field] = uniqueRoutingValues(
        Array.isArray(moduleInfo[field]) ? moduleInfo[field] : [],
        Array.isArray(card[field]) ? card[field] : []
      );
    }
    for (const field of scalarFields) {
      if (moduleInfo[field] === undefined || moduleInfo[field] === null || moduleInfo[field] === '') {
        hydrated[field] = card[field];
      }
    }
    return hydrated;
  }).filter(Boolean);
  return {
    registry: { ...registry, modules },
    warnings
  };
}
function changedPathIdentity(value) {
  return String(value || '').trim().replace(/\\/g, '/').replace(/^\.\//, '').replace(/\/+/g, '/');
}
function changedFilePresentation(routingDecision, cap = 100) {
  const all = Array.isArray(routingDecision.changed_files) ? routingDecision.changed_files : [];
  const highRiskPaths = new Set(
    (routingDecision.candidate_modules || [])
      .filter((candidate) => candidate.high_risk)
      .flatMap((candidate) => candidate.changed_files || [])
      .map((item) => changedPathIdentity(item.path))
      .filter(Boolean)
  );
  const highRisk = all.filter((item) => highRiskPaths.has(changedPathIdentity(item.path)));
  const ordinary = all.filter((item) => !highRiskPaths.has(changedPathIdentity(item.path)));
  const selected = [...highRisk];
  for (const item of ordinary) {
    if (selected.length >= cap) break;
    selected.push(item);
  }
  const selectedPaths = new Set(selected.map((item) => changedPathIdentity(item.path)));
  const omitted = all.filter((item) => !selectedPaths.has(changedPathIdentity(item.path)));
  const omittedHighRisk = omitted
    .filter((item) => highRiskPaths.has(changedPathIdentity(item.path)))
    .map((item) => item.path);
  return {
    files: selected,
    total: all.length,
    included: selected.length,
    truncated: omitted.length > 0,
    truncation_reason: omitted.length > 0
      ? 'changed_file_cap_reached_after_high_risk_preservation'
      : (selected.length > cap ? 'safety_changed_file_cap_overrun' : 'not_truncated'),
    cap,
    safety_overrun: selected.length > cap,
    omitted_high_risk_files: omittedHighRisk
  };
}
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

const SKIPPED_REPO_DIRS = new Set(['.git', 'node_modules', '.next', 'dist', 'build', 'coverage']);

function inspectRepo(root) {
  const totals = { files: 0, bytes: 0 };
  function walk(dir) {
    if (!fs.existsSync(dir)) return;
    assertSafeContainedPath(root, dir);
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      if (entry.name === '.knowledge' || (entry.isDirectory() && SKIPPED_REPO_DIRS.has(entry.name))) continue;
      const abs = path.join(dir, entry.name);
      if (entry.isSymbolicLink()) continue;
      assertSafeContainedPath(root, abs);
      if (entry.isDirectory()) walk(abs);
      else if (entry.isFile()) {
        totals.files += 1;
        try { totals.bytes += fs.statSync(abs).size; } catch { /* transient file: omit bytes */ }
      }
    }
  }
  walk(root);
  return { ...totals, megabytes: Number((totals.bytes / (1024 * 1024)).toFixed(3)) };
}

function buildUnlocked(options = {}) {
  const generatedAt = nowIso();
  const agentId = getAgentId();

  const projectIndex = safeRead(projectPath('project_index.json'), {});
  const trustReport = safeRead(statePath(path.join('maintenance', 'trust_report.json')), {});
  const handoff = safeRead(statePath(path.join('maintenance', 'handoff_summary.json')), {});
  const concurrency = safeRead(projectPath(path.join('maintenance', 'concurrency_policy.json')), safeRead(statePath(path.join('maintenance', 'concurrency_policy.json')), {}));
  const quality = safeRead(statePath(path.join('maintenance', 'quality_report.json')), {});
  const repairQueue = safeRead(statePath(path.join('maintenance', 'repair_queue.json')), { queue: [] });
  const wikiLint = safeRead(statePath(path.join('maintenance', 'wiki_lint_report.json')), {});
  const wikiGraph = safeRead(statePath(path.join('maps', 'wiki_graph.json')), {});
  const externalStatus = safeRead(statePath(path.join('maintenance', 'external_memory_status.json')), {});
  const metrics = safeRead(statePath(path.join('metrics', 'baseline.json')), {});
  const criticalPaths = safeRead(projectPath(path.join('maps', 'critical_paths.json')), { paths: [] });
  const rawRegistry = safeRead(projectPath(path.join('modules', 'module_registry.json')), { modules: [] });
  const hydratedRegistry = hydrateRoutingRegistry(rawRegistry);
  const registry = hydratedRegistry.registry;
  const freshness = safeRead(statePath('freshness.json'), { artifact_statuses: {}, tracked_files: [] });
  const cli = parseCliArgs(process.argv.slice(2)).flags;
  const routingOverride = options.routingMode || options.routing_mode || cli.routingMode || process.env.KNOWLEDGE_ROUTING_MODE || null;
  const routingTask = options.task || cli.task || process.env.KNOWLEDGE_ROUTING_TASK || '';
  const contextBudgetBytes = options.contextBudgetBytes || options.context_budget_bytes || cli.contextBudgetBytes || process.env.KNOWLEDGE_ROUTING_BUDGET_BYTES || null;

  const statusByModule = new Map((trustReport.module_statuses || []).map((item) => [item.module_id, item]));
  const trust = normalizeTrustBuckets(trustReport);
  const freshnessChangedFiles = (freshness.tracked_files || [])
    .map((entry) => ({ ...entry, status: String(entry.status || '').toLowerCase() }))
    .filter((entry) => ['changed', 'missing', 'suspect', 'stale', 'needs_recheck', 'low_confidence'].includes(entry.status))
    .map((entry) => ({ path: entry.path, status: entry.status, source: 'freshness', last_scanned_at: entry.last_scanned_at }))
    .filter((entry) => entry.path);
  const repoSize = inspectRepo(repoRoot);
  const criticalPathRows = (criticalPaths.paths || []).map((item) => ({
    id: item.id,
    name: item.name || item.summary || null,
    modules: item.modules || [],
    test_linkage_status: item.test_linkage?.status || 'unknown',
    start_with: item.start_with || item.entrypoints || []
  }));
  const routingRows = projectIndex.task_routing || [];
  const explicitChangedFiles = splitList(options.changedFiles || options.changed_files || cli.changedFile || cli.changedFiles || process.env.KNOWLEDGE_ROUTING_CHANGED_FILES)
    .map((file) => ({ path: file, status: 'changed', source: 'explicit_scope' }));
  const gitChangedFiles = targetRelativeGitChangedFiles(
    context.git,
    repoRoot
  ).map((file) => ({
    path: file,
    status: 'changed',
    source: 'current_diff'
  }));
  const routingDecision = buildRoutingDecision({
    override: routingOverride ? String(routingOverride).toLowerCase() : null,
    size: repoSize,
    task: routingTask,
    contextBudgetBytes,
    registry,
    statusByModule,
    trustReport,
    freshness: { ...freshness, tracked_files: [] },
    criticalPaths,
    taskRouting: routingRows,
    wikiLint,
    wikiGraph,
    quality,
    repairQueue,
    changedFiles: [...explicitChangedFiles, ...gitChangedFiles, ...freshnessChangedFiles]
  });
  const changedFiles = changedFilePresentation(routingDecision);
  const selectedIds = new Set(routingDecision.selected_modules);
  const selectedPayload = {
    modules: routingDecision.selected.map((item) => item.publicRow),
    critical_paths: filterCriticalPaths(criticalPathRows, selectedIds, routingDecision.mode),
    task_routing: filterTaskRoutes(routingRows, selectedIds, routingDecision.mode, routingTask)
  };
  const highRiskModules = routingDecision.candidate_modules.filter((item) => item.high_risk).map((item) => item.module_id);
  const wikiStatus = normalizeWikiStatus(wikiLint, wikiGraph);
  const {
    selected: _selectedCandidates,
    excluded: _excludedCandidates,
    ...publicRoutingDecision
  } = routingDecision;
  const decisionArtifact = {
    ...publicRoutingDecision,
    generated_at: generatedAt,
    generated_by: agentId,
    repo_size: { ...repoSize, class: repoClass(repoSize) },
    module_count: (registry.modules || []).length,
    input_warnings: hydratedRegistry.warnings
  };

  const bundle = {
    schema_version: SCHEMA_VERSION,
    generated_at: generatedAt,
    generated_by: agentId,
    context: jsonContext(context),
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
      wiki_lint_status: wikiStatus,
      wiki_lint_score: wikiLint.quality_score ?? null,
      metrics_tokens_saved: metrics.routing?.estimated_tokens_saved ?? null
    },
    concurrency: {
      mode: concurrency.mode || concurrency.write_policy || 'locked_atomic_writes',
      requires_agent_id: concurrency.requires_agent_id ?? true,
      recommended_workspace: concurrency.recommended_workspace || 'one git worktree or branch per bot/agent',
      event_log: context.mode === 'repo' ? '.knowledge/maintenance/events/YYYY-MM-DD.ndjson' : path.join(stateRoot, 'maintenance', 'events', 'YYYY-MM-DD.ndjson')
    },
    trust,
    high_risk_modules: highRiskModules,
    changed_or_stale_files: changedFiles.files,
    routing: {
      mode: routingDecision.mode,
      selection: routingDecision.selection,
      reason: routingDecision.reason,
      requested_mode: routingDecision.requested_mode,
      task_input: routingTask || null,
      repo_size: { ...repoSize, class: repoClass(repoSize) },
      module_count: (registry.modules || []).length,
      graph: { edges: wikiGraph.edge_count || 0, status: wikiStatus, structural_status: wikiStatus },
      input_warnings: hydratedRegistry.warnings,
      changed_files: {
        total: changedFiles.total,
        included: changedFiles.included,
        truncated: changedFiles.truncated,
        truncation_reason: changedFiles.truncation_reason,
        cap: changedFiles.cap,
        safety_overrun: changedFiles.safety_overrun,
        omitted_high_risk_files: changedFiles.omitted_high_risk_files
      },
      safety_overrides: routingDecision.safety_overrides,
      context_budget: routingDecision.context_budget,
      selected_modules: routingDecision.selected_modules,
      excluded_high_risk_modules: routingDecision.excluded_high_risk_modules,
      omitted_relevant_high_risk_modules: routingDecision.omitted_relevant_high_risk_modules,
      truncation_reason: routingDecision.truncation_reason,
      fallback_behavior: routingDecision.fallback_behavior,
      decision_artifact: '.knowledge/maintenance/routing_decision.json',
      decision_log: '.knowledge/maintenance/routing_decisions.ndjson',
      acceptance: {
        omitted_relevant_high_risk_modules: routingDecision.omitted_relevant_high_risk_modules.length,
        invariant: 'omitted_relevant_high_risk_modules = 0'
      }
    },
    modules: selectedPayload.modules,
    critical_paths: selectedPayload.critical_paths,
    task_routing: selectedPayload.task_routing,
    wiki: {
      index: '.knowledge/wiki/index.md',
      log: '.knowledge/wiki/log.md',
      graph: '.knowledge/maps/wiki_graph.json',
      lint_report: '.knowledge/maintenance/wiki_lint_report.json',
      nodes: wikiGraph.node_count || 0,
      edges: wikiGraph.edge_count || 0,
      broken_edges: wikiGraph.broken_edge_count || 0,
      status: wikiStatus,
      structural_status: wikiStatus,
      sections: ['architecture/', 'runbooks/', 'concepts/'],
      trust_level: 'advisory_only_unless_backed_by_evidence'
    },
    search: {
      index: '.knowledge/search/index.json',
      command: 'node .knowledge/tools/search-knowledge.js "<query>"',
      rebuild_command: 'node .knowledge/tools/build-search-index.js'
    },
    external_memory: {
      recommended_provider: externalStatus.recommended_provider || 'mem0-oss',
      status: providerStatus(externalStatus, 'mem0-oss').status || providerStatus(externalStatus, 'pinecone').status || 'unknown',
      mode: providerStatus(externalStatus, 'mem0-oss').mode || providerStatus(externalStatus, 'pinecone').mode || 'disabled',
      source_of_truth: false,
      trust_effect: 'advisory_only',
      legacy_providers_detected: providerList(externalStatus.legacy_providers_detected).length,
      command: 'node .knowledge/tools/memory-provider.js status-all --json'
    },
    maintenance_commands: [
      'node .knowledge/tools/sync-tracked.js',
      'node .knowledge/tools/sync-tracked.js --scan',
      'node .knowledge/tools/sync-tracked.js --scan --discover',
      'node .knowledge/tools/build-wiki-graph.js',
      'node .knowledge/tools/lint-wiki.js',
      'node .knowledge/tools/external-memory-status.js',
      'node .knowledge/tools/memory-provider.js status-all --json',
      'node .knowledge/tools/build-routing-bundle.js',
      'node .knowledge/tools/build-search-index.js',
      'node .knowledge/tools/doctor.js',
      'node .knowledge/tools/collect-metrics.js',
      'node .knowledge/tools/worktree-status.js --json',
      'node .knowledge/tools/team-status.js --team-root <path> --json'
    ],
    token_economy: {
      intent: 'Read one compact bundle first, then only the relevant module cards and source files.',
      avoid: 'Do not load the entire wiki, search index, or all module cards unless the task requires it.'
    }
  };

  // Keep the legacy path, but make it a small workspace bootstrap. Detailed
  // module/path/debt data belongs either to maintenance debt or to a task
  // snapshot; it must not be injected into every new agent's first read.
  const workspaceHealth = {
    schema_version: 'knowledge-workspace-health-summary.v1',
    generated_at: generatedAt,
    workspace: { id: context.repoId, modules_total: (registry.modules || []).length },
    global_health: { doctor_score: quality.quality_score ?? null, status: quality.status || 'unknown', open_findings_total: (repairQueue.queue || []).filter((item) => item.status !== 'closed' && item.status !== 'completed' && item.status !== 'done').length },
    trust: { suspect_modules: trust.suspect.length, low_confidence_modules: trust.low_confidence.length, stale_artifacts_total: trustReport.stale_artifacts_total ?? 0 }
  };
  const maintenanceDebt = {
    schema_version: 'knowledge-maintenance-debt.v1', generated_at: generatedAt,
    stale_artifacts_total: trustReport.stale_artifacts_total ?? 0,
    suspect_modules: trust.suspect, low_confidence_modules: trust.low_confidence,
    repair_queue: repairQueue.queue || [], contradictions: quality.contradictions || [],
    changed_or_stale_paths: (routingDecision.changed_files || []).map((item) => item.path),
    pointer: 'maintenance/maintenance_debt.json'
  };
  const routingIndex = taskRouting.writeIndex(context);
  const bootstrap = {
    schema_version: 'knowledge-routing-bootstrap.v1', generated_at: generatedAt, generated_by: agentId,
    purpose: 'Small global bootstrap. Create or read a task-specific snapshot before work that has an explicit scope.',
    workspace: { id: context.repoId, modules_total: (registry.modules || []).length },
    global_health: workspaceHealth.global_health,
    task_routing: { command: 'node .knowledge/tools/task-routing.js create --task="<task>" --scope-module=<module> --scope-path=<path> --json', index: 'routing/index.json', tasks_total: routingIndex.tasks.length },
    pointers: {
      maintenance_debt: 'maintenance/maintenance_debt.json',
      workspace_health: 'maintenance/workspace_health_summary.json',
      source_of_truth: 'project_index.json',
      safety: 'maintenance/trust_report.json',
      concurrency_policy: 'maintenance/concurrency_policy.json'
    },
    first_read_strategy: { read_first: '.knowledge/maintenance/routing_bundle.json', if_task_snapshot: 'Read routing/tasks/<task_scope_hash>/snapshots/<snapshot_hash>/first-read.md; do not load maintenance debt automatically.' },
    token_economy: { target_estimated_tokens: 600, measurement_kind: 'estimated_local_context' }
  };
  const outPath = statePath(path.join('maintenance', 'routing_bundle.json'));
  writeJsonAtomicContained(outPath, bootstrap, stateRoot);
  writeJsonAtomicContained(statePath(path.join('maintenance', 'workspace_health_summary.json')), workspaceHealth, stateRoot);
  writeJsonAtomicContained(statePath(path.join('maintenance', 'maintenance_debt.json')), maintenanceDebt, stateRoot);
  writeJsonAtomicContained(
    statePath(path.join('maintenance', 'routing_decision.json')),
    decisionArtifact,
    stateRoot
  );
  appendNdjsonContained(
    statePath(path.join('maintenance', 'routing_decisions.ndjson')),
    decisionArtifact,
    stateRoot
  );
  if (!options.quiet) console.log(JSON.stringify({
    written: display('maintenance/routing_bundle.json'),
    decision: display('maintenance/routing_decision.json'),
    modules_total: (registry.modules || []).length,
    modules_selected: selectedPayload.modules.length,
    high_risk_modules: highRiskModules.length,
    omitted_relevant_high_risk_modules: routingDecision.omitted_relevant_high_risk_modules.length,
    mode: context.mode,
    routing_mode: routingDecision.mode,
    routing_reason: routingDecision.reason
  }, null, 2));
  return bootstrap;
}

function main(options = {}) {
  assertSafeContainmentRoot(stateRoot);
  assertSafeContainmentRoot(knowledgeRoot);
  if (options.skipLock) return buildUnlocked(options);
  return withContainedLock(ROUTING_BUNDLE_LOCK, () => buildUnlocked(options));
}

module.exports = Object.assign(main, {
  targetRelativeGitChangedFiles
});

if (require.main === module) {
  try {
    main({ quiet: process.argv.includes('--quiet') });
  } catch (error) {
    console.error(error.stack || error.message);
    process.exit(1);
  }
}
