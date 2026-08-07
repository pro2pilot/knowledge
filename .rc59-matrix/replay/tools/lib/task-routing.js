'use strict';

// Task routing keeps a small, task-bound read receipt.  It deliberately does
// not use Git HEAD as an input: only the routing inputs themselves may change
// a snapshot identity.
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const {
  ensureContainedDir,
  readJson,
  writeJsonAtomicContained,
  writeFileAtomicContained,
  assertSafeContainedPath,
  containedPath
} = require('./json-store');
const { withContainedLock } = require('./contained-lock-manager');
const { LOCKS } = require('./lock-policy');
const { buildRoutingDecision, normalizeWikiStatus } = require('./adaptive-routing');
const { readContainedJson } = require('./contained-artifact');
const { systemVersion } = require('./system-version');
const {
  BASELINE_SCHEMA,
  RECIPE_ID: BASELINE_RECIPE_ID,
  RECIPE_VERSION: BASELINE_RECIPE_VERSION,
  GENERATOR: BASELINE_GENERATOR,
  buildWorkspaceBaseline
} = require('./workspace-baseline');

const SCOPE_SCHEMA = 'knowledge-routing-scope.v2';
const SNAPSHOT_SCHEMA = 'knowledge-task-routing-snapshot.v3';
function taskRoutingLock(context, resourceId) {
  return {
    context,
    rootKind: 'state',
    rootPath: context.stateRoot,
    lockName: 'task-routing',
    purpose: LOCKS['task-routing'].purpose,
    resourceId
  };
}
const MANIFEST_SCHEMA = 'knowledge-task-routing-manifest.v4';
const CURRENT_SCHEMA = 'knowledge-task-routing-current.v4';
const INDEX_SCHEMA = 'knowledge-routing-index.v4';
const TRANSACTION_SCHEMA = 'knowledge-task-routing-transaction.v1';
const COMPLETE_SCHEMA = 'knowledge-task-routing-complete.v2';
const BASELINE_COMPLETE_SCHEMA = 'knowledge-routing-baseline-complete.v1';
const COMPARISON_COMPLETE_SCHEMA = 'knowledge-task-routing-comparison-complete.v1';
const COMPARISON_SCHEMA = 'knowledge-workspace-narrowing-comparison.v1';
const COMPARISON_KIND = 'workspace_to_task_first_read_narrowing';
const BASELINE_RECIPE = `${BASELINE_RECIPE_ID}.${BASELINE_RECIPE_VERSION}`;
const IMPLEMENTATION_VERSION = 'task-routing.v3.3-rc4-r8';
const REQUIRED_SNAPSHOT_FILES = Object.freeze([
  'scope.json', 'first-read.md', 'bundle.json', 'decision.json', 'provenance.json', 'continuation.json'
]);
const LEGACY_REQUIRED_SNAPSHOT_FILES = Object.freeze([
  'scope.json', 'first-read.md', 'bundle.json', 'decision.json', 'metrics.json', 'provenance.json'
]);
const PATH_BUDGETS = Object.freeze({ minimal: 12, compact: 32, full: 96 });
const HIGH_RISK_PATH_STATUSES = new Set([
  'missing', 'deleted', 'unsafe', 'unreadable', 'conflicted',
  'suspect', 'needs_recheck', 'low_confidence'
]);
const STOP_WORDS = new Set([
  'a', 'an', 'and', 'are', 'as', 'at', 'be', 'by', 'for', 'from', 'in', 'into', 'is', 'it',
  'of', 'on', 'or', 'our', 'the', 'this', 'to', 'with', 'only', 'update', 'audit', 'review',
  'website', 'site', 'knowledge', 'module', 'modules', 'path', 'paths', 'task', 'please'
]);

function sha(value) {
  return crypto.createHash('sha256').update(
    typeof value === 'string' || Buffer.isBuffer(value) ? value : JSON.stringify(value)
  ).digest('hex');
}
function now() { return new Date().toISOString(); }
function safeRead(file, fallback) { try { return readJson(file, fallback); } catch { return fallback; } }
function uniqueSorted(values) {
  return [...new Set((values || []).map((item) => String(item || '')
    .replace(/\\/g, '/').replace(/^\.\//, '').replace(/\/+/g, '/').replace(/\/$/, ''))
    .filter(Boolean))].sort();
}
function asList(value) {
  return (Array.isArray(value) ? value : [value]).flatMap((item) => String(item || '').split(/[;,\n]+/))
    .map((item) => item.trim()).filter(Boolean);
}
function tokens(value) {
  return [...new Set(String(value || '').toLowerCase().split(/[^a-z0-9_/-]+/)
    .map((item) => item.replace(/^[-_/]+|[-_/]+$/g, ''))
    .filter((item) => item.length >= 3 && !STOP_WORDS.has(item)))];
}
function relPath(value) {
  return String(value || '').replace(/\\/g, '/').replace(/^\.\//, '').replace(/\/+/g, '/');
}
function isSafeRelative(value) {
  const normalized = relPath(value);
  return Boolean(normalized) && !path.posix.isAbsolute(normalized) && !normalized.split('/').includes('..');
}
function pathWithin(candidate, prefix) {
  const file = relPath(candidate).replace(/^\.knowledge\//, '');
  const base = relPath(prefix).replace(/^\.knowledge\//, '').replace(/\/$/, '');
  return Boolean(base) && (file === base || file.startsWith(`${base}/`));
}
function fileData(root, relative) {
  const relativePath = relPath(relative);
  if (!isSafeRelative(relativePath)) return null;
  const resolved = path.resolve(root, ...relativePath.split('/'));
  if (!containedPath(root, resolved) || !fs.existsSync(resolved)) return null;
  // Lexical containment is insufficient: every parent component must be a
  // physical directory inside root before any bytes can enter provenance.
  try { assertSafeContainedPath(root, resolved); } catch { return null; }
  const stat = fs.lstatSync(resolved);
  if (!stat.isFile() || stat.isSymbolicLink()) return null;
  const body = fs.readFileSync(resolved);
  return { path: relativePath, sha256: sha(body), bytes: body.length, body };
}
function canonicalJson(value) {
  if (Array.isArray(value)) return value.map(canonicalJson);
  if (value && typeof value === 'object') return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonicalJson(value[key])]));
  return value;
}
function semanticProjection(value) {
  if (Array.isArray(value)) return value.map(semanticProjection);
  if (!value || typeof value !== 'object') return value;
  const volatile = new Set([
    'generated_at', 'generated_by', 'created_at', 'created_by',
    'updated_at', 'updated_by', 'duration', 'duration_ms', 'pid',
    'log_path', 'temporary_path', 'temp_path', 'timestamp', 'agent_id',
    'last_seen_at', 'last_seen_by', 'first_seen_at', 'first_seen_by',
    'last_scanned_at', 'last_changed_by', 'resolved_at', 'resolved_by',
    'detected_at', 'detected_by', 'observed_at', 'recorded_at',
    'attempt_started_at', 'published_at', 'collected_at'
  ]);
  return Object.fromEntries(Object.keys(value).sort().filter((key) => !volatile.has(key)).map((key) => [key, semanticProjection(value[key])]));
}
function semanticFile(root, relative) {
  const file = fileData(root, relative);
  if (!file?.body) return file;
  try {
    const parsed = JSON.parse(file.body.toString('utf8').replace(/^\uFEFF/, ''));
    return { ...file, semantic_sha256: sha(JSON.stringify(canonicalJson(semanticProjection(parsed)))), semantic_bytes: Buffer.byteLength(JSON.stringify(canonicalJson(semanticProjection(parsed))), 'utf8') };
  } catch { return { ...file, semantic_sha256: file.sha256, semantic_bytes: file.bytes }; }
}
function findFile(context, source) {
  const normalized = relPath(source);
  const candidates = [
    normalized,
    normalized.startsWith('.knowledge/') ? normalized.slice('.knowledge/'.length) : `.knowledge/${normalized}`
  ];
  for (const candidate of candidates) {
    for (const root of [context.targetRoot, context.projectKnowledgeRoot, context.stateRoot]) {
      const value = fileData(root, candidate);
      if (value) return { ...value, root: path.resolve(root) };
    }
  }
  return { path: normalized, sha256: null, bytes: 0, body: null, root: null };
}
function hashValue(pathName, value) {
  return { path: pathName, sha256: sha(value), bytes: Buffer.byteLength(JSON.stringify(value), 'utf8'), kind: 'derived' };
}
function canonicalScope(input, context) {
  const paths = uniqueSorted(asList(input.paths));
  const excludes = uniqueSorted(asList(input.excludePaths));
  if ([...paths, ...excludes].some((item) => !isSafeRelative(item))) {
    const error = new Error('Task scope paths must be safe relative paths.'); error.code = 'task_routing_invalid'; throw error;
  }
  const task = String(input.task || '').trim();
  const scopeSource = ['explicit', 'agent_plan', 'pr_diff', 'inferred', 'fallback_global'].includes(input.scopeSource)
    ? input.scopeSource : (task || input.modules || paths.length ? 'explicit' : 'fallback_global');
  const normalized = {
    repository_id: context.repoId,
    task,
    task_class: String(input.taskClass || 'general').trim() || 'general',
    modules: uniqueSorted(asList(input.modules)),
    paths,
    exclude_modules: uniqueSorted(asList(input.excludeModules)),
    exclude_paths: excludes,
    scope_source: scopeSource,
    constraints: uniqueSorted(asList(input.constraints))
  };
  return {
    schema_version: SCOPE_SCHEMA,
    ...normalized,
    created_at: input.createdAt || now(),
    created_by: input.createdBy || context.agentId || 'unknown',
    task_scope_hash: sha(normalized)
  };
}
function readRegistry(context) {
  const registrySource = readContainedJson(context, '.knowledge/modules/module_registry.json', 'curated', { allowFallback: false, maxBytes: 2 * 1024 * 1024 });
  const trustSource = readContainedJson(context, '.knowledge/maintenance/trust_report.json', 'runtime', { allowFallback: false, maxBytes: 2 * 1024 * 1024 });
  const registry = registrySource.available && !registrySource.error ? registrySource.value : { modules: [] };
  const trust = trustSource.available && !trustSource.error ? trustSource.value : {};
  const statuses = new Map((trust.module_statuses || []).map((item) => [item.module_id, item]));
  return (registry.modules || []).filter((item) => item && item.module_id).map((item) => ({
    ...item, path: relPath(item.path || ''), status: statuses.get(item.module_id) || {},
    registry_source: registrySource.file || null,
    trust_source: trustSource.file || null
  })).sort((a, b) => a.module_id.localeCompare(b.module_id));
}

function containedJsonValue(context, relative, policy, fallback = {}) {
  const source = readContainedJson(context, relative, policy, {
    allowFallback: false,
    maxBytes: 2 * 1024 * 1024
  });
  return source.available && !source.error ? source.value : fallback;
}
function dependenciesOf(moduleInfo) {
  return uniqueSorted([...(moduleInfo.dependencies || []), ...(moduleInfo.depends_on || [])]
    .map((item) => typeof item === 'string' ? item : item?.module_id || item?.id));
}
function normalizeSourceReference(value, defaults = {}) {
  const row = typeof value === 'string' ? { path: value } : (value || {});
  return {
    path: relPath(row.path),
    role: String(row.role || defaults.role || 'source'),
    required: row.required === undefined ? defaults.required === true : row.required === true,
    module_id: defaults.module_id || row.module_id || null
  };
}
function moduleSourceReferences(selected) {
  const merged = new Map();
  const add = (value, defaults) => {
    const row = normalizeSourceReference(value, defaults);
    if (!row.path) return;
    const prior = merged.get(row.path);
    if (!prior) merged.set(row.path, row);
    else merged.set(row.path, {
      ...prior,
      required: prior.required || row.required,
      roles: [...new Set([...(prior.roles || [prior.role]), row.role])].sort(),
      module_ids: [...new Set([...(prior.module_ids || [prior.module_id]), row.module_id].filter(Boolean))].sort()
    });
  };
  for (const item of selected) {
    const moduleId = item.module_id;
    if (item.moduleInfo.card) add(item.moduleInfo.card, {
      role: 'module_card', required: item.moduleInfo.card_required !== false, module_id: moduleId
    });
    for (const file of item.moduleInfo.key_files || []) add(file, { role: 'key_file', required: true, module_id: moduleId });
    for (const file of item.moduleInfo.evidence_files || []) add(file, { role: 'evidence', required: false, module_id: moduleId });
  }
  return [...merged.values()].sort((left, right) => left.path.localeCompare(right.path));
}
function sourcePathState(context, reference) {
  const sourcePath = relPath(reference.path);
  if (!isSafeRelative(sourcePath)) return { path_state: 'unsafe', sha256: null, bytes: 0, body: null };
  const gitRows = context.git?.changed_file_details || [];
  const gitRow = gitRows.find((row) => relPath(row.path) === sourcePath || relPath(row.original_path) === sourcePath) || null;
  if (gitRow?.status === 'deleted' || (gitRow?.status === 'renamed' && relPath(gitRow.original_path) === sourcePath)) {
    return { path_state: 'deleted', sha256: null, bytes: 0, body: null, git_status: gitRow.status };
  }
  const candidates = [
    [context.targetRoot, sourcePath],
    [context.projectKnowledgeRoot, sourcePath.replace(/^\.knowledge\//, '')],
    [context.stateRoot, sourcePath.replace(/^\.knowledge\//, '')]
  ];
  for (const [root, relative] of candidates) {
    const resolved = path.resolve(root, ...relative.split('/'));
    if (!containedPath(root, resolved)) continue;
    if (!fs.existsSync(resolved)) continue;
    try {
      assertSafeContainedPath(root, resolved);
      const stat = fs.lstatSync(resolved);
      if (!stat.isFile() || stat.isSymbolicLink()) return { path_state: 'unsafe', sha256: null, bytes: 0, body: null, git_status: gitRow?.status || null };
      const body = fs.readFileSync(resolved);
      return { path_state: 'present', sha256: sha(body), bytes: body.length, body, git_status: gitRow?.status || null };
    } catch (error) {
      return {
        path_state: error.code === 'EACCES' || error.code === 'EPERM' ? 'unreadable' : 'unsafe',
        sha256: null,
        bytes: 0,
        body: null,
        git_status: gitRow?.status || null
      };
    }
  }
  return { path_state: 'missing', sha256: null, bytes: 0, body: null, git_status: gitRow?.status || null };
}
function moduleTextMatch(moduleInfo, taskTerms) {
  const corpus = [moduleInfo.module_id, moduleInfo.name, moduleInfo.path, moduleInfo.purpose, moduleInfo.summary,
    ...(moduleInfo.keywords || []), ...(moduleInfo.tags || [])].join(' ').toLowerCase();
  return taskTerms.filter((term) => new RegExp(`(?:^|[^a-z0-9_-])${term.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(?:$|[^a-z0-9_-])`, 'i').test(corpus));
}
function moduleSelection(registry, scope) {
  const explicitIds = new Set(scope.modules);
  const scopePaths = scope.paths;
  const direct = new Set();
  const first = registry.filter((moduleInfo) => explicitIds.has(moduleInfo.module_id) ||
    scopePaths.some((prefix) => pathWithin(moduleInfo.path, prefix)));
  for (const moduleInfo of first) for (const dependency of dependenciesOf(moduleInfo)) direct.add(dependency);
  const taskTerms = tokens(scope.task);
  const explicitBoundary = scope.modules.length > 0 || scope.paths.length > 0;
  return registry.map((moduleInfo) => {
    const explicit = explicitIds.has(moduleInfo.module_id);
    const pathMatch = scopePaths.some((prefix) => pathWithin(moduleInfo.path, prefix));
    const directDependency = direct.has(moduleInfo.module_id);
    const matched = explicitBoundary ? [] : moduleTextMatch(moduleInfo, taskTerms);
    const excluded = scope.exclude_modules.includes(moduleInfo.module_id) ||
      scope.exclude_paths.some((prefix) => pathWithin(moduleInfo.path, prefix));
    const relevant = !excluded && (explicit || pathMatch || directDependency || (!explicitBoundary && matched.length > 0));
    return {
      moduleInfo, module_id: moduleInfo.module_id, path: moduleInfo.path,
      explicit, pathMatch, direct_dependency: directDependency, matched, excluded, relevant,
      score: (explicit ? 1000 : 0) + (pathMatch ? 900 : 0) + (directDependency ? 100 : 0) + matched.length * 10
    };
  }).sort((a, b) => b.score - a.score || a.module_id.localeCompare(b.module_id));
}
function relevantPathCandidates(context, scope, selected, mode) {
  const freshness = containedJsonValue(context, '.knowledge/freshness.json', 'runtime', { tracked_files: [] });
  const selectedPaths = selected.map((item) => item.path).filter(Boolean);
  const supported = new Set([
    'modified', 'added', 'deleted', 'renamed', 'copied', 'untracked', 'conflicted',
    'missing', 'unsafe', 'unreadable', 'stale', 'suspect', 'needs_recheck',
    'low_confidence', 'required', 'explicit', 'changed'
  ]);
  const rank = new Map([
    ['explicit', 0], ['required', 1], ['modified', 2], ['added', 2], ['renamed', 2], ['copied', 2],
    ['changed', 2], ['untracked', 2], ['stale', 3], ['low_confidence', 4], ['needs_recheck', 5],
    ['suspect', 6], ['missing', 7], ['deleted', 8], ['unreadable', 9], ['unsafe', 10], ['conflicted', 11]
  ]);
  const rows = [];
  const add = (value, fallbackStatus, source) => {
    const pathValue = relPath(typeof value === 'string' ? value : value?.path);
    const gitStatus = typeof value === 'string' ? null : value?.git_status || null;
    const status = String(typeof value === 'string' ? fallbackStatus : value?.status || fallbackStatus || 'changed').toLowerCase();
    if (pathValue && isSafeRelative(pathValue) && supported.has(status)) rows.push({ path: pathValue, status, source, git_status: gitStatus });
  };
  for (const item of freshness.tracked_files || []) add(item, 'stale', 'freshness');
  for (const item of context.git?.changed_file_details || context.git?.changed_files || []) {
    const gitStatus = String(typeof item === 'string' ? 'modified' : item?.status || 'modified').toLowerCase();
    add(typeof item === 'string' ? item : { path: item.path, status: gitStatus, git_status: gitStatus },
      gitStatus, gitStatus === 'untracked' ? 'git_untracked' : 'git_diff');
    if (typeof item !== 'string' && item.original_path && ['renamed', 'deleted'].includes(gitStatus)) {
      add({ path: item.original_path, status: 'deleted', git_status: gitStatus }, 'deleted', 'git_diff_original');
    }
  }
  for (const item of context.git?.pr_changed_files || []) add(item, 'changed', 'pr_diff');
  for (const item of context.pr?.changed_files || context.prDiff?.changed_files || []) add(item, 'changed', 'pr_diff');
  for (const scopePath of scope.paths) {
    if (findFile(context, scopePath).body) add(scopePath, 'explicit', 'explicit_scope');
  }
  for (const reference of moduleSourceReferences(selected)) {
    if (!reference.required) continue;
    const state = sourcePathState(context, reference);
    add({
      path: reference.path,
      status: state.path_state === 'present' ? 'required' : state.path_state,
      git_status: state.git_status
    }, 'required', reference.role === 'key_file' ? 'required_key_file' : 'required_module_source');
  }
  const merged = new Map();
  for (const row of rows) {
    const prior = merged.get(row.path) || { ...row, provenance: [] };
    prior.provenance = [...new Set([...prior.provenance, row.source])].sort();
    if (row.git_status) prior.git_status = row.git_status;
    if ((rank.get(row.status) || 0) > (rank.get(prior.status) || 0)) prior.status = row.status;
    merged.set(row.path, prior);
  }
  const priority = (item) => item.provenance.some((source) => source.startsWith('required_')) ? 0 : HIGH_RISK_PATH_STATUSES.has(item.status) ? 1 : 2;
  const all = [...merged.values()].sort((a, b) => priority(a) - priority(b) || a.path.localeCompare(b.path));
  const relevantAll = all.filter((item) =>
    scope.paths.some((prefix) => pathWithin(item.path, prefix)) || selectedPaths.some((prefix) => pathWithin(item.path, prefix))
  ).sort((a, b) => priority(a) - priority(b) || a.path.localeCompare(b.path));
  const cap = PATH_BUDGETS[mode] || PATH_BUDGETS.compact;
  const included = relevantAll.slice(0, cap);
  const overflow = relevantAll.slice(cap);
  const continuation = overflow.filter((item) => HIGH_RISK_PATH_STATUSES.has(item.status));
  const omitted = overflow.filter((item) => !HIGH_RISK_PATH_STATUSES.has(item.status))
    .map((item) => ({ ...item, reason: 'task_path_budget_exhausted', high_risk: false }));
  return {
    total: all.length,
    relevant_total: relevantAll.length,
    all_relevant: relevantAll,
    relevant: included,
    omitted,
    included_high_risk: included.filter((item) => HIGH_RISK_PATH_STATUSES.has(item.status)),
    omitted_high_risk: [],
    continuation_high_risk: continuation,
    unrelated: Math.max(0, all.length - relevantAll.length),
    budget: cap,
    budget_escalated_for_high_risk: continuation.length > 0
  };
}
function policyPointers(context) {
  const project = containedJsonValue(context, '.knowledge/project_index.json', 'curated', {});
  const concurrency = containedJsonValue(context, '.knowledge/maintenance/concurrency_policy.json', 'curated', {});
  const trust = containedJsonValue(context, '.knowledge/maintenance/trust_report.json', 'runtime', {});
  const rows = {
    source_of_truth: {
      path: '.knowledge/project_index.json',
      projection: {
        primary_source_of_truth: project.primary_source_of_truth || 'code',
        code_is_source_of_truth: true,
        tests_beat_prose: true
      }
    },
    concurrency: {
      path: '.knowledge/maintenance/concurrency_policy.json',
      projection: {
        mode: concurrency.mode || 'unknown',
        atomic_writes: concurrency.write_policy?.atomic_writes === true,
        lock_path: concurrency.write_policy?.lock_path || '.knowledge/locks/v1/task-routing.lock',
        merge_policy: semanticProjection(concurrency.merge_policy || {})
      }
    },
    safety: {
      path: '.knowledge/maintenance/trust_report.json',
      projection: { concurrency_mode: trust.concurrency_mode || concurrency.mode || 'unknown' }
    }
  };
  return Object.fromEntries(Object.entries(rows).map(([id, row]) => [id, {
    path: row.path,
    semantic_sha256: sha(canonicalJson(row.projection))
  }]));
}
function workspaceIdentity(context) {
  const project = containedJsonValue(context, '.knowledge/project_index.json', 'curated', {});
  return String(context.workspaceId || project.workspace_id || project.workspace?.id || sha(path.resolve(context.targetRoot)));
}
function canonicalBaseline(context, scope) {
  return buildWorkspaceBaseline({
    ...context,
    workspaceId: workspaceIdentity(context),
    repoId: context.repoId
  });
}
function requiredBaseline(context, scope = null) {
  return canonicalBaseline(context, scope);
}
function diagnoseCustomBaseline(file) {
  let parsed = null;
  let readable = false;
  try {
    parsed = JSON.parse(fs.readFileSync(path.resolve(file), 'utf8').replace(/^\uFEFF/, ''));
    readable = Boolean(parsed && typeof parsed === 'object' && !Array.isArray(parsed));
  } catch {}
  return {
    status: readable ? 'diagnostic' : 'diagnostic_invalid',
    schema_version: 'knowledge-routing-custom-baseline-diagnostic.v1',
    source_path: path.resolve(file),
    source_sha256: fs.existsSync(path.resolve(file)) ? sha(fs.readFileSync(path.resolve(file))) : null,
    source_schema_version: parsed?.schema_version || null,
    claim_eligible: false,
    claim_ineligible_reason: 'custom_baseline_not_claim_eligible',
    affects_production_comparison: false
  };
}
function safetyInputs(context, registry, scope) {
  const trust = containedJsonValue(context, '.knowledge/maintenance/trust_report.json', 'runtime', {});
  const wikiLint = containedJsonValue(context, '.knowledge/maintenance/wiki_lint_report.json', 'runtime', {});
  const wikiGraph = containedJsonValue(context, '.knowledge/maps/wiki_graph.json', 'runtime', {});
  const quality = containedJsonValue(context, '.knowledge/maintenance/quality_report.json', 'runtime', {});
  const repairQueue = containedJsonValue(context, '.knowledge/maintenance/repair_queue.json', 'runtime', { queue: [] });
  const criticalPaths = containedJsonValue(context, '.knowledge/maps/critical_paths.json', 'runtime', { paths: [] });
  const freshness = containedJsonValue(context, '.knowledge/freshness.json', 'runtime', { tracked_files: [] });
  const projectIndex = containedJsonValue(context, '.knowledge/project_index.json', 'curated', {});
  const changedFiles = (context.git?.changed_files || []).filter((item) => !String(item).startsWith('.knowledge/'));
  const routing = buildRoutingDecision({
    task: scope.task,
    registry: { modules: registry },
    trustReport: trust,
    wikiLint, wikiGraph, quality, repairQueue, criticalPaths, freshness,
    taskRouting: projectIndex.task_routing || [], changedFiles,
    contextBudgetBytes: 64 * 1024
  });
  return { trust, wikiLint, wikiGraph, quality, repairQueue, criticalPaths, freshness, projectIndex, routing };
}
function taskSafetyState(safety, selected, changed, requiredSourceIssues = []) {
  const selectedIds = new Set(selected.map((item) => item.module_id));
  const candidates = safety.routing.candidate_modules || [];
  const relevant = candidates.filter((item) => selectedIds.has(item.module_id));
  const directContradictions = (safety.quality.contradictions || safety.quality.issues || [])
    .filter((item) => !['closed', 'resolved', 'done'].includes(String(item.status || 'open').toLowerCase()))
    .filter((item) => selectedIds.has(item.module_id));
  const outside = candidates.filter((item) => !selectedIds.has(item.module_id) && item.high_risk)
    .map((item) => ({ module_id: item.module_id, flags: item.flags, relation: 'workspace_only', reason: 'outside_explicit_scope_boundary' }));
  const blockers = [];
  if (safety.routing.wiki_status === 'structurally_broken') blockers.push('structurally_broken_graph');
  if (relevant.some((item) => item.flags?.contradiction) || directContradictions.length) blockers.push('relevant_contradiction');
  if (relevant.some((item) => item.flags?.suspect || item.flags?.low_confidence)) blockers.push('relevant_untrusted_module');
  if (relevant.some((item) => item.flags?.critical_path)) blockers.push('relevant_critical_path');
  if (changed.included_high_risk.length) blockers.push('relevant_high_risk_path');
  if (changed.continuation_high_risk.length) blockers.push('required_high_risk_continuation');
  if (requiredSourceIssues.length) blockers.push('required_source_unavailable');
  return {
    structural_global_blocker: safety.routing.wiki_status === 'structurally_broken',
    relevant_blockers: [...new Set(blockers)],
    workspace_notices: outside,
    relevant_candidates: relevant.map((item) => ({ module_id: item.module_id, flags: item.flags })),
    relevant_contradictions: directContradictions.map((item) => item.id || item.path || item.module_id),
    continuation_required: changed.continuation_high_risk.length > 0,
    required_sources_complete: requiredSourceIssues.length === 0,
    required_source_issues: requiredSourceIssues
  };
}
function taskSafetySnapshot(taskSafety) {
  return {
    structural_global_blocker: taskSafety.structural_global_blocker === true,
    relevant_blockers: [...new Set(taskSafety.relevant_blockers || [])].sort(),
    relevant_candidates: (taskSafety.relevant_candidates || []).map((item) => ({
      module_id: item.module_id,
      flags: semanticProjection(item.flags || {})
    })).sort((a, b) => String(a.module_id).localeCompare(String(b.module_id))),
    relevant_contradictions: [...new Set(taskSafety.relevant_contradictions || [])].sort(),
    continuation_required: taskSafety.continuation_required === true,
    required_sources_complete: taskSafety.required_sources_complete === true,
    required_source_issues: (taskSafety.required_source_issues || []).map(semanticProjection)
      .sort((a, b) => String(a.path || '').localeCompare(String(b.path || '')))
  };
}
function subsetForSnapshot(value, selectedIds, pathPrefixes) {
  const selected = new Set(selectedIds);
  const matches = (row) => selected.has(row?.module_id) ||
    pathPrefixes.some((prefix) => row?.path && pathWithin(row.path, prefix)) ||
    pathPrefixes.some((prefix) => row?.artifact && pathWithin(row.artifact, prefix));
  if (Array.isArray(value)) return value.filter(matches);
  return value;
}
function collectSourceReceipts(context, selected, changed) {
  const declared = moduleSourceReferences(selected);
  const merged = new Map(declared.map((row) => [row.path, row]));
  for (const changedPath of changed.all_relevant) {
    if (!merged.has(changedPath.path)) merged.set(changedPath.path, {
      path: changedPath.path,
      role: 'task_relevant_change',
      required: false,
      module_id: null
    });
  }
  return [...merged.values()].sort((left, right) => left.path.localeCompare(right.path)).map((reference) => {
    const state = sourcePathState(context, reference);
    return {
      path: reference.path,
      sha256: state.sha256,
      bytes: state.bytes,
      kind: 'source',
      role: reference.role,
      roles: reference.roles || [reference.role],
      required: reference.required === true,
      module_id: reference.module_id,
      module_ids: reference.module_ids || (reference.module_id ? [reference.module_id] : []),
      path_state: state.path_state,
      git_status: state.git_status || null
    };
  });
}
function sourceReceipt(context, scope, selected, changed, safety, baseline, taskSafety, sourceFiles = null) {
  const selectedIds = selected.map((item) => item.module_id);
  const selectedPaths = selected.map((item) => item.path).filter(Boolean);
  const receipts = sourceFiles || collectSourceReceipts(context, selected, changed);
  const registrySubset = selected.map((item) => item.moduleInfo)
    .filter((item) => selectedIds.includes(item.module_id));
  const trustSubset = subsetForSnapshot(safety.trust.module_statuses || [], selectedIds, selectedPaths);
  const criticalSubset = (safety.criticalPaths.paths || []).filter((item) => (item.modules || []).some((id) => selectedIds.includes(id)));
  const repairSubset = subsetForSnapshot(safety.repairQueue.queue || safety.repairQueue.items || [], selectedIds, selectedPaths);
  const contradictionSubset = subsetForSnapshot(safety.quality.contradictions || safety.quality.issues || [], selectedIds, selectedPaths);
  const freshnessSubset = changed.all_relevant;
  return [
    ...receipts,
    hashValue('inputs/module_registry[selected]', semanticProjection(registrySubset)),
    hashValue('inputs/trust_report[selected]', semanticProjection(trustSubset)),
    hashValue('inputs/critical_paths[selected]', semanticProjection(criticalSubset)),
    hashValue('inputs/repair_queue[selected]', semanticProjection(repairSubset)),
    hashValue('inputs/contradictions[selected]', semanticProjection(contradictionSubset)),
    hashValue('inputs/freshness[selected]', semanticProjection(freshnessSubset)),
    hashValue('inputs/wiki_structural_status', normalizeWikiStatus(safety.wikiLint, safety.wikiGraph)),
    hashValue('inputs/task_safety', taskSafety),
    hashValue('inputs/adaptive_safety', {
      mode: safety.routing.mode,
      reason: safety.routing.reason,
      wiki_status: safety.routing.wiki_status,
      task_safety: taskSafety
    }),
    hashValue('inputs/routing_output', {
      mode: safety.routing.mode,
      reason: safety.routing.reason,
      wiki_status: safety.routing.wiki_status
    }),
    hashValue('inputs/metrics_policy', {
      estimator_method: 'workspace_to_task_first_read_bytes_divided_by_four.v1',
      baseline_method: `${BASELINE_GENERATOR}:${BASELINE_RECIPE}`,
      claim_contract: 'workspace_narrowing_ready_complete_consistent.v1'
    }),
    hashValue('inputs/policy_pointers', policyPointers(context))
  ].sort((a, b) => a.path.localeCompare(b.path));
}
function estimateFiles(files) {
  return files.reduce((sum, item) => sum + Math.ceil(Number(item.bytes || 0) / 4), 0);
}
function workspaceCandidatePaths(registry, context) {
  return uniqueSorted([
    ...registry.flatMap((moduleInfo) => [
      moduleInfo.card,
      ...(moduleInfo.key_files || []).map((item) => typeof item === 'string' ? item : item?.path),
      ...(moduleInfo.evidence_files || []).map((item) => typeof item === 'string' ? item : item?.path)
    ]),
    ...(context.git?.changed_file_details || []).map((item) => item.path),
    ...(context.git?.pr_changed_files || []).map((item) => typeof item === 'string' ? item : item?.path)
  ]);
}
function taskReadiness(scope, selected, taskSafety) {
  if (!scope.task || !selected.length) return 'needs_explicit_scope';
  if (taskSafety.structural_global_blocker) return 'needs_structural_repair';
  if (!taskSafety.required_sources_complete) return 'needs_required_sources';
  if (taskSafety.continuation_required) return 'requires_high_risk_continuation';
  if (taskSafety.relevant_blockers.length) return 'needs_safety_review';
  return 'ready';
}
function buildSnapshot(context, scope) {
  const registry = readRegistry(context);
  const candidates = moduleSelection(registry, scope);
  const selected = candidates.filter((item) => item.relevant && !item.excluded);
  const safety = safetyInputs(context, registry, scope);
  const changed = relevantPathCandidates(context, scope, selected, safety.routing.mode);
  const baseline = requiredBaseline(context, scope);
  const sourceFiles = collectSourceReceipts(context, selected, changed);
  const requiredSourceIssues = sourceFiles.filter((item) => item.required && item.path_state !== 'present')
    .map((item) => ({ path: item.path, role: item.role, module_id: item.module_id, path_state: item.path_state, git_status: item.git_status }));
  const taskSafety = taskSafetyState(safety, selected, changed, requiredSourceIssues);
  const immutableTaskSafety = taskSafetySnapshot(taskSafety);
  const read_set = sourceReceipt(context, scope, selected, changed, safety, baseline, immutableTaskSafety, sourceFiles);
  const snapshot_hash = sha({
    task_scope_hash: scope.task_scope_hash,
    read_set,
    policy: policyPointers(context),
    implementation: IMPLEMENTATION_VERSION,
    system: systemVersion()
  });
  const safetyOverrides = immutableTaskSafety.relevant_blockers;
  const readiness = taskReadiness(scope, selected, taskSafety);
  const continuation = {
    schema_version: 'knowledge-task-routing-continuation.v1',
    task_scope_hash: scope.task_scope_hash,
    snapshot_hash,
    required: taskSafety.continuation_required,
    status: taskSafety.continuation_required ? 'required_before_ready_or_claim' : 'not_required',
    paths: changed.continuation_high_risk,
    inaccessible_paths: changed.continuation_high_risk.filter((item) => !findFile(context, item.path).body).map((item) => item.path),
    next_action: taskSafety.continuation_required
      ? 'Read routing continuation.json and resolve every listed high-risk path before treating this route as ready.'
      : null
  };
  const readFirst = uniqueSorted([
    ...selected.flatMap((item) => item.moduleInfo.key_files || []),
    ...changed.relevant.map((item) => item.path)
  ]);
  const firstReadLines = [
    '# Task routing first read', '', `Task: ${scope.task || '(no explicit task)'}`,
    `Scope: modules=${scope.modules.join(',') || '-'}; paths=${scope.paths.join(',') || '-'}`,
    `Task readiness: ${readiness}`,
    `Routing mode: ${safety.routing.mode} (${safety.routing.reason})`,
    `Selected modules: ${selected.map((item) => item.module_id).join(', ') || '(none)'}`,
    `Read first: ${readFirst.join(', ') || 'create explicit scope'}`,
    `Relevant changed/stale paths included: ${changed.relevant.length}/${changed.relevant_total}; unrelated workspace paths are excluded by the scope boundary.`,
    continuation.required ? `Required continuation: continuation.json (${continuation.paths.length} high-risk paths)` : 'Required continuation: none',
    requiredSourceIssues.length
      ? `Required source issues: ${requiredSourceIssues.map((item) => `${item.path} (${item.path_state})`).join(', ')}`
      : 'Required source issues: none',
    `Safety overrides: ${safetyOverrides.join(', ') || 'none'}`,
    'Workspace-wide maintenance debt is separate: maintenance/maintenance_debt.json.'
  ].join('\n') + '\n';
  const baselineInputs = [
    ...((baseline.measurement?.files || []).map((item) => ({ ...item, required: true })))
  ];
  const routingInputs = [
    { path: 'first-read.md', sha256: sha(firstReadLines), bytes: Buffer.byteLength(firstReadLines, 'utf8') },
    { path: 'continuation.json', sha256: sha(JSON.stringify(continuation)), bytes: Buffer.byteLength(JSON.stringify(continuation), 'utf8') },
    ...read_set.filter((item) => item.kind === 'source').map((item) => ({ path: item.path, sha256: item.sha256, bytes: item.bytes }))
  ];
  // Overflow high-risk paths are mandatory continuation context. Keep their
  // accounting explicit even though their source receipts are also preserved
  // in immutable provenance.
  const continuationInputs = continuation.paths.map((item) => {
    const file = findFile(context, item.path);
    return { path: item.path, sha256: file.sha256, bytes: file.bytes, available: Boolean(file.body) };
  });
  const mandatoryContinuationTokens = estimateFiles(continuationInputs);
  const inlineRoutingTokens = Math.max(0, estimateFiles(routingInputs) - mandatoryContinuationTokens);
  const baselineTokens = estimateFiles(baselineInputs);
  const routingTokens = inlineRoutingTokens + mandatoryContinuationTokens;
  const taskScopeExplicit = scope.scope_source === 'explicit' && (scope.modules.length > 0 || scope.paths.length > 0);
  const comparisonContractValid = baseline.complete && baseline.comparison_contract_valid !== false && baselineTokens > 0;
  const claimReasons = [];
  if (!taskScopeExplicit) claimReasons.push('requires_explicit_frozen_scope');
  if (!baseline.complete) claimReasons.push(...(baseline.reasons || [baseline.reason || 'workspace_baseline_incomplete']));
  for (const issue of requiredSourceIssues) claimReasons.push(`required_source_${issue.path_state}`);
  if (readiness !== 'ready') claimReasons.push(`task_readiness_${readiness}`);
  if (continuation.required) claimReasons.push('required_high_risk_continuation_unresolved');
  if (continuation.inaccessible_paths.length) claimReasons.push('inaccessible_high_risk_context');
  const estimatorMethod = 'workspace_to_task_first_read_bytes_divided_by_four';
  const estimatorVersion = 'v1';
  const comparisonPolicyVersion = 'workspace_narrowing_claim_policy.v1';
  const metricsComparisonHash = sha({
    schema_version: COMPARISON_SCHEMA,
    comparison_kind: COMPARISON_KIND,
    workspace_baseline_hash: baseline.baseline_hash,
    task_routing_snapshot_hash: snapshot_hash,
    estimator_method: estimatorMethod,
    estimator_version: estimatorVersion,
    comparison_policy_version: comparisonPolicyVersion,
    mandatory_continuation_hashes: continuation.required ? [sha(JSON.stringify(continuation))] : []
  });
  const delta = baselineTokens - routingTokens;
  const assessment = comparisonContractValid
    ? (delta > 0 ? 'estimated_narrowing' : delta < 0 ? 'estimated_overhead' : 'neutral')
    : 'not_comparable';
  const allWorkspacePaths = workspaceCandidatePaths(registry, context);
  const selectedTaskPaths = uniqueSorted(sourceFiles.map((item) => item.path));
  const taskPathSet = new Set(selectedTaskPaths);
  const workspacePathsTotal = allWorkspacePaths.length;
  const taskPathsSelected = selectedTaskPaths.length;
  const unrelatedPathsExcluded = allWorkspacePaths.filter((item) => !taskPathSet.has(item)).length;
  const workspaceNarrowing = {
    modules_total: candidates.length,
    modules_selected: selected.length,
    modules_excluded: candidates.length - selected.length,
    workspace_candidate_paths_total: workspacePathsTotal,
    task_paths_selected: taskPathsSelected,
    unrelated_paths_excluded: unrelatedPathsExcluded,
    relevant_high_risk_paths_inline: changed.included_high_risk.length,
    relevant_high_risk_paths_continued: changed.continuation_high_risk.length,
    inaccessible_relevant_high_risk_paths: requiredSourceIssues.filter((item) => ['missing', 'deleted', 'unsafe', 'unreadable'].includes(item.path_state)).length,
    relevant_high_risk_paths_omitted: 0,
    // Backward-compatible aliases; these are structural counts, never token savings.
    paths_total: workspacePathsTotal,
    paths_relevant: changed.relevant_total,
    paths_selected: taskPathsSelected,
    relevant_paths_omitted_by_budget: changed.omitted.length,
    relevant_high_risk_paths_in_continuation: changed.continuation_high_risk.length
  };
  const immutableClaimEligible = comparisonContractValid && taskScopeExplicit && readiness === 'ready' &&
    requiredSourceIssues.length === 0 && continuation.required !== true && continuation.inaccessible_paths.length === 0;
  const metrics = {
    schema_version: COMPARISON_SCHEMA,
    comparison_kind: COMPARISON_KIND,
    measurement_kind: 'estimated_local_first_read_context',
    comparison_contract_valid: comparisonContractValid,
    workspace_baseline_complete: baseline.complete,
    task_scope_explicit: taskScopeExplicit,
    task_route_current: true,
    // Deprecated: workspace and task scopes are intentionally different.
    scope_comparable: false,
    scope_comparable_deprecated: true,
    baseline_complete: baseline.complete,
    baseline_incomplete_reason: baseline.reason,
    claim_eligible: immutableClaimEligible && claimReasons.length === 0,
    claim_ineligible_reason: claimReasons[0] || null,
    claim_ineligible_reasons: [...new Set(claimReasons.filter(Boolean))],
    claim_requires_current_pointer: true,
    estimator_method: estimatorMethod,
    estimator_version: estimatorVersion,
    comparison_policy_version: comparisonPolicyVersion,
    estimator_limits: 'Local byte-based estimate only; not tokenizer or provider telemetry.',
    estimator_interpretation: 'Estimated workspace-to-task first-read narrowing. This is a deterministic local context estimate, not actual provider-reported model-token usage.',
    scope_hash: scope.task_scope_hash, snapshot_hash, routing_snapshot_hash: snapshot_hash,
    baseline_hash: baseline.baseline_hash, metrics_comparison_hash: metricsComparisonHash,
    comparison_receipt: {
      schema_version: 'knowledge-workspace-narrowing-comparison-receipt.v1', task_scope_hash: scope.task_scope_hash,
      baseline_complete: baseline.complete, baseline_incomplete_reason: baseline.reason,
      baseline_inputs: baselineInputs, routing_inputs: routingInputs, metrics_comparison_hash: metricsComparisonHash,
      required_source_states: sourceFiles.filter((item) => item.required).map((item) => ({ path: item.path, path_state: item.path_state }))
    },
    workspace_baseline: {
      recipe_id: BASELINE_RECIPE_ID,
      recipe_version: BASELINE_RECIPE_VERSION,
      baseline_hash: baseline.baseline_hash,
      complete: baseline.complete,
      estimated_tokens: baselineTokens
    },
    task_context: {
      task_scope_hash: scope.task_scope_hash,
      routing_snapshot_hash: snapshot_hash,
      estimated_tokens: routingTokens
    },
    baseline: { method: `${BASELINE_GENERATOR}:${BASELINE_RECIPE}`, recipe_id: BASELINE_RECIPE_ID, recipe_version: BASELINE_RECIPE_VERSION, schema_version: baseline.measurement?.schema_version || null, baseline_hash: baseline.baseline_hash, canonical_payload_hash: baseline.measurement?.payload_hash || null, estimated_tokens: baselineTokens },
    routing: { method: 'task_scoped_first_read.v1', estimated_tokens: routingTokens },
    inline_estimated_tokens: inlineRoutingTokens,
    mandatory_continuation_estimated_tokens: mandatoryContinuationTokens,
    routing_total_estimated_tokens: routingTokens,
    mandatory_continuations_complete: continuation.required !== true && continuationInputs.every((item) => item.available),
    mandatory_continuation_payloads: continuationInputs,
    required_sources_complete: requiredSourceIssues.length === 0,
    required_source_issues: requiredSourceIssues,
    relevant_git_diff_accounted: true,
    signed_delta_tokens: delta,
    signed_delta_percent: baselineTokens ? Math.round((delta / baselineTokens) * 10000) / 100 : null,
    estimated_tokens_saved: Math.max(0, delta),
    estimated_percent_saved: Math.max(0, baselineTokens ? Math.round((delta / baselineTokens) * 10000) / 100 : 0),
    estimated_tokens_overhead: Math.max(0, -delta),
    estimated_percent_overhead: Math.max(0, baselineTokens ? Math.round((-delta / baselineTokens) * 10000) / 100 : 0),
    assessment,
    actual_model_usage: { available: false, reason: 'no_provider_telemetry' },
    workspace_narrowing: workspaceNarrowing
  };
  const decision = {
    schema_version: SNAPSHOT_SCHEMA, task_scope_hash: scope.task_scope_hash, snapshot_hash,
    routing_mode: safety.routing.mode, routing_reason: safety.routing.reason, wiki_status: safety.routing.wiki_status,
    candidates: candidates.filter((item) => item.relevant || item.excluded || scope.exclude_modules.includes(item.module_id)).map((item) => ({
      module_id: item.module_id, score: item.score, selected: selected.some((chosen) => chosen.module_id === item.module_id),
      inclusion_reason: item.explicit ? 'explicit_scope' : item.pathMatch ? 'path_scope' : item.direct_dependency ? 'direct_dependency' : item.matched.length ? 'task_relevance' : null,
      exclusion_reason: item.excluded ? 'explicit_exclusion' : item.relevant ? null : 'not_task_relevant',
      matched_task_terms: item.matched, explicit_scope_match: item.explicit, path_scope_match: item.pathMatch,
      direct_dependency: item.direct_dependency,
      suspect_or_low_confidence: ['suspect', 'needs_recheck', 'low_confidence'].includes(String(item.moduleInfo.status?.trust_status || '').toLowerCase())
    })),
    safety_overrides: safetyOverrides,
    safety_findings_outside_scope: [],
    workspace_safety_notice: { details: 'maintenance/maintenance_debt.json', included_in_task_snapshot: false },
    task_safety: immutableTaskSafety,
    truncation: {
      reason: changed.omitted.length ? 'task_path_budget_exhausted' : 'not_truncated',
      path_budget: changed.budget,
      omitted_relevant_paths: changed.omitted,
      omitted_relevant_high_risk_paths: [],
      high_risk_continuation: {
        required: continuation.required,
        path: 'continuation.json',
        paths_total: continuation.paths.length,
        inaccessible_paths: continuation.inaccessible_paths
      }
    },
    provenance: {
      implementation_version: IMPLEMENTATION_VERSION,
      read_set,
      policies: policyPointers(context),
      snapshot_identity_excludes: ['git_head_sha'],
      current_state_contract: 'routing/tasks/<task_scope_hash>/current.json is canonical; manifest and index are rebuildable projections.'
    }
  };
  const repairRows = safety.repairQueue.queue || safety.repairQueue.items || [];
  const repairTouchesSelected = (item) => selected.some((chosen) =>
    item?.module_id === chosen.module_id || (item?.path && pathWithin(item.path, chosen.path)) ||
    (item?.artifact && pathWithin(item.artifact, chosen.path))
  );
  const bundle = {
    schema_version: SNAPSHOT_SCHEMA, task_scope_hash: scope.task_scope_hash, snapshot_hash,
    task: scope.task, task_class: scope.task_class, scope_source: scope.scope_source,
    selected_modules: selected.map((item) => item.module_id), relevant_changed_or_stale_paths: changed.relevant,
    workspace_debt: {
      details: 'maintenance/maintenance_debt.json',
      relevant_to_current_task: repairRows.filter(repairTouchesSelected).length,
      unrelated_debt_is_dynamic: true
    },
    high_risk_continuation: {
      required: continuation.required,
      path: 'continuation.json',
      paths_total: continuation.paths.length,
      inaccessible_paths: continuation.inaccessible_paths
    },
    required_sources: {
      complete: requiredSourceIssues.length === 0,
      sources: sourceFiles.filter((item) => item.required).map((item) => ({
        path: item.path,
        role: item.role,
        module_id: item.module_id,
        path_state: item.path_state,
        git_status: item.git_status
      })),
      issues: requiredSourceIssues
    },
    task_readiness: readiness, policies: policyPointers(context),
    safety: {
      wiki_status: safety.routing.wiki_status,
      safety_overrides: safetyOverrides,
      outside_scope_findings: null,
      workspace_only_notices: [],
      workspace_notice_pointer: 'maintenance/maintenance_debt.json',
      relevant_blockers: immutableTaskSafety.relevant_blockers
    }
  };
  const live_input_digest = sha({
    task_scope_hash: scope.task_scope_hash,
    routing_snapshot_hash: snapshot_hash,
    baseline_hash: baseline.baseline_hash,
    metrics_comparison_hash: metricsComparisonHash,
    readiness,
    continuation: sha(canonicalJson(continuation))
  });
  metrics.live_input_digest = live_input_digest;
  return { snapshot_hash, routing_snapshot_hash: snapshot_hash, baseline, scope, bundle, decision, metrics, continuation, live_input_digest, firstRead: firstReadLines };
}
function taskRoot(context, taskHash) { return path.join(context.stateRoot, 'routing', 'tasks', taskHash); }
function canonicalHash(value, label) {
  if (!/^[a-f0-9]{64}$/.test(String(value || ''))) {
    const error = new Error(`${label} must be a canonical SHA-256 hash.`); error.code = 'task_routing_invalid'; throw error;
  }
  return value;
}
function snapshotRoot(context, taskHash, snapshotHash) {
  return path.join(taskRoot(context, canonicalHash(taskHash, 'task id')), 'snapshots', canonicalHash(snapshotHash, 'snapshot id'));
}
function workspaceBaselineRoot(context, baselineHash) {
  return path.join(context.stateRoot, 'routing', 'workspace-baselines', canonicalHash(baselineHash, 'baseline id'));
}
function baselineRoot(context, taskHash, baselineHash = null) {
  const resolvedHash = baselineHash || taskHash;
  const globalRoot = workspaceBaselineRoot(context, resolvedHash);
  if (!baselineHash || fs.existsSync(globalRoot)) return globalRoot;
  // Read-only migration compatibility for RC4-R6 task-local baseline evidence.
  return path.join(taskRoot(context, canonicalHash(taskHash, 'task id')), 'baselines', canonicalHash(resolvedHash, 'baseline id'));
}
function comparisonRoot(context, taskHash, comparisonHash) {
  return path.join(taskRoot(context, canonicalHash(taskHash, 'task id')), 'comparisons', canonicalHash(comparisonHash, 'comparison id'));
}
function immutableArtifactComplete(root, completeSchema, requiredFile) {
  const complete = safeRead(path.join(root, 'complete.json'), null);
  const full = path.join(root, requiredFile);
  return Boolean(complete && complete.schema_version === completeSchema &&
    /^[a-f0-9]{64}$/.test(String(complete.files?.[requiredFile] || '')) &&
    fs.existsSync(full) && fs.lstatSync(full).isFile() && !fs.lstatSync(full).isSymbolicLink() &&
    sha(fs.readFileSync(full)) === complete.files[requiredFile]);
}
function baselineComplete(context, root) {
  return immutableArtifactComplete(root, BASELINE_COMPLETE_SCHEMA, 'baseline.json');
}
function comparisonComplete(context, root) {
  return immutableArtifactComplete(root, COMPARISON_COMPLETE_SCHEMA, 'metrics.json');
}
function snapshotComplete(context, root) {
  const completePath = path.join(root, 'complete.json');
  const complete = safeRead(completePath, null);
  if (!complete || complete.schema_version !== COMPLETE_SCHEMA || !complete.files || typeof complete.files !== 'object') return false;
  for (const name of REQUIRED_SNAPSHOT_FILES) {
    const expected = complete.files[name]; const full = path.join(root, name);
    if (!/^[a-f0-9]{64}$/.test(String(expected || '')) || !fs.existsSync(full)) return false;
    const stat = fs.lstatSync(full);
    if (!stat.isFile() || stat.isSymbolicLink() || sha(fs.readFileSync(full)) !== expected) return false;
  }
  return true;
}
function legacySnapshotComplete(context, root) {
  const complete = safeRead(path.join(root, 'complete.json'), null);
  if (!complete || !complete.files || typeof complete.files !== 'object') return false;
  return LEGACY_REQUIRED_SNAPSHOT_FILES.every((name) => {
    const full = path.join(root, name);
    return /^[a-f0-9]{64}$/.test(String(complete.files[name] || '')) && fs.existsSync(full) &&
      fs.lstatSync(full).isFile() && sha(fs.readFileSync(full)) === complete.files[name];
  });
}
function writeSnapshotUnlocked(context, result) {
  const taskHash = canonicalHash(result.scope.task_scope_hash, 'task id');
  const snapHash = canonicalHash(result.snapshot_hash, 'snapshot id');
  const root = taskRoot(context, taskHash);
  const finalRoot = snapshotRoot(context, taskHash, snapHash);
  if (fs.existsSync(finalRoot) && !snapshotComplete(context, finalRoot)) {
      const error = new Error(`Refusing incomplete task snapshot: ${snapHash}`); error.code = 'task_snapshot_incomplete'; throw error;
  }
  if (!fs.existsSync(finalRoot)) {
      const stage = path.join(root, 'snapshots', `.stage-${snapHash}-${process.pid}-${crypto.randomBytes(6).toString('hex')}`);
      ensureContainedDir(context.stateRoot, stage);
      const artifacts = {
        'scope.json': JSON.stringify(result.scope, null, 2) + '\n',
        'first-read.md': result.firstRead,
        'bundle.json': JSON.stringify(result.bundle, null, 2) + '\n',
        'decision.json': JSON.stringify(result.decision, null, 2) + '\n',
        'provenance.json': JSON.stringify(result.decision.provenance, null, 2) + '\n',
        'continuation.json': JSON.stringify(result.continuation, null, 2) + '\n'
      };
      for (const [name, body] of Object.entries(artifacts)) writeFileAtomicContained(path.join(stage, name), body, context.stateRoot);
      const complete = { schema_version: COMPLETE_SCHEMA, task_scope_hash: taskHash, snapshot_hash: snapHash, created_at: now(), files: Object.fromEntries(REQUIRED_SNAPSHOT_FILES.map((name) => [name, sha(fs.readFileSync(path.join(stage, name)))])) };
      writeJsonAtomicContained(path.join(stage, 'complete.json'), complete, context.stateRoot);
      assertSafeContainedPath(context.stateRoot, stage);
      ensureContainedDir(context.stateRoot, path.dirname(finalRoot));
      fs.renameSync(stage, finalRoot);
      if (!snapshotComplete(context, finalRoot)) throw new Error(`Snapshot verification failed: ${snapHash}`);
  }
  return { task_scope_hash: taskHash, snapshot_hash: snapHash, path: `routing/tasks/${taskHash}` };
}
function writeSnapshot(context, result) {
  const taskHash = canonicalHash(result.scope.task_scope_hash, 'task id');
  return withContainedLock(taskRoutingLock(context, taskHash), () => writeSnapshotUnlocked(context, result));
}
function writeImmutableArtifact(context, taskHash, kind, artifactHash, filename, value, completeSchema) {
  const root = taskRoot(context, taskHash);
  const finalRoot = path.join(root, kind, artifactHash);
  const complete = kind === 'baselines' ? baselineComplete : comparisonComplete;
  if (fs.existsSync(finalRoot) && !complete(context, finalRoot)) {
    const error = new Error(`Refusing incomplete ${kind} artifact: ${artifactHash}`);
    error.code = 'task_routing_artifact_incomplete';
    throw error;
  }
  if (!fs.existsSync(finalRoot)) {
    const stage = path.join(root, kind, `.stage-${artifactHash}-${process.pid}-${crypto.randomBytes(6).toString('hex')}`);
    ensureContainedDir(context.stateRoot, stage);
    const body = `${JSON.stringify(value, null, 2)}\n`;
    writeFileAtomicContained(path.join(stage, filename), body, context.stateRoot);
    writeJsonAtomicContained(path.join(stage, 'complete.json'), {
      schema_version: completeSchema,
      task_scope_hash: taskHash,
      artifact_hash: artifactHash,
      created_at: now(),
      files: { [filename]: sha(Buffer.from(body, 'utf8')) }
    }, context.stateRoot);
    ensureContainedDir(context.stateRoot, path.dirname(finalRoot));
    fs.renameSync(stage, finalRoot);
    if (!complete(context, finalRoot)) throw new Error(`${kind} artifact verification failed: ${artifactHash}`);
  }
  return finalRoot;
}
function writeBaseline(context, result) {
  const baselineHash = canonicalHash(result.baseline.baseline_hash, 'baseline id');
  const root = path.join(context.stateRoot, 'routing', 'workspace-baselines');
  const finalRoot = workspaceBaselineRoot(context, baselineHash);
  if (fs.existsSync(finalRoot) && !baselineComplete(context, finalRoot)) {
    const error = new Error(`Refusing incomplete workspace baseline artifact: ${baselineHash}`);
    error.code = 'workspace_baseline_artifact_incomplete';
    throw error;
  }
  if (!fs.existsSync(finalRoot)) {
    const stage = path.join(root, `.stage-${baselineHash}-${process.pid}-${crypto.randomBytes(6).toString('hex')}`);
    ensureContainedDir(context.stateRoot, stage);
    const body = `${JSON.stringify(result.baseline.parsed, null, 2)}\n`;
    writeFileAtomicContained(path.join(stage, 'baseline.json'), body, context.stateRoot);
    writeJsonAtomicContained(path.join(stage, 'complete.json'), {
      schema_version: BASELINE_COMPLETE_SCHEMA,
      workspace_id: result.baseline.parsed.workspace_id,
      repository_id: result.baseline.parsed.repository_id,
      artifact_hash: baselineHash,
      created_at: now(),
      files: { 'baseline.json': sha(Buffer.from(body, 'utf8')) }
    }, context.stateRoot);
    ensureContainedDir(context.stateRoot, root);
    fs.renameSync(stage, finalRoot);
    if (!baselineComplete(context, finalRoot)) throw new Error(`Workspace baseline verification failed: ${baselineHash}`);
  }
  return baselineHash;
}
function writeComparison(context, result) {
  const taskHash = canonicalHash(result.scope.task_scope_hash, 'task id');
  const comparisonHash = canonicalHash(result.metrics.metrics_comparison_hash, 'comparison id');
  writeImmutableArtifact(context, taskHash, 'comparisons', comparisonHash, 'metrics.json', result.metrics, COMPARISON_COMPLETE_SCHEMA);
  return comparisonHash;
}
function writeRoutingArtifacts(context, result) {
  writeSnapshot(context, result);
  writeBaseline(context, result);
  writeComparison(context, result);
}
function currentPath(context, taskHash) { return path.join(taskRoot(context, taskHash), 'current.json'); }
function transactionRoot(context) { return path.join(context.stateRoot, 'routing', 'transactions'); }
function taskIds(context) {
  const base = path.join(context.stateRoot, 'routing', 'tasks');
  if (!fs.existsSync(base)) return [];
  return fs.readdirSync(base, { withFileTypes: true }).filter((entry) => entry.isDirectory() && /^[a-f0-9]{64}$/.test(entry.name))
    .map((entry) => entry.name).sort();
}
function readCanonicalCurrent(context, taskHash) {
  const pointer = safeRead(currentPath(context, taskHash), null);
  const routeHash = pointer?.routing_snapshot_hash || pointer?.snapshot_hash;
  if (!pointer || pointer.task_scope_hash !== taskHash || !/^[a-f0-9]{64}$/.test(String(routeHash || '')) ||
      !/^[a-f0-9]{64}$/.test(String(pointer.baseline_hash || '')) ||
      !/^[a-f0-9]{64}$/.test(String(pointer.metrics_comparison_hash || ''))) return null;
  const root = snapshotRoot(context, taskHash, routeHash);
  if (!snapshotComplete(context, root)) return null;
  const scope = safeRead(path.join(root, 'scope.json'), null);
  const baselinePath = baselineRoot(context, taskHash, pointer.baseline_hash);
  const comparisonPath = comparisonRoot(context, taskHash, pointer.metrics_comparison_hash);
  if (!baselineComplete(context, baselinePath) || !comparisonComplete(context, comparisonPath)) return null;
  const baseline = safeRead(path.join(baselinePath, 'baseline.json'), null);
  const metrics = safeRead(path.join(comparisonPath, 'metrics.json'), null);
  if (!scope || scope.task_scope_hash !== taskHash || !baseline || baseline.baseline_hash !== pointer.baseline_hash ||
      !metrics || metrics.routing_snapshot_hash !== routeHash || metrics.baseline_hash !== pointer.baseline_hash ||
      metrics.metrics_comparison_hash !== pointer.metrics_comparison_hash) return null;
  return {
    schema_version: CURRENT_SCHEMA,
    task_scope_hash: taskHash,
    snapshot_hash: routeHash,
    routing_snapshot_hash: routeHash,
    baseline_hash: pointer.baseline_hash,
    metrics_comparison_hash: pointer.metrics_comparison_hash,
    path: `routing/tasks/${taskHash}/snapshots/${routeHash}`,
    baseline_path: baselinePath === workspaceBaselineRoot(context, pointer.baseline_hash)
      ? `routing/workspace-baselines/${pointer.baseline_hash}`
      : `routing/tasks/${taskHash}/baselines/${pointer.baseline_hash}`,
    comparison_path: `routing/tasks/${taskHash}/comparisons/${pointer.metrics_comparison_hash}`,
    complete: true,
    updated_at: pointer.updated_at || now(),
    transaction_id: pointer.transaction_id || 'legacy-recovered',
    status: pointer.status || 'current',
    stale: pointer.stale || null,
    scope, baseline,
    metrics
  };
}
function completeSnapshotRows(context, taskHash) {
  const base = path.join(taskRoot(context, taskHash), 'snapshots');
  if (!fs.existsSync(base)) return [];
  return fs.readdirSync(base, { withFileTypes: true }).filter((entry) => entry.isDirectory() && /^[a-f0-9]{64}$/.test(entry.name))
    .filter((entry) => snapshotComplete(context, path.join(base, entry.name)))
    .map((entry) => {
      const root = path.join(base, entry.name);
      const receipt = safeRead(path.join(root, 'complete.json'), {});
      return { snapshot_hash: entry.name, created_at: receipt.created_at || null, path: `routing/tasks/${taskHash}/snapshots/${entry.name}`,
        complete: true };
    }).sort((a, b) => a.snapshot_hash.localeCompare(b.snapshot_hash));
}
function writeManifestProjection(context, current) {
  const taskHash = current.task_scope_hash;
  const manifest = {
    schema_version: MANIFEST_SCHEMA,
    task_scope_hash: taskHash,
    snapshots: completeSnapshotRows(context, taskHash),
    updated_at: now(),
    current_snapshot_hash: current.snapshot_hash,
    current_routing_snapshot_hash: current.routing_snapshot_hash || current.snapshot_hash,
    current_baseline_hash: current.baseline_hash,
    current_metrics_comparison_hash: current.metrics_comparison_hash,
    scope: current.scope,
    projection_of: 'current.json',
    status: current.status,
    stale: current.stale || null
  };
  writeJsonAtomicContained(path.join(taskRoot(context, taskHash), 'manifest.json'), manifest, context.stateRoot);
  return manifest;
}
function reconcileTaskUnlocked(context, taskHash) {
  canonicalHash(taskHash, 'task id');
  let current = readCanonicalCurrent(context, taskHash);
    if (!current) {
      const legacy = safeRead(path.join(taskRoot(context, taskHash), 'manifest.json'), null);
      const legacyHash = legacy?.current_snapshot_hash;
      if (legacyHash && /^[a-f0-9]{64}$/.test(String(legacyHash)) && snapshotComplete(context, snapshotRoot(context, taskHash, legacyHash))) {
        const root = snapshotRoot(context, taskHash, legacyHash);
        const scope = safeRead(path.join(root, 'scope.json'), null);
        const metrics = safeRead(path.join(root, 'metrics.json'), null);
        if (scope?.task_scope_hash === taskHash && metrics?.snapshot_hash === legacyHash) {
          current = {
            schema_version: CURRENT_SCHEMA, task_scope_hash: taskHash, snapshot_hash: legacyHash,
            metrics_comparison_hash: metrics.metrics_comparison_hash || sha(metrics.comparison_receipt || metrics),
            path: `routing/tasks/${taskHash}/snapshots/${legacyHash}`, complete: true, updated_at: now(),
            transaction_id: 'recovered-legacy-projection', status: 'current', stale: null, scope, metrics
          };
          writeJsonAtomicContained(currentPath(context, taskHash), { ...current, scope: undefined, metrics: undefined }, context.stateRoot);
        }
      } else if (legacyHash && /^[a-f0-9]{64}$/.test(String(legacyHash)) && legacySnapshotComplete(context, snapshotRoot(context, taskHash, legacyHash))) {
        const legacyScope = safeRead(path.join(snapshotRoot(context, taskHash, legacyHash), 'scope.json'), null);
        if (legacyScope?.task_scope_hash === taskHash) {
          return {
            status: 'legacy_migration_required', task_scope_hash: taskHash, pointer_consistent: false,
            legacy_scope: legacyScope, legacy_snapshot_hash: legacyHash,
            reason: 'legacy_snapshot_requires_v3_continuation_receipt'
          };
        }
      }
    }
  if (!current) return { status: 'unavailable', task_scope_hash: taskHash, pointer_consistent: false, reason: 'no_valid_canonical_current' };
  writeJsonAtomicContained(currentPath(context, taskHash), { ...current, scope: undefined, metrics: undefined }, context.stateRoot);
  const manifest = writeManifestProjection(context, current);
  return { status: 'ok', task_scope_hash: taskHash, pointer_consistent: true, current, manifest };
}
function reconcileTask(context, taskHash) {
  canonicalHash(taskHash, 'task id');
  return withContainedLock(taskRoutingLock(context, taskHash), () => reconcileTaskUnlocked(context, taskHash));
}
function writeIndexUnlocked(context) {
  const tasks = taskIds(context).map((taskHash) => readCanonicalCurrent(context, taskHash)).filter(Boolean).map((current) => ({
      task_scope_hash: current.task_scope_hash,
      current_snapshot_hash: current.snapshot_hash,
      current_routing_snapshot_hash: current.routing_snapshot_hash || current.snapshot_hash,
      baseline_hash: current.baseline_hash,
      metrics_comparison_hash: current.metrics_comparison_hash,
      task: current.scope.task || null,
      scope_source: current.scope.scope_source || null,
      task_readiness: safeRead(path.join(context.stateRoot, current.path, 'bundle.json'), {}).task_readiness || 'unknown',
      snapshots_total: completeSnapshotRows(context, current.task_scope_hash).length,
      path: `routing/tasks/${current.task_scope_hash}`
    })).sort((a, b) => a.task_scope_hash.localeCompare(b.task_scope_hash));
    const index = { schema_version: INDEX_SCHEMA, generated_at: now(), projection_of: 'routing/tasks/*/current.json', tasks };
    ensureContainedDir(context.stateRoot, path.join(context.stateRoot, 'routing'));
    writeJsonAtomicContained(path.join(context.stateRoot, 'routing', 'index.json'), index, context.stateRoot);
  return index;
}
function writeIndex(context) {
  return withContainedLock(taskRoutingLock(context, 'index'), () => writeIndexUnlocked(context));
}
function reconcileAll(context) {
  const reconciled = taskIds(context).map((taskHash) => reconcileTask(context, taskHash));
  return { tasks: reconciled, index: writeIndex(context) };
}
function commitTaskState(context, result) {
  const taskHash = canonicalHash(result.scope.task_scope_hash, 'task id');
  const snapshotHash = canonicalHash(result.snapshot_hash, 'snapshot id');
  const baselineHash = canonicalHash(result.baseline.baseline_hash, 'baseline id');
  const comparisonHash = canonicalHash(result.metrics.metrics_comparison_hash, 'comparison id');
  const root = snapshotRoot(context, taskHash, snapshotHash);
  if (!snapshotComplete(context, root)) throw new Error(`Cannot promote incomplete task snapshot: ${snapshotHash}`);
  if (!baselineComplete(context, baselineRoot(context, taskHash, baselineHash))) throw new Error(`Cannot promote incomplete task baseline: ${baselineHash}`);
  if (!comparisonComplete(context, comparisonRoot(context, taskHash, comparisonHash))) throw new Error(`Cannot promote incomplete task comparison: ${comparisonHash}`);
  return withContainedLock(taskRoutingLock(context, taskHash), () => {
    const transactionId = sha(`${taskHash}:${snapshotHash}:${process.pid}:${now()}:${crypto.randomBytes(8).toString('hex')}`);
    ensureContainedDir(context.stateRoot, transactionRoot(context));
    const journalPath = path.join(transactionRoot(context), `${transactionId}.json`);
    const current = {
      schema_version: CURRENT_SCHEMA, task_scope_hash: taskHash, snapshot_hash: snapshotHash,
      routing_snapshot_hash: snapshotHash, baseline_hash: baselineHash,
      metrics_comparison_hash: comparisonHash,
      path: `routing/tasks/${taskHash}/snapshots/${snapshotHash}`, complete: true, updated_at: now(),
      transaction_id: transactionId, status: 'current', stale: null
    };
    writeJsonAtomicContained(journalPath, { schema_version: TRANSACTION_SCHEMA, transaction_id: transactionId, status: 'prepared', task_scope_hash: taskHash, new_current: current, prepared_at: now() }, context.stateRoot);
    writeJsonAtomicContained(currentPath(context, taskHash), current, context.stateRoot);
    const canonical = { ...current, scope: result.scope, metrics: result.metrics };
    const manifest = writeManifestProjection(context, canonical);
    const index = writeIndex(context);
    writeJsonAtomicContained(journalPath, { schema_version: TRANSACTION_SCHEMA, transaction_id: transactionId, status: 'committed', task_scope_hash: taskHash, new_current: current, committed_at: now() }, context.stateRoot);
    return { task_scope_hash: taskHash, snapshot_hash: snapshotHash, routing_snapshot_hash: snapshotHash, baseline_hash: baselineHash, metrics_comparison_hash: current.metrics_comparison_hash, transaction_id: transactionId, manifest, index };
  });
}
function listTasks(context) {
  reconcileAll(context);
  return taskIds(context).map((taskHash) => safeRead(path.join(taskRoot(context, taskHash), 'manifest.json'), null)).filter(Boolean);
}
function inspectTask(context, taskHash) {
  if (taskHash) {
    return withContainedLock(taskRoutingLock(context, canonicalHash(taskHash, 'task id')), () => {
      const result = reconcileTaskUnlocked(context, canonicalHash(taskHash, 'task id'));
      const index = writeIndex(context);
      return { ...result, index_reconciled: true, index };
    });
  }
  const all = reconcileAll(context);
  return { status: 'ok', tasks: all.tasks, index_reconciled: true, index: all.index };
}
function create(context, input) {
  const result = buildSnapshot(context, canonicalScope(input, context));
  writeRoutingArtifacts(context, result);
  const committed = commitTaskState(context, result);
  return { status: 'ok', task_scope_hash: committed.task_scope_hash, snapshot_hash: committed.snapshot_hash, routing_snapshot_hash: committed.routing_snapshot_hash, baseline_hash: committed.baseline_hash, metrics_comparison_hash: committed.metrics_comparison_hash, transaction_id: committed.transaction_id, index_reconciled: true, manifest_reconciled: true, scope: result.scope, metrics: result.metrics };
}
function refreshTask(context, taskHash) {
  canonicalHash(taskHash, 'task id');
  const resolved = reconcileTask(context, taskHash);
  const frozenScope = resolved.status === 'legacy_migration_required' ? resolved.legacy_scope : resolved.current?.scope;
  if (!frozenScope) { const error = new Error(`Task snapshot not found: ${taskHash}`); error.code = 'task_routing_not_found'; throw error; }
  const rebuilt = buildSnapshot(context, frozenScope);
  const changed = resolved.status === 'legacy_migration_required' || rebuilt.snapshot_hash !== resolved.current.snapshot_hash;
  writeRoutingArtifacts(context, rebuilt);
  const committed = commitTaskState(context, rebuilt);
  return {
    task_scope_hash: taskHash,
    status: resolved.status === 'legacy_migration_required' ? 'migrated' : changed ? 'refreshed' : 'current',
    previous_snapshot_hash: resolved.status === 'legacy_migration_required' ? resolved.legacy_snapshot_hash : resolved.current.snapshot_hash,
    current_snapshot_hash: committed.snapshot_hash,
    current_routing_snapshot_hash: committed.routing_snapshot_hash,
    snapshot_hash: committed.snapshot_hash,
    routing_snapshot_hash: committed.routing_snapshot_hash,
    previous_baseline_hash: resolved.status === 'legacy_migration_required' ? null : resolved.current.baseline_hash,
    current_baseline_hash: committed.baseline_hash,
    baseline_hash: committed.baseline_hash,
    previous_metrics_comparison_hash: resolved.status === 'legacy_migration_required' ? null : resolved.current.metrics_comparison_hash,
    current_metrics_comparison_hash: committed.metrics_comparison_hash,
    index_reconciled: true,
    manifest_reconciled: true,
    metrics: rebuilt.metrics
  };
}
function refreshAll(context) {
  const tasks = taskIds(context).map((taskHash) => refreshTask(context, taskHash));
  return { status: 'ok', tasks, index: writeIndex(context) };
}
function baselineTask(context, taskHash, options = {}) {
  canonicalHash(taskHash, 'task id');
  if (options.customBaseline) return diagnoseCustomBaseline(options.customBaseline);
  const refreshed = refreshTask(context, taskHash);
  const resolved = readCanonicalCurrent(context, taskHash);
  if (!resolved?.baseline) {
    const error = new Error(`Canonical baseline unavailable after refresh: ${taskHash}`);
    error.code = 'task_routing_baseline_unavailable';
    throw error;
  }
  return {
    status: 'ok',
    task_scope_hash: taskHash,
    baseline_hash: resolved.baseline_hash,
    baseline: resolved.baseline,
    reused: refreshed.previous_baseline_hash === refreshed.current_baseline_hash,
    routing_snapshot_hash: resolved.routing_snapshot_hash,
    metrics_comparison_hash: resolved.metrics_comparison_hash
  };
}
function invalidate(context, taskHash, reason) {
  canonicalHash(taskHash, 'task id');
  return withContainedLock(taskRoutingLock(context, taskHash), () => {
    const resolved = reconcileTaskUnlocked(context, taskHash);
    if (resolved.status !== 'ok') { const error = new Error(`Task snapshot not found: ${taskHash}`); error.code = 'task_routing_not_found'; throw error; }
    const current = {
      ...resolved.current,
      updated_at: now(),
      transaction_id: sha(`${taskHash}:invalidate:${now()}`),
      status: 'stale',
      stale: { status: 'stale', reason: String(reason || 'manual').slice(0, 240), checked_at: now() }
    };
    writeJsonAtomicContained(currentPath(context, taskHash), { ...current, scope: undefined, metrics: undefined }, context.stateRoot);
    writeManifestProjection(context, current);
    writeIndex(context);
    return { status: 'ok', task_scope_hash: taskHash, stale: current.stale, index_reconciled: true, manifest_reconciled: true };
  });
}

module.exports = {
  SCOPE_SCHEMA, SNAPSHOT_SCHEMA, REQUIRED_SNAPSHOT_FILES, PATH_BUDGETS,
  canonicalScope, buildSnapshot, create, listTasks, writeIndex, refreshAll, refreshTask, baselineTask, invalidate, inspectTask, reconcileTask, reconcileAll,
  taskRoot, snapshotRoot, workspaceBaselineRoot, baselineRoot, comparisonRoot, snapshotComplete, baselineComplete, comparisonComplete, canonicalHash,
  __test: {
    tokens, pathWithin, moduleSelection, relevantPathCandidates, sourceReceipt, collectSourceReceipts,
    moduleSourceReferences, sourcePathState, workspaceCandidatePaths, estimateFiles, requiredBaseline,
    canonicalBaseline, diagnoseCustomBaseline, semanticProjection, fileData
  }
};
