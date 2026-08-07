#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const { ensureDir, readJson, writeJsonAtomic, getAgentId } = require('./lib/json-store');
const { withContainedLock } = require('./lib/contained-lock-manager');
const { LOCKS } = require('./lib/lock-policy');
const { resolveKnowledgeContext, jsonContext } = require('./lib/path-context');
const { listTeamStatus, teamLockStatus } = require('./lib/team-store');
const {
  DEFAULT_REPAIR_POLICY,
  MODE_LABELS,
  operatorRepairSettings,
  resolvePolicy
} = require('./lib/repair-on-touch');
const { canonicalWikiStatus } = require('./lib/wiki-status');
const taskRoutingState = require('./lib/task-routing');
const { resolveEffectiveTaskRoutingState, formatTaskRoutingEstimate } = require('./lib/task-routing-state');
const context = resolveKnowledgeContext();
const knowledgeRoot = context.projectKnowledgeRoot;
const stateRoot = context.stateRoot;
const repoRoot = context.targetRoot;
const VISUAL_INSPECTOR_LOCK = Object.freeze({
  context,
  rootKind: 'state',
  rootPath: stateRoot,
  lockName: 'visual-inspector',
  purpose: LOCKS['visual-inspector'].purpose
});
const systemVersion = (() => {
  try {
    return JSON.parse(fs.readFileSync(path.join(knowledgeRoot, 'package.json'), 'utf8')).version || '3.3.0';
  } catch {
    return '3.3.0';
  }
})();

function isRuntimeRel(rel) {
  return /^(maintenance|metrics|search|inspector|sessions|routing)\//.test(rel) ||
    rel === 'freshness.json' ||
    rel === 'maps/wiki_graph.json' ||
    rel === 'maps/file_criticality.json';
}

function safeJson(rel, fallback) {
  const root = isRuntimeRel(rel) ? stateRoot : knowledgeRoot;
  return readJson(path.join(root, rel), fallback);
}

function esc(value) {
  return String(value ?? '').replace(/[&<>"']/g, (c) => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;'
  }[c]));
}

function jsJson(value) {
  return JSON.stringify(value).replace(/</g, '\\u003c');
}

function toArray(value) {
  if (!value) return [];
  return Array.isArray(value) ? value : [value];
}

function normalizePath(value) {
  return String(value || '').replace(/\\/g, '/').replace(/^\.\//, '');
}

function hrefForPath(value) {
  const raw = normalizePath(value);
  if (!raw) return '';
  if (/^https?:\/\//i.test(raw) || raw.startsWith('mailto:')) return raw;
  let rel = raw;
  if (rel.startsWith('.knowledge/')) rel = `../${rel.slice('.knowledge/'.length)}`;
  else if (rel.startsWith('knowledge/')) rel = `../${rel.slice('knowledge/'.length)}`;
  else if (/^(modules|maps|maintenance|wiki|docs|evidence|templates|external_memory|metrics|search|inspector|invariants|sessions|flows|commands|skills|agent-integrations)\//.test(rel)) rel = `../${rel}`;
  else rel = `../../${rel}`;
  return rel.split('/').map((part, index) => {
    if (part === '..' || part === '.' || part === '') return part;
    return encodeURIComponent(part);
  }).join('/');
}

function fileLink(value, options = {}) {
  const raw = normalizePath(value);
  if (!raw) return '<span class="muted">-</span>';
  const label = options.short ? shortPath(raw, options.short) : raw;
  const href = hrefForPath(raw);
  const cls = options.className || 'file-link';
  return `<a class="${cls}" href="${esc(href)}" title="${esc(raw)}">${esc(label)}</a>`;
}

function listLinks(values, empty = '-') {
  const arr = toArray(values).filter(Boolean);
  if (!arr.length) return `<span class="muted">${esc(empty)}</span>`;
  return `<div class="link-list">${arr.map((item) => fileLink(item, { short: 72 })).join('')}</div>`;
}

function shortPath(value, max = 64) {
  const text = normalizePath(value);
  if (text.length <= max) return text;
  const parts = text.split('/');
  if (parts.length <= 2) return `...${text.slice(-(max - 1))}`;
  const last = parts.pop();
  const first = parts.shift();
  const candidate = `${first}/.../${last}`;
  if (candidate.length <= max) return candidate;
  return `.../${last.slice(-(max - 3))}`;
}

function copyButton(command, label = 'Copy') {
  return `<button class="copy-btn" type="button" data-copy="${esc(command)}">${esc(label)}</button>`;
}

function commandBox(command, label = 'Copy command') {
  return `<div class="cmd"><code>${esc(command)}</code>${copyButton(command, label)}</div>`;
}

function safeNumber(value, fallback = 0) {
  const n = Number(value);
  return Number.isFinite(n) ? n : fallback;
}

const DEFAULT_OPERATOR_PROFILE = {
  schema_version: '3.3.0',
  user_mode: 'simple',
  first_run_onboarding_completed: false,
  detected_agent_runtime: null,
  selected_agent_id: null,
  connected_agents: [],
  agent_overrides: {}
};

const DEFAULT_AUTONOMY_POLICY = {
  schema_version: '3.3.0',
  agents_can_do_without_asking: 'run checks and reports',
  network_actions_require_confirmation: true,
  destructive_actions_require_confirmation: true,
  controlled_autonomy: 'planned',
  agent_overrides: {}
};

const DEFAULT_AGENT_POLICY = {
  schema_version: '3.3.0',
  concurrent_work_policy: 'Safe Queue',
  merge_policy: 'Manual Only',
  auto_merge: false,
  safe_queue_default: true,
  agent_overrides: {}
};

const DEFAULT_REPORT_FOOTER = {
  schema_version: '3.3.0',
  mode: 'compact',
  show_token_metrics: true,
  show_restore_action: true,
  show_open_inspector_action: true,
  only_when_trust_incomplete: false,
  agent_overrides: {}
};

function loadSettings() {
  const settings = {
    operator_profile: safeJson('settings/operator-profile.json', DEFAULT_OPERATOR_PROFILE),
    autonomy_policy: safeJson('settings/autonomy-policy.json', DEFAULT_AUTONOMY_POLICY),
    agent_policy: safeJson('settings/agent-policy.json', DEFAULT_AGENT_POLICY),
    report_footer: safeJson('settings/report-footer.json', DEFAULT_REPORT_FOOTER)
  };
  settings.repair_on_touch = resolvePolicy({ context, operator: settings.operator_profile });
  return settings;
}

function onboardingState(settings) {
  const profile = settings.operator_profile || {};
  const completed = profile.first_run_onboarding_completed === true;
  const hasCompletionMarker = Object.prototype.hasOwnProperty.call(profile, 'first_run_onboarding_completed');
  return {
    required: !completed,
    completed,
    reason: completed ? 'completed' : (hasCompletionMarker ? 'not_completed' : 'upgrade_missing_completion_marker'),
    completed_at: profile.onboarding_completed_at || null
  };
}

function selected(value, expected) {
  return String(value || '') === expected ? ' selected' : '';
}

function repairAgentPrompt(data = {}) {
  const score = data.quality?.quality_score ?? data.quality?.score ?? 'unknown';
  const repairCount = (data.repair?.queue || data.repair?.items || []).length;
  const staleCount = (data.stale?.items || data.stale?.stale_items || []).length;
  const branch = data.context?.branch || 'active branch';
  return [
    'Use the packaged kb-repair-trust skill for this repository.',
    '',
    'Task: repair .knowledge trust until doctor quality improves, without pushing anything.',
    `Current context: branch=${branch}, doctor_score=${score}, repair_queue=${repairCount}, stale_items=${staleCount}.`,
    '',
    'Start by reading .knowledge/maintenance/routing_bundle.json, then the doctor/quality report, trust_report, freshness and repair_queue.',
    'Classify problems before editing. Safely rebuild generated artifacts first. For contested knowledge, re-read current code/tests/evidence before changing modules or wiki.',
    '',
    'Ask me before deleting or untracking missing files, editing source/tests, manually raising trust/confidence/evidence, touching auth/payments/security/db/critical paths, or acting with uncertainty.',
    'After changes, run sync/restore/doctor and show before/after.'
  ].join('\n');
}

function collect() {
  const trust = safeJson('maintenance/trust_report.json', {});
  const quality = safeJson('maintenance/quality_report.json', {});
  const routing = safeJson('maintenance/routing_bundle.json', {});
  const taskRoutingReconciliation = taskRoutingState.reconcileAll(context);
  const maintenanceDebtForRouting = safeJson('maintenance/maintenance_debt.json', {
    repair_queue: [], suspect_modules: [], low_confidence_modules: []
  });
  const dynamicWorkspaceNotices = [
    ...(maintenanceDebtForRouting.suspect_modules || []).map((module_id) => ({ module_id, reason: 'workspace_suspect_module' })),
    ...(maintenanceDebtForRouting.low_confidence_modules || []).map((module_id) => ({ module_id, reason: 'workspace_low_confidence_module' }))
  ];
  const taskRoutingIndex = safeJson('routing/index.json', { schema_version: 'knowledge-routing-index.v4', tasks: [] });
  const taskRouting = {
    index: taskRoutingIndex,
    reconciliation: taskRoutingReconciliation,
    tasks: (taskRoutingIndex.tasks || []).map((task) => {
      const resolved = task.task_scope_hash ? taskRoutingState.inspectTask(context, task.task_scope_hash) : null;
      const effective = task.task_scope_hash ? resolveEffectiveTaskRoutingState({ context, taskScopeHash: task.task_scope_hash, verifyLiveInputs: true }) : null;
      const current = resolved?.status === 'ok' ? resolved.current : null;
      const base = current?.path || (task.task_scope_hash && task.current_snapshot_hash ? `routing/tasks/${task.task_scope_hash}/snapshots/${task.current_snapshot_hash}` : null);
      const bundle = base ? safeJson(`${base}/bundle.json`, {}) : {};
      const decision = base ? safeJson(`${base}/decision.json`, {}) : {};
      const metrics = current?.metrics || {};
      return {
        task_scope_hash: task.task_scope_hash,
        task: task.task,
        task_readiness: bundle.task_readiness || task.task_readiness || 'unknown',
        selected_modules: bundle.selected_modules || [],
        safety_overrides: bundle.safety?.safety_overrides || [],
        snapshot_hash: current?.snapshot_hash || task.current_snapshot_hash || null,
        metrics_comparison_hash: current?.metrics_comparison_hash || metrics.metrics_comparison_hash || null,
        pointer_consistent: Boolean(effective?.pointer_consistent),
        current_status: effective?.current_status || current?.status || 'unavailable',
        scope_comparable: effective?.scope_comparable === true,
        comparison_kind: metrics.comparison_kind || null,
        workspace_baseline: metrics.workspace_baseline || {},
        workspace_baseline_valid: effective?.workspace_baseline_complete === true && effective?.canonical_workspace_baseline === true,
        claim_eligible: Boolean(effective?.effective_claim_eligible),
        claim_ineligible_reasons: effective?.claim_ineligible_reasons || metrics.claim_ineligible_reasons || (metrics.claim_ineligible_reason ? [metrics.claim_ineligible_reason] : []),
        assessment: metrics.assessment || 'not_comparable',
        estimate_text: formatTaskRoutingEstimate(metrics, effective || { effective_claim_eligible: false, claim_ineligible_reasons: ['task_routing_state_missing'] }),
        estimated_tokens_saved: effective?.effective_claim_eligible ? metrics.estimated_tokens_saved : null,
        estimated_tokens_overhead: effective?.effective_claim_eligible ? metrics.estimated_tokens_overhead : null,
        workspace_narrowing: metrics.workspace_narrowing || {},
        required_sources: bundle.required_sources || { complete: false, sources: [], issues: [] },
        git_diff_paths: (bundle.relevant_changed_or_stale_paths || []).filter((item) => item.git_status).map((item) => ({ path: item.path, status: item.git_status })),
        relevant_paths: bundle.relevant_changed_or_stale_paths || [],
        omitted_paths: decision.truncation?.omitted_relevant_paths || [],
        high_risk_continuation: bundle.high_risk_continuation || decision.truncation?.high_risk_continuation || {},
        selected_reasons: (decision.candidates || []).filter((item) => item.selected).map((item) => ({ module_id: item.module_id, reason: item.inclusion_reason })),
        excluded_reasons: (decision.candidates || []).filter((item) => !item.selected).map((item) => ({ module_id: item.module_id, reason: item.exclusion_reason })),
        task_debt: bundle.workspace_debt?.relevant_to_current_task ?? 0,
        workspace_debt: Array.isArray(maintenanceDebtForRouting.repair_queue) ? maintenanceDebtForRouting.repair_queue.length : 0,
        workspace_notices: dynamicWorkspaceNotices
      };
    })
  };
  const modules = safeJson('modules/module_registry.json', { modules: [] });
  const repair = safeJson('maintenance/repair_queue.json', { queue: [] });
  const repairOpportunities = safeJson('maintenance/repair_opportunities.json', {
    schema_version: 'knowledge-repair-opportunities.v1',
    opportunities: [],
    status: 'not_generated'
  });
  const verificationReceipts = safeJson('maintenance/verification_receipts/index.json', {
    schema_version: 'knowledge-verification-receipt-index.v1',
    receipts: []
  });
  const stale = safeJson('maintenance/stale_items.json', { items: [] });
  const wikiGraph = safeJson('maps/wiki_graph.json', { nodes: [], edges: [], summary: {} });
  const fileCriticality = safeJson('maps/file_criticality.json', { files: [] });
  const external = safeJson('maintenance/external_memory_status.json', {});
  const appliedTemplates = safeJson('maintenance/applied_templates.json', { templates: [] });
  const metrics = safeJson('metrics/baseline.json', {});
  const secretScan = safeJson('maintenance/secret_scan_report.json', {});
  const searchIndex = safeJson('search/index.json', { documents: [] });
  const wikiLint = safeJson('maintenance/wiki_lint_report.json', {});
  const wikiStatus = canonicalWikiStatus(wikiLint, wikiGraph);
  const prImpact = safeJson('maintenance/pr_impact.json', { status: 'not_generated', changed_files: [], affected_modules: [], policy_warnings: [] });
  const updateStatusRaw = safeJson('maintenance/update_status.json', { status: 'never_checked' });
  const updateStatus = (() => {
    const status = updateStatusRaw && typeof updateStatusRaw === 'object' ? { ...updateStatusRaw } : { status: 'never_checked' };
    if (!status.current_version) status.current_version = systemVersion;
    if (status.current_version !== systemVersion) {
      status.current_version = systemVersion;
    }
    return status;
  })();
  const agentRegistry = safeJson('sessions/agent-registry.json', { schema_version: 'knowledge-agent-registry.v1', sessions: [] });
  const settings = loadSettings();
  settings.user_mode = settings.operator_profile.user_mode || 'simple';
  settings.onboarding = onboardingState(settings);
  let team = null;
  let lockOwner = null;
  if (context.teamRoot) {
    try { team = listTeamStatus(context.teamRoot); } catch (error) { team = { warnings: [error.message] }; }
    try {
      const lockStatus = teamLockStatus(context);
      const safeOwner = lockStatus.current?.owner || lockStatus.legacy?.owner || null;
      lockOwner = safeOwner ? {
        ...safeOwner,
        agentId: safeOwner.agent_id || null,
        branch: null
      } : null;
    } catch { lockOwner = null; }
  }
  return {
    generated_at: new Date().toISOString(),
    generated_by: getAgentId(),
    context: jsonContext(context),
    trust,
    quality,
    routing,
    taskRouting,
    modules,
    repair,
    repairOpportunities,
    verificationReceipts,
    stale,
    wikiGraph,
    fileCriticality,
    external,
    appliedTemplates,
    metrics,
    secretScan,
    searchIndex,
    wikiLint,
    wikiStatus,
    prImpact,
    updateStatus,
    agentRegistry,
    settings,
    team,
    lockOwner
  };
}

function trustCounts(trust) {
  const buckets = trust.modules || {};
  return ['trusted', 'near_trusted', 'routing_trusted', 'advisory_only', 'suspect', 'low_confidence']
    .map((key) => ({ key, count: (buckets[key] || []).length }));
}

function moduleStatusMap(trust) {
  const out = new Map();
  for (const status of trust.module_statuses || []) {
    if (status && status.module_id) out.set(status.module_id, status);
  }
  const buckets = trust.modules || {};
  for (const [bucket, ids] of Object.entries(buckets)) {
    for (const id of ids || []) {
      if (!out.has(id)) out.set(id, { module_id: id, trust_status: bucket });
      else out.get(id).trust_status = out.get(id).trust_status || bucket;
    }
  }
  return out;
}

function trustClass(value) {
  const key = String(value || 'unknown').toLowerCase();
  if (['trusted', 'near_trusted', 'routing_trusted', 'advisory_only', 'suspect', 'low_confidence', 'critical', 'important', 'high', 'medium', 'low'].includes(key)) return key;
  return 'unknown';
}

function explainModule(module, status) {
  const reasons = [];
  const trust = module.current_trust_level || module.trust_status || status?.trust_status || status?.current_trust_level || status?.trust_level || 'unknown';
  const confidence = module.confidence || status?.confidence || 'unknown';
  const verification = module.verification_status || status?.verification_status || module.status || status?.status || '';
  const evidenceFiles = toArray(module.evidence_files || status?.evidence_files);
  const keyFiles = toArray(module.key_files || status?.key_files);
  const freshness = status?.freshness_status || status?.freshness || module.freshness_status || '';

  const reasonObject = status?.reasons || status?.reason || module.reasons || null;
  if (reasonObject && typeof reasonObject === 'object') {
    for (const [key, value] of Object.entries(reasonObject)) {
      if (Array.isArray(value) && value.length) reasons.push(`${key}: ${value.slice(0, 4).join(', ')}`);
      else if (value && typeof value !== 'object') reasons.push(`${key}: ${value}`);
    }
  } else if (typeof reasonObject === 'string' && reasonObject.trim()) {
    reasons.push(reasonObject.trim());
  }

  if (['low_confidence', 'suspect', 'needs_recheck'].includes(String(trust))) reasons.push(`trust is ${trust}; re-read source before behavior claims`);
  if (String(confidence).toLowerCase() === 'low') reasons.push('confidence is low');
  if (!evidenceFiles.length) reasons.push('no evidence files linked yet');
  if (!keyFiles.length && !toArray(module.template_suggested_files).length) reasons.push('no key files mapped yet');
  if (/heuristic|template|seed|advisory|requires/i.test(String(verification))) reasons.push(`verification: ${verification}`);
  if (freshness && !/fresh|current|ok/i.test(String(freshness))) reasons.push(`freshness: ${freshness}`);
  if (!reasons.length) reasons.push('no blocking reason found; verify against current code/tests before raising trust');
  return Array.from(new Set(reasons)).slice(0, 5);
}

function getModules(data) {
  const statuses = moduleStatusMap(data.trust);
  const registry = data.modules.modules || [];
  const seen = new Set();
  const rows = [];
  for (const module of registry) {
    const id = module.module_id || module.id || module.name;
    if (!id) continue;
    const status = statuses.get(id) || {};
    seen.add(id);
    rows.push({
      ...module,
      module_id: id,
      path: module.path || status.path || '',
      card: module.card || status.card || `.knowledge/modules/${id}.json`,
      confidence: module.confidence || status.confidence || '',
      trust_status: module.current_trust_level || status.trust_status || module.trust || 'unknown',
      reasons: explainModule(module, status)
    });
  }
  for (const [id, status] of statuses.entries()) {
    if (seen.has(id)) continue;
    rows.push({
      module_id: id,
      path: status.path || '',
      card: status.card || `.knowledge/modules/${id}.json`,
      confidence: status.confidence || '',
      trust_status: status.trust_status || status.current_trust_level || 'unknown',
      reasons: explainModule({}, status)
    });
  }
  return rows.sort((a, b) => String(a.module_id).localeCompare(String(b.module_id)));
}

function getRepairItems(data) {
  return (data.repair.queue || []).map((item) => ({
    priority: item.priority || item.severity || 'medium',
    subject: item.subject || item.title || item.id || 'Repair item',
    status: item.status || 'open',
    affected_artifacts: item.affected_artifacts || item.artifacts || item.files || [],
    reason: item.reason || item.details || item.description || ''
  }));
}

function getStaleItems(data) {
  return (data.stale.items || data.stale.stale_items || []).map((item) => ({
    status: item.status || item.state || 'stale',
    artifact: item.artifact || item.path || item.file || '',
    reason: item.reason || item.why || '',
    action: item.action || item.recommended_action || ''
  }));
}

function getCriticalFiles(data) {
  return (data.fileCriticality.files || [])
    .filter((file) => ['critical', 'important'].includes(file.classification))
    .map((file) => ({
      classification: file.classification,
      path: file.path || file.file || '',
      modules: file.modules || [],
      reason: file.reason || file.why || ''
    }));
}

function graphGroup(node) {
  const type = String(node.type || node.group || '').toLowerCase();
  if (type === 'source_truth' || String(node.id || '').startsWith('truth:')) return 'source_truth';
  if (type === 'module' || String(node.id || '').startsWith('module:')) return 'module';
  if (type === 'wiki_page' || String(node.path || '').includes('/wiki/')) return 'wiki';
  return 'other';
}

function relationClass(value) {
  return String(value || 'related').replace(/[^a-z0-9_-]/gi, '_');
}

function uniqueGraphValues(values, max = 18) {
  const seen = new Set();
  const out = [];
  for (const value of values || []) {
    const text = String(value || '').trim();
    if (!text || seen.has(text)) continue;
    seen.add(text);
    out.push(text);
    if (out.length >= max) break;
  }
  return out;
}

function graphNodeModuleId(node) {
  const id = String(node.id || '');
  if (node.module_id) return String(node.module_id);
  return id.startsWith('module:') ? id.slice('module:'.length) : '';
}

function graphNodeDisplayName(node) {
  const group = graphGroup(node);
  const title = String(node.title || node.page || node.id || '').replace(/^Module:\s*/i, '').trim();
  if (group === 'module') {
    const moduleId = graphNodeModuleId(node);
    const base = title || moduleId;
    const withoutProduct = base.replace(/^knowledge[-_]kit[-_]?/i, '').replace(/^knowledge_kit_/i, '');
    return (withoutProduct || base || moduleId).replace(/[_-]+/g, ' ').replace(/\bFINAL\b/g, 'final').trim();
  }
  if (group === 'source_truth') return title.replace(/^Current\s+/i, '');
  return title;
}

function compactGraphLabel(node, max = 24) {
  const text = graphNodeDisplayName(node);
  return text.length <= max ? text : `${text.slice(0, Math.max(8, max - 1))}...`;
}

function graphTextLines(value, maxLine = 16, maxLines = 2) {
  const words = String(value || '').split(/\s+/).filter(Boolean);
  const lines = [];
  let line = '';
  for (const word of words) {
    const candidate = line ? `${line} ${word}` : word;
    if (candidate.length <= maxLine || !line) {
      line = candidate;
      continue;
    }
    lines.push(line);
    line = word;
    if (lines.length >= maxLines - 1) break;
  }
  if (line && lines.length < maxLines) lines.push(line);
  const text = lines.join(' ');
  const original = String(value || '');
  if (text.length < original.length && lines.length) lines[lines.length - 1] = `${lines[lines.length - 1].slice(0, Math.max(5, maxLine - 3))}...`;
  return lines.length ? lines : [''];
}

function graphLabelMarkup(node, x, y, label, group) {
  const lines = group === 'module' ? graphTextLines(label, 15, 2) : graphTextLines(label, group === 'source_truth' ? 18 : 20, 2);
  const firstDy = lines.length === 1 ? 0 : -6;
  const tspans = lines.map((line, index) => `<tspan x="${x.toFixed(1)}" dy="${index === 0 ? firstDy : 13}">${esc(line)}${index < lines.length - 1 ? ' ' : ''}</tspan>`).join('');
  return `<text x="${x.toFixed(1)}" y="${y.toFixed(1)}" class="label ${esc(group)}">${tspans}</text>`;
}

function graphHitTargetMarkup(node, labelY) {
  const r = Math.max(node.r + 10, 23);
  const labelTop = Math.min(node.y, labelY) - 18;
  const labelHeight = Math.abs(labelY - node.y) + 32;
  return `<circle cx="${node.x.toFixed(1)}" cy="${node.y.toFixed(1)}" r="${r.toFixed(1)}" class="graph-hit-target"></circle><rect x="${(node.x - 68).toFixed(1)}" y="${labelTop.toFixed(1)}" width="136" height="${labelHeight.toFixed(1)}" rx="8" class="graph-hit-target label-hit-target"></rect>`;
}

function routingModuleFor(data, moduleId) {
  return (data.routing?.modules || []).find((module) => module.module_id === moduleId) || {};
}

function registryModuleFor(data, moduleId) {
  return (data.modules?.modules || []).find((module) => (module.module_id || module.id || module.name) === moduleId) || {};
}

function taskRouteFor(data, moduleId) {
  const routes = Array.isArray(data.routing?.task_routing)
    ? data.routing.task_routing
    : [];
  return routes.find((route) => (route.target_modules || []).includes(moduleId)) || {};
}

function effectiveGraphTrust(node, data) {
  const moduleId = graphNodeModuleId(node);
  if (moduleId) {
    const routingModule = routingModuleFor(data, moduleId);
    return routingModule.trust_status || node.trust || node.status || 'routing_trusted';
  }
  return node.trust || node.status || 'advisory_only';
}

function graphEdgeSummary(edge) {
  return {
    relation: edge.type || edge.relation || 'related',
    from: edge.from || '',
    to: edge.to || '',
    source: edge.source || '',
    reason: edge.reason || ''
  };
}

function graphStatusForNode(node, graph, data) {
  const id = String(node.id || '');
  const pathValue = normalizePath(node.path || node.page || '');
  const orphanPages = graph.summary?.orphan_pages || [];
  const brokenEdges = graph.broken_edges || [];
  const staleItems = getStaleItems(data).filter((item) => {
    const artifact = normalizePath(item.artifact || '');
    if (!artifact) return false;
    const pathMatch = pathValue ? (artifact === pathValue || artifact.endsWith(pathValue)) : false;
    const idMatch = id ? artifact.includes(id) : false;
    return pathMatch || idMatch;
  });
  return {
    node_status: node.status || 'unknown',
    broken: brokenEdges.some((edge) => edge.from === id || edge.to === id),
    orphan: orphanPages.includes(id),
    stale: staleItems.length > 0 || String(node.status || '').toLowerCase().includes('stale'),
    stale_items: staleItems.map((item) => `${item.artifact}${item.reason ? `: ${item.reason}` : ''}`)
  };
}

function graphVerificationForNode(node, data, routingModule = {}) {
  const id = String(node.id || '');
  const moduleId = graphNodeModuleId(node);
  const registryModule = moduleId ? registryModuleFor(data, moduleId) : {};
  const evidenceFiles = uniqueGraphValues([
    ...toArray(node.evidence_files),
    ...toArray(registryModule.evidence_files),
    ...toArray(routingModule.evidence_files)
  ]);
  const relatedFiles = uniqueGraphValues([
    ...toArray(node.key_files),
    ...toArray(registryModule.key_files),
    ...toArray(routingModule.start_with),
    node.path || ''
  ]);
  const tests = relatedFiles.filter((file) => /(^|[\/_-])(test|tests|spec|self-test|qa)([\/_.-]|$)|AGENT_TEST/i.test(file));
  const code = relatedFiles.filter((file) => !tests.includes(file) && !/\.knowledge\/evidence\//i.test(file));
  const evidence = evidenceFiles.concat(relatedFiles.filter((file) => /\.knowledge\/evidence\//i.test(file)));
  if (id === 'truth:code') code.push('Current repository code');
  if (id === 'truth:tests') tests.push('Current tests and self-tests');
  if (id === 'truth:evidence') evidence.push('.knowledge/evidence/*.json');
  if (id === 'truth:modules') code.push('.knowledge/modules/*.json');
  if (id === 'truth:wiki') evidence.push('advisory only, verify against code/tests/evidence');
  return {
    evidence: uniqueGraphValues(evidence),
    tests: uniqueGraphValues(tests),
    code: uniqueGraphValues(code),
    gaps: [
      evidence.length ? '' : 'No explicit evidence JSON listed for this node.',
      tests.length ? '' : 'No explicit tests listed for this node.',
      code.length ? '' : 'No related code/module files listed for this node.'
    ].filter(Boolean)
  };
}

function isWikiGraphNode(node) {
  const id = String(node.id || '');
  const pathValue = normalizePath(node.path || node.page || '');
  return graphGroup(node) === 'wiki' || id === 'truth:wiki' || pathValue.startsWith('.knowledge/wiki');
}

function graphTrustReason(node, data, routingModule = {}, route = {}) {
  const group = graphGroup(node);
  const trust = effectiveGraphTrust(node, data);
  if (group === 'source_truth') {
    return `${node.title || node.id} has canonical rank ${node.rank || '?'} in the source-of-truth order; code and tests outrank generated knowledge and advisory memory.`;
  }
  if (group === 'wiki') {
    return 'Wiki nodes are advisory-only context. Verify every behavior claim against current code, tests, or evidence JSON.';
  }
  if (group === 'module') {
    const parts = [
      `Routing bundle reports trust=${routingModule.trust_status || trust}.`,
      `confidence=${routingModule.confidence || node.confidence || 'unknown'}.`,
      `freshness=${routingModule.freshness_status || node.status || 'unknown'}.`
    ];
    const reasons = routingModule.reasons || {};
    const reasonBits = [
      ...(reasons.changed_or_missing_important_files || []).map((item) => `changed/missing: ${item}`),
      ...(reasons.open_contradictions || []).map((item) => `contradiction: ${item}`),
      ...(reasons.uncovered_important_files || []).map((item) => `uncovered: ${item}`)
    ];
    if (route.route_id) parts.push(`Route ${route.route_id} starts with ${toArray(route.start_with).join(', ') || 'module card'}.`);
    if (reasonBits.length) parts.push(reasonBits.join(' / '));
    return parts.join(' ');
  }
  return `Trust is inherited from graph node metadata: ${trust}. Re-check current code/tests before behavior edits.`;
}

function graphWhyRoute(node, data, routingModule = {}, route = {}) {
  const moduleId = graphNodeModuleId(node);
  if (!moduleId) return '';
  const keywords = toArray(route.keywords).join(', ') || moduleId;
  const startWith = uniqueGraphValues([...toArray(route.start_with), ...toArray(routingModule.start_with)]).join(', ') || node.path || `.knowledge/modules/${moduleId}.json`;
  return `why this route: keywords (${keywords}) target module ${moduleId}; start with ${startWith}.`;
}

function graphNextActions(node, data, verification) {
  const group = graphGroup(node);
  const moduleId = graphNodeModuleId(node);
  const query = moduleId || node.title || node.page || node.id || '';
  const actions = [];
  if (group === 'module' && node.path) actions.push({ label: 'Open module card', href: hrefForPath(node.path), path: normalizePath(node.path) });
  const related = uniqueGraphValues([...(verification.code || []), ...(verification.tests || []), ...(verification.evidence || [])], 8)
    .filter((file) => {
      const text = normalizePath(file);
      return text && !/^Current\s/i.test(text) && (text.includes('/') || text.startsWith('.knowledge') || /\.[a-z0-9]{1,8}$/i.test(text));
    })
    .slice(0, 5);
  for (const file of related) actions.push({ label: `Open ${shortPath(file, 32)}`, href: hrefForPath(file), path: normalizePath(file) });
  actions.push({ label: 'Search node', command: `node .knowledge/tools/search-knowledge.js "${String(query).replace(/"/g, '\\"')}"` });
  actions.push({ label: 'Rebuild graph', command: 'node .knowledge/tools/build-wiki-graph.js' });
  if (group === 'wiki') {
    const wikiPath = normalizePath(node.path || `.knowledge/wiki/${node.id}`);
    actions.push({ label: 'Add typed link', href: hrefForPath(wikiPath), path: wikiPath });
  }
  else actions.push({ label: 'Add typed link', command: 'node .knowledge/tools/lint-wiki.js' });
  return actions.slice(0, 9);
}

function graphDetailForNode(node, graph, data) {
  const moduleId = graphNodeModuleId(node);
  const routingModule = moduleId ? routingModuleFor(data, moduleId) : {};
  const route = moduleId ? taskRouteFor(data, moduleId) : {};
  const verification = graphVerificationForNode(node, data, routingModule);
  const id = String(node.id || '');
  const incoming = (graph.edges || []).filter((edge) => edge.to === id).map(graphEdgeSummary);
  const outgoing = (graph.edges || []).filter((edge) => edge.from === id).map(graphEdgeSummary);
  return {
    title: graphNodeDisplayName(node) || node.title || id,
    raw_title: node.title || id,
    id,
    type: graphGroup(node),
    trust: effectiveGraphTrust(node, data),
    path: normalizePath(node.path || node.page || ''),
    incoming,
    outgoing,
    trust_reason: graphTrustReason(node, data, routingModule, route),
    verification,
    why_route: graphWhyRoute(node, data, routingModule, route),
    status: graphStatusForNode(node, graph, data),
    advisory_note: isWikiGraphNode(node) ? 'advisory only, verify against code/tests/evidence' : '',
    next_actions: graphNextActions(node, data, verification)
  };
}

function graphNodeAttrs(node, detail = null, effectiveTrust = null) {
  const group = graphGroup(node);
  const pathValue = normalizePath(node.path || node.page || '');
  const id = String(node.id || '');
  const moduleId = id.startsWith('module:') ? id.slice('module:'.length) : '';
  const query = moduleId || node.title || node.page || id;
  const command = group === 'wiki'
    ? `node .knowledge/tools/search-knowledge.js "${String(query).replace(/"/g, '\\"')}"`
    : group === 'module'
      ? `node .knowledge/tools/search-knowledge.js "${String(moduleId || query).replace(/"/g, '\\"')}"`
      : 'node .knowledge/tools/restore-trust.js --safe --json';
  const attrs = {
    'data-graph-node': 'true',
    'data-graph-id': id,
    'data-graph-title': graphNodeDisplayName(node) || node.title || node.page || id,
    'data-graph-group': group,
    'data-graph-path': pathValue,
    'data-graph-trust': effectiveTrust || node.trust || node.status || 'advisory_only',
    'data-graph-module': moduleId,
    'data-graph-query': query,
    'data-graph-command': command,
    'data-graph-description': node.description || ''
  };
  if (detail) attrs['data-graph-detail-json'] = JSON.stringify(detail);
  return Object.entries(attrs).map(([key, value]) => `${key}="${esc(value)}"`).join(' ');
}

function placeGraphRow(items, y, width, startX = 84, endPad = 120) {
  if (!items.length) return [];
  const usable = Math.max(1, width - startX - endPad);
  const step = items.length === 1 ? 0 : usable / (items.length - 1);
  return items.map((node, index) => ({
    ...node,
    x: items.length === 1 ? width / 2 : startX + step * index,
    y,
    row_index: index
  }));
}

function graphBusNode(nodes, id, yFallback) {
  const row = nodes || [];
  if (!row.length) return { id, x: 660, y: yFallback, row_index: 0, group: 'bus', r: 1 };
  const minX = Math.min(...row.map((node) => node.x));
  const maxX = Math.max(...row.map((node) => node.x));
  return {
    id,
    x: (minX + maxX) / 2,
    y: row[0].y,
    row_index: 0,
    group: 'bus',
    r: 1
  };
}

function selectVisibleGraphEdges(edgeList, byId, groups) {
  const direct = [];
  const bundles = new Map();
  const moduleBus = graphBusNode(groups.module, 'bus:modules', 282);
  function addBundle(key, edge, a, b) {
    const relation = edge.type || edge.relation || 'related';
    const existing = bundles.get(key);
    if (existing) {
      existing.count += 1;
      existing.edge_ids.push(`${edge.from} -> ${edge.to}`);
      if (edge.reason && !existing.reasons.includes(edge.reason)) existing.reasons.push(edge.reason);
      return;
    }
    bundles.set(key, {
      ...edge,
      from: a.id,
      to: b.id,
      a,
      b,
      type: relation,
      relation,
      bundled: true,
      count: 1,
      edge_ids: [`${edge.from} -> ${edge.to}`],
      reasons: edge.reason ? [edge.reason] : []
    });
  }
  for (const edge of edgeList) {
    const a = byId.get(edge.from);
    const b = byId.get(edge.to);
    if (!a || !b) continue;
    const relation = edge.type || edge.relation || 'related';
    const fromGroup = graphGroup(a);
    const toGroup = graphGroup(b);
    if (fromGroup === 'source_truth' && toGroup === 'module' && ['routes', 'checks', 'evidence'].includes(relation)) {
      addBundle(`${edge.from}:${relation}:module-bus`, edge, a, moduleBus);
      continue;
    }
    if (fromGroup === 'module' && (toGroup === 'wiki' || edge.to === 'truth:wiki')) {
      addBundle(`module-bus:${relation}:${edge.to}`, edge, moduleBus, b);
      continue;
    }
    direct.push({ ...edge, a, b, relation, bundled: false, count: 1 });
  }
  return [...direct, ...bundles.values()];
}

function layoutGraph(nodes, edges) {
  const nodeList = (nodes || []).slice(0, 120);
  const edgeList = (edges || []).slice(0, 260);
  if (!nodeList.length) return { nodes: [], edges: [], width: 1280, height: 600 };
  const degrees = new Map(nodeList.map((node) => [node.id, 0]));
  for (const edge of edgeList) {
    if (degrees.has(edge.from)) degrees.set(edge.from, degrees.get(edge.from) + 1);
    if (degrees.has(edge.to)) degrees.set(edge.to, degrees.get(edge.to) + 1);
  }
  const groups = { source_truth: [], module: [], wiki: [], other: [] };
  for (const node of nodeList) groups[graphGroup(node)].push(node);
  groups.source_truth.sort((a, b) => safeNumber(a.rank, 99) - safeNumber(b.rank, 99));
  groups.module.sort((a, b) => String(a.title || a.id).localeCompare(String(b.title || b.id)));
  groups.wiki.sort((a, b) => {
    if (a.id === 'index.md') return -1;
    if (b.id === 'index.md') return 1;
    return String(a.title || a.id).localeCompare(String(b.title || b.id));
  });
  const width = 1280;
  const height = 600;
  const positioned = [
    ...placeGraphRow(groups.source_truth, 104, width, 86, 106),
    ...placeGraphRow(groups.module, 292, width, 188, 188),
    ...placeGraphRow(groups.wiki, 468, width, 126, 126),
    ...placeGraphRow(groups.other, 548, width, 140, 140)
  ].map((node) => ({
    ...node,
    group: graphGroup(node),
    degree: degrees.get(node.id) || 0,
    r: Math.min(17, Math.max(9, 8 + Math.sqrt(degrees.get(node.id) || 1) * 2))
  }));
  const byId = new Map(positioned.map((node) => [node.id, node]));
  const positionedGroups = { source_truth: [], module: [], wiki: [], other: [] };
  for (const node of positioned) positionedGroups[node.group || 'other'].push(node);
  const visibleEdges = selectVisibleGraphEdges(edgeList, byId, positionedGroups);
  return { nodes: positioned, edges: visibleEdges, width, height };
}

function edgePath(edge) {
  const { a, b } = edge;
  if (edge.bundled) {
    const relation = edge.type || edge.relation || 'related';
    const offset = relation === 'checks' ? -56 : relation === 'routes' ? -22 : relation === 'documents' ? 30 : 52;
    const midY = ((a.y + b.y) / 2) + offset;
    return `M ${a.x.toFixed(1)} ${a.y.toFixed(1)} C ${a.x.toFixed(1)} ${midY.toFixed(1)} ${b.x.toFixed(1)} ${midY.toFixed(1)} ${b.x.toFixed(1)} ${b.y.toFixed(1)}`;
  }
  const vertical = Math.abs(b.y - a.y);
  const sameRow = vertical < 40;
  const mx = (a.x + b.x) / 2;
  const my = (a.y + b.y) / 2;
  const dx = b.x - a.x;
  const dy = b.y - a.y;
  const len = Math.sqrt(dx * dx + dy * dy) || 1;
  const curve = sameRow ? Math.min(64, Math.max(22, Math.abs(dx) * 0.18)) : Math.min(80, Math.max(26, len * 0.11));
  const bend = sameRow ? (a.row_index || 0) % 2 === 0 ? -curve : curve : curve;
  const cx = sameRow ? mx : mx - (dy / len) * bend;
  const cy = sameRow ? my + bend : my + (dx / len) * bend;
  return `M ${a.x.toFixed(1)} ${a.y.toFixed(1)} Q ${cx.toFixed(1)} ${cy.toFixed(1)} ${b.x.toFixed(1)} ${b.y.toFixed(1)}`;
}

function graphMetric(label, value, hint = '') {
  return `<div class="graph-metric"><strong>${esc(value)}</strong><span>${esc(label)}</span>${hint ? `<small>${esc(hint)}</small>` : ''}</div>`;
}

function graphInsights(graph) {
  const summary = graph.summary || {};
  const relationCounts = summary.relation_counts || {};
  const relationText = Object.entries(relationCounts).map(([key, value]) => `${key}:${value}`).join(' / ') || 'none';
  const orphanPages = summary.orphan_pages || [];
  const checks = summary.actionable_checks || [];
  return `<div class="graph-insights"><h3>Graph diagnostics</h3><table class="kv"><tbody><tr><th>View</th><td>${esc(graph.view || 'wiki_graph')}</td></tr><tr><th>Relations</th><td>${esc(relationText)}</td></tr><tr><th>Orphan pages</th><td>${orphanPages.length ? esc(orphanPages.join(', ')) : 'none'}</td></tr><tr><th>Broken edges</th><td>${esc(graph.broken_edge_count || 0)}</td></tr></tbody></table>${checks.length ? `<ul class="reason-list">${checks.map((item) => `<li>${esc(item)}</li>`).join('')}</ul>` : ''}</div>`;
}

function graphShelfSummary(graph, nodes, edges) {
  return [
    `${graph.node_count ?? nodes.length} nodes`,
    `${graph.edge_count ?? edges.length} edges`,
    `${graph.broken_edge_count || 0} broken`,
    `${graph.orphan_page_count || 0} orphans`,
    `readiness: ${graph.readiness || 'unknown'}`
  ].join(' / ');
}

function graphToggleButton(expanded = true) {
  const arrow = expanded ? 'v' : '>';
  const label = expanded ? 'Collapse' : 'Expand';
  return `<button class="copy-btn graph-toggle-btn" type="button" data-graph-toggle="free-core" aria-expanded="${expanded ? 'true' : 'false'}"><span class="graph-toggle-arrow" aria-hidden="true">${arrow}</span> ${label}</button>`;
}

function freeCoreGraphSvg(data) {
  const graph = data.wikiGraph || {};
  const graphNodes = graph.nodes || [];
  const graphEdges = graph.edges || [];
  if (!graphNodes.length) {
    return `<div class="card graph-shelf" data-graph-shelf="free-core"><div class="graph-shelf-header"><div class="graph-title-block"><div class="graph-title-row"><h2>Trust Graph</h2><div class="graph-shelf-actions">${graphToggleButton(true)}</div></div><p class="sub">No graph generated yet.</p></div></div><div class="graph-shelf-body">${emptyState('No free-core graph yet', 'Run graph build after install/import to generate source-of-truth, module, and wiki relations.', 'node .knowledge/tools/build-wiki-graph.js')}</div></div>`;
  }
  const layout = layoutGraph(graphNodes, graphEdges);
  const defs = `<defs><marker id="graph-arrow" viewBox="0 0 10 10" refX="8.5" refY="5" markerWidth="5.5" markerHeight="5.5" orient="auto-start-reverse"><path d="M 0 0 L 10 5 L 0 10 z"></path></marker></defs>`;
  const lanes = [
    ['Source-of-truth order', 104, 56],
    ['Module routing', 292, 258],
    ['Wiki and advisory context', 468, 434]
  ].map(([label, y, labelY]) => `<g class="lane"><line x1="44" y1="${y}" x2="${layout.width - 44}" y2="${y}"></line><text x="48" y="${labelY}">${esc(label)}</text></g>`).join('');
  const edgeMarkup = layout.edges.map((edge) => {
    const relation = edge.relation || edge.type || 'related';
    const valid = edge.valid === false ? ' invalid' : '';
    const bundled = edge.bundled ? ' bundled' : '';
    const countText = edge.bundled ? `\n${edge.count} bundled links\n${esc((edge.edge_ids || []).slice(0, 8).join('\n'))}${edge.count > 8 ? '\n...' : ''}` : '';
    const reasonText = edge.reason || (edge.reasons || []).join(' / ');
    return `<path d="${edgePath(edge)}" class="edge ${relationClass(relation)}${valid}${bundled}" marker-end="url(#graph-arrow)"><title>${esc(relation)}\n${esc(edge.from)} -> ${esc(edge.to)}${countText}${reasonText ? `\n${esc(reasonText)}` : ''}</title></path>`;
  }).join('');
  const nodeMarkup = layout.nodes.map((node) => {
    const detail = graphDetailForNode(node, graph, data);
    const trust = trustClass(detail.trust || node.trust || node.status || 'advisory_only');
    const group = graphGroup(node);
    const label = compactGraphLabel(node, group === 'module' ? 24 : group === 'source_truth' ? 21 : 26);
    const yLabel = group === 'source_truth'
      ? node.y - 25
      : group === 'module'
        ? node.y + ((node.row_index || 0) % 2 === 0 ? 42 : -42)
        : node.y + 38;
    return `<g class="graph-node ${esc(group)}" role="button" tabindex="0" ${graphNodeAttrs(node, detail, detail.trust)}>${graphHitTargetMarkup(node, yLabel)}<circle cx="${node.x.toFixed(1)}" cy="${node.y.toFixed(1)}" r="${node.r}" class="node ${esc(trust)} ${esc(group)}"><title>${esc(node.title || '')}\n${esc(node.id || '')}\ntrust: ${esc(detail.trust || 'advisory_only')}\n${esc(node.description || '')}</title></circle>${graphLabelMarkup(node, node.x, yLabel, label, group)}</g>`;
  }).join('');
  const legendTypes = ['outranks', 'routes', 'documents', 'checks', 'references', 'advisory', 'supports', 'depends_on', 'contradicts'];
  const legend = legendTypes.map((type) => `<span><i class="edge-swatch ${type}"></i>${esc(type)}</span>`).join('');
  const sourceOrder = graph.summary?.source_truth_order || [];
  const summary = graphShelfSummary(graph, graphNodes, graphEdges);
  return `<div class="card graph-shelf" data-graph-shelf="free-core" data-free-core-graph="true"><div class="graph-shelf-header"><div class="graph-title-block"><div class="graph-title-row"><h2>Trust Graph</h2><div class="graph-shelf-actions">${copyButton('node .knowledge/tools/build-wiki-graph.js', 'Copy rebuild command')}${graphToggleButton(true)}</div></div><p class="sub">Source-of-truth order, module routing, wiki relations, and advisory boundaries.</p><small class="graph-shelf-summary">${esc(summary)}</small></div></div><div class="graph-shelf-body"><div class="free-core-graph"><div class="graph-metrics">${graphMetric('nodes', graph.node_count ?? graphNodes.length)}${graphMetric('edges', graph.edge_count ?? graphEdges.length, `${layout.edges.length} visible`)}${graphMetric('broken', graph.broken_edge_count || 0)}${graphMetric('orphans', graph.orphan_page_count || 0)}${graphMetric('readiness', graph.readiness || 'unknown')}</div><div class="legend" aria-label="Graph relation legend">${legend}</div><div class="graph-scroll"><svg class="wiki-svg trust-graph-svg" viewBox="0 0 ${layout.width} ${layout.height}" role="img" aria-label="Trust graph">${defs}${lanes}${edgeMarkup}${nodeMarkup}</svg></div><div class="graph-node-detail" data-graph-detail="true">Select a graph node to inspect incoming/outgoing links, trust reason, evidence, route status, and next actions.</div>${sourceOrder.length ? `<div class="source-order-strip"><strong>Trust order:</strong> ${esc(sourceOrder.join(' > '))}</div>` : ''}${graphEdges.length ? graphInsights(graph) : emptyState('Graph has nodes but no relations', 'Add typed links or rerun the graph builder to restore relation edges.', 'node .knowledge/tools/build-wiki-graph.js')}</div></div></div>`;
}

function legacyGraphSvg(data) {
  const graph = data.wikiGraph || {};
  const graphNodes = graph.nodes || [];
  const graphEdges = graph.edges || [];
  if (!graphNodes.length) {
    return emptyState('No free-core graph yet', 'Run graph build after install/import to generate source-of-truth, module, and wiki relations.', 'node .knowledge/tools/build-wiki-graph.js');
  }
  const layout = layoutGraph(graphNodes, graphEdges);
  const defs = `<defs><marker id="graph-arrow" viewBox="0 0 10 10" refX="8.5" refY="5" markerWidth="5.5" markerHeight="5.5" orient="auto-start-reverse"><path d="M 0 0 L 10 5 L 0 10 z"></path></marker></defs>`;
  const lanes = [
    ['Source-of-truth order', 82],
    ['Module routing', 238],
    ['Wiki and advisory context', 385]
  ].map(([label, y]) => `<g class="lane"><line x1="34" y1="${y}" x2="${layout.width - 34}" y2="${y}"></line><text x="38" y="${y - 26}">${esc(label)}</text></g>`).join('');
  const edgeMarkup = layout.edges.map((edge) => {
    const relation = edge.relation || edge.type || 'related';
    const valid = edge.valid === false ? ' invalid' : '';
    return `<path d="${edgePath(edge)}" class="edge ${esc(relation)}${valid}"><title>${esc(relation)}\n${esc(edge.from)} -> ${esc(edge.to)}</title></path>`;
  }).join('');
  const nodes = layout.nodes.map((node) => {
    const trust = trustClass(node.trust || node.status || 'advisory_only');
    const label = String(node.title || node.page || node.id || '').slice(0, 34);
    const href = hrefForPath(node.id || node.page || '');
    return `<a href="${esc(href)}" class="graph-link"><g class="graph-node"><circle cx="${node.x.toFixed(1)}" cy="${node.y.toFixed(1)}" r="${node.r}" class="node ${esc(trust)}"><title>${esc(node.title || '')}\n${esc(node.id || '')}\ntrust: ${esc(node.trust || 'advisory_only')}</title></circle><text x="${(node.x + node.r + 6).toFixed(1)}" y="${(node.y + 4).toFixed(1)}" class="label">${esc(label)}</text></g></a>`;
  }).join('');
  const legend = ['supports', 'depends_on', 'contradicts', 'related'].map((type) => `<span><i class="edge-swatch ${type}"></i>${esc(type)}</span>`).join('');
  return `<div class="graph-tools"><div class="legend">${legend}</div>${copyButton('node .knowledge/tools/build-wiki-graph.js', 'Copy rebuild command')}</div><svg class="wiki-svg" viewBox="0 0 900 440" role="img" aria-label="Wiki graph">${edges}${nodes}</svg>`;
}

function emptyState(title, text, command) {
  return `<div class="empty-state"><div class="empty-icon">i</div><h3>${esc(title)}</h3><p>${esc(text)}</p>${command ? commandBox(command, 'Copy fix command') : ''}</div>`;
}

function rowAttr(search, filter = '') {
  return ` data-search="${esc(String(search || '').toLowerCase())}" data-filter="${esc(String(filter || '').toLowerCase())}"`;
}

function renderModules(data) {
  const modules = getModules(data);
  if (!modules.length) {
    return emptyState('No modules yet', 'Run ingest to create module routing and cards.', 'node .knowledge/tools/ingest-existing-project.js --merge');
  }
  return `<div class="table-controls"><input data-table-search="modules" aria-label="Filter modules" placeholder="Filter modules by id, path, trust, reason..."><select data-table-filter="modules" aria-label="Filter modules by trust level"><option value="">All trust levels</option><option value="trusted">trusted</option><option value="near_trusted">near_trusted</option><option value="routing_trusted">routing_trusted</option><option value="advisory_only">advisory_only</option><option value="suspect">suspect</option><option value="low_confidence">low_confidence</option><option value="unknown">unknown</option></select></div><table class="filterable" data-table="modules"><thead><tr><th>Module</th><th>Trust</th><th>Confidence</th><th>Why low / next check</th><th>Path</th><th>Card</th></tr></thead><tbody>${modules.map((module) => {
    const trust = module.trust_status || 'unknown';
    const reasons = module.reasons || [];
    const search = [module.module_id, trust, module.confidence, module.path, module.card, reasons.join(' ')].join(' ');
    return `<tr${rowAttr(search, trust)}><td><strong>${esc(module.module_id)}</strong></td><td><span class="pill ${trustClass(trust)}">${esc(trust)}</span></td><td>${esc(module.confidence || '-')}</td><td><ul class="reason-list">${reasons.map((reason) => `<li>${esc(reason)}</li>`).join('')}</ul></td><td>${module.path ? fileLink(module.path, { short: 46 }) : '<span class="muted">-</span>'}</td><td>${fileLink(module.card || `.knowledge/modules/${module.module_id}.json`, { short: 46 })}</td></tr>`;
  }).join('')}</tbody></table>`;
}

function renderRepair(data) {
  const rows = getRepairItems(data).slice(0, 250);
  if (!rows.length) return emptyState('No repair items', 'Nothing is currently queued. Run doctor or ingest after significant changes.', 'node .knowledge/tools/doctor.js');
  return `<div class="table-controls"><input data-table-search="repair" aria-label="Filter repair queue" placeholder="Filter repair queue..."><select data-table-filter="repair" aria-label="Filter repair queue by priority"><option value="">All priorities</option><option value="critical">critical</option><option value="high">high</option><option value="medium">medium</option><option value="low">low</option></select></div><table class="filterable" data-table="repair"><thead><tr><th>Priority</th><th>Status</th><th>Subject</th><th>Artifacts</th><th>Reason</th></tr></thead><tbody>${rows.map((item) => {
    const priority = item.priority || 'medium';
    const search = [priority, item.status, item.subject, item.reason, toArray(item.affected_artifacts).join(' ')].join(' ');
    return `<tr${rowAttr(search, priority)}><td><span class="pill ${trustClass(priority)}">${esc(priority)}</span></td><td>${esc(item.status || 'open')}</td><td>${esc(item.subject)}</td><td>${listLinks(item.affected_artifacts)}</td><td>${esc(item.reason || '-')}</td></tr>`;
  }).join('')}</tbody></table>`;
}

function renderRepairOpportunities(data) {
  const artifact = data.repairOpportunities || data.knowledge_trust?.repair_opportunities || {};
  const rows = Array.isArray(artifact.opportunities) ? artifact.opportunities : [];
  const before = artifact.global?.score ?? 'not measured';
  const after = artifact.global_after?.score ?? 'pending';
  const readinessBefore = artifact.task_readiness?.score ?? 'not measured';
  const readinessAfter = artifact.task_readiness_after?.score ?? 'pending';
  const receipts = data.verificationReceipts || data.knowledge_trust?.verification_receipts || { receipts: [] };
  if (!rows.length) {
    return `${renderMetricStrip([
      ['Global Doctor', before, 'Repository-wide health remains separate from task readiness.'],
      ['Task readiness', readinessBefore, 'Only findings relevant to the current task.']
    ])}${emptyState('No repair opportunities planned', 'Create a task-scoped plan before maintenance. Unrelated debt never expands the task.', 'node .knowledge/tools/repair-on-touch.js plan --task \"describe the task\" --json')}`;
  }
  const relationLabel = {
    direct_overlap: 'Direct task overlap',
    dependency_overlap: 'Required dependency',
    no_overlap: 'Outside current task'
  };
  const statusLabel = {
    selected: 'Selected',
    deferred: 'Deferred',
    repaired: 'Repaired',
    rejected: 'Rejected'
  };
  const body = rows.map((item) => `<tr><td><strong>${esc(item.module_id || 'root')}</strong><small>${esc(item.lifecycle_id || '')}</small></td><td>${esc(item.message || item.reason || item.code)}</td><td>${esc(relationLabel[item.relation_to_current_task] || 'Unknown relation')}</td><td>${esc(item.repair_class || 'manual review')}</td><td>${esc(toArray(item.required_checks).join(', ') || '-')}</td><td>${esc(`${item.estimated_additional_work?.minutes ?? 0} min / ${item.estimated_additional_work?.context_percent ?? 0}% context`)}</td><td>${esc(item.requires_confirmation ? 'Yes' : 'No')}</td><td>${esc(statusLabel[item.status] || item.status || 'Open')}</td></tr>`).join('');
  return `${renderMetricStrip([
    ['Global Doctor before / after', `${before} → ${after}`, 'Repository-wide score is recalculated by Doctor.'],
    ['Task readiness before / after', `${readinessBefore} → ${readinessAfter}`, 'Unrelated findings are excluded but remain visible.'],
    ['Verification receipts', (receipts.receipts || []).length, 'Content-addressed and linked to exact lifecycle findings.']
  ])}<table><thead><tr><th>Module / lifecycle</th><th>Finding</th><th>Task relation</th><th>Repair class</th><th>Required checks</th><th>Estimated work</th><th>Confirm</th><th>Status</th></tr></thead><tbody>${body}</tbody></table>`;
}

function renderRepairSettings(data, options = {}) {
  const repair = data.settings?.repair_on_touch || resolvePolicy({
    context,
    operator: data.settings?.operator_profile || {}
  });
  const configured = repair.configured || DEFAULT_REPAIR_POLICY;
  const cap = repair.policy_cap || {};
  const controls = `<div class="setting-list"><label class="setting-row"><span><strong>Mode</strong><small>Scoped is the default. Extended is advanced and never bypasses safety rules.</small></span>${selectControl('repair-setting-mode', configured.mode || 'scoped', [['off', 'Off'], ['safe-only', 'Safe generated artifacts only'], ['scoped', 'Scoped repair — Recommended'], ['dedicated', 'Dedicated maintenance only'], ['aggressive', 'Extended repair — Advanced']])}</label><label class="setting-row"><span><strong>Maximum findings per task</strong><small>Default: 2.</small></span><input id="repair-setting-max-findings" type="number" min="0" max="100" value="${esc(configured.max_findings_per_task ?? 2)}"></label><label class="setting-row"><span><strong>Additional time budget</strong><small>Minutes. Budget exhaustion never fails the primary task.</small></span><input id="repair-setting-max-minutes" type="number" min="0" max="1440" value="${esc(configured.max_extra_minutes ?? 5)}"></label><label class="setting-row"><span><strong>Additional context budget</strong><small>Percentage. Actual token values remain actual-only telemetry.</small></span><input id="repair-setting-max-context" type="number" min="0" max="100" value="${esc(configured.max_extra_context_percent ?? 10)}"></label><label class="setting-row"><span><strong>Rebuild generated artifacts</strong><small>Allows deterministic routing, index, graph, and report rebuilds.</small></span><input id="repair-setting-rebuild" type="checkbox"${configured.rebuild_generated_artifacts !== false ? ' checked' : ''}></label><label class="setting-row"><span><strong>Confirm critical paths</strong><small>Required by default.</small></span><input id="repair-setting-confirm-critical" type="checkbox"${configured.require_confirmation_for_critical_paths !== false ? ' checked' : ''}></label><label class="setting-row"><span><strong>Confirm security findings</strong><small>Security findings are never opportunistically auto-closed.</small></span><input id="repair-setting-confirm-security" type="checkbox"${configured.require_confirmation_for_security_findings !== false ? ' checked' : ''}></label></div>`;
  const actions = options.live
    ? '<div class="mini-actions"><button class="copy-btn" type="button" data-repair-settings-save="true">Save</button><button class="copy-btn" type="button" data-repair-settings-reset="true">Reset to defaults</button><button class="copy-btn" type="button" data-repair-settings-cancel="true">Cancel</button></div>'
    : commandBox('node .knowledge/tools/repair-on-touch.js settings show', 'Open settings CLI');
  return `<div class="card" id="repair-maintenance-settings"><h2>Maintenance → Opportunistic knowledge repair</h2><p class="sub">Configured mode: <strong>${esc(MODE_LABELS[repair.configured_mode] || repair.configured_mode)}</strong>. Effective mode: <strong>${esc(MODE_LABELS[repair.effective_mode] || repair.effective_mode)}</strong>. Source: ${esc(repair.effective_mode_source || 'built-in default')}.</p><p class="sub">Team-policy restriction: ${esc(cap.active ? `maximum ${MODE_LABELS[cap.max_mode] || cap.max_mode}${cap.restricted ? ' (currently limiting this workspace)' : ''}` : 'none')}.</p><div class="warning-box" data-repair-aggressive-warning="true" hidden><strong>Extended repair warning</strong><p>Extended mode may inspect task-adjacent dependencies. It still cannot change source for health, close security or contradiction findings, or exceed budgets.</p></div>${controls}${actions}</div>`;
}

function renderStale(data) {
  const rows = getStaleItems(data).slice(0, 250);
  if (!rows.length) return emptyState('No stale items', 'Freshness checks have not found stale artifacts.', 'node .knowledge/tools/sync-tracked.js --scan');
  return `<div class="table-controls"><input data-table-search="stale" aria-label="Filter stale items" placeholder="Filter stale items..."><select data-table-filter="stale" aria-label="Filter stale items by status"><option value="">All statuses</option><option value="stale">stale</option><option value="missing">missing</option><option value="changed">changed</option><option value="needs_recheck">needs_recheck</option></select></div><table class="filterable" data-table="stale"><thead><tr><th>Status</th><th>Artifact</th><th>Reason</th><th>Action</th></tr></thead><tbody>${rows.map((item) => {
    const status = item.status || 'stale';
    const search = [status, item.artifact, item.reason, item.action].join(' ');
    return `<tr${rowAttr(search, status)}><td><span class="pill ${trustClass(status)}">${esc(status)}</span></td><td>${fileLink(item.artifact, { short: 70 })}</td><td>${esc(item.reason || '-')}</td><td>${esc(item.action || '-')}</td></tr>`;
  }).join('')}</tbody></table>`;
}

function renderCriticalFiles(data) {
  const rows = getCriticalFiles(data).slice(0, 250);
  if (!rows.length) return emptyState('No critical or important files mapped', 'Run ingest and sync to classify project files.', 'node .knowledge/tools/ingest-existing-project.js --merge');
  return `<div class="table-controls"><input data-table-search="critical" aria-label="Filter critical files" placeholder="Filter files..."><select data-table-filter="critical" aria-label="Filter files by criticality"><option value="">All classes</option><option value="critical">critical</option><option value="important">important</option></select></div><table class="filterable" data-table="critical"><thead><tr><th>Class</th><th>Path</th><th>Modules</th><th>Reason</th></tr></thead><tbody>${rows.map((file) => {
    const cls = file.classification || 'important';
    const search = [cls, file.path, toArray(file.modules).join(' '), file.reason].join(' ');
    return `<tr${rowAttr(search, cls)}><td><span class="pill ${trustClass(cls)}">${esc(cls)}</span></td><td>${fileLink(file.path, { short: 82 })}</td><td>${esc(toArray(file.modules).join(', ') || '-')}</td><td>${esc(file.reason || '-')}</td></tr>`;
  }).join('')}</tbody></table>`;
}

function renderTemplates(data) {
  const templates = data.appliedTemplates.templates || [];
  if (!templates.length) return emptyState('No official templates applied', 'Templates can seed review hints and wiki scaffolding without claiming trust.', 'node .knowledge/tools/apply-template.js --list');
  return `<ul class="template-list">${templates.map((template) => `<li><strong>${esc(template.name || template.id)}</strong><span>${esc(template.status || '')}</span></li>`).join('')}</ul>`;
}

function renderExternal(data) {
  const providers = Array.isArray(data.external.providers)
    ? data.external.providers
    : Object.values(data.external.providers || {});
  if (!providers.length) return emptyState('External memory not checked', 'Run the status command to show optional memory bridges.', 'node .knowledge/tools/external-memory-status.js --json');
  return `<table class="filterable" data-table="external"><thead><tr><th>Provider</th><th>Enabled</th><th>Mode</th><th>Trust role</th><th>Path/source</th><th>Warnings</th></tr></thead><tbody>${providers.map((provider) => {
    const warnings = toArray(provider.warnings).join('; ');
    const search = [provider.provider, provider.mode, provider.path, provider.source, warnings].join(' ');
    return `<tr${rowAttr(search, provider.mode || '')}><td><strong>${esc(provider.provider || 'unknown')}</strong></td><td>${esc(provider.enabled ?? false)}</td><td>${esc(provider.mode || provider.status || 'unknown')}</td><td>${esc(provider.trust_role || 'advisory_only')}</td><td>${esc(provider.path || provider.source || '-')}</td><td>${esc(warnings || '-')}</td></tr>`;
  }).join('')}</tbody></table><div class="mini-actions">${copyButton('node .knowledge/tools/external-memory-status.js --json', 'Copy status command')}${copyButton('node .knowledge/tools/external/pinecone-search.js "query" --dry-run', 'Copy dry-run search')}</div>`;
}

function renderMemoryProviders(data) {
  const providers = Array.isArray(data.external.providers)
    ? data.external.providers
    : Object.values(data.external.providers || {});
  const byId = new Map(providers.map((provider) => [provider.provider_id || provider.provider, provider]));
  const mem0 = byId.get('mem0-oss') || { status: 'runtime_not_installed', license_spdx: 'Apache-2.0', trust_effect: 'advisory_only' };
  const pinecone = byId.get('pinecone') || { status: 'disabled', license_spdx: 'Service-TOS', trust_effect: 'advisory_only' };
  const legacy = data.external.legacy_providers_detected || [];
  const card = (title, provider, body, actions = '') => {
    const warnings = toArray(provider.warnings).join('; ');
    return `<div class="signal-card"><strong>${esc(title)}</strong><span>${esc(provider.status || 'available')}</span><p>${body}</p><table class="kv"><tr><th>Version</th><td>${esc(provider.version || provider.version_pin || 'n/a')}</td></tr><tr><th>License</th><td>${esc(provider.license_spdx || 'n/a')}</td></tr><tr><th>Data/source</th><td>${esc(provider.data_path || provider.path || provider.source_url || 'n/a')}</td></tr><tr><th>Trust</th><td>${esc(provider.trust_effect || provider.trust_role || 'advisory_only')}</td></tr><tr><th>Warnings</th><td>${esc(warnings || 'none')}</td></tr></table><div class="mini-actions">${actions}</div></div>`;
  };
  const mem0Actions = [
    copyButton('node .knowledge/tools/memory-provider.js install mem0-oss --version mem0ai==2.0.4 --yes-i-reviewed-license --json', 'Copy install'),
    copyButton('node .knowledge/tools/memory-provider.js setup mem0-oss --live --json', 'Copy setup'),
    copyButton('node .knowledge/tools/memory-mem0.js health --adapter live --json', 'Copy health'),
    copyButton('node .knowledge/tools/memory-mem0.js add --adapter live --yes-live-memory --text "Release note: Mem0 is advisory-only external memory" --scope repo --json', 'Copy add example'),
    copyButton('node .knowledge/tools/memory-mem0.js search "advisory memory" --adapter live --yes-live-memory --json', 'Copy search example'),
    copyButton('node .knowledge/tools/memory-mem0.js recall "advisory memory" --adapter live --yes-live-memory --json', 'Copy recall example')
  ].join('');
  const mem0Warnings = toArray(mem0.warnings).join('; ');
  const mem0RuntimeVersion = mem0.runtime_version
    ? `${mem0.runtime_version} / expected ${mem0.expected_runtime_version || mem0.version_pin || 'n/a'}`
    : `not checked / expected ${mem0.expected_runtime_version || mem0.version_pin || 'n/a'}`;
  const mem0Card = `<div class="signal-card"><strong>Mem0 OSS - guided onboarding</strong><span>${esc(mem0.status || 'runtime_not_installed')}</span><p>Recommended optional universal backend. Setup is one guided command; status is offline-safe; live operations remain explicit external-memory actions.</p><table class="kv"><tr><th>Receipt</th><td>${esc(mem0.receipt_present ? 'exists' : 'missing')}</td></tr><tr><th>Runtime</th><td>${esc(mem0.runtime_available ? 'available' : 'missing')}</td></tr><tr><th>Runtime health</th><td>${esc(mem0.runtime_health || 'not_available')}</td></tr><tr><th>Runtime version</th><td>${esc(mem0RuntimeVersion)}</td></tr><tr><th>Boundary</th><td>${esc(mem0.trust_effect || mem0.trust_role || 'advisory_only')}</td></tr><tr><th>Data path</th><td>${esc(mem0.data_path || mem0.path || 'n/a')}</td></tr><tr><th>Last live health</th><td>${esc(mem0.last_live_health_check || mem0.runtime_status_checked_at || 'not checked')}</td></tr><tr><th>Warning</th><td>live add writes external memory</td></tr><tr><th>Warnings</th><td>${esc(mem0Warnings || 'none')}</td></tr></table><div class="mini-actions">${mem0Actions}</div></div>`;
  const policy = data.external.source_of_truth_policy || {};
  const legacyCard = legacy.length
    ? card('Legacy Claude MEM - advisory legacy only', legacy[0], 'Legacy artifacts are shown only for migration/archive awareness and cannot raise trust.', copyButton('node .knowledge/tools/memory-provider.js migrate-legacy --json', 'Write deprecation note'))
    : '';
  return `<div class="empty-state"><h3>External memory is advisory</h3><p>Code, tests and evidence outrank memory. Memory cannot raise trust automatically.</p></div><div class="signal-grid" style="margin-top:12px">${card('.knowledge Source of Truth', { status: 'authoritative', license_spdx: 'Apache-2.0', trust_effect: 'source_of_truth', data_path: data.context?.projectKnowledgeRoot }, `Curated repo-local knowledge stays in modules, evidence, wiki and decisions. External memory policy: source_of_truth=${esc(policy.external_memory_source_of_truth ?? false)}, can_raise_trust=${esc(policy.external_memory_can_raise_trust ?? false)}.`)}${mem0Card}${card('Pinecone - optional vector/cloud retrieval', pinecone, 'Optional vector/cloud retrieval provider for teams already using Pinecone. Status stays offline and never needs an API key just to render.', `${copyButton('node .knowledge/tools/memory-provider.js status pinecone --json', 'Pinecone Status')}${copyButton('node .knowledge/tools/external/pinecone-search.js "query" --dry-run', 'Dry-run Search')}${copyButton('node .knowledge/tools/memory-provider.js preview pinecone --json', 'Pinecone Preview')}`)}<div class="signal-card"><strong>Graphiti - future optional temporal graph</strong><span>not included in free core</span><p>Temporal graph provider contracts are not part of this install asset. Free core keeps external memory advisory.</p></div><div class="signal-card"><strong>Zep - future optional managed/BYOC memory</strong><span>not included in free core</span><p>Managed memory provider contracts are not part of this install asset. Free core keeps the advisory policy boundary.</p></div>${legacyCard}</div><div class="mini-actions">${copyButton('node .knowledge/tools/memory-provider.js status-all --json', 'Memory Status')}${copyButton('node .knowledge/tools/memory-provider.js list --json', 'List Providers')}${fileLink('maintenance/external_memory_status.json', { short: 54 })}</div>`;
}

function renderQuickActions(options = {}) {
  const live = options.live === true;
  const liveActions = Array.isArray(options.actions) ? options.actions : [];
  const actions = [
    ['Run Doctor', 'node .knowledge/tools/doctor.js --json'],
    ['Refresh Release', 'node .knowledge/tools/flow.js release --no-color --json'],
    ['Build Inspector', 'node .knowledge/tools/build-visual-inspector.js --json'],
    ['Search', 'node .knowledge/tools/search-knowledge.js "<query>"'],
    ['Generate PR Summary', 'node .knowledge/tools/generate-pr-summary.js --json'],
    ['Review PR Impact', 'node .knowledge/tools/pr-impact.js --json'],
    ['Team Status', 'node .knowledge/tools/team-status.js --team-root <teamRoot> --json'],
    ['Memory Status', 'node .knowledge/tools/memory-provider.js status-all --json'],
    ['Setup Mem0', 'node .knowledge/tools/memory-provider.js setup mem0-oss --live --json']
  ];
  const staticButtons = actions.map(([label, command]) => `<button type="button" class="action-card" data-copy="${esc(command)}"><span>${esc(label)}</span><code>${esc(command)}</code></button>`);
  const liveButtons = liveActions.map((action) => {
    const command = action.command || action.id;
    const locked = action.risk === 'extension_locked' ? ' locked' : '';
    return `<button type="button" class="action-card${locked}" data-action="${esc(action.id)}"><span>${esc(action.label || action.id)}</span><code>${esc(action.risk || 'local')} - ${esc(action.description || command)}</code></button>`;
  });
  const repairPrompt = repairAgentPrompt(options.data || {});
  const repairButton = `<button type="button" class="action-card repair-agent-action" data-copy="${esc(repairPrompt)}"><span>Repair trust with an agent</span><code>kb-repair-trust prompt</code></button>`;
  const buttons = live ? [...liveButtons, repairButton] : [...staticButtons, repairButton];
  const modeCopy = live
    ? 'Live mode uses the token-protected local action API; copy fallback remains available for agent prompts.'
    : 'Static mode copies exact allowlisted commands only; it never runs local commands silently.';
  return `<div class="panel"><p class="sub">${esc(modeCopy)}</p><div class="quick-actions">${buttons.join('')}</div></div>`;
}

function renderUpdates(data) {
  const status = data.updateStatus || {};
  const latest = status.latest_version || '-';
  const current = status.current_version || '-';
  const state = status.status || 'never_checked';
  const asset = status.asset_name || 'knowledge-v<version>.zip';
  const stateClass = state === 'update_available' ? ' available' : state === 'check_failed' ? ' failed' : '';
  const manual = [
    ['Check Updates', 'node .knowledge/tools/check-updates.js --json'],
    ['Dry-run Update', 'node .knowledge/tools/update-system-files.js --from <new-knowledge-root> --target-knowledge-root .knowledge --dry-run --json'],
    ['Apply Update', 'node .knowledge/tools/update-system-files.js --from <new-knowledge-root> --target-knowledge-root .knowledge --apply --yes --json'],
    ['Verify Upgrade', 'node .knowledge/tools/update-system-files.js --verify-upgrade --json']
  ];
  const autoCheck = status.auto_check_on_inspector_open !== false;
  const note = status.update_check_note || 'Live Inspector checks for new releases when it starts. Updates are never applied automatically.';
  return `<div class="update-banner${stateClass}" id="updateBanner" data-current-version="${esc(current)}" data-latest-version="${esc(latest)}" data-asset-name="${esc(asset)}" data-auto-check="${autoCheck ? 'true' : 'false'}"><div><strong>Update status: <span id="updateState">${esc(state)}</span></strong><p class="sub" id="updateSummary">Current <span data-update-current>${esc(current)}</span> / Latest <span data-update-latest>${esc(latest)}</span> / Asset <span data-update-asset>${esc(asset)}</span>. <span data-update-note>${esc(note)}</span></p></div><div class="mini-actions"><button class="copy-btn mode-btn" type="button" id="updateAutoCheckMode" data-update-mode="auto-check" aria-pressed="${autoCheck ? 'true' : 'false'}">${autoCheck ? 'Auto-check: On' : 'Auto-check: Off'}</button><button class="copy-btn danger-btn" type="button" id="updateApplyButton" data-update-action="apply"${state === 'update_available' ? '' : ' disabled'}>${state === 'update_available' ? 'Update' : (state === 'check_failed' ? 'Check failed' : 'Up to date')}</button></div></div><pre class="markdown-preview" id="updateOutput">No live update action has run in this Inspector tab yet.</pre><div class="quick-actions">${manual.map(([label, command]) => `<button class="action-card" type="button" data-copy="${esc(command)}"><span>${esc(label)}</span><code>${esc(command)}</code></button>`).join('')}</div>`;
}

function renderUpdatesV2(data, options = {}) {
  const status = data.updateStatus || {};
  const latest = status.latest_version || '-';
  const current = status.current_version || '-';
  const state = status.status || 'never_checked';
  const asset = status.asset_name || 'knowledge-v<version>.zip';
  const stateClass = state === 'update_available' ? ' available' : state === 'check_failed' ? ' failed' : '';
  const canUpdate = state === 'update_available';
  const buttonLabel = canUpdate ? 'Update' : (state === 'check_failed' ? 'Check failed' : 'Up to date');
  const autoCheck = status.auto_check_on_inspector_open !== false;
  const modeLabel = autoCheck ? 'Auto-check: On' : 'Auto-check: Off';
  const modeTitle = autoCheck
    ? 'Live Inspector checks for new releases on start. It never applies updates automatically.'
    : 'Automatic update checks on Inspector start are disabled.';
  const note = status.update_check_note || modeTitle;
  const modeDisabled = options.live ? '' : ' disabled';
  return `<div class="update-banner${stateClass}" id="updateBanner" data-current-version="${esc(current)}" data-latest-version="${esc(latest)}" data-asset-name="${esc(asset)}" data-auto-check="${autoCheck ? 'true' : 'false'}"><div><strong>Update status: <span id="updateState">${esc(state)}</span></strong><p class="sub" id="updateSummary">Current <span data-update-current>${esc(current)}</span> / Latest <span data-update-latest>${esc(latest)}</span> / Asset <span data-update-asset>${esc(asset)}</span>. <span data-update-note>${esc(note)}</span></p></div><div class="mini-actions"><button class="copy-btn mode-btn" type="button" id="updateAutoCheckMode" data-update-mode="auto-check" aria-pressed="${autoCheck ? 'true' : 'false'}" title="${esc(modeTitle)}"${modeDisabled}>${esc(modeLabel)}</button><button class="copy-btn danger-btn" type="button" id="updateApplyButton" data-update-action="apply"${canUpdate ? '' : ' disabled'}>${esc(buttonLabel)}</button></div></div><pre class="markdown-preview" id="updateOutput" hidden></pre>`;
}

function renderRouting(data) {
  const routing = data.routing || {};
  const taskRouting = data.taskRouting || { tasks: [] };
  const first = routing.first_read_strategy?.read_first || '.knowledge/maintenance/routing_bundle.json';
  const modules = routing.modules || [];
  const tasks = taskRouting.tasks || [];
  const taskRows = tasks.length
    ? `<table><thead><tr><th>Task / current</th><th>Readiness / claim</th><th>Workspace comparison</th><th>Modules and paths</th><th>Sources / safety</th></tr></thead><tbody>${tasks.map((task) => `<tr><td><strong>${esc(task.task || task.task_scope_hash?.slice(0, 12) || '-')}</strong><br><small>snapshot ${esc(task.snapshot_hash || 'unavailable')}<br>pointer ${esc(task.pointer_consistent ? 'consistent' : 'unavailable')}</small></td><td>${esc(task.task_readiness)}<br><small>claim ${esc(task.claim_eligible ? 'eligible' : 'ineligible')}${task.claim_ineligible_reasons?.length ? `: ${esc(task.claim_ineligible_reasons.join(', '))}` : ''}</small></td><td><small>kind ${esc(task.comparison_kind || 'unavailable')}<br>baseline ${esc(task.workspace_baseline?.recipe_id || '-')}.${esc(task.workspace_baseline?.recipe_version || '-')} / ${esc(task.workspace_baseline_valid ? 'valid' : 'invalid')}<br>${esc(task.estimate_text)}<br>narrowing ${esc(JSON.stringify(task.workspace_narrowing || {}))}</small></td><td><small>selected: ${esc((task.selected_reasons || []).map((item) => `${item.module_id}:${item.reason}`).join(', ') || '-') }<br>excluded: ${esc((task.excluded_reasons || []).map((item) => `${item.module_id}:${item.reason}`).join(', ') || '-') }<br>paths: ${esc((task.relevant_paths || []).map((item) => `${item.path}:${item.git_status || item.status || '-'}`).join(', ') || '-')}<br>omitted: ${esc((task.omitted_paths || []).map((item) => item.path).join(', ') || '-')}</small></td><td><small>required sources ${esc(task.required_sources?.complete ? 'complete' : 'blocked')}: ${esc((task.required_sources?.issues || []).map((item) => `${item.path}:${item.path_state}`).join(', ') || 'none')}<br>Git: ${esc((task.git_diff_paths || []).map((item) => `${item.path}:${item.status}`).join(', ') || 'none')}<br>blockers: ${esc((task.safety_overrides || []).join(', ') || 'none')}<br>task debt ${esc(task.task_debt)} / workspace debt ${esc(task.workspace_debt)}<br>continuation ${esc(task.high_risk_continuation?.required ? 'required' : 'none')}</small></td></tr>`).join('')}</tbody></table>`
    : '<p class="sub">No task snapshot is available. Create an explicit task scope before using task routing.</p>';
  return `<table class="kv"><tr><th>First read</th><td>${esc(first)}</td></tr><tr><th>Mode</th><td>${esc(data.context.mode)}</td></tr><tr><th>Global modules</th><td>${esc(modules.length)}</td></tr><tr><th>Task snapshots</th><td>${esc(tasks.length)}</td></tr><tr><th>High risk</th><td>${esc((routing.high_risk_modules || []).join(', ') || '-')}</td></tr><tr><th>Source of truth</th><td>${esc((routing.source_of_truth_order || []).join(' > '))}</td></tr></table>${taskRows}<div class="mini-actions">${copyButton('node .knowledge/tools/build-routing-bundle.js --json', 'Copy rebuild command')}${copyButton('node .knowledge/tools/task-routing.js list --json', 'List task snapshots')}</div>`;
}

function renderPrPreview(data) {
  const prPath = path.join(stateRoot, 'maintenance', 'pr_summary.md');
  const markdown = fs.existsSync(prPath) ? fs.readFileSync(prPath, 'utf8').slice(0, 2200) : '';
  if (!markdown) return emptyState('No PR summary yet', 'Generate a reviewer-facing local markdown summary.', 'node .knowledge/tools/generate-pr-summary.js --json');
  return `<pre class="markdown-preview">${esc(markdown)}</pre><div class="mini-actions">${copyButton('node .knowledge/tools/generate-pr-summary.js --json', 'Copy regenerate command')}</div>`;
}

function renderPrImpactPreview(data) {
  const impact = data.prImpact || {};
  const changed = impact.changed_files || [];
  const modules = impact.affected_modules || [];
  const warnings = impact.policy_warnings || [];
  if (!changed.length) {
    return emptyState('No PR impact yet', 'Run PR Impact to map git changes to modules, trust, freshness, criticality and repair debt.', 'node .knowledge/tools/pr-impact.js --json');
  }
  const stats = [
    ['Changed files', changed.length],
    ['Affected modules', modules.length],
    ['Policy warnings', warnings.length],
    ['Repair overlaps', impact.repair_delta?.count ?? 0]
  ].map(([label, value]) => `<div class="stat"><div class="num">${esc(value)}</div><div class="cap">${esc(label)}</div></div>`).join('');
  const warningRows = warnings.length
    ? `<table><thead><tr><th>Severity</th><th>File/module</th><th>Warning</th><th>Action</th></tr></thead><tbody>${warnings.map((warning) => `<tr><td><span class="pill ${trustClass(warning.severity)}">${esc(warning.severity)}</span></td><td>${esc(warning.file || warning.module_id || '-')}</td><td>${esc(warning.message || warning.id)}</td><td>${esc(warning.action || '-')}</td></tr>`).join('')}</tbody></table>`
    : '<div class="empty-state"><h3>No policy warnings</h3><p>The current diff has no PR Impact warnings.</p></div>';
  const fileRows = `<table><thead><tr><th>Changed file</th><th>Status</th><th>Modules</th><th>Runtime</th></tr></thead><tbody>${changed.map((file) => `<tr><td>${fileLink(file.path, { short: 72 })}</td><td>${esc(file.status || '-')}</td><td>${esc((file.modules || []).join(', ') || '-')}</td><td>${esc(file.generated_runtime ? 'yes' : 'no')}</td></tr>`).join('')}</tbody></table>`;
  return `<div class="grid stats">${stats}</div><h3>Policy warnings</h3>${warningRows}<h3>Changed files</h3>${fileRows}<div class="mini-actions">${copyButton('node .knowledge/tools/pr-impact.js --json', 'Review PR Impact')}${fileLink('maintenance/pr_impact.json', { short: 54 })}</div>`;
}

function renderTeamMode(data) {
  const ctx = data.context || {};
  const active = data.team?.workspaces_total ?? 0;
  const warnings = Array.from(new Set([...(ctx.warnings || []), ...(data.team?.warnings || [])]));
  return `<table class="kv"><tr><th>Mode</th><td>${esc(ctx.mode || 'repo')}</td></tr><tr><th>Repo ID</th><td>${esc(ctx.repoId || '-')}</td></tr><tr><th>Workspace</th><td>${esc(ctx.workspaceId || '-')}</td></tr><tr><th>Agent</th><td>${esc(ctx.agentId || '-')}</td></tr><tr><th>Target root</th><td>${esc(ctx.targetRoot || '-')}</td></tr><tr><th>State root</th><td>${esc(ctx.stateRoot || '-')}</td></tr><tr><th>Branch/head</th><td>${esc(`${ctx.branch || 'unknown'} / ${(ctx.headSha || '').slice(0, 12) || 'unknown'}`)}</td></tr><tr><th>Active workspaces</th><td>${esc(active)}</td></tr><tr><th>Flow lock owner</th><td>${esc(data.lockOwner ? `${data.lockOwner.agentId || data.lockOwner.pid} on ${data.lockOwner.branch || 'unknown'}` : 'none')}</td></tr><tr><th>Warnings</th><td>${esc(warnings.join('; ') || '-')}</td></tr></table><div class="mini-actions">${copyButton('node .knowledge/tools/worktree-status.js --json', 'Copy worktree check')}${copyButton('node .knowledge/tools/flow.js release --exclusive --json', 'Copy exclusive release')}${copyButton('node .knowledge/tools/team-status.js --team-root <teamRoot> --json', 'Copy team status')}</div>`;
}

function renderTeamModePanel(data) {
  const ctx = data.context || {};
  const active = data.team?.workspaces_total ?? 0;
  const warnings = Array.from(new Set([...(ctx.warnings || []), ...(data.team?.warnings || [])]));
  return `<table class="kv"><tr><th>Mode</th><td>${esc(ctx.mode || 'repo')}</td></tr><tr><th>Repo ID</th><td>${esc(ctx.repoId || '-')}</td></tr><tr><th>Workspace ID</th><td>${esc(ctx.workspaceId || '-')}</td></tr><tr><th>Agent ID</th><td>${esc(ctx.agentId || '-')}</td></tr><tr><th>Target root</th><td>${esc(ctx.targetRoot || '-')}</td></tr><tr><th>State root</th><td>${esc(ctx.stateRoot || '-')}</td></tr><tr><th>Branch/head</th><td>${esc(`${ctx.branch || 'unknown'} / ${(ctx.headSha || '').slice(0, 12) || 'unknown'}`)}</td></tr><tr><th>Dirty status</th><td>${esc(ctx.git?.dirty ? 'dirty' : 'clean or unknown')}</td></tr><tr><th>Lock owner</th><td>${esc(data.lockOwner ? `${data.lockOwner.agentId || data.lockOwner.pid} on ${data.lockOwner.branch || 'unknown'}` : 'none')}</td></tr><tr><th>Active workspaces</th><td>${esc(active)}</td></tr><tr><th>Stale locks</th><td>${esc(data.team?.stale_locks_total ?? 0)}</td></tr><tr><th>Warnings</th><td>${esc(warnings.join('; ') || '-')}</td></tr></table><div class="mini-actions">${copyButton('node .knowledge/tools/team-pr-summary.js --team-root <teamRoot> --workspace-id <id> --json', 'Team PR Summary')}${copyButton('node .knowledge/tools/worktree-status.js --json', 'Worktree Check')}${copyButton('node .knowledge/tools/team-status.js --team-root <teamRoot> --json', 'Team Status')}</div><div class="empty-state" style="margin-top:12px"><h3>Pro team dashboard boundary</h3><p>Free Inspector shows local status. Pro Inspector adds multi-repo governance, history, ownership and fleet policy.</p></div>`;
}

function renderBranchDiagnostics(data, renderOptions = {}) {
  const ctx = data.context || {};
  const git = ctx.git || {};
  const branchState = git.branches || { active: ctx.branch || 'unknown', selected: ctx.branch || 'unknown', branches: [] };
  if (!git.is_git_repo) {
    return `<div class="card branch-diagnostics" data-branch-diagnostics="true"><h2>Git Branch Diagnostics</h2><p class="sub">No Git repository detected for this target root.</p></div>`;
  }
  const active = branchState.active || ctx.branch || 'unknown';
  const branches = (branchState.branches || []).length
    ? branchState.branches
    : [{ name: active, current: true, head_sha: ctx.headSha || null, upstream: null, worktree_path: branchState.worktree_root || null, active_worktree: true }];
  const selected = branches.find((branch) => branch.current) || branches.find((branch) => branch.name === active) || branches[0];
  const dirty = git.dirty ? `dirty (${git.dirty_summary?.changed ?? 0} changed, ${git.dirty_summary?.staged ?? 0} staged)` : 'clean';
  const branchOptions = branches.map((branch) => `<option value="${esc(branch.name)}"${branch.name === selected.name ? ' selected' : ''}>${esc(branch.name)}${branch.name === active ? ' (active)' : ''}</option>`).join('');
  const trustRepair = renderOptions.showSimpleTrust === true ? renderSimpleTrustActions(data, renderOptions, true) : '';
  return `<div class="card branch-diagnostics" data-branch-diagnostics="true"><div class="branch-diagnostics-head"><div><h2>Git Branch Diagnostics</h2><p class="sub">Default target is the active branch. Switching here changes Inspector diagnostics only; it does not run <code>git checkout</code>.</p></div><label class="branch-picker">Diagnostic branch<select data-branch-select="true">${branchOptions}</select></label></div><div class="branch-diagnostics-body"><div><table class="kv"><tr><th>Selected branch</th><td data-branch-field="branch">${esc(selected.name || 'unknown')}</td></tr><tr><th>Active branch</th><td data-branch-field="active">${esc(active)}</td></tr><tr><th>Head SHA</th><td data-branch-field="head">${esc((selected.head_sha || '').slice(0, 12) || 'unknown')}</td></tr><tr><th>Upstream</th><td data-branch-field="upstream">${esc(selected.upstream || 'none')}</td></tr><tr><th>Worktree</th><td data-branch-field="worktree">${esc(selected.worktree_path || 'not checked out')}</td></tr><tr><th>Dirty status</th><td data-branch-field="dirty">${esc(selected.name === active ? dirty : 'not checked in current worktree')}</td></tr><tr><th>Note</th><td data-branch-field="note">${esc(selected.name === active ? 'Diagnostics are using the active worktree.' : (selected.worktree_path ? 'Branch is checked out in another worktree.' : 'Branch is not checked out in this worktree.'))}</td></tr></table><div class="mini-actions">${copyButton('node .knowledge/tools/worktree-status.js --json', 'Worktree Check')}${copyButton('node .knowledge/inspector.js', 'Open Live Inspector')}</div></div>${trustRepair}</div></div>`;
}

function renderProWaitlist() {
  return `<div class="pro-preview-intro"><div><strong>Inspector Pro waitlist</strong><span>Inspector Pro is planned as a separate team workflow layer. The local Inspector remains included in the free core.</span></div><a class="pro-waitlist-button" style="letter-spacing:0" href="https://pro2pilot.com/inspector/" target="_blank" rel="noopener">Join Inspector Pro waitlist</a></div>`;
}

function selectControl(id, value, options) {
  return `<select id="${esc(id)}">${options.map(([optionValue, label]) => `<option value="${esc(optionValue)}"${selected(value, optionValue)}>${esc(label)}</option>`).join('')}</select>`;
}

function agentOptionKey(agent) {
  return String(agent?.agent_instance_id || agent?.id || agent?.agent_runtime_id || agent?.session_id || '').trim();
}

function agentOptionLabel(agent) {
  return String(agent?.agent_display_name || agent?.label || agent?.agent_runtime_label || agent?.agent_instance_id || agent?.agent_runtime_id || 'Connected agent').trim();
}

function normalizeConnectedAgent(agent = {}) {
  const id = agentOptionKey(agent);
  if (!id) return null;
  return {
    id,
    label: agentOptionLabel(agent),
    runtime: agent.agent_runtime_id || agent.runtime || agent.detected_agent_runtime || '',
    runtime_label: agent.agent_runtime_label || agent.runtime_label || agent.agent_runtime_id || '',
    status: agent.status || 'available',
    session_id: agent.session_id || '',
    branch: agent.branch || '',
    workspace_id: agent.workspace_id || ''
  };
}

function connectedAgents(data, settings) {
  const profile = settings.operator_profile || DEFAULT_OPERATOR_PROFILE;
  const registrySessions = [
    ...(data.agentRegistry?.sessions || []),
    ...(data.agent_activity?.registry?.sessions || [])
  ];
  const preferred = registrySessions
    .filter((session) => ['running', 'waiting'].includes(session.status))
    .concat(registrySessions.slice(-25).reverse())
    .concat(toArray(profile.connected_agents));
  const fallbackRuntime = profile.detected_agent_runtime || data.context?.agentId || data.generated_by || 'local-agent';
  preferred.push({
    agent_instance_id: profile.selected_agent_id || fallbackRuntime,
    agent_runtime_id: fallbackRuntime,
    agent_display_name: fallbackRuntime,
    status: registrySessions.length ? 'saved' : 'current'
  });
  const byId = new Map();
  for (const candidate of preferred) {
    const normalized = normalizeConnectedAgent(candidate);
    if (normalized && !byId.has(normalized.id)) byId.set(normalized.id, normalized);
  }
  return [...byId.values()];
}

function selectedAgentId(settings, agents) {
  const profile = settings.operator_profile || DEFAULT_OPERATOR_PROFILE;
  const preferred = profile.selected_agent_id || profile.detected_agent_runtime || '';
  if (preferred && agents.some((agent) => agent.id === preferred || agent.runtime === preferred)) {
    return agents.find((agent) => agent.id === preferred || agent.runtime === preferred).id;
  }
  return agents[0]?.id || 'local-agent';
}

function onboardingSettingsForAgent(settings, agentId) {
  const profile = settings.operator_profile || DEFAULT_OPERATOR_PROFILE;
  const autonomy = settings.autonomy_policy || DEFAULT_AUTONOMY_POLICY;
  const agent = settings.agent_policy || DEFAULT_AGENT_POLICY;
  const footer = settings.report_footer || DEFAULT_REPORT_FOOTER;
  const profileOverride = profile.agent_overrides?.[agentId] || {};
  const autonomyOverride = autonomy.agent_overrides?.[agentId] || {};
  const agentOverride = agent.agent_overrides?.[agentId] || {};
  const footerOverride = footer.agent_overrides?.[agentId] || {};
  const repair = settings.repair_on_touch?.configured ||
    operatorRepairSettings(profile) ||
    DEFAULT_REPAIR_POLICY;
  return {
    user_mode: profileOverride.user_mode || profile.user_mode || 'simple',
    agents_can_do_without_asking: autonomyOverride.agents_can_do_without_asking || autonomy.agents_can_do_without_asking || DEFAULT_AUTONOMY_POLICY.agents_can_do_without_asking,
    concurrent_work_policy: agentOverride.concurrent_work_policy || agent.concurrent_work_policy || 'Safe Queue',
    merge_policy: agentOverride.merge_policy || agent.merge_policy || 'Manual Only',
    report_footer_mode: footerOverride.mode || footer.mode || 'compact',
    repair_mode: repair.mode || 'scoped',
    repair_max_findings: repair.max_findings_per_task ?? 2,
    repair_max_extra_minutes: repair.max_extra_minutes ?? 5,
    repair_max_extra_context_percent: repair.max_extra_context_percent ?? 10,
    repair_rebuild_generated_artifacts: repair.rebuild_generated_artifacts !== false,
    repair_require_confirmation_for_critical_paths: repair.require_confirmation_for_critical_paths !== false
  };
}

function onboardingAgentSettingsMap(settings, agents) {
  return Object.fromEntries(agents.map((agent) => [agent.id, onboardingSettingsForAgent(settings, agent.id)]));
}

function connectedAgentSummary(agent) {
  const bits = [
    agent.runtime ? `runtime ${agent.runtime}` : '',
    agent.status ? `status ${agent.status}` : '',
    agent.branch ? `branch ${agent.branch}` : '',
    agent.workspace_id ? `workspace ${agent.workspace_id}` : ''
  ].filter(Boolean);
  return bits.join(' / ') || 'No active session metadata yet.';
}

function renderOnboarding(data, options = {}) {
  const settings = data.settings || {};
  const onboarding = settings.onboarding || onboardingState(settings);
  const agents = connectedAgents(data, settings);
  const selectedId = selectedAgentId(settings, agents);
  const selectedAgent = agents.find((agent) => agent.id === selectedId) || agents[0] || normalizeConnectedAgent({ agent_instance_id: 'local-agent' });
  const selectedSettings = onboardingSettingsForAgent(settings, selectedId);
  const agentSettings = onboardingAgentSettingsMap(settings, agents);
  const agentOptions = agents.map((agent) => `<option value="${esc(agent.id)}"${agent.id === selectedId ? ' selected' : ''}>${esc(agent.label)}${agent.status ? ` (${esc(agent.status)})` : ''}</option>`).join('');
  const expanded = onboarding.required === true;
  const saveControl = options.live
    ? '<button class="copy-btn" type="button" data-onboarding-save="true">Save setup</button>'
    : copyButton('node .knowledge/inspector.js', 'Open live setup');
  const status = onboarding.completed ? `Completed${onboarding.completed_at ? ` at ${onboarding.completed_at}` : ''}` : `Required: ${onboarding.reason || 'not_completed'}`;
  return `<div class="card onboarding-card${expanded ? ' requires-setup' : ''}" id="onboarding-wizard" data-onboarding-wizard="true" data-onboarding-expanded="${expanded ? 'true' : 'false'}" data-onboarding-agents="${esc(JSON.stringify(agents))}" data-onboarding-agent-settings="${esc(JSON.stringify(agentSettings))}"><button class="onboarding-toggle" type="button" data-onboarding-toggle="true"><span>First-run setup</span><small>${esc(status)}</small></button><div class="onboarding-body"${expanded ? '' : ' hidden'}><p class="sub">Use safe defaults or tune each connected agent before local agents write reports.</p><div class="setting-list"><label class="setting-row"><span><strong>Connected agent</strong><small>Select an active or recently connected agent. Settings below apply to that agent.</small></span><div class="agent-picker"><select id="onboarding-agent" data-onboarding-agent-select="true">${agentOptions}</select><small data-onboarding-agent-summary="true">${esc(connectedAgentSummary(selectedAgent))}</small></div></label><label class="setting-row"><span><strong>User mode</strong><small>Simple keeps summaries plain; Advanced shows raw evidence.</small></span>${selectControl('onboarding-user-mode', selectedSettings.user_mode, [['simple', 'Simple'], ['advanced', 'Advanced']])}</label><label class="setting-row"><span><strong>What can agents do without asking?</strong><small>Default is safe local checks and reports.</small></span>${selectControl('onboarding-permission', selectedSettings.agents_can_do_without_asking, [['run checks and reports', 'Run checks and reports'], ['ask before every action', 'Ask before every action'], ['run safe local actions', 'Run safe local actions']])}</label><label class="setting-row"><span><strong>Concurrent work policy</strong><small>Safe Queue avoids overlapping writes by default.</small></span>${selectControl('onboarding-concurrency', selectedSettings.concurrent_work_policy, [['Safe Queue', 'Safe Queue'], ['Observe', 'Observe'], ['Guided', 'Guided'], ['Active Sessions', 'Active Sessions'], ['Parallel Worktrees', 'Parallel Worktrees']])}</label><label class="setting-row"><span><strong>Merge policy</strong><small>Manual Only keeps releases under your control.</small></span>${selectControl('onboarding-merge', selectedSettings.merge_policy, [['Manual Only', 'Never merge automatically'], ['Assisted Merge', 'Assisted Merge'], ['Auto PR', 'Auto PR']])}</label><label class="setting-row"><span><strong>Agent report footer</strong><small>Controls trust footer and restore action in reports.</small></span>${selectControl('onboarding-footer', selectedSettings.report_footer_mode, [['compact', 'Compact + restore action'], ['full', 'Full'], ['only_when_trust_incomplete', 'Only when trust incomplete'], ['off', 'Off']])}</label></div><div class="mini-actions">${saveControl}</div></div></div>`;
}

function renderRepairFirstRun(data, options = {}) {
  const settings = data.settings || {};
  const onboarding = settings.onboarding || onboardingState(settings);
  const repair = settings.repair_on_touch || resolvePolicy({ context, operator: settings.operator_profile || {} });
  const configured = repair.configured || DEFAULT_REPAIR_POLICY;
  const expanded = onboarding.required === true;
  const saveButton = options.live
    ? '<button class="copy-btn" type="button" data-onboarding-save="true">Save complete setup</button>'
    : copyButton('node .knowledge/inspector.js', 'Open live setup');
  return `<div class="card onboarding-card${expanded ? ' requires-setup' : ''}" id="repair-first-run-step"><button class="onboarding-toggle" type="button" data-repair-setup-toggle="true"><span>Opportunistic knowledge repair</span><small>Scoped repair — Recommended</small></button><div class="onboarding-body"${expanded ? '' : ' hidden'} data-repair-setup-body="true"><p class="sub">When an agent already verifies uncertain repository context during normal work, .knowledge can preserve that verification instead of making the next agent repeat it.</p><p class="sub">This does not chase a perfect Doctor score, expand the task into unrelated modules, or change source code for health. Critical-path and security repair still require confirmation, and the mode remains editable in Inspector.</p><div class="setting-list"><label class="setting-row"><span><strong>Mode</strong><small>Extended repair is advanced and requires an explicit warning confirmation.</small></span>${selectControl('onboarding-repair-mode', configured.mode || 'scoped', [['off', 'Off'], ['safe-only', 'Safe generated artifacts only'], ['scoped', 'Scoped repair — Recommended'], ['dedicated', 'Dedicated maintenance only'], ['aggressive', 'Extended repair — Advanced']])}</label><label class="setting-row"><span><strong>Maximum findings per task</strong><small>Maintenance stops at the limit without failing the primary task.</small></span><input id="onboarding-repair-max-findings" type="number" min="0" max="100" value="${esc(configured.max_findings_per_task ?? 2)}"></label><label class="setting-row"><span><strong>Maximum additional minutes</strong><small>Default: five minutes.</small></span><input id="onboarding-repair-max-minutes" type="number" min="0" max="1440" value="${esc(configured.max_extra_minutes ?? 5)}"></label><label class="setting-row"><span><strong>Maximum additional context</strong><small>Percentage budget; telemetry reports actual tokens separately.</small></span><input id="onboarding-repair-max-context" type="number" min="0" max="100" value="${esc(configured.max_extra_context_percent ?? 10)}"></label><label class="setting-row"><span><strong>Rebuild generated artifacts</strong><small>Routing, indexes, graphs, and derived reports.</small></span><input id="onboarding-repair-rebuild" type="checkbox"${configured.rebuild_generated_artifacts !== false ? ' checked' : ''}></label><label class="setting-row"><span><strong>Require confirmation for critical paths</strong><small>Enabled by default and never bypassed by Extended mode.</small></span><input id="onboarding-repair-confirm-critical" type="checkbox"${configured.require_confirmation_for_critical_paths !== false ? ' checked' : ''}></label></div><div class="mini-actions">${saveButton}</div></div></div>`;
}

function metricSeverity(label, value) {
  const text = `${label} ${value}`.toLowerCase();
  const numeric = Number(value);
  if (Number.isFinite(numeric)) {
    if (/score|readiness|quality/.test(text) && numeric < 70) return 'critical';
    if (/score|readiness|quality/.test(text) && numeric < 90) return 'warning';
    if (/repair pressure|stale items|policy warnings/.test(text) && numeric > 0) return numeric > 25 ? 'critical' : 'warning';
  }
  if (/(critical|broken|failed|failure|blocked)/.test(text)) return 'critical';
  if (/(degraded|warning|needs|stale|suspect|low_confidence|missing|not_generated|unknown)/.test(text)) return 'warning';
  return 'ok';
}

function renderMetricCard(label, value, body) {
  const severity = metricSeverity(label, value);
  return `<div class="stat metric-card ${severity}"><div class="severity-dot" aria-hidden="true"></div><div class="num">${esc(value)}</div><div class="cap">${esc(label)}</div><p class="sub">${esc(body)}</p></div>`;
}

function renderTrustRepairPrompt(data, label = 'Trust repair prompt for agent') {
  const prompt = repairAgentPrompt(data);
  return `<button type="button" class="copy-btn" data-copy="${esc(prompt)}">${esc(label)}</button>`;
}

function renderSimpleTrustActions(data, options = {}, compact = false) {
  const restore = options.live
    ? '<button type="button" class="copy-btn" data-action="trust.restore.safe">Restore Trust</button>'
    : copyButton('node .knowledge/tools/restore-trust.js --safe --json', 'Restore Trust');
  return `<div class="${compact ? 'simple-trust-actions compact' : 'card simple-trust-actions'}"><h2>Simple Mode trust repair</h2><p class="sub">Restore generated trust artifacts first. If the score does not improve, hand the repair prompt to an agent.</p><div class="mini-actions">${restore}${renderTrustRepairPrompt(data, 'Repair trust with an agent')}</div></div>`;
}

function renderActionResultPanel(options = {}) {
  if (!options.live) return '';
  return `<div class="card result-panel is-collapsed" data-result-panel="true"><button type="button" class="result-toggle" data-result-toggle="true"><span>Action Result</span><small data-result-summary="true">Collapsed until an action runs</small></button><pre id="result" hidden>Session is local. Buttons use allowlisted actions only.</pre></div>`;
}

function renderOutcomePanel({ title, verdict, body, tone = 'ok', actions = '' } = {}) {
  return `<section class="outcome-panel ${esc(tone)}" data-outcome-panel="true"><div><span class="eyebrow">Plain answer</span><h3>${esc(title || 'Status')}</h3><strong>${esc(verdict || 'Ready')}</strong><p>${esc(body || 'Open the advanced details below when you need exact evidence, commands, or JSON.')}</p></div>${actions ? `<div class="outcome-actions">${actions}</div>` : ''}</section>`;
}

function renderPageHeader({ title, summary, chips = [] } = {}) {
  const chipHtml = chips.filter(Boolean).map((chip) => `<span class="chip">${esc(chip)}</span>`).join('');
  return `<div class="page-header" data-page-header="true"><div><span class="eyebrow">.knowledge Inspector</span><h2>${esc(title || 'Inspector')}</h2>${summary ? `<p class="sub">${esc(summary)}</p>` : ''}</div>${chipHtml ? `<div class="chips page-chips">${chipHtml}</div>` : ''}</div>`;
}

function renderAdvancedShelf(id, title, body, summary = 'Advanced details for agents and maintainers.') {
  return `<details class="advanced-shelf" data-advanced-shelf="${esc(id)}"><summary><span>${esc(title)}</span><small>${esc(summary)}</small></summary><div class="advanced-shelf-body">${body}</div></details>`;
}

function renderMetricStrip(items = []) {
  return `<div class="grid stats metric-grid compact-top-metrics metric-strip" data-metric-strip="true">${items.map(([label, value, body]) => renderMetricCard(label, value, body)).join('')}</div>`;
}

function renderNextActionPanel({ title = 'Next action', body = 'Use the recommended action first.', primary = '', secondary = '' } = {}) {
  return `<aside class="next-action-panel" data-next-action-panel="true"><span class="eyebrow">${esc(title)}</span><p>${esc(body)}</p><div class="mini-actions">${primary || ''}${secondary || ''}</div></aside>`;
}

function renderFilePreviewDrawer() {
  return `<aside class="file-preview-drawer" data-file-preview-drawer="true" aria-live="polite" hidden><div class="file-preview-head"><div><span class="eyebrow">File preview</span><strong data-file-preview-title="true">No file selected</strong><small data-file-preview-meta="true">Next action links open here in live mode.</small></div><button type="button" class="copy-btn" data-file-preview-close="true">Close</button></div><div class="mini-actions file-preview-actions"><button type="button" class="copy-btn" data-file-preview-copy-path="true" disabled>Copy path</button><button type="button" class="copy-btn" data-file-preview-copy-code="true" disabled>Copy code -g</button><a class="copy-btn graph-action-link" href="#" data-file-preview-fallback="true">Open raw</a></div><pre class="file-preview-body" data-file-preview-body="true">Select a module card, .knowledge file, or spec file from Next action.</pre></aside>`;
}

function renderAppShell({ data, nav, sections, qualityScore, branch, head, updateState, turnOffButton }) {
  return `<div class="app">
<aside class="sidebar"><div class="brand">.knowledge Inspector ${esc(systemVersion)}</div><nav>${nav}</nav></aside>
<div class="content">
<header class="topbar"><div class="topbar-main"><h1>.knowledge Inspector ${esc(systemVersion)}</h1><div class="chips"><span class="chip">Repo: ${esc(data.context?.repoId || 'local')}</span><span class="chip">Team Mode: ${esc(data.context?.mode || 'repo')}</span><span class="chip">Doctor score: ${esc(qualityScore)}</span><span class="chip">Branch: ${esc(branch)}</span><span class="chip">Head SHA: ${esc(head)}</span><span class="chip" data-update-chip>Update: ${esc(updateState)}</span><span class="chip">No cloud</span><span class="chip">No telemetry</span><span class="chip">Build time: ${esc(data.generated_at)}</span></div></div><div class="topbar-actions">${turnOffButton}</div></header>
<main>${sections}</main>
</div></div>`;
}

function inspectorDesignCss() {
  return `
:root{--bg-0:#0a0a0c;--bg-1:#0f0f12;--bg-2:#14141a;--bg-3:#1a1a22;--line-soft:rgba(255,255,255,.06);--line-strong:rgba(255,255,255,.12);--fg-main:#ededf0;--fg-dim:#a4a4ad;--fg-mute:#6b6b75;--amber:oklch(.78 .13 75);--trusted:oklch(.78 .11 165);--info:oklch(.76 .1 230);--advisory:oklch(.76 .09 290);--blocker:oklch(.72 .15 35)}
body{background:linear-gradient(180deg,var(--bg-0),#090d10 58%,var(--bg-0));color:var(--fg-main);letter-spacing:0}
body:before{content:"";position:fixed;inset:0;pointer-events:none;background-image:linear-gradient(var(--line-soft) 1px,transparent 1px),linear-gradient(90deg,var(--line-soft) 1px,transparent 1px);background-size:44px 44px;mask-image:linear-gradient(180deg,#000b,transparent 78%);opacity:.28}
.app{grid-template-columns:244px minmax(0,1fr);background:transparent}
.sidebar{background:linear-gradient(180deg,#0b1014,#090c0f);border-right:1px solid var(--line-strong);padding:16px;z-index:6}
.brand{font-size:16px;letter-spacing:0;margin-bottom:14px}
.tab-btn{min-height:40px;border-radius:8px;color:var(--fg-dim);font-weight:700}
.tab-btn.active{background:#12191d;color:var(--fg-main);border-color:var(--line-strong);box-shadow:inset 3px 0 0 var(--amber)}
.tab-btn:hover{background:#11171b;border-color:var(--line-strong)}
.topbar{background:rgba(10,13,16,.88);border-bottom:1px solid var(--line-strong);backdrop-filter:blur(14px)}
.topbar h1{font-size:20px;letter-spacing:0}
.chip{border-color:var(--line-strong);background:#10161a;color:var(--fg-dim);border-radius:999px}
main{max-width:1500px;margin:0 auto;padding:18px}
.page-header{display:flex;justify-content:space-between;align-items:flex-start;gap:16px;margin-bottom:14px}
.page-header h2{font-size:24px;letter-spacing:0;margin:0}
.page-chips{justify-content:flex-end}
.eyebrow{display:block;color:var(--fg-mute);font:700 11px/1.2 ui-monospace,SFMono-Regular,Menlo,monospace;text-transform:uppercase;letter-spacing:.08em;margin-bottom:6px}
.outcome-panel{display:flex;justify-content:space-between;align-items:flex-start;gap:18px;border:1px solid var(--line-strong);background:linear-gradient(180deg,#101519,#0b0f12);border-radius:8px;padding:16px;margin:0 0 14px;box-shadow:0 20px 60px #0006}
.outcome-panel h3{margin:0 0 8px;font-size:14px;color:var(--fg-dim)}
.outcome-panel strong{display:block;font-size:20px;letter-spacing:0}
.outcome-panel p{margin:6px 0 0;color:var(--fg-dim);max-width:760px}
.outcome-panel.ok{border-left:4px solid var(--trusted)}.outcome-panel.warn{border-left:4px solid var(--amber)}.outcome-panel.info{border-left:4px solid var(--info)}.outcome-panel.blocked{border-left:4px solid var(--blocker)}
.outcome-actions{display:flex;flex-wrap:wrap;justify-content:flex-end;gap:8px;min-width:210px}
.card,.panel,.stat,.signal-card,.empty-state,.graph-node-detail,.source-order-strip,.graph-insights,.update-banner,.setting-row,.simple-trust-actions.compact,.advanced-shelf,.next-action-panel,.file-preview-drawer{border-radius:8px;background:#0d1317;border:1px solid var(--line-soft);box-shadow:none}
.card,.panel{padding:14px}
.two{grid-template-columns:minmax(0,1.14fr) minmax(320px,.86fr)}
.metric-strip{margin:0 0 14px}
.metric-card{background:#0d1317;border-left:4px solid var(--line-strong)}
.metric-card.ok{border-left-color:var(--trusted)}.metric-card.warning{border-left-color:var(--amber)}.metric-card.critical{border-left-color:var(--blocker)}
.copy-btn,.pro-waitlist-button{border-radius:8px;background:#11191e;border-color:var(--line-strong);color:var(--fg-main);min-height:34px}
.copy-btn:hover,.pro-waitlist-button:hover{border-color:var(--amber);text-decoration:none}
.quick-actions{grid-template-columns:repeat(auto-fit,minmax(210px,1fr))}
.action-card{background:#0d1317;border-color:var(--line-soft);border-radius:8px}
.action-card span{font-size:13px}.action-card code,.cmd code,.file-link{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
.advanced-shelf{margin:10px 0;overflow:hidden}
.advanced-shelf summary{display:flex;justify-content:space-between;gap:12px;align-items:center;cursor:pointer;padding:11px 12px;color:var(--fg-main)}
.advanced-shelf summary span{font-weight:800}.advanced-shelf summary small{color:var(--fg-mute);font-size:12px}
.advanced-shelf-body{border-top:1px solid var(--line-soft);padding:12px}
.next-action-panel{padding:14px;align-self:start;position:sticky;top:94px}
.next-action-panel p{color:var(--fg-dim);margin:0 0 10px}
.file-preview-drawer{position:fixed;right:16px;bottom:16px;width:min(720px,calc(100vw - 32px));max-height:min(72vh,760px);z-index:30;padding:0;background:#0b1014;box-shadow:0 24px 80px #000b}
.file-preview-head{display:flex;justify-content:space-between;gap:12px;padding:14px;border-bottom:1px solid var(--line-soft)}
.file-preview-head strong,.file-preview-head small{display:block}.file-preview-head small{color:var(--fg-mute);margin-top:3px}
.file-preview-actions{padding:10px 14px;margin:0;border-bottom:1px solid var(--line-soft)}
.file-preview-actions a{text-decoration:none}
.file-preview-body{margin:0;max-height:48vh;overflow:auto;background:#070b0e;color:#dce8df;border:0;border-radius:0;padding:14px;white-space:pre-wrap;font:12px/1.45 ui-monospace,SFMono-Regular,Menlo,monospace}
.graph-detail-grid{grid-template-columns:1fr}
.graph-detail-summary{border:1px solid var(--line-soft);background:#0b1115;border-radius:8px;padding:10px;margin-bottom:10px}
.graph-detail-summary p{margin:6px 0;color:var(--fg-dim)}
.graph-detail-actions{gap:8px}
.trust-graph-svg{background:#080d10}
.graph-scroll{border:1px solid var(--line-soft);background:#080d10}
.tab-panel{scroll-margin-top:90px}
@media(max-width:980px){.app{display:block}.sidebar{position:sticky;top:0;height:auto;display:flex;align-items:center;gap:8px;overflow:auto;padding:10px}.brand{white-space:nowrap;margin:0 10px 0 0}.tab-btn{width:auto;white-space:nowrap}.topbar{position:relative}.page-header,.outcome-panel{display:block}.outcome-actions{justify-content:flex-start;margin-top:12px}.two{grid-template-columns:1fr}.next-action-panel{position:relative;top:auto}.trust-graph-svg{min-width:900px}.file-preview-drawer{left:10px;right:10px;bottom:10px;width:auto}}
@media(max-width:640px){main{padding:12px}.chips{gap:6px}.page-header h2{font-size:20px}.outcome-panel strong{font-size:17px}.setting-row{grid-template-columns:1fr}.cmd{display:block}.cmd .copy-btn{margin-top:8px;width:100%}}
`;
}

function render(data) {
  const counts = trustCounts(data.trust);
  const countsHtml = counts.map((count) => `<div class="stat ${trustClass(count.key)}"><div class="num">${count.count}</div><div class="cap">${esc(count.key)}</div></div>`).join('');
  const moduleCount = (data.modules.modules || []).length;
  const repairCount = (data.repair.queue || []).length;
  const staleCount = (data.stale.items || data.stale.stale_items || []).length;
  const wikiEdges = (data.wikiGraph.edges || []).length;
  const searchDocs = (data.searchIndex.documents || []).length;
  const qualityScore = data.quality.quality_score ?? data.quality.score ?? '-';
  const secretStatus = data.secretScan.status || 'not_run';
  const wikiLintScore = data.wikiLint.quality_score ?? '-';
  const wikiLintStatus = data.wikiStatus || canonicalWikiStatus(data.wikiLint, data.wikiGraph);
  const wikiLintSeverity = metricSeverity('wiki structural status', wikiLintStatus);
  const generated = esc(data.generated_at);
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>.knowledge Visual Inspector</title>
<style>
:root{--bg:#060a13;--bg2:#0b1120;--panel:#0e1629;--panel2:#111d35;--line:#25324d;--line2:#33415f;--text:#ecf3ff;--muted:#9ca9c4;--soft:#c6d3ee;--green:#2fd17c;--yellow:#f5c451;--orange:#ff8a4c;--red:#ef4444;--blue:#56b7ff;--purple:#b692f6;--cyan:#67e8f9;--shadow:0 24px 80px #0008}*{box-sizing:border-box}html{scroll-behavior:smooth}body{margin:0;background:radial-gradient(1200px 700px at 12% -10%,#1f3b7c66 0,transparent 55%),radial-gradient(900px 520px at 90% 5%,#4c1d9544 0,transparent 55%),linear-gradient(180deg,#070b14 0,#0a1020 38%,#070b14 100%);color:var(--text);font:14px/1.48 Inter,ui-sans-serif,system-ui,-apple-system,Segoe UI,Arial}a{color:#9fd3ff;text-decoration:none}a:hover{text-decoration:underline}header{padding:34px 36px 20px;border-bottom:1px solid #22304a;background:linear-gradient(180deg,#0c1428cc,#0c142855);backdrop-filter:blur(10px);position:sticky;top:0;z-index:10}h1{font-size:34px;letter-spacing:-.04em;margin:0 0 8px}h2{font-size:20px;margin:0 0 16px}h3{margin:16px 0 8px}.sub{color:var(--muted)}main{padding:24px 36px 56px}.topbar{display:flex;justify-content:space-between;gap:20px;align-items:flex-start}.quick-actions{display:grid;grid-template-columns:repeat(3,minmax(180px,1fr));gap:12px;margin-top:18px}.action-card{cursor:pointer;text-align:left;border:1px solid var(--line);background:linear-gradient(180deg,#111c34,#0a1326);border-radius:16px;padding:13px;color:var(--text);box-shadow:0 10px 32px #0004}.action-card:hover{border-color:#4d6ba2;transform:translateY(-1px)}.action-card span{display:block;font-weight:800;margin-bottom:5px}.action-card code{display:block;color:#9fd3ff;font-size:11px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.grid{display:grid;gap:16px}.stats{grid-template-columns:repeat(6,minmax(120px,1fr));}.two{grid-template-columns:1.18fr .82fr}.card{background:linear-gradient(180deg,var(--panel),var(--panel2));border:1px solid var(--line);border-radius:20px;padding:18px;box-shadow:var(--shadow)}.stat{background:#08101f;border:1px solid #1d2a43;border-radius:16px;padding:14px;min-height:82px}.stat.trusted{border-color:#164e36}.stat.suspect,.stat.low_confidence{border-color:#5d1f2b}.num{font-size:31px;font-weight:900;letter-spacing:-.03em}.cap{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.08em}.mini-stat-row{display:flex;gap:10px;flex-wrap:wrap}.mini-stat{background:#08101f;border:1px solid #1d2a43;border-radius:12px;padding:9px 11px;color:#dbeafe}.mini-stat strong{display:block;font-size:18px}section{margin:18px 0}.pill{display:inline-flex;align-items:center;padding:3px 9px;border-radius:999px;background:#23304a;color:#d8e3ff;font-size:12px;white-space:nowrap}.critical,.high,.suspect,.low_confidence{background:#4a1824;color:#ffd2d8}.important,.medium,.near_trusted{background:#423112;color:#ffe7ad}.trusted{background:#123a2a;color:#aaf0c4}.routing_trusted{background:#143657;color:#b7dcff}.advisory_only{background:#2b2545;color:#e4dcff}.unknown,.low{background:#1e293b;color:#d8e3ff}.table-controls{display:flex;gap:10px;align-items:center;margin:0 0 12px}.table-controls input,.table-controls select,.global-filter{background:#07101f;border:1px solid #25304a;border-radius:12px;padding:10px;color:var(--text);min-width:0}.table-controls input{flex:1}.global-filter{width:100%;margin-top:14px}table{width:100%;border-collapse:collapse}td,th{padding:10px 9px;border-bottom:1px solid #1f2b44;text-align:left;vertical-align:top}th{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.06em}.reason-list{margin:0;padding-left:18px}.reason-list li{margin-bottom:4px;color:#cad6ed}.link-list{display:flex;flex-direction:column;gap:4px}.file-link{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px}.edge{fill:none;stroke:#55627e;stroke-width:1.6;opacity:.75}.edge.invalid{stroke-dasharray:5 5;opacity:.5}.edge.contradicts{stroke:var(--red)}.edge.supports{stroke:var(--green)}.edge.depends_on{stroke:var(--yellow)}.edge.references,.edge.related{stroke:#7c8aa7}.node{fill:var(--purple);stroke:white;stroke-width:1}.node.trusted{fill:var(--green)}.node.routing_trusted{fill:var(--blue)}.node.suspect,.node.low_confidence{fill:var(--red)}.label{font-size:10px;fill:#dbe7ff;paint-order:stroke;stroke:#06101f;stroke-width:3px}.wiki-svg{width:100%;height:440px;background:radial-gradient(circle at 50% 45%,#12213a,#06101f 70%);border-radius:16px;border:1px solid #1f2b44}.graph-tools{display:flex;justify-content:space-between;align-items:center;gap:12px;margin-bottom:12px}.legend{display:flex;flex-wrap:wrap;gap:12px;color:var(--muted);font-size:12px}.edge-swatch{display:inline-block;width:22px;height:3px;border-radius:99px;background:#7c8aa7;margin-right:6px;vertical-align:middle}.edge-swatch.supports{background:var(--green)}.edge-swatch.depends_on{background:var(--yellow)}.edge-swatch.contradicts{background:var(--red)}.empty-state{border:1px dashed #33415f;border-radius:16px;background:#07101f;padding:24px;text-align:center;color:var(--muted)}.empty-state h3{color:var(--text)}.empty-icon{font-size:28px;color:var(--blue);margin-bottom:8px}.cmd{display:flex;gap:10px;align-items:center;background:#050b16;border:1px solid #1f2b44;border-radius:12px;padding:10px;margin-top:12px;text-align:left}.cmd code{flex:1;color:#bce0ff;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.copy-btn{border:1px solid #3a4a6b;background:#0e1b32;color:#e8eefc;border-radius:10px;padding:8px 10px;cursor:pointer}.copy-btn:hover{border-color:#79b7ff}.mini-actions{display:flex;flex-wrap:wrap;gap:8px;margin-top:12px}.template-list{margin:0;padding-left:18px}.template-list li{margin-bottom:8px}.template-list span{color:var(--muted);margin-left:8px}.kv th{width:150px}.markdown-preview{white-space:pre-wrap;max-height:420px;overflow:auto;background:#050b16;border:1px solid #1f2b44;border-radius:14px;padding:14px;color:#dbeafe}.signal-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}.signal-card{border:1px solid #2a3958;background:#07101f;border-radius:12px;padding:11px}.signal-card.active{border-color:#2fd17c;background:#0b2018}.signal-card strong,.signal-card span{display:block}.signal-card span{color:#9ca9c4;font-size:11px;text-transform:uppercase;letter-spacing:.06em}.signal-card p{color:#c6d3ee;margin:8px 0 10px}.toast{position:fixed;right:18px;bottom:18px;background:#123a2a;color:#bcf5cf;border:1px solid #21885c;padding:12px 14px;border-radius:12px;box-shadow:var(--shadow);opacity:0;transform:translateY(8px);transition:.18s}.toast.show{opacity:1;transform:translateY(0)}@media(max-width:1100px){.stats,.two,.quick-actions{grid-template-columns:1fr 1fr}}@media(max-width:720px){.stats,.two,.quick-actions,.signal-grid{grid-template-columns:1fr}main,header{padding-left:18px;padding-right:18px}.topbar{display:block}.table-controls{display:block}.table-controls input,.table-controls select{width:100%;margin-bottom:8px}}
.pro-waitlist-button{letter-spacing:0}
</style>
</head>
<body>
<header><div class="topbar"><div><h1>.knowledge Visual Inspector</h1><div class="sub">Generated ${generated} / source of truth remains current code and tests.</div></div><div class="mini-stat-row"><div class="mini-stat"><strong>${esc(qualityScore)}</strong>quality</div><div class="mini-stat"><strong>${esc(moduleCount)}</strong>modules</div><div class="mini-stat"><strong>${esc(searchDocs)}</strong>search docs</div><div class="mini-stat"><strong>${esc(secretStatus)}</strong>secret scan</div></div></div><input class="global-filter" id="globalFilter" placeholder="Filter all tables by module, path, trust, command, reason..."></header>
<main>
<section>${renderQuickActions()}</section>
<section class="grid stats">${countsHtml}<div class="stat"><div class="num">${esc(qualityScore)}</div><div class="cap">quality</div></div><div class="stat metric-card ${wikiLintSeverity}"><div class="severity-dot" aria-hidden="true"></div><div class="num">${esc(wikiLintStatus)}</div><div class="cap">wiki status / score ${esc(wikiLintScore)}</div></div><div class="stat"><div class="num">${esc(repairCount)}</div><div class="cap">repair queue</div></div><div class="stat"><div class="num">${esc(staleCount)}</div><div class="cap">stale items</div></div><div class="stat"><div class="num">${esc(wikiEdges)}</div><div class="cap">wiki edges</div></div></section>
<section class="grid two"><div class="card"><h2>Routing Bundle View</h2>${renderRouting(data)}</div><div class="card"><h2>Team Mode</h2>${renderTeamMode(data)}</div></section>
<section>${freeCoreGraphSvg(data)}</section>
<section class="grid two"><div class="card"><h2>Memory Providers</h2><p class="sub">Optional advisory context, not truth.</p>${renderMemoryProviders(data)}<h2 style="margin-top:24px">Applied Templates</h2>${renderTemplates(data)}</div><div class="card"><h2>Modules <span class="sub">/ with low-confidence explanations</span></h2>${renderModules(data)}</div></section>
<section class="grid two"><div class="card"><h2>Repair Queue</h2>${renderRepair(data)}</div><div class="card"><h2>Stale Items</h2>${renderStale(data)}</div></section>
<section class="card"><h2>Critical / Important Files</h2>${renderCriticalFiles(data)}</section>
<section class="grid two"><div class="card"><h2>PR Summary Preview</h2>${renderPrPreview(data)}</div><div class="card"><h2>Inspector Pro waitlist</h2>${renderProWaitlist(data)}</div></section>
</main>
<div id="toast" class="toast">Copied</div>
<script>
const toast = document.getElementById('toast');
function showToast(text){ toast.textContent = text || 'Copied'; toast.classList.add('show'); setTimeout(()=>toast.classList.remove('show'), 1400); }
function copyText(text){ if(navigator.clipboard && navigator.clipboard.writeText){ navigator.clipboard.writeText(text).then(()=>showToast('Copied command')).catch(()=>fallbackCopy(text)); } else fallbackCopy(text); }
function fallbackCopy(text){ const el=document.createElement('textarea'); el.value=text; document.body.appendChild(el); el.select(); document.execCommand('copy'); el.remove(); showToast('Copied command'); }
function escapeHtmlClient(value){return String(value||'').replace(/[&<>"']/g,(ch)=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]))}
function graphToggleHtml(collapsed){return '<span class="graph-toggle-arrow" aria-hidden="true">'+(collapsed?'>':'v')+'</span> '+(collapsed?'Expand':'Collapse')}
function setGraphShelf(id,collapsed){const shelf=document.querySelector('[data-graph-shelf="'+id+'"]');if(!shelf)return;shelf.classList.toggle('is-collapsed',collapsed);const button=shelf.querySelector('[data-graph-toggle]');if(button){button.innerHTML=graphToggleHtml(collapsed);button.setAttribute('aria-expanded',collapsed?'false':'true')}try{localStorage.setItem('knowledge.graph.'+id+'.collapsed',collapsed?'1':'0')}catch{}}
function initGraphShelves(){document.querySelectorAll('[data-graph-shelf]').forEach((shelf)=>{const id=shelf.getAttribute('data-graph-shelf');let collapsed=false;try{collapsed=localStorage.getItem('knowledge.graph.'+id+'.collapsed')==='1'}catch{}setGraphShelf(id,collapsed)})}
function graphList(items,empty,formatter){const values=Array.isArray(items)?items:[];if(!values.length)return '<p class="muted">'+escapeHtmlClient(empty)+'</p>';return '<ul>'+values.map((item)=>'<li>'+formatter(item)+'</li>').join('')+'</ul>'}
function graphEdgeText(edge){return '<b>'+escapeHtmlClient(edge.relation||'related')+'</b> '+escapeHtmlClient(edge.from||'')+' -> '+escapeHtmlClient(edge.to||'')+(edge.source?' <small>'+escapeHtmlClient(edge.source)+'</small>':'')+(edge.reason?'<em>'+escapeHtmlClient(edge.reason)+'</em>':'')}
function graphArtifacts(values,empty){return graphList(values,empty,(item)=>escapeHtmlClient(item))}
function inspectorFileHref(action){if(liveMode&&sessionToken&&action.path)return '/api/files/open?path='+encodeURIComponent(action.path)+'&token='+encodeURIComponent(sessionToken);return action.href||'#'}
function graphAction(action){if(action.href){const rawPath=action.path||'';return '<a class="copy-btn graph-action-link" href="'+escapeHtmlClient(inspectorFileHref(action))+'" data-open-path="'+escapeHtmlClient(rawPath)+'" data-open-label="'+escapeHtmlClient(action.label||'Open')+'">'+escapeHtmlClient(action.label||'Open')+'</a>'}if(action.command)return '<button class="copy-btn" type="button" data-copy="'+escapeHtmlClient(action.command)+'">'+escapeHtmlClient(action.label||'Copy')+'</button>';return '<span class="pill">'+escapeHtmlClient(action.label||'Action')+'</span>'}
function graphStatusText(status){const s=status||{};const bits=['node status: '+(s.node_status||'unknown'),s.broken?'broken':'not broken',s.orphan?'orphan':'not orphan',s.stale?'stale':'not stale'];return bits.join(' / ')}
function showGraphNodeDetail(node){const detail=document.querySelector('[data-graph-detail="true"]');if(!detail)return;let payload=null;try{payload=JSON.parse(node.getAttribute('data-graph-detail-json')||'null')}catch{}const group=node.getAttribute('data-graph-group')||payload?.type||'other';const title=payload?.title||node.getAttribute('data-graph-title')||node.getAttribute('data-graph-id')||'Graph node';const trust=payload?.trust||node.getAttribute('data-graph-trust')||'advisory_only';const pathValue=payload?.path||node.getAttribute('data-graph-path')||'';const command=node.getAttribute('data-graph-command')||'node .knowledge/tools/restore-trust.js --safe --json';const moduleId=node.getAttribute('data-graph-module')||'';if(group==='module'){const input=document.querySelector('[data-table-search="modules"]');if(input&&moduleId){input.value=moduleId;applyFilters('modules')}}if(!payload){detail.innerHTML='<strong>'+escapeHtmlClient(title)+'</strong><span>Type: '+escapeHtmlClient(group)+' / Trust: '+escapeHtmlClient(trust)+'</span>'+(pathValue?'<span>Path: '+escapeHtmlClient(pathValue)+'</span>':'')+'<code>'+escapeHtmlClient(command)+'</code>';return}const v=payload.verification||{};detail.innerHTML='<div class="graph-detail-head"><strong>'+escapeHtmlClient(title)+'</strong><span>Type: '+escapeHtmlClient(group)+' / Trust: '+escapeHtmlClient(trust)+(pathValue?' / Path: '+escapeHtmlClient(pathValue):'')+'</span>'+(payload.advisory_note?'<span class="graph-advisory">'+escapeHtmlClient(payload.advisory_note)+'</span>':'')+'</div><div class="graph-detail-grid"><section><h4>Incoming links</h4>'+graphList(payload.incoming,'No incoming links for this node.',graphEdgeText)+'</section><section><h4>Outgoing links</h4>'+graphList(payload.outgoing,'No outgoing links for this node.',graphEdgeText)+'</section><section><h4>Why trust is this</h4><p>'+escapeHtmlClient(payload.trust_reason||'Trust comes from graph metadata; verify before behavior edits.')+'</p>'+(payload.why_route?'<p>'+escapeHtmlClient(payload.why_route)+'</p>':'')+'</section><section><h4>Evidence / tests / code</h4><b>Evidence</b>'+graphArtifacts(v.evidence,'No evidence JSON listed.')+'<b>Tests</b>'+graphArtifacts(v.tests,'No tests listed.')+'<b>Code</b>'+graphArtifacts(v.code,'No code/module files listed.')+(v.gaps&&v.gaps.length?'<p class="muted">'+escapeHtmlClient(v.gaps.join(' '))+'</p>':'')+'</section><section><h4>Status</h4><p>'+escapeHtmlClient(graphStatusText(payload.status))+'</p>'+graphArtifacts(payload.status?.stale_items||[],'No stale items matched this node.')+'</section><section><h4>Next action</h4><div class="graph-detail-actions">'+(payload.next_actions||[]).map(graphAction).join('')+'</div></section></div>'}
document.addEventListener('click', (event)=>{ const graphToggle=event.target.closest('[data-graph-toggle]'); if(graphToggle){const id=graphToggle.getAttribute('data-graph-toggle'); const shelf=document.querySelector('[data-graph-shelf="'+id+'"]'); setGraphShelf(id,!shelf?.classList.contains('is-collapsed')); return;} const graphNode=event.target.closest('[data-graph-node]'); if(graphNode){showGraphNodeDetail(graphNode); return;} const btn=event.target.closest('[data-copy]'); if(btn) copyText(btn.getAttribute('data-copy')); });
document.addEventListener('keydown',(event)=>{const graphNode=event.target.closest?.('[data-graph-node]');if(graphNode&&(event.key==='Enter'||event.key===' ')){event.preventDefault();showGraphNodeDetail(graphNode)}});
function applyFilters(tableName){ const searchInput=document.querySelector('[data-table-search="'+tableName+'"]'); const select=document.querySelector('[data-table-filter="'+tableName+'"]'); const global=document.getElementById('globalFilter'); const q=((searchInput&&searchInput.value)||'').toLowerCase(); const g=(global.value||'').toLowerCase(); const f=((select&&select.value)||'').toLowerCase(); document.querySelectorAll('table[data-table="'+tableName+'"] tbody tr').forEach(row=>{ const text=(row.getAttribute('data-search')||row.textContent||'').toLowerCase(); const rowFilter=(row.getAttribute('data-filter')||'').toLowerCase(); const okText=(!q||text.includes(q)) && (!g||text.includes(g)); const okFilter=!f||rowFilter===f||rowFilter.includes(f); row.style.display=(okText&&okFilter)?'':'none'; }); }
function applyAll(){ document.querySelectorAll('table[data-table]').forEach(t=>applyFilters(t.getAttribute('data-table'))); }
document.querySelectorAll('[data-table-search],[data-table-filter],#globalFilter').forEach(el=>el.addEventListener('input',applyAll));
document.querySelectorAll('[data-table-filter]').forEach(el=>el.addEventListener('change',applyAll));
initGraphShelves();
</script>
</body>
</html>`;
}

function renderTabbed(data, options = {}) {
  data.settings = data.settings || {
    ...loadSettings(),
    user_mode: 'simple'
  };
  data.settings.user_mode = data.settings.user_mode || data.settings.operator_profile?.user_mode || 'simple';
  data.settings.onboarding = data.settings.onboarding || onboardingState(data.settings);
  const counts = trustCounts(data.trust);
  const moduleCount = (data.modules.modules || []).length;
  const repairCount = (data.repair.queue || []).length;
  const staleCount = (data.stale.items || data.stale.stale_items || []).length;
  const criticalCount = getCriticalFiles(data).length;
  const searchDocs = (data.searchIndex.documents || []).length;
  const qualityScore = data.quality.quality_score ?? data.quality.score ?? '-';
  const branch = data.context?.branch || 'unknown';
  const head = (data.context?.headSha || '').slice(0, 12) || 'unknown';
  const memoryStatus = data.external.providers?.find?.((provider) => provider.provider_id === 'mem0-oss')?.status || 'runtime_not_installed';
  const prStatus = fs.existsSync(path.join(stateRoot, 'maintenance', 'pr_summary.md')) ? 'available' : 'not generated';
  const prImpactStatus = data.prImpact?.status || 'not_generated';
  const nextAction = repairCount ? 'Review Repair Queue' : staleCount ? 'Refresh stale items' : 'Run Doctor';
  const homeMetricItems = [
    ['Repo Readiness', qualityScore, 'Can agents safely work in this repo right now?'],
    ['Knowledge Trust', counts.map((count) => `${count.key}:${count.count}`).join(' / '), 'Can agents trust the knowledge they are using?'],
    ['Evidence Coverage', (data.searchIndex.documents || []).length, 'How much knowledge is backed by local evidence/search data?'],
    ['Routing Status', (data.routing.modules || []).length, 'Do agents know where to start and what to read first?'],
    ['Repair Pressure', repairCount, 'What needs to be repaired to restore trust?'],
    ['PR Review Status', prImpactStatus || prStatus, 'How risky are current changes?'],
    ['Agent Activity', data.context?.mode || 'repo', 'Who is working, waiting or ready for review?'],
    ['Memory Providers', memoryStatus, 'External memory is advisory and cannot override evidence.'],
    ['Next Recommended Action', nextAction, 'Use the local server action drawer or copy fallback.'],
    ['Recent Reports', prStatus, 'Latest local reports remain in .knowledge/maintenance.']
  ];
  const homeCards = homeMetricItems.map(([label, value, body]) => renderMetricCard(label, value, body)).join('');
  const countCards = counts.map((count) => `<div class="stat ${trustClass(count.key)}"><div class="num">${count.count}</div><div class="cap">${esc(count.key)}</div></div>`).join('');
  const searchBody = `<div class="empty-state"><h3>Local search</h3><p>${esc(searchDocs)} indexed documents. Search runs locally from generated index data.</p>${commandBox('node .knowledge/tools/search-knowledge.js "<query>"', 'Copy search command')}</div>`;
  const exportBody = `<div class="quick-actions"><button class="action-card" type="button" data-copy="node .knowledge/tools/install-check.js --json"><span>Run Install Check</span><code>node .knowledge/tools/install-check.js --json</code></button></div><div class="empty-state" style="margin-top:14px"><h3>Release artifact hygiene</h3><p>Use the uploaded release asset for install checks; source snapshots are not install packages.</p></div>`;
  const onboarding = `${renderOnboarding(data, options)}${renderRepairFirstRun(data, options)}`;
  const updatesPanel = renderUpdatesV2(data, options);
  const updateState = data.updateStatus?.status || 'never_checked';
  const turnOffButton = options.live
    ? '<button class="copy-btn danger-btn turn-off-btn" type="button" data-shutdown="true">Turn off</button>'
    : '<button class="copy-btn turn-off-btn" type="button" disabled title="Only available in live Inspector mode">Turn off</button>';
  const actionDrawer = `<div class="panel"><h3>Global action drawer</h3><p class="sub">${options.live ? 'Live buttons run allowlisted local actions with the session token.' : 'Static fallback copies commands only. Run <code>node .knowledge/inspector.js</code> for token-protected local buttons.'}</p>${renderQuickActions({ ...options, data })}</div>`;
  const actionResult = renderActionResultPanel(options);
  const settingsBody = `${renderRepairSettings(data, options)}<div class="card"><h2>Repair opportunities</h2><p class="sub">Global Doctor and current-task readiness are intentionally separate. Deferred work stays visible without becoming hidden scope creep.</p>${renderRepairOpportunities(data)}</div><div class="grid two"><div class="card"><h2>User Mode: Simple / Advanced</h2><p class="sub">Simple Mode uses plain-language summaries and safe defaults. Advanced Mode shows raw JSON, locks, routing, evidence and branch policy.</p>${commandBox('node .knowledge/tools/agent-session.js report --json', 'Agent sessions')}</div><div class="card"><h2>Agent Report Footer</h2><p class="sub">Supported modes: off, compact, full, only when trust incomplete. Token metrics must be labelled as estimates.</p>${commandBox('node .knowledge/tools/restore-trust.js --safe --json', 'Restore Trust')}</div><div class="card"><h2>Concurrent Work Policy</h2><p class="sub">Default multi-agent mode is Safe Queue. Merge policy defaults to Manual Only.</p>${renderTeamModePanel(data)}</div><div class="card"><h2>Local Server</h2><p class="sub">Browser and VS Code shell use the same local API.</p>${commandBox('node .knowledge/inspector.js', 'Open Inspector')}</div></div>`;
  const agentsBody = `<div class="grid two"><div class="card"><h2>Agent Registry / Active Sessions</h2><p class="sub">No manual active-agent switch. Connected agents register sessions, heartbeats, reports and locks.</p>${commandBox('node .knowledge/tools/agent-session.js start --runtime claude-code --json', 'Start session')}${commandBox('node .knowledge/tools/agent-session.js report --json', 'Session report')}</div><div class="card"><h2>Safe Queue / Locks / Parallel Worktrees / Merge Queue</h2>${renderTeamModePanel(data)}</div></div>`;
  const trustPrimary = options.live ? '<button type="button" class="copy-btn" data-action="trust.restore.safe">Restore Trust</button>' : copyButton('node .knowledge/tools/restore-trust.js --safe --json', 'Restore Trust');
  const tabs = [
    {
      id: 'home',
      label: 'Home',
      body: `${renderPageHeader({ title: 'Home', summary: 'Repo-local status, update state, and the safest next step.', chips: [`Doctor ${qualityScore}`, `Update ${updateState}`, `Branch ${branch}`] })}${renderOutcomePanel({ title: 'Repo readiness', verdict: repairCount ? 'Repair queue needs attention' : staleCount ? 'Refresh stale knowledge before relying on it' : 'Ready to work', body: 'Inspector keeps commands explicit and shows raw details only when you open the shelves.', tone: repairCount ? 'warn' : 'ok', actions: copyButton('node .knowledge/tools/doctor.js --json', 'Copy doctor') })}${onboarding}${updatesPanel}${renderMetricStrip(homeMetricItems)}<div class="grid two"><div>${renderBranchDiagnostics(data, { ...options, showSimpleTrust: data.settings.user_mode === 'simple' })}</div>${renderNextActionPanel({ body: `Recommended now: ${nextAction}. Use live buttons when available; static mode copies commands.`, primary: copyButton('node .knowledge/tools/doctor.js --json', 'Run Doctor'), secondary: copyButton('node .knowledge/inspector.js', 'Open live') })}</div>${renderAdvancedShelf('home-actions', 'Commands and action output', `${actionDrawer}${actionResult}`, 'Copyable commands and live action results.')}${renderAdvancedShelf('home-memory', 'Memory provider details', `<div class="card"><h2>Memory Providers</h2><p class="sub">External memory is advisory and cannot override evidence.</p>${renderMemoryProviders(data)}</div>`, 'Optional advisory context and provider diagnostics.')}`
    },
    {
      id: 'review',
      label: 'Review',
      body: `${renderPageHeader({ title: 'Review', summary: 'Change impact, reviewer notes, and policy warnings in one consistent shell.', chips: [`PR impact ${prImpactStatus}`, `Critical ${criticalCount}`] })}${renderOutcomePanel({ title: 'Review outcome', verdict: prImpactStatus === 'not_generated' ? 'PR impact has not been generated yet' : 'Review data is available', body: 'Start with the summary. Open advanced shelves only when you need exact JSON, files, or command output.', tone: prImpactStatus === 'not_generated' ? 'warn' : 'ok', actions: copyButton('node .knowledge/tools/pr-impact.js --json', 'Copy PR impact') })}<div class="grid two"><div class="card"><h2>PR Impact</h2>${renderPrImpactPreview(data)}</div><div>${renderNextActionPanel({ title: 'Reviewer next step', body: 'Verify touched trust boundaries first, then inspect critical files only when listed.', primary: copyButton('node .knowledge/tools/generate-pr-summary.js', 'PR summary'), secondary: copyButton('node .knowledge/tools/pr-impact.js --json', 'Impact JSON') })}</div></div>${renderAdvancedShelf('review-notes', 'Reviewer notes and raw summary', `<div class="card"><h2>Reviewer Notes</h2>${renderPrPreview(data)}</div>`, 'Detailed reviewer text stays available without crowding the default view.')}${renderAdvancedShelf('review-critical', 'Critical paths and policy warnings', `<div class="card"><h2>Critical Paths / Policy Warnings</h2>${renderCriticalFiles(data)}</div>`, 'Open when review outcome points to important files.')}`
    },
    {
      id: 'trust',
      label: 'Knowledge Trust',
      body: `${renderPageHeader({ title: 'Knowledge Trust', summary: 'Trust graph, routing, evidence, freshness, and repair status.', chips: [`Modules ${moduleCount}`, `Repair ${repairCount}`, `Stale ${staleCount}`] })}${renderOutcomePanel({ title: 'Trust answer', verdict: repairCount ? 'Repair generated trust artifacts before relying on summaries' : 'No blocking trust repairs found', body: 'Click a graph node to get a plain explanation. Incoming links, outgoing links, evidence, tests, and code stay in collapsible shelves.', tone: repairCount ? 'warn' : 'ok', actions: `${trustPrimary}${renderTrustRepairPrompt(data)}` })}<div class="grid stats">${countCards}</div>${freeCoreGraphSvg(data)}${renderAdvancedShelf('trust-routing', 'Modules, evidence, routing, and search', `<div class="grid two"><div class="card"><h2>Trust Overview</h2>${renderModules(data)}</div><div class="card"><h2>Evidence and Routing</h2>${renderRouting(data)}<h3>Search</h3>${searchBody}</div></div>`, 'Raw routing and module tables for advanced users.')}${renderAdvancedShelf('trust-freshness', 'Freshness and repair queue', `<div class="grid two"><div class="card"><h2>Freshness</h2>${renderStale(data)}</div><div class="card"><h2>Repair Queue / Restore Trust</h2>${renderRepair(data)}${commandBox('node .knowledge/tools/restore-trust.js --safe --json', 'Restore Trust')}</div></div>`, 'Exact stale items and repair commands.')}`
    },
    {
      id: 'agents',
      label: 'Agents',
      body: `${renderPageHeader({ title: 'Agents', summary: 'Sessions, locks, Safe Queue, and handoff readiness.', chips: [`Mode ${data.context?.mode || 'repo'}`, `Head ${head}`] })}${renderOutcomePanel({ title: 'Agent activity', verdict: 'Use the queue and session report before overlapping work', body: 'The free Inspector shows local/team state; it does not merge or publish without explicit action.', tone: 'info', actions: copyButton('node .knowledge/tools/agent-session.js report --json', 'Session report') })}${agentsBody}${renderAdvancedShelf('agents-team', 'Raw team and worktree diagnostics', `${renderTeamModePanel(data)}${commandBox('node .knowledge/tools/worktree-status.js --json', 'Worktree Check')}`, 'Detailed locks, worktree state, and team status.')}`
    },
    {
      id: 'reports',
      label: 'Reports',
      body: `${renderPageHeader({ title: 'Reports', summary: 'Verification results, skipped checks, and generated reports.', chips: [`PR ${prStatus}`, `Impact ${prImpactStatus}`] })}${renderOutcomePanel({ title: 'Verification summary', verdict: 'Only selected local checks are represented here', body: 'This page must say what ran and what did not. Full release gate remains separate unless explicitly requested.', tone: 'info', actions: copyButton('node .knowledge/tools/install-check.js --json', 'Install check') })}<div class="grid two"><div class="card"><h2>Release Checks</h2>${exportBody}</div><div class="card"><h2>Local Evaluation</h2><p class="sub">Runs deterministic installed-repository checks. It is not a comparative model benchmark.</p>${commandBox('node .knowledge/tools/evaluation-harness.js', 'Local evaluation')}</div></div>${renderAdvancedShelf('reports-output', 'Command output and skipped checks', `${commandBox('node .knowledge/tools/doctor.js --json', 'Doctor JSON')}${commandBox('node .knowledge/tools/build-visual-inspector.js --json', 'Inspector JSON')}`, 'Exact command output belongs here after checks run.')}`
    },
    {
      id: 'settings',
      label: 'Settings',
      body: `${renderPageHeader({ title: 'Settings', summary: 'Simple/Advanced mode, local server behavior, and memory provider defaults.', chips: [`User mode ${data.settings.user_mode}`, options.live ? 'Live API' : 'Static mode'] })}${renderOutcomePanel({ title: 'Settings model', verdict: 'Simple mode stays readable; advanced details stay one click away', body: 'Browser and VS Code use the same local API and the same generated UI.', tone: 'info', actions: copyButton('node .knowledge/inspector.js', 'Open Inspector') })}${settingsBody}${renderAdvancedShelf('settings-memory', 'Memory provider configuration details', `<div class="card"><h2>Memory Providers</h2>${renderMemoryProviders(data)}</div>`, 'Provider status, boundaries, and setup commands.')}`
    },
    {
      id: 'pro',
      label: 'Pro Preview',
      body: `${renderPageHeader({ title: 'Pro Preview', summary: 'Optional team workflow layer on top of the free local trust layer.', chips: ['Free core remains local', 'Optional'] })}${renderOutcomePanel({ title: 'Boundary', verdict: 'Free .knowledge remains local-first and fully usable', body: 'Pro Preview is an in-app capability preview, not a replacement for the open local Inspector.', tone: 'info', actions: renderProWaitlist(data) })}${renderAdvancedShelf('pro-details', 'Capability notes', '<div class="card"><h2>Coming Soon</h2><p class="sub">Inspector Pro is planned for teams that need deeper collaboration and governance. Free .knowledge remains local-first and fully usable.</p></div>', 'Free vs team capability boundary.')}`
    }
  ];
  const nav = tabs.map((tab, index) => `<button type="button" class="tab-btn${index === 0 ? ' active' : ''}" data-tab="${index}" data-route="${esc(tab.id)}">${esc(tab.label)}</button>`).join('');
  const sections = tabs.map((tab, index) => `<section class="tab-panel${index === 0 ? ' active' : ''}" data-panel="${index}" data-route="${esc(tab.id)}" aria-label="${esc(tab.label)}">${tab.body}</section>`).join('');
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>.knowledge Inspector ${esc(systemVersion)}</title>
<style>
:root{--bg:#091017;--panel:#101a23;--panel2:#13212b;--line:#2c3c45;--text:#f4f7f4;--muted:#aebbb3;--green:#39b980;--yellow:#e6b84c;--red:#e05252;--blue:#62a8e5;--violet:#a48be0;--shadow:0 18px 60px #0007}*{box-sizing:border-box}body{margin:0;background:#091017;color:var(--text);font:14px/1.48 ui-sans-serif,system-ui,-apple-system,Segoe UI,Arial}.app{display:grid;grid-template-columns:250px minmax(0,1fr);min-height:100vh}.sidebar{position:sticky;top:0;height:100vh;overflow:auto;border-right:1px solid var(--line);background:#0b141b;padding:18px}.brand{font-weight:900;font-size:18px;margin-bottom:14px}.tab-btn{width:100%;display:block;text-align:left;border:1px solid transparent;background:transparent;color:var(--muted);padding:9px 10px;border-radius:8px;cursor:pointer}.tab-btn:hover,.tab-btn.active{background:#14232d;color:var(--text);border-color:#324752}.content{min-width:0}.topbar{position:sticky;top:0;z-index:5;background:#0e1820e8;backdrop-filter:blur(10px);border-bottom:1px solid var(--line);padding:14px 22px}.topbar h1{font-size:22px;margin:0 0 8px}.chips{display:flex;gap:8px;flex-wrap:wrap}.chip{border:1px solid #344852;background:#121f28;border-radius:999px;padding:5px 9px;color:#dce8df;font-size:12px}main{padding:22px}.tab-panel{display:none}.tab-panel.active{display:block}.panel,.card{background:linear-gradient(180deg,var(--panel),var(--panel2));border:1px solid var(--line);border-radius:8px;padding:16px;box-shadow:var(--shadow)}.panel-head{display:flex;justify-content:space-between;align-items:center;margin-bottom:12px}h2{font-size:19px;margin:0}h3{font-size:15px;margin:16px 0 8px}.sub{color:var(--muted)}.grid{display:grid;gap:12px}.stats{grid-template-columns:repeat(auto-fit,minmax(150px,1fr))}.metric-grid{margin-top:10px}.compact-top-metrics{grid-template-columns:repeat(auto-fit,minmax(118px,1fr));gap:10px}.compact-top-metrics .stat{padding:10px 12px;min-height:0}.compact-top-metrics .num{font-size:14px;line-height:1.15}.compact-top-metrics .cap{font-size:10px;margin-top:4px}.compact-top-metrics .sub{font-size:10px;line-height:1.35;margin-top:6px}.compact-top-metrics .severity-dot{top:8px;right:8px;width:6px;height:6px}.branch-diagnostics{margin:12px 0}.branch-diagnostics-head{display:flex;justify-content:space-between;align-items:flex-start;gap:14px;flex-wrap:wrap}.branch-diagnostics-body{display:grid;grid-template-columns:minmax(0,1.15fr) minmax(260px,.85fr);gap:16px;align-items:start}.branch-picker{display:grid;gap:5px;color:var(--muted);font-size:12px}.branch-picker select{background:#0b141b;border:1px solid #344852;color:var(--text);border-radius:8px;padding:9px;min-width:220px}.quick-actions{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:12px}.action-card{cursor:pointer;text-align:left;border:1px solid #344852;background:#0d1820;border-radius:8px;padding:12px;color:var(--text)}.action-card.locked{border-style:dashed;opacity:.72}.action-card:hover{border-color:#63a0c9}.action-card span{display:block;font-weight:800;margin-bottom:5px}.action-card code{display:block;color:#9bd0f4;font-size:11px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.stat{background:#0d1820;border:1px solid #263841;border-radius:8px;padding:12px;min-height:78px}.metric-card{position:relative;margin-top:6px;padding-top:18px;border-left:4px solid #3b5360}.metric-card.ok{border-left-color:var(--green)}.metric-card.warning{border-left-color:var(--yellow);background:#1d1a10}.metric-card.critical{border-left-color:var(--red);background:#211316}.severity-dot{position:absolute;top:8px;right:10px;width:8px;height:8px;border-radius:999px;background:#3b5360}.metric-card.ok .severity-dot{background:var(--green)}.metric-card.warning .severity-dot{background:var(--yellow)}.metric-card.critical .severity-dot{background:var(--red)}.num{font-size:24px;font-weight:900;word-break:break-word}.cap{color:var(--muted);font-size:11px;text-transform:uppercase}.pill{display:inline-flex;padding:3px 8px;border-radius:999px;background:#23323b}.trusted{background:#133629}.routing_trusted{background:#14324a}.near_trusted,.important,.medium{background:#3b2d15}.suspect,.low_confidence,.critical,.high{background:#4a1d22}.advisory_only{background:#292542}.table-controls{display:flex;gap:8px;margin-bottom:10px}.table-controls input,.table-controls select{background:#0b141b;border:1px solid #344852;color:var(--text);border-radius:8px;padding:9px}table{width:100%;border-collapse:collapse}th,td{padding:9px;border-bottom:1px solid #263841;text-align:left;vertical-align:top}th{color:var(--muted);font-size:11px;text-transform:uppercase}.kv th{width:170px}.mini-actions{display:flex;gap:8px;flex-wrap:wrap;margin-top:12px}.copy-btn{border:1px solid #3b5360;background:#11212c;color:#eaf3ee;border-radius:8px;padding:7px 9px;cursor:pointer}.danger-btn{border-color:#87535a;background:#321920}.onboarding-card{margin-bottom:14px}.onboarding-card.requires-setup{border-color:var(--yellow)}.onboarding-toggle{display:flex;justify-content:space-between;gap:12px;width:100%;border:0;background:transparent;color:var(--text);padding:0;text-align:left;cursor:pointer}.onboarding-toggle span{font-weight:900}.onboarding-toggle small{color:var(--muted)}.onboarding-body{margin-top:14px}.onboarding-body[hidden]{display:none}.setting-list{display:grid;gap:10px}.setting-row{display:grid;grid-template-columns:minmax(180px,1fr) minmax(220px,320px);gap:14px;align-items:center;border:1px solid #263841;background:#0d1820;border-radius:8px;padding:10px}.setting-row span,.setting-row small{display:block}.setting-row small{color:var(--muted);margin-top:3px}.setting-row select,.setting-row input{width:100%;background:#0b141b;border:1px solid #344852;color:var(--text);border-radius:8px;padding:9px}.simple-trust-actions,.trust-repair-actions{margin:12px 0}.simple-trust-actions.compact{margin:0;height:100%;display:flex;flex-direction:column;justify-content:flex-end;padding:16px;border:1px solid #263841;border-radius:8px;background:#0d1820}.simple-trust-actions.compact h2{font-size:16px}.update-banner{display:flex;justify-content:space-between;gap:14px;align-items:flex-start;border:1px solid #3b5360;background:#0d1820;border-radius:8px;padding:14px;margin-bottom:12px}.update-banner.available{border-color:#e6b84c}.update-banner.failed{border-color:#e05252}.empty-state{border:1px dashed #3b5360;background:#0c171f;border-radius:8px;padding:18px;text-align:center;color:var(--muted)}.cmd{display:flex;gap:8px;align-items:center;background:#081017;border:1px solid #263841;border-radius:8px;padding:9px;margin-top:10px}.cmd code{flex:1;color:#9bd0f4;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.pro-preview-intro{display:flex;justify-content:space-between;gap:16px;align-items:center;border:1px solid #30434d;background:#0d1820;border-radius:8px;padding:14px;margin:14px 0}.pro-preview-intro strong,.pro-preview-intro span{display:block}.pro-preview-intro span{color:var(--muted);margin-top:3px}.pro-waitlist-button{display:inline-flex;align-items:center;justify-content:center;min-height:46px;padding:0 22px;border:1px solid #3c3f4b;border-radius:8px;background:linear-gradient(180deg,#34343d,#161720);box-shadow:inset 0 1px 0 #ffffff18,0 8px 18px #0008;color:#f4f0f2;text-transform:uppercase;letter-spacing:2px;font-weight:900;text-decoration:none;white-space:nowrap}.pro-waitlist-button:hover{border-color:#6d7180;background:linear-gradient(180deg,#3d3e48,#1c1d27)}.signal-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:12px}.signal-card{border:1px solid #314752;background:#0d1820;border-radius:8px;padding:12px}.signal-card strong,.signal-card span{display:block}.signal-card span{color:var(--muted);font-size:12px}.result-panel{margin-top:12px}.result-toggle{width:100%;display:flex;justify-content:space-between;align-items:center;gap:12px;border:0;background:transparent;color:var(--text);padding:0;text-align:left;cursor:pointer}.result-toggle span{font-weight:900}.result-toggle small{color:var(--muted)}.result-panel pre{margin-top:12px}.result-panel.is-collapsed pre{display:none}.wiki-svg{width:100%;height:440px;background:#081017;border:1px solid #263841;border-radius:8px}.edge{fill:none;stroke:#6d7d88}.edge.contradicts{stroke:var(--red)}.edge.supports{stroke:var(--green)}.edge.depends_on{stroke:var(--yellow)}.node{fill:var(--violet);stroke:#fff}.node.trusted{fill:var(--green)}.node.routing_trusted{fill:var(--blue)}.node.suspect,.node.low_confidence{fill:var(--red)}.label{font-size:10px;fill:#eef7f2;paint-order:stroke;stroke:#081017;stroke-width:3px}.toast{position:fixed;right:18px;bottom:18px;background:#123629;color:#c8f3dc;border:1px solid #2a8b62;padding:10px 12px;border-radius:8px;opacity:0;transform:translateY(8px);transition:.18s}.toast.show{opacity:1;transform:translateY(0)}@media(max-width:850px){.app{grid-template-columns:1fr}.sidebar{position:relative;height:auto}.tab-btn{display:inline-block;width:auto;margin:0 4px 6px 0}.topbar{position:relative}main{padding:14px}.table-controls,.setting-row{display:block}.table-controls input,.table-controls select,.setting-row select,.setting-row input{width:100%;margin-top:8px;margin-bottom:8px}.update-banner{display:block}.branch-diagnostics-body{grid-template-columns:1fr}.pro-preview-intro{align-items:flex-start;flex-direction:column}.pro-waitlist-button{width:100%}}
</style>
<style>
body,.app,.content,main{overflow-x:hidden}.agent-picker{display:grid;gap:5px;min-width:0}.agent-picker small{color:var(--muted);line-height:1.35}.graph-hit-target{fill:#fff;fill-opacity:0;stroke:none;pointer-events:all}.graph-node .label{pointer-events:all;cursor:pointer}.graph-node:hover .graph-hit-target,.graph-node:focus .graph-hit-target{stroke:#fff;stroke-opacity:.18;stroke-width:1}
.topbar{display:flex;justify-content:space-between;align-items:flex-start;gap:16px}.topbar-main{min-width:0}.topbar-actions{display:flex;gap:8px;align-items:center;flex:0 0 auto}.turn-off-btn{white-space:nowrap;font-size:16px;font-weight:900;line-height:1.1;min-height:50px;padding:17px 23px}.turn-off-btn:disabled{opacity:.55;cursor:not-allowed}.graph-shelf{margin:12px 0}.graph-shelf-header{display:block}.graph-title-block{min-width:0}.graph-title-row{display:flex;align-items:center;gap:12px;flex-wrap:wrap}.graph-title-row h2,.graph-shelf-header h2{margin:0}.graph-shelf-summary{display:block;color:var(--muted);margin-top:4px}.graph-shelf-actions{display:flex;gap:8px;flex-wrap:wrap;justify-content:flex-start;align-items:center}.graph-toggle-btn{display:inline-flex;align-items:center;gap:5px}.graph-toggle-arrow{font-weight:900}.graph-shelf.is-collapsed .graph-shelf-body{display:none}.graph-shelf.is-collapsed{padding-bottom:12px}.free-core-graph{display:grid;gap:12px}.free-core-graph>.legend{display:flex;flex-wrap:wrap;gap:10px 16px;align-items:center;line-height:1.7;color:var(--muted)}.free-core-graph>.legend span{display:inline-flex;align-items:center;gap:6px;white-space:nowrap}.graph-scroll{overflow:auto;border-radius:8px;max-width:100%;contain:layout paint}.graph-metrics{display:grid;grid-template-columns:repeat(auto-fit,minmax(105px,1fr));gap:8px}.graph-metric{border:1px solid #263841;background:#0b141b;border-radius:8px;padding:9px 10px}.graph-metric strong,.graph-metric span,.graph-metric small{display:block}.graph-metric strong{font-size:18px}.graph-metric span{color:var(--muted);font-size:11px;text-transform:uppercase}.graph-metric small{color:var(--muted);font-size:11px;margin-top:3px}.trust-graph-svg{height:580px;min-width:1120px;background:linear-gradient(180deg,#081017,#0c1820);overflow:visible}.lane line{stroke:#263841;stroke-width:1}.lane text{fill:#aebbb3;font-size:12px;text-transform:uppercase}.edge{fill:none;stroke:#6d7d88;stroke-width:2;opacity:.62;stroke-linecap:round}.edge.bundled{stroke-width:3.2;opacity:.78}.edge.invalid{stroke-dasharray:5 5;opacity:.5}.edge.outranks{stroke:#eaf3ee}.edge.routes{stroke:var(--blue)}.edge.documents{stroke:var(--green)}.edge.checks{stroke:#67e8f9}.edge.evidence{stroke:#9bd0f4}.edge.references,.edge.related{stroke:var(--violet)}.edge.advisory{stroke:var(--yellow);stroke-dasharray:6 4}.edge.supports{stroke:var(--green)}.edge.depends_on{stroke:var(--yellow)}.edge.contradicts{stroke:var(--red)}#graph-arrow path{fill:#91a2ad}.graph-node{cursor:pointer}.graph-node:focus .node,.graph-node:hover .node{stroke:#fff;stroke-width:3}.node{stroke:#081017;stroke-width:2}.node.source_truth{fill:#eaf3ee}.node.module{fill:var(--blue)}.node.wiki{fill:var(--violet)}.node.trusted{fill:var(--green)}.node.routing_trusted{fill:var(--blue)}.node.advisory_only{fill:var(--violet)}.node.suspect,.node.low_confidence{fill:var(--red)}.label{text-anchor:middle;font-size:10.5px;fill:#eef7f2;paint-order:stroke;stroke:#081017;stroke-width:4px;pointer-events:none}.label.source_truth{font-weight:800}.graph-node-detail{border:1px solid #263841;background:#0b141b;border-radius:8px;padding:12px;color:#dce8df;max-height:430px;overflow:auto}.graph-node-detail strong,.graph-node-detail span,.graph-node-detail code{display:block}.graph-node-detail span{color:var(--muted);margin-top:3px}.graph-node-detail code{color:#9bd0f4;margin-top:6px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.graph-detail-head{border-bottom:1px solid #263841;margin-bottom:10px;padding-bottom:8px}.graph-detail-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:12px}.graph-detail-grid section{border:1px solid #263841;background:#09161d;border-radius:8px;padding:10px;margin:0}.graph-detail-grid h4{margin:0 0 7px;font-size:12px;text-transform:uppercase;color:#aebbb3}.graph-detail-grid ul{margin:0;padding-left:18px}.graph-detail-grid li{margin-bottom:5px}.graph-detail-grid em,.graph-detail-grid small{display:block;color:var(--muted);font-style:normal}.graph-detail-grid b{display:block;margin-top:7px}.graph-detail-actions{display:flex;flex-wrap:wrap;gap:7px}.graph-action-link{text-decoration:none}.graph-advisory{color:#ffe7ad!important}.source-order-strip{border:1px solid #263841;background:#0b141b;border-radius:8px;padding:10px;color:#dce8df}.graph-insights{border:1px solid #263841;background:#0b141b;border-radius:8px;padding:12px}.graph-insights h3{margin-top:0}.graph-insights .reason-list{margin-top:10px}.edge-swatch.outranks{background:#eaf3ee}.edge-swatch.routes{background:var(--blue)}.edge-swatch.documents,.edge-swatch.supports{background:var(--green)}.edge-swatch.checks{background:#67e8f9}.edge-swatch.evidence{background:#9bd0f4}.edge-swatch.references{background:var(--violet)}.edge-swatch.advisory{background:var(--yellow)}.edge-swatch.contradicts{background:var(--red)}@media(max-width:850px){.topbar{display:block}.topbar-actions{margin-top:10px}.trust-graph-svg{height:500px;min-width:900px}.graph-tools,.graph-shelf-header{display:block}.graph-title-row{align-items:flex-start}.graph-tools .copy-btn,.graph-shelf-actions{margin-top:8px}}
</style>
<style>
${inspectorDesignCss()}
</style>
</head>
<body>
${renderAppShell({ data, nav, sections, qualityScore, branch, head, updateState, turnOffButton })}
${renderFilePreviewDrawer()}
<div id="toast" class="toast">Copied</div>
<script>
const toast=document.getElementById('toast');
const sessionToken=${JSON.stringify(options.token || '')};
const liveMode=${options.live ? 'true' : 'false'};
const gitBranchState=${jsJson(data.context?.git?.branches || {})};
const gitDirtyState=${jsJson({ dirty: data.context?.git?.dirty === true, dirty_summary: data.context?.git?.dirty_summary || { changed: 0, staged: 0, generated_runtime_staged: 0 } })};
function showToast(text){toast.textContent=text||'Copied';toast.classList.add('show');setTimeout(()=>toast.classList.remove('show'),1400)}
function fallbackCopy(text){const el=document.createElement('textarea');el.value=text;document.body.appendChild(el);el.select();document.execCommand('copy');el.remove();showToast('Copied command')}
function copyText(text){if(navigator.clipboard&&navigator.clipboard.writeText)navigator.clipboard.writeText(text).then(()=>showToast('Copied command')).catch(()=>fallbackCopy(text));else fallbackCopy(text)}
function setResultPanel(open,summary){const panel=document.querySelector('[data-result-panel="true"]');const pre=document.getElementById('result');const meta=document.querySelector('[data-result-summary="true"]');if(!panel||!pre)return;panel.classList.toggle('is-collapsed',!open);pre.hidden=!open;if(meta&&summary)meta.textContent=summary}
function authHeaders(headers){return sessionToken?{...(headers||{}),authorization:'Bearer '+sessionToken}:(headers||{})}
let currentPreviewPath='';
let currentPreviewHref='#';
function codeCommandForPath(pathValue){return 'code -g '+String(pathValue||'')}
function setFilePreview(pathValue,metaText,bodyText,fallbackHref){currentPreviewPath=pathValue||'';currentPreviewHref=fallbackHref||'#';const drawer=document.querySelector('[data-file-preview-drawer="true"]');if(!drawer)return;const title=drawer.querySelector('[data-file-preview-title="true"]');const meta=drawer.querySelector('[data-file-preview-meta="true"]');const body=drawer.querySelector('[data-file-preview-body="true"]');const copyPath=drawer.querySelector('[data-file-preview-copy-path="true"]');const copyCode=drawer.querySelector('[data-file-preview-copy-code="true"]');const raw=drawer.querySelector('[data-file-preview-fallback="true"]');if(title)title.textContent=pathValue||'File preview';if(meta)meta.textContent=metaText||'';if(body)body.textContent=bodyText||'';if(copyPath)copyPath.disabled=!currentPreviewPath;if(copyCode)copyCode.disabled=!currentPreviewPath;if(raw)raw.setAttribute('href',currentPreviewHref||'#');drawer.hidden=false}
async function openInspectorFile(pathValue,fallbackHref){if(!pathValue)return false;const href=fallbackHref||('/api/files/open?path='+encodeURIComponent(pathValue));if(!liveMode||!sessionToken){setFilePreview(pathValue,'Static mode: copy the path or open the fallback link.','Live preview is available after running node .knowledge/inspector.js.',href);return false}setFilePreview(pathValue,'Loading through /api/files/open ...','Loading...',href);try{const res=await fetch('/api/files/open?path='+encodeURIComponent(pathValue),{headers:authHeaders()});const text=await res.text();const type=res.headers.get('content-type')||'text/plain';if(!res.ok){setFilePreview(pathValue,'Open failed: HTTP '+res.status,text||'The file could not be opened.',href);return false}setFilePreview(pathValue,type,text,href);showToast('File preview opened');return true}catch(error){setFilePreview(pathValue,'Open failed',String(error&&error.message||error),href);return false}}
function closeFilePreview(){const drawer=document.querySelector('[data-file-preview-drawer="true"]');if(drawer)drawer.hidden=true}
function extractUpdateStatus(json){return json?.refreshed_status||json?.apply?.refreshed_status||json?.status||json?.release||json?.dry_run?.status||json?.dry_run?.json||{}}
function setUpdateText(selector,value){document.querySelectorAll(selector).forEach((el)=>{el.textContent=value||'-'})}
function paintUpdateStatus(status,json){const s=status||{};const current=s.current_version||'-';const latest=s.latest_version||'-';const asset=s.asset_name||'knowledge-v<version>.zip';const stateText=s.status||'never_checked';const autoCheck=s.auto_check_on_inspector_open!==false;const autoNote=s.update_check_note||(autoCheck?'Live Inspector checks for new releases when it starts. Updates are never applied automatically.':'Automatic update checks on Inspector start are disabled.');const state=document.getElementById('updateState');if(state)state.textContent=stateText;setUpdateText('[data-update-current]',current);setUpdateText('[data-update-latest]',latest);setUpdateText('[data-update-asset]',asset);setUpdateText('[data-update-note]',autoNote);document.querySelectorAll('[data-update-chip]').forEach((el)=>{el.textContent='Update: '+stateText});const banner=document.getElementById('updateBanner');if(banner){banner.setAttribute('data-current-version',current);banner.setAttribute('data-latest-version',latest);banner.setAttribute('data-asset-name',asset);banner.setAttribute('data-auto-check',autoCheck?'true':'false');banner.classList.toggle('available',stateText==='update_available');banner.classList.toggle('failed',json?.ok===false||stateText==='check_failed')}const mode=document.getElementById('updateAutoCheckMode');if(mode){const busy=mode.getAttribute('data-busy')==='true';mode.textContent=autoCheck?'Auto-check: On':'Auto-check: Off';mode.setAttribute('aria-pressed',autoCheck?'true':'false');mode.title=autoCheck?'Checks on Inspector start; updates still require confirmation.':'Auto-check on Inspector start is off.';if(!busy)mode.disabled=!liveMode}const button=document.getElementById('updateApplyButton');if(button){const canUpdate=stateText==='update_available';button.disabled=!canUpdate;button.textContent=canUpdate?'Update':(stateText==='check_failed'?'Check failed':'Up to date')}return s}
async function toggleUpdateAutoCheck(button){if(!liveMode||!sessionToken){showToast('Run live Inspector to change auto-check');return}const enabled=button.getAttribute('aria-pressed')!=='true';button.setAttribute('data-busy','true');button.disabled=true;button.textContent=enabled?'Turning on...':'Turning off...';const json=await updateApi('/api/update/auto-check',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({enabled})});button.setAttribute('data-busy','false');if(json&&json.ok){paintUpdateStatus(extractUpdateStatus(json),json);showToast(enabled?'Auto-check enabled':'Auto-check disabled')}else{button.disabled=false;paintUpdateStatus(extractUpdateStatus(json),json||{ok:false})}}
async function updateApi(path,options){const output=document.getElementById('updateOutput');const isApply=String(path||'').includes('/api/update/apply');try{const opts=options||{};opts.headers=authHeaders(opts.headers);const button=document.getElementById('updateApplyButton');if(isApply&&button){button.disabled=true;button.textContent='Updating...'}const res=await fetch(path,opts);const json=await res.json();paintUpdateStatus(extractUpdateStatus(json),json);if(output){output.hidden=!isApply&&!json?.error;output.textContent=JSON.stringify(json,null,2)}if(isApply)showToast(json.ok?'Update applied':'Update needs review');return json}catch(error){if(output){output.hidden=false;output.textContent='Update API unavailable in static mode: '+error.message}paintUpdateStatus({status:'check_failed',error:error.message},{ok:false});return null}}
function escapeHtmlClient(value){return String(value||'').replace(/[&<>"']/g,(ch)=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]))}
function graphToggleHtml(collapsed){return '<span class="graph-toggle-arrow" aria-hidden="true">'+(collapsed?'>':'v')+'</span> '+(collapsed?'Expand':'Collapse')}
function setGraphShelf(id,collapsed){const shelf=document.querySelector('[data-graph-shelf="'+id+'"]');if(!shelf)return;shelf.classList.toggle('is-collapsed',collapsed);const button=shelf.querySelector('[data-graph-toggle]');if(button){button.innerHTML=graphToggleHtml(collapsed);button.setAttribute('aria-expanded',collapsed?'false':'true')}try{localStorage.setItem('knowledge.graph.'+id+'.collapsed',collapsed?'1':'0')}catch{}}
function initGraphShelves(){document.querySelectorAll('[data-graph-shelf]').forEach((shelf)=>{const id=shelf.getAttribute('data-graph-shelf');let collapsed=false;try{collapsed=localStorage.getItem('knowledge.graph.'+id+'.collapsed')==='1'}catch{}setGraphShelf(id,collapsed)})}
function graphList(items,empty,formatter){const values=Array.isArray(items)?items:[];if(!values.length)return '<p class="muted">'+escapeHtmlClient(empty)+'</p>';return '<ul>'+values.map((item)=>'<li>'+formatter(item)+'</li>').join('')+'</ul>'}
function graphEdgeText(edge){return '<b>'+escapeHtmlClient(edge.relation||'related')+'</b> '+escapeHtmlClient(edge.from||'')+' -> '+escapeHtmlClient(edge.to||'')+(edge.source?' <small>'+escapeHtmlClient(edge.source)+'</small>':'')+(edge.reason?'<em>'+escapeHtmlClient(edge.reason)+'</em>':'')}
function graphArtifacts(values,empty){return graphList(values,empty,(item)=>escapeHtmlClient(item))}
function inspectorFileHref(action){if(liveMode&&sessionToken&&action.path)return '/api/files/open?path='+encodeURIComponent(action.path)+'&token='+encodeURIComponent(sessionToken);return action.href||'#'}
function graphAction(action){if(action.href){const rawPath=action.path||'';return '<a class="copy-btn graph-action-link" href="'+escapeHtmlClient(inspectorFileHref(action))+'" data-open-path="'+escapeHtmlClient(rawPath)+'" data-open-label="'+escapeHtmlClient(action.label||'Open')+'">'+escapeHtmlClient(action.label||'Open')+'</a>'}if(action.command)return '<button class="copy-btn" type="button" data-copy="'+escapeHtmlClient(action.command)+'">'+escapeHtmlClient(action.label||'Copy')+'</button>';return '<span class="pill">'+escapeHtmlClient(action.label||'Action')+'</span>'}
function graphStatusText(status){const s=status||{};const bits=['node status: '+(s.node_status||'unknown'),s.broken?'broken':'not broken',s.orphan?'orphan':'not orphan',s.stale?'stale':'not stale'];return bits.join(' / ')}
function showGraphNodeDetail(node){const detail=document.querySelector('[data-graph-detail="true"]');if(!detail)return;let payload=null;try{payload=JSON.parse(node.getAttribute('data-graph-detail-json')||'null')}catch{}const group=node.getAttribute('data-graph-group')||payload?.type||'other';const title=payload?.title||node.getAttribute('data-graph-title')||node.getAttribute('data-graph-id')||'Graph node';const trust=payload?.trust||node.getAttribute('data-graph-trust')||'advisory_only';const pathValue=payload?.path||node.getAttribute('data-graph-path')||'';const command=node.getAttribute('data-graph-command')||'node .knowledge/tools/restore-trust.js --safe --json';const moduleId=node.getAttribute('data-graph-module')||'';if(group==='module'){const input=document.querySelector('[data-table-search="modules"]');if(input&&moduleId){input.value=moduleId;applyFilters('modules')}}if(!payload){detail.innerHTML='<strong>'+escapeHtmlClient(title)+'</strong><span>Type: '+escapeHtmlClient(group)+' / Trust: '+escapeHtmlClient(trust)+'</span>'+(pathValue?'<span>Path: '+escapeHtmlClient(pathValue)+'</span>':'')+'<code>'+escapeHtmlClient(command)+'</code>';return}const v=payload.verification||{};detail.innerHTML='<div class="graph-detail-head"><strong>'+escapeHtmlClient(title)+'</strong><span>Type: '+escapeHtmlClient(group)+' / Trust: '+escapeHtmlClient(trust)+(pathValue?' / Path: '+escapeHtmlClient(pathValue):'')+'</span>'+(payload.advisory_note?'<span class="graph-advisory">'+escapeHtmlClient(payload.advisory_note)+'</span>':'')+'</div><div class="graph-detail-grid"><section><h4>Incoming links</h4>'+graphList(payload.incoming,'No incoming links for this node.',graphEdgeText)+'</section><section><h4>Outgoing links</h4>'+graphList(payload.outgoing,'No outgoing links for this node.',graphEdgeText)+'</section><section><h4>Why trust is this</h4><p>'+escapeHtmlClient(payload.trust_reason||'Trust comes from graph metadata; verify before behavior edits.')+'</p>'+(payload.why_route?'<p>'+escapeHtmlClient(payload.why_route)+'</p>':'')+'</section><section><h4>Evidence / tests / code</h4><b>Evidence</b>'+graphArtifacts(v.evidence,'No evidence JSON listed.')+'<b>Tests</b>'+graphArtifacts(v.tests,'No tests listed.')+'<b>Code</b>'+graphArtifacts(v.code,'No code/module files listed.')+(v.gaps&&v.gaps.length?'<p class="muted">'+escapeHtmlClient(v.gaps.join(' '))+'</p>':'')+'</section><section><h4>Status</h4><p>'+escapeHtmlClient(graphStatusText(payload.status))+'</p>'+graphArtifacts(payload.status?.stale_items||[],'No stale items matched this node.')+'</section><section><h4>Next action</h4><div class="graph-detail-actions">'+(payload.next_actions||[]).map(graphAction).join('')+'</div></section></div>'}
function graphDetailShelf(id,title,body,summary){return '<details class="advanced-shelf" data-advanced-shelf="'+escapeHtmlClient(id)+'"><summary><span>'+escapeHtmlClient(title)+'</span><small>'+escapeHtmlClient(summary||'Advanced detail')+'</small></summary><div class="advanced-shelf-body">'+body+'</div></details>'}
function showGraphNodeDetail(node){const detail=document.querySelector('[data-graph-detail="true"]');if(!detail)return;let payload=null;try{payload=JSON.parse(node.getAttribute('data-graph-detail-json')||'null')}catch{}const group=node.getAttribute('data-graph-group')||payload?.type||'other';const title=payload?.title||node.getAttribute('data-graph-title')||node.getAttribute('data-graph-id')||'Graph node';const trust=payload?.trust||node.getAttribute('data-graph-trust')||'advisory_only';const pathValue=payload?.path||node.getAttribute('data-graph-path')||'';const command=node.getAttribute('data-graph-command')||'node .knowledge/tools/restore-trust.js --safe --json';const moduleId=node.getAttribute('data-graph-module')||'';if(group==='module'){const input=document.querySelector('[data-table-search="modules"]');if(input&&moduleId){input.value=moduleId;applyFilters('modules')}}if(!payload){detail.innerHTML='<div class="graph-detail-summary"><strong>'+escapeHtmlClient(title)+'</strong><p>Type: '+escapeHtmlClient(group)+' / Trust: '+escapeHtmlClient(trust)+'</p>'+(pathValue?'<p>Path: '+escapeHtmlClient(pathValue)+'</p>':'')+'</div>'+graphDetailShelf('graph-command','Command','<code>'+escapeHtmlClient(command)+'</code>','Exact fallback command.');return}const v=payload.verification||{};const summary='<div class="graph-detail-summary"><strong>'+escapeHtmlClient(title)+'</strong><p>Type: '+escapeHtmlClient(group)+' / Trust: '+escapeHtmlClient(trust)+(pathValue?' / Path: '+escapeHtmlClient(pathValue):'')+'</p>'+(payload.advisory_note?'<p class="graph-advisory">'+escapeHtmlClient(payload.advisory_note)+'</p>':'')+'<p>'+escapeHtmlClient(payload.trust_reason||'Trust comes from graph metadata; verify before behavior edits.')+'</p>'+(payload.why_route?'<p>'+escapeHtmlClient(payload.why_route)+'</p>':'')+'</div>';const actions='<section><h4>Next action</h4><div class="graph-detail-actions">'+(payload.next_actions||[]).map(graphAction).join('')+'</div></section>';detail.innerHTML='<div class="graph-detail-head">'+summary+actions+'</div><div class="graph-detail-grid">'+graphDetailShelf('graph-incoming','Incoming links',graphList(payload.incoming,'No incoming links for this node.',graphEdgeText),'Links pointing to this node.')+graphDetailShelf('graph-outgoing','Outgoing links',graphList(payload.outgoing,'No outgoing links for this node.',graphEdgeText),'Links leaving this node.')+graphDetailShelf('graph-evidence','Evidence / tests / code','<b>Evidence</b>'+graphArtifacts(v.evidence,'No evidence JSON listed.')+'<b>Tests</b>'+graphArtifacts(v.tests,'No tests listed.')+'<b>Code</b>'+graphArtifacts(v.code,'No code/module files listed.')+(v.gaps&&v.gaps.length?'<p class="muted">'+escapeHtmlClient(v.gaps.join(' '))+'</p>':''),'Raw verification sources.')+graphDetailShelf('graph-status','Status','<p>'+escapeHtmlClient(graphStatusText(payload.status))+'</p>'+graphArtifacts(payload.status?.stale_items||[],'No stale items matched this node.'),'Broken/orphan/stale details.')+'</div>'}
async function shutdownInspector(){if(!liveMode||!sessionToken){showToast('No live Inspector process');return}if(!confirm('Turn off the live Inspector and release this port?'))return;const out=document.getElementById('result');const button=document.querySelector('[data-shutdown="true"]');if(button){button.disabled=true;button.textContent='Turning off...'}setResultPanel(true,'Inspector shutdown');if(out)out.textContent='Closing Inspector server...';try{const res=await fetch('/api/shutdown',{method:'POST',headers:authHeaders({'Content-Type':'application/json'}),body:'{}'});const json=await res.json();if(!res.ok)throw new Error(json?.error||('HTTP '+res.status));if(out)out.textContent=JSON.stringify(json,null,2);if(button)button.textContent='Turning off';showToast('Inspector is shutting down');setTimeout(()=>{try{window.close()}catch{}},450)}catch(error){if(button){button.disabled=false;button.textContent='Turn off'}if(out)out.textContent='Shutdown request failed: '+error.message}}
function branchByName(name){return (gitBranchState.branches||[]).find((branch)=>branch.name===name)||null}
function setBranchField(name,value){document.querySelectorAll('[data-branch-field="'+name+'"]').forEach((el)=>{el.textContent=value||'none'})}
function dirtyLabel(diagnostics){if(diagnostics.current_worktree_dirty===true){const s=diagnostics.dirty_summary||{};return 'dirty ('+(s.changed||0)+' changed, '+(s.staged||0)+' staged)'}if(diagnostics.current_worktree_dirty===false)return 'clean';return 'not checked in current worktree'}
function applyBranchDiagnostics(name){const branch=branchByName(name)||{};const active=gitBranchState.active||'unknown';const current=(branch.name||name)===active;const diagnostics={branch:branch.name||name||active,active_branch:active,head_sha:branch.head_sha||'',upstream:branch.upstream||null,worktree_path:branch.worktree_path||null,current_worktree_dirty:current?gitDirtyState.dirty:null,dirty_summary:current?gitDirtyState.dirty_summary:null,note:current?'Diagnostics are using the active worktree.':(branch.worktree_path?'Branch is checked out in another worktree; run diagnostics there for file-level status.':'Branch is not checked out in this worktree; select or create a worktree before file-level diagnostics.')};setBranchField('branch',diagnostics.branch);setBranchField('active',diagnostics.active_branch);setBranchField('head',(diagnostics.head_sha||'').slice(0,12)||'unknown');setBranchField('upstream',diagnostics.upstream||'none');setBranchField('worktree',diagnostics.worktree_path||'not checked out');setBranchField('dirty',dirtyLabel(diagnostics));setBranchField('note',diagnostics.note)}
async function refreshBranchDiagnostics(name){applyBranchDiagnostics(name);if(!liveMode||!sessionToken)return;try{const res=await fetch('/api/git/diagnostics?branch='+encodeURIComponent(name),{headers:authHeaders()});const json=await res.json();if(json.ok&&json.diagnostics){setBranchField('branch',json.diagnostics.branch||'unknown');setBranchField('active',json.diagnostics.active_branch||gitBranchState.active||'unknown');setBranchField('head',((json.diagnostics.head_sha||'').slice(0,12)||'unknown'));setBranchField('upstream',json.diagnostics.upstream||'none');setBranchField('worktree',json.diagnostics.worktree_path||'not checked out');setBranchField('dirty',dirtyLabel(json.diagnostics));setBranchField('note',json.diagnostics.note||'')}}catch{}}
function onboardingAttrJson(name,fallback){const card=document.getElementById('onboarding-wizard');try{return JSON.parse(card?.getAttribute(name)||'')||fallback}catch{return fallback}}
function onboardingAgents(){return onboardingAttrJson('data-onboarding-agents',[])}
function onboardingSettings(){return onboardingAttrJson('data-onboarding-agent-settings',{})}
function onboardingSelectedAgent(){const select=document.getElementById('onboarding-agent');const id=select?.value||'';return onboardingAgents().find((agent)=>agent.id===id)||{id:id||'local-agent',label:id||'local-agent',runtime:id||''}}
function setControlValue(id,value){const el=document.getElementById(id);if(el&&value!=null)el.value=value}
function onboardingAgentSummary(agent){const bits=[agent.runtime?'runtime '+agent.runtime:'',agent.status?'status '+agent.status:'',agent.branch?'branch '+agent.branch:'',agent.workspace_id?'workspace '+agent.workspace_id:''].filter(Boolean);return bits.join(' / ')||'No active session metadata yet.'}
function applyOnboardingAgentSettings(agentId){const settings=onboardingSettings()[agentId]||{};setControlValue('onboarding-user-mode',settings.user_mode||'simple');setControlValue('onboarding-permission',settings.agents_can_do_without_asking||'run checks and reports');setControlValue('onboarding-concurrency',settings.concurrent_work_policy||'Safe Queue');setControlValue('onboarding-merge',settings.merge_policy||'Manual Only');setControlValue('onboarding-footer',settings.report_footer_mode||'compact');setControlValue('onboarding-repair-mode',settings.repair_mode||'scoped');setControlValue('onboarding-repair-max-findings',settings.repair_max_findings??2);setControlValue('onboarding-repair-max-minutes',settings.repair_max_extra_minutes??5);setControlValue('onboarding-repair-max-context',settings.repair_max_extra_context_percent??10);const rebuild=document.getElementById('onboarding-repair-rebuild');if(rebuild)rebuild.checked=settings.repair_rebuild_generated_artifacts!==false;const critical=document.getElementById('onboarding-repair-confirm-critical');if(critical)critical.checked=settings.repair_require_confirmation_for_critical_paths!==false;const agent=onboardingAgents().find((item)=>item.id===agentId)||{};document.querySelectorAll('[data-onboarding-agent-summary]').forEach((el)=>{el.textContent=onboardingAgentSummary(agent)})}
async function saveOnboarding(){if(!liveMode||!sessionToken){copyText('node .knowledge/inspector.js');return}const out=document.getElementById('result');setResultPanel(true,'Setup response');if(out)out.textContent='Saving first-run setup...';const selectedAgent=onboardingSelectedAgent();const repairMode=document.getElementById('onboarding-repair-mode')?.value||'scoped';let aggressiveConfirmed=false;if(repairMode==='aggressive'){aggressiveConfirmed=confirm('Extended repair may inspect task-adjacent dependencies. Safety rules, confirmation requirements, and budgets still apply. Enable it?');if(!aggressiveConfirmed){if(out)out.textContent='Extended repair was not enabled.';return}}const body={agent_id:selectedAgent.id,agent_runtime:selectedAgent.runtime||selectedAgent.id,agent_display_name:selectedAgent.label||selectedAgent.id,user_mode:document.getElementById('onboarding-user-mode')?.value||'simple',agents_can_do_without_asking:document.getElementById('onboarding-permission')?.value||'run checks and reports',concurrent_work_policy:document.getElementById('onboarding-concurrency')?.value||'Safe Queue',merge_policy:document.getElementById('onboarding-merge')?.value||'Manual Only',report_footer_mode:document.getElementById('onboarding-footer')?.value||'compact',detected_agent_runtime:selectedAgent.runtime||selectedAgent.id,repair_on_touch:{mode:repairMode,max_findings_per_task:Number(document.getElementById('onboarding-repair-max-findings')?.value??2),max_extra_minutes:Number(document.getElementById('onboarding-repair-max-minutes')?.value??5),max_extra_context_percent:Number(document.getElementById('onboarding-repair-max-context')?.value??10),rebuild_generated_artifacts:document.getElementById('onboarding-repair-rebuild')?.checked!==false,require_confirmation_for_critical_paths:document.getElementById('onboarding-repair-confirm-critical')?.checked!==false},repair_confirm_aggressive:aggressiveConfirmed};const res=await fetch('/api/settings/onboarding',{method:'POST',headers:authHeaders({'content-type':'application/json'}),body:JSON.stringify(body)});const json=await res.json();if(out)out.textContent=JSON.stringify(json,null,2);if(json.ok){const card=document.getElementById('onboarding-wizard');const bodyEl=card?.querySelector('.onboarding-body');if(bodyEl)bodyEl.hidden=true;if(card)card.setAttribute('data-onboarding-expanded','false');const repairBody=document.querySelector('[data-repair-setup-body]');if(repairBody)repairBody.hidden=true;showToast('Setup saved')}}
async function runLocalAction(id){if(!liveMode||!sessionToken)return;const out=document.getElementById('result');setResultPanel(true,'Latest local action output');if(out)out.textContent='Running '+id+'...';const res=await fetch('/api/actions/'+encodeURIComponent(id)+'/run',{method:'POST',headers:authHeaders({'content-type':'application/json'}),body:JSON.stringify({confirmed:true})});const json=await res.json();if(out)out.textContent=JSON.stringify(json,null,2);showToast(json.ok?'Action finished':'Action needs review')}
function repairSettingsRequestBody(){return{mode:document.getElementById('repair-setting-mode')?.value||'scoped',max_findings_per_task:Number(document.getElementById('repair-setting-max-findings')?.value??2),max_extra_minutes:Number(document.getElementById('repair-setting-max-minutes')?.value??5),max_extra_context_percent:Number(document.getElementById('repair-setting-max-context')?.value??10),rebuild_generated_artifacts:document.getElementById('repair-setting-rebuild')?.checked!==false,require_confirmation_for_critical_paths:document.getElementById('repair-setting-confirm-critical')?.checked!==false,require_confirmation_for_security_findings:document.getElementById('repair-setting-confirm-security')?.checked!==false}}
function showRepairWarning(){const mode=document.getElementById('repair-setting-mode')?.value;document.querySelectorAll('[data-repair-aggressive-warning]').forEach((el)=>{el.hidden=mode!=='aggressive'})}
async function saveRepairSettingsUi(reset=false){if(!liveMode||!sessionToken){copyText('node .knowledge/tools/repair-on-touch.js settings show');return}const out=document.getElementById('result');setResultPanel(true,'Repair settings response');const body=reset?{}:repairSettingsRequestBody();if(!reset&&body.mode==='aggressive'){body.confirm_aggressive=confirm('Extended repair may inspect task-adjacent dependencies. It cannot bypass safety invariants or confirmation rules. Continue?');if(!body.confirm_aggressive){if(out)out.textContent='Extended repair was not enabled.';return}}const endpoint=reset?'/api/settings/repair-on-touch/reset':'/api/settings/repair-on-touch';const res=await fetch(endpoint,{method:'POST',headers:authHeaders({'content-type':'application/json'}),body:JSON.stringify(body)});const json=await res.json();if(out)out.textContent=JSON.stringify(json,null,2);if(json.ok){showToast(reset?'Repair settings reset':'Repair settings saved')}else{showToast('Repair settings were not saved')}}
function cancelRepairSettingsUi(){showToast('Unsaved repair settings discarded');window.location.reload()}
document.addEventListener('click',(event)=>{const openLink=event.target.closest('[data-open-path]');if(openLink){const pathValue=openLink.getAttribute('data-open-path')||'';if(pathValue){event.preventDefault();openInspectorFile(pathValue,openLink.getAttribute('href')||'#');return}}const closePreview=event.target.closest('[data-file-preview-close]');if(closePreview){closeFilePreview();return}const copyPreviewPath=event.target.closest('[data-file-preview-copy-path]');if(copyPreviewPath){copyText(currentPreviewPath);return}const copyPreviewCode=event.target.closest('[data-file-preview-copy-code]');if(copyPreviewCode){copyText(codeCommandForPath(currentPreviewPath));return}const copy=event.target.closest('[data-copy]');if(copy){copyText(copy.getAttribute('data-copy'));return}const shutdown=event.target.closest('[data-shutdown]');if(shutdown){shutdownInspector();return}const graphToggle=event.target.closest('[data-graph-toggle]');if(graphToggle){const id=graphToggle.getAttribute('data-graph-toggle');const shelf=document.querySelector('[data-graph-shelf="'+id+'"]');setGraphShelf(id,!shelf?.classList.contains('is-collapsed'));return}const graphNode=event.target.closest('[data-graph-node]');if(graphNode){showGraphNodeDetail(graphNode);return}const resultToggle=event.target.closest('[data-result-toggle]');if(resultToggle){const panel=document.querySelector('[data-result-panel="true"]');const open=panel?.classList.contains('is-collapsed');setResultPanel(open,open?'Latest local action output':'Collapsed until an action runs');return}const toggle=event.target.closest('[data-onboarding-toggle]');if(toggle){const card=document.getElementById('onboarding-wizard');const body=card?.querySelector('.onboarding-body');if(body){body.hidden=!body.hidden;if(card)card.setAttribute('data-onboarding-expanded',body.hidden?'false':'true')}return}const save=event.target.closest('[data-onboarding-save]');if(save){saveOnboarding();return}const localAction=event.target.closest('[data-action]');if(localAction){runLocalAction(localAction.getAttribute('data-action'));return}const updateMode=event.target.closest('[data-update-mode="auto-check"]');if(updateMode){toggleUpdateAutoCheck(updateMode);return}const update=event.target.closest('[data-update-action]');if(update){const action=update.getAttribute('data-update-action');setResultPanel(true,'Update action output');if(action==='status')updateApi('/api/update/status?refresh=1');if(action==='dry-run')updateApi('/api/update/dry-run',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'});if(action==='apply'&&confirm('Apply .knowledge system update now? Project knowledge will be preserved and a backup will be created.')){const latest=document.getElementById('updateBanner')?.getAttribute('data-latest-version')||'';updateApi('/api/update/apply',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({confirm:true,expectedVersion:latest&&latest!=='-'?latest:null})})}return}const tab=event.target.closest('[data-tab]');if(tab){document.querySelectorAll('.tab-btn').forEach((b)=>b.classList.remove('active'));document.querySelectorAll('.tab-panel').forEach((p)=>p.classList.remove('active'));tab.classList.add('active');const panel=document.querySelector('[data-panel="'+tab.getAttribute('data-tab')+'"]');if(panel)panel.classList.add('active')}});
document.addEventListener('keydown',(event)=>{const graphNode=event.target.closest?.('[data-graph-node]');if(graphNode&&(event.key==='Enter'||event.key===' ')){event.preventDefault();showGraphNodeDetail(graphNode)}});
document.addEventListener('click',(event)=>{const repairSetup=event.target.closest('[data-repair-setup-toggle]');if(repairSetup){const body=document.querySelector('[data-repair-setup-body]');if(body)body.hidden=!body.hidden;return}if(event.target.closest('[data-repair-settings-save]')){saveRepairSettingsUi(false);return}if(event.target.closest('[data-repair-settings-reset]')){saveRepairSettingsUi(true);return}if(event.target.closest('[data-repair-settings-cancel]')){cancelRepairSettingsUi()}})
document.addEventListener('change',(event)=>{const agentSelect=event.target.closest('[data-onboarding-agent-select]');if(agentSelect){applyOnboardingAgentSettings(agentSelect.value);return}const select=event.target.closest('[data-branch-select]');if(select)refreshBranchDiagnostics(select.value)});
document.addEventListener('change',(event)=>{if(event.target.id==='repair-setting-mode')showRepairWarning()});
async function initInspectorLiveState(){if(location.protocol==='http:'||location.protocol==='https:')await updateApi('/api/update/status')}
initInspectorLiveState();
initGraphShelves();
showRepairWarning();
function applyFilters(tableName){const searchInput=document.querySelector('[data-table-search="'+tableName+'"]');const select=document.querySelector('[data-table-filter="'+tableName+'"]');const q=((searchInput&&searchInput.value)||'').toLowerCase();const f=((select&&select.value)||'').toLowerCase();document.querySelectorAll('table[data-table="'+tableName+'"] tbody tr').forEach((row)=>{const text=(row.getAttribute('data-search')||row.textContent||'').toLowerCase();const rowFilter=(row.getAttribute('data-filter')||'').toLowerCase();row.style.display=((!q||text.includes(q))&&(!f||rowFilter===f||rowFilter.includes(f)))?'':'none'})}
document.querySelectorAll('[data-table-search],[data-table-filter]').forEach((el)=>el.addEventListener('input',()=>applyFilters(el.getAttribute('data-table-search')||el.getAttribute('data-table-filter'))));
</script>
</body>
</html>`;
}

function escapeRegExp(value) {
  return String(value || '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function sanitizeInspectorHtml(html, data) {
  let out = String(html || '');
  const ctx = data.context || {};
  const replacements = [
    [ctx.targetRoot, '<targetRoot>'],
    [ctx.projectKnowledgeRoot, '<projectKnowledgeRoot>'],
    [ctx.stateRoot, '<stateRoot>'],
    [ctx.teamRoot, '<teamRoot>']
  ].filter(([from]) => from);
  for (const [from, to] of replacements) {
    out = out.replace(new RegExp(escapeRegExp(String(from)), 'g'), to);
    out = out.replace(new RegExp(escapeRegExp(String(from).replace(/\\/g, '/')), 'g'), to);
  }
  return out
    .replace(/[A-Z]:\\(?:Users\\[^\s"'<>\\]+|MyProject)[^\s"'<>]*/gi, '<local-path>')
    .replace(/\/mnt\/data[^\s"'<>]*/gi, '<local-path>')
    .replace(/\/tmp\/knowledge[^\s"'<>]*/gi, '<local-path>')
    .replace(/Users\\[^\s"'<>\\]+/gi, 'Users\\<local-user>')
    .replace(/Users\/[^\s"'<>/]+/gi, 'Users/<local-user>')
    .replace(new RegExp(`knowledge${'-'}kit`, 'gi'), 'workspace');
}

function sanitizeInspectorData(value) {
  if (typeof value === 'string') {
    return value
      .replace(/[A-Z]:\\(?:Users\\[^\s"',}\\]+|MyProject)[^\s"',}]+/gi, '<local-path>')
      .replace(/\/mnt\/data[^\s"',}]+/gi, '<local-path>')
      .replace(/\/tmp\/knowledge[^\s"',}]+/gi, '<local-path>')
      .replace(/Users\\[^\s"',}\\]+/gi, 'Users\\<local-user>')
      .replace(/Users\/[^\s"',}/]+/gi, 'Users/<local-user>')
      .replace(new RegExp(`knowledge${'-'}kit`, 'gi'), 'workspace');
  }
  if (Array.isArray(value)) return value.map(sanitizeInspectorData);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, sanitizeInspectorData(item)]));
  }
  return value;
}

function build(options = {}) {
  const data = collect();
  const outDir = path.join(stateRoot, 'inspector');
  ensureDir(outDir);
  const inspectorData = sanitizeInspectorData(data);
  const inspectorJson = JSON.stringify(inspectorData, null, 2);
  fs.writeFileSync(path.join(outDir, 'data.json'), inspectorJson + '\n', 'utf8');
  fs.writeFileSync(path.join(outDir, 'index.html'), sanitizeInspectorHtml(renderTabbed(data), data), 'utf8');
  const status = {
    generated_at: data.generated_at,
    generated_by: data.generated_by,
    mode: context.mode,
    output: context.mode === 'repo' ? '.knowledge/inspector/index.html' : path.join(outDir, 'index.html'),
    data: context.mode === 'repo' ? '.knowledge/inspector/data.json' : path.join(outDir, 'data.json'),
    features: [
      'improved_wiki_graph',
      'per_table_filters',
      'file_links',
      'empty_states',
      'low_confidence_explanations',
      'copy_command_fallback',
      'canonical_navigation',
      'team_mode_panel',
      'routing_bundle_view',
      'pr_summary_preview',
      'pr_impact_preview',
      'external_memory_status',
      'memory_provider_cards',
      'conversion_signal_preview'
      ,'tabbed_navigation'
      ,'local_action_drawer_fallback'
      ,'memory_provider_runtime_boundary'
      ,'restore_trust_entrypoint'
      ,'git_branch_diagnostics'
      ,'shared_live_static_renderer'
      ,'collapsible_onboarding'
      ,'metric_severity_cards'
      ,'trust_repair_agent_prompt'
      ,'inspector_update_api'
      ,'inspector_update_apply'
      ,'inspector_shutdown'
      ,'collapsible_trust_graph'
      ,'graph_node_drilldown'
      ,'onboarding_agent_picker'
      ,'plain_language_outcome_panels'
      ,'advanced_detail_shelves'
      ,'inline_file_preview_drawer'
      ,'vscode_simple_browser_layout'
      ,'app_shell_renderer'
      ,'inspector_update_auto_check_mode'
      ,'inspector_startup_update_check'
      ,'repair_on_touch_settings'
      ,'repair_opportunities'
      ,'global_doctor_and_task_readiness'
    ]
  };
  writeJsonAtomic(path.join(outDir, 'status.json'), status);
  if (!options.quiet) console.log(JSON.stringify(status, null, 2));
  return status;
}

if (require.main === module) withContainedLock(VISUAL_INSPECTOR_LOCK, () => build({ quiet: process.argv.includes('--quiet') }));
const runBuild = (options = {}) => options.skipLock ? build(options) : withContainedLock(VISUAL_INSPECTOR_LOCK, () => build(options));
module.exports = Object.assign(runBuild, {
  collect,
  renderAppShell,
  renderTabbed,
  sanitizeInspectorHtml,
  sanitizeInspectorData,
  repairAgentPrompt
});
