#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const { ensureDir, readJson, writeJsonAtomic, getAgentId, withLock } = require('./lib/json-store');
const { resolveKnowledgeContext, jsonContext } = require('./lib/path-context');
const { listTeamStatus, readLock, lockPath } = require('./lib/team-store');
const context = resolveKnowledgeContext();
const knowledgeRoot = context.projectKnowledgeRoot;
const stateRoot = context.stateRoot;
const repoRoot = context.targetRoot;
const lockDir = path.join(stateRoot, '.lock');

function isRuntimeRel(rel) {
  return /^(maintenance|metrics|search|inspector|sessions)\//.test(rel) ||
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
  if (!raw) return '<span class="muted">—</span>';
  const label = options.short ? shortPath(raw, options.short) : raw;
  const href = hrefForPath(raw);
  const cls = options.className || 'file-link';
  return `<a class="${cls}" href="${esc(href)}" title="${esc(raw)}">${esc(label)}</a>`;
}

function listLinks(values, empty = '—') {
  const arr = toArray(values).filter(Boolean);
  if (!arr.length) return `<span class="muted">${esc(empty)}</span>`;
  return `<div class="link-list">${arr.map((item) => fileLink(item, { short: 72 })).join('')}</div>`;
}

function shortPath(value, max = 64) {
  const text = normalizePath(value);
  if (text.length <= max) return text;
  const parts = text.split('/');
  if (parts.length <= 2) return `…${text.slice(-(max - 1))}`;
  const last = parts.pop();
  const first = parts.shift();
  const candidate = `${first}/…/${last}`;
  if (candidate.length <= max) return candidate;
  return `…/${last.slice(-(max - 3))}`;
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
  schema_version: '3.2.2',
  user_mode: 'simple',
  first_run_onboarding_completed: false,
  detected_agent_runtime: null
};

const DEFAULT_AUTONOMY_POLICY = {
  schema_version: '3.2.2',
  agents_can_do_without_asking: 'run checks and reports',
  network_actions_require_confirmation: true,
  destructive_actions_require_confirmation: true,
  controlled_autonomy: 'planned'
};

const DEFAULT_AGENT_POLICY = {
  schema_version: '3.2.2',
  concurrent_work_policy: 'Safe Queue',
  merge_policy: 'Manual Only',
  auto_merge: false,
  safe_queue_default: true
};

const DEFAULT_REPORT_FOOTER = {
  schema_version: '3.2.2',
  mode: 'compact',
  show_token_metrics: true,
  show_restore_action: true,
  show_open_inspector_action: true,
  only_when_trust_incomplete: false
};

function loadSettings() {
  return {
    operator_profile: safeJson('settings/operator-profile.json', DEFAULT_OPERATOR_PROFILE),
    autonomy_policy: safeJson('settings/autonomy-policy.json', DEFAULT_AUTONOMY_POLICY),
    agent_policy: safeJson('settings/agent-policy.json', DEFAULT_AGENT_POLICY),
    report_footer: safeJson('settings/report-footer.json', DEFAULT_REPORT_FOOTER)
  };
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
  const modules = safeJson('modules/module_registry.json', { modules: [] });
  const repair = safeJson('maintenance/repair_queue.json', { queue: [] });
  const stale = safeJson('maintenance/stale_items.json', { items: [] });
  const wikiGraph = safeJson('maps/wiki_graph.json', { nodes: [], edges: [], summary: {} });
  const fileCriticality = safeJson('maps/file_criticality.json', { files: [] });
  const external = safeJson('maintenance/external_memory_status.json', {});
  const appliedTemplates = safeJson('maintenance/applied_templates.json', { templates: [] });
  const metrics = safeJson('metrics/baseline.json', {});
  const secretScan = safeJson('maintenance/secret_scan_report.json', {});
  const searchIndex = safeJson('search/index.json', { documents: [] });
  const wikiLint = safeJson('maintenance/wiki_lint_report.json', {});
  const prImpact = safeJson('maintenance/pr_impact.json', { status: 'not_generated', changed_files: [], affected_modules: [], policy_warnings: [] });
  const updateStatus = safeJson('maintenance/update_status.json', { status: 'never_checked' });
  const settings = loadSettings();
  settings.user_mode = settings.operator_profile.user_mode || 'simple';
  settings.onboarding = onboardingState(settings);
  let team = null;
  let lockOwner = null;
  if (context.teamRoot) {
    try { team = listTeamStatus(context.teamRoot); } catch (error) { team = { warnings: [error.message] }; }
    try { lockOwner = readLock(lockPath(context.teamRoot, context.repoId, 'flow')); } catch { lockOwner = null; }
  }
  return {
    generated_at: new Date().toISOString(),
    generated_by: getAgentId(),
    context: jsonContext(context),
    trust,
    quality,
    routing,
    modules,
    repair,
    stale,
    wikiGraph,
    fileCriticality,
    external,
    appliedTemplates,
    metrics,
    secretScan,
    searchIndex,
    wikiLint,
    prImpact,
    updateStatus,
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

function graphNodeHref(node) {
  const target = normalizePath(node.path || '');
  if (!target) return '';
  if (['.knowledge/evidence', '.knowledge/modules', '.knowledge/wiki', '.knowledge/sessions', '.knowledge/external_memory'].includes(target)) return hrefForPath(target);
  if (target.startsWith('.knowledge/') || /^(docs|modules|maps|maintenance|wiki|evidence|external_memory|sessions)\//.test(target)) return hrefForPath(target);
  return '';
}

function compactGraphLabel(value, max = 24) {
  const text = String(value || '').replace(/^Module:\s*/i, '').replace(/^Current\s+/i, '').trim();
  return text.length <= max ? text : `${text.slice(0, Math.max(8, max - 1))}...`;
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

function layoutGraph(nodes, edges) {
  const nodeList = (nodes || []).slice(0, 120);
  const edgeList = (edges || []).slice(0, 260);
  if (!nodeList.length) return { nodes: [], edges: [], width: 980, height: 520 };
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
  const width = 980;
  const height = 520;
  const positioned = [
    ...placeGraphRow(groups.source_truth, 82, width, 74, 94),
    ...placeGraphRow(groups.module, 238, width, 170, 170),
    ...placeGraphRow(groups.wiki, 385, width, 106, 116),
    ...placeGraphRow(groups.other, 470, width, 120, 120)
  ].map((node) => ({
    ...node,
    group: graphGroup(node),
    degree: degrees.get(node.id) || 0,
    r: Math.min(17, Math.max(9, 8 + Math.sqrt(degrees.get(node.id) || 1) * 2))
  }));
  const byId = new Map(positioned.map((node) => [node.id, node]));
  const visibleEdges = edgeList.map((edge) => {
    const a = byId.get(edge.from);
    const b = byId.get(edge.to);
    if (!a || !b) return null;
    return { ...edge, a, b };
  }).filter(Boolean);
  return { nodes: positioned, edges: visibleEdges, width, height };
}

function edgePath(edge) {
  const { a, b } = edge;
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

function freeCoreGraphSvg(data) {
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
    return `<path d="${edgePath(edge)}" class="edge ${relationClass(relation)}${valid}" marker-end="url(#graph-arrow)"><title>${esc(relation)}\n${esc(edge.from)} -> ${esc(edge.to)}${edge.reason ? `\n${esc(edge.reason)}` : ''}</title></path>`;
  }).join('');
  const nodeMarkup = layout.nodes.map((node) => {
    const trust = trustClass(node.trust || node.status || 'advisory_only');
    const group = graphGroup(node);
    const label = compactGraphLabel(node.title || node.page || node.id || '', group === 'source_truth' ? 21 : 26);
    const yLabel = group === 'source_truth' ? node.y - 25 : node.y + 31;
    const body = `<g class="graph-node ${esc(group)}"><circle cx="${node.x.toFixed(1)}" cy="${node.y.toFixed(1)}" r="${node.r}" class="node ${esc(trust)} ${esc(group)}"><title>${esc(node.title || '')}\n${esc(node.id || '')}\ntrust: ${esc(node.trust || 'advisory_only')}\n${esc(node.description || '')}</title></circle><text x="${node.x.toFixed(1)}" y="${yLabel.toFixed(1)}" class="label ${esc(group)}">${esc(label)}</text></g>`;
    const href = graphNodeHref(node);
    return href ? `<a href="${esc(href)}" class="graph-link">${body}</a>` : body;
  }).join('');
  const legendTypes = ['outranks', 'routes', 'documents', 'checks', 'references', 'advisory', 'supports', 'depends_on', 'contradicts'];
  const legend = legendTypes.map((type) => `<span><i class="edge-swatch ${type}"></i>${esc(type)}</span>`).join('');
  const sourceOrder = graph.summary?.source_truth_order || [];
  return `<div class="free-core-graph" data-free-core-graph="true"><div class="graph-tools"><div><strong>Free Core Trust Graph</strong><p class="sub">Source-of-truth order, module routing, wiki relations, and advisory boundaries.</p></div>${copyButton('node .knowledge/tools/build-wiki-graph.js', 'Copy rebuild command')}</div><div class="graph-metrics">${graphMetric('nodes', graph.node_count ?? graphNodes.length)}${graphMetric('edges', graph.edge_count ?? graphEdges.length)}${graphMetric('broken', graph.broken_edge_count || 0)}${graphMetric('orphans', graph.orphan_page_count || 0)}${graphMetric('readiness', graph.readiness || 'unknown')}</div><div class="legend">${legend}</div><svg class="wiki-svg trust-graph-svg" viewBox="0 0 ${layout.width} ${layout.height}" role="img" aria-label="Free core trust graph">${defs}${lanes}${edgeMarkup}${nodeMarkup}</svg>${sourceOrder.length ? `<div class="source-order-strip"><strong>Trust order:</strong> ${esc(sourceOrder.join(' > '))}</div>` : ''}${graphEdges.length ? graphInsights(graph) : emptyState('Graph has nodes but no relations', 'Add typed links or rerun the 3.2.2 graph builder to restore relation edges.', 'node .knowledge/tools/build-wiki-graph.js')}</div>`;
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
    return `<path d="${edgePath(edge)}" class="edge ${esc(relation)}${valid}"><title>${esc(relation)}\n${esc(edge.from)} → ${esc(edge.to)}</title></path>`;
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
  return `<div class="empty-state"><div class="empty-icon">◇</div><h3>${esc(title)}</h3><p>${esc(text)}</p>${command ? commandBox(command, 'Copy fix command') : ''}</div>`;
}

function rowAttr(search, filter = '') {
  return ` data-search="${esc(String(search || '').toLowerCase())}" data-filter="${esc(String(filter || '').toLowerCase())}"`;
}

function renderModules(data) {
  const modules = getModules(data);
  if (!modules.length) {
    return emptyState('No modules yet', 'Run ingest to create module routing and cards.', 'node .knowledge/tools/ingest-existing-project.js --merge');
  }
  return `<div class="table-controls"><input data-table-search="modules" placeholder="Filter modules by id, path, trust, reason..."><select data-table-filter="modules"><option value="">All trust levels</option><option value="trusted">trusted</option><option value="near_trusted">near_trusted</option><option value="routing_trusted">routing_trusted</option><option value="advisory_only">advisory_only</option><option value="suspect">suspect</option><option value="low_confidence">low_confidence</option><option value="unknown">unknown</option></select></div><table class="filterable" data-table="modules"><thead><tr><th>Module</th><th>Trust</th><th>Confidence</th><th>Why low / next check</th><th>Path</th><th>Card</th></tr></thead><tbody>${modules.map((module) => {
    const trust = module.trust_status || 'unknown';
    const reasons = module.reasons || [];
    const search = [module.module_id, trust, module.confidence, module.path, module.card, reasons.join(' ')].join(' ');
    return `<tr${rowAttr(search, trust)}><td><strong>${esc(module.module_id)}</strong></td><td><span class="pill ${trustClass(trust)}">${esc(trust)}</span></td><td>${esc(module.confidence || '—')}</td><td><ul class="reason-list">${reasons.map((reason) => `<li>${esc(reason)}</li>`).join('')}</ul></td><td>${module.path ? fileLink(module.path, { short: 46 }) : '<span class="muted">—</span>'}</td><td>${fileLink(module.card || `.knowledge/modules/${module.module_id}.json`, { short: 46 })}</td></tr>`;
  }).join('')}</tbody></table>`;
}

function renderRepair(data) {
  const rows = getRepairItems(data).slice(0, 250);
  if (!rows.length) return emptyState('No repair items', 'Nothing is currently queued. Run doctor or ingest after significant changes.', 'node .knowledge/tools/doctor.js');
  return `<div class="table-controls"><input data-table-search="repair" placeholder="Filter repair queue..."><select data-table-filter="repair"><option value="">All priorities</option><option value="critical">critical</option><option value="high">high</option><option value="medium">medium</option><option value="low">low</option></select></div><table class="filterable" data-table="repair"><thead><tr><th>Priority</th><th>Status</th><th>Subject</th><th>Artifacts</th><th>Reason</th></tr></thead><tbody>${rows.map((item) => {
    const priority = item.priority || 'medium';
    const search = [priority, item.status, item.subject, item.reason, toArray(item.affected_artifacts).join(' ')].join(' ');
    return `<tr${rowAttr(search, priority)}><td><span class="pill ${trustClass(priority)}">${esc(priority)}</span></td><td>${esc(item.status || 'open')}</td><td>${esc(item.subject)}</td><td>${listLinks(item.affected_artifacts)}</td><td>${esc(item.reason || '—')}</td></tr>`;
  }).join('')}</tbody></table>`;
}

function renderStale(data) {
  const rows = getStaleItems(data).slice(0, 250);
  if (!rows.length) return emptyState('No stale items', 'Freshness checks have not found stale artifacts.', 'node .knowledge/tools/sync-tracked.js --scan');
  return `<div class="table-controls"><input data-table-search="stale" placeholder="Filter stale items..."><select data-table-filter="stale"><option value="">All statuses</option><option value="stale">stale</option><option value="missing">missing</option><option value="changed">changed</option><option value="needs_recheck">needs_recheck</option></select></div><table class="filterable" data-table="stale"><thead><tr><th>Status</th><th>Artifact</th><th>Reason</th><th>Action</th></tr></thead><tbody>${rows.map((item) => {
    const status = item.status || 'stale';
    const search = [status, item.artifact, item.reason, item.action].join(' ');
    return `<tr${rowAttr(search, status)}><td><span class="pill ${trustClass(status)}">${esc(status)}</span></td><td>${fileLink(item.artifact, { short: 70 })}</td><td>${esc(item.reason || '—')}</td><td>${esc(item.action || '—')}</td></tr>`;
  }).join('')}</tbody></table>`;
}

function renderCriticalFiles(data) {
  const rows = getCriticalFiles(data).slice(0, 250);
  if (!rows.length) return emptyState('No critical or important files mapped', 'Run ingest and sync to classify project files.', 'node .knowledge/tools/ingest-existing-project.js --merge');
  return `<div class="table-controls"><input data-table-search="critical" placeholder="Filter files..."><select data-table-filter="critical"><option value="">All classes</option><option value="critical">critical</option><option value="important">important</option></select></div><table class="filterable" data-table="critical"><thead><tr><th>Class</th><th>Path</th><th>Modules</th><th>Reason</th></tr></thead><tbody>${rows.map((file) => {
    const cls = file.classification || 'important';
    const search = [cls, file.path, toArray(file.modules).join(' '), file.reason].join(' ');
    return `<tr${rowAttr(search, cls)}><td><span class="pill ${trustClass(cls)}">${esc(cls)}</span></td><td>${fileLink(file.path, { short: 82 })}</td><td>${esc(toArray(file.modules).join(', ') || '—')}</td><td>${esc(file.reason || '—')}</td></tr>`;
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
    return `<tr${rowAttr(search, provider.mode || '')}><td><strong>${esc(provider.provider || 'unknown')}</strong></td><td>${esc(provider.enabled ?? false)}</td><td>${esc(provider.mode || provider.status || 'unknown')}</td><td>${esc(provider.trust_role || 'advisory_only')}</td><td>${esc(provider.path || provider.source || '—')}</td><td>${esc(warnings || '—')}</td></tr>`;
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
  const policy = data.external.source_of_truth_policy || {};
  const legacyCard = legacy.length
    ? card('Legacy Claude MEM - advisory legacy only', legacy[0], 'Legacy artifacts are shown only for migration/archive awareness and cannot raise trust.', copyButton('node .knowledge/tools/memory-provider.js migrate-legacy --json', 'Write deprecation note'))
    : '';
  return `<div class="empty-state"><h3>External memory is advisory</h3><p>Code, tests and evidence outrank memory. Memory cannot raise trust automatically.</p></div><div class="signal-grid" style="margin-top:12px">${card('.knowledge Source of Truth', { status: 'authoritative', license_spdx: 'Apache-2.0', trust_effect: 'source_of_truth', data_path: data.context?.projectKnowledgeRoot }, `Curated repo-local knowledge stays in modules, evidence, wiki and decisions. External memory policy: source_of_truth=${esc(policy.external_memory_source_of_truth ?? false)}, can_raise_trust=${esc(policy.external_memory_can_raise_trust ?? false)}.`)}${card('Mem0 OSS - recommended optional universal backend', mem0, 'Universal optional backend for local/core use. Live health auto-detects Python in standard locations, keeps discovery probes short, uses a 30000 ms health timeout for slow first Windows import mem0, never installs packages, and reports runtime_not_installed unless mem0ai is importable.', `${copyButton('node .knowledge/tools/memory-provider.js preview mem0-oss --json', 'Preview Mem0')}${copyButton('node .knowledge/tools/memory-provider.js status mem0-oss --json', 'Mem0 Status')}${copyButton('node .knowledge/tools/memory-mem0.js health --adapter live --json', 'Live Mem0 Health')}${copyButton('node .knowledge/tools/memory-mem0.js add --text "..." --scope repo --json', 'Mem0 Add')}${copyButton('node .knowledge/tools/memory-mem0.js search "query" --json', 'Mem0 Search')}`)}${card('Pinecone - optional vector/cloud retrieval', pinecone, 'Optional vector/cloud retrieval provider for teams already using Pinecone. Status stays offline and never needs an API key just to render.', `${copyButton('node .knowledge/tools/memory-provider.js status pinecone --json', 'Pinecone Status')}${copyButton('node .knowledge/tools/external/pinecone-search.js "query" --dry-run', 'Dry-run Search')}${copyButton('node .knowledge/tools/memory-provider.js preview pinecone --json', 'Pinecone Preview')}`)}<div class="signal-card"><strong>Graphiti - future optional temporal graph</strong><span>not included in free core</span><p>Temporal graph provider contracts are not part of this install asset. Free core keeps external memory advisory.</p></div><div class="signal-card"><strong>Zep - future optional managed/BYOC memory</strong><span>not included in free core</span><p>Managed memory provider contracts are not part of this install asset. Free core keeps the advisory policy boundary.</p></div>${legacyCard}</div><div class="mini-actions">${copyButton('node .knowledge/tools/memory-provider.js status-all --json', 'Memory Status')}${copyButton('node .knowledge/tools/memory-provider.js list --json', 'List Providers')}${fileLink('maintenance/external_memory_status.json', { short: 54 })}</div>`;
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
    ['Preview Mem0', 'node .knowledge/tools/memory-provider.js preview mem0-oss --json']
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
  const manual = [
    ['Check Updates', 'node .knowledge/tools/check-updates.js --json'],
    ['Dry-run Update', 'node .knowledge/tools/update-system-files.js --from <new-knowledge-root> --target-knowledge-root .knowledge --dry-run --json'],
    ['Apply Update', 'node .knowledge/tools/update-system-files.js --from <new-knowledge-root> --target-knowledge-root .knowledge --apply --yes --json'],
    ['Verify Upgrade', 'node .knowledge/tools/update-system-files.js --verify-upgrade --json']
  ];
  return `<div class="update-banner" id="updateBanner" data-current-version="${esc(current)}" data-latest-version="${esc(latest)}"><div><strong>Update status: <span id="updateState">${esc(state)}</span></strong><p class="sub" id="updateSummary">Current ${esc(current)} · Latest ${esc(latest)} · Asset ${esc(asset)}. Served Inspector checks the official release feed on launch; static Inspector stays local and command-only.</p></div><div class="mini-actions"><button class="copy-btn" type="button" data-update-action="status">Check Now</button><button class="copy-btn" type="button" data-update-action="dry-run">View Plan</button><button class="copy-btn danger-btn" type="button" data-update-action="apply">Apply Update</button></div></div><pre class="markdown-preview" id="updateOutput">No live update check has run in this Inspector tab yet.</pre><div class="quick-actions">${manual.map(([label, command]) => `<button class="action-card" type="button" data-copy="${esc(command)}"><span>${esc(label)}</span><code>${esc(command)}</code></button>`).join('')}</div>`;
}

function renderRouting(data) {
  const routing = data.routing || {};
  const first = routing.first_read_strategy?.read_first || '.knowledge/maintenance/routing_bundle.json';
  const modules = routing.modules || [];
  return `<table class="kv"><tr><th>First read</th><td>${esc(first)}</td></tr><tr><th>Mode</th><td>${esc(data.context.mode)}</td></tr><tr><th>Modules</th><td>${esc(modules.length)}</td></tr><tr><th>High risk</th><td>${esc((routing.high_risk_modules || []).join(', ') || '—')}</td></tr><tr><th>Source of truth</th><td>${esc((routing.source_of_truth_order || []).join(' > '))}</td></tr></table><div class="mini-actions">${copyButton('node .knowledge/tools/build-routing-bundle.js --json', 'Copy rebuild command')}</div>`;
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
  return `<table class="kv"><tr><th>Mode</th><td>${esc(ctx.mode || 'repo')}</td></tr><tr><th>Repo ID</th><td>${esc(ctx.repoId || '—')}</td></tr><tr><th>Workspace</th><td>${esc(ctx.workspaceId || '—')}</td></tr><tr><th>Agent</th><td>${esc(ctx.agentId || '—')}</td></tr><tr><th>Target root</th><td>${esc(ctx.targetRoot || '—')}</td></tr><tr><th>State root</th><td>${esc(ctx.stateRoot || '—')}</td></tr><tr><th>Branch/head</th><td>${esc(`${ctx.branch || 'unknown'} / ${(ctx.headSha || '').slice(0, 12) || 'unknown'}`)}</td></tr><tr><th>Active workspaces</th><td>${esc(active)}</td></tr><tr><th>Flow lock owner</th><td>${esc(data.lockOwner ? `${data.lockOwner.agentId || data.lockOwner.pid} on ${data.lockOwner.branch || 'unknown'}` : 'none')}</td></tr><tr><th>Warnings</th><td>${esc(warnings.join('; ') || '—')}</td></tr></table><div class="mini-actions">${copyButton('node .knowledge/tools/worktree-status.js --json', 'Copy worktree check')}${copyButton('node .knowledge/tools/flow.js release --exclusive --json', 'Copy exclusive release')}${copyButton('node .knowledge/tools/team-status.js --team-root <teamRoot> --json', 'Copy team status')}</div>`;
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

function renderOnboarding(data, options = {}) {
  const settings = data.settings || {};
  const profile = settings.operator_profile || DEFAULT_OPERATOR_PROFILE;
  const autonomy = settings.autonomy_policy || DEFAULT_AUTONOMY_POLICY;
  const agent = settings.agent_policy || DEFAULT_AGENT_POLICY;
  const footer = settings.report_footer || DEFAULT_REPORT_FOOTER;
  const onboarding = settings.onboarding || onboardingState(settings);
  const expanded = onboarding.required === true;
  const saveControl = options.live
    ? '<button class="copy-btn" type="button" data-onboarding-save="true">Save setup</button>'
    : copyButton('node .knowledge/inspector.js', 'Open live setup');
  const status = onboarding.completed ? `Completed${onboarding.completed_at ? ` at ${onboarding.completed_at}` : ''}` : `Required: ${onboarding.reason || 'not_completed'}`;
  return `<div class="card onboarding-card${expanded ? ' requires-setup' : ''}" id="onboarding-wizard" data-onboarding-wizard="true" data-onboarding-expanded="${expanded ? 'true' : 'false'}"><button class="onboarding-toggle" type="button" data-onboarding-toggle="true"><span>First-run setup</span><small>${esc(status)}</small></button><div class="onboarding-body"${expanded ? '' : ' hidden'}><p class="sub">Use safe defaults or tune agent behavior before local agents write reports.</p><div class="setting-list"><label class="setting-row"><span><strong>Connected agent</strong><small>Detected runtime for reports and sessions.</small></span><input id="onboarding-runtime" value="${esc(profile.detected_agent_runtime || '')}" placeholder="none yet"></label><label class="setting-row"><span><strong>User mode</strong><small>Simple keeps summaries plain; Advanced shows raw evidence.</small></span>${selectControl('onboarding-user-mode', profile.user_mode || 'simple', [['simple', 'Simple'], ['advanced', 'Advanced']])}</label><label class="setting-row"><span><strong>What can agents do without asking?</strong><small>Default is safe local checks and reports.</small></span>${selectControl('onboarding-permission', autonomy.agents_can_do_without_asking || DEFAULT_AUTONOMY_POLICY.agents_can_do_without_asking, [['run checks and reports', 'Run checks and reports'], ['ask before every action', 'Ask before every action'], ['run safe local actions', 'Run safe local actions']])}</label><label class="setting-row"><span><strong>Concurrent work policy</strong><small>Safe Queue avoids overlapping writes by default.</small></span>${selectControl('onboarding-concurrency', agent.concurrent_work_policy || 'Safe Queue', [['Safe Queue', 'Safe Queue'], ['Observe', 'Observe'], ['Guided', 'Guided'], ['Active Sessions', 'Active Sessions'], ['Parallel Worktrees', 'Parallel Worktrees']])}</label><label class="setting-row"><span><strong>Merge policy</strong><small>Manual Only keeps releases under your control.</small></span>${selectControl('onboarding-merge', agent.merge_policy || 'Manual Only', [['Manual Only', 'Never merge automatically'], ['Assisted Merge', 'Assisted Merge'], ['Auto PR', 'Auto PR']])}</label><label class="setting-row"><span><strong>Agent report footer</strong><small>Controls trust footer and restore action in reports.</small></span>${selectControl('onboarding-footer', footer.mode || 'compact', [['compact', 'Compact + restore action'], ['full', 'Full'], ['only_when_trust_incomplete', 'Only when trust incomplete'], ['off', 'Off']])}</label></div><div class="mini-actions">${saveControl}</div></div></div>`;
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

function render(data) {
  const counts = trustCounts(data.trust);
  const countsHtml = counts.map((count) => `<div class="stat ${trustClass(count.key)}"><div class="num">${count.count}</div><div class="cap">${esc(count.key)}</div></div>`).join('');
  const moduleCount = (data.modules.modules || []).length;
  const repairCount = (data.repair.queue || []).length;
  const staleCount = (data.stale.items || data.stale.stale_items || []).length;
  const wikiEdges = (data.wikiGraph.edges || []).length;
  const searchDocs = (data.searchIndex.documents || []).length;
  const qualityScore = data.quality.quality_score ?? data.quality.score ?? '—';
  const secretStatus = data.secretScan.status || 'not_run';
  const wikiLintScore = data.wikiLint.quality_score ?? '—';
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
<header><div class="topbar"><div><h1>.knowledge Visual Inspector</h1><div class="sub">Generated ${generated} · source of truth remains current code and tests.</div></div><div class="mini-stat-row"><div class="mini-stat"><strong>${esc(qualityScore)}</strong>quality</div><div class="mini-stat"><strong>${esc(moduleCount)}</strong>modules</div><div class="mini-stat"><strong>${esc(searchDocs)}</strong>search docs</div><div class="mini-stat"><strong>${esc(secretStatus)}</strong>secret scan</div></div></div><input class="global-filter" id="globalFilter" placeholder="Filter all tables by module, path, trust, command, reason..."></header>
<main>
<section>${renderQuickActions()}</section>
<section class="grid stats">${countsHtml}<div class="stat"><div class="num">${esc(qualityScore)}</div><div class="cap">quality</div></div><div class="stat"><div class="num">${esc(wikiLintScore)}</div><div class="cap">wiki lint</div></div><div class="stat"><div class="num">${esc(repairCount)}</div><div class="cap">repair queue</div></div><div class="stat"><div class="num">${esc(staleCount)}</div><div class="cap">stale items</div></div><div class="stat"><div class="num">${esc(wikiEdges)}</div><div class="cap">wiki edges</div></div></section>
<section class="grid two"><div class="card"><h2>Routing Bundle View</h2>${renderRouting(data)}</div><div class="card"><h2>Team Mode</h2>${renderTeamMode(data)}</div></section>
<section class="grid two"><div class="card"><h2>Free Core Trust Graph</h2>${freeCoreGraphSvg(data)}</div><div class="card"><h2>Memory Providers</h2><p class="sub">Optional advisory context, not truth.</p>${renderMemoryProviders(data)}<h2 style="margin-top:24px">Applied Templates</h2>${renderTemplates(data)}</div></section>
<section class="card"><h2>Modules <span class="sub">· with low-confidence explanations</span></h2>${renderModules(data)}</section>
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
document.addEventListener('click', (event)=>{ const btn=event.target.closest('[data-copy]'); if(btn) copyText(btn.getAttribute('data-copy')); });
function applyFilters(tableName){ const searchInput=document.querySelector('[data-table-search="'+tableName+'"]'); const select=document.querySelector('[data-table-filter="'+tableName+'"]'); const global=document.getElementById('globalFilter'); const q=((searchInput&&searchInput.value)||'').toLowerCase(); const g=(global.value||'').toLowerCase(); const f=((select&&select.value)||'').toLowerCase(); document.querySelectorAll('table[data-table="'+tableName+'"] tbody tr').forEach(row=>{ const text=(row.getAttribute('data-search')||row.textContent||'').toLowerCase(); const rowFilter=(row.getAttribute('data-filter')||'').toLowerCase(); const okText=(!q||text.includes(q)) && (!g||text.includes(g)); const okFilter=!f||rowFilter===f||rowFilter.includes(f); row.style.display=(okText&&okFilter)?'':'none'; }); }
function applyAll(){ document.querySelectorAll('table[data-table]').forEach(t=>applyFilters(t.getAttribute('data-table'))); }
document.querySelectorAll('[data-table-search],[data-table-filter],#globalFilter').forEach(el=>el.addEventListener('input',applyAll));
document.querySelectorAll('[data-table-filter]').forEach(el=>el.addEventListener('change',applyAll));
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
  const homeCards = [
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
  ].map(([label, value, body]) => renderMetricCard(label, value, body)).join('');
  const countCards = counts.map((count) => `<div class="stat ${trustClass(count.key)}"><div class="num">${count.count}</div><div class="cap">${esc(count.key)}</div></div>`).join('');
  const searchBody = `<div class="empty-state"><h3>Local search</h3><p>${esc(searchDocs)} indexed documents. Search runs locally from generated index data.</p>${commandBox('node .knowledge/tools/search-knowledge.js "<query>"', 'Copy search command')}</div>`;
  const exportBody = `<div class="quick-actions"><button class="action-card" type="button" data-copy="node .knowledge/tools/validate-release-artifact.js dist/knowledge-v3.2.2.zip --json"><span>Validate Release Artifact</span><code>node .knowledge/tools/validate-release-artifact.js dist/knowledge-v3.2.2.zip --json</code></button></div><div class="empty-state" style="margin-top:14px"><h3>Release artifact hygiene</h3><p>Use the uploaded release asset for install checks; source snapshots are not install packages.</p></div>`;
  const onboarding = renderOnboarding(data, options);
  const actionDrawer = `<div class="panel"><h3>Global action drawer</h3><p class="sub">${options.live ? 'Live buttons run allowlisted local actions with the session token.' : 'Static fallback copies commands only. Run <code>node .knowledge/inspector.js</code> for token-protected local buttons.'}</p>${renderQuickActions({ ...options, data })}</div>`;
  const actionResult = renderActionResultPanel(options);
  const settingsBody = `<div class="grid two"><div class="card"><h2>User Mode: Simple / Advanced</h2><p class="sub">Simple Mode uses plain-language summaries and safe defaults. Advanced Mode shows raw JSON, locks, routing, evidence and branch policy.</p>${commandBox('node .knowledge/tools/agent-session.js report --json', 'Agent sessions')}</div><div class="card"><h2>Agent Report Footer</h2><p class="sub">Supported modes: off, compact, full, only when trust incomplete. Token metrics must be labelled as estimates.</p>${commandBox('node .knowledge/tools/restore-trust.js --safe --json', 'Restore Trust')}</div><div class="card"><h2>Concurrent Work Policy</h2><p class="sub">Default multi-agent mode is Safe Queue. Merge policy defaults to Manual Only.</p>${renderTeamModePanel(data)}</div><div class="card"><h2>Local Server</h2><p class="sub">Browser and VS Code shell use the same local API.</p>${commandBox('node .knowledge/inspector.js', 'Open Inspector')}</div></div>`;
  const agentsBody = `<div class="grid two"><div class="card"><h2>Agent Registry / Active Sessions</h2><p class="sub">No manual active-agent switch. Connected agents register sessions, heartbeats, reports and locks.</p>${commandBox('node .knowledge/tools/agent-session.js start --runtime claude-code --json', 'Start session')}${commandBox('node .knowledge/tools/agent-session.js report --json', 'Session report')}</div><div class="card"><h2>Safe Queue / Locks / Parallel Worktrees / Merge Queue</h2>${renderTeamModePanel(data)}</div></div>`;
  const tabs = [
    ['Home', `${onboarding}<div class="grid stats metric-grid compact-top-metrics">${homeCards}</div>${renderBranchDiagnostics(data, { ...options, showSimpleTrust: data.settings.user_mode === 'simple' })}${actionDrawer}${actionResult}<div class="card"><h2>Memory Providers</h2><p class="sub">External memory is advisory and cannot override evidence.</p>${renderMemoryProviders(data)}</div>`],
    ['Review', `<div class="grid two"><div class="card"><h2>PR Impact</h2>${renderPrImpactPreview(data)}</div><div class="card"><h2>Reviewer Notes</h2>${renderPrPreview(data)}</div></div><div class="card"><h2>Critical Paths / Policy Warnings</h2>${renderCriticalFiles(data)}</div>`],
    ['Knowledge Trust', `<div class="grid stats">${countCards}</div><div class="mini-actions trust-repair-actions">${options.live ? '<button type="button" class="copy-btn" data-action="trust.restore.safe">Restore Trust</button>' : copyButton('node .knowledge/tools/restore-trust.js --safe --json', 'Restore Trust')}${renderTrustRepairPrompt(data)}</div><div class="grid two"><div class="card"><h2>Trust Overview</h2>${renderModules(data)}</div><div class="card"><h2>Evidence and Routing</h2>${renderRouting(data)}<h3>Search</h3>${searchBody}</div></div><div class="grid two"><div class="card"><h2>Freshness</h2>${renderStale(data)}</div><div class="card"><h2>Repair Queue / Restore Trust</h2>${renderRepair(data)}${commandBox('node .knowledge/tools/restore-trust.js --safe --json', 'Restore Trust')}</div></div><div class="card"><h2>Free Core Trust Graph</h2>${freeCoreGraphSvg(data)}</div>`],
    ['Agents Activity', agentsBody],
    ['Reports', `<div class="grid two"><div class="card"><h2>Release Checks</h2>${exportBody}</div><div class="card"><h2>Benchmark Smoke</h2>${commandBox('node .knowledge/benchmarks/run-benchmarks.js --suite smoke --json', 'Benchmark smoke')}</div></div>`],
    ['Settings', `${settingsBody}<div class="card"><h2>Memory Providers</h2>${renderMemoryProviders(data)}</div>`],
    ['Pro Preview', `<div class="card"><h2>Coming Soon</h2><p class="sub">Inspector Pro is planned for teams that need deeper collaboration and governance. Free .knowledge remains local-first and fully usable.</p>${renderProWaitlist(data)}</div>`]
  ];
  const nav = tabs.map(([label], index) => `<button type="button" class="tab-btn${index === 0 ? ' active' : ''}" data-tab="${index}">${esc(label)}</button>`).join('');
  const sections = tabs.map(([label, body], index) => `<section class="tab-panel${index === 0 ? ' active' : ''}" data-panel="${index}" aria-label="${esc(label)}"><div class="panel-head"><h2>${esc(label)}</h2></div>${body}</section>`).join('');
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>.knowledge Inspector 3.2.2</title>
<style>
:root{--bg:#091017;--panel:#101a23;--panel2:#13212b;--line:#2c3c45;--text:#f4f7f4;--muted:#aebbb3;--green:#39b980;--yellow:#e6b84c;--red:#e05252;--blue:#62a8e5;--violet:#a48be0;--shadow:0 18px 60px #0007}*{box-sizing:border-box}body{margin:0;background:#091017;color:var(--text);font:14px/1.48 ui-sans-serif,system-ui,-apple-system,Segoe UI,Arial}.app{display:grid;grid-template-columns:250px minmax(0,1fr);min-height:100vh}.sidebar{position:sticky;top:0;height:100vh;overflow:auto;border-right:1px solid var(--line);background:#0b141b;padding:18px}.brand{font-weight:900;font-size:18px;margin-bottom:14px}.tab-btn{width:100%;display:block;text-align:left;border:1px solid transparent;background:transparent;color:var(--muted);padding:9px 10px;border-radius:8px;cursor:pointer}.tab-btn:hover,.tab-btn.active{background:#14232d;color:var(--text);border-color:#324752}.content{min-width:0}.topbar{position:sticky;top:0;z-index:5;background:#0e1820e8;backdrop-filter:blur(10px);border-bottom:1px solid var(--line);padding:14px 22px}.topbar h1{font-size:22px;margin:0 0 8px}.chips{display:flex;gap:8px;flex-wrap:wrap}.chip{border:1px solid #344852;background:#121f28;border-radius:999px;padding:5px 9px;color:#dce8df;font-size:12px}main{padding:22px}.tab-panel{display:none}.tab-panel.active{display:block}.panel,.card{background:linear-gradient(180deg,var(--panel),var(--panel2));border:1px solid var(--line);border-radius:8px;padding:16px;box-shadow:var(--shadow)}.panel-head{display:flex;justify-content:space-between;align-items:center;margin-bottom:12px}h2{font-size:19px;margin:0}h3{font-size:15px;margin:16px 0 8px}.sub{color:var(--muted)}.grid{display:grid;gap:12px}.stats{grid-template-columns:repeat(auto-fit,minmax(150px,1fr))}.metric-grid{margin-top:10px}.compact-top-metrics{grid-template-columns:repeat(auto-fit,minmax(118px,1fr));gap:10px}.compact-top-metrics .stat{padding:10px 12px;min-height:0}.compact-top-metrics .num{font-size:14px;line-height:1.15}.compact-top-metrics .cap{font-size:10px;margin-top:4px}.compact-top-metrics .sub{font-size:10px;line-height:1.35;margin-top:6px}.compact-top-metrics .severity-dot{top:8px;right:8px;width:6px;height:6px}.branch-diagnostics{margin:12px 0}.branch-diagnostics-head{display:flex;justify-content:space-between;align-items:flex-start;gap:14px;flex-wrap:wrap}.branch-diagnostics-body{display:grid;grid-template-columns:minmax(0,1.15fr) minmax(260px,.85fr);gap:16px;align-items:start}.branch-picker{display:grid;gap:5px;color:var(--muted);font-size:12px}.branch-picker select{background:#0b141b;border:1px solid #344852;color:var(--text);border-radius:8px;padding:9px;min-width:220px}.quick-actions{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:12px}.action-card{cursor:pointer;text-align:left;border:1px solid #344852;background:#0d1820;border-radius:8px;padding:12px;color:var(--text)}.action-card.locked{border-style:dashed;opacity:.72}.action-card:hover{border-color:#63a0c9}.action-card span{display:block;font-weight:800;margin-bottom:5px}.action-card code{display:block;color:#9bd0f4;font-size:11px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.stat{background:#0d1820;border:1px solid #263841;border-radius:8px;padding:12px;min-height:78px}.metric-card{position:relative;margin-top:6px;padding-top:18px;border-left:4px solid #3b5360}.metric-card.ok{border-left-color:var(--green)}.metric-card.warning{border-left-color:var(--yellow);background:#1d1a10}.metric-card.critical{border-left-color:var(--red);background:#211316}.severity-dot{position:absolute;top:8px;right:10px;width:8px;height:8px;border-radius:999px;background:#3b5360}.metric-card.ok .severity-dot{background:var(--green)}.metric-card.warning .severity-dot{background:var(--yellow)}.metric-card.critical .severity-dot{background:var(--red)}.num{font-size:24px;font-weight:900;word-break:break-word}.cap{color:var(--muted);font-size:11px;text-transform:uppercase}.pill{display:inline-flex;padding:3px 8px;border-radius:999px;background:#23323b}.trusted{background:#133629}.routing_trusted{background:#14324a}.near_trusted,.important,.medium{background:#3b2d15}.suspect,.low_confidence,.critical,.high{background:#4a1d22}.advisory_only{background:#292542}.table-controls{display:flex;gap:8px;margin-bottom:10px}.table-controls input,.table-controls select{background:#0b141b;border:1px solid #344852;color:var(--text);border-radius:8px;padding:9px}table{width:100%;border-collapse:collapse}th,td{padding:9px;border-bottom:1px solid #263841;text-align:left;vertical-align:top}th{color:var(--muted);font-size:11px;text-transform:uppercase}.kv th{width:170px}.mini-actions{display:flex;gap:8px;flex-wrap:wrap;margin-top:12px}.copy-btn{border:1px solid #3b5360;background:#11212c;color:#eaf3ee;border-radius:8px;padding:7px 9px;cursor:pointer}.danger-btn{border-color:#87535a;background:#321920}.onboarding-card{margin-bottom:14px}.onboarding-card.requires-setup{border-color:var(--yellow)}.onboarding-toggle{display:flex;justify-content:space-between;gap:12px;width:100%;border:0;background:transparent;color:var(--text);padding:0;text-align:left;cursor:pointer}.onboarding-toggle span{font-weight:900}.onboarding-toggle small{color:var(--muted)}.onboarding-body{margin-top:14px}.onboarding-body[hidden]{display:none}.setting-list{display:grid;gap:10px}.setting-row{display:grid;grid-template-columns:minmax(180px,1fr) minmax(220px,320px);gap:14px;align-items:center;border:1px solid #263841;background:#0d1820;border-radius:8px;padding:10px}.setting-row span,.setting-row small{display:block}.setting-row small{color:var(--muted);margin-top:3px}.setting-row select,.setting-row input{width:100%;background:#0b141b;border:1px solid #344852;color:var(--text);border-radius:8px;padding:9px}.simple-trust-actions,.trust-repair-actions{margin:12px 0}.simple-trust-actions.compact{margin:0;height:100%;display:flex;flex-direction:column;justify-content:flex-end;padding:16px;border:1px solid #263841;border-radius:8px;background:#0d1820}.simple-trust-actions.compact h2{font-size:16px}.update-banner{display:flex;justify-content:space-between;gap:14px;align-items:flex-start;border:1px solid #3b5360;background:#0d1820;border-radius:8px;padding:14px;margin-bottom:12px}.update-banner.available{border-color:#e6b84c}.update-banner.failed{border-color:#e05252}.empty-state{border:1px dashed #3b5360;background:#0c171f;border-radius:8px;padding:18px;text-align:center;color:var(--muted)}.cmd{display:flex;gap:8px;align-items:center;background:#081017;border:1px solid #263841;border-radius:8px;padding:9px;margin-top:10px}.cmd code{flex:1;color:#9bd0f4;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.pro-preview-intro{display:flex;justify-content:space-between;gap:16px;align-items:center;border:1px solid #30434d;background:#0d1820;border-radius:8px;padding:14px;margin:14px 0}.pro-preview-intro strong,.pro-preview-intro span{display:block}.pro-preview-intro span{color:var(--muted);margin-top:3px}.pro-waitlist-button{display:inline-flex;align-items:center;justify-content:center;min-height:46px;padding:0 22px;border:1px solid #3c3f4b;border-radius:8px;background:linear-gradient(180deg,#34343d,#161720);box-shadow:inset 0 1px 0 #ffffff18,0 8px 18px #0008;color:#f4f0f2;text-transform:uppercase;letter-spacing:2px;font-weight:900;text-decoration:none;white-space:nowrap}.pro-waitlist-button:hover{border-color:#6d7180;background:linear-gradient(180deg,#3d3e48,#1c1d27)}.signal-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:12px}.signal-card{border:1px solid #314752;background:#0d1820;border-radius:8px;padding:12px}.signal-card strong,.signal-card span{display:block}.signal-card span{color:var(--muted);font-size:12px}.result-panel{margin-top:12px}.result-toggle{width:100%;display:flex;justify-content:space-between;align-items:center;gap:12px;border:0;background:transparent;color:var(--text);padding:0;text-align:left;cursor:pointer}.result-toggle span{font-weight:900}.result-toggle small{color:var(--muted)}.result-panel pre{margin-top:12px}.result-panel.is-collapsed pre{display:none}.wiki-svg{width:100%;height:440px;background:#081017;border:1px solid #263841;border-radius:8px}.edge{fill:none;stroke:#6d7d88}.edge.contradicts{stroke:var(--red)}.edge.supports{stroke:var(--green)}.edge.depends_on{stroke:var(--yellow)}.node{fill:var(--violet);stroke:#fff}.node.trusted{fill:var(--green)}.node.routing_trusted{fill:var(--blue)}.node.suspect,.node.low_confidence{fill:var(--red)}.label{font-size:10px;fill:#eef7f2;paint-order:stroke;stroke:#081017;stroke-width:3px}.toast{position:fixed;right:18px;bottom:18px;background:#123629;color:#c8f3dc;border:1px solid #2a8b62;padding:10px 12px;border-radius:8px;opacity:0;transform:translateY(8px);transition:.18s}.toast.show{opacity:1;transform:translateY(0)}@media(max-width:850px){.app{grid-template-columns:1fr}.sidebar{position:relative;height:auto}.tab-btn{display:inline-block;width:auto;margin:0 4px 6px 0}.topbar{position:relative}main{padding:14px}.table-controls,.setting-row{display:block}.table-controls input,.table-controls select,.setting-row select,.setting-row input{width:100%;margin-top:8px;margin-bottom:8px}.update-banner{display:block}.branch-diagnostics-body{grid-template-columns:1fr}.pro-preview-intro{align-items:flex-start;flex-direction:column}.pro-waitlist-button{width:100%}}
</style>
<style>
.free-core-graph{display:grid;gap:12px}.graph-metrics{display:grid;grid-template-columns:repeat(auto-fit,minmax(105px,1fr));gap:8px}.graph-metric{border:1px solid #263841;background:#0b141b;border-radius:8px;padding:9px 10px}.graph-metric strong,.graph-metric span,.graph-metric small{display:block}.graph-metric strong{font-size:18px}.graph-metric span{color:var(--muted);font-size:11px;text-transform:uppercase}.graph-metric small{color:var(--muted);font-size:11px;margin-top:3px}.trust-graph-svg{height:520px;background:linear-gradient(180deg,#081017,#0c1820);overflow:visible}.lane line{stroke:#263841;stroke-width:1}.lane text{fill:#aebbb3;font-size:12px;text-transform:uppercase}.edge{fill:none;stroke:#6d7d88;stroke-width:2;opacity:.86}.edge.outranks{stroke:#eaf3ee}.edge.routes{stroke:var(--blue)}.edge.documents{stroke:var(--green)}.edge.checks{stroke:#67e8f9}.edge.references,.edge.related{stroke:var(--violet)}.edge.advisory{stroke:var(--yellow);stroke-dasharray:6 4}.edge.supports{stroke:var(--green)}.edge.depends_on{stroke:var(--yellow)}.edge.contradicts{stroke:var(--red)}#graph-arrow path{fill:#91a2ad}.node{stroke:#081017;stroke-width:2}.node.source_truth{fill:#eaf3ee}.node.module{fill:var(--blue)}.node.wiki{fill:var(--violet)}.node.trusted{fill:var(--green)}.node.routing_trusted{fill:var(--blue)}.node.advisory_only{fill:var(--violet)}.node.suspect,.node.low_confidence{fill:var(--red)}.label{text-anchor:middle;font-size:11px;fill:#eef7f2;paint-order:stroke;stroke:#081017;stroke-width:4px}.label.source_truth{font-weight:800}.source-order-strip{border:1px solid #263841;background:#0b141b;border-radius:8px;padding:10px;color:#dce8df}.graph-insights{border:1px solid #263841;background:#0b141b;border-radius:8px;padding:12px}.graph-insights h3{margin-top:0}.graph-insights .reason-list{margin-top:10px}.edge-swatch.outranks{background:#eaf3ee}.edge-swatch.routes{background:var(--blue)}.edge-swatch.documents,.edge-swatch.supports{background:var(--green)}.edge-swatch.checks{background:#67e8f9}.edge-swatch.references{background:var(--violet)}.edge-swatch.advisory{background:var(--yellow)}.edge-swatch.contradicts{background:var(--red)}@media(max-width:850px){.trust-graph-svg{height:420px}.graph-tools{display:block}.graph-tools .copy-btn{margin-top:8px}}
</style>
</head>
<body>
<div class="app">
<aside class="sidebar"><div class="brand">.knowledge Inspector 3.2.2</div><nav>${nav}</nav></aside>
<div class="content">
<header class="topbar"><h1>.knowledge Inspector 3.2.2</h1><div class="chips"><span class="chip">Repo: ${esc(data.context?.repoId || 'local')}</span><span class="chip">Team Mode: ${esc(data.context?.mode || 'repo')}</span><span class="chip">Doctor score: ${esc(qualityScore)}</span><span class="chip">Branch: ${esc(branch)}</span><span class="chip">Head SHA: ${esc(head)}</span><span class="chip">No cloud</span><span class="chip">No telemetry</span><span class="chip">Build time: ${esc(data.generated_at)}</span></div></header>
<main>${sections}</main>
</div></div>
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
async function updateApi(path,options){const output=document.getElementById('updateOutput');try{const opts=options||{};opts.headers=authHeaders(opts.headers);const res=await fetch(path,opts);const json=await res.json();if(output)output.textContent=JSON.stringify(json,null,2);const status=json.status||json.release||json.dry_run?.json||json.apply?.json||{};const state=document.getElementById('updateState');if(state&&status.status)state.textContent=status.status;const banner=document.getElementById('updateBanner');if(banner){banner.classList.toggle('available',status.status==='update_available');banner.classList.toggle('failed',json.ok===false||status.status==='check_failed')}return json}catch(error){if(output)output.textContent='Update API unavailable in static mode: '+error.message;return null}}
function branchByName(name){return (gitBranchState.branches||[]).find((branch)=>branch.name===name)||null}
function setBranchField(name,value){document.querySelectorAll('[data-branch-field="'+name+'"]').forEach((el)=>{el.textContent=value||'none'})}
function dirtyLabel(diagnostics){if(diagnostics.current_worktree_dirty===true){const s=diagnostics.dirty_summary||{};return 'dirty ('+(s.changed||0)+' changed, '+(s.staged||0)+' staged)'}if(diagnostics.current_worktree_dirty===false)return 'clean';return 'not checked in current worktree'}
function applyBranchDiagnostics(name){const branch=branchByName(name)||{};const active=gitBranchState.active||'unknown';const current=(branch.name||name)===active;const diagnostics={branch:branch.name||name||active,active_branch:active,head_sha:branch.head_sha||'',upstream:branch.upstream||null,worktree_path:branch.worktree_path||null,current_worktree_dirty:current?gitDirtyState.dirty:null,dirty_summary:current?gitDirtyState.dirty_summary:null,note:current?'Diagnostics are using the active worktree.':(branch.worktree_path?'Branch is checked out in another worktree; run diagnostics there for file-level status.':'Branch is not checked out in this worktree; select or create a worktree before file-level diagnostics.')};setBranchField('branch',diagnostics.branch);setBranchField('active',diagnostics.active_branch);setBranchField('head',(diagnostics.head_sha||'').slice(0,12)||'unknown');setBranchField('upstream',diagnostics.upstream||'none');setBranchField('worktree',diagnostics.worktree_path||'not checked out');setBranchField('dirty',dirtyLabel(diagnostics));setBranchField('note',diagnostics.note)}
async function refreshBranchDiagnostics(name){applyBranchDiagnostics(name);if(!liveMode||!sessionToken)return;try{const res=await fetch('/api/git/diagnostics?branch='+encodeURIComponent(name),{headers:authHeaders()});const json=await res.json();if(json.ok&&json.diagnostics){setBranchField('branch',json.diagnostics.branch||'unknown');setBranchField('active',json.diagnostics.active_branch||gitBranchState.active||'unknown');setBranchField('head',((json.diagnostics.head_sha||'').slice(0,12)||'unknown'));setBranchField('upstream',json.diagnostics.upstream||'none');setBranchField('worktree',json.diagnostics.worktree_path||'not checked out');setBranchField('dirty',dirtyLabel(json.diagnostics));setBranchField('note',json.diagnostics.note||'')}}catch{}}
async function saveOnboarding(){if(!liveMode||!sessionToken){copyText('node .knowledge/inspector.js');return}const out=document.getElementById('result');setResultPanel(true,'Setup response');if(out)out.textContent='Saving first-run setup...';const body={user_mode:document.getElementById('onboarding-user-mode')?.value||'simple',agents_can_do_without_asking:document.getElementById('onboarding-permission')?.value||'run checks and reports',concurrent_work_policy:document.getElementById('onboarding-concurrency')?.value||'Safe Queue',merge_policy:document.getElementById('onboarding-merge')?.value||'Manual Only',report_footer_mode:document.getElementById('onboarding-footer')?.value||'compact',detected_agent_runtime:document.getElementById('onboarding-runtime')?.value||null};const res=await fetch('/api/settings/onboarding',{method:'POST',headers:authHeaders({'content-type':'application/json'}),body:JSON.stringify(body)});const json=await res.json();if(out)out.textContent=JSON.stringify(json,null,2);if(json.ok){const card=document.getElementById('onboarding-wizard');const bodyEl=card?.querySelector('.onboarding-body');if(bodyEl)bodyEl.hidden=true;if(card)card.setAttribute('data-onboarding-expanded','false');showToast('Setup saved')}}
async function runLocalAction(id){if(!liveMode||!sessionToken)return;const out=document.getElementById('result');setResultPanel(true,'Latest local action output');if(out)out.textContent='Running '+id+'...';const res=await fetch('/api/actions/'+encodeURIComponent(id)+'/run',{method:'POST',headers:authHeaders({'content-type':'application/json'}),body:JSON.stringify({confirmed:true})});const json=await res.json();if(out)out.textContent=JSON.stringify(json,null,2);showToast(json.ok?'Action finished':'Action needs review')}
document.addEventListener('click',(event)=>{const copy=event.target.closest('[data-copy]');if(copy){copyText(copy.getAttribute('data-copy'));return}const resultToggle=event.target.closest('[data-result-toggle]');if(resultToggle){const panel=document.querySelector('[data-result-panel="true"]');const open=panel?.classList.contains('is-collapsed');setResultPanel(open,open?'Latest local action output':'Collapsed until an action runs');return}const toggle=event.target.closest('[data-onboarding-toggle]');if(toggle){const card=document.getElementById('onboarding-wizard');const body=card?.querySelector('.onboarding-body');if(body){body.hidden=!body.hidden;if(card)card.setAttribute('data-onboarding-expanded',body.hidden?'false':'true')}return}const save=event.target.closest('[data-onboarding-save]');if(save){saveOnboarding();return}const localAction=event.target.closest('[data-action]');if(localAction){runLocalAction(localAction.getAttribute('data-action'));return}const update=event.target.closest('[data-update-action]');if(update){const action=update.getAttribute('data-update-action');setResultPanel(true,'Update action output');if(action==='status')updateApi('/api/update/status');if(action==='dry-run')updateApi('/api/update/dry-run',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'});if(action==='apply'&&confirm('Apply .knowledge system update now? Project knowledge will be preserved and a backup will be created.')){const latest=document.getElementById('updateBanner')?.getAttribute('data-latest-version')||'';updateApi('/api/update/apply',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({confirm:true,expectedVersion:latest&&latest!=='-'?latest:null})})}return}const tab=event.target.closest('[data-tab]');if(tab){document.querySelectorAll('.tab-btn').forEach((b)=>b.classList.remove('active'));document.querySelectorAll('.tab-panel').forEach((p)=>p.classList.remove('active'));tab.classList.add('active');const panel=document.querySelector('[data-panel="'+tab.getAttribute('data-tab')+'"]');if(panel)panel.classList.add('active')}});
document.addEventListener('change',(event)=>{const select=event.target.closest('[data-branch-select]');if(select)refreshBranchDiagnostics(select.value)});
if(location.protocol==='http:'||location.protocol==='https:')updateApi('/api/update/status');
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
    ]
  };
  writeJsonAtomic(path.join(outDir, 'status.json'), status);
  if (!options.quiet) console.log(JSON.stringify(status, null, 2));
  return status;
}

if (require.main === module) withLock(lockDir, () => build({ quiet: process.argv.includes('--quiet') }));
const runBuild = (options = {}) => options.skipLock ? build(options) : withLock(lockDir, () => build(options));
module.exports = Object.assign(runBuild, {
  collect,
  renderTabbed,
  sanitizeInspectorHtml,
  sanitizeInspectorData,
  repairAgentPrompt
});
