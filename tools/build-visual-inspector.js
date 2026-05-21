#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const { ensureDir, readJson, writeJsonAtomic, getAgentId, withLock } = require('./lib/json-store');

const knowledgeRoot = path.resolve(__dirname, '..');
const repoRoot = path.resolve(knowledgeRoot, '..');
const lockDir = path.join(knowledgeRoot, '.lock');

function safeJson(rel, fallback) {
  return readJson(path.join(knowledgeRoot, rel), fallback);
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
  return {
    generated_at: new Date().toISOString(),
    generated_by: getAgentId(),
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
    wikiLint
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

function layoutGraph(nodes, edges) {
  const nodeList = (nodes || []).slice(0, 90);
  const edgeList = (edges || []).slice(0, 220);
  if (!nodeList.length) return { nodes: [], edges: [] };
  const degrees = new Map(nodeList.map((node) => [node.id, 0]));
  for (const edge of edgeList) {
    if (degrees.has(edge.from)) degrees.set(edge.from, degrees.get(edge.from) + 1);
    if (degrees.has(edge.to)) degrees.set(edge.to, degrees.get(edge.to) + 1);
  }
  const sorted = [...nodeList].sort((a, b) => (degrees.get(b.id) || 0) - (degrees.get(a.id) || 0));
  const centerId = sorted[0]?.id;
  const positioned = [];
  const width = 900;
  const height = 440;
  const cx = width / 2;
  const cy = height / 2;
  const golden = Math.PI * (3 - Math.sqrt(5));
  for (let i = 0; i < sorted.length; i += 1) {
    const node = sorted[i];
    if (node.id === centerId) {
      positioned.push({ ...node, x: cx, y: cy, degree: degrees.get(node.id) || 0, r: 13 });
      continue;
    }
    const ring = Math.floor(Math.sqrt(i));
    const radius = Math.min(190, 78 + ring * 46);
    const angle = i * golden;
    const x = cx + Math.cos(angle) * radius + ((i % 3) - 1) * 22;
    const y = cy + Math.sin(angle) * radius * 0.72 + ((i % 2) ? 10 : -10);
    positioned.push({ ...node, x: Math.max(50, Math.min(width - 190, x)), y: Math.max(40, Math.min(height - 45, y)), degree: degrees.get(node.id) || 0, r: Math.min(15, 7 + (degrees.get(node.id) || 0)) });
  }
  const byId = new Map(positioned.map((node) => [node.id, node]));
  const visibleEdges = edgeList.map((edge) => {
    const a = byId.get(edge.from);
    const b = byId.get(edge.to);
    if (!a || !b) return null;
    return { ...edge, a, b };
  }).filter(Boolean);
  return { nodes: positioned, edges: visibleEdges };
}

function edgePath(edge) {
  const { a, b } = edge;
  const mx = (a.x + b.x) / 2;
  const my = (a.y + b.y) / 2;
  const dx = b.x - a.x;
  const dy = b.y - a.y;
  const len = Math.sqrt(dx * dx + dy * dy) || 1;
  const curve = Math.min(46, Math.max(18, len * 0.12));
  const cx = mx - (dy / len) * curve;
  const cy = my + (dx / len) * curve;
  return `M ${a.x.toFixed(1)} ${a.y.toFixed(1)} Q ${cx.toFixed(1)} ${cy.toFixed(1)} ${b.x.toFixed(1)} ${b.y.toFixed(1)}`;
}

function graphSvg(data) {
  const graphNodes = data.wikiGraph.nodes || [];
  const graphEdges = data.wikiGraph.edges || [];
  if (!graphNodes.length) {
    return emptyState('No wiki graph yet', 'Run wiki graph build after adding wiki pages or typed links.', 'node .knowledge/tools/build-wiki-graph.js');
  }
  const layout = layoutGraph(graphNodes, graphEdges);
  const edges = layout.edges.map((edge) => {
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
  const pinecone = data.external.providers?.pinecone || {};
  return `<table class="kv"><tr><th>Provider</th><td>Pinecone</td></tr><tr><th>Enabled</th><td>${esc(pinecone.enabled ?? false)}</td></tr><tr><th>Mode</th><td>${esc(pinecone.mode || pinecone.status || 'disabled')}</td></tr><tr><th>Configured</th><td>${esc(pinecone.configured ?? false)}</td></tr><tr><th>Source of truth</th><td>false</td></tr></table><div class="mini-actions">${copyButton('node .knowledge/tools/external-memory-status.js', 'Copy status command')}${copyButton('node .knowledge/tools/external/pinecone-search.js "query" --dry-run', 'Copy dry-run search')}</div>`;
}

function renderQuickActions() {
  const actions = [
    ['Release flow', 'node .knowledge/tools/flow.js release --no-color'],
    ['Doctor', 'node .knowledge/tools/doctor.js'],
    ['Search', 'node .knowledge/tools/search-knowledge.js "query" --scope=project'],
    ['Rebuild inspector', 'node .knowledge/tools/build-visual-inspector.js'],
    ['List templates', 'node .knowledge/tools/apply-template.js --list'],
    ['Secret scan', 'node .knowledge/tools/scan-secrets.js']
  ];
  return `<div class="quick-actions">${actions.map(([label, command]) => `<button type="button" class="action-card" data-copy="${esc(command)}"><span>${esc(label)}</span><code>${esc(command)}</code></button>`).join('')}</div>`;
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
:root{--bg:#060a13;--bg2:#0b1120;--panel:#0e1629;--panel2:#111d35;--line:#25324d;--line2:#33415f;--text:#ecf3ff;--muted:#9ca9c4;--soft:#c6d3ee;--green:#2fd17c;--yellow:#f5c451;--orange:#ff8a4c;--red:#ef4444;--blue:#56b7ff;--purple:#b692f6;--cyan:#67e8f9;--shadow:0 24px 80px #0008}*{box-sizing:border-box}html{scroll-behavior:smooth}body{margin:0;background:radial-gradient(1200px 700px at 12% -10%,#1f3b7c66 0,transparent 55%),radial-gradient(900px 520px at 90% 5%,#4c1d9544 0,transparent 55%),linear-gradient(180deg,#070b14 0,#0a1020 38%,#070b14 100%);color:var(--text);font:14px/1.48 Inter,ui-sans-serif,system-ui,-apple-system,Segoe UI,Arial}a{color:#9fd3ff;text-decoration:none}a:hover{text-decoration:underline}header{padding:34px 36px 20px;border-bottom:1px solid #22304a;background:linear-gradient(180deg,#0c1428cc,#0c142855);backdrop-filter:blur(10px);position:sticky;top:0;z-index:10}h1{font-size:34px;letter-spacing:-.04em;margin:0 0 8px}h2{font-size:20px;margin:0 0 16px}h3{margin:0 0 8px}.sub{color:var(--muted)}main{padding:24px 36px 56px}.topbar{display:flex;justify-content:space-between;gap:20px;align-items:flex-start}.quick-actions{display:grid;grid-template-columns:repeat(3,minmax(180px,1fr));gap:12px;margin-top:18px}.action-card{cursor:pointer;text-align:left;border:1px solid var(--line);background:linear-gradient(180deg,#111c34,#0a1326);border-radius:16px;padding:13px;color:var(--text);box-shadow:0 10px 32px #0004}.action-card:hover{border-color:#4d6ba2;transform:translateY(-1px)}.action-card span{display:block;font-weight:800;margin-bottom:5px}.action-card code{display:block;color:#9fd3ff;font-size:11px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.grid{display:grid;gap:16px}.stats{grid-template-columns:repeat(6,minmax(120px,1fr));}.two{grid-template-columns:1.18fr .82fr}.card{background:linear-gradient(180deg,var(--panel),var(--panel2));border:1px solid var(--line);border-radius:20px;padding:18px;box-shadow:var(--shadow)}.stat{background:#08101f;border:1px solid #1d2a43;border-radius:16px;padding:14px;min-height:82px}.stat.trusted{border-color:#164e36}.stat.suspect,.stat.low_confidence{border-color:#5d1f2b}.num{font-size:31px;font-weight:900;letter-spacing:-.03em}.cap{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.08em}.mini-stat-row{display:flex;gap:10px;flex-wrap:wrap}.mini-stat{background:#08101f;border:1px solid #1d2a43;border-radius:12px;padding:9px 11px;color:#dbeafe}.mini-stat strong{display:block;font-size:18px}section{margin:18px 0}.pill{display:inline-flex;align-items:center;padding:3px 9px;border-radius:999px;background:#23304a;color:#d8e3ff;font-size:12px;white-space:nowrap}.critical,.high,.suspect,.low_confidence{background:#4a1824;color:#ffd2d8}.important,.medium,.near_trusted{background:#423112;color:#ffe7ad}.trusted{background:#123a2a;color:#aaf0c4}.routing_trusted{background:#143657;color:#b7dcff}.advisory_only{background:#2b2545;color:#e4dcff}.unknown,.low{background:#1e293b;color:#d8e3ff}.table-controls{display:flex;gap:10px;align-items:center;margin:0 0 12px}.table-controls input,.table-controls select,.global-filter{background:#07101f;border:1px solid #25304a;border-radius:12px;padding:10px;color:var(--text);min-width:0}.table-controls input{flex:1}.global-filter{width:100%;margin-top:14px}table{width:100%;border-collapse:collapse}td,th{padding:10px 9px;border-bottom:1px solid #1f2b44;text-align:left;vertical-align:top}th{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.06em}.reason-list{margin:0;padding-left:18px}.reason-list li{margin-bottom:4px;color:#cad6ed}.link-list{display:flex;flex-direction:column;gap:4px}.file-link{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px}.edge{fill:none;stroke:#55627e;stroke-width:1.6;opacity:.75}.edge.invalid{stroke-dasharray:5 5;opacity:.5}.edge.contradicts{stroke:var(--red)}.edge.supports{stroke:var(--green)}.edge.depends_on{stroke:var(--yellow)}.edge.references,.edge.related{stroke:#7c8aa7}.node{fill:var(--purple);stroke:white;stroke-width:1}.node.trusted{fill:var(--green)}.node.routing_trusted{fill:var(--blue)}.node.suspect,.node.low_confidence{fill:var(--red)}.label{font-size:10px;fill:#dbe7ff;paint-order:stroke;stroke:#06101f;stroke-width:3px}.wiki-svg{width:100%;height:440px;background:radial-gradient(circle at 50% 45%,#12213a,#06101f 70%);border-radius:16px;border:1px solid #1f2b44}.graph-tools{display:flex;justify-content:space-between;align-items:center;gap:12px;margin-bottom:12px}.legend{display:flex;flex-wrap:wrap;gap:12px;color:var(--muted);font-size:12px}.edge-swatch{display:inline-block;width:22px;height:3px;border-radius:99px;background:#7c8aa7;margin-right:6px;vertical-align:middle}.edge-swatch.supports{background:var(--green)}.edge-swatch.depends_on{background:var(--yellow)}.edge-swatch.contradicts{background:var(--red)}.empty-state{border:1px dashed #33415f;border-radius:16px;background:#07101f;padding:24px;text-align:center;color:var(--muted)}.empty-state h3{color:var(--text)}.empty-icon{font-size:28px;color:var(--blue);margin-bottom:8px}.cmd{display:flex;gap:10px;align-items:center;background:#050b16;border:1px solid #1f2b44;border-radius:12px;padding:10px;margin-top:12px;text-align:left}.cmd code{flex:1;color:#bce0ff;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.copy-btn{border:1px solid #3a4a6b;background:#0e1b32;color:#e8eefc;border-radius:10px;padding:8px 10px;cursor:pointer}.copy-btn:hover{border-color:#79b7ff}.mini-actions{display:flex;flex-wrap:wrap;gap:8px;margin-top:12px}.template-list{margin:0;padding-left:18px}.template-list li{margin-bottom:8px}.template-list span{color:var(--muted);margin-left:8px}.kv th{width:150px}.toast{position:fixed;right:18px;bottom:18px;background:#123a2a;color:#bcf5cf;border:1px solid #21885c;padding:12px 14px;border-radius:12px;box-shadow:var(--shadow);opacity:0;transform:translateY(8px);transition:.18s}.toast.show{opacity:1;transform:translateY(0)}@media(max-width:1100px){.stats,.two,.quick-actions{grid-template-columns:1fr 1fr}}@media(max-width:720px){.stats,.two,.quick-actions{grid-template-columns:1fr}main,header{padding-left:18px;padding-right:18px}.topbar{display:block}.table-controls{display:block}.table-controls input,.table-controls select{width:100%;margin-bottom:8px}}
</style>
</head>
<body>
<header><div class="topbar"><div><h1>.knowledge Visual Inspector</h1><div class="sub">Generated ${generated} · source of truth remains current code and tests.</div></div><div class="mini-stat-row"><div class="mini-stat"><strong>${esc(qualityScore)}</strong>quality</div><div class="mini-stat"><strong>${esc(moduleCount)}</strong>modules</div><div class="mini-stat"><strong>${esc(searchDocs)}</strong>search docs</div><div class="mini-stat"><strong>${esc(secretStatus)}</strong>secret scan</div></div></div><input class="global-filter" id="globalFilter" placeholder="Filter all tables by module, path, trust, command, reason..."></header>
<main>
<section>${renderQuickActions()}</section>
<section class="grid stats">${countsHtml}<div class="stat"><div class="num">${esc(qualityScore)}</div><div class="cap">quality</div></div><div class="stat"><div class="num">${esc(wikiLintScore)}</div><div class="cap">wiki lint</div></div><div class="stat"><div class="num">${esc(repairCount)}</div><div class="cap">repair queue</div></div><div class="stat"><div class="num">${esc(staleCount)}</div><div class="cap">stale items</div></div><div class="stat"><div class="num">${esc(wikiEdges)}</div><div class="cap">wiki edges</div></div></section>
<section class="grid two"><div class="card"><h2>Wiki Graph</h2>${graphSvg(data)}</div><div class="card"><h2>External Memory</h2><p class="sub">Pinecone bridge is optional retrieved context, not truth.</p>${renderExternal(data)}<h2 style="margin-top:24px">Applied Templates</h2>${renderTemplates(data)}</div></section>
<section class="card"><h2>Modules <span class="sub">· with low-confidence explanations</span></h2>${renderModules(data)}</section>
<section class="grid two"><div class="card"><h2>Repair Queue</h2>${renderRepair(data)}</div><div class="card"><h2>Stale Items</h2>${renderStale(data)}</div></section>
<section class="card"><h2>Critical / Important Files</h2>${renderCriticalFiles(data)}</section>
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

function build(options = {}) {
  const data = collect();
  const outDir = path.join(knowledgeRoot, 'inspector');
  ensureDir(outDir);
  writeJsonAtomic(path.join(outDir, 'data.json'), data);
  fs.writeFileSync(path.join(outDir, 'index.html'), render(data), 'utf8');
  const status = {
    generated_at: data.generated_at,
    generated_by: data.generated_by,
    output: '.knowledge/inspector/index.html',
    data: '.knowledge/inspector/data.json',
    features: [
      'improved_wiki_graph',
      'per_table_filters',
      'file_links',
      'empty_states',
      'low_confidence_explanations',
      'copy_command_actions'
    ]
  };
  writeJsonAtomic(path.join(outDir, 'status.json'), status);
  if (!options.quiet) console.log(JSON.stringify(status, null, 2));
  return status;
}

if (require.main === module) withLock(lockDir, () => build({ quiet: process.argv.includes('--quiet') }));
module.exports = (options = {}) => options.skipLock ? build(options) : withLock(lockDir, () => build(options));
