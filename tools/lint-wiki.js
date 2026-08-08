#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const { ensureDir, readJson, writeJsonAtomic, appendNdjson, getAgentId } = require('./lib/json-store');
const { withContainedLock } = require('./lib/contained-lock-manager');
const { LOCKS } = require('./lib/lock-policy');
const { reconcile: reconcileQueue } = require('./lib/queue-lifecycle');
const buildWikiGraph = require('./build-wiki-graph');
const { resolveKnowledgeContext } = require('./lib/path-context');
const { systemVersion } = require('./lib/system-version');

const context = resolveKnowledgeContext();
const knowledgeRoot = context.projectKnowledgeRoot;
const stateRoot = context.stateRoot;
const wikiRoot = path.join(knowledgeRoot, 'wiki');
const WIKI_LINT_LOCK = Object.freeze({
  context,
  rootKind: 'state',
  rootPath: stateRoot,
  lockName: 'wiki-lint',
  purpose: LOCKS['wiki-lint'].purpose
});

function nowIso() { return new Date().toISOString(); }
function rel(abs, base = wikiRoot) { return path.relative(base, abs).replace(/\\/g, '/'); }
function walk(dir, out = []) {
  if (!fs.existsSync(dir)) return out;
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const abs = path.join(dir, entry.name);
    if (entry.isDirectory()) walk(abs, out);
    else if (entry.isFile() && entry.name.endsWith('.md')) out.push(abs);
  }
  return out;
}
function add(issues, severity, code, message, artifact, extra = {}) { issues.push({ severity, code, message, artifact, ...extra }); }
function hasFrontmatter(text) { return /^---\r?\n[\s\S]*?\r?\n---\r?\n?/.test(String(text || '').replace(/^\uFEFF/, '')); }
function frontmatterBlock(text) { return String(text || '').replace(/^\uFEFF/, '').match(/^---\r?\n([\s\S]*?)\r?\n---\r?\n?/)?.[1] || ''; }
function title(text, fallback) { return String(text || '').match(/^#\s+(.+)$/m)?.[1]?.trim() || fallback; }
function qualityScore(issues) {
  let score = 100;
  for (const issue of issues) score -= issue.severity === 'high' ? 12 : issue.severity === 'medium' ? 6 : 2;
  return Math.max(0, score);
}
function aggregateStatus(score, structuralStatus) {
  if (structuralStatus === 'structurally_broken') return 'structurally_broken';
  if (structuralStatus === 'usable_with_warnings') return 'usable_with_warnings';
  return score >= 90 ? 'healthy' : 'usable_with_warnings';
}
function lintUnlocked(options = {}) {
  ensureDir(path.join(stateRoot, 'maintenance'));
  const issues = [];
  const pages = walk(wikiRoot);
  const titles = new Map();
  const graph = buildWikiGraph({ skipLock: true, quiet: true });
  for (const abs of pages) {
    const page = rel(abs);
    const artifact = `.knowledge/wiki/${page}`;
    const raw = fs.readFileSync(abs, 'utf8');
    const t = title(raw, page);
    const key = t.toLowerCase();
    titles.set(key, [...(titles.get(key) || []), artifact]);
    const isIndexOrLog = page === 'index.md' || page === 'log.md' || page.endsWith('/README.md');
    if (!isIndexOrLog && !hasFrontmatter(raw)) add(issues, 'medium', 'missing_frontmatter', 'Wiki page lacks YAML frontmatter.', artifact);
    const fm = frontmatterBlock(raw);
    if (!isIndexOrLog && fm) {
      if (!/^trust\s*:/m.test(fm)) add(issues, 'low', 'missing_trust_key', 'Wiki frontmatter should include trust: advisory_only | evidence_backed | stale.', artifact);
      if (!/^links\s*:/m.test(fm)) add(issues, 'low', 'missing_typed_links', 'Wiki frontmatter should include links: typed edge block.', artifact);
    }
    // a verified_against reference that points to an official
    // template counts as a valid (but advisory) reference. Trust still
    // stays advisory_only — the template marker is not strong enough to
    // elevate trust automatically.
    const hasEvidenceRef = /\.knowledge\/evidence\//.test(raw);
    const hasVerifiedRef = /^\s*verified_against\s*:\s*\[[^\]]+\]/m.test(fm) || /^\s*verified_against\s*:\s*$([\s\S]*?)(?:^\S|\Z)/m.test(fm + '\n');
    const hasTemplateRef = /template:[\w-]+:[\w.-]+/.test(fm);
    if (!isIndexOrLog && !hasEvidenceRef && !hasVerifiedRef && !hasTemplateRef) {
      add(issues, 'low', 'weak_evidence_reference', 'Wiki page has no explicit evidence or verified_against reference.', artifact);
    }
  }
  for (const [name, artifacts] of titles.entries()) if (artifacts.length > 1) add(issues, 'low', 'duplicate_title', `Duplicate wiki title: ${name}`, artifacts[0], { artifacts });
  for (const edge of graph.broken_edges || []) add(issues, 'medium', 'broken_wiki_edge', `Broken wiki edge: ${edge.from} -> ${edge.to}`, `.knowledge/wiki/${edge.from}`, { edge });
  const incoming = new Map();
  for (const edge of graph.edges || []) incoming.set(edge.to, (incoming.get(edge.to) || 0) + 1);
  for (const node of graph.nodes || []) {
    if (node.type !== 'wiki_page') continue;
    const id = node.id;
    if (!['index.md', 'log.md'].includes(id) && !id.endsWith('/README.md') && !(incoming.get(id) || 0)) add(issues, 'low', 'orphan_wiki_page', 'Wiki page has no incoming wiki links.', node.path);
  }
  const score = qualityScore(issues);
  const structuralStatus = graph.structural_status || (graph.broken_edge_count > 0 ? 'structurally_broken' : 'healthy');
  const report = {
    schema_version: systemVersion(),
    generated_at: nowIso(),
    generated_by: getAgentId(),
    mode: context.mode,
    status: aggregateStatus(score, structuralStatus),
    structural_status: structuralStatus,
    quality_score: score,
    pages: pages.length,
    graph: {
      nodes: graph.node_count,
      edges: graph.edge_count,
      broken_edges: graph.broken_edge_count,
      duplicate_titles: graph.duplicate_title_count || 0,
      orphan_pages: graph.orphan_page_count || 0,
      structural_status: structuralStatus,
      view: graph.view || 'wiki_graph'
    },
    issues
  };
  const staleItems = readJson(path.join(stateRoot, 'maintenance', 'stale_items.json'), { items: [] });
  const repairQueue = readJson(path.join(stateRoot, 'maintenance', 'repair_queue.json'), { queue: [] });
  const queueProjection = reconcileQueue({
    staleItems,
    repairQueue,
    findings: issues.map((item) => ({ module_id: 'wiki', code: `wiki_${item.code}`, artifact: item.artifact, reason: item.message, severity: item.severity, affected_artifacts: item.artifacts || [item.artifact] })),
    source: 'wiki_lint',
    agentId: getAgentId(),
    timestamp: report.generated_at
  });
  report.queue_transitions = queueProjection.events;
  writeJsonAtomic(path.join(stateRoot, 'maintenance', 'stale_items.json'), staleItems);
  writeJsonAtomic(path.join(stateRoot, 'maintenance', 'repair_queue.json'), repairQueue);
  writeJsonAtomic(path.join(stateRoot, 'maintenance', 'wiki_lint_report.json'), report);
  if (queueProjection.events.length) appendNdjson(path.join(stateRoot, 'maintenance', 'events', `${report.generated_at.slice(0, 10)}.ndjson`), { type: 'queue_lifecycle', source: 'wiki_lint', generated_at: report.generated_at, agent_id: getAgentId(), transitions: queueProjection.events });
  if (!options.quiet) console.log(JSON.stringify(report, null, 2));
  return report;
}
function main(options = {}) { return options.skipLock ? lintUnlocked(options) : withContainedLock(WIKI_LINT_LOCK, () => lintUnlocked(options)); }
module.exports = main;
if (require.main === module) {
  try {
    const report = main({ quiet: process.argv.includes('--quiet') });
    if (process.argv.includes('--strict') && report.status === 'structurally_broken') process.exitCode = 2;
  }
  catch (error) { console.error(error.stack || error.message); process.exit(1); }
}
