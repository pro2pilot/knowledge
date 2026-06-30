#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { ensureDir, readJson, writeJsonAtomic, getAgentId, withLock } = require('./lib/json-store');
const { resolveKnowledgeContext } = require('./lib/path-context');

const context = resolveKnowledgeContext();
const knowledgeRoot = context.projectKnowledgeRoot;
const stateRoot = context.stateRoot;
const wikiRoot = path.join(knowledgeRoot, 'wiki');
const lockDir = path.join(stateRoot, '.lock');

const allowedTypes = [
  'supports',
  'contradicts',
  'depends_on',
  'supersedes',
  'preceded_by',
  'followed_by',
  'implements',
  'references',
  'related',
  'source_of',
  'evidence',
  'source_files',
  'tests',
  'outranks',
  'routes',
  'documents',
  'checks',
  'advisory'
];

const SOURCE_TRUTH = [
  {
    id: 'truth:code',
    title: 'Current code',
    rank: 1,
    trust: 'trusted',
    path: '',
    description: 'Behavior source of truth.'
  },
  {
    id: 'truth:tests',
    title: 'Current tests',
    rank: 2,
    trust: 'trusted',
    path: '',
    description: 'Executable verification outranks prose.'
  },
  {
    id: 'truth:evidence',
    title: 'Evidence JSON',
    rank: 3,
    trust: 'near_trusted',
    path: '.knowledge/evidence',
    description: 'Machine-readable trace and test evidence.'
  },
  {
    id: 'truth:modules',
    title: 'Module cards',
    rank: 4,
    trust: 'routing_trusted',
    path: '.knowledge/modules',
    description: 'Routing and risk summaries.'
  },
  {
    id: 'truth:decisions',
    title: 'Decisions',
    rank: 5,
    trust: 'routing_trusted',
    path: '.knowledge/decisions.json',
    description: 'Recorded project decisions.'
  },
  {
    id: 'truth:wiki',
    title: 'Wiki pages',
    rank: 6,
    trust: 'advisory_only',
    path: '.knowledge/wiki',
    description: 'Human-readable advisory context.'
  },
  {
    id: 'truth:sessions',
    title: 'Sessions',
    rank: 7,
    trust: 'advisory_only',
    path: '.knowledge/sessions',
    description: 'Agent handoff and activity notes.'
  },
  {
    id: 'truth:external-memory',
    title: 'External memory',
    rank: 8,
    trust: 'advisory_only',
    path: '.knowledge/external_memory',
    description: 'Retrieved context; never overrides repo evidence.'
  }
];

function nowIso() { return new Date().toISOString(); }
function sha256(text) { return crypto.createHash('sha256').update(text).digest('hex'); }
function rel(abs, base = knowledgeRoot) { return path.relative(base, abs).replace(/\\/g, '/'); }
function normalizeRel(value) { return String(value || '').replace(/\\/g, '/').replace(/^\.\//, ''); }
function statePath(relPath) { return path.join(stateRoot, relPath); }
function projectPath(relPath) { return path.join(knowledgeRoot, relPath); }

function safeReadJson(relPath, fallback) {
  const state = statePath(relPath);
  const project = projectPath(relPath);
  if (fs.existsSync(state)) return readJson(state, fallback);
  if (fs.existsSync(project)) return readJson(project, fallback);
  return fallback;
}

function walk(dir, out = []) {
  if (!fs.existsSync(dir)) return out;
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const abs = path.join(dir, entry.name);
    if (entry.isDirectory()) walk(abs, out);
    else if (entry.isFile() && entry.name.toLowerCase().endsWith('.md')) out.push(abs);
  }
  return out;
}

function parseFrontmatter(text) {
  const raw = String(text || '').replace(/^\uFEFF/, '');
  const match = raw.match(/^---\r?\n([\s\S]*?)\r?\n---\r?\n?/);
  if (!match) return { data: {}, body: raw, hasFrontmatter: false };
  const data = {};
  const lines = match[1].split(/\r?\n/);
  let section = null;
  let subsection = null;
  for (const line of lines) {
    if (!line.trim() || /^\s*#/.test(line)) continue;
    const indent = line.match(/^\s*/)[0].length;
    const trimmed = line.trim();
    const keyValue = trimmed.match(/^([^:]+):\s*(.*)$/);
    if (keyValue && indent === 0) {
      section = keyValue[1].trim();
      subsection = null;
      const value = keyValue[2].trim();
      data[section] = value === '' ? {} : parseScalar(value);
    } else if (keyValue && indent === 2 && section) {
      if (typeof data[section] !== 'object' || Array.isArray(data[section])) data[section] = {};
      subsection = keyValue[1].trim();
      const value = keyValue[2].trim();
      data[section][subsection] = value === '' ? [] : parseScalar(value);
    } else if (trimmed.startsWith('- ') && section) {
      const target = subsection && data[section] && typeof data[section] === 'object' ? data[section] : data;
      const key = subsection || section;
      if (!Array.isArray(target[key])) target[key] = [];
      target[key].push(parseScalar(trimmed.slice(2)));
    }
  }
  return { data, body: raw.slice(match[0].length), hasFrontmatter: true };
}

function parseScalar(value) {
  const v = String(value || '').trim();
  if (v === 'true') return true;
  if (v === 'false') return false;
  if (v === 'null') return null;
  if (v.startsWith('[') && v.endsWith(']')) return v.slice(1, -1).split(',').map((x) => x.trim()).filter(Boolean);
  return v.replace(/^['"]|['"]$/g, '');
}

function titleFrom(text, fallback) { return (String(text || '').match(/^#\s+(.+)$/m)?.[1] || fallback).trim(); }

function canonical(ref, fromPage = 'index.md') {
  let value = String(ref || '').trim();
  if (!value || /^https?:\/\//i.test(value) || value.startsWith('mailto:')) return value;
  value = value.replace(/^\.knowledge\//, '').replace(/^wiki\//, '').replace(/^@/, '').split('#')[0];
  if (value.startsWith('./') || value.startsWith('../')) value = path.posix.normalize(path.posix.join(path.posix.dirname(fromPage), value));
  if (!value.endsWith('.md') && !value.includes('.')) value += '.md';
  return value.replace(/\\/g, '/');
}

function normalizeList(value) {
  if (!value) return [];
  if (Array.isArray(value)) return value.flatMap(normalizeList).filter(Boolean);
  if (typeof value === 'object') return Object.values(value).flatMap(normalizeList).filter(Boolean);
  return [String(value).trim()].filter(Boolean);
}

function inlineLinks(markdown) {
  const out = [];
  const wiki = /\[\[([^\]]+)\]\]/g;
  const md = /\[[^\]]+\]\(([^)]+)\)/g;
  let m;
  while ((m = wiki.exec(markdown))) out.push({ type: 'related', target: m[1].split('|')[0].trim(), source: 'wikilink' });
  while ((m = md.exec(markdown))) out.push({ type: 'references', target: m[1].trim(), source: 'markdown_link' });
  return out;
}

function edgeKey(edge) {
  return `${edge.from}\u0000${edge.to}\u0000${edge.type}\u0000${edge.source || ''}`;
}

function addNode(nodes, seen, node) {
  if (!node || !node.id || seen.has(node.id)) return;
  nodes.push(node);
  seen.add(node.id);
}

function addEdge(edges, seen, edge) {
  if (!edge || !edge.from || !edge.to) return;
  const type = allowedTypes.includes(edge.type) ? edge.type : 'related';
  const normalized = { ...edge, type };
  const key = edgeKey(normalized);
  if (seen.has(key)) return;
  edges.push(normalized);
  seen.add(key);
}

function sourceTruthNodes() {
  return SOURCE_TRUTH.map((item) => ({
    ...item,
    type: 'source_truth',
    status: 'canonical',
    group: 'source_truth'
  }));
}

function sourceTruthEdges() {
  const edges = [];
  for (let i = 0; i < SOURCE_TRUTH.length - 1; i += 1) {
    edges.push({
      from: SOURCE_TRUTH[i].id,
      to: SOURCE_TRUTH[i + 1].id,
      type: 'outranks',
      source: 'source_truth_order',
      reason: 'Canonical source-of-truth precedence.'
    });
  }
  return edges;
}

function readModuleCard(module) {
  const card = module.card || (module.module_id ? `.knowledge/modules/${module.module_id}.json` : '');
  if (!card) return {};
  const relPath = normalizeRel(card).replace(/^\.knowledge\//, '');
  return safeReadJson(relPath, {});
}

function moduleStatusMap(trustReport) {
  const out = new Map();
  for (const status of trustReport.module_statuses || []) {
    if (status?.module_id) out.set(status.module_id, status);
  }
  for (const [bucket, ids] of Object.entries(trustReport.modules || {})) {
    for (const id of ids || []) {
      const row = out.get(id) || { module_id: id };
      row.trust_status = row.trust_status || bucket;
      out.set(id, row);
    }
  }
  return out;
}

function moduleNodes(registry, trustReport) {
  const statuses = moduleStatusMap(trustReport);
  const rows = [];
  const seen = new Set();
  for (const module of registry.modules || []) {
    const id = module.module_id || module.id || module.name;
    if (!id) continue;
    const card = readModuleCard(module);
    const status = statuses.get(id) || {};
    rows.push({
      id: `module:${id}`,
      title: `Module: ${module.name || id}`,
      type: 'module',
      group: 'module',
      module_id: id,
      path: module.card || status.card || `.knowledge/modules/${id}.json`,
      trust: module.current_trust_level || card.current_trust_level || status.trust_status || module.trust_status || 'routing_trusted',
      status: module.status || card.status || status.status || 'known',
      confidence: module.confidence || card.confidence || status.confidence || 'unknown',
      key_files: module.key_files || card.key_files || status.key_files || [],
      evidence_files: module.evidence_files || card.evidence_files || status.evidence_files || [],
      description: module.purpose || card.purpose || module.path || ''
    });
    seen.add(id);
  }
  for (const [id, status] of statuses.entries()) {
    if (seen.has(id)) continue;
    rows.push({
      id: `module:${id}`,
      title: `Module: ${id}`,
      type: 'module',
      group: 'module',
      module_id: id,
      path: status.card || `.knowledge/modules/${id}.json`,
      trust: status.trust_status || 'routing_trusted',
      status: status.status || 'known',
      confidence: status.confidence || 'unknown',
      key_files: status.key_files || [],
      evidence_files: status.evidence_files || [],
      description: status.path || ''
    });
  }
  return rows;
}

function inferWikiIndexEdges(pageSet) {
  const targets = [
    'architecture/README.md',
    'concepts/README.md',
    'runbooks/README.md',
    'log.md'
  ].filter((page) => pageSet.has(page));
  if (!pageSet.has('index.md')) return [];
  return targets.map((to) => ({
    from: 'index.md',
    to,
    type: 'references',
    source: 'default_wiki_index',
    reason: 'Default wiki index section.'
  }));
}

function inferModuleEdges(modules, pageSet) {
  const edges = [];
  for (const module of modules) {
    addInferredModuleEdge(edges, 'truth:modules', module.id, 'routes', 'module_registry');
    addInferredModuleEdge(edges, 'truth:code', module.id, 'checks', 'current_code_contract');
    addInferredModuleEdge(edges, module.id, 'truth:wiki', 'documents', 'module_to_wiki_layer');
    if (pageSet.has('index.md')) addInferredModuleEdge(edges, module.id, 'index.md', 'documents', 'module_wiki_index');
    if (pageSet.has('architecture/README.md')) addInferredModuleEdge(edges, module.id, 'architecture/README.md', 'documents', 'module_architecture_notes');
    if (pageSet.has('runbooks/README.md')) addInferredModuleEdge(edges, module.id, 'runbooks/README.md', 'documents', 'module_runbooks');
    if ((module.evidence_files || []).length) addInferredModuleEdge(edges, 'truth:evidence', module.id, 'evidence', 'module_evidence_files');
  }
  return edges;
}

function addInferredModuleEdge(edges, from, to, type, source) {
  edges.push({
    from,
    to,
    type,
    source,
    reason: 'Inferred free-core trust graph relation.'
  });
}

function relationCounts(edges) {
  const counts = {};
  for (const edge of edges || []) counts[edge.type] = (counts[edge.type] || 0) + 1;
  return counts;
}

function incomingCounts(edges) {
  const incoming = new Map();
  for (const edge of edges || []) incoming.set(edge.to, (incoming.get(edge.to) || 0) + 1);
  return incoming;
}

function buildUnlocked(options = {}) {
  ensureDir(path.join(stateRoot, 'maps'));
  const pages = walk(wikiRoot);
  const pageSet = new Set(pages.map((abs) => rel(abs, wikiRoot)));
  const nodes = [];
  const nodeSeen = new Set();
  const edges = [];
  const edgeSeen = new Set();
  const wikiNodes = [];

  for (const node of sourceTruthNodes()) addNode(nodes, nodeSeen, node);
  for (const edge of sourceTruthEdges()) addEdge(edges, edgeSeen, edge);

  for (const abs of pages) {
    const page = rel(abs, wikiRoot);
    const raw = fs.readFileSync(abs, 'utf8');
    const fm = parseFrontmatter(raw);
    const title = titleFrom(fm.body, page);
    const node = {
      id: page,
      path: `.knowledge/wiki/${page}`,
      title,
      type: fm.data.type || 'wiki_page',
      group: 'wiki',
      trust: fm.data.trust || 'advisory_only',
      status: fm.data.status || 'unknown',
      sha256: sha256(raw)
    };
    wikiNodes.push(node);
    addNode(nodes, nodeSeen, node);
    const typed = fm.data.links && typeof fm.data.links === 'object' ? fm.data.links : {};
    for (const [type, value] of Object.entries(typed)) {
      for (const targetRaw of normalizeList(value)) {
        addEdge(edges, edgeSeen, {
          from: page,
          to: canonical(targetRaw, page),
          type: allowedTypes.includes(type) ? type : 'related',
          source: 'frontmatter'
        });
      }
    }
    for (const link of inlineLinks(fm.body)) {
      addEdge(edges, edgeSeen, {
        from: page,
        to: canonical(link.target, page),
        type: link.type,
        source: link.source
      });
    }
  }

  for (const edge of inferWikiIndexEdges(pageSet)) addEdge(edges, edgeSeen, edge);

  const moduleRegistry = safeReadJson('modules/module_registry.json', { modules: [] });
  const trustReport = safeReadJson('maintenance/trust_report.json', {});
  const moduleGraphNodes = moduleNodes(moduleRegistry, trustReport);
  for (const node of moduleGraphNodes) addNode(nodes, nodeSeen, node);
  for (const edge of inferModuleEdges(moduleGraphNodes, pageSet)) addEdge(edges, edgeSeen, edge);

  if (pageSet.has('index.md')) addEdge(edges, edgeSeen, {
    from: 'truth:wiki',
    to: 'index.md',
    type: 'advisory',
    source: 'source_truth_order',
    reason: 'Wiki is advisory unless backed by current code/tests/evidence.'
  });

  const nodeIdSet = new Set(nodes.map((node) => node.id));
  const broken_edges = [];
  for (const edge of edges) {
    if (/^https?:\/\//i.test(edge.to) || edge.to.startsWith('mailto:') || edge.to.startsWith('.knowledge/')) continue;
    if (!nodeIdSet.has(edge.to)) broken_edges.push(edge);
  }

  const incoming = incomingCounts(edges);
  const orphan_pages = wikiNodes
    .filter((node) => !['index.md', 'log.md'].includes(node.id) && !node.id.endsWith('/README.md') && !(incoming.get(node.id) || 0))
    .map((node) => node.id);
  const relation_counts = relationCounts(edges);

  const graph = {
    schema_version: '3.2.5',
    generated_at: nowIso(),
    generated_by: getAgentId(),
    mode: context.mode,
    view: 'free_core_trust_graph',
    readiness: edges.length >= 8 && SOURCE_TRUTH.length >= 6 ? 'actionable' : 'needs_more_links',
    node_count: nodes.length,
    edge_count: edges.length,
    wiki_node_count: wikiNodes.length,
    module_node_count: moduleGraphNodes.length,
    source_truth_node_count: SOURCE_TRUTH.length,
    broken_edge_count: broken_edges.length,
    orphan_page_count: orphan_pages.length,
    allowed_edge_types: allowedTypes,
    summary: {
      source_truth_order: SOURCE_TRUTH.map((item) => item.title),
      relation_counts,
      orphan_pages,
      broken_edges: broken_edges.length,
      actionable_checks: [
        'Keep source-of-truth order visible.',
        'Add typed wiki links for durable project-specific relations.',
        'Keep module cards connected to wiki/runbooks.',
        'Treat external memory as advisory only.'
      ]
    },
    nodes,
    edges,
    broken_edges
  };
  writeJsonAtomic(path.join(stateRoot, 'maps', 'wiki_graph.json'), graph);
  if (!options.quiet) {
    console.log(JSON.stringify({
      written: context.mode === 'repo' ? '.knowledge/maps/wiki_graph.json' : path.join(stateRoot, 'maps', 'wiki_graph.json'),
      view: graph.view,
      readiness: graph.readiness,
      nodes: nodes.length,
      edges: edges.length,
      broken_edges: broken_edges.length,
      orphan_pages: orphan_pages.length
    }, null, 2));
  }
  return graph;
}

function main(options = {}) { return options.skipLock ? buildUnlocked(options) : withLock(lockDir, () => buildUnlocked(options)); }
module.exports = main;
if (require.main === module) {
  try { main({ quiet: process.argv.includes('--quiet') }); }
  catch (error) { console.error(error.stack || error.message); process.exit(1); }
}
