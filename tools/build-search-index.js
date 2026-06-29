#!/usr/bin/env node
'use strict';

// wiki body, cookbook, decisions, contradictions, invariants, glossary,
// external_memory advisories, official templates, modules and evidence.
// Tighten scoring so empty evidence files or unrelated module cards do
// not win only because of weak path-level terms.

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { ensureDir, readJson, writeJsonAtomic, getAgentId, withLock } = require('./lib/json-store');
const { estimateTokens } = require('./lib/token-estimate');
const { resolveKnowledgeContext } = require('./lib/path-context');

const context = resolveKnowledgeContext();
const repoRoot = context.targetRoot;
const knowledgeRoot = context.projectKnowledgeRoot;
const stateRoot = context.stateRoot;
const lockDir = path.join(stateRoot, '.lock');
const maxBytes = Number(process.env.KNOWLEDGE_SEARCH_MAX_FILE_BYTES || 250000);

const stopwords = new Set('the a an and or of to in for on with without into from by as is are was were be been this that these those it its code tests evidence module modules knowledge json md read write current source truth project file files'.split(' '));

// covers only obviously equivalent pairs that we observed missed in the
// earlier field tests.
const SYNONYMS = {
  auth: ['authentication', 'authorization', 'login', 'identity', 'session'],
  authentication: ['auth'],
  authorization: ['auth', 'rbac', 'permission', 'role'],
  db: ['database', 'storage', 'persistence'],
  database: ['db'],
  migration: ['schema', 'migrations'],
  queue: ['job', 'jobs', 'worker', 'workers', 'background'],
  worker: ['queue', 'job', 'background'],
  billing: ['payment', 'payments', 'invoice', 'invoices', 'charge', 'charges', 'stripe'],
  payment: ['billing', 'charge', 'stripe'],
  rate: ['ratelimit', 'rate-limit', 'throttle', 'throttling'],
  limiting: ['rate-limit', 'throttle', 'throttling'],
  ratelimit: ['rate', 'throttle'],
  pinecone: ['vector', 'embedding', 'external_memory', 'archive'],
  external: ['pinecone', 'archive', 'cold-storage'],
  test: ['tests', 'verification', 'spec', 'coverage'],
  tests: ['test', 'spec', 'verification'],
  secret: ['credentials', 'apikey', 'token', 'env'],
  pii: ['privacy', 'personal']
};

function nowIso() { return new Date().toISOString(); }
function rel(abs) {
  const fromProject = path.relative(knowledgeRoot, abs).replace(/\\/g, '/');
  if (!fromProject.startsWith('..') && !path.isAbsolute(fromProject)) return fromProject;
  const fromState = path.relative(stateRoot, abs).replace(/\\/g, '/');
  if (!fromState.startsWith('..') && !path.isAbsolute(fromState)) return fromState;
  return path.basename(abs);
}
function sha256Text(text) { return crypto.createHash('sha256').update(text).digest('hex'); }
function expandTokens(tokens) {
  const out = new Set(tokens);
  for (const token of tokens) {
    const syns = SYNONYMS[token];
    if (syns) for (const s of syns) out.add(s);
  }
  return Array.from(out);
}
function tokenize(text) {
  const matched = String(text || '').toLowerCase().match(/[a-zа-яё0-9_./:-]{2,}/gi) || [];
  return matched.map((t) => t.toLowerCase()).filter((t) => !stopwords.has(t));
}
function countTerms(tokens) {
  const counts = new Map();
  for (const token of tokens) counts.set(token, (counts.get(token) || 0) + 1);
  return Array.from(counts.entries()).sort((a, b) => b[1] - a[1]);
}
function firstHeading(markdown, fallback) {
  const match = String(markdown || '').match(/^#\s+(.+)$/m);
  return match ? match[1].trim() : fallback;
}

function classify(relative) {
  if (relative.startsWith('wiki/')) return 'wiki';
  if (relative.startsWith('docs/cookbook/')) return 'cookbook';
  if (relative === 'decisions.json') return 'decision';
  if (relative === 'contradictions.json') return 'contradiction';
  if (relative.startsWith('invariants/')) return 'invariant';
  if (relative === 'glossary.json') return 'glossary';
  if (relative.startsWith('external_memory/')) return 'external_memory';
  if (relative.startsWith('templates/official/')) return 'template';
  if (relative.startsWith('modules/')) return 'module';
  if (relative.startsWith('evidence/')) return 'evidence';
  if (relative.startsWith('maps/')) return 'map';
  if (relative.startsWith('maintenance/')) return 'maintenance';
  return 'knowledge';
}

// "rate limiting" query stops surfacing an empty evidence stub just because
// the filename happens to contain a weak path-level term.
function qualityWeight(text, kind) {
  const body = String(text || '').trim();
  if (!body) return 0.1;
  if (kind === 'evidence' || kind === 'glossary' || kind === 'decision' || kind === 'contradiction') {
    try {
      const data = JSON.parse(body);
      const containers = ['facts', 'links', 'items', 'decisions', 'contradictions', 'entries', 'terms'];
      const filled = containers.some((key) => Array.isArray(data[key]) && data[key].length > 0);
      if (!filled) return 0.1;
    } catch { /* not strict JSON — fall through */ }
  }
  if (body.length < 80) return 0.4;
  return 1.0;
}

function walk(dir, output = []) {
  if (!fs.existsSync(dir)) return output;
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const abs = path.join(dir, entry.name);
    const relative = rel(abs);
    if (relative.includes('/events/') || relative.startsWith('.runtime/') || relative.startsWith('.lock/') || relative.startsWith('tools/') || relative.startsWith('search/')) continue;
    if (entry.isDirectory()) walk(abs, output);
    else if (entry.isFile() && /\.(md|json|txt)$/i.test(entry.name)) output.push(abs);
  }
  return output;
}

function collectFiles() {
  // scope is explicit per spec.
  const includedRoots = [
    'wiki',
    'docs/cookbook',
    'modules',
    'evidence',
    'maps',
    'invariants',
    'external_memory',
    'templates/official'
  ];
  const projectFiles = ['decisions.json', 'contradictions.json', 'glossary.json', 'project_index.json', 'maintenance/concurrency_policy.json'];
  const stateFiles = ['maintenance/handoff_summary.json', 'maintenance/trust_report.json', 'maintenance/quality_report.json', 'maintenance/routing_bundle.json'];
  const files = [];
  for (const rootName of includedRoots) walk(path.join(knowledgeRoot, rootName), files);
  for (const file of projectFiles) {
    const abs = path.join(knowledgeRoot, file);
    if (fs.existsSync(abs) && fs.statSync(abs).isFile()) files.push(abs);
  }
  for (const file of stateFiles) {
    const abs = path.join(stateRoot, file);
    if (fs.existsSync(abs) && fs.statSync(abs).isFile()) files.push(abs);
  }
  return Array.from(new Set(files));
}

function makeSnippet(text) {
  const clean = String(text || '').replace(/\s+/g, ' ').trim();
  return clean.slice(0, 600);
}
function readCompact(abs) {
  const stats = fs.statSync(abs);
  if (stats.size > maxBytes) return null;
  const raw = fs.readFileSync(abs, 'utf8').replace(/^﻿/, '');
  const relative = rel(abs);
  if (relative.endsWith('.json')) {
    try { return JSON.stringify(JSON.parse(raw), null, 2); } catch { return raw; }
  }
  return raw;
}

function expandCollectionDocs(relative, parsed) {
  const out = [];
  if (relative === 'decisions.json' && Array.isArray(parsed?.decisions)) {
    for (const decision of parsed.decisions) {
      out.push({ subPath: `${relative}#${decision.id || decision.title || 'decision'}`, kind: 'decision', title: decision.title || decision.id || 'Decision', body: JSON.stringify(decision, null, 2) });
    }
  }
  if (relative === 'contradictions.json' && Array.isArray(parsed?.items)) {
    for (const item of parsed.items) {
      out.push({ subPath: `${relative}#${item.id || item.subject || 'contradiction'}`, kind: 'contradiction', title: item.subject || item.id || 'Contradiction', body: JSON.stringify(item, null, 2) });
    }
  }
  if (relative === 'glossary.json' && Array.isArray(parsed?.terms)) {
    for (const term of parsed.terms) {
      out.push({ subPath: `${relative}#${term.term || term.id || 'term'}`, kind: 'glossary', title: term.term || term.id || 'Term', body: JSON.stringify(term, null, 2) });
    }
  }
  return out;
}

function buildUnlocked(options = {}) {
  ensureDir(path.join(stateRoot, 'search'));
  const generatedAt = nowIso();
  const docs = [];
  const includedCounts = {};

  for (const abs of collectFiles()) {
    const text = readCompact(abs);
    if (!text) continue;
    const relative = rel(abs);
    const kind = classify(relative);
    includedCounts[kind] = (includedCounts[kind] || 0) + 1;

    let parsed = null;
    if (relative.endsWith('.json')) {
      try { parsed = JSON.parse(text); } catch { parsed = null; }
    }
    const expanded = parsed ? expandCollectionDocs(relative, parsed) : [];
    if (expanded.length > 0) {
      for (const item of expanded) {
        const title = item.title;
        const tokens = expandTokens(tokenize(`${item.subPath} ${title} ${item.body}`));
        const topTerms = countTerms(tokens).slice(0, 40).map(([term, count]) => ({ term, count }));
        docs.push({
          id: docs.length + 1,
          path: `.knowledge/${item.subPath}`,
          source_file: `.knowledge/${relative}`,
          type: item.kind,
          title,
          sha256: sha256Text(item.body),
          bytes: Buffer.byteLength(item.body, 'utf8'),
          tokens_approx: estimateTokens(item.body),
          quality_weight: qualityWeight(item.body, item.kind),
          top_terms: topTerms,
          snippet: makeSnippet(item.body)
        });
      }
      continue;
    }

    const title = relative.endsWith('.md') ? firstHeading(text, relative) : relative;
    const tokens = expandTokens(tokenize(`${relative} ${title} ${text}`));
    const topTerms = countTerms(tokens).slice(0, 40).map(([term, count]) => ({ term, count }));
    docs.push({
      id: docs.length + 1,
      path: `.knowledge/${relative}`,
      type: kind,
      title,
      sha256: sha256Text(text),
      bytes: Buffer.byteLength(text, 'utf8'),
      tokens_approx: estimateTokens(text),
      quality_weight: qualityWeight(text, kind),
      top_terms: topTerms,
      snippet: makeSnippet(text)
    });
  }

  const index = {
    schema_version: '3.2.2',
    generated_at: generatedAt,
    generated_by: getAgentId(),
    mode: context.mode,
    target_root: context.targetRoot,
    project_knowledge_root: context.projectKnowledgeRoot,
    state_root: context.stateRoot,
    index_type: 'local_lexical_compact',
    purpose: 'Compact local search index. Use search-knowledge.js to retrieve only relevant .knowledge documents.',
    document_kinds: ['wiki', 'cookbook', 'decision', 'contradiction', 'invariant', 'glossary', 'external_memory', 'template', 'module', 'evidence', 'map', 'maintenance', 'knowledge'],
    counts_by_kind: includedCounts,
    synonyms_known: Object.keys(SYNONYMS).length,
    document_count: docs.length,
    documents: docs.sort((a, b) => a.path.localeCompare(b.path))
  };
  writeJsonAtomic(path.join(stateRoot, 'search', 'index.json'), index);
  if (!options.quiet) console.log(JSON.stringify({ written: context.mode === 'repo' ? '.knowledge/search/index.json' : path.join(stateRoot, 'search', 'index.json'), documents: docs.length, kinds: includedCounts }, null, 2));
  return index;
}

function main(options = {}) {
  if (options.skipLock) return buildUnlocked(options);
  return withLock(lockDir, () => buildUnlocked(options));
}

module.exports = main;

if (require.main === module) {
  try { main({ quiet: process.argv.includes('--quiet') }); }
  catch (error) { console.error(error.stack || error.message); process.exit(1); }
}
