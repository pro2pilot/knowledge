#!/usr/bin/env node
'use strict';

// --scope= filter so official templates and cookbook recipes do not
// pollute project-fact queries. Default scope is "project".
//
// Scopes:
//   project   modules, evidence, maps, maintenance, project_index,
//             wiki, decisions, contradictions, glossary, invariants,
//             external_memory. No templates. Cookbook excluded unless
//             explicitly chosen.
//   cookbook  docs/cookbook only.
//   templates templates/official only.
//   all       no filter.

const fs = require('fs');
const path = require('path');
const { readJson, assertSafeContainedPath } = require('./lib/json-store');
const { resolveKnowledgeContext } = require('./lib/path-context');

const context = resolveKnowledgeContext();
const indexPath = path.join(context.stateRoot, 'search', 'index.json');
const buildIndex = require('./build-search-index.js');

const VALID_SCOPES = ['project', 'cookbook', 'templates', 'all'];
const DEFAULT_SCOPE = 'project';

const PROJECT_TYPES = new Set([
  'module', 'evidence', 'map', 'maintenance', 'knowledge',
  'wiki', 'decision', 'contradiction', 'glossary', 'invariant',
  'external_memory'
]);

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
  pinecone: ['vector', 'embedding', 'external_memory', 'archive'],
  external: ['pinecone', 'archive', 'cold-storage'],
  test: ['tests', 'verification', 'spec', 'coverage'],
  tests: ['test', 'spec', 'verification'],
  secret: ['credentials', 'apikey', 'token', 'env'],
  pii: ['privacy', 'personal']
};

function tokenize(text) {
  return String(text || '').normalize('NFC').toLowerCase().match(/[\p{L}\p{M}\p{N}_./:-]{2,}/gu) || [];
}

function expandTokens(tokens) {
  const out = new Set(tokens);
  for (const token of tokens) {
    const syns = SYNONYMS[token];
    if (syns) for (const s of syns) out.add(s);
  }
  return Array.from(out);
}

function usage() {
  return [
    'Usage: node .knowledge/tools/search-knowledge.js "query" [flags]',
    '',
    'Flags:',
    '  --limit=<n>          Maximum results (default 10)',
    '  --json               Emit JSON',
    '  --explain            Print expanded query terms',
    '  --kind=<kind>        Restrict to a single document kind',
    `  --scope=<scope>      One of ${VALID_SCOPES.join(', ')} (default ${DEFAULT_SCOPE})`,
    '',
    'Scopes:',
    '  project    project facts (modules, evidence, wiki, decisions, ...).',
    '             Templates and cookbook are excluded.',
    '  cookbook   docs/cookbook only.',
    '  templates  templates/official only.',
    '  all        no filter (broad exploratory search).',
    '',
    'Run build-search-index.js first if the index is stale.'
  ].join('\n');
}

function parseArgs(argv) {
  const queryParts = [];
  let limit = 10;
  let jsonMode = false;
  let explain = false;
  let kind = null;
  let scope = DEFAULT_SCOPE;
  let help = false;
  const contextFlags = new Set(['--system-root', '--target-root', '--project-knowledge-root', '--state-root', '--mode', '--team-root', '--workspace-id', '--agent-id']);
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    const key = arg.split('=')[0];
    const value = () => {
      if (arg.includes('=')) return arg.slice(arg.indexOf('=') + 1);
      if (!argv[index + 1] || argv[index + 1].startsWith('--')) throw new Error(`${key} requires a value`);
      index += 1;
      return argv[index];
    };
    if (contextFlags.has(key)) { value(); }
    else if (key === '--limit') {
      limit = Number(value());
      if (!Number.isSafeInteger(limit) || limit < 1) throw new Error('--limit must be a positive integer');
    }
    else if (arg === '--json') jsonMode = true;
    else if (arg === '--explain') explain = true;
    else if (arg === '--help') help = true;
    else if (key === '--kind') kind = value();
    else if (key === '--scope') scope = value();
    else if (arg.startsWith('--')) throw new Error(`Unknown search flag: ${arg}`);
    else queryParts.push(arg);
  }
  return { query: queryParts.join(' ').trim(), limit, jsonMode, explain, kind, scope, help };
}

function loadIndex() {
  if (!fs.existsSync(indexPath)) buildIndex({ quiet: true });
  assertSafeContainedPath(context.stateRoot, indexPath);
  const index = readJson(indexPath);
  if (!index || !Array.isArray(index.documents)) throw new Error('Search index must contain a documents array. Rebuild the index after reviewing the damaged file.');
  return index;
}

function passesScope(doc, scope) {
  if (scope === 'all') return true;
  if (scope === 'templates') return doc.type === 'template';
  if (scope === 'cookbook') return doc.type === 'cookbook';
  if (scope === 'project') return PROJECT_TYPES.has(doc.type);
  return false;
}

function scoreDoc(doc, terms) {
  const pathText = String(doc.path || '').normalize('NFC').toLowerCase();
  const titleText = String(doc.title || '').normalize('NFC').toLowerCase();
  const snippetText = String(doc.snippet || '').normalize('NFC').toLowerCase();
  const top = new Map((doc.top_terms || []).map((item) => [item.term, item.count]));
  let score = 0;
  let matchedTerms = 0;
  for (const term of terms) {
    let local = 0;
    if (titleText.includes(term)) local += 6;
    if (pathText.includes(term)) local += 3;
    if (snippetText.includes(term)) local += 2;
    const tf = Math.min(top.get(term) || 0, 10);
    local += tf;
    if (local > 0) matchedTerms += 1;
    score += local;
  }
  // Document-kind priors rank actual matches; they must never manufacture
  // hits for an unrelated query or a query with no searchable terms.
  if (matchedTerms === 0) return 0;
  const kindBoost = {
    decision: 2, contradiction: 3, invariant: 2, wiki: 2, cookbook: 2,
    template: 1, glossary: 1, module: 1, external_memory: 1, evidence: 1
  };
  score += kindBoost[doc.type] || 0;
  if (matchedTerms > 1) score += matchedTerms * 2;
  const quality = typeof doc.quality_weight === 'number' ? doc.quality_weight : 1;
  return score * quality;
}

function main(argv = process.argv.slice(2)) {
  const { query, limit, jsonMode, explain, kind, scope, help } = parseArgs(argv);
  if (help) {
    console.log(jsonMode ? JSON.stringify({ usage: usage() }, null, 2) : usage());
    return [];
  }
  if (!VALID_SCOPES.includes(scope)) {
    const message = `Invalid --scope=${scope}. Valid: ${VALID_SCOPES.join(', ')}`;
    if (jsonMode) console.log(JSON.stringify({ error: message, valid_scopes: VALID_SCOPES }, null, 2));
    else console.error(message);
    process.exit(1);
  }
  if (!query) {
    if (jsonMode) console.log(JSON.stringify({ error: usage() }, null, 2));
    else console.log(usage());
    return [];
  }
  const baseTerms = Array.from(new Set(tokenize(query)));
  const terms = expandTokens(baseTerms);
  const index = loadIndex();
  const filtered = (index.documents || []).filter((doc) => passesScope(doc, scope));
  const results = filtered
    .filter((doc) => !kind || doc.type === kind)
    .map((doc) => ({ ...doc, score: scoreDoc(doc, terms) }))
    .filter((doc) => doc.score > 0)
    .sort((a, b) => b.score - a.score || a.path.localeCompare(b.path))
    .slice(0, limit)
    .map((doc) => ({ path: doc.path, type: doc.type, title: doc.title, score: Math.round(doc.score * 10) / 10, snippet: doc.snippet, quality_weight: doc.quality_weight }));

  if (jsonMode) {
    console.log(JSON.stringify({
      query,
      scope,
      kind_filter: kind,
      terms_with_synonyms: terms,
      base_terms: baseTerms,
      docs_in_scope: filtered.length,
      results
    }, null, 2));
  } else {
    console.log(`Knowledge search: ${query} [scope=${scope}]${explain ? ' --explain' : ''}`);
    if (explain) console.log(`Expanded terms: ${terms.join(', ')}`);
    if (results.length === 0) {
      const hint = scope === 'project'
        ? 'No project matches. Try --scope=templates for scaffolding suggestions or --scope=all for broad search.'
        : 'No matches. Try broader terms or run node .knowledge/tools/build-search-index.js.';
      console.log(hint);
    }
    for (const [i, doc] of results.entries()) {
      console.log(`\n${i + 1}. ${doc.path} [${doc.type}] score=${doc.score}`);
      console.log(`   ${doc.title}`);
      console.log(`   ${doc.snippet}`);
    }
  }
  return results;
}

module.exports = main;
module.exports.VALID_SCOPES = VALID_SCOPES;
module.exports.DEFAULT_SCOPE = DEFAULT_SCOPE;

if (require.main === module) {
  try { main(); }
  catch (error) { console.error(error.stack || error.message); process.exit(1); }
}
