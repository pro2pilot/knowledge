#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { ensureDir, writeJsonAtomic, getAgentId, withLock } = require('./lib/json-store');

const knowledgeRoot = path.resolve(__dirname, '..');
const wikiRoot = path.join(knowledgeRoot, 'wiki');
const lockDir = path.join(knowledgeRoot, '.lock');
const allowedTypes = ['supports', 'contradicts', 'depends_on', 'supersedes', 'preceded_by', 'followed_by', 'implements', 'references', 'related', 'source_of', 'evidence', 'source_files', 'tests'];

function nowIso() { return new Date().toISOString(); }
function sha256(text) { return crypto.createHash('sha256').update(text).digest('hex'); }
function rel(abs, base = knowledgeRoot) { return path.relative(base, abs).replace(/\\/g, '/'); }
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
  return v.replace(/^['\"]|['\"]$/g, '');
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
function buildUnlocked(options = {}) {
  ensureDir(path.join(knowledgeRoot, 'maps'));
  const pages = walk(wikiRoot);
  const pageSet = new Set(pages.map((abs) => rel(abs, wikiRoot)));
  const nodes = [];
  const edges = [];
  const broken_edges = [];
  for (const abs of pages) {
    const page = rel(abs, wikiRoot);
    const raw = fs.readFileSync(abs, 'utf8');
    const fm = parseFrontmatter(raw);
    const title = titleFrom(fm.body, page);
    nodes.push({ id: page, path: `.knowledge/wiki/${page}`, title, type: fm.data.type || 'wiki_page', trust: fm.data.trust || 'advisory_only', status: fm.data.status || 'unknown', sha256: sha256(raw) });
    const typed = fm.data.links && typeof fm.data.links === 'object' ? fm.data.links : {};
    for (const [type, value] of Object.entries(typed)) {
      for (const targetRaw of normalizeList(value)) edges.push({ from: page, to: canonical(targetRaw, page), type: allowedTypes.includes(type) ? type : 'related', source: 'frontmatter' });
    }
    for (const link of inlineLinks(fm.body)) edges.push({ from: page, to: canonical(link.target, page), type: link.type, source: link.source });
  }
  for (const edge of edges) {
    if (/^https?:\/\//i.test(edge.to) || edge.to.startsWith('mailto:') || edge.to.startsWith('.knowledge/')) continue;
    if (!pageSet.has(edge.to)) broken_edges.push(edge);
  }
  const graph = { schema_version: '3.1.8', generated_at: nowIso(), generated_by: getAgentId(), node_count: nodes.length, edge_count: edges.length, broken_edge_count: broken_edges.length, allowed_edge_types: allowedTypes, nodes, edges, broken_edges };
  writeJsonAtomic(path.join(knowledgeRoot, 'maps', 'wiki_graph.json'), graph);
  if (!options.quiet) console.log(JSON.stringify({ written: '.knowledge/maps/wiki_graph.json', nodes: nodes.length, edges: edges.length, broken_edges: broken_edges.length }, null, 2));
  return graph;
}
function main(options = {}) { return options.skipLock ? buildUnlocked(options) : withLock(lockDir, () => buildUnlocked(options)); }
module.exports = main;
if (require.main === module) {
  try { main({ quiet: process.argv.includes('--quiet') }); }
  catch (error) { console.error(error.stack || error.message); process.exit(1); }
}
