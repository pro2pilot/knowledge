#!/usr/bin/env node
'use strict';

const path = require('path');
const { ensureDir, readJson, writeJsonAtomic, getAgentId, withLock } = require('./lib/json-store');
const knowledgeRoot = path.resolve(__dirname, '..');
const lockDir = path.join(knowledgeRoot, '.lock');
function nowIso() { return new Date().toISOString(); }
function env(name) { return process.env[name] || ''; }
function pineconeMode() {
  const mode = env('PINECONE_MODE').toLowerCase();
  if (['local','cloud','disabled'].includes(mode)) return mode;
  const host = env('PINECONE_HOST') || env('PINECONE_INDEX_HOST') || env('PINECONE_LOCAL_HOST');
  if (/^https?:\/\/(localhost|127\.0\.0\.1|0\.0\.0\.0)(:|\/|$)/i.test(host)) return 'local';
  if (host && env('PINECONE_API_KEY')) return 'cloud';
  return 'disabled';
}
function statusUnlocked(options = {}) {
  ensureDir(path.join(knowledgeRoot, 'maintenance'));
  const registry = readJson(path.join(knowledgeRoot, 'external_memory', 'registry.json'), { providers: {} });
  const policy = readJson(path.join(knowledgeRoot, 'external_memory', 'retrieval_policy.json'), {});
  const sources = readJson(path.join(knowledgeRoot, 'external_memory', 'pinecone_sources.json'), { sources: [] });
  const mode = pineconeMode();
  const host = env('PINECONE_HOST') || env('PINECONE_INDEX_HOST') || env('PINECONE_LOCAL_HOST');
  const apiKeyRequired = mode === 'cloud';
  const configured = mode !== 'disabled' && Boolean(host) && (!apiKeyRequired || Boolean(env('PINECONE_API_KEY')));
  const report = {
    schema_version: '3.1.9', generated_at: nowIso(), generated_by: getAgentId(),
    policy: { local_first: policy.local_first !== false, source_of_truth: false, max_external_chunks: policy.max_external_chunks || 5 },
    providers: { pinecone: { enabled: Boolean(registry.providers?.pinecone?.enabled || sources.enabled), mode, configured, status: mode === 'disabled' ? 'disabled' : configured ? `ready_${mode}` : `missing_${mode}_environment`, api_key_required: apiKeyRequired, local_supported: true, source_of_truth: false } },
    sources: { configured_sources: (sources.sources || []).length, namespace: sources.namespace || env('PINECONE_NAMESPACE') || null, index: sources.index || env('PINECONE_INDEX') || null },
    live_checks: { pinecone: { mode: options.live ? mode : 'offline', status: options.live ? (configured ? 'configured_not_pinged_by_default' : 'skipped') : 'not_run', reason: options.live ? 'This tool performs readiness checks; run pinecone-search/upsert for live API behavior.' : 'Use --live for explicit readiness with env.' } }
  };
  writeJsonAtomic(path.join(knowledgeRoot, 'maintenance', 'external_memory_status.json'), report);
  if (!options.quiet) console.log(JSON.stringify(report, null, 2));
  return report;
}
function main(options = {}) { return options.skipLock ? statusUnlocked(options) : withLock(lockDir, () => statusUnlocked(options)); }
module.exports = main;
if (require.main === module) { try { main({ quiet: process.argv.includes('--quiet'), live: process.argv.includes('--live') }); } catch(e){ console.error(e.stack||e.message); process.exit(1); } }
