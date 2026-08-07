#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const { parseCliArgs, resolveKnowledgeContext } = require('./lib/path-context');
const { buildExternalMemoryReport } = require('./lib/memory-providers');
const {
  advisoryEnvelope,
  assertAdvisory,
  memoryRecord,
  publicRecord,
  redactSecrets,
  sha
} = require('./lib/memory-adapter-contract');
const pc = require('./external/pinecone-common');

function liveAllowed(flags) {
  return Boolean(flags.live || flags.yesLiveMemory || process.env.KNOWLEDGE_MEMORY_PROVIDER_TEST_MODE === '1');
}

function pineconeEnvSummary() {
  const env = pc.env();
  return redactSecrets({
    mode: env.mode,
    configured: env.configured,
    api_key_required: env.apiKeyRequired,
    host: env.host || null,
    namespace: env.namespace,
    index: env.index || null
  });
}

function pineconeHealth(flags) {
  const env = pineconeEnvSummary();
  return advisoryEnvelope('pinecone', 'pinecone-rest', 'health', {
    status: env.configured ? 'available' : env.mode === 'disabled' ? 'disabled' : 'error',
    runtime_health: env.configured ? 'unknown' : 'not_available',
    mode: env.mode,
    configured: env.configured,
    environment: env,
    warnings: [
      'Health/status does not call Pinecone.',
      env.mode === 'cloud' ? 'Cloud mode can make network calls only with explicit --live actions.' : null
    ].filter(Boolean)
  });
}

function recordToVector(record) {
  const text = record.text || '';
  return {
    id: record.id,
    sparseValues: pc.sparse(text),
    metadata: {
      provider_id: record.provider_id,
      scope: record.scope,
      user_id: record.user_id || '',
      text_sha256: record.text_sha256 || sha(text),
      chunk_text: text.slice(0, 1800),
      source_of_truth: false,
      trust_effect: 'advisory_only',
      override_attempt: Boolean(record.override_attempt),
      ...(record.metadata || {})
    }
  };
}

function sourceVectors(flags) {
  const vectors = [];
  for (const filePath of pc.sourceFiles()) {
    const text = fs.readFileSync(filePath, 'utf8');
    const rel = path.relative(pc.repoRoot(), filePath).replace(/\\/g, '/');
    pc.chunk(text).forEach((chunk, index) => {
      vectors.push({
        id: `${sha(rel).slice(0, 12)}-${index}`,
        sparseValues: pc.sparse(chunk),
        metadata: {
          source_uri: rel,
          chunk_index: index,
          chunk_text: chunk.slice(0, 1800),
          sha256: sha(chunk),
          source_of_truth: false,
          trust_effect: 'advisory_only',
          trust: 'external_unverified'
        }
      });
    });
  }
  return vectors;
}

async function remember(flags, positional) {
  const text = String(flags.text || positional.slice(1).join(' ') || '').trim();
  if (!text) throw new Error('remember/add requires --text "..." or positional text');
  const record = memoryRecord('pinecone', text, {
    scope: flags.scope || 'repo',
    user_id: flags.userId || flags.user || process.env.KNOWLEDGE_MEMORY_USER_ID || 'knowledge-repo',
    metadata: flags.metadataJson ? JSON.parse(String(flags.metadataJson)) : {}
  });
  const env = pc.env();
  const request = { namespace: env.namespace, vectors: [recordToVector(record)] };
  if (!liveAllowed(flags) || !env.configured) {
    return advisoryEnvelope('pinecone', 'pinecone-rest', 'remember', {
      status: env.configured ? 'preview' : 'disabled',
      persisted: false,
      dry_run: true,
      request,
      record: publicRecord(record, false),
      warnings: ['Pinecone upsert was not called. Pass --live with configured Pinecone env for explicit network write.', ...record.policy_warnings]
    });
  }
  const raw = await pc.request('/vectors/upsert', request);
  return advisoryEnvelope('pinecone', 'pinecone-rest', 'remember', {
    status: 'ok',
    persisted: true,
    network_calls: 'explicit_live_call',
    record: publicRecord(record, false),
    raw
  });
}

async function syncSources(flags) {
  const env = pc.env();
  const vectors = sourceVectors(flags);
  const request = { namespace: env.namespace, vectors };
  if (!liveAllowed(flags) || !env.configured) {
    return advisoryEnvelope('pinecone', 'pinecone-rest', 'sync-sources', {
      status: env.configured ? 'preview' : 'disabled',
      persisted: false,
      dry_run: true,
      vector_count: vectors.length,
      namespace: env.namespace,
      warnings: ['Pinecone source sync was not called. Pass --live with configured Pinecone env for explicit network write.']
    });
  }
  const raw = await pc.request('/vectors/upsert', request);
  return advisoryEnvelope('pinecone', 'pinecone-rest', 'sync-sources', {
    status: 'ok',
    persisted: true,
    network_calls: 'explicit_live_call',
    vector_count: vectors.length,
    raw
  });
}

async function recall(flags, positional) {
  const query = String(positional.slice(1).join(' ') || flags.query || '').trim();
  if (!query) throw new Error('recall/search requires query');
  const env = pc.env();
  const request = {
    namespace: env.namespace,
    topK: Number(flags.topK || flags.top || 5),
    sparseVector: pc.sparse(query),
    includeMetadata: true,
    source_of_truth: false
  };
  if (!liveAllowed(flags) || !env.configured) {
    return advisoryEnvelope('pinecone', 'pinecone-rest', 'recall', {
      status: env.configured ? 'preview' : 'disabled',
      query,
      dry_run: true,
      request,
      last_retrieval_count: 0,
      results: [],
      warnings: ['Pinecone query was not called. Pass --live with configured Pinecone env for explicit network search.']
    });
  }
  const raw = await pc.request('/query', request);
  return advisoryEnvelope('pinecone', 'pinecone-rest', 'recall', {
    status: 'ok',
    query,
    network_calls: 'explicit_live_call',
    raw
  });
}

function exportRedacted() {
  return advisoryEnvelope('pinecone', 'pinecone-rest', 'export-redacted', {
    status: 'ok',
    content_included: false,
    environment: pineconeEnvSummary(),
    records: []
  });
}

function syncReport(context) {
  const report = buildExternalMemoryReport(context, { write: true });
  return advisoryEnvelope('pinecone', 'pinecone-rest', 'sync-report', {
    status: 'ok',
    report: {
      maintenance: 'maintenance/external_memory_status.json',
      metrics: 'metrics/external_memory.json',
      pinecone_status: report.provider_statuses?.pinecone?.status || null
    }
  });
}

async function main(argv = process.argv.slice(2)) {
  const parsed = parseCliArgs(argv);
  const flags = parsed.flags;
  const command = parsed.positional[0] || 'health';
  const context = resolveKnowledgeContext(flags);
  let result;
  if (command === 'health' || command === 'status') result = pineconeHealth(flags);
  else if (command === 'add' || command === 'remember' || command === 'upsert') result = await remember(flags, parsed.positional);
  else if (command === 'sync-sources') result = await syncSources(flags);
  else if (command === 'search' || command === 'recall' || command === 'query') result = await recall(flags, parsed.positional);
  else if (command === 'export-redacted') result = exportRedacted(flags);
  else if (command === 'sync-report') result = syncReport(context);
  else throw new Error(`Unknown Pinecone memory command: ${command}`);
  result = assertAdvisory(result);
  console.log(JSON.stringify(result, null, 2));
  return result;
}

if (require.main === module) {
  main().catch((error) => {
    const result = advisoryEnvelope('pinecone', 'pinecone-rest', 'error', { status: 'error', error: error.message });
    console.log(JSON.stringify(result, null, 2));
    process.exit(1);
  });
}

module.exports = main;
