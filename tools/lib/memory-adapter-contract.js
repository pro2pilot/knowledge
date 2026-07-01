'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const SCHEMA_VERSION = '3.2.6';
const TRUST_POLICY = Object.freeze({
  source_of_truth: false,
  trust_effect: 'advisory_only',
  can_raise_trust: false,
  can_overwrite_curated_knowledge: false,
  can_execute_actions: false
});

function nowIso() {
  return new Date().toISOString();
}

function sha(value) {
  return crypto.createHash('sha256').update(String(value || '')).digest('hex');
}

function ensureDir(dirPath) {
  fs.mkdirSync(dirPath, { recursive: true });
}

function readJsonl(filePath) {
  if (!fs.existsSync(filePath)) return [];
  return fs.readFileSync(filePath, 'utf8').split(/\r?\n/).filter(Boolean).map((line) => {
    try { return JSON.parse(line); } catch { return null; }
  }).filter(Boolean);
}

function writeJsonl(filePath, records) {
  ensureDir(path.dirname(filePath));
  fs.writeFileSync(filePath, records.map((record) => JSON.stringify(record)).join('\n') + (records.length ? '\n' : ''), 'utf8');
}

function redactSecrets(value) {
  if (value === null || value === undefined) return value;
  if (Array.isArray(value)) return value.map(redactSecrets);
  if (typeof value === 'object') {
    const out = {};
    for (const [key, item] of Object.entries(value)) {
      if (
        key !== 'secrets_redacted' &&
        !/required$/i.test(key) &&
        /(api[_-]?key|access[_-]?token|auth[_-]?token|secret|password|authorization|bearer)/i.test(key)
      ) out[key] = '<redacted>';
      else out[key] = redactSecrets(item);
    }
    return out;
  }
  if (typeof value !== 'string') return value;
  return value
    .replace(/\bpcsk_[A-Za-z0-9_-]{8,}\b/g, '<redacted-pinecone-key>')
    .replace(/\b(?:sk|pk|rk)-[A-Za-z0-9_-]{16,}\b/g, '<redacted-key>')
    .replace(/Bearer\s+[A-Za-z0-9._-]+/gi, 'Bearer <redacted>');
}

function advisoryEnvelope(providerId, adapterId, operation, payload = {}) {
  return redactSecrets({
    schema_version: SCHEMA_VERSION,
    generated_at: nowIso(),
    provider_id: providerId,
    adapter_id: adapterId,
    operation,
    source_of_truth: false,
    trust_effect: 'advisory_only',
    trust_policy: TRUST_POLICY,
    network_calls: 'not_run',
    secrets_redacted: true,
    ...payload
  });
}

function normalizeMetadata(metadata = {}) {
  const safe = {};
  const warnings = [];
  let overrideAttempt = false;
  for (const [key, value] of Object.entries(metadata || {})) {
    if (key === 'source_of_truth' && value !== false) {
      warnings.push('Blocked metadata source_of_truth override attempt.');
      overrideAttempt = true;
      safe.source_of_truth = false;
      continue;
    }
    if (key === 'trust_effect' && value !== 'advisory_only') {
      warnings.push('Blocked metadata trust_effect override attempt.');
      overrideAttempt = true;
      safe.trust_effect = 'advisory_only';
      continue;
    }
    if (/^(can_raise_trust|can_overwrite_curated_knowledge|trusted)$/i.test(key)) {
      warnings.push(`Blocked metadata trust-control field: ${key}.`);
      overrideAttempt = true;
      continue;
    }
    safe[key] = value;
  }
  safe.source_of_truth = false;
  safe.trust_effect = 'advisory_only';
  return { metadata: safe, warnings, overrideAttempt };
}

function memoryRecord(providerId, text, options = {}) {
  const normalized = normalizeMetadata(options.metadata || {});
  const createdAt = options.created_at || nowIso();
  const id = options.id || `${providerId}-${sha(`${createdAt}:${text}`).slice(0, 16)}`;
  return {
    id,
    provider_id: providerId,
    scope: options.scope || 'repo',
    user_id: options.user_id || null,
    created_at: createdAt,
    updated_at: options.updated_at || null,
    text: String(text || ''),
    text_sha256: sha(text),
    metadata: normalized.metadata,
    source_of_truth: false,
    trust_effect: 'advisory_only',
    override_attempt: Boolean(normalized.overrideAttempt || options.override_attempt),
    policy_warnings: normalized.warnings
  };
}

function publicRecord(record, includeText = false) {
  return {
    id: record.id,
    provider_id: record.provider_id,
    scope: record.scope,
    user_id: record.user_id || null,
    created_at: record.created_at,
    updated_at: record.updated_at || null,
    text_sha256: record.text_sha256 || sha(record.text),
    text: includeText ? record.text : undefined,
    metadata: redactSecrets(record.metadata || {}),
    source_of_truth: false,
    trust_effect: 'advisory_only',
    override_attempt: Boolean(record.override_attempt)
  };
}

function visibleRecords(filePath) {
  return readJsonl(filePath).filter((record) => !record.deleted_at);
}

function jsonlAdapter(providerId, adapterId, filePath) {
  return {
    providerId,
    adapterId,
    filePath,
    health() {
      const records = visibleRecords(filePath);
      return advisoryEnvelope(providerId, adapterId, 'health', {
        status: 'ok',
        runtime_health: 'ok',
        records_count: records.length,
        data_path: path.dirname(filePath)
      });
    },
    remember(input = {}) {
      const text = String(input.text || '').trim();
      if (!text) throw new Error('remember requires text');
      const records = readJsonl(filePath);
      const record = memoryRecord(providerId, text, {
        scope: input.scope,
        user_id: input.user_id,
        metadata: input.metadata,
        override_attempt: input.override_attempt
      });
      records.push(record);
      writeJsonl(filePath, records);
      return advisoryEnvelope(providerId, adapterId, 'remember', {
        status: 'ok',
        persisted: true,
        record: publicRecord(record, false),
        warnings: record.policy_warnings
      });
    },
    recall(input = {}) {
      const query = String(input.query || '').trim();
      if (!query) throw new Error('recall requires query');
      const q = query.toLowerCase();
      const results = visibleRecords(filePath)
        .filter((record) => String(record.text || '').toLowerCase().includes(q))
        .map((record) => ({ ...publicRecord(record, Boolean(input.include_text)), score: 1 }));
      return advisoryEnvelope(providerId, adapterId, 'recall', {
        status: 'ok',
        query,
        last_retrieval_count: results.length,
        results
      });
    },
    list(input = {}) {
      const records = visibleRecords(filePath).map((record) => publicRecord(record, Boolean(input.include_text)));
      return advisoryEnvelope(providerId, adapterId, 'list', { status: 'ok', records_count: records.length, records });
    },
    forget(input = {}) {
      const id = String(input.id || '').trim();
      if (!id) throw new Error('forget requires id');
      const records = readJsonl(filePath);
      let deleted = false;
      const updated = records.map((record) => {
        if (record.id === id && !record.deleted_at) {
          deleted = true;
          return { ...record, deleted_at: nowIso() };
        }
        return record;
      });
      writeJsonl(filePath, updated);
      return advisoryEnvelope(providerId, adapterId, 'forget', { status: 'ok', deleted, id });
    },
    exportRedacted() {
      const records = visibleRecords(filePath).map((record) => publicRecord(record, false));
      return advisoryEnvelope(providerId, adapterId, 'export-redacted', {
        status: 'ok',
        content_included: false,
        records_count: records.length,
        records
      });
    }
  };
}

function dryRunAdapter(providerId, adapterId, status = 'runtime_not_installed') {
  return {
    providerId,
    adapterId,
    health() {
      return advisoryEnvelope(providerId, adapterId, 'health', {
        status,
        runtime_health: 'not_available',
        live_runtime_checked: false,
        warnings: ['Dry-run adapter did not import provider runtime, call network, or write memory data.']
      });
    },
    remember(input = {}) {
      const record = memoryRecord(providerId, input.text || '', {
        scope: input.scope,
        user_id: input.user_id,
        metadata: input.metadata,
        override_attempt: input.override_attempt
      });
      return advisoryEnvelope(providerId, adapterId, 'remember', {
        status,
        persisted: false,
        dry_run: true,
        would_remember: publicRecord(record, false),
        warnings: ['Dry-run adapter did not write memory data.', ...record.policy_warnings]
      });
    },
    recall(input = {}) {
      return advisoryEnvelope(providerId, adapterId, 'recall', {
        status,
        query: input.query || '',
        last_retrieval_count: 0,
        results: [],
        warnings: ['Dry-run adapter did not query memory data.']
      });
    },
    list() {
      return advisoryEnvelope(providerId, adapterId, 'list', {
        status,
        records_count: 0,
        records: []
      });
    },
    forget(input = {}) {
      return advisoryEnvelope(providerId, adapterId, 'forget', {
        status,
        deleted: false,
        dry_run: true,
        id: input.id || null
      });
    },
    exportRedacted() {
      return advisoryEnvelope(providerId, adapterId, 'export-redacted', {
        status,
        content_included: false,
        records_count: 0,
        records: []
      });
    }
  };
}

function assertAdvisory(result) {
  if (!result || result.source_of_truth !== false || result.trust_effect !== 'advisory_only') {
    throw new Error('Memory adapter result violated advisory-only trust contract.');
  }
  return result;
}

module.exports = {
  SCHEMA_VERSION,
  TRUST_POLICY,
  nowIso,
  sha,
  readJsonl,
  writeJsonl,
  redactSecrets,
  advisoryEnvelope,
  normalizeMetadata,
  memoryRecord,
  publicRecord,
  visibleRecords,
  jsonlAdapter,
  dryRunAdapter,
  assertAdvisory
};
