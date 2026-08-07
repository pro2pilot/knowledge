'use strict';

const ROOT_KINDS = Object.freeze({
  state: Object.freeze({ public: true, description: 'Resolved writable .knowledge state root or explicit team state root.' }),
  project: Object.freeze({ public: true, description: 'Resolved project knowledge root.' }),
  system: Object.freeze({ public: false, description: 'Maintainer-only installed system root.' }),
});

const LOCKS = Object.freeze({
  'agent-integrations': Object.freeze({ root_kinds: ['state'], purpose: 'Install agent integrations transactionally.', consumers: ['install-agent-integrations'] }),
  'apply-template': Object.freeze({ root_kinds: ['project'], purpose: 'Apply or remove project templates.', consumers: ['apply-template'] }),
  'doctor': Object.freeze({ root_kinds: ['state'], purpose: 'Refresh Doctor health artifacts.', consumers: ['doctor'] }),
  'evidence-publication': Object.freeze({ root_kinds: ['system'], purpose: 'Publish maintainer release evidence atomically.', consumers: [] }),
  'external-memory-status': Object.freeze({ root_kinds: ['state'], purpose: 'Refresh external memory status.', consumers: ['external-memory-status'] }),
  'field-report': Object.freeze({ root_kinds: ['state'], purpose: 'Mutate Field Report state.', consumers: ['field-report'] }),
  'git-hooks': Object.freeze({ root_kinds: ['project'], purpose: 'Install project Git hooks.', consumers: ['install-git-hooks'] }),
  'ingest': Object.freeze({ root_kinds: ['project'], purpose: 'Ingest project knowledge artifacts.', consumers: ['ingest-existing-project'] }),
  'memory-provider': Object.freeze({ root_kinds: ['state'], purpose: 'Serialize mutable memory provider operations.', consumers: ['memory-mem0', 'memory-pinecone', 'memory-provider'] }),
  'recertify': Object.freeze({ root_kinds: ['state'], purpose: 'Recertify knowledge artifacts.', consumers: ['recertify'] }),
  'repair-on-touch': Object.freeze({ root_kinds: ['state'], purpose: 'Mutate Repair-on-touch state.', consumers: ['repair-on-touch'] }),
  'routing-bundle': Object.freeze({ root_kinds: ['state'], purpose: 'Build the routing bundle.', consumers: ['build-routing-bundle'] }),
  'search-index': Object.freeze({ root_kinds: ['state'], purpose: 'Build the compact search index.', consumers: ['build-search-index'] }),
  'secret-scan': Object.freeze({ root_kinds: ['state'], purpose: 'Refresh secret scan artifacts.', consumers: ['scan-secrets'] }),
  'sync': Object.freeze({ root_kinds: ['state'], purpose: 'Synchronize tracked knowledge state.', consumers: ['sync-tracked'] }),
  'task-routing': Object.freeze({
    root_kinds: ['state'],
    purpose: 'Mutate task routing snapshots and indexes.',
    resource_id: 'task_hash_or_index',
    consumers: ['task-routing']
  }),
  'team-flow': Object.freeze({ root_kinds: ['state'], purpose: 'Serialize exclusive team flow operations.', consumers: ['team-store'] }),
  'visual-inspector': Object.freeze({ root_kinds: ['state'], purpose: 'Build Visual Inspector data and pages.', consumers: ['build-visual-inspector'] }),
  'watch-maintenance': Object.freeze({ root_kinds: ['state'], purpose: 'Update maintenance watcher state.', consumers: ['watch-maintenance'] }),
  'wiki-graph': Object.freeze({ root_kinds: ['state'], purpose: 'Build the typed wiki graph.', consumers: ['build-wiki-graph'] }),
  'wiki-lint': Object.freeze({ root_kinds: ['state'], purpose: 'Lint wiki structure and evidence.', consumers: ['lint-wiki'] }),
});

const LOCK_POLICY = Object.freeze({
  schema_version: 'knowledge-lock-policy.v1',
  layout_version: 1,
  owner_schema_version: 'knowledge-lock-owner.v1',
  owner_max_bytes: 4096,
  owner_initialization_grace_ms: 2000,
  default_timeout_ms: 30000,
  default_stale_ms: 120000,
  default_retry_ms: 100,
  min_timeout_ms: 1,
  max_timeout_ms: 600000,
  min_stale_ms: 1,
  max_stale_ms: 604800000,
  remote_stale_ms: 86400000,
  hardlinks: 'reject',
  root_kinds: ROOT_KINDS,
  locks: LOCKS,
  timeout_owner_fields: Object.freeze(['pid', 'hostname', 'agent_id', 'acquired_at']),
});

function policyError(code, message) {
  const error = new Error(message);
  error.code = code;
  return error;
}

function lockDefinition(lockName, rootKind, purpose, options = {}) {
  if (typeof lockName !== 'string' || !/^[a-z][a-z0-9-]{0,62}$/.test(lockName)) {
    throw policyError('lock_name_invalid', 'Lock name must be a canonical allowlisted identifier.');
  }
  const definition = LOCK_POLICY.locks[lockName];
  if (!definition) throw policyError('unknown_lock_name', `Lock name "${lockName}" is not allowlisted.`);
  const root = LOCK_POLICY.root_kinds[rootKind];
  if (!root) throw policyError('unknown_lock_root_kind', `Lock root kind "${String(rootKind)}" is not allowlisted.`);
  if (!root.public && options.maintainer !== true) {
    throw policyError('lock_root_kind_forbidden', `Lock root kind "${rootKind}" is maintainer-only.`);
  }
  if (!definition.root_kinds.includes(rootKind)) {
    throw policyError('lock_root_kind_forbidden', `Lock "${lockName}" cannot use root kind "${rootKind}".`);
  }
  if (purpose !== definition.purpose) {
    throw policyError('lock_purpose_mismatch', `Lock "${lockName}" purpose does not match the policy registry.`);
  }
  return definition;
}

module.exports = {
  LOCK_POLICY,
  ROOT_KINDS,
  LOCKS,
  lockDefinition,
};
