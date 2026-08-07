'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const { spawnSync } = require('child_process');
const {
  ensureDir,
  readJson,
  writeJsonAtomic,
  writeFileAtomic,
  getAgentId
} = require('./json-store');
const {
  collectPythonCandidates,
  discoverPython,
  packageInstallCommand,
  validatePythonCandidate
} = require('./python-discovery');

const LEGACY_DEPRECATION_TEXT = `# Deprecated Claude MEM state

Claude MEM first-class bridge has been removed.
Use Mem0 OSS as the recommended universal optional memory provider.
Existing Claude MEM artifacts are treated as legacy advisory context only and are never used to raise trust.
`;
const FASTEMBED_VERSION_PIN = 'fastembed==0.5.1';
const DEFAULT_OPENAI_EMBEDDING_MODEL = 'text-embedding-3-small';
const DEFAULT_OPENAI_EMBEDDING_DIMS = 1536;
const DEFAULT_OPENAI_LLM_MODEL = 'gpt-5-mini';
const OPENAI_EMBEDDING_MODELS = {
  'text-embedding-3-small': { dimensions: 1536 },
  'text-embedding-3-large': { dimensions: 3072 },
  'text-embedding-ada-002': { dimensions: 1536 }
};
const FASTEMBED_MODEL_CHOICES = {
  'small-en-fast': {
    model: 'BAAI/bge-small-en-v1.5',
    dimensions: 384,
    size_gb: 0.067,
    when_to_choose: 'Fast default for English/code.'
  },
  'mini-en-fast': {
    model: 'sentence-transformers/all-MiniLM-L6-v2',
    dimensions: 384,
    size_gb: 0.09,
    when_to_choose: 'Very light model for simple tasks.'
  },
  'base-en-balanced': {
    model: 'BAAI/bge-base-en-v1.5',
    dimensions: 768,
    size_gb: 0.21,
    when_to_choose: 'Better English/code quality, heavier than small.'
  },
  'multilingual-small': {
    model: 'sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2',
    dimensions: 384,
    size_gb: 0.22,
    when_to_choose: 'Light RU/EN and multilingual notes.'
  },
  'multilingual-large': {
    model: 'intfloat/multilingual-e5-large',
    dimensions: 1024,
    size_gb: 2.24,
    when_to_choose: 'Better multilingual quality, much heavier.'
  }
};

function nowIso() {
  return new Date().toISOString();
}

function normalizeProviderId(id) {
  const value = String(id || '').trim().toLowerCase();
  if (['mem0', 'mem0ai', 'mem0-oss'].includes(value)) return 'mem0-oss';
  if (['pinecone', 'pinecone-vector'].includes(value)) return 'pinecone';
  return value;
}

function safeReadJson(filePath, fallback) {
  try { return readJson(filePath, fallback); }
  catch { return fallback; }
}

function under(child, parent) {
  const rel = path.relative(parent, child);
  return rel && !rel.startsWith('..') && !path.isAbsolute(rel);
}

function displayPath(context, filePath) {
  const relState = path.relative(context.stateRoot, filePath).replace(/\\/g, '/');
  if (relState && !relState.startsWith('..') && !path.isAbsolute(relState)) {
    return context.mode === 'repo' ? `.knowledge/${relState}` : filePath;
  }
  const relProject = path.relative(context.projectKnowledgeRoot, filePath).replace(/\\/g, '/');
  if (relProject && !relProject.startsWith('..') && !path.isAbsolute(relProject)) return `.knowledge/${relProject}`;
  return filePath;
}

function readManifest(filePath, layer = 'free_core') {
  const manifest = readJson(filePath, null);
  if (!manifest || typeof manifest !== 'object') throw new Error(`Invalid memory provider manifest: ${filePath}`);
  return {
    ...manifest,
    id: normalizeProviderId(manifest.id),
    layer,
    manifest_path: filePath
  };
}

function loadProviderManifests(context, options = {}) {
  const dir = path.join(context.projectKnowledgeRoot, 'memory-providers');
  const manifests = [];
  if (fs.existsSync(dir)) {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      if (!entry.isDirectory()) continue;
      const filePath = path.join(dir, entry.name, 'manifest.json');
      if (!fs.existsSync(filePath)) continue;
      manifests.push(readManifest(filePath, 'free_core'));
    }
  }

  const extensionRoot = options.extensionRoot || process.env.KNOWLEDGE_OPTIONAL_PROVIDER_ROOT || null;
  if (extensionRoot) {
    const extensionDir = path.join(path.resolve(extensionRoot), 'memory-providers');
    if (fs.existsSync(extensionDir)) {
      for (const entry of fs.readdirSync(extensionDir, { withFileTypes: true })) {
        if (!entry.isDirectory()) continue;
        const filePath = path.join(extensionDir, entry.name, 'manifest.json');
        if (!fs.existsSync(filePath)) continue;
        manifests.push(readManifest(filePath, 'optional_extension'));
      }
    }
  }

  return manifests.sort((a, b) => String(a.id).localeCompare(String(b.id)));
}

function findManifest(context, providerId, options = {}) {
  const id = normalizeProviderId(providerId);
  const manifest = loadProviderManifests(context, options).find((item) => item.id === id);
  if (!manifest) throw new Error(`Unknown memory provider: ${providerId}`);
  return manifest;
}

function providerStateDir(context, manifest) {
  const dirName = manifest.data?.state_dir_name || manifest.state_dir_name || manifest.id;
  return path.join(context.stateRoot, 'external_memory', dirName);
}

function defaultUserDataRoot() {
  const home = os.homedir();
  if (process.platform === 'win32') {
    return process.env.LOCALAPPDATA || process.env.APPDATA || path.join(home, 'AppData', 'Local');
  }
  if (process.platform === 'darwin') {
    return path.join(home, 'Library', 'Application Support');
  }
  return process.env.XDG_DATA_HOME || path.join(home, '.local', 'share');
}

function defaultSharedMem0Root(flags = {}) {
  const explicit = flags.sharedProviderRoot ||
    flags.providerRoot ||
    process.env.KNOWLEDGE_MEM0_SHARED_ROOT ||
    process.env.KNOWLEDGE_MEM0_PROVIDER_ROOT;
  if (explicit) return path.resolve(String(explicit));
  return path.join(defaultUserDataRoot(), 'pro2pilot', 'knowledge', 'memory-providers', 'mem0');
}

function projectStorageKey(context) {
  const name = slugPart(path.basename(context.targetRoot || 'repo')).slice(0, 40) || 'repo';
  const hash = crypto.createHash('sha256').update(String(context.repoId || context.targetRoot || name)).digest('hex').slice(0, 12);
  return `${name}-${hash}`;
}

function inferMem0ProviderScope(context, qdrantPath, sharedRoot) {
  if (!qdrantPath) return null;
  const normalized = path.resolve(qdrantPath);
  const projectDir = providerStateDir(context, findManifest(context, 'mem0-oss'));
  if (under(normalized, projectDir) || normalized === projectDir) return 'project';
  if (under(normalized, sharedRoot) || normalized === sharedRoot) return 'shared';
  return 'custom';
}

function requestedProviderScope(flags = {}) {
  const raw = String(flags.providerScope || flags.mem0ProviderScope || '').trim().toLowerCase();
  if (!raw && !flags.projectLocal && !flags.localProvider) return null;
  if (flags.projectLocal || flags.localProvider || ['project', 'project-local', 'repo', 'repo-local', 'local'].includes(raw)) return 'project';
  if (['shared', 'user', 'global', 'default'].includes(raw)) return 'shared';
  throw new Error('--provider-scope must be shared or project');
}

function mem0StoragePlan(context, manifest, flags = {}, existingConfig = null) {
  const projectDir = providerStateDir(context, manifest);
  const sharedRoot = defaultSharedMem0Root(flags);
  const existingMeta = safeReadJson(mem0ConfigMetaPath(context, manifest), null);
  const existingSharedRoot = existingMeta?.shared_provider_root || sharedRoot;
  const requested = requestedProviderScope(flags);
  const existingVectorConfig = existingConfig?.vector_store?.config || {};
  const existingQdrant = existingVectorConfig.path || null;
  const existingHistory = existingConfig?.history_db_path || null;

  if (!requested && existingQdrant) {
    const pathInferred = inferMem0ProviderScope(context, existingQdrant, existingSharedRoot);
    const metaScope = existingMeta?.provider_scope || null;
    const inferred = pathInferred || metaScope;
    const existingDir = path.dirname(path.resolve(existingQdrant));
    return {
      provider_scope: inferred || 'custom',
      shared_provider_root: inferred === 'shared' ? existingSharedRoot : null,
      project_storage_key: inferred === 'shared' ? projectStorageKey(context) : null,
      data_dir: existingDir,
      qdrant_path: path.resolve(existingQdrant),
      history_db_path: existingHistory ? path.resolve(existingHistory) : path.join(existingDir, 'history.db'),
      preserved_existing_paths: true,
      metadata_provider_scope: metaScope,
      path_inferred_provider_scope: pathInferred,
      metadata_scope_mismatch: Boolean(metaScope && pathInferred && metaScope !== pathInferred)
    };
  }

  if (requested === 'project') {
    return {
      provider_scope: 'project',
      shared_provider_root: null,
      project_storage_key: null,
      data_dir: projectDir,
      qdrant_path: path.join(projectDir, 'qdrant'),
      history_db_path: path.join(projectDir, 'history.db'),
      preserved_existing_paths: false
    };
  }

  const dataDir = path.join(sharedRoot, 'projects', projectStorageKey(context));
  return {
    provider_scope: 'shared',
    shared_provider_root: sharedRoot,
    project_storage_key: projectStorageKey(context),
    data_dir: dataDir,
    qdrant_path: path.join(dataDir, 'qdrant'),
    history_db_path: path.join(dataDir, 'history.db'),
    preserved_existing_paths: false
  };
}

function receiptPath(context, manifest) {
  return path.join(providerStateDir(context, manifest), 'install_receipt.json');
}

function runtimeStatusPath(context, manifest) {
  return path.join(providerStateDir(context, manifest), 'runtime_status.json');
}

function mem0ConfigPath(context, manifest) {
  return path.join(providerStateDir(context, manifest), 'config.json');
}

function mem0ConfigMetaPath(context, manifest) {
  return path.join(providerStateDir(context, manifest), 'config.meta.json');
}

function mem0RecipeTemplatePath(context) {
  return path.join(context.projectKnowledgeRoot, 'templates', 'cookbook', '09-mem0-live-memory.md');
}

function mem0RecipePath(context) {
  return path.join(context.projectKnowledgeRoot, 'docs', 'cookbook', '09-mem0-live-memory.md');
}

function canonicalMem0Path(suffix = '') {
  const clean = String(suffix || '').replace(/^[/\\]+/, '').replace(/\\/g, '/');
  return `.knowledge/external_memory/mem0${clean ? `/${clean}` : ''}`;
}

function sharedMem0DocPath() {
  return [
    'Windows: %LOCALAPPDATA%\\pro2pilot\\knowledge\\memory-providers\\mem0',
    'macOS: ~/Library/Application Support/pro2pilot/knowledge/memory-providers/mem0',
    'Linux: ${XDG_DATA_HOME:-~/.local/share}/pro2pilot/knowledge/memory-providers/mem0'
  ].join('\n');
}

function pinnedRuntimeVersion(manifest) {
  const pin = String(manifest.source?.version_pin || '');
  const match = pin.match(/==(.+)$/);
  return match ? match[1] : (manifest.source?.version || null);
}

function versionsMatch(actual, expected) {
  if (!actual || !expected) return false;
  const clean = (value) => String(value || '').trim().replace(/^v/i, '');
  return clean(actual) === clean(expected);
}

function updateReceiptPath(context, manifest) {
  return path.join(providerStateDir(context, manifest), 'update_receipt.json');
}

function uninstallReceiptPath(context, manifest) {
  return path.join(providerStateDir(context, manifest), 'uninstall_receipt.json');
}

function pineconeMode() {
  const env = process.env;
  const requested = String(env.PINECONE_MODE || '').toLowerCase();
  if (['local', 'cloud', 'disabled'].includes(requested)) return requested;
  const host = env.PINECONE_HOST || env.PINECONE_INDEX_HOST || env.PINECONE_LOCAL_HOST || '';
  if (/^https?:\/\/(localhost|127\.0\.0\.1|0\.0\.0\.0)(:|\/|$)/i.test(host)) return 'local';
  if (host && env.PINECONE_API_KEY) return 'cloud';
  return 'disabled';
}

function pineconeStatus(context, manifest, registry, sources) {
  const mode = pineconeMode();
  const host = process.env.PINECONE_HOST || process.env.PINECONE_INDEX_HOST || process.env.PINECONE_LOCAL_HOST || '';
  const apiKeyRequired = mode === 'cloud';
  const configured = mode !== 'disabled' && Boolean(host) && (!apiKeyRequired || Boolean(process.env.PINECONE_API_KEY));
  const warnings = [];
  if (mode === 'cloud') warnings.push('Pinecone cloud mode may make network calls only through explicit Pinecone tools, not status/report mode.');
  if (mode !== 'disabled' && !configured) warnings.push(`Pinecone ${mode} mode is missing required environment.`);
  return {
    provider_id: 'pinecone',
    provider: 'pinecone',
    provider_name: manifest.display_name || 'Pinecone',
    type: manifest.type || 'cloud',
    layer: manifest.layer,
    status: mode === 'disabled' ? 'disabled' : configured ? 'available' : 'error',
    runtime_health: configured ? 'unknown' : 'not_available',
    enabled: Boolean(registry.providers?.pinecone?.enabled || sources.enabled),
    installed: false,
    configured,
    detected: configured,
    mode,
    scope: 'repo',
    data_path: host || null,
    path: host || null,
    api_key_required: apiKeyRequired,
    index: sources.index || process.env.PINECONE_INDEX || null,
    namespace: sources.namespace || process.env.PINECONE_NAMESPACE || null,
    adapter_contract: 'knowledge.memory_adapter.v1',
    adapter_command: 'node .knowledge/tools/memory-pinecone.js health --json',
    license_spdx: manifest.license?.spdx || 'Service-TOS',
    version: manifest.source?.version || null,
    records_count: Array.isArray(sources.sources) ? sources.sources.length : 0,
    last_retrieval_count: 0,
    source_of_truth: false,
    trust_effect: 'advisory_only',
    trust_role: 'advisory_only',
    warnings,
    errors: mode !== 'disabled' && !configured ? [`Missing ${apiKeyRequired ? 'PINECONE_API_KEY or ' : ''}PINECONE_HOST`] : []
  };
}

function genericProviderStatus(context, manifest, options = {}) {
  const dir = providerStateDir(context, manifest);
  const receipt = safeReadJson(receiptPath(context, manifest), null);
  const runtimeStatus = manifest.id === 'mem0-oss' ? safeReadJson(runtimeStatusPath(context, manifest), null) : null;
  const storageDiagnostic = manifest.id === 'mem0-oss' && ['qdrant_lock_busy', 'qdrant_path_permission_denied'].includes(runtimeStatus?.diagnostic_code);
  const liveRuntimeOk = Boolean(
    runtimeStatus
    && (
      runtimeStatus.runtime_available === true
      || (storageDiagnostic && Boolean(runtimeStatus.version || runtimeStatus.selected_python))
      || (
        runtimeStatus.diagnostic_code === 'mem0_available'
        && ['available', 'ok'].includes(String(runtimeStatus.status || '').toLowerCase())
      )
    )
  );
  const receiptPresent = Boolean(receipt);
  const installExecuted = receipt?.install_executed === true;
  const packageInstalled = Boolean(installExecuted || liveRuntimeOk);
  const runtimeVersion = manifest.id === 'mem0-oss' ? runtimeStatus?.version || null : null;
  const expectedRuntimeVersion = manifest.id === 'mem0-oss' ? runtimeStatus?.expected_version || pinnedRuntimeVersion(manifest) : null;
  const runtimeVersionMatchesPin = manifest.id === 'mem0-oss'
    ? (runtimeVersion && expectedRuntimeVersion ? versionsMatch(runtimeVersion, expectedRuntimeVersion) : null)
    : null;
  const mem0Adapter = manifest.id === 'mem0-oss' ? readMem0AdapterSummary(dir) : null;
  const status = liveRuntimeOk
    ? (storageDiagnostic ? 'storage_unavailable' : 'available')
    : installExecuted
    ? (receipt.enabled === false ? 'disabled' : 'installed')
    : (manifest.id === 'mem0-oss' ? 'runtime_not_installed' : 'available');
  const warnings = [];
  if (receipt && receipt.install_executed !== true) {
    warnings.push(liveRuntimeOk
      ? 'Install approval receipt exists; live Mem0 runtime was detected by an explicit adapter check.'
      : 'Install approval receipt exists, but .knowledge did not execute the package install.');
  }
  if (liveRuntimeOk) warnings.push('Live Mem0 status is cached from an explicit adapter command; status/report mode still makes no live provider calls.');
  if (manifest.id === 'mem0-oss') warnings.push('Mem0 runtime is optional; status/report mode does not import Python packages or run network installs.');
  if (manifest.install?.requires_network) warnings.push('Install/update requires explicit user action and may use network outside status/report mode.');
  if (manifest.type === 'optional') warnings.push('Provider implementation is optional and is not bundled into free core.');
  const mem0Config = manifest.id === 'mem0-oss' ? readMem0ConfigSummary(context, manifest, options) : null;
  if (manifest.id === 'mem0-oss' && mem0Config?.metadata_scope_mismatch) {
    warnings.push(`Mem0 config metadata says provider_scope=${mem0Config.metadata_provider_scope}, but the configured Qdrant path is ${mem0Config.path_inferred_provider_scope}. Status follows the actual storage path; rerun configure-embeddings with --provider-scope shared or --provider-scope project to make the choice explicit.`);
  }
  if (manifest.id === 'mem0-oss' && mem0Config?.provider_scope === 'project') {
    warnings.push('Mem0 project-local storage is active. Shared user storage remains the default; project-local storage should be an explicit user choice.');
  }
  const mem0Configured = Boolean(manifest.id === 'mem0-oss' && fs.existsSync(mem0ConfigPath(context, manifest)));
  return {
    provider_id: manifest.id,
    provider: manifest.id,
    provider_name: manifest.display_name || manifest.id,
    type: manifest.type || 'local',
    layer: manifest.layer,
    status,
    runtime_health: storageDiagnostic ? 'storage_unavailable' : (liveRuntimeOk ? 'ok' : (installExecuted ? 'unknown' : (manifest.id === 'mem0-oss' ? 'not_available' : 'unknown'))),
    enabled: Boolean(liveRuntimeOk || (receipt?.enabled && installExecuted)),
    installed: packageInstalled,
    receipt_present: receiptPresent,
    runtime_available: liveRuntimeOk,
    package_installed: packageInstalled,
    configured: manifest.id === 'mem0-oss' ? mem0Configured : receiptPresent,
    detected: fs.existsSync(dir),
    mode: manifest.install?.mode || 'manual',
    scope: mem0Config?.provider_scope || manifest.data?.scope || 'repo',
    provider_scope: mem0Config?.provider_scope || null,
    shared_provider_root: mem0Config?.shared_provider_root || null,
    project_storage_key: mem0Config?.project_storage_key || null,
    metadata_provider_scope: mem0Config?.metadata_provider_scope || null,
    path_inferred_provider_scope: mem0Config?.path_inferred_provider_scope || null,
    metadata_scope_mismatch: mem0Config?.metadata_scope_mismatch || false,
    stale_shared_provider_root: mem0Config?.stale_shared_provider_root || null,
    stale_shared_qdrant_path: mem0Config?.stale_shared_qdrant_path || null,
    stale_shared_lock_path: mem0Config?.stale_shared_lock_path || null,
    data_path: dir,
    path: dir,
    license_spdx: manifest.license?.spdx || 'unknown',
    version: receipt?.version || manifest.source?.version_pin || manifest.source?.version || null,
    version_pin: manifest.source?.version_pin || null,
    source_url: manifest.source?.homepage || manifest.source?.repository || manifest.source?.package || null,
    adapter_contract: manifest.id === 'mem0-oss' ? 'knowledge.memory_adapter.v1' : null,
    adapter_command: manifest.id === 'mem0-oss' ? 'node .knowledge/tools/memory-mem0.js health --json' : null,
    setup_command: manifest.id === 'mem0-oss' ? 'node .knowledge/tools/memory-provider.js setup mem0-oss --live --json' : null,
    live_health_command: manifest.id === 'mem0-oss' ? 'node .knowledge/tools/memory-mem0.js health --adapter live --json' : null,
    live_add_command: manifest.id === 'mem0-oss' ? 'node .knowledge/tools/memory-mem0.js add --adapter live --yes-live-memory --text "Release note: Mem0 is advisory-only external memory" --scope repo --json' : null,
    live_search_command: manifest.id === 'mem0-oss' ? 'node .knowledge/tools/memory-mem0.js search "advisory memory" --adapter live --yes-live-memory --json' : null,
    live_recall_command: manifest.id === 'mem0-oss' ? 'node .knowledge/tools/memory-mem0.js recall "advisory memory" --adapter live --yes-live-memory --json' : null,
    live_list_command: manifest.id === 'mem0-oss' ? 'node .knowledge/tools/memory-mem0.js list --adapter live --yes-live-memory --json' : null,
    llm_provider: mem0Config?.llm_provider || null,
    llm_model: mem0Config?.llm_model || null,
    embedding_provider: mem0Config?.embedding_provider || null,
    embedding_model: mem0Config?.embedding_model || null,
    embedding_dimensions: mem0Config?.embedding_dimensions || null,
    vector_store_provider: mem0Config?.vector_store_provider || null,
    vector_collection_name: mem0Config?.vector_collection_name || null,
    qdrant_path: mem0Config?.qdrant_path || null,
    history_store_provider: mem0Config?.history_store_provider || null,
    history_db_path: mem0Config?.history_db_path || null,
    install_receipt_path: manifest.id === 'mem0-oss' ? displayPath(context, receiptPath(context, manifest)) : null,
    runtime_status_path: manifest.id === 'mem0-oss' ? displayPath(context, runtimeStatusPath(context, manifest)) : null,
    config_path: manifest.id === 'mem0-oss' && fs.existsSync(mem0ConfigPath(context, manifest)) ? displayPath(context, mem0ConfigPath(context, manifest)) : null,
    runtime_status_checked_at: runtimeStatus?.checked_at || null,
    last_live_health_check: runtimeStatus?.last_live_health_check || (runtimeStatus?.operation === 'health' ? runtimeStatus?.checked_at || null : null),
    diagnostic_code: runtimeStatus?.diagnostic_code || null,
    runtime_version: runtimeVersion,
    expected_runtime_version: expectedRuntimeVersion,
    runtime_version_matches_pin: runtimeVersionMatchesPin,
    selected_python: mem0Config?.selected_python || runtimeStatus?.selected_python || null,
    python_runtime: mem0Config?.python_runtime || null,
    live_operations_require_explicit_consent: manifest.id === 'mem0-oss',
    records_count: runtimeStatus?.records_count ?? mem0Adapter?.records_count ?? 0,
    last_retrieval_count: runtimeStatus?.last_retrieval_count ?? mem0Adapter?.last_retrieval_count ?? 0,
    last_retrieval_query: runtimeStatus?.last_retrieval_query || null,
    adapter_records_count: mem0Adapter?.records_count || 0,
    override_attempts_blocked: mem0Adapter?.override_attempts_blocked || 0,
    source_of_truth: false,
    trust_effect: 'advisory_only',
    trust_role: 'advisory_only',
    warnings,
    errors: []
  };
}

function mem0AdapterFile(dir) {
  return path.join(dir, 'adapter-records.jsonl');
}

function readJsonl(filePath) {
  if (!fs.existsSync(filePath)) return [];
  const text = fs.readFileSync(filePath, 'utf8');
  return text.split(/\r?\n/).filter(Boolean).map((line) => {
    try { return JSON.parse(line); } catch { return null; }
  }).filter(Boolean);
}

function readMem0AdapterSummary(dir) {
  const records = [
    ...readJsonl(mem0AdapterFile(dir)),
    ...readJsonl(path.join(dir, 'test-adapter-records.jsonl'))
  ].filter((record) => !record.deleted_at);
  return {
    records_count: records.length,
    last_retrieval_count: 0,
    override_attempts_blocked: records.filter((record) => record.override_attempt || record.contradicts_source || record.claims_source_override).length
  };
}

function detectLegacyClaude(context, registry = {}) {
  const candidates = [];
  const explicitPath = process.env.CLAUDE_MEMORY_PATH || registry.providers?.claude_auto_memory?.path || '';
  if (explicitPath) candidates.push({ source: 'CLAUDE_MEMORY_PATH or legacy registry', path: path.resolve(explicitPath), explicit: true });
  for (const name of ['claude_mem', 'claude', 'claude-auto-memory']) {
    candidates.push({ source: 'legacy stateRoot probe', path: path.join(context.stateRoot, 'external_memory', name), explicit: false });
  }
  const seen = new Set();
  const found = [];
  for (const candidate of candidates) {
    if (!candidate.path || seen.has(candidate.path)) continue;
    seen.add(candidate.path);
    const detected = fs.existsSync(candidate.path);
    const enabled = Boolean(registry.providers?.claude_auto_memory?.enabled || process.env.CLAUDE_MEMORY_ENABLED === '1');
    if (!detected && !(enabled && candidate.explicit)) continue;
    const warnings = ['legacy Claude MEM artifacts found; treated as advisory-only legacy data'];
    let mode = 'legacy';
    if (context.mode === 'team') {
      mode = under(candidate.path, context.stateRoot) ? 'workspace-specific-legacy' : 'shared-legacy';
      if (mode === 'shared-legacy') warnings.push('Legacy Claude memory appears shared across worktrees; keep it advisory and do not mix it into curated knowledge.');
    }
    found.push({
      provider_id: 'legacy-claude-mem',
      provider: 'legacy-claude-mem',
      provider_name: 'Legacy Claude MEM',
      type: 'legacy',
      layer: 'legacy',
      status: 'legacy',
      enabled: false,
      installed: false,
      detected,
      legacy: true,
      mode,
      scope: context.mode === 'team' ? 'workspace' : 'repo',
      data_path: detected || candidate.explicit ? candidate.path : null,
      path: detected || candidate.explicit ? candidate.path : null,
      source: candidate.source,
      license_spdx: 'unknown',
      version: 'unknown',
      source_of_truth: false,
      trust_effect: 'advisory_only',
      trust_role: 'advisory_only',
      warnings,
      errors: []
    });
  }
  return found;
}

function sourceOfTruthPolicy() {
  return {
    external_memory_source_of_truth: false,
    external_memory_can_raise_trust: false,
    external_memory_can_overwrite_curated_knowledge: false,
    external_memory_can_execute_actions: false,
    retrieved_memory_requires_code_or_evidence_verification: true
  };
}

function buildExternalMemoryReport(context, options = {}) {
  const registry = safeReadJson(path.join(context.projectKnowledgeRoot, 'external_memory', 'registry.json'), { providers: {} });
  const policy = safeReadJson(path.join(context.projectKnowledgeRoot, 'external_memory', 'retrieval_policy.json'), {});
  const sources = safeReadJson(path.join(context.projectKnowledgeRoot, 'external_memory', 'pinecone_sources.json'), { sources: [] });
  const manifests = loadProviderManifests(context, options).filter((manifest) => manifest.layer === 'free_core');
  const providers = manifests.map((manifest) => (
    manifest.id === 'pinecone'
      ? pineconeStatus(context, manifest, registry, sources)
      : genericProviderStatus(context, manifest, options)
  ));
  const providerOverrideAttempts = providers.reduce((sum, provider) => sum + Number(provider.override_attempts_blocked || 0), 0);
  const legacy = detectLegacyClaude(context, registry);
  const warnings = Array.from(new Set([
    ...providers.flatMap((provider) => provider.warnings || []),
    ...legacy.flatMap((provider) => provider.warnings || [])
  ]));
  const providerStatuses = Object.fromEntries(providers.map((provider) => [provider.provider_id.replace(/-/g, '_'), provider]));
  const metrics = {
    schema_version: '3.3.0',
    generated_at: nowIso(),
    generated_by: getAgentId(),
    mode: context.mode,
    provider_count: providers.length,
    enabled_provider_count: providers.filter((provider) => provider.enabled).length,
    legacy_provider_count: legacy.length,
    external_memory_records_count: providers.reduce((sum, provider) => sum + Number(provider.records_count || 0), 0),
    last_retrieval_count: providers.reduce((sum, provider) => sum + Number(provider.last_retrieval_count || 0), 0),
    external_memory_override_count: 0,
    override_attempts_blocked: providerOverrideAttempts,
    unknown_license_count: providers.filter((provider) => !provider.license_spdx || provider.license_spdx === 'unknown').length
  };
  const report = {
    schema_version: '3.3.0',
    generated_at: nowIso(),
    generated_by: getAgentId(),
    mode: context.mode,
    target_root: context.targetRoot,
    project_knowledge_root: context.projectKnowledgeRoot,
    state_root: context.stateRoot,
    recommended_provider: 'mem0-oss',
    policy: {
      local_first: policy.local_first !== false,
      source_of_truth: false,
      max_external_chunks: policy.max_external_chunks || 5
    },
    source_of_truth_policy: sourceOfTruthPolicy(),
    providers,
    provider_statuses: providerStatuses,
    legacy_providers_detected: legacy,
    sources: {
      configured_sources: Array.isArray(sources.sources) ? sources.sources.length : 0,
      namespace: sources.namespace || process.env.PINECONE_NAMESPACE || null,
      index: sources.index || process.env.PINECONE_INDEX || null
    },
    live_checks: {
      status_report_mode: 'offline',
      network_calls: 'not_run',
      adapter_live_calls_require_explicit_command: true
    },
    warnings,
    metrics
  };
  if (options.write !== false) {
    ensureDir(path.join(context.stateRoot, 'maintenance'));
    ensureDir(path.join(context.stateRoot, 'metrics'));
    writeJsonAtomic(path.join(context.stateRoot, 'maintenance', 'external_memory_status.json'), report);
    writeJsonAtomic(path.join(context.stateRoot, 'metrics', 'external_memory.json'), metrics);
  }
  return report;
}

function previewProvider(context, providerId, options = {}) {
  const manifest = findManifest(context, providerId, options);
  return {
    ok: true,
    action: 'preview',
    provider_id: manifest.id,
    provider_name: manifest.display_name,
    layer: manifest.layer,
    type: manifest.type,
    recommended: Boolean(manifest.recommended),
    license: manifest.license || {},
    source: manifest.source || {},
    install: {
      mode: manifest.install?.mode || 'manual',
      commands: manifest.install?.commands || [],
      requires_network: Boolean(manifest.install?.requires_network),
      requires_user_confirmation: manifest.install?.requires_user_confirmation !== false
    },
    data: {
      data_path: providerStateDir(context, manifest),
      scope: manifest.data?.scope || 'repo',
      stores_user_data: manifest.data?.stores_user_data !== false
    },
    trust_policy: manifest.trust_policy || sourceOfTruthPolicy(),
    warnings: [
      'Preview only; no install, update, network call, or provider state write was performed.',
      'External memory is advisory and cannot raise trust.'
    ]
  };
}

function requireConfirmation(flags, action) {
  if (flags.yesIReviewedLicense || process.env.KNOWLEDGE_MEMORY_PROVIDER_TEST_MODE === '1') return;
  throw new Error(`${action} requires --yes-i-reviewed-license`);
}

function requireVersion(value, label) {
  const version = String(value || '').trim();
  if (!version) throw new Error(`${label} requires an explicit version`);
  if (!/^[A-Za-z0-9_.@/-]+==[A-Za-z0-9_.+-]+$/.test(version)) {
    throw new Error(`${label} version must be pinned, for example mem0ai==2.0.4`);
  }
  return version;
}

function recordInstall(context, providerId, flags = {}, options = {}) {
  const manifest = findManifest(context, providerId, options);
  if (manifest.layer !== 'free_core') throw new Error(`${manifest.id} is not installable from free core`);
  if ((manifest.license?.spdx || 'unknown') === 'unknown') throw new Error(`${manifest.id} install blocked: unknown license`);
  requireConfirmation(flags, 'install');
  const version = requireVersion(flags.version, 'install');
  if (manifest.source?.version_pin && version !== manifest.source.version_pin) {
    throw new Error(`${manifest.id} install requires pinned version ${manifest.source.version_pin}`);
  }
  const dir = providerStateDir(context, manifest);
  const receipt = {
    schema_version: '3.3.0',
    provider_id: manifest.id,
    recorded_at: nowIso(),
    installed_at: null,
    installed_by_command: `node .knowledge/tools/memory-provider.js install ${manifest.id} --version ${version} --yes-i-reviewed-license`,
    version,
    license_spdx: manifest.license.spdx,
    license_url: manifest.license.url,
    source_url: manifest.source?.package || manifest.source?.repository || manifest.source?.homepage || '',
    data_path: dir,
    install_mode: 'manual_receipt',
    install_executed: false,
    requires_network: Boolean(manifest.install?.requires_network),
    user_confirmed: true,
    source_of_truth: false,
    trust_effect: 'advisory_only',
    enabled: false,
    warnings: [
      '.knowledge recorded approval only; it did not execute pip/npm/docker or any network install.',
      'Run the official pinned install command manually if you want Mem0 present in the Python environment.'
    ]
  };
  writeJsonAtomic(receiptPath(context, manifest), receipt);
  const mem0SetupCommand = 'node .knowledge/tools/memory-provider.js setup mem0-oss --live --json';
  const mem0AddCommand = 'node .knowledge/tools/memory-mem0.js add --adapter live --yes-live-memory --text "Release note: Mem0 is advisory-only external memory" --scope repo --json';
  const mem0SearchCommand = 'node .knowledge/tools/memory-mem0.js search "advisory memory" --adapter live --yes-live-memory --json';
  const mem0RecallCommand = 'node .knowledge/tools/memory-mem0.js recall "advisory memory" --adapter live --yes-live-memory --json';
  const mem0InstallText = [
    'Mem0 receipt recorded for .knowledge advisory-only external memory.',
    `Receipt: ${displayPath(context, receiptPath(context, manifest))}`,
    'Live operations do not run automatically.',
    `Recommended setup: ${mem0SetupCommand}`,
    `For writes after setup use: ${mem0AddCommand}`,
    `For search after setup use: ${mem0SearchCommand}`,
    `For recall after setup use: ${mem0RecallCommand}`,
    'Boundary: advisory-only.'
  ].join('\n');
  const isMem0 = manifest.id === 'mem0-oss';
  return {
    ok: true,
    action: 'install_receipt_recorded',
    provider_id: manifest.id,
    installed: false,
    receipt: displayPath(context, receiptPath(context, manifest)),
    data_path: dir,
    setup_command: isMem0 ? mem0SetupCommand : null,
    next_commands: isMem0 ? [mem0SetupCommand] : [],
    agent_message: isMem0 ? 'Mem0 receipt recorded for .knowledge advisory-only external memory' : null,
    agent_facing: isMem0 ? {
      text: mem0InstallText,
      setup_command: mem0SetupCommand,
      add_command: mem0AddCommand,
      search_command: mem0SearchCommand,
      recall_command: mem0RecallCommand,
      boundary: 'advisory-only'
    } : null,
    source_of_truth: false,
    trust_role: 'advisory_only',
    trust_effect: 'advisory_only',
    warnings: receipt.warnings
  };
}

function recordUpdate(context, providerId, flags = {}, options = {}) {
  const manifest = findManifest(context, providerId, options);
  if (manifest.layer !== 'free_core') throw new Error(`${manifest.id} is not updatable from free core`);
  if ((manifest.license?.spdx || 'unknown') === 'unknown') throw new Error(`${manifest.id} update blocked: unknown license`);
  requireConfirmation(flags, 'update');
  const toVersion = requireVersion(flags.to || flags.version, 'update');
  const receipt = {
    schema_version: '3.3.0',
    provider_id: manifest.id,
    recorded_at: nowIso(),
    updated_at: null,
    to_version: toVersion,
    license_spdx: manifest.license.spdx,
    source_url: manifest.source?.package || manifest.source?.repository || manifest.source?.homepage || '',
    update_mode: 'manual_receipt',
    update_executed: false,
    requires_network: Boolean(manifest.install?.requires_network),
    user_confirmed: true,
    source_of_truth: false,
    trust_effect: 'advisory_only',
    warnings: [
      '.knowledge recorded update approval only; it did not execute package manager commands.',
      'Review release notes and run the official pinned update command manually.'
    ]
  };
  writeJsonAtomic(updateReceiptPath(context, manifest), receipt);
  return {
    ok: true,
    action: 'update_receipt_recorded',
    provider_id: manifest.id,
    updated: false,
    receipt: displayPath(context, updateReceiptPath(context, manifest)),
    warnings: receipt.warnings
  };
}

function providerVersionPin(manifest) {
  return manifest.source?.version_pin || (manifest.source?.version ? `mem0ai==${manifest.source.version}` : 'mem0ai==2.0.4');
}

function stripSecretFields(value) {
  if (Array.isArray(value)) return value.map((item) => stripSecretFields(item));
  if (!value || typeof value !== 'object') return value;
  const next = {};
  for (const [key, item] of Object.entries(value)) {
    if (/api[_-]?key|secret|token|password/i.test(key)) continue;
    next[key] = stripSecretFields(item);
  }
  return next;
}

function parsePositiveInt(value) {
  const number = Number(value);
  return Number.isInteger(number) && number > 0 ? number : null;
}

function inferMem0Collection(collectionName) {
  const name = String(collectionName || '');
  const inferred = {
    embedding_provider: null,
    embedding_model: null,
    embedding_dimensions: null
  };
  const dimMatch = name.match(/_(\d{2,5})$/);
  if (dimMatch) inferred.embedding_dimensions = Number(dimMatch[1]);
  if (/^knowledge_mem0_openai_/i.test(name)) {
    inferred.embedding_provider = 'openai';
    if (/text_embedding_3_small/i.test(name)) inferred.embedding_model = 'text-embedding-3-small';
    else if (/text_embedding_3_large/i.test(name)) inferred.embedding_model = 'text-embedding-3-large';
    else if (/text_embedding_ada_002/i.test(name)) inferred.embedding_model = 'text-embedding-ada-002';
  } else if (/^knowledge_mem0_fastembed_/i.test(name)) {
    inferred.embedding_provider = 'fastembed';
  }
  return inferred;
}

function readMem0ConfigSummary(context, manifest, flags = {}) {
  const configPath = mem0ConfigPath(context, manifest);
  const metaPath = mem0ConfigMetaPath(context, manifest);
  const config = safeReadJson(configPath, null);
  const meta = safeReadJson(metaPath, null);
  const vectorConfig = config?.vector_store?.config || {};
  const embedderConfig = config?.embedder?.config || {};
  const llmConfig = config?.llm?.config || {};
  const inferred = inferMem0Collection(vectorConfig.collection_name);
  const sharedRoot = meta?.shared_provider_root || defaultSharedMem0Root(flags);
  const pathInferredProviderScope = inferMem0ProviderScope(context, vectorConfig.path, sharedRoot);
  const metadataProviderScope = meta?.provider_scope || null;
  const providerScope = pathInferredProviderScope || metadataProviderScope;
  const metadataScopeMismatch = Boolean(metadataProviderScope && pathInferredProviderScope && metadataProviderScope !== pathInferredProviderScope);
  const staleSharedRoot = metadataScopeMismatch && metadataProviderScope === 'shared' ? meta?.shared_provider_root || sharedRoot : null;
  const staleProjectStorageKey = metadataScopeMismatch && metadataProviderScope === 'shared' ? meta?.project_storage_key || projectStorageKey(context) : null;
  return {
    config_exists: Boolean(config),
    config_path: fs.existsSync(configPath) ? displayPath(context, configPath) : null,
    config_meta_path: fs.existsSync(metaPath) ? displayPath(context, metaPath) : null,
    provider_scope: providerScope,
    metadata_provider_scope: metadataProviderScope,
    path_inferred_provider_scope: pathInferredProviderScope,
    metadata_scope_mismatch: metadataScopeMismatch,
    stale_shared_provider_root: staleSharedRoot,
    stale_shared_qdrant_path: staleSharedRoot && staleProjectStorageKey ? path.join(staleSharedRoot, 'projects', staleProjectStorageKey, 'qdrant') : null,
    stale_shared_lock_path: staleSharedRoot && staleProjectStorageKey ? path.join(staleSharedRoot, 'projects', staleProjectStorageKey, 'qdrant', '.lock') : null,
    shared_provider_root: providerScope === 'shared' ? (meta?.shared_provider_root || sharedRoot) : null,
    project_storage_key: providerScope === 'shared' ? (meta?.project_storage_key || projectStorageKey(context)) : null,
    llm_provider: config?.llm?.provider || null,
    llm_model: llmConfig.model || null,
    embedding_provider: config?.embedder?.provider || inferred.embedding_provider,
    embedding_model: embedderConfig.model || inferred.embedding_model,
    embedding_dimensions: parsePositiveInt(embedderConfig.embedding_dims)
      || parsePositiveInt(embedderConfig.dims)
      || parsePositiveInt(vectorConfig.embedding_model_dims)
      || inferred.embedding_dimensions,
    vector_store_provider: config?.vector_store?.provider || (config?.vector_store ? 'qdrant' : null),
    vector_collection_name: vectorConfig.collection_name || null,
    vector_embedding_dimensions: parsePositiveInt(vectorConfig.embedding_model_dims) || inferred.embedding_dimensions,
    qdrant_path: vectorConfig.path || null,
    history_store_provider: config?.history_db_path ? 'sqlite' : null,
    history_db_path: config?.history_db_path || null,
    selected_python: meta?.selected_python || meta?.python_runtime?.selected_python || null,
    python_runtime: meta?.python_runtime || null,
    contains_runtime_user_id: Boolean(config && Object.prototype.hasOwnProperty.call(config, 'user_id')),
    contains_inline_secret: /api[_-]?key|secret|token|password/i.test(JSON.stringify(config || {}))
  };
}

function slugPart(value) {
  const clean = String(value || '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '')
    .replace(/_+/g, '_');
  return clean || 'model';
}

function validateCollectionName(value) {
  const name = String(value || '').trim();
  if (!/^[A-Za-z0-9_.-]{1,128}$/.test(name)) {
    throw new Error('Qdrant collection name must use only letters, numbers, underscore, dot, or dash and be at most 128 chars');
  }
  return name;
}

function collectionNameFor(embedder, model, dimensions) {
  const slug = slugPart(model);
  const base = `knowledge_mem0_${slugPart(embedder)}_${slug}_${dimensions}`;
  if (base.length <= 96) return base;
  const hash = crypto.createHash('sha256').update(`${embedder}:${model}:${dimensions}`).digest('hex').slice(0, 10);
  return `knowledge_mem0_${slugPart(embedder)}_${slug.slice(0, 48)}_${hash}_${dimensions}`;
}

function normalizeEmbedder(value) {
  const embedder = String(value || '').trim().toLowerCase();
  if (['openai', 'fastembed'].includes(embedder)) return embedder;
  throw new Error('configure-embeddings requires --embedder openai or --embedder fastembed');
}

function resolveFastEmbedModel(modelOrAlias) {
  const raw = String(modelOrAlias || '').trim();
  if (!raw) throw new Error('configure-embeddings --embedder fastembed requires --model');
  const choice = FASTEMBED_MODEL_CHOICES[raw];
  return {
    alias: choice ? raw : null,
    ...(choice || { model: raw })
  };
}

function resolveOpenAiEmbeddingModel(model) {
  const selected = String(model || DEFAULT_OPENAI_EMBEDDING_MODEL).trim();
  const known = OPENAI_EMBEDDING_MODELS[selected];
  return {
    model: selected,
    dimensions: known?.dimensions || DEFAULT_OPENAI_EMBEDDING_DIMS,
    known: Boolean(known)
  };
}

function resolveLlmConfig(existing, flags = {}) {
  const existingLlm = existing?.llm || {};
  const provider = String(flags.llmProvider || existingLlm.provider || 'openai').trim();
  const config = stripSecretFields(existingLlm.config || {});
  const model = flags.llmModel || config.model || (provider === 'openai' ? DEFAULT_OPENAI_LLM_MODEL : null);
  return {
    provider,
    config: model ? { ...config, model } : config
  };
}

function fastEmbedInstallCommands(pythonCommand = 'python') {
  return [
    packageInstallCommand(pythonCommand, 'mem0ai==2.0.4'),
    packageInstallCommand(pythonCommand, FASTEMBED_VERSION_PIN)
  ];
}

function pinnedFastEmbedVersion() {
  const match = FASTEMBED_VERSION_PIN.match(/==(.+)$/);
  return match ? match[1] : FASTEMBED_VERSION_PIN;
}

function pythonVersionParts(value) {
  const match = String(value || '').trim().match(/^(\d+)\.(\d+)(?:\.(\d+))?/);
  if (!match) return null;
  return {
    major: Number(match[1]),
    minor: Number(match[2]),
    patch: Number(match[3] || 0),
    raw: match[0]
  };
}

function fastEmbedSupportedRuntimeNextCommands() {
  return [
    'Use a Python 3.12 runtime or virtualenv for Local FastEmbed.',
    'After activating that runtime, run the pinned installs: python -m pip install mem0ai==2.0.4 && python -m pip install fastembed==0.5.1',
    'Re-run configure-embeddings with --python "<path-to-python-3.12>" before live add/search/recall smoke tests.'
  ];
}

function fastEmbedRuntimeGuard(selected = {}) {
  const version = process.env.KNOWLEDGE_MEMORY_PROVIDER_TEST_FASTEMBED_RUNTIME_VERSION || selected.version || '';
  const parsed = pythonVersionParts(version);
  if (!parsed) {
    return {
      ok: false,
      diagnostic_code: 'fastembed_runtime_unknown',
      python_version: version || null,
      recommended_python: '3.12',
      error: `${FASTEMBED_VERSION_PIN} requires a Python runtime with known compatible wheels. Use Python 3.12 for Local FastEmbed.`,
      next_commands: fastEmbedSupportedRuntimeNextCommands()
    };
  }
  if (parsed.major > 3 || (parsed.major === 3 && parsed.minor >= 14)) {
    return {
      ok: false,
      diagnostic_code: 'fastembed_runtime_unsupported',
      python_version: parsed.raw,
      recommended_python: '3.12',
      error: `${FASTEMBED_VERSION_PIN} is not supported by this guided recipe on Python ${parsed.raw}. Use Python 3.12 so pinned FastEmbed dependencies install from wheels instead of failing source builds.`,
      next_commands: fastEmbedSupportedRuntimeNextCommands()
    };
  }
  return { ok: true, python_version: parsed.raw, recommended_python: '3.12' };
}

function fastEmbedVersionGuard(version) {
  const expected = pinnedFastEmbedVersion();
  const actual = String(version || '').trim();
  if (actual === expected) return { ok: true, fastembed_version: actual, expected_version: expected };
  return {
    ok: false,
    diagnostic_code: actual ? 'fastembed_version_mismatch' : 'fastembed_version_missing',
    fastembed_version: actual || null,
    expected_version: expected,
    error: `FastEmbed runtime version ${actual || 'unknown'} does not match required ${expected}. Install ${FASTEMBED_VERSION_PIN} in a supported Python runtime before configuring Local FastEmbed.`
  };
}

function lookupFastEmbedModelFromCatalog(catalog, model) {
  const list = Array.isArray(catalog) ? catalog : (Array.isArray(catalog?.models) ? catalog.models : []);
  const found = list.find((item) => String(item.model || item.model_name || item.name || '') === model);
  if (!found) return null;
  return {
    model,
    dimensions: parsePositiveInt(found.dim) || parsePositiveInt(found.dimensions) || parsePositiveInt(found.embedding_size),
    size_gb: Number(found.size_in_GB ?? found.size_gb ?? found.sizeGB ?? 0) || null,
    source: 'fastembed_catalog'
  };
}

function testFastEmbedCatalog(model) {
  const raw = process.env.KNOWLEDGE_MEMORY_PROVIDER_TEST_FASTEMBED_MODELS_JSON;
  if (!raw) return null;
  try {
    return lookupFastEmbedModelFromCatalog(JSON.parse(raw), model);
  } catch {
    return null;
  }
}

function chooseFastEmbedPythonRuntime(flags = {}) {
  const timeoutMs = Number(flags.pythonTimeoutMs || flags.timeoutMs || 5000);
  const baseOptions = { flags, timeoutMs, env: process.env };
  const candidates = collectPythonCandidates(baseOptions);
  const results = [];
  for (const candidate of candidates) {
    const checked = validatePythonCandidate(candidate, baseOptions);
    const guard = checked.status === 'ok' ? fastEmbedRuntimeGuard(checked) : null;
    const result = guard && !guard.ok
      ? {
        ...checked,
        status: 'unsupported',
        diagnostic_code: guard.diagnostic_code,
        error: guard.error,
        recommended_python: guard.recommended_python
      }
      : checked;
    results.push(result);
    if (checked.status === 'ok' && guard?.ok) {
      return {
        ok: true,
        selected_python: checked.executable || checked.command,
        selected: checked,
        discovery: {
          status: 'found',
          diagnostic_code: 'python_available',
          selected: checked,
          candidates_checked: results.length,
          candidates: results
        },
        runtime_guard: guard
      };
    }
    if (candidate.explicit) {
      return {
        ok: false,
        diagnostic_code: result.diagnostic_code || 'python_not_found',
        error: result.error || 'Explicit Python runtime is not usable for Local FastEmbed.',
        selected_python: checked.executable || checked.command || candidate.command || null,
        python_version: checked.version || null,
        recommended_python: result.recommended_python || '3.12',
        discovery: {
          status: 'not_found',
          diagnostic_code: result.diagnostic_code || 'python_not_found',
          selected: null,
          candidates_checked: results.length,
          candidates: results,
          next_commands: fastEmbedSupportedRuntimeNextCommands()
        },
        next_commands: result.diagnostic_code === 'fastembed_runtime_unsupported'
          ? fastEmbedSupportedRuntimeNextCommands()
          : [
            'Install Python or pass --python "<path-to-python-3.12>"',
            ...fastEmbedInstallCommands('python')
          ]
      };
    }
  }

  const unsupported = results.find((item) => item.diagnostic_code === 'fastembed_runtime_unsupported');
  if (unsupported) {
    return {
      ok: false,
      diagnostic_code: 'fastembed_runtime_unsupported',
      error: unsupported.error,
      selected_python: unsupported.executable || unsupported.command || null,
      python_version: unsupported.version || null,
      recommended_python: unsupported.recommended_python || '3.12',
      discovery: {
        status: 'not_found',
        diagnostic_code: 'fastembed_runtime_unsupported',
        selected: null,
        candidates_checked: results.length,
        candidates: results,
        next_commands: fastEmbedSupportedRuntimeNextCommands()
      },
      next_commands: fastEmbedSupportedRuntimeNextCommands()
    };
  }

  const discovery = discoverPython(baseOptions);
  return {
    ok: false,
    diagnostic_code: discovery.diagnostic_code || 'python_missing',
    error: 'Python is required to inspect FastEmbed model dimensions.',
    selected_python: null,
    discovery,
    next_commands: [
      ...(discovery.next_commands || []),
      ...fastEmbedInstallCommands('python')
    ]
  };
}

function readFastEmbedModelInfo(flags = {}, model) {
  const testRuntimeGuard = process.env.KNOWLEDGE_MEMORY_PROVIDER_TEST_FASTEMBED_RUNTIME_VERSION
    ? fastEmbedRuntimeGuard({ version: process.env.KNOWLEDGE_MEMORY_PROVIDER_TEST_FASTEMBED_RUNTIME_VERSION })
    : null;
  if (testRuntimeGuard && !testRuntimeGuard.ok) {
    return {
      ok: false,
      diagnostic_code: testRuntimeGuard.diagnostic_code,
      error: testRuntimeGuard.error,
      model,
      discovery: { status: 'test_runtime_guard', selected: { version: testRuntimeGuard.python_version } },
      selected_python: null,
      python_version: testRuntimeGuard.python_version,
      recommended_python: testRuntimeGuard.recommended_python,
      next_commands: testRuntimeGuard.next_commands
    };
  }
  const testModel = testFastEmbedCatalog(model);
  if (testModel) return { ok: true, ...testModel, selected_python: null, fastembed_version: 'test-catalog' };

  const runtime = chooseFastEmbedPythonRuntime(flags);
  if (!runtime.ok) {
    return {
      ok: false,
      diagnostic_code: runtime.diagnostic_code,
      error: runtime.error,
      model,
      discovery: runtime.discovery,
      selected_python: runtime.selected_python || null,
      python_version: runtime.python_version || null,
      recommended_python: runtime.recommended_python || '3.12',
      next_commands: runtime.next_commands || fastEmbedInstallCommands(runtime.selected_python || 'python')
    };
  }

  const discovery = runtime.discovery;
  const pythonCommand = runtime.selected_python;
  const runtimeGuard = runtime.runtime_guard || fastEmbedRuntimeGuard(discovery.selected || {});
  const script = [
    'import importlib.metadata as metadata, json, sys',
    'target = sys.argv[1]',
    'try:',
    '    from fastembed import TextEmbedding',
    '    models = TextEmbedding.list_supported_models()',
    '    version = metadata.version("fastembed")',
    'except Exception as exc:',
    '    print(json.dumps({"ok": False, "error": str(exc), "type": exc.__class__.__name__}))',
    '    sys.exit(0)',
    'for item in models:',
    '    if item.get("model") == target:',
    '        print(json.dumps({"ok": True, "model": target, "dimensions": item.get("dim"), "size_gb": item.get("size_in_GB"), "fastembed_version": version}, default=str))',
    '        sys.exit(0)',
    'print(json.dumps({"ok": False, "error": "FastEmbed model is not in TextEmbedding.list_supported_models()", "model": target, "supported_count": len(models)}))'
  ].join('\n');
  const res = spawnSync(pythonCommand, ['-c', script, model], {
    cwd: process.cwd(),
    env: process.env,
    encoding: 'utf8',
    windowsHide: true,
    timeout: Number(flags.pythonTimeoutMs || flags.timeoutMs || 20000)
  });
  if (res.error) {
    return {
      ok: false,
      diagnostic_code: res.error.code === 'ETIMEDOUT' ? 'python_timeout' : 'python_not_usable',
      error: res.error.message,
      discovery,
      selected_python: pythonCommand,
      next_commands: fastEmbedInstallCommands(pythonCommand)
    };
  }
  let parsed = null;
  try { parsed = JSON.parse(String(res.stdout || '').trim() || '{}'); } catch {}
  if (res.status !== 0 || !parsed) {
    return {
      ok: false,
      diagnostic_code: 'fastembed_catalog_error',
      error: `${res.stderr || ''}\n${res.stdout || ''}`.trim().slice(0, 1000) || 'FastEmbed catalog check did not return JSON.',
      discovery,
      selected_python: pythonCommand,
      next_commands: fastEmbedInstallCommands(pythonCommand)
    };
  }
  if (!parsed.ok) {
    const missingPackage = /No module named|ModuleNotFoundError/i.test(String(parsed.error || ''));
    return {
      ok: false,
      diagnostic_code: missingPackage ? 'fastembed_runtime_missing' : 'fastembed_model_not_supported',
      error: parsed.error || 'FastEmbed model metadata unavailable.',
      model,
      discovery,
      selected_python: pythonCommand,
      next_commands: fastEmbedInstallCommands(pythonCommand)
    };
  }
  const versionGuard = fastEmbedVersionGuard(parsed.fastembed_version);
  if (!versionGuard.ok) {
    return {
      ok: false,
      diagnostic_code: versionGuard.diagnostic_code,
      error: versionGuard.error,
      model,
      discovery,
      selected_python: pythonCommand,
      fastembed_version: versionGuard.fastembed_version,
      expected_version: versionGuard.expected_version,
      next_commands: fastEmbedInstallCommands(pythonCommand)
    };
  }
  const dimensions = parsePositiveInt(parsed.dimensions);
  if (!dimensions) {
    return {
      ok: false,
      diagnostic_code: 'fastembed_dimensions_missing',
      error: `FastEmbed did not report dimensions for ${model}.`,
      model,
      discovery,
      selected_python: pythonCommand,
      next_commands: fastEmbedInstallCommands(pythonCommand)
    };
  }
  return {
    ok: true,
    model,
    dimensions,
    size_gb: Number(parsed.size_gb || 0) || null,
    fastembed_version: parsed.fastembed_version || null,
    selected_python: pythonCommand,
    python_version: runtimeGuard.python_version || discovery.selected?.version || null,
    recommended_python: runtimeGuard.recommended_python || '3.12',
    source: 'fastembed_catalog',
    discovery
  };
}

function collectionReuseConflict(previous, collectionName, nextSpec) {
  if (!previous?.vector_collection_name || previous.vector_collection_name !== collectionName) return null;
  const previousDims = previous.embedding_dimensions || previous.vector_embedding_dimensions;
  const previousProvider = previous.embedding_provider;
  const previousModel = previous.embedding_model;
  const metadataMissing = !previousDims || !previousProvider || !previousModel;
  const dimsDiffer = previousDims && Number(previousDims) !== Number(nextSpec.dimensions);
  const providerDiffers = previousProvider && previousProvider !== nextSpec.embedder;
  const modelDiffers = previousModel && previousModel !== nextSpec.model;
  if (!metadataMissing && !dimsDiffer && !providerDiffers && !modelDiffers) return null;
  return {
    previous_collection_name: collectionName,
    previous_embedding_provider: previousProvider,
    previous_embedding_model: previousModel,
    previous_embedding_dimensions: previousDims || null,
    requested_embedding_provider: nextSpec.embedder,
    requested_embedding_model: nextSpec.model,
    requested_embedding_dimensions: nextSpec.dimensions,
    reason: metadataMissing
      ? 'Existing collection is missing embedding provider, model, or dimensions metadata.'
      : 'Existing collection appears to belong to a different embedding provider, model, or dimensions.'
  };
}

function mem0SmokeCommands() {
  return {
    health: 'node .knowledge/tools/memory-mem0.js health --adapter live --json',
    add: 'node .knowledge/tools/memory-mem0.js add --adapter live --yes-live-memory --text "Release note: Mem0 embedding backend smoke test" --scope repo --json',
    search: 'node .knowledge/tools/memory-mem0.js search "embedding backend smoke test" --adapter live --yes-live-memory --json',
    recall: 'node .knowledge/tools/memory-mem0.js recall "embedding backend smoke test" --adapter live --yes-live-memory --json'
  };
}

function writeMem0EmbeddingConfig(context, manifest, spec, flags = {}) {
  const dir = providerStateDir(context, manifest);
  const configPath = mem0ConfigPath(context, manifest);
  const metaPath = mem0ConfigMetaPath(context, manifest);
  ensureDir(dir);

  const existing = safeReadJson(configPath, null);
  const storage = mem0StoragePlan(context, manifest, flags, existing);
  ensureDir(storage.data_dir);
  ensureDir(storage.qdrant_path);
  const previous = readMem0ConfigSummary(context, manifest);
  const collectionName = flags.collectionName
    ? validateCollectionName(flags.collectionName)
    : collectionNameFor(spec.embedder, spec.model, spec.dimensions);
  const conflict = collectionReuseConflict(previous, collectionName, spec);
  if (conflict) {
    return {
      ok: false,
      action: 'configure_embeddings',
      provider_id: manifest.id,
      diagnostic_code: 'collection_reuse_blocked',
      configuration_written: false,
      collection_reuse_blocked: true,
      conflict,
      next_collection_name: collectionNameFor(spec.embedder, spec.model, spec.dimensions),
      message: 'Refusing to reuse a Qdrant collection with mismatched embedding dimensions or provider.',
      source_of_truth: false,
      trust_role: 'advisory_only',
      trust_effect: 'advisory_only'
    };
  }

  const existingVectorConfig = existing?.vector_store?.config || {};
  const llm = resolveLlmConfig(existing, flags);
  const nextConfig = {
    llm,
    embedder: {
      provider: spec.embedder,
      config: {
        model: spec.model,
        embedding_dims: spec.dimensions
      }
    },
    vector_store: {
      provider: 'qdrant',
      config: {
        path: storage.qdrant_path,
        collection_name: collectionName,
        embedding_model_dims: spec.dimensions,
        on_disk: existingVectorConfig.on_disk === true
      }
    },
    history_db_path: storage.history_db_path,
    version: existing?.version || 'v1.1'
  };
  for (const key of ['custom_fact_extraction_prompt', 'custom_update_memory_prompt', 'custom_instructions', 'reranker']) {
    if (existing && Object.prototype.hasOwnProperty.call(existing, key)) nextConfig[key] = stripSecretFields(existing[key]);
  }

  writeJsonAtomic(configPath, nextConfig);
  const meta = {
    schema_version: '3.3.0',
    provider_id: manifest.id,
    generated_at: nowIso(),
    generated_by: getAgentId(),
    config_path: configPath,
    provider_scope: storage.provider_scope,
    shared_provider_root: storage.shared_provider_root,
    project_storage_key: storage.project_storage_key,
    provider_data_path: storage.data_dir,
    preserved_existing_paths: storage.preserved_existing_paths,
    llm_provider: llm.provider,
    llm_model: llm.config?.model || null,
    embedding_provider: spec.embedder,
    embedding_model: spec.model,
    embedding_dimensions: spec.dimensions,
    vector_store: 'qdrant',
    history_store: 'sqlite',
    qdrant_path: nextConfig.vector_store.config.path,
    history_db_path: nextConfig.history_db_path,
    collection_name: collectionName,
    collection_policy: 'Embedding provider, model, or dimensions changes must use a new Qdrant collection name.',
    selected_python: spec.selected_python || null,
    python_runtime: spec.selected_python ? {
      selected_python: spec.selected_python,
      python_version: spec.python_version || null,
      fastembed_version: spec.fastembed_version || null,
      expected_fastembed_version: spec.embedder === 'fastembed' ? pinnedFastEmbedVersion() : null,
      recommended_python: spec.embedder === 'fastembed' ? '3.12' : null,
      source: 'configure-embeddings'
    } : null,
    previous_config: previous,
    source_of_truth: false,
    trust_role: 'advisory_only',
    trust_effect: 'advisory_only'
  };
  writeJsonAtomic(metaPath, meta);

  return {
    ok: true,
    action: 'configure_embeddings',
    provider_id: manifest.id,
    configuration_written: true,
    config: displayPath(context, configPath),
    config_meta: displayPath(context, metaPath),
    provider_scope: storage.provider_scope,
    shared_provider_root: storage.shared_provider_root,
    project_storage_key: storage.project_storage_key,
    llm_provider: { provider: llm.provider, model: llm.config?.model || null },
    embedding_provider: { provider: spec.embedder, model: spec.model, dimensions: spec.dimensions },
    vector_store: {
      provider: 'qdrant',
      collection_name: collectionName,
      embedding_model_dims: spec.dimensions,
      path: displayPath(context, nextConfig.vector_store.config.path)
    },
    history_store: { provider: 'sqlite', path: displayPath(context, nextConfig.history_db_path) },
    selected_python: spec.selected_python || null,
    python_runtime: spec.selected_python ? meta.python_runtime : null,
    previous_config: previous,
    source_of_truth: false,
    trust_role: 'advisory_only',
    trust_effect: 'advisory_only'
  };
}

function ensureMem0RepoConfig(context, manifest, flags = {}) {
  const dir = providerStateDir(context, manifest);
  const configPath = mem0ConfigPath(context, manifest);
  const metaPath = mem0ConfigMetaPath(context, manifest);
  ensureDir(dir);

  const existing = safeReadJson(configPath, null);
  const storage = mem0StoragePlan(context, manifest, flags, existing);
  ensureDir(storage.data_dir);
  ensureDir(storage.qdrant_path);
  const existingVectorConfig = existing?.vector_store?.config || {};
  const existingSummary = readMem0ConfigSummary(context, manifest);
  const embeddingProvider = existingSummary.embedding_provider || 'openai';
  const embeddingModel = existingSummary.embedding_model || DEFAULT_OPENAI_EMBEDDING_MODEL;
  const embeddingDimensions = existingSummary.embedding_dimensions || DEFAULT_OPENAI_EMBEDDING_DIMS;
  const collectionName = existingVectorConfig.collection_name || collectionNameFor(embeddingProvider, embeddingModel, embeddingDimensions);
  const llm = resolveLlmConfig(existing, {});
  const nextConfig = {
    llm,
    embedder: {
      provider: embeddingProvider,
      config: {
        model: embeddingModel,
        embedding_dims: embeddingDimensions
      }
    },
    vector_store: {
      provider: 'qdrant',
      config: {
        path: storage.qdrant_path,
        collection_name: collectionName,
        embedding_model_dims: embeddingDimensions,
        on_disk: existingVectorConfig.on_disk === true
      }
    },
    history_db_path: storage.history_db_path,
    version: existing?.version || 'v1.1'
  };
  for (const key of ['custom_fact_extraction_prompt', 'custom_update_memory_prompt', 'custom_instructions', 'reranker']) {
    if (existing && Object.prototype.hasOwnProperty.call(existing, key)) nextConfig[key] = stripSecretFields(existing[key]);
  }
  writeJsonAtomic(configPath, nextConfig);
  writeJsonAtomic(metaPath, {
    schema_version: '3.3.0',
    provider_id: manifest.id,
    generated_at: nowIso(),
    config_path: configPath,
    provider_scope: storage.provider_scope,
    shared_provider_root: storage.shared_provider_root,
    project_storage_key: storage.project_storage_key,
    provider_data_path: storage.data_dir,
    preserved_existing_paths: storage.preserved_existing_paths,
    llm_provider: llm.provider,
    llm_model: llm.config?.model || null,
    embedding_provider: embeddingProvider,
    embedding_model: embeddingModel,
    embedding_dimensions: embeddingDimensions,
    vector_store: 'qdrant',
    history_store: 'sqlite',
    qdrant_path: nextConfig.vector_store.config.path,
    history_db_path: nextConfig.history_db_path,
    collection_name: collectionName,
    collection_policy: 'Embedding provider, model, or dimensions changes must use a new Qdrant collection name.',
    source_of_truth: false,
    trust_role: 'advisory_only',
    trust_effect: 'advisory_only'
  });
  return {
    path: configPath,
    display_path: displayPath(context, configPath),
    meta_path: displayPath(context, metaPath),
    provider_scope: storage.provider_scope,
    shared_provider_root: storage.shared_provider_root,
    project_storage_key: storage.project_storage_key,
    qdrant_path: nextConfig.vector_store.config.path,
    history_db_path: nextConfig.history_db_path,
    collection_name: collectionName,
    embedding_provider: embeddingProvider,
    embedding_model: embeddingModel,
    embedding_dimensions: embeddingDimensions,
    llm_provider: llm.provider,
    llm_model: llm.config?.model || null
  };
}

function configureMem0Embeddings(context, providerId, flags = {}, options = {}) {
  const manifest = findManifest(context, providerId, options);
  if (manifest.id !== 'mem0-oss') throw new Error(`configure-embeddings is only implemented for mem0-oss, got ${manifest.id}`);
  const embedder = normalizeEmbedder(flags.embedder);
  const smoke = mem0SmokeCommands();
  let spec;
  let modelInfo = null;
  const warnings = [
    'This command writes repo-local Mem0 config only; it does not install packages, call OpenAI, or warm/download FastEmbed models.',
    'Mem0 remains advisory-only external memory and cannot raise trust.'
  ];

  if (embedder === 'openai') {
    modelInfo = resolveOpenAiEmbeddingModel(flags.model);
    spec = {
      embedder,
      model: modelInfo.model,
      dimensions: parsePositiveInt(flags.dimensions) || modelInfo.dimensions
    };
    if (!modelInfo.known && !flags.dimensions) {
      throw new Error(`Unknown OpenAI embedding model ${modelInfo.model}; pass --dimensions explicitly if this model is intentional`);
    }
  } else {
    const selected = resolveFastEmbedModel(flags.model);
    modelInfo = readFastEmbedModelInfo(flags, selected.model);
    if (!modelInfo.ok) {
      return {
        ok: false,
        action: 'configure_embeddings',
        provider_id: manifest.id,
        diagnostic_code: modelInfo.diagnostic_code || 'fastembed_model_metadata_unavailable',
        configuration_written: false,
        embedder,
        model: selected.model,
        model_alias: selected.alias,
        model_choices: FASTEMBED_MODEL_CHOICES,
        error: modelInfo.error,
        selected_python: modelInfo.selected_python || null,
        next_commands: modelInfo.next_commands || fastEmbedInstallCommands(modelInfo.selected_python || 'python'),
        source_of_truth: false,
        trust_role: 'advisory_only',
        trust_effect: 'advisory_only'
      };
    }
    spec = {
      embedder,
      model: selected.model,
      dimensions: modelInfo.dimensions,
      selected_python: modelInfo.selected_python || null,
      python_version: modelInfo.python_version || null,
      fastembed_version: modelInfo.fastembed_version || null
    };
  }

  const written = writeMem0EmbeddingConfig(context, manifest, spec, flags);
  if (!written.ok) return written;
  const installCommands = embedder === 'fastembed' ? fastEmbedInstallCommands(modelInfo.selected_python || 'python') : [];
  return {
    ...written,
    embedder,
    model: spec.model,
    dimensions: spec.dimensions,
    model_alias: embedder === 'fastembed' ? resolveFastEmbedModel(flags.model).alias : null,
    model_info: modelInfo,
    llm_provider: written.llm_provider,
    embedding_provider: written.embedding_provider,
    vector_store: written.vector_store,
    history_store: written.history_store,
    collection_policy: 'Embedding provider, model, or dimensions changes must use a new Qdrant collection name; do not reuse an OpenAI 1536-dimension collection for FastEmbed.',
    install_commands: installCommands,
    setup_command: 'node .knowledge/tools/memory-provider.js setup mem0-oss --live --json',
    health_command: smoke.health,
    smoke_commands: smoke,
    environment_guidance: embedder === 'openai' ? {
      secret_policy: 'Do not paste OPENAI_API_KEY into repo files or commits.',
      macos_linux: 'export OPENAI_API_KEY="sk-..."',
      windows_powershell: '$env:OPENAI_API_KEY="sk-..."'
    } : null,
    agent_facing: {
      text: embedder === 'openai'
        ? [
          'Embedding provider configured: OpenAI API.',
          'Do not write OPENAI_API_KEY into repository files.',
          'Ask the user to set OPENAI_API_KEY in their local terminal, then run setup and live health.'
        ].join('\n')
        : [
          'Embedding provider configured: Local FastEmbed.',
          `Model: ${spec.model} (${spec.dimensions} dimensions).`,
          `Collection: ${written.vector_store.collection_name}.`,
          'Run the pinned install commands first if the runtime is missing, then run health/add/search/recall smoke commands.'
        ].join('\n'),
      install_commands: installCommands,
      setup_command: 'node .knowledge/tools/memory-provider.js setup mem0-oss --live --json',
      health_command: smoke.health,
      smoke_commands: smoke,
      boundary: 'advisory-only'
    },
    warnings
  };
}

function renderMem0RecipeTemplate(context, manifest) {
  const templatePath = mem0RecipeTemplatePath(context);
  if (!fs.existsSync(templatePath)) throw new Error(`Mem0 recipe template missing: ${templatePath}`);
  return fs.readFileSync(templatePath, 'utf8')
    .replace(/\{\{VERSION_PIN\}\}/g, providerVersionPin(manifest))
    .replace(/\{\{RECEIPT_PATH\}\}/g, canonicalMem0Path('install_receipt.json'))
    .replace(/\{\{CONFIG_PATH\}\}/g, canonicalMem0Path('config.json'))
    .replace(/\{\{RUNTIME_STATUS_PATH\}\}/g, canonicalMem0Path('runtime_status.json'))
    .replace(/\{\{DATA_PATH\}\}/g, canonicalMem0Path())
    .replace(/\{\{QDRANT_PATH\}\}/g, canonicalMem0Path('qdrant'))
    .replace(/\{\{HISTORY_DB_PATH\}\}/g, canonicalMem0Path('history.db'))
    .replace(/\{\{SHARED_PROVIDER_ROOT\}\}/g, sharedMem0DocPath());
}

function writeMem0Recipe(context, providerId, options = {}) {
  const manifest = findManifest(context, providerId, options);
  if (manifest.id !== 'mem0-oss') throw new Error(`write-recipe is only implemented for mem0-oss, got ${manifest.id}`);
  const outputPath = mem0RecipePath(context);
  const body = renderMem0RecipeTemplate(context, manifest);
  writeFileAtomic(outputPath, body.endsWith('\n') ? body : `${body}\n`);
  return {
    ok: true,
    action: 'write_recipe',
    provider_id: manifest.id,
    recipe: displayPath(context, outputPath),
    template: displayPath(context, mem0RecipeTemplatePath(context)),
    generated_from_template: true,
    deterministic: true,
    source_of_truth: false,
    trust_role: 'advisory_only',
    trust_effect: 'advisory_only'
  };
}

function extractRecipeNodeCommands(text) {
  const commands = [];
  const re = /^node\s+\.knowledge\/tools\/([^\s]+)\s*(.*)$/gm;
  let match;
  while ((match = re.exec(text))) {
    commands.push({
      script: match[1],
      args: String(match[2] || '').trim().split(/\s+/).filter(Boolean),
      line: match[0]
    });
  }
  return commands;
}

function extractRecipePipInstallCommands(text) {
  return String(text || '')
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => /^(?:python\s+-m\s+)?pip\s+install\s+\S+/i.test(line));
}

function hasEllipsisCommand(text) {
  return String(text || '')
    .split(/\r?\n/)
    .map((line) => line.trim())
    .some((line) => line === '...' || /^(?:node|python|pip|npm|pnpm|yarn|bun|npx)\b.*\.\.\./i.test(line));
}

function recipeCommandExists(context, command) {
  const scriptPath = path.join(context.projectKnowledgeRoot, 'tools', command.script.replace(/\//g, path.sep));
  if (!fs.existsSync(scriptPath)) return false;
  const firstArg = command.args[0] || '';
  const res = spawnSync(process.execPath, [scriptPath, 'help', '--json'], {
    cwd: context.targetRoot,
    encoding: 'utf8',
    windowsHide: true,
    timeout: 10000
  });
  if (res.status !== 0) return false;
  let parsed = null;
  try { parsed = JSON.parse(String(res.stdout || '').trim() || '{}'); }
  catch { return false; }
  const commands = new Set((parsed.commands || []).map((entry) => typeof entry === 'string' ? entry : entry?.name).filter(Boolean));
  return commands.has(firstArg);
}

function expectedMem0RecipeCommands() {
  return [
    'node .knowledge/tools/memory-provider.js setup mem0-oss --live --json',
    'node .knowledge/tools/memory-provider.js configure-embeddings mem0-oss --embedder openai --model text-embedding-3-small --json',
    'node .knowledge/tools/memory-provider.js configure-embeddings mem0-oss --embedder fastembed --model sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2 --json',
    'node .knowledge/tools/memory-provider.js configure-embeddings mem0-oss --embedder fastembed --model sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2 --provider-scope project --json',
    'node .knowledge/tools/memory-provider.js status mem0-oss --json',
    'node .knowledge/tools/memory-provider.js status-all --json',
    'node .knowledge/tools/memory-mem0.js health --adapter live --json',
    'node .knowledge/tools/memory-mem0.js list --adapter live --yes-live-memory --json',
    'node .knowledge/tools/memory-mem0.js add --adapter live --yes-live-memory --text "Release note: Mem0 is advisory-only external memory" --scope repo --json',
    'node .knowledge/tools/memory-mem0.js search "advisory memory" --adapter live --yes-live-memory --json',
    'node .knowledge/tools/memory-mem0.js recall "advisory memory" --adapter live --yes-live-memory --json',
    'node .knowledge/tools/memory-provider.js write-recipe mem0-oss --json',
    'node .knowledge/tools/memory-provider.js validate-recipe mem0-oss --json'
  ];
}

function validateMem0Recipe(context, providerId, options = {}) {
  const manifest = findManifest(context, providerId, options);
  if (manifest.id !== 'mem0-oss') throw new Error(`validate-recipe is only implemented for mem0-oss, got ${manifest.id}`);
  const recipePath = mem0RecipePath(context);
  const readmePath = path.join(context.projectKnowledgeRoot, 'docs', 'cookbook', 'README.md');
  const recipe = fs.existsSync(recipePath) ? fs.readFileSync(recipePath, 'utf8') : '';
  const readme = fs.existsSync(readmePath) ? fs.readFileSync(readmePath, 'utf8') : '';
  const commands = extractRecipeNodeCommands(recipe);
  const pipInstallCommands = extractRecipePipInstallCommands(recipe);
  const mem0InstallCommand = `python -m pip install ${providerVersionPin(manifest)}`;
  const fastembedInstallCommand = 'python -m pip install fastembed==0.5.1';
  const allowedPipInstallCommands = new Set([mem0InstallCommand, fastembedInstallCommand]);
  const expectedCommands = expectedMem0RecipeCommands();
  const expectedCommandSet = new Set(expectedCommands);
  const commandLines = commands.map((command) => command.line);
  const failures = [];
  let checksTotal = 0;
  const check = (id, ok, detail) => {
    checksTotal += 1;
    if (!ok) failures.push({ id, detail });
  };
  const setupFlowMatches = recipe.match(/node \.knowledge\/tools\/memory-provider\.js setup mem0-oss --live --json/g) || [];

  check('recipe_exists', Boolean(recipe), `${displayPath(context, recipePath)} is missing`);
  check('no_ellipsis', !hasEllipsisCommand(recipe), 'Recipe must not contain ellipsis commands.');
  check('receipt_path', recipe.includes(canonicalMem0Path('install_receipt.json')), 'Recipe must include install receipt path.');
  check('status_mem0', /memory-provider\.js status mem0-oss --json/.test(recipe), 'Recipe must include status mem0-oss.');
  check('status_all', /memory-provider\.js status-all --json/.test(recipe), 'Recipe must include status-all.');
  check('setup_flow', /memory-provider\.js setup mem0-oss --live --json/.test(recipe), 'Recipe must include one recommended setup flow.');
  check('single_setup_flow', setupFlowMatches.length === 1, `Recipe must contain exactly one recommended setup flow, found ${setupFlowMatches.length}.`);
  check('embedding_provider_choice_required', /needs_embedding_provider_choice/.test(recipe) && /must not silently choose OpenAI API or Local FastEmbed/i.test(recipe), 'Recipe must require the agent to ask for an embedding provider before live setup.');
  check('configure_openai_embeddings', /memory-provider\.js configure-embeddings mem0-oss --embedder openai --model text-embedding-3-small --json/.test(recipe), 'Recipe must include OpenAI embedding configure command.');
  check('configure_fastembed_embeddings', /memory-provider\.js configure-embeddings mem0-oss --embedder fastembed --model sentence-transformers\/paraphrase-multilingual-MiniLM-L12-v2 --json/.test(recipe), 'Recipe must include FastEmbed configure command.');
  check('project_local_scope_explicit', /--provider-scope project/.test(recipe), 'Recipe must show project-local provider storage only as an explicit command.');
  check('provider_layers', /LLM provider/i.test(recipe) && /Embedding provider/i.test(recipe) && /Vector store/i.test(recipe) && /History store/i.test(recipe), 'Recipe must distinguish LLM, embedding, vector, and history layers.');
  check('fastembed_regular_choice', /regular choice, not an emergency fallback/i.test(recipe), 'Recipe must present Local FastEmbed as a normal guided choice.');
  check('shared_provider_default', /default provider storage is shared per OS user/i.test(recipe), 'Recipe must document shared provider storage as the default.');
  check('shared_storage_not_python_runtime', /shared provider root is data storage, not a Python virtualenv/i.test(recipe), 'Recipe must distinguish shared provider storage from Python runtime.');
  check('operational_diagnostic_layers', /status[\s\S]+health --adapter live[\s\S]+list[\s\S]+add[\s\S]+search[\s\S]+recall/i.test(recipe), 'Recipe must distinguish offline status, live health, and operational live smoke layers.');
  check('fastembed_onnx_diagnostic', /fastembed_onnx_external_data_path_error/.test(recipe), 'Recipe must document FastEmbed ONNX model-cache diagnostics.');
  check('collection_dimension_guard', /Never reuse an OpenAI `1536`-dimension collection/i.test(recipe), 'Recipe must warn against OpenAI 1536 collection reuse for FastEmbed.');
  check('live_health', /memory-mem0\.js health --adapter live --json/.test(recipe), 'Recipe must include live health command.');
  check('live_add', /memory-mem0\.js add --adapter live --yes-live-memory/.test(recipe), 'Recipe must include explicit live add command.');
  check('live_search', /memory-mem0\.js search "advisory memory" --adapter live --yes-live-memory --json/.test(recipe), 'Recipe must include explicit live search command.');
  check('live_recall', /memory-mem0\.js recall "advisory memory" --adapter live --yes-live-memory --json/.test(recipe), 'Recipe must include explicit live recall command.');
  check('live_list', /memory-mem0\.js list --adapter live --yes-live-memory --json/.test(recipe), 'Recipe must include explicit live list command.');
  check('recall_guidance', /search\/recall returns advisory context/i.test(recipe), 'Recipe must include recall/search guidance.');
  check('advisory_boundary', /advisory-only/i.test(recipe) && /source_of_truth: false/i.test(recipe), 'Recipe must include advisory-only boundary.');
  check('external_write_warning', /external-memory write/i.test(recipe), 'Live write commands must be marked as external-memory write.');
  check('cookbook_readme_link', /09-mem0-live-memory\.md/.test(readme), 'Cookbook README must link to the Mem0 recipe.');
  check('no_missing_args', !/<[^>]+>/.test(recipe) && !/\bTODO\b/i.test(recipe), 'Commands must not require invented placeholder args.');
  check('mem0_install_command', pipInstallCommands.filter((line) => line === mem0InstallCommand).length === 1, `Recipe must include exactly one pinned Mem0 install command: ${mem0InstallCommand}`);
  check('optional_fastembed_command', pipInstallCommands.filter((line) => line === fastembedInstallCommand).length === 1, `Recipe must include exactly one optional local embedder install command: ${fastembedInstallCommand}`);
  check('install_command_allowlist', pipInstallCommands.every((line) => allowedPipInstallCommands.has(line)), `Recipe contains unsupported install commands: ${pipInstallCommands.filter((line) => !allowedPipInstallCommands.has(line)).join('; ') || 'none'}`);
  check('commands_present', commands.length > 0, 'Recipe must include node .knowledge/tools commands.');
  check('exact_node_command_set', expectedCommands.every((line) => commandLines.includes(line)) && commandLines.every((line) => expectedCommandSet.has(line)), `Recipe node commands must match the generated allowlist exactly. Unexpected: ${commandLines.filter((line) => !expectedCommandSet.has(line)).join('; ') || 'none'}`);
  for (const command of commands) {
    check('command_dispatch', recipeCommandExists(context, command), `Recipe command does not dispatch: ${command.line}`);
  }

  return {
    ok: failures.length === 0,
    action: 'validate_recipe',
    provider_id: manifest.id,
    recipe: displayPath(context, recipePath),
    checks_total: checksTotal,
    failures,
    commands_checked: commandLines,
    dispatch_checked_via_help: true,
    source_of_truth: false,
    trust_role: 'advisory_only',
    trust_effect: 'advisory_only'
  };
}

function contextCliArgs(context) {
  return [
    '--project-knowledge-root', context.projectKnowledgeRoot,
    '--system-root', context.systemRoot,
    '--target-root', context.targetRoot,
    '--state-root', context.stateRoot
  ];
}

function parseJsonResult(result) {
  try { return JSON.parse(String(result.stdout || '').trim() || '{}'); }
  catch {
    return {
      ok: false,
      status: 'error',
      diagnostic_code: 'unknown_live_adapter_error',
      error: String(result.stdout || result.stderr || '').trim().slice(0, 1000)
    };
  }
}

function runMem0LiveHealth(context, flags, config) {
  const args = [
    path.join(context.systemRoot, 'tools', 'memory-mem0.js'),
    'health',
    '--adapter', 'live',
    '--config', config.path,
    '--json',
    ...contextCliArgs(context)
  ];
  if (flags.python) args.push('--python', String(flags.python));
  if (flags.timeoutMs) args.push('--timeout-ms', String(flags.timeoutMs));
  if (flags.pythonTimeoutMs) args.push('--python-timeout-ms', String(flags.pythonTimeoutMs));
  const result = spawnSync(process.execPath, args, {
    cwd: context.targetRoot,
    env: {
      ...process.env,
      MEM0_TELEMETRY: process.env.MEM0_TELEMETRY || 'False',
      MEM0_TELEMETRY_SAMPLE_RATE: process.env.MEM0_TELEMETRY_SAMPLE_RATE || '0',
      MEM0_DIR: process.env.MEM0_DIR || path.dirname(config.path)
    },
    encoding: 'utf8',
    windowsHide: true,
    timeout: Number(flags.timeoutMs || 60000)
  });
  const parsed = parseJsonResult(result);
  if (result.error) {
    parsed.ok = false;
    parsed.status = 'error';
    parsed.diagnostic_code = result.error.code === 'ETIMEDOUT' ? 'live_operation_timeout' : 'unknown_live_adapter_error';
    parsed.error = result.error.message;
  }
  return parsed;
}

function firstRecommendedInstallCommand(liveHealth) {
  const commands = (liveHealth?.next_commands || []).filter((command) => /pip install mem0ai==/i.test(String(command)));
  return commands[0] || null;
}

function mem0EmbeddingProviderChoices() {
  return [
    {
      id: 'openai',
      label: 'OpenAI API',
      command: 'node .knowledge/tools/memory-provider.js configure-embeddings mem0-oss --embedder openai --model text-embedding-3-small --json',
      notes: [
        'simpler',
        'good quality',
        'requires OPENAI_API_KEY',
        'paid by API usage',
        'can fail with 429 insufficient_quota'
      ]
    },
    {
      id: 'fastembed',
      label: 'Local FastEmbed',
      command: 'node .knowledge/tools/memory-provider.js configure-embeddings mem0-oss --embedder fastembed --model sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2 --json',
      notes: [
        'free by API usage',
        'runs locally on CPU',
        'does not require GPU',
        'downloads a local model',
        'requires selecting a model and creating a separate Qdrant collection'
      ]
    }
  ];
}

function mem0EmbeddingProviderQuestion() {
  return {
    id: 'mem0_embedding_provider',
    required: true,
    question: 'Which backend should Mem0 use for embeddings?',
    choices: mem0EmbeddingProviderChoices(),
    layer_boundary: {
      llm_provider: 'separate Mem0 reasoning/extraction model',
      embedding_provider: 'OpenAI API or Local FastEmbed',
      vector_store: 'Qdrant; shared by default, project-local only by explicit request',
      history_store: 'SQLite; shared provider storage by default'
    }
  };
}

function setupMem0Provider(context, providerId, flags = {}, options = {}) {
  const manifest = findManifest(context, providerId, options);
  if (manifest.id !== 'mem0-oss') throw new Error(`setup is only implemented for mem0-oss, got ${manifest.id}`);
  const version = providerVersionPin(manifest);
  const receiptFile = receiptPath(context, manifest);
  let receipt = safeReadJson(receiptFile, null);
  let receiptAction = 'existing';
  if (!receipt) {
    recordInstall(context, manifest.id, { ...flags, version, yesIReviewedLicense: true }, options);
    receipt = safeReadJson(receiptFile, null);
    receiptAction = 'created';
  } else if (receipt.schema_version !== '3.3.0') {
    receipt = {
      ...receipt,
      schema_version: '3.3.0',
      migrated_at: nowIso(),
      migration_note: 'Mem0 install receipt schema migrated by setup; no install or network action was executed.'
    };
    writeJsonAtomic(receiptFile, receipt);
    receiptAction = 'migrated';
  }
  const recipe = writeMem0Recipe(context, manifest.id, options);
  const configExists = fs.existsSync(mem0ConfigPath(context, manifest));
  if (!configExists) {
    const question = mem0EmbeddingProviderQuestion();
    const status = statusProvider(context, manifest.id, { ...options, ...flags, write: true });
    return {
      ok: true,
      action: 'setup',
      provider_id: manifest.id,
      setup_status: 'needs_embedding_provider_choice',
      receipt_action: receiptAction,
      receipt_present: Boolean(receipt),
      receipt: displayPath(context, receiptFile),
      config: null,
      config_required: true,
      provider_choice_required: true,
      embedding_provider_question: question,
      next_questions: [question],
      next_commands: question.choices.map((choice) => choice.command),
      recipe: recipe.recipe,
      runtime_status_cache: displayPath(context, runtimeStatusPath(context, manifest)),
      live_checked: false,
      live_health: null,
      status,
      runtime_available: false,
      package_installed: false,
      agent_message: 'Mem0 is connected to .knowledge as advisory-only external memory',
      agent_facing: {
        text: [
          'Ask the user which Mem0 embedding backend to use before running live setup.',
          'Do not silently choose OpenAI API or Local FastEmbed.',
          `Question: ${question.question}`,
          `OpenAI command: ${question.choices[0].command}`,
          `Local FastEmbed command: ${question.choices[1].command}`,
          'After configure-embeddings, rerun: node .knowledge/tools/memory-provider.js setup mem0-oss --live --json',
          'Boundary: advisory-only.'
        ].join('\n'),
        boundary: 'advisory-only'
      },
      source_of_truth: false,
      trust_role: 'advisory_only',
      trust_effect: 'advisory_only'
    };
  }
  const config = ensureMem0RepoConfig(context, manifest, flags);
  const liveHealth = flags.live ? runMem0LiveHealth(context, flags, config) : null;
  const status = statusProvider(context, manifest.id, { ...options, ...flags, write: true });
  const runtimeAvailable = Boolean(liveHealth?.status === 'available' || status.runtime_available);
  const recommendedInstall = firstRecommendedInstallCommand(liveHealth);
  const setupStatus = runtimeAvailable
    ? 'connected'
    : recommendedInstall
    ? 'needs_runtime_install'
    : flags.live
    ? 'needs_runtime_attention'
    : 'configured_without_live_check';
  const addCommand = 'node .knowledge/tools/memory-mem0.js add --adapter live --yes-live-memory --text "Release note: Mem0 is advisory-only external memory" --scope repo --json';
  const searchCommand = 'node .knowledge/tools/memory-mem0.js search "advisory memory" --adapter live --yes-live-memory --json';
  const recallCommand = 'node .knowledge/tools/memory-mem0.js recall "advisory memory" --adapter live --yes-live-memory --json';
  const agentLines = [
    'Mem0 is connected to .knowledge as advisory-only external memory.',
    `Receipt: ${displayPath(context, receiptFile)}`,
    'Live operations do not run automatically.',
    `To add useful memory: ${addCommand}`,
    `To search memory: ${searchCommand}`,
    `To recall memory: ${recallCommand}`,
    'Boundary: advisory-only.'
  ];
  if (recommendedInstall && !runtimeAvailable) agentLines.splice(3, 0, `Recommended install: ${recommendedInstall}`);
  return {
    ok: true,
    action: 'setup',
    provider_id: manifest.id,
    setup_status: setupStatus,
    receipt_action: receiptAction,
    receipt_present: Boolean(receipt),
    receipt: displayPath(context, receiptFile),
    config: config.display_path,
    config_meta: config.meta_path,
    provider_scope: config.provider_scope,
    shared_provider_root: config.shared_provider_root,
    project_storage_key: config.project_storage_key,
    recipe: recipe.recipe,
    runtime_status_cache: displayPath(context, runtimeStatusPath(context, manifest)),
    live_checked: Boolean(flags.live),
    live_health: liveHealth,
    status,
    runtime_available: runtimeAvailable,
    package_installed: runtimeAvailable,
    recommended_command: recommendedInstall,
    next_commands: recommendedInstall && !runtimeAvailable ? [recommendedInstall] : [],
    agent_message: 'Mem0 is connected to .knowledge as advisory-only external memory',
    agent_facing: {
      text: agentLines.join('\n'),
      add_command: addCommand,
      search_command: searchCommand,
      recall_command: recallCommand,
      boundary: 'advisory-only'
    },
    source_of_truth: false,
    trust_role: 'advisory_only',
    trust_effect: 'advisory_only'
  };
}

function uninstallProvider(context, providerId, flags = {}, options = {}) {
  const manifest = findManifest(context, providerId, options);
  if (manifest.layer !== 'free_core') throw new Error(`${manifest.id} is not uninstallable from free core`);
  const dir = providerStateDir(context, manifest);
  const receipt = safeReadJson(receiptPath(context, manifest), {});
  const uninstall = {
    schema_version: '3.3.0',
    provider_id: manifest.id,
    uninstalled_at: nowIso(),
    uninstall_mode: 'manual_receipt',
    uninstall_executed: false,
    data_deleted: false,
    data_path: dir,
    source_of_truth: false,
    trust_effect: 'advisory_only',
    warnings: ['Provider data was preserved by default.']
  };
  if (flags.deleteData) {
    if (!under(dir, path.join(context.stateRoot, 'external_memory'))) {
      throw new Error(`Refusing to delete provider data outside stateRoot: ${dir}`);
    }
    fs.rmSync(dir, { recursive: true, force: true });
    uninstall.data_deleted = true;
    uninstall.warnings = ['Provider data directory under stateRoot was deleted because --delete-data was passed.'];
  } else {
    ensureDir(dir);
    writeJsonAtomic(uninstallReceiptPath(context, manifest), uninstall);
    if (receipt && Object.keys(receipt).length) {
      writeJsonAtomic(receiptPath(context, manifest), { ...receipt, enabled: false, uninstalled_at: uninstall.uninstalled_at });
    }
  }
  return {
    ok: true,
    action: 'uninstall_receipt_recorded',
    provider_id: manifest.id,
    uninstalled: false,
    data_deleted: uninstall.data_deleted,
    data_path: dir,
    receipt: uninstall.data_deleted ? null : displayPath(context, uninstallReceiptPath(context, manifest)),
    warnings: uninstall.warnings
  };
}

function migrateLegacy(context, options = {}) {
  const registry = safeReadJson(path.join(context.projectKnowledgeRoot, 'external_memory', 'registry.json'), { providers: {} });
  const found = detectLegacyClaude(context, registry);
  const migrated = [];
  const warnings = [];
  for (const item of found) {
    if (!item.path || !fs.existsSync(item.path)) continue;
    if (!under(item.path, context.stateRoot)) {
      warnings.push(`Legacy Claude MEM path is outside stateRoot; left untouched: ${item.path}`);
      continue;
    }
    ensureDir(item.path);
    const notePath = path.join(item.path, 'DEPRECATED.md');
    writeFileAtomic(notePath, LEGACY_DEPRECATION_TEXT);
    migrated.push(displayPath(context, notePath));
  }
  if (options.writeReport !== false) buildExternalMemoryReport(context, { write: true });
  return {
    ok: true,
    action: 'migrate_legacy',
    legacy_found: found.length,
    migration_notes_written: migrated,
    warnings
  };
}

function statusProvider(context, providerId, options = {}) {
  const id = normalizeProviderId(providerId);
  const report = buildExternalMemoryReport(context, { ...options, write: options.write !== false });
  const provider = [...report.providers, ...report.legacy_providers_detected].find((item) => normalizeProviderId(item.provider_id) === id || normalizeProviderId(item.provider) === id);
  if (!provider) throw new Error(`Unknown memory provider status: ${providerId}`);
  return provider;
}

function listProviders(context, options = {}) {
  const manifests = loadProviderManifests(context, options);
  return {
    ok: true,
    schema_version: '3.3.0',
    generated_at: nowIso(),
    mode: context.mode,
    providers: manifests.map((manifest) => ({
      id: manifest.id,
      display_name: manifest.display_name,
      layer: manifest.layer,
      type: manifest.type,
      recommended: Boolean(manifest.recommended),
      license_spdx: manifest.license?.spdx || 'unknown',
      version_pin: manifest.source?.version_pin || null,
      source_of_truth: false,
      trust_effect: 'advisory_only'
    }))
  };
}

module.exports = {
  normalizeProviderId,
  loadProviderManifests,
  findManifest,
  providerStateDir,
  receiptPath,
  previewProvider,
  recordInstall,
  recordUpdate,
  setupMem0Provider,
  configureMem0Embeddings,
  writeMem0Recipe,
  validateMem0Recipe,
  uninstallProvider,
  migrateLegacy,
  statusProvider,
  listProviders,
  buildExternalMemoryReport,
  detectLegacyClaude,
  sourceOfTruthPolicy,
  LEGACY_DEPRECATION_TEXT
};
