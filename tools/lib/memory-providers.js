'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');
const {
  ensureDir,
  readJson,
  writeJsonAtomic,
  writeFileAtomic,
  getAgentId
} = require('./json-store');

const LEGACY_DEPRECATION_TEXT = `# Deprecated Claude MEM state

Claude MEM first-class bridge has been removed.
Use Mem0 OSS as the recommended universal optional memory provider.
Existing Claude MEM artifacts are treated as legacy advisory context only and are never used to raise trust.
`;

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

function receiptPath(context, manifest) {
  return path.join(providerStateDir(context, manifest), 'install_receipt.json');
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

function genericProviderStatus(context, manifest) {
  const dir = providerStateDir(context, manifest);
  const receipt = safeReadJson(receiptPath(context, manifest), null);
  const mem0Adapter = manifest.id === 'mem0-oss' ? readMem0AdapterSummary(dir) : null;
  const status = receipt?.install_executed === true
    ? (receipt.enabled === false ? 'disabled' : 'installed')
    : (manifest.id === 'mem0-oss' ? 'runtime_not_installed' : 'available');
  const warnings = [];
  if (receipt && receipt.install_executed !== true) {
    warnings.push('Install approval receipt exists, but .knowledge did not execute the package install.');
  }
  if (manifest.id === 'mem0-oss') warnings.push('Mem0 runtime is optional; status/report mode does not import Python packages or run network installs.');
  if (manifest.install?.requires_network) warnings.push('Install/update requires explicit user action and may use network outside status/report mode.');
  if (manifest.type === 'optional') warnings.push('Provider implementation is optional and is not bundled into free core.');
  return {
    provider_id: manifest.id,
    provider: manifest.id,
    provider_name: manifest.display_name || manifest.id,
    type: manifest.type || 'local',
    layer: manifest.layer,
    status,
    runtime_health: receipt?.install_executed === true ? 'unknown' : (manifest.id === 'mem0-oss' ? 'not_available' : 'unknown'),
    enabled: Boolean(receipt?.enabled && receipt?.install_executed === true),
    installed: Boolean(receipt?.install_executed === true),
    receipt_present: Boolean(receipt),
    configured: Boolean(receipt),
    detected: fs.existsSync(dir),
    mode: manifest.install?.mode || 'manual',
    scope: manifest.data?.scope || 'repo',
    data_path: dir,
    path: dir,
    license_spdx: manifest.license?.spdx || 'unknown',
    version: receipt?.version || manifest.source?.version_pin || manifest.source?.version || null,
    version_pin: manifest.source?.version_pin || null,
    source_url: manifest.source?.homepage || manifest.source?.repository || manifest.source?.package || null,
    adapter_contract: manifest.id === 'mem0-oss' ? 'knowledge.memory_adapter.v1' : null,
    adapter_command: manifest.id === 'mem0-oss' ? 'node .knowledge/tools/memory-mem0.js health --json' : null,
    records_count: mem0Adapter?.records_count || 0,
    last_retrieval_count: mem0Adapter?.last_retrieval_count || 0,
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
      : genericProviderStatus(context, manifest)
  ));
  const providerOverrideAttempts = providers.reduce((sum, provider) => sum + Number(provider.override_attempts_blocked || 0), 0);
  const legacy = detectLegacyClaude(context, registry);
  const warnings = Array.from(new Set([
    ...providers.flatMap((provider) => provider.warnings || []),
    ...legacy.flatMap((provider) => provider.warnings || [])
  ]));
  const providerStatuses = Object.fromEntries(providers.map((provider) => [provider.provider_id.replace(/-/g, '_'), provider]));
  const metrics = {
    schema_version: '3.2.3',
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
    schema_version: '3.2.3',
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
    schema_version: '3.2.3',
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
  return {
    ok: true,
    action: 'install_receipt_recorded',
    provider_id: manifest.id,
    installed: false,
    receipt: displayPath(context, receiptPath(context, manifest)),
    data_path: dir,
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
    schema_version: '3.2.3',
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

function uninstallProvider(context, providerId, flags = {}, options = {}) {
  const manifest = findManifest(context, providerId, options);
  if (manifest.layer !== 'free_core') throw new Error(`${manifest.id} is not uninstallable from free core`);
  const dir = providerStateDir(context, manifest);
  const receipt = safeReadJson(receiptPath(context, manifest), {});
  const uninstall = {
    schema_version: '3.2.3',
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
    schema_version: '3.2.3',
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
  uninstallProvider,
  migrateLegacy,
  statusProvider,
  listProviders,
  buildExternalMemoryReport,
  detectLegacyClaude,
  sourceOfTruthPolicy,
  LEGACY_DEPRECATION_TEXT
};
