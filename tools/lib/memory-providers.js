'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');
const { spawnSync } = require('child_process');
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

function genericProviderStatus(context, manifest) {
  const dir = providerStateDir(context, manifest);
  const receipt = safeReadJson(receiptPath(context, manifest), null);
  const runtimeStatus = manifest.id === 'mem0-oss' ? safeReadJson(runtimeStatusPath(context, manifest), null) : null;
  const liveRuntimeOk = Boolean(
    runtimeStatus
    && (
      runtimeStatus.runtime_available === true
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
    ? 'available'
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
  return {
    provider_id: manifest.id,
    provider: manifest.id,
    provider_name: manifest.display_name || manifest.id,
    type: manifest.type || 'local',
    layer: manifest.layer,
    status,
    runtime_health: liveRuntimeOk ? 'ok' : (installExecuted ? 'unknown' : (manifest.id === 'mem0-oss' ? 'not_available' : 'unknown')),
    enabled: Boolean(liveRuntimeOk || (receipt?.enabled && installExecuted)),
    installed: packageInstalled,
    receipt_present: receiptPresent,
    runtime_available: liveRuntimeOk,
    package_installed: packageInstalled,
    configured: receiptPresent,
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
    setup_command: manifest.id === 'mem0-oss' ? 'node .knowledge/tools/memory-provider.js setup mem0-oss --live --json' : null,
    live_health_command: manifest.id === 'mem0-oss' ? 'node .knowledge/tools/memory-mem0.js health --adapter live --json' : null,
    live_add_command: manifest.id === 'mem0-oss' ? 'node .knowledge/tools/memory-mem0.js add --adapter live --yes-live-memory --text "Release note: Mem0 is advisory-only external memory" --scope repo --json' : null,
    live_search_command: manifest.id === 'mem0-oss' ? 'node .knowledge/tools/memory-mem0.js search "advisory memory" --adapter live --yes-live-memory --json' : null,
    live_recall_command: manifest.id === 'mem0-oss' ? 'node .knowledge/tools/memory-mem0.js recall "advisory memory" --adapter live --yes-live-memory --json' : null,
    live_list_command: manifest.id === 'mem0-oss' ? 'node .knowledge/tools/memory-mem0.js list --adapter live --yes-live-memory --json' : null,
    install_receipt_path: manifest.id === 'mem0-oss' ? displayPath(context, receiptPath(context, manifest)) : null,
    runtime_status_path: manifest.id === 'mem0-oss' ? displayPath(context, runtimeStatusPath(context, manifest)) : null,
    config_path: manifest.id === 'mem0-oss' && fs.existsSync(mem0ConfigPath(context, manifest)) ? displayPath(context, mem0ConfigPath(context, manifest)) : null,
    runtime_status_checked_at: runtimeStatus?.checked_at || null,
    last_live_health_check: runtimeStatus?.last_live_health_check || (runtimeStatus?.operation === 'health' ? runtimeStatus?.checked_at || null : null),
    diagnostic_code: runtimeStatus?.diagnostic_code || null,
    runtime_version: runtimeVersion,
    expected_runtime_version: expectedRuntimeVersion,
    runtime_version_matches_pin: runtimeVersionMatchesPin,
    selected_python: runtimeStatus?.selected_python || null,
    live_operations_require_explicit_consent: manifest.id === 'mem0-oss',
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
    schema_version: '3.2.6',
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
    schema_version: '3.2.6',
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
    schema_version: '3.2.6',
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
    schema_version: '3.2.6',
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

function ensureMem0RepoConfig(context, manifest) {
  const dir = providerStateDir(context, manifest);
  const configPath = mem0ConfigPath(context, manifest);
  const metaPath = mem0ConfigMetaPath(context, manifest);
  const qdrantPath = path.join(dir, 'qdrant');
  const historyDbPath = path.join(dir, 'history.db');
  ensureDir(dir);
  ensureDir(qdrantPath);

  const existing = safeReadJson(configPath, null);
  const existingVectorConfig = existing?.vector_store?.config || {};
  const collectionName = existingVectorConfig.collection_name || 'knowledge_mem0_openai_text_embedding_3_small_1536';
  const nextConfig = {
    vector_store: {
      provider: 'qdrant',
      config: {
        path: existingVectorConfig.path || qdrantPath,
        collection_name: collectionName
      }
    },
    history_db_path: existing?.history_db_path || historyDbPath
  };
  writeJsonAtomic(configPath, nextConfig);
  writeJsonAtomic(metaPath, {
    schema_version: '3.2.6',
    provider_id: manifest.id,
    generated_at: nowIso(),
    config_path: configPath,
    qdrant_path: nextConfig.vector_store.config.path,
    history_db_path: nextConfig.history_db_path,
    collection_name: collectionName,
    collection_policy: 'If embedding dimensions change, create a new collection name instead of reusing an existing Qdrant collection.',
    source_of_truth: false,
    trust_role: 'advisory_only',
    trust_effect: 'advisory_only'
  });
  return {
    path: configPath,
    display_path: displayPath(context, configPath),
    meta_path: displayPath(context, metaPath),
    qdrant_path: nextConfig.vector_store.config.path,
    history_db_path: nextConfig.history_db_path,
    collection_name: collectionName
  };
}

function renderMem0RecipeTemplate(context, manifest) {
  const templatePath = mem0RecipeTemplatePath(context);
  if (!fs.existsSync(templatePath)) throw new Error(`Mem0 recipe template missing: ${templatePath}`);
  ensureMem0RepoConfig(context, manifest);
  return fs.readFileSync(templatePath, 'utf8')
    .replace(/\{\{VERSION_PIN\}\}/g, providerVersionPin(manifest))
    .replace(/\{\{RECEIPT_PATH\}\}/g, canonicalMem0Path('install_receipt.json'))
    .replace(/\{\{CONFIG_PATH\}\}/g, canonicalMem0Path('config.json'))
    .replace(/\{\{RUNTIME_STATUS_PATH\}\}/g, canonicalMem0Path('runtime_status.json'))
    .replace(/\{\{DATA_PATH\}\}/g, canonicalMem0Path())
    .replace(/\{\{QDRANT_PATH\}\}/g, canonicalMem0Path('qdrant'))
    .replace(/\{\{HISTORY_DB_PATH\}\}/g, canonicalMem0Path('history.db'));
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
  check('no_ellipsis', !/\.\.\./.test(recipe), 'Recipe must not contain ellipsis commands.');
  check('receipt_path', recipe.includes(canonicalMem0Path('install_receipt.json')), 'Recipe must include install receipt path.');
  check('status_mem0', /memory-provider\.js status mem0-oss --json/.test(recipe), 'Recipe must include status mem0-oss.');
  check('status_all', /memory-provider\.js status-all --json/.test(recipe), 'Recipe must include status-all.');
  check('setup_flow', /memory-provider\.js setup mem0-oss --live --json/.test(recipe), 'Recipe must include one recommended setup flow.');
  check('single_setup_flow', setupFlowMatches.length === 1, `Recipe must contain exactly one recommended setup flow, found ${setupFlowMatches.length}.`);
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
  } else if (receipt.schema_version !== '3.2.6') {
    receipt = {
      ...receipt,
      schema_version: '3.2.6',
      migrated_at: nowIso(),
      migration_note: 'Mem0 install receipt schema migrated by setup; no install or network action was executed.'
    };
    writeJsonAtomic(receiptFile, receipt);
    receiptAction = 'migrated';
  }
  const config = ensureMem0RepoConfig(context, manifest);
  const recipe = writeMem0Recipe(context, manifest.id, options);
  const liveHealth = flags.live ? runMem0LiveHealth(context, flags, config) : null;
  const status = statusProvider(context, manifest.id, { ...options, write: true });
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
    'Mem0 подключен к .knowledge как advisory-only external memory.',
    `Receipt: ${displayPath(context, receiptFile)}`,
    'Live операции не запускаются автоматически.',
    `Для записи используй: ${addCommand}`,
    `Для поиска используй: ${searchCommand}`,
    `Для recall используй: ${recallCommand}`,
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
    recipe: recipe.recipe,
    runtime_status_cache: displayPath(context, runtimeStatusPath(context, manifest)),
    live_checked: Boolean(flags.live),
    live_health: liveHealth,
    status,
    runtime_available: runtimeAvailable,
    package_installed: runtimeAvailable,
    recommended_command: recommendedInstall,
    next_commands: recommendedInstall && !runtimeAvailable ? [recommendedInstall] : [],
    agent_message: 'Mem0 подключен к .knowledge как advisory-only external memory',
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
    schema_version: '3.2.6',
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
    schema_version: '3.2.6',
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
