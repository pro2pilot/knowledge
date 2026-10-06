#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { spawnSync } = require('child_process');
const { ensureContainedDir, writeJsonAtomicContained, appendNdjsonContained, getAgentId, assertSafeContainedPath } = require('./lib/json-store');
const { withContainedLock } = require('./lib/contained-lock-manager');
const { LOCKS } = require('./lib/lock-policy');
const {
  reconcile: reconcileQueue,
  lifecycleById,
  canonicalPath,
  canonicalModule
} = require('./lib/queue-lifecycle');
const { resolveKnowledgeContext } = require('./lib/path-context');
const { appendTeamEvent } = require('./lib/team-store');
const { loadProviderManifests } = require('./lib/memory-providers');
const { systemVersion } = require('./lib/system-version');
const { granularFinding, severityCost, taskReadiness } = require('./lib/repair-on-touch');
const { canonicalWikiStatus } = require('./lib/wiki-status');

const context = resolveKnowledgeContext();
const repoRoot = context.targetRoot;
const knowledgeRoot = context.projectKnowledgeRoot;
const stateRoot = context.stateRoot;
const DOCTOR_LOCK = Object.freeze({
  context,
  rootKind: 'state',
  rootPath: stateRoot,
  lockName: 'doctor',
  purpose: LOCKS.doctor.purpose
});
const SCHEMA_VERSION = systemVersion();

function nowIso() { return new Date().toISOString(); }
function rel(abs, base = knowledgeRoot) {
  const fromBase = path.relative(base, abs).replace(/\\/g, '/');
  if (!fromBase.startsWith('..') && !path.isAbsolute(fromBase)) return fromBase;
  const fromState = path.relative(stateRoot, abs).replace(/\\/g, '/');
  if (!fromState.startsWith('..') && !path.isAbsolute(fromState)) return fromState;
  return path.basename(abs);
}
function stateArtifact(relPath) {
  const clean = String(relPath || '').replace(/\\/g, '/').replace(/^\/+/, '');
  if (context.mode === 'repo') return `.knowledge/${clean}`;
  return `.knowledge-team/repos/${context.repoId}/workspaces/${context.workspaceId}/state/${clean}`;
}
function documentRelative(abs) {
  const fromState = path.relative(stateRoot, abs).replace(/\\/g, '/');
  return fromState !== '..' && !fromState.startsWith('../') && !path.isAbsolute(fromState)
    ? fromState : path.relative(knowledgeRoot, abs).replace(/\\/g, '/');
}
function documentArtifact(abs) {
  const fromState = path.relative(stateRoot, abs).replace(/\\/g, '/');
  return fromState !== '..' && !fromState.startsWith('../') && !path.isAbsolute(fromState)
    ? stateArtifact(fromState) : `.knowledge/${path.relative(knowledgeRoot, abs).replace(/\\/g, '/')}`;
}
function exists(relPath) {
  const resolved = sourcePath(relPath);
  return Boolean(resolved && physicalFile(resolved.root, resolved.absolute));
}
function artifactExists(relPath) {
  if (exists(relPath)) return true;
  if (!safeRelative(relPath)) return false;
  return physicalFile(knowledgeRoot, path.join(knowledgeRoot, relPath));
}
function safeRelative(value) {
  if (typeof value !== 'string' || !value) return false;
  try { return canonicalPath(value) !== 'unknown'; } catch { return false; }
}
function physicalFile(root, absolute) {
  try {
    assertSafeContainedPath(root, absolute);
    return fs.lstatSync(absolute).isFile();
  } catch { return false; }
}
function sourcePath(value) {
  if (!safeRelative(value)) return null;
  const normalized = canonicalPath(value);
  const root = normalized.startsWith('.knowledge/') ? knowledgeRoot : repoRoot;
  return { root, absolute: path.join(root, normalized.replace(/^\.knowledge\//, '')) };
}
function object(value) { return value !== null && typeof value === 'object' && !Array.isArray(value); }
function documentShape(relative, value) {
  const pathList = (item, key) => item[key] === undefined ||
    (Array.isArray(item[key]) && item[key].every(safeRelative));
  const moduleEntry = (item) => {
    if (!object(item) || typeof item.module_id !== 'string') return false;
    try { canonicalModule(item.module_id); } catch { return false; }
    return (!item.card || safeRelative(item.card)) && pathList(item, 'key_files') && pathList(item, 'evidence_files');
  };
  const definitions = {
    'modules/module_registry.json': { modules: ['array', moduleEntry] },
    'freshness.json': { tracked_files: ['array', (item) => object(item) && safeRelative(item.path)], artifact_dependencies: ['object'], artifact_statuses: ['object'] },
    'maintenance/trust_report.json': { modules: ['object'] },
    'maintenance/wiki_lint_report.json': {},
    'maps/wiki_graph.json': {},
    'maps/file_criticality.json': { files: ['array', (item) => object(item) && safeRelative(item.path || item.file)] },
    'maintenance/external_memory_status.json': { providers: ['array', object], source_of_truth_policy: ['object'], legacy_providers_detected: ['array'] },
    'maintenance/secret_scan_report.json': { by_severity: ['object'] },
    'maintenance/stale_items.json': { items: ['array', object] },
    'maintenance/repair_queue.json': { queue: ['array', object] }
  };
  const definition = definitions[relative] || (/^modules\/.+\.json$/.test(relative)
    ? { key_files: ['array', safeRelative], evidence_files: ['array', safeRelative] } : null);
  if (!definition) return true;
  if (!object(value)) return false;
  for (const [key, [type, entry]] of Object.entries(definition)) {
    if (value[key] === undefined) continue;
    if (type === 'object' && !object(value[key])) return false;
    if (type === 'array' && (!Array.isArray(value[key]) || (entry && !value[key].every(entry)))) return false;
  }
  if (relative === 'maintenance/trust_report.json' && value.modules) {
    for (const key of ['trusted', 'near_trusted', 'routing_trusted', 'advisory_only', 'suspect', 'low_confidence']) {
      if (value.modules[key] === undefined) continue;
      if (!Array.isArray(value.modules[key]) || !value.modules[key].every((id) => {
        if (typeof id !== 'string') return false;
        try { canonicalModule(id); return true; } catch { return false; }
      })) return false;
    }
  }
  return true;
}
function issue(issues, severity, code, message, artifact = null, details = {}) {
  issues.push(granularFinding({
    severity,
    score_cost: severityCost(severity),
    code,
    message,
    artifact,
    ...details
  }));
}
function walk(dir, output = []) {
  if (!fs.existsSync(dir)) return output;
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const abs = path.join(dir, entry.name);
    const relative = rel(abs);
    if (relative.startsWith('.lock/') || relative.startsWith('locks/') || relative.startsWith('.runtime/') || relative.includes('.tmp-') || relative.includes('.bak-')) continue;
    if (entry.isDirectory()) walk(abs, output);
    else if (entry.isFile()) output.push(abs);
  }
  return output;
}
function safeJson(abs, issues, invalid = new Set()) {
  try {
    const value = JSON.parse(fs.readFileSync(abs, 'utf8').replace(/^\uFEFF/, ''));
    if (!documentShape(documentRelative(abs), value)) {
      invalid.add(abs);
      issue(issues, 'critical', 'invalid_artifact_shape', 'Knowledge artifact has an invalid data shape. Restore or repair it before maintenance.', documentArtifact(abs), { safe_during_current_task: false });
      return null;
    }
    return value;
  }
  catch (error) {
    invalid.add(abs);
    issue(issues, 'critical', 'invalid_json', `Invalid JSON: ${error.message}`, documentArtifact(abs), { safe_during_current_task: false });
    return null;
  }
}
function scoreFromIssues(issues) {
  return Math.max(0, 100 - issues.reduce((total, item) =>
    total + (Number.isFinite(Number(item.score_cost)) ? Number(item.score_cost) : severityCost(item.severity)), 0));
}
function statusFromScore(score, criticalCount) {
  return criticalCount === 0 && score >= 90 ? 'healthy' : 'usable_with_warnings';
}
function statusWithStructure(score, criticalCount, structuralStatus) {
  if (structuralStatus === 'structurally_broken') return 'structurally_broken';
  if (structuralStatus === 'usable_with_warnings') return 'usable_with_warnings';
  return statusFromScore(score, criticalCount);
}

function updateChecksEnabled() {
  const configPath = path.join(knowledgeRoot, 'config.yaml');
  if (!fs.existsSync(configPath)) return false;
  const lines = fs.readFileSync(configPath, 'utf8').split(/\r?\n/);
  let inUpdates = false;
  for (const line of lines) {
    if (/^updates:\s*$/.test(line)) { inUpdates = true; continue; }
    if (inUpdates && /^\S/.test(line) && line.trim()) return false;
    if (inUpdates && /^\s{2}enabled:\s*true\s*$/.test(line)) return true;
  }
  return false;
}

function runUpdateCheckAuto() {
  const script = path.join(knowledgeRoot, 'tools', 'check-updates.js');
  if (!fs.existsSync(script)) return null;
  const res = spawnSync(process.execPath, [script, '--auto', '--json'], { cwd: repoRoot, encoding: 'utf8', timeout: 10000 });
  if (res.status !== 0) return { status: 'check_failed', error: (res.stderr || '').trim() || `exit ${res.status}` };
  try { return JSON.parse((res.stdout || '').trim() || '{}'); }
  catch (error) { return { status: 'check_failed', error: `Invalid update check JSON: ${error.message}` }; }
}

function stagedRuntimeProviderFiles() {
  const res = spawnSync('git', ['-C', repoRoot, 'diff', '--cached', '--name-only'], {
    encoding: 'utf8',
    windowsHide: true,
    timeout: 5000
  });
  if (res.status !== 0) return [];
  return (res.stdout || '')
    .split(/\r?\n/)
    .map((line) => line.trim().replace(/\\/g, '/'))
    .filter(Boolean)
    .filter((file) => /(^|\/)\.knowledge\/external_memory\/(mem0|legacy|claude|claude_mem|claude-auto-memory)(\/|$)/i.test(file) ||
      /^external_memory\/(mem0|legacy|claude|claude_mem|claude-auto-memory)(\/|$)/i.test(file));
}

function collectStrings(value, out = []) {
  if (typeof value === 'string') out.push(value);
  else if (Array.isArray(value)) value.forEach((item) => collectStrings(item, out));
  else if (value && typeof value === 'object') Object.values(value).forEach((item) => collectStrings(item, out));
  return out;
}

function looksLikeSecret(value) {
  const text = String(value || '');
  if (!text || /^<.*>$/.test(text)) return false;
  return /(api[_-]?key|secret|token|password)\s*[:=]\s*['"]?[A-Za-z0-9_./+=-]{12,}/i.test(text) ||
    /\b(sk|pk|m0sk|pcsk|eyJ)[A-Za-z0-9_./+=-]{20,}\b/.test(text);
}

function legacyProjectRootKnowledgeBackups() {
  let entries = [];
  try { entries = fs.readdirSync(repoRoot, { withFileTypes: true }); } catch { return []; }
  return entries
    .filter((entry) => entry.isDirectory() && /^\.knowledge[_-]backup(?:[_-].*)?$/i.test(entry.name))
    .map((entry) => entry.name)
    .sort();
}

function doctorUnlocked(options = {}) {
  ensureContainedDir(stateRoot, path.join(stateRoot, 'maintenance'));
  const issues = [];
  const checks = [];
  const legacyBackups = legacyProjectRootKnowledgeBackups();
  checks.push({
    check: 'legacy_project_root_knowledge_backups',
    status: legacyBackups.length ? 'warn' : 'pass',
    count: legacyBackups.length,
    paths: legacyBackups
  });
  if (legacyBackups.length) {
    issue(
      issues,
      'low',
      'legacy_project_root_knowledge_backup',
      `${legacyBackups.length} legacy .knowledge backup director${legacyBackups.length === 1 ? 'y is' : 'ies are'} outside .knowledge state. They are excluded from discovery; verify the current update before archiving or removing them.`,
      legacyBackups[0]
    );
  }
  const projectRequired = [
    'project_index.json',
    'modules/module_registry.json',
    'maintenance/concurrency_policy.json',
    'maps/critical_paths.json',
    'evidence/file_facts.json',
    'wiki/index.md',
    'external_memory/registry.json',
    'external_memory/retrieval_policy.json',
    'models/memory-provider.schema.json',
    'models/external-memory-report.schema.json',
    'memory-providers/mem0/manifest.json',
    'memory-providers/pinecone/manifest.json'
  ];
  const stateRequired = [
    'freshness.json',
    'maintenance/trust_report.json',
    'maintenance/handoff_summary.json',
    'maintenance/routing_bundle.json',
    'maps/file_criticality.json',
    'maps/wiki_graph.json',
    'maintenance/wiki_lint_report.json'
  ];
  for (const file of projectRequired) {
    const ok = physicalFile(knowledgeRoot, path.join(knowledgeRoot, file));
    checks.push({ check: 'required_file', artifact: `.knowledge/${file}`, status: ok ? 'pass' : 'fail' });
    if (!ok) issue(issues, file.includes('routing_bundle') ? 'medium' : 'high', 'missing_required_file', `Missing required knowledge artifact: ${file}`, `.knowledge/${file}`);
  }
  for (const file of stateRequired) {
    const ok = physicalFile(stateRoot, path.join(stateRoot, file));
    const artifact = stateArtifact(file);
    checks.push({ check: 'runtime_file', artifact, status: ok ? 'pass' : 'warn' });
    if (!ok) issue(issues, 'medium', 'missing_runtime_file', `Missing runtime artifact: ${file}. Run the relevant flow to generate it.`, artifact);
  }

  const jsonFiles = Array.from(new Set([
    ...walk(knowledgeRoot),
    ...(stateRoot === knowledgeRoot ? [] : walk(stateRoot))
  ])).filter((abs) => abs.endsWith('.json'));
  const parsed = new Map();
  const invalidInputs = new Set();
  for (const abs of jsonFiles) parsed.set(abs, safeJson(abs, issues, invalidInputs));
  const projectJson = (relative, fallback) => parsed.get(path.join(knowledgeRoot, relative)) || fallback;
  const stateJson = (relative, fallback) => parsed.get(path.join(stateRoot, relative)) || fallback;
  checks.push({ check: 'json_parse', status: issues.some((i) => i.code === 'invalid_json') ? 'fail' : 'pass', files_checked: jsonFiles.length });
  checks.push({ check: 'artifact_shapes', status: issues.some((i) => i.code === 'invalid_artifact_shape') ? 'fail' : 'pass' });

  const registry = projectJson('modules/module_registry.json', { modules: [] });
  const modules = registry.modules || [];
  checks.push({ check: 'module_registry_non_empty', status: modules.length > 0 ? 'pass' : 'warn', modules: modules.length });
  if (modules.length === 0) issue(issues, 'medium', 'empty_module_registry', 'Module registry is empty. Run ingest-existing-project.js.', '.knowledge/modules/module_registry.json');
  if (!modules.some((m) => m.module_id === 'root')) issue(issues, 'medium', 'missing_root_module', 'Root module is missing; repository-level manifests may be poorly routed.', '.knowledge/modules/module_registry.json');

  for (const moduleInfo of modules) {
    if (!moduleInfo.card || !artifactExists(moduleInfo.card)) issue(issues, 'high', 'missing_module_card', `Module card is missing for ${moduleInfo.module_id}.`, moduleInfo.card || null);
    for (const file of [...(moduleInfo.key_files || []), ...(moduleInfo.evidence_files || [])]) {
      if (file && !exists(file)) issue(issues, 'medium', 'missing_module_referenced_file', `Module ${moduleInfo.module_id} references missing file ${file}.`, moduleInfo.card || null);
    }
  }

  const freshness = stateJson('freshness.json', { tracked_files: [] });
  const tracked = freshness.tracked_files || [];
  const missingTracked = tracked.filter((entry) => entry.path && !exists(entry.path));
  for (const entry of missingTracked) {
    issue(
      issues,
      'high',
      'tracked_file_missing',
      `Tracked file is missing: ${entry.path}.`,
      entry.path,
      {
        module_id: entry.module_id || 'root',
        affected_artifacts: [entry.path, '.knowledge/freshness.json'],
        repair_class: 'manual_review',
        required_checks: ['restore_or_remove_tracked_file', 'verify_module_evidence'],
        resolution_predicate: 'tracked_file_state_explicitly_resolved',
        safe_during_current_task: false
      }
    );
  }
  checks.push({ check: 'tracked_files_exist', status: missingTracked.length ? 'fail' : 'pass', tracked_files: tracked.length, missing: missingTracked.length });

  const missingPaths = new Set(missingTracked.map((entry) => entry.path));
  let changedSinceScan = 0;
  let pendingRecheck = 0;
  for (const entry of tracked) {
    if (missingPaths.has(entry.path)) continue;
    const resolved = sourcePath(entry.path);
    let currentHash = null;
    try { currentHash = crypto.createHash('sha256').update(fs.readFileSync(resolved.absolute)).digest('hex'); }
    catch { /* Unreadable files remain unverified. */ }
    const hashMismatch = currentHash !== entry.sha256 || !/^[a-f0-9]{64}$/.test(String(entry.sha256 || ''));
    const unresolved = entry.status !== 'clean';
    if (hashMismatch) changedSinceScan += 1;
    if (!hashMismatch && !unresolved) continue;
    pendingRecheck += 1;
    const moduleInfo = modules
      .filter((item) => [...(item.key_files || []), ...(item.evidence_files || [])].includes(entry.path))
      .sort((a, b) => String(b.path || '').length - String(a.path || '').length)[0];
    issue(issues, 'medium', 'tracked_file_needs_recheck',
      hashMismatch
        ? `Tracked file differs from its recorded hash or could not be read: ${entry.path}. Sync and verify current source and relevant tests.`
        : `Tracked file still requires verification: ${entry.path} (${entry.status}). Repeated scans do not recertify source.`,
      entry.path, {
        module_id: entry.module_id || moduleInfo?.module_id || 'root',
        // Freshness is the mutable detector projection. Recertification
        // updates it after verifying this source; requiring its pre-repair
        // bytes as an immutable KVR source would invalidate that very repair.
        affected_artifacts: [entry.path],
        repair_class: 'verify_on_touch'
      });
  }
  checks.push({ check: 'tracked_files_current', status: pendingRecheck ? 'warn' : 'pass', tracked_files: tracked.length, changed_since_scan: changedSinceScan, pending_recheck: pendingRecheck });

  const trust = stateJson('maintenance/trust_report.json', {});
  const suspectModules = ((trust.modules || {}).suspect || []).map((module_id) => ({ module_id, trust_status: 'suspect' }));
  const lowModules = ((trust.modules || {}).low_confidence || []).map((module_id) => ({ module_id, trust_status: 'low_confidence' }));
  const uncertainModules = [...suspectModules, ...lowModules];
  const suspectCount = uncertainModules.length;
  const moduleById = new Map(modules.map((item) => [item.module_id, item]));
  for (const uncertain of uncertainModules) {
    const moduleInfo = moduleById.get(uncertain.module_id) || {};
    const card = moduleInfo.card || `.knowledge/modules/${uncertain.module_id}.json`;
    const primaryArtifact = (moduleInfo.key_files || [])[0] || card;
    const affected = Array.from(new Set([
      primaryArtifact,
      card,
      ...(moduleInfo.key_files || []),
      ...(moduleInfo.evidence_files || [])
    ]));
    issue(
      issues,
      'medium',
      uncertain.trust_status === 'low_confidence' ? 'low_confidence_module' : 'suspect_module',
      `Module ${uncertain.module_id} is ${uncertain.trust_status}; current source and relevant tests must be verified before behavior claims.`,
      primaryArtifact,
      {
        module_id: uncertain.module_id,
        affected_artifacts: affected,
        repair_class: 'verify_on_touch',
        required_checks: ['read_current_source', 'run_relevant_tests', 'compare_existing_claims'],
        resolution_predicate: 'source_and_relevant_tests_confirm_claim',
        safe_during_current_task: true
      }
    );
  }
  checks.push({ check: 'trust_report_present', status: trust.generated_at ? 'pass' : 'warn', generated_at: trust.generated_at || null, suspect_or_low_modules: suspectCount });

  const wikiLint = stateJson('maintenance/wiki_lint_report.json', {});
  const graph = stateJson('maps/wiki_graph.json', {});
  const wikiStructuralStatus = canonicalWikiStatus(wikiLint, graph);
  if (wikiStructuralStatus === 'structurally_broken') issue(issues, 'medium', 'wiki_structurally_broken', 'Wiki graph is structurally broken.', '.knowledge/maintenance/wiki_lint_report.json', { affected_artifacts: ['.knowledge/maintenance/wiki_lint_report.json', '.knowledge/maps/wiki_graph.json'] });
  else if (wikiStructuralStatus !== 'healthy') issue(issues, 'low', 'wiki_lint_has_warnings', `Wiki canonical status is ${wikiStructuralStatus}.`, '.knowledge/maintenance/wiki_lint_report.json', { affected_artifacts: ['.knowledge/maintenance/wiki_lint_report.json', '.knowledge/maps/wiki_graph.json'] });
  checks.push({
    check: 'wiki_lint_report',
    status: wikiLint.generated_at ? 'pass' : 'warn',
    aggregate_status: wikiStructuralStatus,
    reported_status: wikiLint.status || null,
    quality_score: wikiLint.quality_score ?? null,
    structural_status: wikiStructuralStatus,
    reported_structural_status: wikiLint.structural_status || null
  });
  if ((graph.broken_edge_count || 0) > 0) issue(issues, 'medium', 'broken_wiki_edges', `${graph.broken_edge_count} broken wiki graph edges.`, '.knowledge/maps/wiki_graph.json');
  checks.push({ check: 'wiki_graph', status: graph.generated_at ? 'pass' : 'warn', nodes: graph.node_count || 0, edges: graph.edge_count || 0, broken_edges: graph.broken_edge_count || 0, structural_status: wikiStructuralStatus });

  const externalStatusPath = path.join(stateRoot, 'maintenance', 'external_memory_status.json');
  if (!fs.existsSync(externalStatusPath)) { try { require(path.join(context.systemRoot, 'tools', 'external-memory-status.js'))({ skipLock: true, quiet: true }); } catch {} }
  if (!parsed.has(externalStatusPath) && physicalFile(stateRoot, externalStatusPath)) parsed.set(externalStatusPath, safeJson(externalStatusPath, issues, invalidInputs));
  const externalStatus = stateJson('maintenance/external_memory_status.json', {});
  checks.push({ check: 'external_memory_status', status: externalStatus.generated_at ? 'pass' : 'warn', providers: externalStatus.providers || [] });
  let manifests = [];
  try { manifests = loadProviderManifests(context).filter((manifest) => manifest.layer === 'free_core'); }
  catch (error) { issue(issues, 'high', 'memory_provider_manifest_invalid', 'Memory provider manifests could not be loaded; inspect their JSON and required fields.', '.knowledge/memory-providers/'); }
  const manifestById = new Map(manifests.map((manifest) => [manifest.id, manifest]));
  const mem0Manifest = manifestById.get('mem0-oss');
  checks.push({ check: 'memory_provider_manifest_mem0', status: mem0Manifest ? 'pass' : 'fail', artifact: '.knowledge/memory-providers/mem0/manifest.json' });
  if (!mem0Manifest) issue(issues, 'high', 'mem0_manifest_missing', 'Mem0 OSS manifest is missing.', '.knowledge/memory-providers/mem0/manifest.json');
  for (const manifest of manifests) {
    const artifact = `.knowledge/${rel(manifest.manifest_path)}`;
    const license = manifest.license?.spdx || 'unknown';
    const sourceOfTruth = manifest.trust_policy?.source_of_truth === true || manifest.trust_policy?.can_raise_trust === true || manifest.trust_policy?.can_overwrite_curated_knowledge === true;
    if (!license || license === 'unknown') issue(issues, 'medium', 'memory_provider_unknown_license', `${manifest.id} has unknown license.`, artifact);
    if (manifest.id === 'mem0-oss' && !manifest.source?.version_pin) issue(issues, 'medium', 'memory_provider_missing_version_pin', 'Mem0 OSS must keep a pinned package version.', artifact);
    if (sourceOfTruth) issue(issues, 'high', 'external_memory_trust_policy_violation', `${manifest.id} may raise trust or become source-of-truth.`, artifact);
    if (collectStrings(manifest).some(looksLikeSecret)) issue(issues, 'high', 'memory_provider_secret_in_manifest', `${manifest.id} manifest appears to contain a secret-like value.`, artifact);
  }
  const sourcePolicy = externalStatus.source_of_truth_policy || {};
  const sourcePolicyOk = sourcePolicy.external_memory_source_of_truth === false &&
    sourcePolicy.external_memory_can_raise_trust === false &&
    sourcePolicy.external_memory_can_overwrite_curated_knowledge === false;
  checks.push({ check: 'memory_source_of_truth_policy', status: sourcePolicyOk ? 'pass' : 'fail', source_of_truth_policy: sourcePolicy });
  if (!sourcePolicyOk) issue(issues, 'high', 'external_memory_source_of_truth_policy_broken', 'External memory policy must be advisory-only and unable to raise trust.', '.knowledge/maintenance/external_memory_status.json');
  const legacyClaude = externalStatus.legacy_providers_detected || [];
  checks.push({ check: 'legacy_claude_mem', status: legacyClaude.length ? 'warn' : 'pass', detected: legacyClaude.length });
  if (legacyClaude.length) issue(issues, 'low', 'legacy_claude_mem_found', 'Legacy Claude MEM artifacts found; treated as advisory-only legacy data.', '.knowledge/maintenance/external_memory_status.json');
  const mem0Status = (externalStatus.providers || []).find((provider) => provider.provider_id === 'mem0-oss') || {};
  checks.push({ check: 'mem0_status', status: mem0Status.status ? 'pass' : 'warn', provider_status: mem0Status.status || 'unknown', installed: Boolean(mem0Status.installed), receipt_present: Boolean(mem0Status.receipt_present) });
  if (mem0Status.receipt_present && mem0Status.license_spdx !== 'Apache-2.0') issue(issues, 'medium', 'mem0_receipt_invalid_license', 'Mem0 install receipt must preserve Apache-2.0 license metadata.', '.knowledge/external_memory/mem0/install_receipt.json');
  const pineconeStatus = (externalStatus.providers || []).find((provider) => provider.provider_id === 'pinecone') || {};
  checks.push({ check: 'pinecone_provider_status', status: pineconeStatus.errors?.length ? 'warn' : 'pass', provider_status: pineconeStatus.status || 'unknown', mode: pineconeStatus.mode || 'disabled' });
  const stagedProviderFiles = stagedRuntimeProviderFiles();
  checks.push({ check: 'provider_runtime_state_not_staged', status: stagedProviderFiles.length ? 'warn' : 'pass', staged: stagedProviderFiles });
  if (stagedProviderFiles.length) issue(issues, 'medium', 'provider_runtime_state_staged', 'Provider runtime state is staged; keep runtime memory out of commits.', stagedProviderFiles[0]);

  if (updateChecksEnabled()) {
    const updateStatus = runUpdateCheckAuto();
    checks.push({
      check: 'update_check',
      status: updateStatus && updateStatus.status !== 'check_failed' ? 'pass' : 'warn',
      update_status: updateStatus ? updateStatus.status : 'unknown',
      current_version: updateStatus ? updateStatus.current_version : null,
      latest_version: updateStatus ? updateStatus.latest_version || null : null
    });
    if (updateStatus && updateStatus.status === 'update_available') issue(issues, 'low', 'update_available', `A newer .knowledge release is available: ${updateStatus.current_version} -> ${updateStatus.latest_version}.`, '.knowledge/maintenance/update_status.json');
    if (updateStatus && updateStatus.status === 'check_failed') issue(issues, 'low', 'update_check_failed', updateStatus.error || 'Update check failed.', '.knowledge/maintenance/update_status.json');
  }

  const searchIndexExists = physicalFile(stateRoot, path.join(stateRoot, 'search', 'index.json'));
  checks.push({ check: 'search_index', status: searchIndexExists ? 'pass' : 'warn', artifact: '.knowledge/search/index.json' });
  if (!searchIndexExists) issue(issues, 'low', 'search_index_missing', 'Search index is missing. Run build-search-index.js for token-efficient knowledge retrieval.', '.knowledge/search/index.json');

  const eventsDir = context.mode === 'team'
    ? path.join(context.teamRoot, 'repos', context.repoId, 'events')
    : path.join(stateRoot, 'maintenance', 'events');
  const eventsArtifact = context.mode === 'team'
    ? `.knowledge-team/repos/${context.repoId}/events/`
    : '.knowledge/maintenance/events/';
  checks.push({ check: 'append_only_events_dir', status: fs.existsSync(eventsDir) ? 'pass' : 'fail', artifact: eventsArtifact });
  if (!fs.existsSync(eventsDir)) issue(issues, 'medium', 'events_dir_missing', 'Append-only events directory is missing.', eventsArtifact);

  // doctor itself does not run the scan (keeps doctor fast and side-effect-free);
  // it just reports the latest run. Use `node .knowledge/tools/scan-secrets.js`
  // to refresh, or `--strict` in CI to block.
  const secretReportPath = path.join(stateRoot, 'maintenance', 'secret_scan_report.json');
  if (fs.existsSync(secretReportPath)) {
    const secretReport = stateJson('maintenance/secret_scan_report.json', {});
    checks.push({ check: 'secret_scan', status: secretReport.status === 'clean' ? 'pass' : 'warn', findings_total: secretReport.findings_total || 0, secret_scan_status: secretReport.status || 'unknown', generated_at: secretReport.generated_at || null });
    if ((secretReport.by_severity || {}).critical) issue(issues, 'critical', 'secret_scan_critical', `${secretReport.by_severity.critical} critical secret finding(s) in last scan.`, '.knowledge/maintenance/secret_scan_report.json');
    else if ((secretReport.by_severity || {}).high) issue(issues, 'high', 'secret_scan_high', `${secretReport.by_severity.high} high-severity secret finding(s) in last scan.`, '.knowledge/maintenance/secret_scan_report.json');
    else if ((secretReport.by_severity || {}).medium) issue(issues, 'medium', 'secret_scan_medium', `${secretReport.by_severity.medium} medium secret finding(s) in last scan.`, '.knowledge/maintenance/secret_scan_report.json');
  } else {
    checks.push({ check: 'secret_scan', status: 'warn', note: 'Never run. Run scan-secrets.js for a baseline.' });
    issue(issues, 'low', 'secret_scan_missing', 'No secret_scan_report.json. Run node .knowledge/tools/scan-secrets.js for a baseline.', '.knowledge/maintenance/secret_scan_report.json');
  }

  const criticality = stateJson('maps/file_criticality.json', {});
  const criticalFiles = new Set(
    (criticality.files || [])
      .filter((item) => item && (item.classification === 'critical' || item.criticality === 'critical' || item.level === 'critical'))
      .map((item) => String(item.path || item.file || '').replace(/\\/g, '/').replace(/^\.\//, '').toLowerCase())
  );
  const securityFiles = new Set((criticality.files || []).filter((item) => item.security_sensitive === true).map((item) => String(item.path || item.file || '').replace(/\\/g, '/')));
  for (const finding of issues) {
    if (finding.affected_artifacts.some((artifact) => criticalFiles.has(String(artifact).toLowerCase()))) {
      finding.critical_path = true;
    }
    if (/secret|security|auth(?:entication|orization)?/i.test(`${finding.code} ${finding.message}`) ||
        finding.affected_artifacts.some((artifact) => securityFiles.has(artifact) || /(^|\/)(?:auth(?:entication|orization)?|security|secrets?|credentials)(?=[\/._-]|$)/i.test(artifact))) {
      finding.security_sensitive = true;
    }
  }
  const staleItems = stateJson('maintenance/stale_items.json', { items: [] });
  const repairQueue = stateJson('maintenance/repair_queue.json', { queue: [] });
  let queueInputsValid = ['maintenance/stale_items.json', 'maintenance/repair_queue.json']
    .every((relative) => {
      const absolute = path.join(stateRoot, relative);
      if (invalidInputs.has(absolute)) return false;
      try { fs.lstatSync(absolute); } catch (error) { return error.code === 'ENOENT'; }
      if (physicalFile(stateRoot, absolute)) return true;
      issue(issues, 'critical', 'unsafe_queue_artifact', 'Queue state is not a contained physical file; preserve it for manual repair.', stateArtifact(relative), { safe_during_current_task: false });
      return false;
    });
  let currentLifecycle = new Map();
  if (queueInputsValid) {
    try { currentLifecycle = lifecycleById(staleItems, repairQueue); }
    catch (error) {
      queueInputsValid = false;
      issue(issues, 'critical', 'invalid_queue_state', 'Existing queue lifecycle identities are invalid; preserve and repair queue evidence before reconciliation.', stateArtifact('maintenance/stale_items.json'), { safe_during_current_task: false });
    }
  }
  const pendingTrustClosures = new Map(
    (options.pendingTrustClosures || [])
      .filter((item) =>
        item &&
        /^LC-[a-f0-9]{16}$/.test(String(item.lifecycle_id || '')) &&
        /^KVR-[a-f0-9]{64}$/.test(String(item.receipt_id || '')) &&
        /^[a-f0-9]{64}$/.test(String(item.receipt_sha256 || ''))
      )
      .map((item) => [String(item.lifecycle_id), item])
  );
  const preservedPendingClosures = [];
  const reconciliationIssues = issues.filter((item) => {
    const pending = pendingTrustClosures.get(item.lifecycle_id);
    if (
      !pending ||
      !['suspect_module', 'low_confidence_module'].includes(item.code)
    ) {
      return true;
    }
    const current = currentLifecycle.get(item.lifecycle_id);
    const evidence = current?.resolution_evidence || {};
    const preserve = Boolean(
      current &&
      ['closed', 'resolved'].includes(current.status) &&
      evidence.receipt_id === pending.receipt_id &&
      evidence.receipt_sha256 === pending.receipt_sha256 &&
      evidence.task_id === pending.task_id &&
      evidence.session_id === pending.session_id
    );
    if (preserve) preservedPendingClosures.push(item.lifecycle_id);
    return !preserve;
  });
  const criticalCount = reconciliationIssues
    .filter((i) => i.severity === 'critical').length;
  const score = scoreFromIssues(reconciliationIssues);
  const reportStatus = wikiStructuralStatus !== 'structurally_broken' && (pendingRecheck || missingTracked.length)
    ? 'usable_with_warnings' : statusWithStructure(score, criticalCount, wikiStructuralStatus);
  const report = {
    schema_version: SCHEMA_VERSION,
    generated_at: nowIso(),
    generated_by: getAgentId(),
    mode: context.mode,
    target_root: context.targetRoot,
    project_knowledge_root: context.projectKnowledgeRoot,
    state_root: context.stateRoot,
    quality_score: score,
    status: reportStatus,
    structural_status: wikiStructuralStatus,
    summary: `${reconciliationIssues.length} issue(s), ${criticalCount} critical, score ${score}/100.`,
    checks,
    issues: reconciliationIssues,
    findings: reconciliationIssues,
    global: {
      score,
      status: reportStatus !== 'healthy' ? reportStatus : reconciliationIssues.length ? 'healthy_with_debt' : 'healthy',
      findings_open: reconciliationIssues.length
    }
  };
  if (options.taskScope) {
    report.task_readiness = taskReadiness(
      reconciliationIssues,
      options.taskScope
    );
    report.deferred_unrelated_findings = report.task_readiness.excluded_unrelated_findings;
  }
  const queueProjection = queueInputsValid ? reconcileQueue({
    staleItems,
    repairQueue,
    findings: reconciliationIssues.map((item) => ({
      ...item,
      reason: item.message
    })),
    source: 'doctor',
    agentId: getAgentId(),
    timestamp: report.generated_at
  }) : { events: [] };
  report.pending_trust_closures_observed =
    preservedPendingClosures.sort();
  if (queueInputsValid) {
    writeJsonAtomicContained(path.join(stateRoot, 'maintenance', 'stale_items.json'), staleItems, stateRoot);
    writeJsonAtomicContained(path.join(stateRoot, 'maintenance', 'repair_queue.json'), repairQueue, stateRoot);
  }
  report.queue_reconciliation_status = queueInputsValid ? 'completed' : 'skipped_invalid_input';
  report.queue_transitions = queueProjection.events;
  writeJsonAtomicContained(path.join(stateRoot, 'maintenance', 'quality_report.json'), report, stateRoot);
  try { require(path.join(context.systemRoot, 'tools', 'build-routing-bundle.js'))({ skipLock: true, quiet: true }); }
  catch (error) {
    report.routing_bundle_refresh_error = error.message;
    writeJsonAtomicContained(path.join(stateRoot, 'maintenance', 'quality_report.json'), report, stateRoot);
  }
  appendTeamEvent(context, 'doctor_result', {
    status: report.status,
    quality_score: report.quality_score,
    issues_total: report.issues.length
  });
  if (queueProjection.events.length) appendNdjsonContained(path.join(stateRoot, 'maintenance', 'events', `${report.generated_at.slice(0, 10)}.ndjson`), { type: 'queue_lifecycle', source: 'doctor', generated_at: report.generated_at, agent_id: getAgentId(), transitions: queueProjection.events }, stateRoot);
  if (!options.quiet) console.log(JSON.stringify(report, null, 2));
  return report;
}

function main(options = {}) {
  if (options.skipLock) return doctorUnlocked(options);
  return withContainedLock(DOCTOR_LOCK, () => doctorUnlocked(options));
}

module.exports = main;
module.exports.__test = { statusFromScore, statusWithStructure };

if (require.main === module) {
  try { main({ quiet: process.argv.includes('--quiet') }); }
  catch (error) { console.error(error.stack || error.message); process.exit(1); }
}
