#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const {
  ensureDir,
  readJson,
  writeJsonAtomic,
  appendNdjson,
  normalizeRelative,
  getAgentId,
  withLock
} = require('./lib/json-store');
const { resolveKnowledgeContext } = require('./lib/path-context');

const context = resolveKnowledgeContext();
const repoRoot = context.targetRoot;
const knowledgeRoot = context.projectKnowledgeRoot;
const stateRoot = context.stateRoot;
const lockDir = path.join(stateRoot, '.lock');
const trigger = process.env.KNOWLEDGE_TRIGGER || (process.argv.includes('--scan') ? 'manual-scan' : 'manual');
const agentId = getAgentId();
const fullScan = process.argv.includes('--scan') || process.env.KNOWLEDGE_FULL_SCAN === '1';
const discoverNewFiles = process.argv.includes('--discover') || process.env.KNOWLEDGE_DISCOVER_NEW === '1' || !fullScan;

const paths = {
  freshness: path.join(stateRoot, 'freshness.json'),
  staleItems: path.join(stateRoot, 'maintenance', 'stale_items.json'),
  repairQueue: path.join(stateRoot, 'maintenance', 'repair_queue.json'),
  syncLog: path.join(stateRoot, 'maintenance', 'sync_log.json'),
  eventLogDir: path.join(stateRoot, 'maintenance', 'events'),
  activeTaskLegacy: path.join(stateRoot, 'sessions', 'active_task.json'),
  activeTasksDir: path.join(stateRoot, 'sessions', 'active_tasks'),
  moduleRegistry: path.join(knowledgeRoot, 'modules', 'module_registry.json'),
  contradictions: path.join(knowledgeRoot, 'contradictions.json'),
  fileCriticality: path.join(stateRoot, 'maps', 'file_criticality.json'),
  fileFacts: path.join(knowledgeRoot, 'evidence', 'file_facts.json'),
  criticalPaths: path.join(knowledgeRoot, 'maps', 'critical_paths.json'),
  trustReport: path.join(stateRoot, 'maintenance', 'trust_report.json'),
  automationStatus: path.join(stateRoot, 'maintenance', 'automation_status.json'),
  handoffSummary: path.join(stateRoot, 'maintenance', 'handoff_summary.json'),
  routingBundle: path.join(stateRoot, 'maintenance', 'routing_bundle.json')
};

const WATCHED_ROOTS = ['.'];
const IGNORED_SEGMENTS = ['.git', 'node_modules', '.claude', '.agents', '.opencode', '.vercel', '.knowledge', '.knowledge', '.next', '.turbo', '.cache', '.pytest_cache', '.mypy_cache', '.venv', 'venv', 'dist', 'build', 'coverage', 'target', 'bin', 'obj', 'dist-release', 'dist-installer', 'dist-release-fresh', 'runtime-seed', 'comfy_models', 'comfy_input', 'comfy_output', 'comfy_custom_nodes', 'pro2pilot-inspector', '.tmp'];
const SOURCE_EXTENSIONS = new Set(['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs', '.py', '.go', '.rs', '.java', '.kt', '.swift', '.rb', '.php', '.cs', '.sql', '.toml', '.yaml', '.yml', '.json', '.prisma']);

function exists(filePath) { return fs.existsSync(filePath); }
function isFile(filePath) {
  try { return fs.statSync(filePath).isFile(); } catch { return false; }
}
function isDirectory(filePath) {
  try { return fs.statSync(filePath).isDirectory(); } catch { return false; }
}
function resolveArtifactPath(relPath) {
  const raw = String(relPath || '');
  const clean = raw.replace(/^\.knowledge[\\/]/, '');
  const candidates = [
    path.join(repoRoot, raw),
    path.join(repoRoot, clean),
    path.join(knowledgeRoot, clean)
  ];
  return candidates.find((candidate) => fs.existsSync(candidate)) || candidates[0];
}
function nowIso() { return new Date().toISOString(); }
function sha256(filePath) { return crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex'); }
function safeReadJson(filePath, fallback) { return readJson(filePath, fallback); }
function limitArray(items, max) { return items.length > max ? items.slice(items.length - max) : items; }
function rel(filePath) { return path.relative(repoRoot, filePath).replace(/\\/g, '/'); }

function parseTouchedHint() {
  try {
    const parsed = JSON.parse(process.env.KNOWLEDGE_CHANGED_FILES || '[]');
    return Array.isArray(parsed) ? parsed.map(normalizeRelative).filter(Boolean) : [];
  } catch {
    return [];
  }
}

function isKnowledgeSourceCheckoutPath(pathStr) {
  const normalized = normalizeRelative(pathStr);
  if (!normalized) return false;
  const top = normalized.split('/')[0];
  if (!top || top.startsWith('.')) return false;
  const full = path.join(repoRoot, top);
  const lower = top.toLowerCase();
  const pkg = safeReadJson(path.join(full, 'package.json'), {}) || {};
  const hasKnowledgePackage = pkg.name === 'dot-knowledge' || pkg.name === 'knowledge' || /knowledge/.test(String(pkg.name || ''));
  const hasReleaseTool = isFile(path.join(full, 'tools', 'package-release.js'));
  const hasInstallManifest = isFile(path.join(full, 'install-manifest.json'));
  const hasQuickStart = isFile(path.join(full, 'Quick-Start.md'));
  const hasSourceGit = isDirectory(path.join(full, '.git'));
  return (
    lower === 'knowledge-src' ||
    lower.startsWith('knowledge-src') ||
    (hasKnowledgePackage && hasReleaseTool && hasInstallManifest) ||
    (hasSourceGit && hasReleaseTool && hasQuickStart)
  );
}

function isIgnored(pathStr) {
  const normalized = normalizeRelative(pathStr);
  if (isKnowledgeSourceCheckoutPath(normalized)) return true;
  if (normalized.split('/').some((part) => part.startsWith('.tmp-'))) return true;
  const parts = normalized.split('/');
  return IGNORED_SEGMENTS.some((segment) => parts.includes(segment));
}
function isDocPath(pathStr) {
  const normalized = normalizeRelative(pathStr);
  return /(^|\/)(readme|changelog|contributing|architecture|design|notes?)\.md$/i.test(normalized) || normalized.endsWith('.md');
}
function isTestPath(pathStr) {
  const normalized = normalizeRelative(pathStr);
  return /(^|\/)(test|tests|__tests__|spec|specs)(\/|$)/i.test(normalized) || /\.(test|spec)\.[^.]+$/i.test(normalized);
}
function getCriticality(pathStr) {
  const normalized = normalizeRelative(pathStr);
  if (!normalized || normalized.startsWith('..') || isIgnored(normalized)) return 'ignore';
  const ext = path.extname(normalized).toLowerCase();
  const base = path.posix.basename(normalized).toLowerCase();
  const isSourceLike = SOURCE_EXTENSIONS.has(ext);
  if (['package-lock.json', 'pnpm-lock.yaml', 'yarn.lock', 'bun.lockb', 'bun.lock', 'poetry.lock', 'cargo.lock'].includes(base)) return 'ignore';
  if (isDocPath(normalized) || isTestPath(normalized)) return 'contextual';
  if (/^\.github\/workflows\/.+\.(yml|yaml)$/i.test(normalized)) return 'important';
  if (/(^|\/)(migrations?|schema)(\/|$)/i.test(normalized) && ['.sql', '.prisma', '.json', '.js', '.ts', '.py'].includes(ext)) return /(initial|init|baseline|foundation|0001)/i.test(normalized) ? 'critical' : 'important';
  if (['dockerfile', 'compose.yaml', 'docker-compose.yml', 'docker-compose.yaml', 'package.json', 'pyproject.toml', 'requirements.txt', 'go.mod', 'cargo.toml', 'composer.json', 'gemfile', 'tsconfig.json', 'vite.config.ts', 'vite.config.js', 'next.config.js', 'next.config.mjs', 'next.config.ts', 'turbo.json', 'pnpm-workspace.yaml'].includes(base)) return 'important';
  if (!isSourceLike) return 'ignore';
  if (/(^|\/)(app\/api|api|server|backend|workers?|jobs?|queue|src\/server|src\/main)(\/|$)/i.test(normalized)) return 'important';
  if (isSourceLike) return 'important';
  return 'ignore';
}
function shouldAutoTrackNewFile(pathStr) { return getCriticality(pathStr) !== 'ignore'; }

function walkFiles(rootDir, maxFiles = 20000) {
  const out = [];
  const stack = [rootDir];
  while (stack.length && out.length < maxFiles) {
    const current = stack.pop();
    let entries = [];
    try { entries = fs.readdirSync(current, { withFileTypes: true }); } catch { continue; }
    for (const entry of entries) {
      const abs = path.join(current, entry.name);
      const relative = rel(abs);
      if (isIgnored(relative)) continue;
      if (entry.isDirectory()) stack.push(abs);
      else if (entry.isFile()) out.push(relative);
    }
  }
  return out;
}

function inferModule(pathStr, moduleRegistry) {
  const normalized = normalizeRelative(pathStr);
  const candidates = (moduleRegistry.modules || []).filter((moduleInfo) => {
    const modulePath = normalizeRelative(moduleInfo.path || '');
    if (!modulePath || modulePath === '.') return !normalized.includes('/');
    return normalized === modulePath.replace(/\/$/, '') || normalized.startsWith(modulePath.endsWith('/') ? modulePath : `${modulePath}/`);
  });
  candidates.sort((a, b) => String(b.path || '').length - String(a.path || '').length);
  return candidates[0]?.module_id || 'root';
}

function getModuleCardPath(moduleId, moduleRegistry) {
  const moduleInfo = (moduleRegistry.modules || []).find((entry) => entry.module_id === moduleId);
  return moduleInfo?.card || null;
}

function addUnique(list, value) {
  if (!list.includes(value)) list.push(value);
}

function addRepairItem(repairQueue, item) {
  repairQueue.queue = repairQueue.queue || [];
  if (repairQueue.queue.some((existing) => existing.subject === item.subject && JSON.stringify(existing.affected_artifacts || []) === JSON.stringify(item.affected_artifacts || []))) return;
  repairQueue.queue.push({ id: `RQ-${String(repairQueue.queue.length + 1).padStart(4, '0')}`, ...item });
}

function addStaleItem(staleItems, item) {
  staleItems.items = staleItems.items || [];
  if (staleItems.items.some((existing) => existing.artifact === item.artifact && existing.reason === item.reason && existing.status !== 'resolved')) return;
  staleItems.items.push({ id: `STALE-${String(staleItems.items.length + 1).padStart(4, '0')}`, ...item });
}

function updateActiveTasks(timestamp, note) {
  ensureDir(paths.activeTasksDir);
  const agentTaskPath = path.join(paths.activeTasksDir, `${agentId.replace(/[^a-zA-Z0-9_.-]/g, '_')}.json`);
  const task = safeReadJson(agentTaskPath, {
    task_id: agentId,
    agent_id: agentId,
    status: 'in_progress',
    started_at: timestamp,
    updated_at: timestamp,
    goal: 'Agent-local maintenance session',
    relevant_modules: [],
    files_read: [],
    notes: []
  });
  if (task.status !== 'completed') {
    task.agent_id = task.agent_id || agentId;
    task.updated_at = timestamp;
    task.notes = task.notes || [];
    task.notes.push(note);
    task.notes = limitArray(task.notes, 200);
    writeJsonAtomic(agentTaskPath, task);
  }

  const legacy = safeReadJson(paths.activeTaskLegacy, null);
  if (legacy && legacy.status !== 'completed') {
    legacy.updated_at = timestamp;
    legacy.notes = legacy.notes || [];
    legacy.notes.push(`[${agentId}] ${note}`);
    legacy.notes = limitArray(legacy.notes, 200);
    writeJsonAtomic(paths.activeTaskLegacy, legacy);
  }
}

function mainUnlocked() {
  const timestamp = nowIso();
  const freshness = safeReadJson(paths.freshness, { generated_at: null, hash_algorithm: 'sha256', tracked_files: [], artifact_dependencies: {}, artifact_statuses: {} });
  const staleItems = safeReadJson(paths.staleItems, { generated_at: null, items: [] });
  const repairQueue = safeReadJson(paths.repairQueue, { generated_at: null, queue: [] });
  const syncLog = safeReadJson(paths.syncLog, { generated_at: null, entries: [] });
  const contradictions = safeReadJson(paths.contradictions, { generated_at: null, items: [] });
  const moduleRegistry = safeReadJson(paths.moduleRegistry, { generated_at: null, modules: [] });
  const fileCriticality = safeReadJson(paths.fileCriticality, { generated_at: null, files: [], coverage_by_module: {} });
  const fileFacts = safeReadJson(paths.fileFacts, { generated_at: null, facts: [] });
  const criticalPaths = safeReadJson(paths.criticalPaths, { generated_at: null, paths: [] });
  const automationStatus = safeReadJson(paths.automationStatus, { mode: 'event-driven' });
  const handoffSummary = safeReadJson(paths.handoffSummary, {
    schema_version: '3.2.4',
    generated_at: null,
    generated_by: null,
    project_operational_summary: 'Generated handoff summary for the current .knowledge state.',
    trusted_modules: [],
    near_trusted_modules: [],
    routing_only_modules: [],
    non_authoritative_modules: [],
    highest_risk_modules: [],
    next_agent_first_reads: [
      '.knowledge/maintenance/routing_bundle.json',
      '.knowledge/maintenance/trust_report.json',
      '.knowledge/maintenance/quality_report.json'
    ]
  });
  let routingBundleSummary = null;

  freshness.tracked_files = freshness.tracked_files || [];
  freshness.artifact_dependencies = freshness.artifact_dependencies || {};
  fileCriticality.files = fileCriticality.files || [];
  fileCriticality.coverage_by_module = fileCriticality.coverage_by_module || {};

  const touchedHint = parseTouchedHint();
  const candidateFiles = new Set(touchedHint);
  if (fullScan) for (const file of walkFiles(repoRoot)) candidateFiles.add(file);

  const trackedPaths = new Set(freshness.tracked_files.map((entry) => entry.path));
  const changedFiles = [];
  const missingFiles = [];
  const newFiles = [];
  const criticalityByPath = new Map((fileCriticality.files || []).map((file) => [file.path, file.classification]));

  for (const rawPath of candidateFiles) {
    const relPath = normalizeRelative(rawPath);
    const abs = path.join(repoRoot, relPath);
    const classification = getCriticality(relPath);
    if (classification === 'ignore') continue;
    if (discoverNewFiles && !trackedPaths.has(relPath) && exists(abs) && shouldAutoTrackNewFile(relPath)) {
      const moduleId = inferModule(relPath, moduleRegistry);
      freshness.tracked_files.push({ path: relPath, sha256: sha256(abs), last_scanned_at: timestamp, status: classification === 'contextual' ? 'clean' : 'needs_recheck', first_seen_by: agentId, first_seen_at: timestamp });
      trackedPaths.add(relPath);
      newFiles.push({ path: relPath, module_id: moduleId, classification });
      if (!fileCriticality.files.some((file) => file.path === relPath)) {
        fileCriticality.files.push({ path: relPath, classification, modules: moduleId ? [moduleId] : [], source: fullScan ? 'auto_scan' : 'auto_detected', first_seen_by: agentId });
        criticalityByPath.set(relPath, classification);
      }
      if (moduleId) {
        const coverage = fileCriticality.coverage_by_module[moduleId] || { important_or_critical_files: [], tracked_in_freshness: [], referenced_by_module_card: [], covered_by_evidence: [], uncovered: [] };
        if (['critical', 'important'].includes(classification)) addUnique(coverage.important_or_critical_files, relPath);
        addUnique(coverage.tracked_in_freshness, relPath);
        if (['critical', 'important'].includes(classification)) addUnique(coverage.uncovered, relPath);
        fileCriticality.coverage_by_module[moduleId] = coverage;
      }
      if (moduleId && ['critical', 'important'].includes(classification)) {
        const cardPath = getModuleCardPath(moduleId, moduleRegistry);
        if (cardPath) {
          addStaleItem(staleItems, { artifact: cardPath, status: 'needs_recheck', reason: `New ${classification} file detected: ${relPath}`, linked_contradictions: [], detected_by: agentId, detected_at: timestamp });
          addRepairItem(repairQueue, { priority: classification === 'critical' ? 'high' : 'medium', subject: `Cover new ${classification} file ${relPath}`, affected_artifacts: [cardPath, '.knowledge/maps/file_criticality.json', '.knowledge/evidence/file_facts.json'], detected_by: agentId, detected_at: timestamp });
        }
      }
    }
  }

  for (const entry of freshness.tracked_files) {
    trackedPaths.add(entry.path);
    const abs = path.join(repoRoot, entry.path);
    if (!exists(abs)) {
      entry.status = 'missing';
      entry.last_scanned_at = timestamp;
      missingFiles.push(entry.path);
      continue;
    }
    const nextHash = sha256(abs);
    if (nextHash !== entry.sha256) {
      entry.previous_sha256 = entry.sha256;
      entry.sha256 = nextHash;
      entry.status = 'changed';
      entry.reason = 'File content hash changed since previous scan.';
      entry.last_scanned_at = timestamp;
      entry.last_changed_by = agentId;
      changedFiles.push(entry.path);
    } else {
      entry.status = ['suspect', 'needs_recheck'].includes(entry.status) ? entry.status : 'clean';
      if (entry.status === 'clean') delete entry.reason;
      entry.last_scanned_at = timestamp;
    }
  }

  const artifactStatuses = freshness.artifact_statuses || {};
  const touchedArtifacts = new Set();
  for (const [artifact, deps] of Object.entries(freshness.artifact_dependencies || {})) {
    const affected = (deps || []).filter((dep) => changedFiles.includes(dep) || missingFiles.includes(dep) || newFiles.some((newFile) => newFile.path === dep));
    if (affected.length > 0) {
      artifactStatuses[artifact] = { status: 'needs_recheck', updated_at: timestamp, affected_files: affected, detected_by: agentId };
      touchedArtifacts.add(artifact);
    }
  }

  freshness.generated_at = timestamp;
  freshness.artifact_statuses = artifactStatuses;
  staleItems.generated_at = timestamp;
  repairQueue.generated_at = timestamp;
  fileCriticality.generated_at = timestamp;

  const evidenceCovered = new Set((fileFacts.facts || []).map((fact) => fact.file));
  const openContradictions = (contradictions.items || []).filter((item) => item.status === 'open');
  const highSeverity = openContradictions.filter((item) => item.severity === 'high');
  const staleArtifactsTotal = (staleItems.items || []).filter((item) => item.status === 'needs_recheck' || item.status === 'partial').length;

  const moduleTrust = [];
  for (const moduleInfo of moduleRegistry.modules || []) {
    let card = null;
    try { card = readJson(resolveArtifactPath(moduleInfo.card)); } catch { card = null; }
    if (!card) {
      moduleTrust.push({ module_id: moduleInfo.module_id, confidence: 'low', freshness_status: 'missing_card', trust_status: 'low_confidence', reasons: { missing_card: moduleInfo.card } });
      continue;
    }
    const keyFiles = Array.from(new Set([...(card.key_files || []), ...(card.evidence_files || [])]));
    const criticalFiles = keyFiles.filter((file) => getCriticality(file) === 'critical');
    const importantFiles = keyFiles.filter((file) => ['critical', 'important'].includes(getCriticality(file)));
    const criticalTrackingComplete = criticalFiles.every((file) => trackedPaths.has(file));
    const criticalEvidenceComplete = criticalFiles.every((file) => evidenceCovered.has(file));
    const uncoveredImportant = importantFiles.filter((file) => !evidenceCovered.has(file));
    const changedOrMissingImportant = freshness.tracked_files.filter((file) => importantFiles.includes(file.path) && ['changed', 'missing', 'suspect', 'needs_recheck'].includes(file.status));
    const contradictionTouch = openContradictions.filter((item) => (item.sources || []).some((source) => keyFiles.includes(source.file)));
    const pathTouches = (criticalPaths.paths || []).filter((criticalPath) => (criticalPath.modules || []).includes(moduleInfo.module_id));
    const allGapPaths = pathTouches.length > 0 && pathTouches.every((criticalPath) => (criticalPath.test_linkage?.status || 'gap') === 'gap');
    const anyPartialOrBetter = pathTouches.some((criticalPath) => ['verified', 'partial'].includes(criticalPath.test_linkage?.status || ''));
    const freshnessStatus = (changedOrMissingImportant.length > 0 || artifactStatuses[moduleInfo.card]?.status === 'needs_recheck') ? 'suspect' : 'fresh';
    const verificationStatus = String(card.verification_status || '');
    const docsOnly = /placeholder|unknown|docs-only|partial_from_docs_only/i.test(verificationStatus);
    const advisoryTarget = card.target_trust_level === 'advisory_only';
    let trustStatus = 'trusted';
    if (advisoryTarget) trustStatus = 'advisory_only';
    else if (card.confidence === 'low' || docsOnly) trustStatus = 'low_confidence';
    else if (freshnessStatus !== 'fresh' || contradictionTouch.length > 0 || !criticalTrackingComplete || !criticalEvidenceComplete || uncoveredImportant.length > 0 || (allGapPaths && pathTouches.length > 0)) trustStatus = 'suspect';
    else if (pathTouches.length > 0 && !anyPartialOrBetter) trustStatus = 'near_trusted';
    else if (criticalFiles.length > 0 || importantFiles.length > 0) trustStatus = 'trusted';
    else trustStatus = 'routing_trusted';
    moduleTrust.push({ module_id: moduleInfo.module_id, confidence: card.confidence, freshness_status: freshnessStatus, trust_status: trustStatus, reasons: { changed_or_missing_important_files: changedOrMissingImportant.map((file) => file.path), open_contradictions: contradictionTouch.map((item) => item.id), uncovered_important_files: uncoveredImportant } });
  }

  const grouped = (status) => moduleTrust.filter((moduleInfo) => moduleInfo.trust_status === status).map((moduleInfo) => moduleInfo.module_id);
  const trustedModules = grouped('trusted');
  const nearTrustedModules = grouped('near_trusted');
  const routingTrustedModules = grouped('routing_trusted');
  const advisoryOnlyModules = grouped('advisory_only');
  const suspectModules = grouped('suspect');
  const lowModules = grouped('low_confidence');
  const modulesFresh = moduleTrust.filter((moduleInfo) => moduleInfo.freshness_status === 'fresh').length;
  const criticalFiles = fileCriticality.files.filter((file) => file.classification === 'critical');
  const criticalPathsWithTests = (criticalPaths.paths || []).filter((criticalPath) => ['verified', 'partial'].includes(criticalPath.test_linkage?.status || '')).length;
  const uncoveredImportantFiles = moduleTrust.flatMap((moduleInfo) => (moduleInfo.reasons.uncovered_important_files || []).map((file) => ({ module_id: moduleInfo.module_id, file })));

  const trustReport = {
    generated_at: timestamp,
    generated_by: agentId,
    concurrency_mode: 'locked_atomic_writes',
    modules_total: (moduleRegistry.modules || []).length,
    modules_fresh: modulesFresh,
    modules_low_confidence: lowModules.length,
    critical_files_total: criticalFiles.length,
    critical_files_tracked: criticalFiles.filter((file) => trackedPaths.has(file.path)).length,
    evidence_covered_files: Array.from(evidenceCovered).filter((file) => fileCriticality.files.some((criticalityFile) => criticalityFile.path === file)).length,
    critical_paths_total: (criticalPaths.paths || []).length,
    critical_paths_with_test_linkage: criticalPathsWithTests,
    open_contradictions_total: openContradictions.length,
    high_severity_contradictions_total: highSeverity.length,
    stale_artifacts_total: staleArtifactsTotal,
    uncovered_important_files: uncoveredImportantFiles,
    modules: { trusted: trustedModules, near_trusted: nearTrustedModules, routing_trusted: routingTrustedModules, advisory_only: advisoryOnlyModules, suspect: suspectModules, low_confidence: lowModules },
    module_statuses: moduleTrust,
    critical_path_test_summary: (criticalPaths.paths || []).map((criticalPath) => ({ id: criticalPath.id, status: criticalPath.test_linkage?.status || 'unknown', linked_tests: criticalPath.test_linkage?.linked_tests || [], gaps: criticalPath.test_linkage?.gaps || [], summary: criticalPath.test_linkage?.summary || null }))
  };

  automationStatus.mode = 'event-driven';
  automationStatus.concurrent_safe = true;
  automationStatus.locking = { strategy: 'directory_lock', path: context.mode === 'repo' ? '.knowledge/.lock' : path.join(stateRoot, '.lock'), atomic_writes: true };
  automationStatus.knowledge_mode = context.mode;
  automationStatus.state_root = stateRoot;
  automationStatus.hooks_installed = automationStatus.hooks_installed ?? false;
  automationStatus.watcher_supported = true;
  automationStatus.watcher_last_seen_at = trigger === 'watcher' ? timestamp : (automationStatus.watcher_last_seen_at ?? null);
  automationStatus.last_auto_maintenance_at = timestamp;
  automationStatus.last_trigger_source = trigger;
  automationStatus.last_agent_id = agentId;
  automationStatus.last_changed_files = changedFiles;
  automationStatus.last_new_important_files = newFiles.filter((file) => ['critical', 'important'].includes(file.classification)).map((file) => ({ path: file.path, classification: file.classification, module_id: file.module_id }));
  automationStatus.automation_health = missingFiles.length > 0 ? 'degraded_missing_files' : (newFiles.some((file) => ['critical', 'important'].includes(file.classification)) ? 'degraded_new_uncovered_files' : 'healthy');
  automationStatus.watched_roots = WATCHED_ROOTS;
  automationStatus.ignored_segments = IGNORED_SEGMENTS;
  automationStatus.trigger_history = limitArray([...(automationStatus.trigger_history || []), { timestamp, trigger, agent_id: agentId, changed_files: changedFiles, new_files: newFiles.map((file) => file.path) }], 200);

  const syncEntry = { timestamp, action: 'sync_tracked_files', trigger, agent_id: agentId, full_scan: fullScan, changed_files: changedFiles, missing_files: missingFiles, new_files: newFiles.map((file) => ({ path: file.path, classification: file.classification, module_id: file.module_id })), impacted_artifacts: Array.from(touchedArtifacts), trust_report_refreshed: true };
  syncLog.generated_at = timestamp;
  syncLog.entries = limitArray([...(syncLog.entries || []), syncEntry], 200);

  const note = `sync_tracked_files(trigger=${trigger}): changed=${changedFiles.length}, missing=${missingFiles.length}, new=${newFiles.length}, trusted=${trustedModules.length}, near=${nearTrustedModules.length}, routing=${routingTrustedModules.length}, advisory=${advisoryOnlyModules.length}, suspect=${suspectModules.length}, low=${lowModules.length}`;
  updateActiveTasks(timestamp, note);

  writeJsonAtomic(paths.freshness, freshness);
  writeJsonAtomic(paths.fileCriticality, fileCriticality);
  writeJsonAtomic(paths.staleItems, staleItems);
  writeJsonAtomic(paths.repairQueue, repairQueue);
  writeJsonAtomic(paths.syncLog, syncLog);
  writeJsonAtomic(paths.trustReport, trustReport);
  writeJsonAtomic(paths.automationStatus, automationStatus);
  handoffSummary.generated_at = timestamp;
  handoffSummary.generated_by = agentId;
  handoffSummary.trusted_modules = trustedModules;
  handoffSummary.near_trusted_modules = nearTrustedModules;
  handoffSummary.routing_only_modules = routingTrustedModules;
  handoffSummary.non_authoritative_modules = advisoryOnlyModules;
  handoffSummary.highest_risk_modules = Array.from(new Set([...(handoffSummary.highest_risk_modules || []), ...suspectModules, ...lowModules]));
  writeJsonAtomic(paths.handoffSummary, handoffSummary);

  try {
    const buildRoutingBundle = require(path.join(context.systemRoot, 'tools', 'build-routing-bundle.js'));
    const routingBundle = buildRoutingBundle({ skipLock: true, quiet: true });
    routingBundleSummary = { modules: (routingBundle.modules || []).length, high_risk_modules: (routingBundle.high_risk_modules || []).length };
    automationStatus.routing_bundle_status = 'healthy';
    automationStatus.routing_bundle_updated_at = timestamp;
    automationStatus.routing_bundle_error = null;
    writeJsonAtomic(paths.automationStatus, automationStatus);
  } catch (error) {
    automationStatus.routing_bundle_status = 'failed';
    automationStatus.routing_bundle_error = error.message;
    writeJsonAtomic(paths.automationStatus, automationStatus);
  }

  const eventDate = timestamp.slice(0, 10);
  appendNdjson(path.join(paths.eventLogDir, `${eventDate}.ndjson`), { type: 'sync', ...syncEntry, routing_bundle: routingBundleSummary });

  return { trigger, agent_id: agentId, full_scan: fullScan, changed_files: changedFiles, missing_files: missingFiles, new_files: newFiles, trusted_modules: trustedModules, near_trusted_modules: nearTrustedModules, routing_trusted_modules: routingTrustedModules, advisory_only_modules: advisoryOnlyModules, suspect_modules: suspectModules, low_confidence_modules: lowModules, routing_bundle: routingBundleSummary };
}

function main() {
  ensureDir(path.join(stateRoot, 'maintenance'));
  return withLock(lockDir, mainUnlocked);
}

if (require.main === module) {
  try {
    console.log(JSON.stringify(main(), null, 2));
  } catch (error) {
    console.error(error.stack || error.message);
    process.exit(1);
  }
}

module.exports = main;
