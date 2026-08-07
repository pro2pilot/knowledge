#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');
const { readJson, writeJsonAtomic, normalizeRelative } = require('./lib/json-store');
const { parseCliArgs, resolveKnowledgeContext, jsonContext } = require('./lib/path-context');
const { runGit, isGeneratedRuntimePath } = require('./lib/git-context');
const { systemVersion } = require('./lib/system-version');

const SOURCE_EXTENSIONS = new Set([
  '.c', '.cc', '.cpp', '.cs', '.css', '.go', '.h', '.hpp', '.java', '.js', '.jsx',
  '.kt', '.mjs', '.php', '.py', '.rb', '.rs', '.scss', '.sql', '.swift', '.ts',
  '.tsx', '.vue', '.yaml', '.yml'
]);

function uniq(values) {
  return Array.from(new Set((values || []).filter(Boolean)));
}

function normalize(value) {
  return normalizeRelative(value).replace(/^\.knowledge\//, '');
}

function stripKnowledge(value) {
  return normalizeRelative(value).replace(/^\.knowledge\//, '');
}

function pathVariants(value) {
  const raw = normalizeRelative(value);
  const stripped = stripKnowledge(raw);
  return uniq([raw, stripped, `.knowledge/${stripped}`]);
}

function isSameOrInside(filePath, target) {
  const fileVariants = pathVariants(filePath);
  const targetVariants = pathVariants(target);
  for (const file of fileVariants) {
    for (const item of targetVariants) {
      if (!item || item === '.') continue;
      const clean = item.replace(/\/$/, '');
      if (file === clean || file.startsWith(`${clean}/`)) return true;
    }
  }
  return false;
}

function isSourceFile(filePath) {
  const rel = stripKnowledge(filePath);
  if (/^(maintenance|metrics|search|inspector|sessions|dist)\//.test(rel)) return false;
  if (/^(evidence|modules|wiki|docs|maps|templates|external_memory)\//.test(rel)) return false;
  return SOURCE_EXTENSIONS.has(path.posix.extname(rel).toLowerCase());
}

function isRuntimeFile(filePath) {
  const rel = normalizeRelative(filePath);
  const stripped = stripKnowledge(rel);
  return isGeneratedRuntimePath(rel) ||
    /^(maintenance|metrics|search|inspector|sessions|dist)\//.test(stripped) ||
    stripped === 'freshness.json' ||
    stripped === 'maps/wiki_graph.json' ||
    stripped === 'maps/file_criticality.json';
}

function safeReadJson(root, rel, fallback) {
  const clean = stripKnowledge(rel);
  const candidates = uniq([
    path.join(root, clean),
    path.join(root, rel)
  ]);
  for (const candidate of candidates) {
    try {
      if (fs.existsSync(candidate)) return readJson(candidate, fallback);
    } catch {
      return fallback;
    }
  }
  return fallback;
}

function safeReadRuntimeJson(context, rel, fallback) {
  const clean = stripKnowledge(rel);
  const stateCandidate = path.join(context.stateRoot, clean);
  if (fs.existsSync(stateCandidate)) return readJson(stateCandidate, fallback);
  return safeReadJson(context.projectKnowledgeRoot, clean, fallback);
}

function runGitChecked(targetRoot, args) {
  return runGit(targetRoot, args, { timeoutMs: 12000 });
}

function parseNameStatus(output, staged = false) {
  const rows = [];
  for (const line of String(output || '').split(/\r?\n/).filter(Boolean)) {
    const parts = line.split(/\t+/);
    const code = parts[0] || 'M';
    const file = normalizeRelative(parts[parts.length - 1]);
    if (!file) continue;
    rows.push({ path: file, status: code, staged });
  }
  return rows;
}

function parseStatus(output) {
  const rows = [];
  for (const line of String(output || '').split(/\r?\n/).filter(Boolean)) {
    const index = line.slice(0, 1);
    const worktree = line.slice(1, 2);
    let file = normalizeRelative(line.slice(3).replace(/^"|"$/g, '').replace(/\\"/g, '"'));
    if (file.includes(' -> ')) file = normalizeRelative(file.split(' -> ').pop());
    rows.push({
      path: file,
      status: `${index}${worktree}`.trim() || 'M',
      staged: Boolean(index && index !== ' ' && index !== '?')
    });
  }
  return rows;
}

function mergeChanged(rows) {
  const byPath = new Map();
  for (const row of rows) {
    const rel = normalizeRelative(row.path);
    if (!rel) continue;
    const current = byPath.get(rel) || { path: rel, statuses: [], staged: false };
    current.statuses.push(row.status || 'M');
    current.staged = current.staged || Boolean(row.staged);
    byPath.set(rel, current);
  }
  return Array.from(byPath.values()).map((row) => ({
    path: row.path,
    status: uniq(row.statuses).join(','),
    staged: row.staged,
    generated_runtime: isRuntimeFile(row.path),
    source_file: isSourceFile(row.path)
  })).sort((a, b) => a.path.localeCompare(b.path));
}

function collectChangedFiles(context, flags) {
  if (flags.files) {
    const rows = String(flags.files).split(',').map((file) => ({ path: file.trim(), status: 'manual', staged: false }));
    return { files: mergeChanged(rows), warnings: ['changed files supplied through --files'] };
  }
  if (!context.git?.is_git_repo) {
    return { files: [], warnings: ['targetRoot is not a git repository'] };
  }

  const targetRoot = context.targetRoot;
  const rows = [];
  const warnings = [];
  if (flags.base || flags.head) {
    const left = flags.base || 'HEAD';
    const range = flags.head ? `${left}...${flags.head}` : left;
    const diff = runGitChecked(targetRoot, ['diff', '--name-status', '--diff-filter=ACMRTUXB', range, '--']);
    if (!diff.ok) warnings.push(diff.stderr || `git diff failed for ${range}`);
    else rows.push(...parseNameStatus(diff.stdout, false));
    return { files: mergeChanged(rows), warnings };
  }

  const hasHead = runGitChecked(targetRoot, ['rev-parse', '--verify', 'HEAD']);
  if (!hasHead.ok) {
    const status = runGitChecked(targetRoot, ['status', '--porcelain=v1']);
    if (!status.ok) warnings.push(status.stderr || 'git status failed');
    else rows.push(...parseStatus(status.stdout));
    return { files: mergeChanged(rows), warnings };
  }

  const unstaged = runGitChecked(targetRoot, ['diff', '--name-status', '--diff-filter=ACMRTUXB', 'HEAD', '--']);
  if (unstaged.ok) rows.push(...parseNameStatus(unstaged.stdout, false));
  else warnings.push(unstaged.stderr || 'git diff failed');

  const staged = runGitChecked(targetRoot, ['diff', '--cached', '--name-status', '--diff-filter=ACMRTUXB', 'HEAD', '--']);
  if (staged.ok) rows.push(...parseNameStatus(staged.stdout, true));
  else warnings.push(staged.stderr || 'git diff --cached failed');

  const untracked = runGitChecked(targetRoot, ['ls-files', '--others', '--exclude-standard']);
  if (untracked.ok) {
    rows.push(...String(untracked.stdout || '').split(/\r?\n/).filter(Boolean).map((file) => ({
      path: file,
      status: '??',
      staged: false
    })));
  } else {
    warnings.push(untracked.stderr || 'git ls-files failed');
  }

  return { files: mergeChanged(rows), warnings };
}

function readModuleRegistry(context) {
  const registry = safeReadJson(context.projectKnowledgeRoot, 'modules/module_registry.json', { modules: [] });
  const modules = Array.isArray(registry.modules) ? registry.modules : [];
  return modules.map((module) => {
    const id = module.module_id || module.id || module.name;
    const cardRel = stripKnowledge(module.card || `modules/${id}.json`);
    const card = safeReadJson(context.projectKnowledgeRoot, cardRel, {});
    return {
      ...card,
      ...module,
      module_id: id,
      card: module.card || `.knowledge/${cardRel}`,
      key_files: uniq([...(module.key_files || []), ...(card.key_files || [])]),
      evidence_files: uniq([...(module.evidence_files || []), ...(card.evidence_files || [])])
    };
  }).filter((module) => module.module_id);
}

function moduleStatusMap(trust) {
  const out = new Map();
  for (const status of trust.module_statuses || []) {
    if (status?.module_id) out.set(status.module_id, status);
  }
  for (const [bucket, ids] of Object.entries(trust.modules || {})) {
    for (const id of ids || []) {
      const current = out.get(id) || { module_id: id };
      current.trust_status = current.trust_status || bucket;
      out.set(id, current);
    }
  }
  return out;
}

function findModulesForFile(file, modules) {
  const matches = modules.filter((module) => {
    const keyFiles = module.key_files || [];
    const evidenceFiles = module.evidence_files || [];
    if (keyFiles.some((item) => isSameOrInside(file.path, item))) return true;
    if (evidenceFiles.some((item) => isSameOrInside(file.path, item))) return true;
    if (module.path && module.path !== '.' && isSameOrInside(file.path, module.path)) return true;
    return false;
  });
  if (matches.length) return matches;
  const root = modules.find((module) => module.module_id === 'root');
  return root ? [root] : [];
}

function freshnessForModule(module, status, freshness) {
  const explicit = status?.freshness_status || module.freshness_status || module.freshness;
  if (explicit) return explicit;
  const artifacts = freshness.artifact_statuses || {};
  const candidates = uniq([module.card, ...(module.key_files || []), ...(module.evidence_files || [])]);
  for (const item of candidates) {
    for (const variant of pathVariants(item)) {
      const row = artifacts[variant] || artifacts[stripKnowledge(variant)];
      const state = row?.status || row?.freshness_status || row?.state;
      if (state && !/fresh|current|ok/i.test(String(state))) return state;
    }
  }
  return 'unknown';
}

function buildCriticalIndex(context) {
  const fileCriticality = safeReadRuntimeJson(context, 'maps/file_criticality.json', { files: [] });
  const criticalPaths = safeReadJson(context.projectKnowledgeRoot, 'maps/critical_paths.json', { paths: [], critical_paths: [] });
  const files = [];
  for (const row of fileCriticality.files || []) {
    files.push({
      path: row.path || row.file,
      classification: row.classification || row.criticality || row.severity || 'important',
      reason: row.reason || row.why || '',
      modules: row.modules || []
    });
  }
  for (const row of criticalPaths.paths || criticalPaths.critical_paths || []) {
    const filePath = typeof row === 'string' ? row : row.path || row.file || row.glob;
    if (filePath) files.push({
      path: filePath,
      classification: row.classification || row.criticality || 'critical',
      reason: row.reason || row.why || 'critical path',
      modules: row.modules || []
    });
  }
  return files.filter((row) => row.path);
}

function findCritical(file, criticalIndex) {
  return criticalIndex.filter((row) => isSameOrInside(file.path, row.path));
}

function repairFiles(item) {
  return uniq([
    ...(item.affected_artifacts || []),
    ...(item.artifacts || []),
    ...(item.files || []),
    ...(item.paths || [])
  ]);
}

function findRepairItems(file, module, queue) {
  return (queue || []).filter((item) => {
    const itemFiles = repairFiles(item);
    if (itemFiles.some((candidate) => isSameOrInside(file.path, candidate) || isSameOrInside(candidate, file.path))) return true;
    const text = JSON.stringify(item).toLowerCase();
    return module?.module_id && text.includes(String(module.module_id).toLowerCase());
  });
}

function evidenceExists(context, evidenceFile) {
  const clean = stripKnowledge(evidenceFile);
  return fs.existsSync(path.join(context.projectKnowledgeRoot, clean)) ||
    fs.existsSync(path.join(context.stateRoot, clean));
}

function riskLevel({ criticalCount, trustStatus, freshnessStatus, repairCount, evidenceMissing }) {
  if (criticalCount > 0 || evidenceMissing || ['suspect', 'low_confidence', 'needs_recheck'].includes(String(trustStatus))) return 'high';
  if (repairCount > 0 || freshnessStatus && !/fresh|current|ok|unknown/i.test(String(freshnessStatus))) return 'medium';
  return 'low';
}

function analyze(options = {}) {
  const context = resolveKnowledgeContext({ __skipCli: true, ...options });
  const flags = { ...options };
  const trust = safeReadRuntimeJson(context, 'maintenance/trust_report.json', {});
  const freshness = safeReadRuntimeJson(context, 'freshness.json', {});
  const repair = safeReadRuntimeJson(context, 'maintenance/repair_queue.json', { queue: [] });
  const modules = readModuleRegistry(context);
  const statuses = moduleStatusMap(trust);
  const criticalIndex = buildCriticalIndex(context);
  const changed = collectChangedFiles(context, flags);

  const changedFiles = changed.files.map((file) => ({ ...file, modules: findModulesForFile(file, modules).map((module) => module.module_id) }));
  const affected = new Map();
  const criticalFiles = [];
  const trustWarnings = [];
  const freshnessWarnings = [];
  const policyWarnings = [];
  const reviewerNotes = [];
  const repairMatches = [];

  for (const file of changedFiles) {
    const matchedModules = findModulesForFile(file, modules);
    const critical = findCritical(file, criticalIndex);
    if (critical.length) {
      criticalFiles.push({ path: file.path, matches: critical });
      policyWarnings.push({
        id: 'critical-file-touched',
        severity: 'needs_review',
        file: file.path,
        message: `Critical or important file touched: ${file.path}`,
        action: 'Reviewer should inspect current source and tests before merge.'
      });
    }
    if (file.staged && file.generated_runtime) {
      policyWarnings.push({
        id: 'generated-runtime-staged',
        severity: 'block',
        file: file.path,
        message: `Generated runtime file is staged: ${file.path}`,
        action: 'Unstage runtime artifacts unless the PR intentionally changes source templates.'
      });
    }

    for (const module of matchedModules) {
      const status = statuses.get(module.module_id) || {};
      const trustStatus = module.current_trust_level || module.trust_status || status.trust_status || status.current_trust_level || 'unknown';
      const freshnessStatus = freshnessForModule(module, status, freshness);
      const evidenceFiles = module.evidence_files || [];
      const evidenceMissing = file.source_file && (!evidenceFiles.length || !evidenceFiles.some((item) => evidenceExists(context, item)));
      const repairItems = findRepairItems(file, module, repair.queue || []);
      const risk = riskLevel({
        criticalCount: critical.length,
        trustStatus,
        freshnessStatus,
        repairCount: repairItems.length,
        evidenceMissing
      });
      const current = affected.get(module.module_id) || {
        module_id: module.module_id,
        card: module.card,
        path: module.path || '',
        trust_status: trustStatus,
        freshness_status: freshnessStatus,
        confidence: module.confidence || status.confidence || '',
        changed_files: [],
        evidence_files: evidenceFiles,
        key_files: module.key_files || [],
        repair_items: [],
        risk: 'low'
      };
      current.changed_files.push(file.path);
      current.repair_items.push(...repairItems.map((item) => item.id || item.subject || item.title || 'repair-item'));
      current.risk = risk === 'high' || current.risk === 'high' ? 'high' : risk === 'medium' || current.risk === 'medium' ? 'medium' : 'low';
      affected.set(module.module_id, current);

      if (['suspect', 'low_confidence', 'needs_recheck'].includes(String(trustStatus))) {
        trustWarnings.push({
          module_id: module.module_id,
          trust_status: trustStatus,
          file: file.path,
          message: `Module ${module.module_id} is ${trustStatus}; re-read source before behavior claims.`
        });
        policyWarnings.push({
          id: 'low-trust-module-touched',
          severity: 'needs_review',
          module_id: module.module_id,
          file: file.path,
          message: `Changed file maps to low-trust module ${module.module_id}.`,
          action: 'Require targeted source/test review.'
        });
      }
      if (freshnessStatus && !/fresh|current|ok|unknown/i.test(String(freshnessStatus))) {
        freshnessWarnings.push({
          module_id: module.module_id,
          freshness_status: freshnessStatus,
          file: file.path,
          message: `Module ${module.module_id} freshness is ${freshnessStatus}.`
        });
        policyWarnings.push({
          id: 'stale-module-touched',
          severity: 'warn',
          module_id: module.module_id,
          file: file.path,
          message: `Changed file maps to stale module ${module.module_id}.`,
          action: 'Refresh evidence/module card after reviewing the diff.'
        });
      }
      if (evidenceMissing) {
        policyWarnings.push({
          id: 'source-changed-evidence-missing',
          severity: 'warn',
          module_id: module.module_id,
          file: file.path,
          message: `Source file changed but module ${module.module_id} has no current evidence file.`,
          action: 'Add or refresh evidence before raising trust.'
        });
      }
      for (const item of repairItems) {
        repairMatches.push({
          id: item.id || item.subject || item.title || 'repair-item',
          module_id: module.module_id,
          file: file.path,
          priority: item.priority || item.severity || 'medium',
          status: item.status || 'open'
        });
      }
    }
  }

  if (!changedFiles.length) {
    reviewerNotes.push('No changed files were found in the selected git diff/status range.');
  } else {
    reviewerNotes.push(`${changedFiles.length} changed file(s) map to ${affected.size} module(s).`);
    if (criticalFiles.length) reviewerNotes.push(`${criticalFiles.length} changed file(s) are critical or important.`);
    if (trustWarnings.length || freshnessWarnings.length) reviewerNotes.push('Trust/freshness warnings require source-backed review.');
    if (repairMatches.length) reviewerNotes.push(`${repairMatches.length} open repair item(s) overlap the diff.`);
  }

  const affectedModules = Array.from(affected.values()).map((module) => ({
    ...module,
    changed_files: uniq(module.changed_files),
    repair_items: uniq(module.repair_items)
  })).sort((a, b) => a.module_id.localeCompare(b.module_id));

  const result = {
    schema_version: systemVersion(),
    generated_at: new Date().toISOString(),
    status: changedFiles.length ? (policyWarnings.some((item) => item.severity === 'block') ? 'block' : 'ok') : 'empty',
    context: jsonContext(context),
    range: {
      base: flags.base || null,
      head: flags.head || null,
      mode: flags.base || flags.head ? 'range' : 'working-tree'
    },
    changed_files: changedFiles,
    affected_modules: affectedModules,
    critical_files: criticalFiles,
    trust_warnings: trustWarnings,
    freshness_warnings: freshnessWarnings,
    repair_delta: {
      count: repairMatches.length,
      matched_items: repairMatches
    },
    policy_warnings: policyWarnings,
    reviewer_notes: reviewerNotes,
    warnings: changed.warnings,
    empty_state: changedFiles.length ? null : {
      title: 'No changed files',
      detail: 'PR Impact needs a git diff or dirty working tree to review.'
    }
  };

  if (!flags.noWrite) {
    writeJsonAtomic(path.join(context.stateRoot, 'maintenance', 'pr_impact.json'), result);
  }
  return result;
}

function printHuman(result) {
  if (result.status === 'empty') {
    console.log('PR Impact: no changed files.');
    return;
  }
  console.log(`PR Impact: ${result.changed_files.length} file(s), ${result.affected_modules.length} module(s), ${result.policy_warnings.length} warning(s).`);
  for (const warning of result.policy_warnings.slice(0, 12)) {
    console.log(`- [${warning.severity}] ${warning.message}`);
  }
}

function main(argv = process.argv.slice(2)) {
  const parsed = parseCliArgs(argv);
  const result = analyze(parsed.flags);
  if (parsed.flags.json) console.log(JSON.stringify(result, null, 2));
  else printHuman(result);
}

if (require.main === module) {
  try { main(); }
  catch (error) {
    const parsed = parseCliArgs(process.argv.slice(2));
    if (parsed.flags.json) console.log(JSON.stringify({ schema_version: systemVersion(), status: 'failed', error: error.message }, null, 2));
    else console.error(error.stack || error.message);
    process.exit(1);
  }
}

module.exports = { analyze, collectChangedFiles, isRuntimeFile, isSourceFile };
