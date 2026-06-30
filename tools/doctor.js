#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');
const { ensureDir, readJson, writeJsonAtomic, getAgentId, withLock } = require('./lib/json-store');
const { resolveKnowledgeContext } = require('./lib/path-context');
const { appendTeamEvent } = require('./lib/team-store');
const { loadProviderManifests } = require('./lib/memory-providers');

const context = resolveKnowledgeContext();
const repoRoot = context.targetRoot;
const knowledgeRoot = context.projectKnowledgeRoot;
const stateRoot = context.stateRoot;
const lockDir = path.join(stateRoot, '.lock');

function nowIso() { return new Date().toISOString(); }
function rel(abs, base = knowledgeRoot) {
  const fromBase = path.relative(base, abs).replace(/\\/g, '/');
  if (!fromBase.startsWith('..') && !path.isAbsolute(fromBase)) return fromBase;
  const fromState = path.relative(stateRoot, abs).replace(/\\/g, '/');
  if (!fromState.startsWith('..') && !path.isAbsolute(fromState)) return fromState;
  return path.basename(abs);
}
function exists(relPath) {
  const raw = String(relPath || '');
  const clean = raw.replace(/^\.knowledge[\\/]/, '');
  return fs.existsSync(path.join(repoRoot, raw)) ||
    fs.existsSync(path.join(repoRoot, clean)) ||
    fs.existsSync(path.join(knowledgeRoot, clean));
}
function artifactExists(relPath) {
  return fs.existsSync(path.join(repoRoot, relPath)) ||
    fs.existsSync(path.join(knowledgeRoot, String(relPath).replace(/^\.knowledge[\\/]/, '')));
}
function issue(issues, severity, code, message, artifact = null) { issues.push({ severity, code, message, artifact }); }
function walk(dir, output = []) {
  if (!fs.existsSync(dir)) return output;
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const abs = path.join(dir, entry.name);
    const relative = rel(abs);
    if (relative.startsWith('.lock/') || relative.startsWith('.runtime/') || relative.includes('.tmp-') || relative.includes('.bak-')) continue;
    if (entry.isDirectory()) walk(abs, output);
    else if (entry.isFile()) output.push(abs);
  }
  return output;
}
function safeJson(abs, issues) {
  try { return JSON.parse(fs.readFileSync(abs, 'utf8').replace(/^\uFEFF/, '')); }
  catch (error) { issue(issues, 'critical', 'invalid_json', `Invalid JSON: ${error.message}`, `.knowledge/${rel(abs)}`); return null; }
}
function scoreFromIssues(issues) {
  let score = 100;
  for (const item of issues) {
    if (item.severity === 'critical') score -= 25;
    else if (item.severity === 'high') score -= 15;
    else if (item.severity === 'medium') score -= 7;
    else score -= 3;
  }
  return Math.max(0, score);
}
function statusFromScore(score, criticalCount) {
  if (criticalCount > 0 || score < 50) return 'broken';
  if (score < 75) return 'degraded';
  if (score < 90) return 'usable_with_caution';
  return 'healthy';
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

function doctorUnlocked(options = {}) {
  ensureDir(path.join(stateRoot, 'maintenance'));
  const issues = [];
  const checks = [];
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
    const ok = fs.existsSync(path.join(knowledgeRoot, file));
    checks.push({ check: 'required_file', artifact: `.knowledge/${file}`, status: ok ? 'pass' : 'fail' });
    if (!ok) issue(issues, file.includes('routing_bundle') ? 'medium' : 'high', 'missing_required_file', `Missing required knowledge artifact: ${file}`, `.knowledge/${file}`);
  }
  for (const file of stateRequired) {
    const ok = fs.existsSync(path.join(stateRoot, file));
    checks.push({ check: 'runtime_file', artifact: context.mode === 'repo' ? `.knowledge/${file}` : path.join(stateRoot, file), status: ok ? 'pass' : 'warn' });
    if (!ok) issue(issues, 'medium', 'missing_runtime_file', `Missing runtime artifact: ${file}. Run the relevant flow to generate it.`, context.mode === 'repo' ? `.knowledge/${file}` : path.join(stateRoot, file));
  }

  const jsonFiles = Array.from(new Set([
    ...walk(knowledgeRoot),
    ...(stateRoot === knowledgeRoot ? [] : walk(stateRoot))
  ])).filter((abs) => abs.endsWith('.json'));
  const parsed = new Map();
  for (const abs of jsonFiles) parsed.set(rel(abs), safeJson(abs, issues));
  checks.push({ check: 'json_parse', status: issues.some((i) => i.code === 'invalid_json') ? 'fail' : 'pass', files_checked: jsonFiles.length });

  const registry = parsed.get('modules/module_registry.json') || { modules: [] };
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

  const freshness = parsed.get('freshness.json') || { tracked_files: [] };
  const tracked = freshness.tracked_files || [];
  const missingTracked = tracked.filter((entry) => entry.path && !exists(entry.path));
  if (missingTracked.length > 0) issue(issues, 'high', 'tracked_file_missing', `${missingTracked.length} tracked files are missing.`, '.knowledge/freshness.json');
  checks.push({ check: 'tracked_files_exist', status: missingTracked.length ? 'fail' : 'pass', tracked_files: tracked.length, missing: missingTracked.length });

  const trust = parsed.get('maintenance/trust_report.json') || {};
  const suspectCount = ((trust.modules || {}).suspect || []).length + ((trust.modules || {}).low_confidence || []).length;
  if (suspectCount > 0) issue(issues, 'medium', 'suspect_or_low_modules', `${suspectCount} modules are suspect or low-confidence; code recheck is mandatory before behavior claims.`, '.knowledge/maintenance/trust_report.json');
  checks.push({ check: 'trust_report_present', status: trust.generated_at ? 'pass' : 'warn', generated_at: trust.generated_at || null, suspect_or_low_modules: suspectCount });

  const wikiLint = parsed.get('maintenance/wiki_lint_report.json') || {};
  if (wikiLint.status && !['healthy','usable_with_warnings'].includes(wikiLint.status)) issue(issues, 'low', 'wiki_lint_not_healthy', `Wiki lint status is ${wikiLint.status}.`, '.knowledge/maintenance/wiki_lint_report.json');
  checks.push({ check: 'wiki_lint_report', status: wikiLint.generated_at ? 'pass' : 'warn', quality_score: wikiLint.quality_score ?? null });

  const graph = parsed.get('maps/wiki_graph.json') || {};
  if ((graph.broken_edge_count || 0) > 0) issue(issues, 'medium', 'broken_wiki_edges', `${graph.broken_edge_count} broken wiki graph edges.`, '.knowledge/maps/wiki_graph.json');
  checks.push({ check: 'wiki_graph', status: graph.generated_at ? 'pass' : 'warn', nodes: graph.node_count || 0, edges: graph.edge_count || 0, broken_edges: graph.broken_edge_count || 0 });

  const externalStatusPath = path.join(stateRoot, 'maintenance', 'external_memory_status.json');
  if (!fs.existsSync(externalStatusPath)) { try { require(path.join(context.systemRoot, 'tools', 'external-memory-status.js'))({ skipLock: true, quiet: true }); } catch {} }
  const externalStatus = fs.existsSync(externalStatusPath) ? readJson(externalStatusPath, {}) : {};
  checks.push({ check: 'external_memory_status', status: externalStatus.generated_at ? 'pass' : 'warn', providers: externalStatus.providers || [] });
  const manifests = loadProviderManifests(context).filter((manifest) => manifest.layer === 'free_core');
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

  const searchIndexExists = fs.existsSync(path.join(stateRoot, 'search', 'index.json'));
  checks.push({ check: 'search_index', status: searchIndexExists ? 'pass' : 'warn', artifact: '.knowledge/search/index.json' });
  if (!searchIndexExists) issue(issues, 'low', 'search_index_missing', 'Search index is missing. Run build-search-index.js for token-efficient knowledge retrieval.', '.knowledge/search/index.json');

  const eventsDir = path.join(stateRoot, 'maintenance', 'events');
  checks.push({ check: 'append_only_events_dir', status: fs.existsSync(eventsDir) ? 'pass' : 'fail', artifact: '.knowledge/maintenance/events/' });
  if (!fs.existsSync(eventsDir)) issue(issues, 'medium', 'events_dir_missing', 'Append-only events directory is missing.', '.knowledge/maintenance/events/');

  // doctor itself does not run the scan (keeps doctor fast and side-effect-free);
  // it just reports the latest run. Use `node .knowledge/tools/scan-secrets.js`
  // to refresh, or `--strict` in CI to block.
  const secretReportPath = path.join(stateRoot, 'maintenance', 'secret_scan_report.json');
  if (fs.existsSync(secretReportPath)) {
    const secretReport = readJson(secretReportPath, {});
    checks.push({ check: 'secret_scan', status: secretReport.status === 'clean' ? 'pass' : 'warn', findings_total: secretReport.findings_total || 0, secret_scan_status: secretReport.status || 'unknown', generated_at: secretReport.generated_at || null });
    if ((secretReport.by_severity || {}).critical) issue(issues, 'critical', 'secret_scan_critical', `${secretReport.by_severity.critical} critical secret finding(s) in last scan.`, '.knowledge/maintenance/secret_scan_report.json');
    else if ((secretReport.by_severity || {}).high) issue(issues, 'high', 'secret_scan_high', `${secretReport.by_severity.high} high-severity secret finding(s) in last scan.`, '.knowledge/maintenance/secret_scan_report.json');
    else if ((secretReport.by_severity || {}).medium) issue(issues, 'medium', 'secret_scan_medium', `${secretReport.by_severity.medium} medium secret finding(s) in last scan.`, '.knowledge/maintenance/secret_scan_report.json');
  } else {
    checks.push({ check: 'secret_scan', status: 'warn', note: 'Never run. Run scan-secrets.js for a baseline.' });
    issue(issues, 'low', 'secret_scan_missing', 'No secret_scan_report.json. Run node .knowledge/tools/scan-secrets.js for a baseline.', '.knowledge/maintenance/secret_scan_report.json');
  }

  const criticalCount = issues.filter((i) => i.severity === 'critical').length;
  const score = scoreFromIssues(issues);
  const report = {
    schema_version: '3.2.3',
    generated_at: nowIso(),
    generated_by: getAgentId(),
    mode: context.mode,
    target_root: context.targetRoot,
    project_knowledge_root: context.projectKnowledgeRoot,
    state_root: context.stateRoot,
    quality_score: score,
    status: statusFromScore(score, criticalCount),
    summary: `${issues.length} issue(s), ${criticalCount} critical, score ${score}/100.`,
    checks,
    issues
  };
  writeJsonAtomic(path.join(stateRoot, 'maintenance', 'quality_report.json'), report);
  try { require(path.join(context.systemRoot, 'tools', 'build-routing-bundle.js'))({ skipLock: true, quiet: true }); } catch (error) { report.routing_bundle_refresh_error = error.message; }
  appendTeamEvent(context, 'doctor_result', {
    status: report.status,
    quality_score: report.quality_score,
    issues_total: report.issues.length
  });
  if (!options.quiet) console.log(JSON.stringify(report, null, 2));
  return report;
}

function main(options = {}) {
  if (options.skipLock) return doctorUnlocked(options);
  return withLock(lockDir, () => doctorUnlocked(options));
}

module.exports = main;

if (require.main === module) {
  try { main({ quiet: process.argv.includes('--quiet') }); }
  catch (error) { console.error(error.stack || error.message); process.exit(1); }
}
