#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');
const { ensureDir, readJson, writeJsonAtomic, getAgentId, withLock } = require('./lib/json-store');

const repoRoot = path.resolve(__dirname, '..', '..');
const knowledgeRoot = path.resolve(__dirname, '..');
const lockDir = path.join(knowledgeRoot, '.lock');

function nowIso() { return new Date().toISOString(); }
function rel(abs, base = knowledgeRoot) { return path.relative(base, abs).replace(/\\/g, '/'); }
function exists(relPath) { return fs.existsSync(path.join(repoRoot, relPath)); }
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
  try { return readJson(abs, null); }
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

function doctorUnlocked(options = {}) {
  ensureDir(path.join(knowledgeRoot, 'maintenance'));
  const issues = [];
  const checks = [];
  const required = [
    'project_index.json',
    'freshness.json',
    'modules/module_registry.json',
    'maintenance/trust_report.json',
    'maintenance/handoff_summary.json',
    'maintenance/concurrency_policy.json',
    'maintenance/routing_bundle.json',
    'maps/critical_paths.json',
    'maps/file_criticality.json',
    'evidence/file_facts.json',
    'wiki/index.md',
    'maps/wiki_graph.json',
    'maintenance/wiki_lint_report.json',
    'external_memory/registry.json',
    'external_memory/retrieval_policy.json'
  ];
  for (const file of required) {
    const ok = fs.existsSync(path.join(knowledgeRoot, file));
    checks.push({ check: 'required_file', artifact: `.knowledge/${file}`, status: ok ? 'pass' : 'fail' });
    if (!ok) issue(issues, file.includes('routing_bundle') ? 'medium' : 'high', 'missing_required_file', `Missing required knowledge artifact: ${file}`, `.knowledge/${file}`);
  }

  const jsonFiles = walk(knowledgeRoot).filter((abs) => abs.endsWith('.json'));
  const parsed = new Map();
  for (const abs of jsonFiles) parsed.set(rel(abs), safeJson(abs, issues));
  checks.push({ check: 'json_parse', status: issues.some((i) => i.code === 'invalid_json') ? 'fail' : 'pass', files_checked: jsonFiles.length });

  const registry = parsed.get('modules/module_registry.json') || { modules: [] };
  const modules = registry.modules || [];
  checks.push({ check: 'module_registry_non_empty', status: modules.length > 0 ? 'pass' : 'warn', modules: modules.length });
  if (modules.length === 0) issue(issues, 'medium', 'empty_module_registry', 'Module registry is empty. Run ingest-existing-project.js.', '.knowledge/modules/module_registry.json');
  if (!modules.some((m) => m.module_id === 'root')) issue(issues, 'medium', 'missing_root_module', 'Root module is missing; repository-level manifests may be poorly routed.', '.knowledge/modules/module_registry.json');

  for (const moduleInfo of modules) {
    if (!moduleInfo.card || !fs.existsSync(path.join(repoRoot, moduleInfo.card))) issue(issues, 'high', 'missing_module_card', `Module card is missing for ${moduleInfo.module_id}.`, moduleInfo.card || null);
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

  const externalStatusPath = path.join(knowledgeRoot, 'maintenance', 'external_memory_status.json');
  if (!fs.existsSync(externalStatusPath)) { try { require(path.join(knowledgeRoot, 'tools', 'external-memory-status.js'))({ skipLock: true, quiet: true }); } catch {} }
  const externalStatus = fs.existsSync(externalStatusPath) ? readJson(externalStatusPath, {}) : {};
  checks.push({ check: 'external_memory_status', status: externalStatus.generated_at ? 'pass' : 'warn', pinecone: externalStatus.providers?.pinecone || null });

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

  const searchIndexExists = fs.existsSync(path.join(knowledgeRoot, 'search', 'index.json'));
  checks.push({ check: 'search_index', status: searchIndexExists ? 'pass' : 'warn', artifact: '.knowledge/search/index.json' });
  if (!searchIndexExists) issue(issues, 'low', 'search_index_missing', 'Search index is missing. Run build-search-index.js for token-efficient knowledge retrieval.', '.knowledge/search/index.json');

  const eventsDir = path.join(knowledgeRoot, 'maintenance', 'events');
  checks.push({ check: 'append_only_events_dir', status: fs.existsSync(eventsDir) ? 'pass' : 'fail', artifact: '.knowledge/maintenance/events/' });
  if (!fs.existsSync(eventsDir)) issue(issues, 'medium', 'events_dir_missing', 'Append-only events directory is missing.', '.knowledge/maintenance/events/');

  // doctor itself does not run the scan (keeps doctor fast and side-effect-free);
  // it just reports the latest run. Use `node .knowledge/tools/scan-secrets.js`
  // to refresh, or `--strict` in CI to block.
  const secretReportPath = path.join(knowledgeRoot, 'maintenance', 'secret_scan_report.json');
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
    schema_version: '3.1.8',
    generated_at: nowIso(),
    generated_by: getAgentId(),
    quality_score: score,
    status: statusFromScore(score, criticalCount),
    summary: `${issues.length} issue(s), ${criticalCount} critical, score ${score}/100.`,
    checks,
    issues
  };
  writeJsonAtomic(path.join(knowledgeRoot, 'maintenance', 'quality_report.json'), report);
  try { require(path.join(knowledgeRoot, 'tools', 'build-routing-bundle.js'))({ skipLock: true, quiet: true }); } catch (error) { report.routing_bundle_refresh_error = error.message; }
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
