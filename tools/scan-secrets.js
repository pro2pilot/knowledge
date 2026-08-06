#!/usr/bin/env node
'use strict';

// Scans .knowledge/ by default and optionally repo files filtered by
// critical/important scope (via .knowledge/maps/file_criticality.json).
// All matches are MASKED — the report never contains the raw secret.

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { ensureDir, readJson, writeJsonAtomic, getAgentId } = require('./lib/json-store');
const { withContainedLock } = require('./lib/contained-lock-manager');
const { LOCKS } = require('./lib/lock-policy');
const { resolveKnowledgeContext } = require('./lib/path-context');
const { systemVersion } = require('./lib/system-version');

const context = resolveKnowledgeContext();
const repoRoot = context.targetRoot;
const knowledgeRoot = context.projectKnowledgeRoot;
const stateRoot = context.stateRoot;
const SECRET_SCAN_LOCK = Object.freeze({
  context,
  rootKind: 'state',
  rootPath: stateRoot,
  lockName: 'secret-scan',
  purpose: LOCKS['secret-scan'].purpose
});
const reportPath = path.join(stateRoot, 'maintenance', 'secret_scan_report.json');

// positive rates. Tuned not to fire on placeholders like "xxx" or "<...>".
const RULES = [
  { id: 'private_key_pem', severity: 'critical', pattern: /-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP |ENCRYPTED |)PRIVATE KEY-----/ },
  { id: 'github_pat', severity: 'high', pattern: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b/ },
  { id: 'github_fine_grained_pat', severity: 'high', pattern: /\bgithub_pat_[A-Za-z0-9_]{60,}\b/ },
  { id: 'openai_api_key', severity: 'high', pattern: /\bsk-[A-Za-z0-9_-]{20,}\b/ },
  { id: 'anthropic_api_key', severity: 'high', pattern: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/ },
  { id: 'aws_access_key_id', severity: 'high', pattern: /\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b/ },
  { id: 'aws_secret_access_key', severity: 'high', pattern: /aws_secret_access_key\s*[:=]\s*["']?[A-Za-z0-9/+]{40}["']?/i },
  { id: 'slack_token', severity: 'high', pattern: /\bxox[abrsp]-[A-Za-z0-9-]{10,}\b/ },
  { id: 'jwt_token', severity: 'medium', pattern: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/ },
  { id: 'env_secret_assignment', severity: 'medium', pattern: /^\s*(?:[A-Z][A-Z0-9_]*_(?:SECRET|TOKEN|KEY|PASSWORD|PWD|DSN|URL|API)|PRIVATE_KEY|DATABASE_URL)\s*=\s*[^\s#"<>][^\s#]{8,}/m }
];

// Files we never scan (binaries, large artefacts).
const SKIP_EXT = new Set(['.png', '.jpg', '.jpeg', '.gif', '.webp', '.ico', '.pdf', '.zip', '.tar', '.gz', '.bz2', '.7z', '.exe', '.dll', '.so', '.dylib', '.bin', '.mp4', '.mp3', '.wav', '.woff', '.woff2', '.ttf', '.eot']);
const SKIP_DIR = new Set(['node_modules', '.git', 'dist', 'build', 'coverage', '.next', '.cache', '.qa-tmp', '.self-test-tmp', '.knowledge/.lock', '.knowledge/locks', '.knowledge/inspector']);

function nowIso() { return new Date().toISOString(); }
function rel(abs) { return path.relative(repoRoot, abs).replace(/\\/g, '/'); }

function mask(raw) {
  if (!raw) return '';
  const s = String(raw);
  // Show first 3 and last 3 chars only, replace the middle, never dump full value.
  if (s.length <= 8) return '*'.repeat(s.length);
  const head = s.slice(0, 3);
  const tail = s.slice(-3);
  const sha = crypto.createHash('sha256').update(s).digest('hex').slice(0, 8);
  return `${head}***${tail} (sha8:${sha})`;
}

function looksLikePlaceholder(value) {
  const v = String(value || '').toLowerCase();
  return /<.*>/.test(v) ||
    /(xxxx|placeholder|example|your[_-]?(?:key|token|secret)|to[_-]?do|change[_-]?me|fill[_-]?me|fake|dummy)/.test(v) ||
    /^\s*$/.test(v);
}

function* walk(dir, opts) {
  if (!fs.existsSync(dir)) return;
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
  for (const entry of entries) {
    const abs = path.join(dir, entry.name);
    const rel0 = rel(abs);
    if (SKIP_DIR.has(entry.name) || SKIP_DIR.has(rel0)) continue;
    if (entry.isDirectory()) yield* walk(abs, opts);
    else if (entry.isFile()) {
      if (SKIP_EXT.has(path.extname(entry.name).toLowerCase())) continue;
      if (opts.scopeFilter && !opts.scopeFilter(rel0)) continue;
      yield abs;
    }
  }
}

function lineNumberOf(content, index) {
  if (index < 0) return null;
  return content.slice(0, index).split(/\r?\n/).length;
}

function scanFile(abs) {
  let content;
  try {
    const stats = fs.statSync(abs);
    if (stats.size > 1024 * 1024) return []; // skip files > 1MB
    content = fs.readFileSync(abs, 'utf8');
  } catch { return []; }
  // Skip our own scan report, which contains masked findings.
  if (rel(abs) === '.knowledge/maintenance/secret_scan_report.json') return [];
  const findings = [];
  for (const rule of RULES) {
    let match;
    rule.pattern.lastIndex = 0;
    if (rule.pattern.global) {
      while ((match = rule.pattern.exec(content)) !== null) {
        const raw = match[0];
        if (looksLikePlaceholder(raw)) continue;
        findings.push({ file: rel(abs), rule: rule.id, severity: rule.severity, line: lineNumberOf(content, match.index), masked_value: mask(raw) });
      }
    } else {
      const m = content.match(rule.pattern);
      if (m && !looksLikePlaceholder(m[0])) {
        findings.push({ file: rel(abs), rule: rule.id, severity: rule.severity, line: lineNumberOf(content, m.index ?? content.indexOf(m[0])), masked_value: mask(m[0]) });
      }
    }
  }
  return findings;
}

function loadCriticalityScope() {
  const data = readJson(path.join(stateRoot, 'maps', 'file_criticality.json'), { files: [] });
  return new Set((data.files || []).filter((f) => ['critical', 'important'].includes(f.classification)).map((f) => f.path));
}

function main(argv = process.argv.slice(2)) {
  const flags = new Set(argv);
  const includeRepo = flags.has('--include-repo'); // opt-in: also scan repo critical/important files
  const strict = flags.has('--strict'); // exit non-zero on any finding
  const jsonOut = flags.has('--json');

  const findings = [];

  // Always scan .knowledge/ except inspector cache + lock + this report
  for (const abs of walk(knowledgeRoot, {})) {
    findings.push(...scanFile(abs));
  }

  let repoScanned = 0;
  if (includeRepo) {
    const scope = loadCriticalityScope();
    if (scope.size > 0) {
      for (const abs of walk(repoRoot, {
        scopeFilter: (relPath) => scope.has(relPath)
      })) {
        repoScanned++;
        findings.push(...scanFile(abs));
      }
    }
  }

  const bySeverity = findings.reduce((acc, f) => { acc[f.severity] = (acc[f.severity] || 0) + 1; return acc; }, {});
  const status = findings.some((f) => f.severity === 'critical') ? 'critical_findings'
    : findings.some((f) => f.severity === 'high') ? 'high_findings'
    : findings.length > 0 ? 'low_findings'
    : 'clean';

  const report = {
    schema_version: systemVersion(),
    generated_at: nowIso(),
    generated_by: getAgentId(),
    mode: context.mode,
    scope: includeRepo ? 'knowledge_plus_repo_critical_important' : 'knowledge_only',
    repo_files_scanned: repoScanned,
    rules_count: RULES.length,
    findings_total: findings.length,
    by_severity: bySeverity,
    status,
    note: 'All matches are masked (head***tail with sha8 fingerprint). Raw secret values are never written to this report.',
    findings
  };

  ensureDir(path.dirname(reportPath));
  writeJsonAtomic(reportPath, report);

  if (jsonOut) {
    console.log(JSON.stringify(report, null, 2));
  } else {
    console.log(JSON.stringify({
      status,
      findings_total: findings.length,
      by_severity: bySeverity,
      report: context.mode === 'repo' ? '.knowledge/maintenance/secret_scan_report.json' : reportPath
    }, null, 2));
  }

  if (strict && findings.length > 0) process.exit(1);
  return report;
}

if (require.main === module) {
  try { withContainedLock(SECRET_SCAN_LOCK, () => main()); }
  catch (error) { console.error(error.stack || error.message); process.exit(1); }
}

module.exports = main;
