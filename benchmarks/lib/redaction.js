#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { parseCliArgs } = require('../../tools/lib/path-context');
const { ensureDir } = require('../../tools/lib/json-store');

const root = path.resolve(__dirname, '..', '..');

function forbiddenPatterns() {
  return [
    { id: 'local_windows_project_path', pattern: /[A-Z]:\\(?:Users\\[^\\]+|MyProject)/i },
    { id: 'mnt_data_path', pattern: /\/mnt\/data/i },
    { id: 'tmp_knowledge_path', pattern: /\/tmp\/knowledge/i },
    { id: 'local_user_path', pattern: /Users\\[^\\]+|Users\/[^/]+/i },
    { id: 'workspace_name_leak', pattern: new RegExp(`knowledge${'-'}kit`, 'i') },
    { id: 'env_assignment', pattern: /\b[A-Z0-9_]*(TOKEN|SECRET|API_KEY|PASSWORD)\s*=/i }
  ];
}

function walk(dir, out = []) {
  if (!fs.existsSync(dir)) return out;
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const abs = path.join(dir, entry.name);
    if (entry.isDirectory()) walk(abs, out);
    else if (entry.isFile()) out.push(abs);
  }
  return out;
}

function textFile(file) {
  return /\.(csv|html|json|md|ndjson|ps1|sh|svg|txt)$/i.test(file) || path.basename(file) === 'manifest';
}

function sha256(file) {
  return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
}

function scanRun(runDir) {
  const findings = [];
  const checksums = [];
  for (const file of walk(runDir)) {
    if (file.endsWith('.zip')) continue;
    const rel = path.relative(runDir, file).replace(/\\/g, '/');
    checksums.push(`${sha256(file)}  ${rel}`);
    if (!textFile(file)) continue;
    const text = fs.readFileSync(file, 'utf8');
    for (const item of forbiddenPatterns()) {
      if (item.pattern.test(text)) findings.push({ file: rel, pattern: item.id });
    }
  }
  return { findings, checksums };
}

function main(argv = process.argv.slice(2)) {
  const { flags } = parseCliArgs(argv);
  const runId = flags.runId || flags.latest;
  if (!runId) throw new Error('redaction requires --run-id <run_id>');
  const runDir = path.join(root, 'benchmark-runs', String(runId));
  if (!fs.existsSync(runDir)) throw new Error(`benchmark run not found: ${runId}`);
  const result = scanRun(runDir);
  ensureDir(path.join(runDir, 'verification'));
  fs.writeFileSync(path.join(runDir, 'verification', 'checksums.sha256'), result.checksums.join('\n') + '\n', 'utf8');
  fs.writeFileSync(path.join(runDir, 'verification', 'redaction-report.md'), `# Redaction report\n\nStatus: ${result.findings.length ? 'failed' : 'passed'}\n\nFindings: ${result.findings.length}\n`, 'utf8');
  const output = {
    schema_version: '3.2.2',
    run_id: runId,
    status: result.findings.length ? 'failed' : 'passed',
    findings: result.findings,
    checksums: 'verification/checksums.sha256'
  };
  if (flags.json) console.log(JSON.stringify(output, null, 2));
  else console.log(`redaction ${output.status}`);
  if (output.status !== 'passed') process.exit(2);
}

if (require.main === module) {
  try { main(); }
  catch (error) {
    const { flags } = parseCliArgs(process.argv.slice(2));
    const output = { schema_version: '3.2.2', status: 'failed', error: error.message };
    if (flags.json) console.log(JSON.stringify(output, null, 2));
    else console.error(error.message);
    process.exit(2);
  }
}

module.exports = { scanRun, forbiddenPatterns };
