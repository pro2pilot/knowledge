#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');

const root = path.resolve(__dirname, '..');

function parseArgs(argv = process.argv.slice(2)) {
  const args = { json: false, report: path.join(root, 'maintenance', 'release-gate-report.json') };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--json') args.json = true;
    else if (arg === '--report') args.report = path.resolve(argv[++i]);
    else if (arg.startsWith('--report=')) args.report = path.resolve(arg.slice('--report='.length));
  }
  return args;
}

function renderMarkdown(result) {
  const lines = [
    '# Pro2Pilot Conformance Report',
    '',
    `Generated: ${result.generated_at}`,
    `Status: ${result.status}`,
    `Mode: ${result.mode}`,
    '',
    '## Artifact',
    '',
    `- Package version: ${result.package_version || 'unknown'}`,
    `- Artifact: ${result.artifact || 'unknown'}`,
    `- SHA-256: ${result.artifact_sha256 || 'not available'}`,
    '',
    '## Step Summary',
    '',
    '| Step | Status | Duration ms |',
    '|---|---|---:|'
  ];
  for (const step of result.steps) lines.push(`| ${step.id} | ${step.status} | ${step.duration_ms} |`);
  if (result.failures.length) {
    lines.push('', '## Failures', '');
    for (const failure of result.failures) lines.push(`- ${failure.id}: ${failure.status}`);
  }
  return `${lines.join('\n')}\n`;
}

function generateFromReport(report, options = {}) {
  const outDir = options.outDir || path.join(root, 'internal', 'pro2pilot-conformance', 'reports');
  fs.mkdirSync(outDir, { recursive: true });
  const result = {
    schema_version: 'pro2pilot-conformance-results.v1',
    generated_at: new Date().toISOString(),
    source_report_schema_version: report.schema_version || null,
    status: report.status === 'pass' ? 'pass' : 'fail',
    mode: report.mode || null,
    package_version: report.package_version || null,
    artifact: report.artifact || null,
    artifact_sha256: report.artifact_sha256 || null,
    node_version: report.node_version || null,
    platform: report.platform || null,
    git_head: report.git_head || null,
    log_dir: report.log_dir || null,
    steps: (report.steps || []).map((step) => ({
      id: step.id,
      status: step.status,
      duration_ms: step.duration_ms,
      stdout_path: step.stdout_path || null,
      stderr_path: step.stderr_path || null
    })),
    failures: report.failures || [],
    skipped: report.skipped || []
  };
  const jsonPath = path.join(outDir, 'conformance-results.latest.json');
  const mdPath = path.join(outDir, 'conformance-report.latest.md');
  fs.writeFileSync(jsonPath, JSON.stringify(result, null, 2) + '\n', 'utf8');
  fs.writeFileSync(mdPath, renderMarkdown(result), 'utf8');
  return {
    schema_version: 'pro2pilot-conformance-report-generator.v1',
    status: 'pass',
    outputs: {
      json: path.relative(root, jsonPath).replace(/\\/g, '/'),
      markdown: path.relative(root, mdPath).replace(/\\/g, '/')
    },
    result
  };
}

function main(argv = process.argv.slice(2)) {
  const args = parseArgs(argv);
  const report = JSON.parse(fs.readFileSync(args.report, 'utf8'));
  const generated = generateFromReport(report);
  if (args.json) console.log(JSON.stringify(generated, null, 2));
  else console.log(`conformance report ${generated.status}`);
}

if (require.main === module) {
  try { main(); }
  catch (error) {
    const args = parseArgs(process.argv.slice(2));
    const result = { schema_version: 'pro2pilot-conformance-report-generator.v1', status: 'fail', error: error.message };
    if (args.json) console.log(JSON.stringify(result, null, 2));
    else console.error(error.message);
    process.exit(2);
  }
}

module.exports = { generateFromReport };
