#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { parseCliArgs } = require('../tools/lib/path-context');
const { ensureDir, readJson, writeJsonAtomic } = require('../tools/lib/json-store');
const { createZip } = require('../tools/package-release');
const { forbiddenPatterns } = require('./lib/redaction');

const root = path.resolve(__dirname, '..');

function walk(dir, out = []) {
  if (!fs.existsSync(dir)) return out;
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const abs = path.join(dir, entry.name);
    if (entry.isDirectory()) walk(abs, out);
    else if (entry.isFile()) out.push(abs);
  }
  return out;
}

function sha256(file) {
  return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
}

function textFile(file) {
  return /\.(csv|html|json|md|ndjson|ps1|sh|svg|txt)$/i.test(file);
}

function latestRunId() {
  const runsRoot = path.join(root, 'benchmark-runs');
  if (!fs.existsSync(runsRoot)) throw new Error('No benchmark-runs directory found. Run run-benchmarks.js first.');
  const dirs = fs.readdirSync(runsRoot, { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .map((entry) => {
      const abs = path.join(runsRoot, entry.name);
      return { name: entry.name, mtimeMs: fs.statSync(abs).mtimeMs };
    })
    .sort((a, b) => b.mtimeMs - a.mtimeMs);
  if (!dirs.length) throw new Error('No benchmark run directories found.');
  return dirs[0].name;
}

function loadRun(runId) {
  const runDir = path.join(root, 'benchmark-runs', runId);
  const manifest = readJson(path.join(runDir, 'manifest.json'), null);
  if (!manifest) throw new Error(`Benchmark run not found or missing manifest: ${runId}`);
  return { runDir, manifest };
}

function claimText(suite) {
  const measured = ['measured', 'measured-on-fixture'].includes(suite.claim_status);
  if (!measured) return 'Not approved for public marketing.';
  const firstMetric = Object.entries(suite.metrics || {})[0];
  const metricText = firstMetric ? `${firstMetric[0]}=${firstMetric[1]}` : `status=${suite.status}`;
  return `${suite.id} ${suite.title}: ${metricText}.`;
}

function marketableSuites(manifest) {
  return (manifest.results || []).filter((suite) => ['measured', 'measured-on-fixture'].includes(suite.claim_status));
}

function blockedSuites(manifest) {
  return (manifest.results || []).filter((suite) => !['measured', 'measured-on-fixture'].includes(suite.claim_status));
}

function tableRows(suites) {
  return suites.map((suite) => {
    const metrics = Object.entries(suite.metrics || {}).map(([key, value]) => `${key}=${value}`).join(', ') || 'status only';
    const evidence = (suite.evidence || [])[0] || `raw/${suite.slug}.json`;
    const limitation = (suite.limitations || [])[0] || 'local fixture scope';
    return `| ${suite.id} | ${suite.status} | ${suite.claim_status} | ${metrics} | ${evidence} | ${limitation} |`;
  }).join('\n');
}

function renderReadme(runId, manifest, allowed, blocked) {
  return `# Marketing Proof Pack

Run: ${runId}

Verdict: ${manifest.verdict}

This pack only promotes suites with \`measured\` or \`measured-on-fixture\` claim status. Preview, planned, diagnostic and failed suites are included only as limitations.

## Approved public claims

${allowed.map((suite) => `- ${claimText(suite)} Evidence: \`${(suite.evidence || [])[0] || `raw/${suite.slug}.json`}\`.`).join('\n') || '- No public claims are approved from this run.'}

## Not approved

${blocked.map((suite) => `- ${suite.id} ${suite.title}: ${suite.claim_status}; ${(suite.limitations || [])[0] || 'needs more evidence'}.`).join('\n') || '- None.'}

## Reproduce

\`\`\`sh
node .knowledge/benchmarks/run-benchmarks.js --suite ${manifest.suite} --runs ${manifest.runs} --json
node .knowledge/benchmarks/generate-marketing-pack.js --latest --json
\`\`\`
`;
}

function renderClaimMap(allowed, blocked) {
  return `# Claim Evidence Map

## Public-ready

| Suite | Status | Claim status | Metrics | Evidence | Limitation |
|---|---|---|---|---|---|
${tableRows(allowed) || '| None | n/a | n/a | n/a | n/a | no public claims approved |'}

## Held back

| Suite | Status | Claim status | Metrics | Evidence | Limitation |
|---|---|---|---|---|---|
${tableRows(blocked) || '| None | n/a | n/a | n/a | n/a | n/a |'}
`;
}

function renderProofCards(allowed, blocked) {
  return `# Proof Cards

${allowed.map((suite) => `## ${suite.id} ${suite.title}

- Approved wording: ${claimText(suite)}
- Evidence: ${(suite.evidence || []).join(', ') || `raw/${suite.slug}.json`}
- Scope: ${(suite.limitations || [])[0] || 'local fixture scope'}
`).join('\n') || 'No approved proof cards in this run.\n'}

## Guardrails

- Do not say best, fastest, guaranteed, enterprise-ready, replaces code review, or 10x.
- Keep preview and planned suites out of public claims.
- Mention fixture scope when using measured-on-fixture claims.

## Held-back proof

${blocked.map((suite) => `- ${suite.id}: ${suite.claim_status}; ${(suite.limitations || [])[0] || 'needs more evidence'}.`).join('\n') || '- None.'}
`;
}

function renderHomepage(allowed) {
  return `# Homepage Block

Measured local proof for repo-local knowledge governance.

${allowed.slice(0, 3).map((suite) => `- ${claimText(suite)}`).join('\n') || '- Public proof is pending measured claims.'}

Every claim links back to raw benchmark artifacts, reproduction commands and limitations.
`;
}

function renderReadmeBlock(allowed) {
  return `# README Block

## Benchmark Proof

${allowed.map((suite) => `- ${claimText(suite)} See \`${(suite.evidence || [])[0] || `raw/${suite.slug}.json`}\`.`).join('\n') || '- No public claims are approved from the latest benchmark run.'}

Full methodology and limitations are in the benchmark run folder.
`;
}

function renderLaunchPosts(allowed, blocked) {
  const claims = allowed.slice(0, 3).map((suite) => claimText(suite)).join(' ');
  const caveat = blocked.length ? `${blocked.length} suite(s) remain preview, planned, diagnostic or failed and are not used as claims.` : 'All included claims are measured in this run.';
  return {
    hn: `Show HN: .knowledge, a repo-local governance layer for AI coding agents\n\nWe built local benchmark artifacts for routing, trust/freshness, PR impact, Team Mode and memory safety. ${claims || 'The latest run did not approve public claims yet.'} ${caveat}`,
    reddit: `We ran a local proof pack for .knowledge. The useful part is that every claim has a claim ID, raw artifact, reproduction command and limitation. ${claims || 'No public claims approved in this run.'} ${caveat}`,
    linkedin: `.knowledge is a repo-local knowledge governance layer for AI coding agents. Latest local benchmark proof: ${claims || 'claims pending further measured runs.'} We are keeping preview/planned suites out of public copy.`,
    x: `1/ Local benchmark proof pack for .knowledge is ready.\n2/ Approved claims only come from measured or measured-on-fixture suites.\n3/ ${claims || 'No claims approved yet.'}\n4/ Limitations stay in the copy: ${caveat}`
  };
}

function renderDemoScript(allowed, minutes) {
  const beats = [
    'Open the benchmark run executive summary.',
    'Show the claim evidence map and explain measured versus preview status.',
    'Open raw suite JSON for one approved claim.',
    'Show the redaction report and checksums.',
    'End on the limitation that every public claim must cite a run artifact.'
  ];
  if (allowed.some((suite) => suite.id === 'KB-12')) beats.splice(2, 0, 'Show Team Mode fixture evidence for isolated workspace state.');
  return `# ${minutes}-Minute Demo Script

${beats.map((beat, index) => `${index + 1}. ${beat}`).join('\n')}
`;
}

function renderChartSvg(allowed, blocked) {
  const total = Math.max(1, allowed.length + blocked.length);
  const approvedWidth = Math.round((allowed.length / total) * 520);
  return `<svg xmlns="http://www.w3.org/2000/svg" width="640" height="220" role="img" aria-label="Benchmark claim readiness chart">
  <rect width="640" height="220" fill="#f6f7f2"/>
  <text x="32" y="44" fill="#17211a" font-family="Arial" font-size="22">Claim readiness</text>
  <rect x="32" y="76" width="520" height="42" fill="#d8ded5"/>
  <rect x="32" y="76" width="${approvedWidth}" height="42" fill="#2f6f4e"/>
  <text x="32" y="150" fill="#17211a" font-family="Arial" font-size="16">Approved: ${allowed.length}</text>
  <text x="32" y="178" fill="#17211a" font-family="Arial" font-size="16">Held back: ${blocked.length}</text>
  <text x="32" y="202" fill="#5b645d" font-family="Arial" font-size="12">Generated from benchmark manifest; not a product screenshot.</text>
</svg>
`;
}

function renderSummaryCard(runId, manifest, allowed, blocked) {
  return `<svg xmlns="http://www.w3.org/2000/svg" width="960" height="540" role="img" aria-label="Benchmark run summary card">
  <rect width="960" height="540" fill="#111814"/>
  <text x="48" y="72" fill="#f7f4ea" font-family="Arial" font-size="36">Benchmark proof pack</text>
  <text x="48" y="118" fill="#cfd7ce" font-family="Arial" font-size="18">Run ${runId}</text>
  <text x="48" y="190" fill="#f7f4ea" font-family="Arial" font-size="28">Verdict: ${manifest.verdict}</text>
  <text x="48" y="250" fill="#8ed0a8" font-family="Arial" font-size="24">Approved claims: ${allowed.length}</text>
  <text x="48" y="292" fill="#e1b667" font-family="Arial" font-size="24">Held back: ${blocked.length}</text>
  <text x="48" y="390" fill="#cfd7ce" font-family="Arial" font-size="18">Generated evidence card, not a product UI screenshot.</text>
</svg>
`;
}

function scanPack(packDir) {
  const findings = [];
  const checksums = [];
  for (const file of walk(packDir)) {
    if (file.endsWith('.zip')) continue;
    const rel = path.relative(packDir, file).replace(/\\/g, '/');
    checksums.push(`${sha256(file)}  ${rel}`);
    if (!textFile(file)) continue;
    const text = fs.readFileSync(file, 'utf8');
    for (const item of forbiddenPatterns()) {
      if (item.pattern.test(text)) findings.push({ file: rel, pattern: item.id });
    }
  }
  return { findings, checksums };
}

function zipDirectory(dir, zipPath) {
  const entries = walk(dir).filter((file) => file !== zipPath).map((abs) => {
    const rel = path.relative(dir, abs).replace(/\\/g, '/');
    return { abs, rel, name: rel };
  });
  createZip(entries, zipPath);
}

function generate(runId) {
  const { manifest } = loadRun(runId);
  const packDir = path.join(root, 'marketing-proof-packs', runId);
  const allowed = marketableSuites(manifest);
  const blocked = blockedSuites(manifest);
  for (const dir of ['', 'screenshots', 'charts', 'verification']) ensureDir(path.join(packDir, dir));
  writeJsonAtomic(path.join(packDir, 'manifest.json'), {
    schema_version: '3.2.1',
    run_id: runId,
    source_benchmark_run: `benchmark-runs/${runId}`,
    generated_at: new Date().toISOString(),
    public_claims_approved: allowed.length,
    public_claims_blocked: blocked.length,
    verdict: manifest.verdict
  });
  fs.writeFileSync(path.join(packDir, 'README.md'), renderReadme(runId, manifest, allowed, blocked), 'utf8');
  fs.writeFileSync(path.join(packDir, 'claim_evidence_map.md'), renderClaimMap(allowed, blocked), 'utf8');
  fs.writeFileSync(path.join(packDir, 'proof_cards.md'), renderProofCards(allowed, blocked), 'utf8');
  fs.writeFileSync(path.join(packDir, 'homepage_block.md'), renderHomepage(allowed), 'utf8');
  fs.writeFileSync(path.join(packDir, 'readme_block.md'), renderReadmeBlock(allowed), 'utf8');
  const posts = renderLaunchPosts(allowed, blocked);
  fs.writeFileSync(path.join(packDir, 'launch_post_hn.md'), posts.hn + '\n', 'utf8');
  fs.writeFileSync(path.join(packDir, 'launch_post_reddit.md'), posts.reddit + '\n', 'utf8');
  fs.writeFileSync(path.join(packDir, 'linkedin_post.md'), posts.linkedin + '\n', 'utf8');
  fs.writeFileSync(path.join(packDir, 'x_thread.md'), posts.x + '\n', 'utf8');
  fs.writeFileSync(path.join(packDir, 'demo_60s_script.md'), renderDemoScript(allowed, '60-Second'), 'utf8');
  fs.writeFileSync(path.join(packDir, 'demo_3min_script.md'), renderDemoScript(allowed, '3'), 'utf8');
  fs.writeFileSync(path.join(packDir, 'screenshots', 'run-summary-card.svg'), renderSummaryCard(runId, manifest, allowed, blocked), 'utf8');
  fs.writeFileSync(path.join(packDir, 'screenshots', 'README.md'), 'Generated evidence cards are included here. Browser screenshots are not claimed unless produced by a separate visual run.\n', 'utf8');
  fs.writeFileSync(path.join(packDir, 'charts', 'claim-readiness.svg'), renderChartSvg(allowed, blocked), 'utf8');
  const scan = scanPack(packDir);
  fs.writeFileSync(path.join(packDir, 'verification', 'checksums.sha256'), scan.checksums.join('\n') + '\n', 'utf8');
  fs.writeFileSync(path.join(packDir, 'redaction_report.md'), `# Redaction report

Status: ${scan.findings.length ? 'failed' : 'passed'}

Findings: ${scan.findings.length}
`, 'utf8');
  if (scan.findings.length) throw new Error(`marketing pack redaction failed: ${JSON.stringify(scan.findings.slice(0, 5))}`);
  zipDirectory(packDir, path.join(root, 'marketing-proof-packs', `${runId}.zip`));
  return {
    schema_version: '3.2.1',
    status: 'ok',
    run_id: runId,
    pack_dir: `marketing-proof-packs/${runId}`,
    pack_archive: `marketing-proof-packs/${runId}.zip`,
    public_claims_approved: allowed.length,
    public_claims_blocked: blocked.length
  };
}

function main(argv = process.argv.slice(2)) {
  const { flags } = parseCliArgs(argv);
  const runId = flags.runId || (flags.latest ? latestRunId() : null);
  if (!runId) throw new Error('Usage: node benchmarks/generate-marketing-pack.js --latest|--run-id <id> [--json]');
  const result = generate(String(runId));
  if (flags.json) console.log(JSON.stringify(result, null, 2));
  else console.log(`marketing proof pack: ${result.pack_dir}`);
}

if (require.main === module) {
  try { main(); }
  catch (error) {
    const { flags } = parseCliArgs(process.argv.slice(2));
    const output = { schema_version: '3.2.1', status: 'failed', error: error.message };
    if (flags.json) console.log(JSON.stringify(output, null, 2));
    else console.error(error.message);
    process.exit(2);
  }
}

module.exports = { generate, latestRunId };
