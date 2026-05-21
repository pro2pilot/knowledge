#!/usr/bin/env node
'use strict';

//   default    one line per step ("[ ok ] step  Xms")
//   --quiet    final summary only
//   --json     single well-formed JSON object (never ANSI)
//   --no-color disable ANSI escape sequences in all modes
// Per-step logs are always written to
// .knowledge/maintenance/flow-logs/<flow>-<timestamp>.json so debugging
// stays available without polluting the terminal.

const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const knowledgeRoot = path.resolve(__dirname, '..');
const repoRoot = path.resolve(knowledgeRoot, '..');

const flows = {
  scan:   ['sync-tracked.js --scan', 'build-wiki-graph.js', 'lint-wiki.js', 'external-memory-status.js', 'build-routing-bundle.js', 'build-search-index.js', 'build-visual-inspector.js', 'scan-secrets.js', 'doctor.js'],
  doctor: ['external-memory-status.js', 'build-routing-bundle.js', 'build-search-index.js', 'doctor.js'],
  lint:   ['build-wiki-graph.js', 'lint-wiki.js', 'build-search-index.js', 'build-visual-inspector.js', 'scan-secrets.js', 'doctor.js'],
  import: ['ingest-existing-project.js --merge', 'sync-tracked.js --scan --discover', 'build-wiki-graph.js', 'lint-wiki.js', 'external-memory-status.js', 'build-routing-bundle.js', 'build-search-index.js', 'build-visual-inspector.js', 'scan-secrets.js', 'doctor.js'],
  release:['sync-tracked.js --scan', 'build-wiki-graph.js', 'lint-wiki.js', 'external-memory-status.js', 'build-routing-bundle.js', 'build-search-index.js', 'build-visual-inspector.js', 'scan-secrets.js', 'doctor.js', 'collect-metrics.js', 'generate-pr-summary.js', 'render-graph-execution.js', 'evaluation-harness.js']
};

const STEP_LABELS = {
  'sync-tracked.js': 'sync',
  'build-wiki-graph.js': 'wiki-graph',
  'lint-wiki.js': 'lint',
  'external-memory-status.js': 'ext-memory',
  'check-updates.js': 'updates',
  'build-routing-bundle.js': 'routing',
  'build-search-index.js': 'search-idx',
  'build-visual-inspector.js': 'inspector',
  'scan-secrets.js': 'secret-scan',
  'doctor.js': 'doctor',
  'collect-metrics.js': 'metrics',
  'generate-pr-summary.js': 'pr-summary',
  'render-graph-execution.js': 'graphs',
  'evaluation-harness.js': 'harness',
  'ingest-existing-project.js': 'ingest'
};

function parseArgs(argv) {
  const positional = [];
  let quiet = false;
  let json = false;
  let noColor = false;
  for (const arg of argv) {
    if (arg === '--quiet') quiet = true;
    else if (arg === '--json') json = true;
    else if (arg === '--no-color') noColor = true;
    else positional.push(arg);
  }
  const name = positional[0] || 'release';
  return { name, quiet, json, noColor };
}

function colorEnabled({ json, noColor }) {
  if (json) return false;
  if (noColor) return false;
  if (process.env.NO_COLOR) return false;
  if (!process.stdout.isTTY) return false;
  return true;
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

function stepsForFlow(name) {
  const base = flows[name] || [];
  if (!updateChecksEnabled()) return base;
  const updateStep = 'check-updates.js --auto --json';
  if (base.includes(updateStep)) return base;
  const doctorIndex = base.findIndex((cmd) => cmd.startsWith('doctor.js'));
  if (doctorIndex === -1) return [...base, updateStep];
  return [...base.slice(0, doctorIndex), updateStep, ...base.slice(doctorIndex)];
}

function runOne(cmd) {
  const [file, ...args] = cmd.split(/\s+/);
  const scriptPath = path.join(knowledgeRoot, 'tools', file);
  const started = Date.now();
  const res = spawnSync(process.execPath, [scriptPath, ...args], { cwd: repoRoot });
  const duration_ms = Date.now() - started;
  const stdout = (res.stdout || '').toString();
  const stderr = (res.stderr || '').toString();
  let parsed = null;
  if (stdout.trim()) {
    try { parsed = JSON.parse(stdout); } catch { parsed = null; }
  }
  return {
    step: STEP_LABELS[file] || file.replace(/\.js$/, ''),
    command: `${file}${args.length ? ' ' + args.join(' ') : ''}`,
    exit: res.status,
    duration_ms,
    parsed,
    stdout: stdout.trim().slice(0, 4000),
    stderr: stderr.trim().slice(0, 2000)
  };
}

function detailFor(step) {
  const p = step.parsed;
  if (!p) return '';
  if (step.step === 'doctor') return `${p.quality_score ?? '-'}/100 ${p.status ?? ''}`;
  if (step.step === 'lint') return `${p.quality_score ?? '-'}/100 ${p.status ?? ''}`;
  if (step.step === 'wiki-graph') return `${p.nodes ?? '-'} nodes / ${p.edges ?? '-'} edges`;
  if (step.step === 'search-idx') return `${p.documents ?? '-'} docs`;
  if (step.step === 'routing') return `${p.modules ?? '-'} modules`;
  if (step.step === 'inspector') return `${(p.output || '').replace(/^.*\//, '')}`;
  if (step.step === 'secret-scan') return `${p.status || 'unknown'} · ${(p.findings || []).length} findings`;
  if (step.step === 'ext-memory') return `${p.providers?.pinecone?.mode ?? 'disabled'}`;
  if (step.step === 'metrics') return `${p.routing?.estimated_percent_saved ?? '-'}% tokens saved`;
  if (step.step === 'updates') return `${p.status || 'unknown'}${p.latest_version ? ' · latest ' + p.latest_version : ''}`;
  return '';
}

function writeFlowLog(name, started, results, totalMs) {
  const dir = path.join(knowledgeRoot, 'maintenance', 'flow-logs');
  fs.mkdirSync(dir, { recursive: true });
  const ts = started.toISOString().replace(/[:.]/g, '-');
  const file = path.join(dir, `${name}-${ts}.json`);
  fs.writeFileSync(file, JSON.stringify({
    flow: name,
    started_at: started.toISOString(),
    duration_total_ms: totalMs,
    steps_total: results.length,
    steps_ok: results.filter((r) => r.exit === 0).length,
    overall_status: results.every((r) => r.exit === 0) ? 'ok' : 'failed',
    steps: results
  }, null, 2));
  return path.relative(repoRoot, file).replace(/\\/g, '/');
}

function main(argv = process.argv.slice(2)) {
  const { name, quiet, json, noColor } = parseArgs(argv);
  if (!flows[name]) {
    console.error(`Unknown flow: ${name}. Available: ${Object.keys(flows).join(', ')}`);
    process.exit(1);
  }
  const useColor = colorEnabled({ json, noColor });
  const ansi = {
    ok: (s) => useColor ? `[32m${s}[0m` : s,
    fail: (s) => useColor ? `[31m${s}[0m` : s
  };
  const started = new Date();
  const startedMs = Date.now();
  const results = [];
  for (const cmd of stepsForFlow(name)) {
    const result = runOne(cmd);
    results.push(result);
    if (!quiet && !json) {
      const status = result.exit === 0 ? ansi.ok('ok') : ansi.fail('fail');
      const detail = detailFor(result);
      const pad = (s, n) => (s + ' '.repeat(n)).slice(0, n);
      console.log(`[ ${status} ] ${pad(result.step, 11)} ${String(result.duration_ms).padStart(5, ' ')} ms${detail ? '  ·  ' + detail : ''}`);
    }
  }
  const totalMs = Date.now() - startedMs;
  const ok = results.filter((r) => r.exit === 0).length;
  const total = results.length;
  const logRel = writeFlowLog(name, started, results, totalMs);
  const overall = ok === total ? 'ok' : 'failed';

  if (json) {
    const out = {
      flow: name,
      started_at: started.toISOString(),
      duration_total_ms: totalMs,
      steps_total: total,
      steps_ok: ok,
      overall_status: overall,
      flow_log: logRel,
      steps: results.map((r) => ({ step: r.step, command: r.command, exit: r.exit, duration_ms: r.duration_ms, summary: detailFor(r) }))
    };
    console.log(JSON.stringify(out, null, 2));
  } else {
    console.log(`flow.${name}: ${ok}/${total} ok · ${totalMs} ms · log: ${logRel}`);
  }
  if (overall !== 'ok') process.exit(2);
}

if (require.main === module) main();

module.exports = { runOne, parseArgs, colorEnabled };
