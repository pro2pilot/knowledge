#!/usr/bin/env node
'use strict';

// Output modes:
//   default    one line per step ("[ ok ] step  Xms")
//   --quiet    final summary only
//   --json     single well-formed JSON object (never ANSI)
//   --no-color disable ANSI escape sequences in all modes
//
// In repo-local mode runtime logs stay under `.knowledge/maintenance/flow-logs`.
// In team mode runtime logs move to `stateRoot/maintenance/flow-logs`.

const fs = require('fs');
const path = require('path');
const { spawnSync, spawn } = require('child_process');
const { parseCliArgs, resolveKnowledgeContext, contextEnv, jsonContext } = require('./lib/path-context');
const { ensureDir, writeJsonAtomic } = require('./lib/json-store');
const { acquireTeamLock, appendTeamEvent, updateWorkspaceFlow } = require('./lib/team-store');
const { inspectSemanticJson } = require('./lib/semantic-json');

const flows = {
  scan: ['sync-tracked.js --scan', 'build-wiki-graph.js', 'lint-wiki.js', 'external-memory-status.js', 'build-routing-bundle.js', 'build-search-index.js', 'build-visual-inspector.js', 'scan-secrets.js', 'doctor.js'],
  doctor: ['sync-tracked.js --scan', 'build-wiki-graph.js', 'lint-wiki.js', 'external-memory-status.js', 'build-routing-bundle.js', 'build-search-index.js', 'scan-secrets.js', 'doctor.js'],
  lint: ['build-wiki-graph.js', 'lint-wiki.js', 'build-search-index.js', 'build-visual-inspector.js', 'scan-secrets.js', 'doctor.js'],
  import: ['install-check.js --json', 'ingest-existing-project.js --merge', 'sync-tracked.js --scan --discover', 'build-wiki-graph.js', 'lint-wiki.js', 'external-memory-status.js', 'build-routing-bundle.js', 'build-search-index.js', 'build-visual-inspector.js', 'scan-secrets.js', 'doctor.js'],
  release: ['sync-tracked.js --scan', 'build-wiki-graph.js', 'lint-wiki.js', 'external-memory-status.js', 'build-routing-bundle.js', 'build-search-index.js', 'build-visual-inspector.js', 'scan-secrets.js', 'doctor.js', 'collect-metrics.js', 'generate-pr-summary.js', 'render-graph-execution.js', 'evaluation-harness.js']
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
  'install-check.js': 'install-check',
  'ingest-existing-project.js': 'ingest'
};

function parseArgs(argv) {
  const parsed = parseCliArgs(argv);
  const flags = parsed.flags;
  const name = parsed.positional[0] || 'release';
  return {
    name,
    quiet: Boolean(flags.quiet),
    json: Boolean(flags.json),
    noColor: Boolean(flags.noColor),
    exclusive: Boolean(flags.exclusive),
    contextFlags: flags
  };
}

function colorEnabled({ json, noColor }) {
  if (json) return false;
  if (noColor) return false;
  if (process.env.NO_COLOR) return false;
  if (!process.stdout.isTTY) return false;
  return true;
}

function updateChecksEnabled(context) {
  const configPath = path.join(context.projectKnowledgeRoot, 'config.yaml');
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

function stepsForFlow(name, context) {
  const base = flows[name] || [];
  if (!updateChecksEnabled(context)) return base;
  const updateStep = 'check-updates.js --auto --json';
  if (base.includes(updateStep)) return base;
  const doctorIndex = base.findIndex((cmd) => cmd.startsWith('doctor.js'));
  if (doctorIndex === -1) return [...base, updateStep];
  return [...base.slice(0, doctorIndex), updateStep, ...base.slice(doctorIndex)];
}

function runOne(cmd, context) {
  const [file, ...args] = cmd.split(/\s+/);
  const scriptPath = path.join(context.systemRoot, 'tools', file);
  const started = Date.now();
  const res = spawnSync(process.execPath, [scriptPath, ...args], {
    cwd: context.targetRoot,
    env: contextEnv(context),
    windowsHide: true
  });
  const duration_ms = Date.now() - started;
  const stdout = (res.stdout || '').toString();
  const stderr = (res.stderr || '').toString();
  let parsed = null;
  if (stdout.trim()) {
    try { parsed = JSON.parse(stdout.trim().replace(/^\uFEFF/, '')); } catch { parsed = null; }
  }
  const semantic = parsed ? inspectSemanticJson(parsed) : { ok: true, errors: [] };
  const success = res.status === 0 && semantic.ok;
  return {
    step: STEP_LABELS[file] || file.replace(/\.js$/, ''),
    command: `${file}${args.length ? ' ' + args.join(' ') : ''}`,
    exit: res.status,
    success,
    status: success ? 'pass' : 'fail',
    json_status: parsed?.status || null,
    semantic_errors: semantic.errors,
    duration_ms,
    parsed,
    stdout: stdout.trim().slice(0, 4000),
    stderr: stderr.trim().slice(0, 2000)
  };
}

function detailFor(step) {
  const p = step.parsed;
  if (!p) return '';
  if (step.step === 'doctor') return `${p.quality_score ?? '-'} /100 ${p.status ?? ''}`;
  if (step.step === 'lint') return `${p.quality_score ?? '-'} /100 ${p.status ?? ''}`;
  if (step.step === 'wiki-graph') return `${p.nodes ?? '-'} nodes / ${p.edges ?? '-'} edges`;
  if (step.step === 'search-idx') return `${p.documents ?? p.document_count ?? '-'} docs`;
  if (step.step === 'routing') return `${p.modules ?? '-'} modules`;
  if (step.step === 'inspector') return `${(p.output || '').replace(/^.*\//, '')}`;
  if (step.step === 'secret-scan') return `${p.status || 'unknown'} / ${(p.findings || []).length} findings`;
  if (step.step === 'ext-memory') return `${p.providers?.pinecone?.mode ?? p.providers?.[0]?.mode ?? 'disabled'}`;
  if (step.step === 'metrics') return `${p.routing?.estimated_percent_saved ?? '-'}% tokens saved`;
  if (step.step === 'updates') return `${p.status || 'unknown'}${p.latest_version ? ' / latest ' + p.latest_version : ''}`;
  return '';
}

function displayPath(filePath, context) {
  const rel = path.relative(context.targetRoot, filePath).replace(/\\/g, '/');
  if (!rel.startsWith('..') && !path.isAbsolute(rel)) return rel;
  return filePath;
}

function readJsonIfExists(filePath, fallback) {
  if (!fs.existsSync(filePath)) return fallback;
  try {
    return JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch {
    return fallback;
  }
}

function onboardingFollowUp(context, flowName) {
  if (!['import', 'release'].includes(flowName)) return null;
  const profile = readJsonIfExists(path.join(context.projectKnowledgeRoot, 'settings', 'operator-profile.json'), {});
  const completed = profile.first_run_onboarding_completed === true;
  if (completed) return null;
  const chatMessage = '.knowledge is installed and already working. I opened the local Inspector for First-run setup so you can tune agent behavior, autonomy rules, and chat/report preferences for full capabilities.';
  return {
    required: true,
    reason: Object.prototype.hasOwnProperty.call(profile, 'first_run_onboarding_completed') ? 'not_completed' : 'upgrade_missing_completion_marker',
    command: 'node .knowledge/inspector.js',
    note: 'The system is ready. Complete First-run setup in the live Inspector for full behavior and autonomy controls.',
    chat_message: chatMessage,
    auto_launch: true,
    auto_launch_disable_env: 'KNOWLEDGE_FLOW_NO_OPEN=1'
  };
}

function launchInspectorForOnboarding(context) {
  const entry = path.join(context.projectKnowledgeRoot, 'inspector.js');
  if (!fs.existsSync(entry)) {
    return { attempted: true, status: 'missing_entrypoint', entry };
  }
  if (process.env.KNOWLEDGE_FLOW_NO_OPEN === '1' || process.env.CI === 'true') {
    return { attempted: false, status: 'disabled', reason: process.env.CI === 'true' ? 'ci' : 'KNOWLEDGE_FLOW_NO_OPEN' };
  }
  const child = spawn(process.execPath, [entry, '--open'], {
    cwd: context.targetRoot,
    env: contextEnv(context),
    detached: true,
    stdio: 'ignore',
    windowsHide: true
  });
  child.unref();
  return {
    attempted: true,
    status: 'started',
    command: 'node .knowledge/inspector.js --open'
  };
}

function writeFlowLog(name, started, results, totalMs, context) {
  const dir = path.join(context.stateRoot, 'maintenance', 'flow-logs');
  ensureDir(dir);
  const ts = started.toISOString().replace(/[:.]/g, '-');
  const file = path.join(dir, `${name}-${ts}.json`);
  writeJsonAtomic(file, {
    flow: name,
    context: jsonContext(context),
    started_at: started.toISOString(),
    duration_total_ms: totalMs,
    steps_total: results.length,
    steps_ok: results.filter((r) => r.success).length,
    overall_status: results.every((r) => r.success) ? 'ok' : 'failed',
    steps: results
  });
  return displayPath(file, context);
}

function runFlow(options) {
  const { name, quiet, json, noColor, exclusive, context } = options;
  if (!flows[name]) {
    throw new Error(`Unknown flow: ${name}. Available: ${Object.keys(flows).join(', ')}`);
  }
  ensureDir(path.join(context.stateRoot, 'maintenance'));
  appendTeamEvent(context, 'flow_start', { flow: name, exclusive });
  const useColor = colorEnabled({ json, noColor });
  const ansi = {
    ok: (s) => useColor ? `\x1b[32m${s}\x1b[0m` : s,
    fail: (s) => useColor ? `\x1b[31m${s}\x1b[0m` : s
  };
  const started = new Date();
  const startedMs = Date.now();
  const results = [];
  for (const cmd of stepsForFlow(name, context)) {
    const result = runOne(cmd, context);
    results.push(result);
    appendTeamEvent(context, 'flow_step', { flow: name, step: result.step, exit: result.exit, success: result.success, duration_ms: result.duration_ms });
    if (!quiet && !json) {
      const status = result.success ? ansi.ok('ok') : ansi.fail('fail');
      const detail = detailFor(result);
      const pad = (s, n) => (s + ' '.repeat(n)).slice(0, n);
      console.log(`[ ${status} ] ${pad(result.step, 11)} ${String(result.duration_ms).padStart(5, ' ')} ms${detail ? '  /  ' + detail : ''}`);
    }
  }
  const totalMs = Date.now() - startedMs;
  const ok = results.filter((r) => r.success).length;
  const total = results.length;
  const logRel = writeFlowLog(name, started, results, totalMs, context);
  const overall = ok === total ? 'ok' : 'failed';
  const onboarding = onboardingFollowUp(context, name);
  if (overall === 'ok' && onboarding?.required && !json && !quiet) {
    onboarding.launch = launchInspectorForOnboarding(context);
  }
  const out = {
    flow: name,
    mode: context.mode,
    repo_id: context.repoId,
    workspace_id: context.workspaceId,
    agent_id: context.agentId,
    target_root: context.targetRoot,
    project_knowledge_root: context.projectKnowledgeRoot,
    state_root: context.stateRoot,
    branch: context.branch,
    head_sha: context.headSha,
    started_at: started.toISOString(),
    duration_total_ms: totalMs,
    steps_total: total,
    steps_ok: ok,
    status: overall,
    overall_status: overall,
    warnings: context.warnings,
    flow_log: logRel,
    onboarding_follow_up: onboarding,
    steps: results.map((r) => ({
      step: r.step,
      command: r.command,
      exit: r.exit,
      success: r.success,
      status: r.status,
      json_status: r.json_status,
      semantic_errors: r.semantic_errors,
      duration_ms: r.duration_ms,
      summary: detailFor(r)
    }))
  };
  updateWorkspaceFlow(context, out);
  appendTeamEvent(context, 'flow_end', { flow: name, overall_status: overall, steps_ok: ok, steps_total: total, flow_log: logRel });
  return out;
}

function main(argv = process.argv.slice(2)) {
  const args = parseArgs(argv);
  const context = resolveKnowledgeContext(args.contextFlags);
  let release = null;
  try {
    if (context.mode === 'team' && args.exclusive) release = acquireTeamLock(context, 'flow');
    const out = runFlow({ ...args, context });
    if (args.json) console.log(JSON.stringify(out, null, 2));
    else {
      console.log(`flow.${args.name}: ${out.steps_ok}/${out.steps_total} ok / ${out.duration_total_ms} ms / log: ${out.flow_log}`);
      if (out.onboarding_follow_up?.required) {
        if (out.onboarding_follow_up.chat_message) console.log(out.onboarding_follow_up.chat_message);
        if (out.onboarding_follow_up.launch?.status === 'started') console.log('Inspector opened for First-run setup.');
        else console.log(`next: ${out.onboarding_follow_up.command}`);
        console.log(out.onboarding_follow_up.note);
      }
    }
    if (out.overall_status !== 'ok') process.exit(2);
    return out;
  } finally {
    if (release) release();
  }
}

if (require.main === module) {
  try { main(); }
  catch (error) { console.error(error.stack || error.message); process.exit(1); }
}

module.exports = { runOne, parseArgs, colorEnabled, runFlow };
