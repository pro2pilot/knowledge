#!/usr/bin/env node
'use strict';

const fs = require('fs');
const http = require('http');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { spawn, spawnSync } = require('child_process');

const systemRoot = path.resolve(__dirname, '..');

function assert(condition, message, details = null) {
  if (!condition) {
    const error = new Error(message);
    if (details) error.details = details;
    throw error;
  }
}

function readJson(filePath, fallback = null) {
  try { return JSON.parse(fs.readFileSync(filePath, 'utf8')); }
  catch { return fallback; }
}

function writeJson(filePath, value) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, JSON.stringify(value, null, 2) + '\n', 'utf8');
}

function sha256(filePath) {
  return crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
}

function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: options.cwd || systemRoot,
    env: { ...process.env, ...(options.env || {}) },
    encoding: 'utf8',
    windowsHide: true,
    timeout: options.timeoutMs || 180000
  });
  return {
    command: [path.basename(command), ...args].join(' '),
    status: result.status,
    stdout: result.stdout || '',
    stderr: result.stderr || '',
    error: result.error || null
  };
}

function mustJson(command, args, options = {}) {
  const result = run(command, args, options);
  assert(result.status === 0, `${result.command} failed`, result);
  try {
    return JSON.parse(result.stdout);
  } catch (error) {
    throw new Error(`${result.command} did not return JSON: ${error.message}\n${result.stdout}\n${result.stderr}`);
  }
}

function nodeTool(tool, args, context, options = {}) {
  return mustJson(process.execPath, [
    path.join(systemRoot, 'tools', tool),
    ...args,
    '--system-root', systemRoot,
    '--project-knowledge-root', systemRoot,
    '--target-root', context.project,
    '--state-root', context.state
  ], {
    cwd: context.project,
    env: {
      KNOWLEDGE_AGENT_ID: 'canonical-e2e',
      KNOWLEDGE_INSPECTOR_NO_OPEN: '1',
      ...(options.env || {})
    },
    timeoutMs: options.timeoutMs || 240000
  });
}

function httpRequest(port, method, requestPath, token = null, body = null) {
  return new Promise((resolve, reject) => {
    const payload = body ? JSON.stringify(body) : '';
    const headers = {
      ...(token ? { authorization: `Bearer ${token}` } : {}),
      ...(payload ? { 'content-type': 'application/json', 'content-length': Buffer.byteLength(payload) } : {})
    };
    const req = http.request({ hostname: '127.0.0.1', port, path: requestPath, method, headers }, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk.toString(); });
      res.on('end', () => {
        let json = null;
        try { json = JSON.parse(data); } catch {}
        resolve({ status: res.statusCode, body: data, json });
      });
    });
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

async function waitForInspector(port, child) {
  let lastError = null;
  for (let i = 0; i < 80; i += 1) {
    if (child.exitCode !== null) throw new Error(`Inspector exited early with ${child.exitCode}`);
    try {
      const page = await httpRequest(port, 'GET', '/');
      const match = page.body.match(/const sessionToken=(".*?");/) || page.body.match(/const token=(".*?");/);
      if (page.status === 200 && match) return JSON.parse(match[1]);
    } catch (error) {
      lastError = error;
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw lastError || new Error('Inspector did not become ready');
}

async function inspectorE2E(context, checks) {
  const port = 23000 + Math.floor(Math.random() * 20000);
  const child = spawn(process.execPath, [
    path.join(systemRoot, 'tools', 'serve-inspector.js'),
    '--port', String(port),
    '--system-root', systemRoot,
    '--project-knowledge-root', systemRoot,
    '--target-root', context.project,
    '--state-root', context.state
  ], {
    cwd: systemRoot,
    env: { ...process.env, KNOWLEDGE_AGENT_ID: 'canonical-e2e', KNOWLEDGE_INSPECTOR_NO_OPEN: '1', KNOWLEDGE_UPDATE_DISABLE_ON_LAUNCH: '1' },
    windowsHide: true,
    stdio: ['ignore', 'pipe', 'pipe']
  });
  const stderr = [];
  child.stderr.on('data', (chunk) => stderr.push(chunk.toString()));
  try {
    const token = await waitForInspector(port, child);
    const invalid = await httpRequest(port, 'GET', '/api/state', 'invalid-token');
    assert(invalid.status === 401, 'invalid Inspector token must be rejected');

    const state = await httpRequest(port, 'GET', '/api/state', token);
    assert(state.status === 200, 'Inspector state API failed', state);
    assert(state.json?.state?.product?.version === '3.2.0', 'Inspector state did not report 3.2.0');
    assert(state.json.state.product.no_cloud_required === true, 'free Inspector must remain no-cloud');

    const actions = await httpRequest(port, 'GET', '/api/actions', token);
    const ids = new Set((actions.json?.actions || []).map((action) => action.id));
    for (const id of ['doctor.run', 'trust.restore.safe', 'memory.status', 'team.status', 'report.debug_bundle', 'report.pro_snapshot', 'pro.pr_impact_pro']) {
      assert(ids.has(id), `Inspector action missing: ${id}`);
    }

    const fixtureSecret = ['sk', 'live', 'THIS_SHOULD_BE_REDACTED_1234567890'].join('-');
    writeJson(path.join(context.state, 'maintenance', 'trust_report.json'), {
      schema_version: 'test',
      status: 'fixture',
      api_key: fixtureSecret
    });
    const debugRun = await httpRequest(port, 'POST', '/api/actions/report.debug_bundle/run', token, { confirmed: true });
    assert(debugRun.status === 200 && debugRun.json?.run?.status === 'passed', 'debug bundle action did not pass', debugRun);
    const stdout = fs.readFileSync(debugRun.json.run.stdout_path, 'utf8');
    assert(!stdout.includes(fixtureSecret), 'debug bundle action log leaked a secret');
    assert(stdout.includes('<redacted'), 'debug bundle action log did not redact fixture secret');

    const runFetch = await httpRequest(port, 'GET', `/api/runs/${encodeURIComponent(debugRun.json.run.run_id)}`, token);
    assert(runFetch.status === 200 && runFetch.json?.run?.run_id === debugRun.json.run.run_id, 'run lifecycle fetch failed');
    const stream = await httpRequest(port, 'GET', `/api/runs/${encodeURIComponent(debugRun.json.run.run_id)}/stream`, token);
    assert(stream.status === 200 && stream.body.includes('event: run'), 'run stream fallback failed');

    const pro = await httpRequest(port, 'POST', '/api/actions/pro.pr_impact_pro/run', token, { confirmed: true });
    assert(pro.status === 423 && pro.json?.run?.status === 'blocked', 'Pro action must be gated in free mode', pro);
    checks.push('live Inspector token auth, API, actions, lifecycle, SSE fallback, redaction and Pro gate');
  } finally {
    child.kill();
    if (stderr.join('').trim()) checks.push('Inspector stderr captured for diagnostics');
  }
}

function createFixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge-canonical-e2e-'));
  const project = path.join(root, 'repo');
  const state = path.join(root, 'state');
  fs.mkdirSync(project, { recursive: true });
  fs.mkdirSync(state, { recursive: true });
  fs.writeFileSync(path.join(project, 'package.json'), '{"name":"canonical-e2e-fixture","version":"1.0.0"}\n', 'utf8');
  fs.writeFileSync(path.join(project, 'index.js'), 'module.exports = function answer() { return 42; };\n', 'utf8');
  fs.writeFileSync(path.join(project, 'README.md'), '# Canonical E2E Fixture\n', 'utf8');
  const gitInit = run('git', ['init', '-b', 'main'], { cwd: project, timeoutMs: 60000 });
  if (gitInit.status !== 0) run('git', ['init'], { cwd: project, timeoutMs: 60000 });
  run('git', ['config', 'user.email', 'knowledge-e2e@example.invalid'], { cwd: project });
  run('git', ['config', 'user.name', 'Knowledge E2E'], { cwd: project });
  run('git', ['add', 'package.json', 'index.js', 'README.md'], { cwd: project });
  run('git', ['commit', '-m', 'fixture baseline'], { cwd: project, timeoutMs: 60000 });
  return { root, project, state };
}

async function main() {
  const context = createFixture();
  const checks = [];
  try {
    const sourceHashes = {
      package: sha256(path.join(context.project, 'package.json')),
      index: sha256(path.join(context.project, 'index.js')),
      readme: sha256(path.join(context.project, 'README.md'))
    };

    const doctorBefore = nodeTool('doctor.js', ['--json'], context);
    assert(['healthy', 'usable_with_warnings', 'degraded', 'broken'].includes(doctorBefore.status), 'doctor returned unexpected status');
    checks.push('clean fixture repo doctor --json returns structured status');

    fs.mkdirSync(path.join(context.state, 'maintenance'), { recursive: true });
    fs.writeFileSync(path.join(context.state, 'maintenance', 'corrupt-fixture.json'), '{not valid json', 'utf8');
    const corruptDoctor = nodeTool('doctor.js', ['--json'], context);
    assert(corruptDoctor.checks.some((check) => check.check === 'json_parse' && check.status === 'fail'), 'doctor did not report corrupt JSON');
    fs.rmSync(path.join(context.state, 'maintenance', 'corrupt-fixture.json'), { force: true });
    checks.push('corrupt JSON fixture is detected without touching source');

    const restore = nodeTool('restore-trust.js', ['--safe', '--json'], context, { timeoutMs: 300000 });
    assert(restore.status === 'passed', 'Restore Trust safe flow failed', restore);
    assert(restore.source_code_changed === false, 'Restore Trust claimed source code changed');
    assert(restore.merged_branches === false, 'Restore Trust must not merge branches');
    assert(restore.raised_trust_without_evidence === false, 'Restore Trust must not raise trust without evidence');
    assert(sourceHashes.package === sha256(path.join(context.project, 'package.json')), 'Restore Trust changed package.json');
    assert(sourceHashes.index === sha256(path.join(context.project, 'index.js')), 'Restore Trust changed index.js');
    assert(sourceHashes.readme === sha256(path.join(context.project, 'README.md')), 'Restore Trust changed README.md');
    assert(fs.existsSync(path.join(context.state, 'maintenance', 'restore-trust-report.md')), 'Restore Trust plain-language report missing');
    checks.push('Restore Trust refreshes generated state only and preserves source hashes');

    const memory = nodeTool('memory-provider.js', ['status-all', '--json'], context);
    assert(memory.source_of_truth_policy?.external_memory_source_of_truth === false, 'external memory source-of-truth policy broken');
    assert(memory.source_of_truth_policy?.external_memory_can_raise_trust === false, 'external memory must not raise trust');
    assert((memory.providers || []).every((provider) => provider.trust_effect === 'advisory_only' || provider.trust_role === 'advisory_only'), 'memory provider not advisory-only');
    checks.push('memory providers stay advisory-only when unavailable/unconfigured');

    const prImpact = nodeTool('pr-impact.js', ['--json'], context);
    assert(Array.isArray(prImpact.changed_files), 'PR Impact JSON missing changed_files');
    fs.writeFileSync(path.join(context.project, 'dirty.js'), 'module.exports = "dirty";\n', 'utf8');
    const dirtyImpact = nodeTool('pr-impact.js', ['--json'], context);
    assert(dirtyImpact.changed_files.some((file) => file.path === 'dirty.js'), 'dirty repo PR Impact did not detect changed file');
    checks.push('PR Impact handles clean and dirty fixture repos with JSON output');

    const debug = nodeTool('export-debug-bundle.js', ['--json'], context);
    assert(debug.ok === true && debug.bundle?.includes?.api_keys === false, 'debug bundle did not exclude API keys');
    const snapshot = nodeTool('export-pro-snapshot.js', ['--json'], context);
    assert(snapshot.ok === true && snapshot.snapshot?.provenance?.secrets_included === false, 'Pro snapshot included secrets');
    checks.push('debug bundle and Pro snapshot export sanitized JSON artifacts');

    const start = nodeTool('agent-session.js', ['start', '--runtime', 'codex', '--instance', 'codex-e2e', '--operator', 'qa', '--workspace-id', 'ws-e2e', '--task-id', 'canonical-e2e', '--json'], context);
    nodeTool('agent-session.js', ['heartbeat', '--session-id', start.session.session_id, '--runtime', 'codex', '--instance', 'codex-e2e', '--json'], context);
    const activeReport = nodeTool('agent-session.js', ['report', '--json'], context);
    assert(activeReport.active_sessions.some((session) => session.session_id === start.session.session_id), 'active session missing without manual switch');
    nodeTool('agent-session.js', ['finish', '--session-id', start.session.session_id, '--runtime', 'codex', '--instance', 'codex-e2e', '--json'], context);
    const finalReport = nodeTool('agent-session.js', ['report', '--json'], context);
    assert(!finalReport.active_sessions.some((session) => session.session_id === start.session.session_id), 'finished session still active');
    checks.push('agent start/heartbeat/report/finish drives active sessions from registry');

    const footerSimple = nodeTool('agent-footer.js', ['--mode', 'full', '--json'], context);
    assert(footerSimple.footer.includes('Open Inspector') || footerSimple.footer.includes('Restore trust'), 'agent footer missing action hints');
    checks.push('agent footer exposes Simple/Advanced-compatible local actions');

    const team = nodeTool('team-status.js', ['--json'], context);
    assert(team.safe_queue?.default === true && team.merge_policy?.auto_merge === false, 'repo-mode Safe Queue/Manual Only defaults broken');
    checks.push('repo-mode Safe Queue and Manual Only defaults are visible');

    await inspectorE2E(context, checks);

    const stateArtifacts = [
      'maintenance/routing_bundle.json',
      'maintenance/trust_report.json',
      'maintenance/repair_queue.json',
      'maintenance/external_memory_status.json',
      'maintenance/quality_report.json',
      'search/index.json',
      'inspector/index.html',
      'maintenance/debug-bundle.json',
      'maintenance/pro-inspector-snapshot.json'
    ];
    for (const rel of stateArtifacts) assert(fs.existsSync(path.join(context.state, rel)), `missing generated artifact: ${rel}`);
    checks.push('routing, trust, freshness, repair, search, Inspector and export artifacts generated');

    const result = {
      schema_version: '3.2.0',
      status: 'pass',
      simulated: [
        'clean temporary git repo',
        'dirty repo diff',
        'corrupt JSON runtime artifact',
        'unavailable/advisory memory providers',
        'invalid Inspector token',
        'free-mode Pro action without entitlement',
        'no browser open / API-only Inspector run',
        'secret-bearing fixture report for redaction'
      ],
      checks
    };
    console.log(JSON.stringify(result, null, 2));
    return result;
  } finally {
    fs.rmSync(context.root, { recursive: true, force: true });
  }
}

if (require.main === module) {
  main().catch((error) => {
    console.error(error.stack || error.message);
    if (error.details) console.error(JSON.stringify(error.details, null, 2));
    process.exit(1);
  });
}

module.exports = main;
