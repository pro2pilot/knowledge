#!/usr/bin/env node
'use strict';

const crypto = require('crypto');
const fs = require('fs');
const http = require('http');
const net = require('net');
const path = require('path');
const { spawn, spawnSync } = require('child_process');

const ROOT_ENV = [
  'KNOWLEDGE_ROOT', 'KNOWLEDGE_SYSTEM_ROOT', 'KNOWLEDGE_TARGET_ROOT',
  'KNOWLEDGE_PROJECT_KNOWLEDGE_ROOT', 'KNOWLEDGE_STATE_ROOT',
  'KNOWLEDGE_TEAM_ROOT', 'KNOWLEDGE_WORKSPACE_ID', 'KNOWLEDGE_REPO_ID',
  'KNOWLEDGE_SOURCE_ROOT'
];
const RUNTIMES = ['codex','claude','opencode','openclaw','hermes','gemini','copilot','devin','windsurf','continue','roo','aider'];

function arg(name) {
  const index = process.argv.indexOf(name);
  if (index >= 0) return process.argv[index + 1] || null;
  const prefix = `${name}=`;
  const found = process.argv.find((value) => value.startsWith(prefix));
  return found ? found.slice(prefix.length) : null;
}
function required(name) {
  const value = arg(name);
  if (!value) throw new Error(`${name}=<value> is required`);
  return path.resolve(value);
}
function boolArg(name) { return arg(name) === 'true'; }
function ensure(dir) { fs.mkdirSync(dir, { recursive: true }); }
function portable(value) { return String(value).replace(/\\/g, '/'); }
function sha256File(file) { return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex'); }
function writeJson(file, value) { ensure(path.dirname(file)); fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`, 'utf8'); }
function cleanEnv() {
  const env = { ...process.env, NODE_PATH: '', CI: 'true', KNOWLEDGE_INSPECTOR_NO_OPEN: '1', KNOWLEDGE_FLOW_NO_OPEN: '1' };
  for (const name of ROOT_ENV) delete env[name];
  return env;
}
function walk(root, predicate, output = []) {
  for (const entry of fs.readdirSync(root, { withFileTypes: true })) {
    const full = path.join(root, entry.name);
    if (entry.isDirectory()) walk(full, predicate, output);
    else if (entry.isFile() && predicate(full)) output.push(full);
  }
  return output;
}
function parseJson(raw, id) {
  try { return JSON.parse(String(raw || '').trim() || '{}'); }
  catch (error) { throw new Error(`${id} did not emit JSON: ${error.message}`); }
}
function safeOutput(root, relative) {
  const target = path.resolve(root, ...String(relative).replace(/\\/g, '/').split('/'));
  const resolvedRoot = path.resolve(root);
  if (target !== resolvedRoot && !target.startsWith(`${resolvedRoot}${path.sep}`)) {
    throw new Error(`unsafe ZIP output path: ${relative}`);
  }
  return target;
}
function verifyReplayManifest(replay) {
  const manifestPath = path.join(replay, 'manifest.json');
  const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  const failures = [];
  for (const item of manifest.files || []) {
    const file = safeOutput(replay, item.path);
    if (!fs.existsSync(file)) failures.push({ path: item.path, reason: 'missing' });
    else {
      const actual = sha256File(file);
      if (actual !== item.sha256) failures.push({ path: item.path, reason: 'sha256_mismatch', expected: item.sha256, actual });
    }
  }
  if (failures.length) throw new Error(`replay manifest failed: ${JSON.stringify(failures.slice(0, 3))}`);
  return { status: 'pass', checks_total: (manifest.files || []).length, passed: (manifest.files || []).length, failed: 0, manifest_sha256: sha256File(manifestPath) };
}
function availablePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const port = server.address().port;
      server.close((error) => error ? reject(error) : resolve(port));
    });
  });
}
function httpJson(port, pathname, options = {}) {
  return new Promise((resolve, reject) => {
    const request = http.request({
      hostname: '127.0.0.1', port, path: pathname, method: options.method || 'GET',
      headers: options.headers || {}
    }, (response) => {
      const chunks = [];
      response.on('data', (chunk) => chunks.push(chunk));
      response.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        try { resolve({ status: response.statusCode, body: JSON.parse(text) }); }
        catch (error) { reject(new Error(`invalid Inspector response: ${error.message}`)); }
      });
    });
    request.once('error', reject);
    request.end(options.body || null);
  });
}

const candidate = required('--candidate');
const replay = required('--replay');
const baseline = arg('--baseline') ? path.resolve(arg('--baseline')) : null;
const out = required('--out');
const osLabel = arg('--os') || process.platform;
const nodeLabel = arg('--node-major') || process.versions.node.split('.')[0];
const upgradeEnabled = boolArg('--upgrade');
const expectedCandidate = arg('--expected-candidate');
const expectedBaseline = arg('--expected-baseline');

if (fs.existsSync(out)) throw new Error(`refusing existing output directory: ${out}`);
ensure(out); ensure(path.join(out, 'stdout')); ensure(path.join(out, 'stderr'));
const commands = [];

function run(id, executable, args, options = {}) {
  const started = Date.now();
  const result = spawnSync(executable, args, {
    cwd: options.cwd || out,
    env: options.env || cleanEnv(),
    encoding: 'utf8',
    timeout: options.timeout || 600000,
    maxBuffer: 32 * 1024 * 1024,
    windowsHide: true
  });
  const stdout = result.stdout || '';
  const stderr = result.stderr || (result.error ? `${result.error.stack || result.error.message}\n` : '');
  fs.writeFileSync(path.join(out, 'stdout', `${id}.log`), stdout, 'utf8');
  fs.writeFileSync(path.join(out, 'stderr', `${id}.log`), stderr, 'utf8');
  const item = {
    id, command: [executable, ...args], cwd: portable(options.cwd || out),
    exit_code: result.status, signal: result.signal || null, duration_ms: Date.now() - started,
    stdout: `stdout/${id}.log`, stderr: `stderr/${id}.log`,
    spawn_error: result.error ? { code: result.error.code || null, message: result.error.message } : null,
    status: result.status === 0 && !result.error ? 'pass' : 'fail'
  };
  commands.push(item);
  if (item.status !== 'pass') throw new Error(`${id} failed (exit ${item.exit_code}): ${stderr.slice(0, 800)}`);
  return { ...item, stdout, stderr };
}

async function exerciseInspector(fixture) {
  const port = await availablePort();
  const server = spawn(process.execPath, [path.join(fixture, '.knowledge', 'tools', 'serve-inspector.js'), `--port=${port}`], {
    cwd: fixture, env: cleanEnv(), windowsHide: true
  });
  let stdout = '', stderr = '';
  server.stdout.on('data', (chunk) => { stdout += chunk.toString(); });
  server.stderr.on('data', (chunk) => { stderr += chunk.toString(); });
  const deadline = Date.now() + 25000;
  let session = null;
  while (Date.now() < deadline) {
    try {
      const response = await httpJson(port, '/api/session');
      if (response.status === 200 && response.body.ok) { session = response.body; break; }
    } catch (_) {}
    await new Promise((resolve) => setTimeout(resolve, 150));
  }
  let state = null, shutdown = null;
  try {
    if (!session?.token) throw new Error('Inspector did not provide a session token');
    state = await httpJson(port, '/api/state', { headers: { authorization: `Bearer ${session.token}` } });
    shutdown = await httpJson(port, '/api/shutdown', { method: 'POST', headers: { authorization: `Bearer ${session.token}` } });
    if (state.status !== 200 || !state.body.ok || shutdown.status !== 200 || !shutdown.body.ok) {
      throw new Error('Inspector state or shutdown failed');
    }
  } finally {
    await new Promise((resolve) => {
      const timer = setTimeout(() => { server.kill(); resolve(); }, 10000);
      server.once('exit', () => { clearTimeout(timer); resolve(); });
    });
    fs.writeFileSync(path.join(out, 'stdout', 'inspector-live.log'), stdout, 'utf8');
    fs.writeFileSync(path.join(out, 'stderr', 'inspector-live.log'), stderr, 'utf8');
  }
  const report = { status: 'pass', port, state_ok: state.body.ok, shutdown_ok: shutdown.body.ok };
  writeJson(path.join(out, 'inspector-live.json'), report);
  commands.push({
    id: 'inspector-live', command: [process.execPath, '.knowledge/tools/serve-inspector.js', `--port=${port}`],
    cwd: portable(fixture), exit_code: 0, signal: null, duration_ms: null,
    stdout: 'stdout/inspector-live.log', stderr: 'stderr/inspector-live.log', spawn_error: null, status: 'pass'
  });
}

async function main() {
  const actualNodeMajor = Number(process.versions.node.split('.')[0]);
  if (actualNodeMajor !== Number(nodeLabel)) {
    throw new Error(`Node major mismatch: requested ${nodeLabel}, running ${process.version}`);
  }
  const expectedPlatform = {
    windows: 'win32',
    macos: 'darwin',
    ubuntu: 'linux',
    linux: 'linux'
  }[String(osLabel).toLowerCase()];
  if (expectedPlatform && process.platform !== expectedPlatform) {
    throw new Error(`OS mismatch: requested ${osLabel}, running ${process.platform}`);
  }
  const candidateSha = sha256File(candidate);
  if (expectedCandidate && candidateSha !== expectedCandidate) throw new Error(`candidate SHA mismatch: ${candidateSha}`);
  if (baseline && expectedBaseline && sha256File(baseline) !== expectedBaseline) throw new Error('baseline SHA mismatch');

  const replayVerification = verifyReplayManifest(replay);
  writeJson(path.join(out, 'replay-manifest-verification.json'), replayVerification);

  const validator = require(path.join(replay, 'tools', 'validate-release-artifact.js'));
  const validation = validator.validate(candidate);
  writeJson(path.join(out, 'candidate-validation.json'), validation);
  if (validation.status !== 'ok') throw new Error('candidate validation failed');

  const fixture = path.join(out, 'fixture');
  const externalCwd = path.join(out, 'external-cwd');
  ensure(fixture); ensure(externalCwd);
  const zip = validator.readZipEntries(candidate);
  for (const entry of zip.entries) {
    if (entry.name.endsWith('/')) continue;
    const target = safeOutput(fixture, entry.name);
    ensure(path.dirname(target)); fs.writeFileSync(target, entry.body);
  }
  const knowledge = path.join(fixture, '.knowledge');
  if (!fs.existsSync(knowledge)) throw new Error('candidate has no .knowledge root');

  run('git-init', 'git', ['init'], { cwd: fixture });
  run('git-config-email', 'git', ['config', 'user.email', 'matrix@example.invalid'], { cwd: fixture });
  run('git-config-name', 'git', ['config', 'user.name', 'RC55 Matrix'], { cwd: fixture });
  fs.writeFileSync(path.join(fixture, 'README.fixture.md'), '# RC55 matrix fixture\n');
  run('git-add', 'git', ['add', '.'], { cwd: fixture });
  run('git-commit', 'git', ['commit', '-m', 'fixture baseline'], { cwd: fixture });

  const jsFiles = walk(knowledge, (file) => file.endsWith('.js'));
  const syntaxFailures = [];
  for (const file of jsFiles) {
    const result = spawnSync(process.execPath, ['--check', file], { cwd: fixture, env: cleanEnv(), encoding: 'utf8', windowsHide: true });
    if (result.status !== 0) syntaxFailures.push({ path: portable(path.relative(fixture, file)), stderr: result.stderr || '', exit_code: result.status });
  }
  const syntax = { status: syntaxFailures.length ? 'fail' : 'pass', checks_total: jsFiles.length, passed: jsFiles.length - syntaxFailures.length, failed: syntaxFailures.length, failures: syntaxFailures };
  writeJson(path.join(out, 'javascript-syntax.json'), syntax);
  if (syntax.status !== 'pass') throw new Error(`JavaScript syntax failures: ${syntax.failed}`);

  const before = parseJson(run('install-check-before', process.execPath, [path.join(knowledge, 'tools', 'install-check.js'), '--json'], { cwd: fixture }).stdout, 'install-check-before');
  writeJson(path.join(out, 'install-check-before.json'), before);

  run('shipped-self-tests', process.execPath, [
    path.join(replay, 'tools', 'run-shipped-self-tests.js'),
    '--artifact', candidate, '--out', path.join(out, 'self-tests.json')
  ], { cwd: externalCwd, timeout: 900000 });
  const selfTests = JSON.parse(fs.readFileSync(path.join(out, 'self-tests.json'), 'utf8'));
  const expectedSelfTests = Array.isArray(selfTests.expected_tests)
    ? selfTests.expected_tests.length
    : 0;
  if (
    selfTests.status !== 'pass' ||
    selfTests.passed !== expectedSelfTests ||
    selfTests.failed !== 0
  ) {
    throw new Error(
      `shipped self-tests are not ${expectedSelfTests}/${expectedSelfTests}`
    );
  }

  const integrationsRaw = run('install-agent-integrations', process.execPath, [
    path.join(knowledge, 'tools', 'install-agent-integrations.js'), '--all', '--confirm-all', '--no-package-scripts'
  ], { cwd: fixture, timeout: 300000 }).stdout;
  const integrations = parseJson(integrationsRaw, 'install-agent-integrations');
  const agents = fs.readFileSync(path.join(fixture, 'AGENTS.md'), 'utf8');
  const integrationReport = {
    status: integrations.status === 'ok' &&
      Array.isArray(integrations.runtimes) &&
      RUNTIMES.every((item) => integrations.runtimes.includes(item)) &&
      agents.split('<!-- BEGIN DOT-KNOWLEDGE MANAGED BLOCK -->').length - 1 === 1 &&
      agents.split('<!-- END DOT-KNOWLEDGE MANAGED BLOCK -->').length - 1 === 1 &&
      fs.existsSync(path.join(fixture, '.windsurf', 'rules', 'knowledge.md')) &&
      fs.existsSync(path.join(fixture, '.devin', 'rules', 'knowledge.rules')) &&
      !fs.existsSync(path.join(fixture, '.devin', 'rules', 'knowledge.md'))
        ? 'pass' : 'fail',
    runtimes: integrations.runtimes,
    agents_managed_blocks: agents.split('<!-- BEGIN DOT-KNOWLEDGE MANAGED BLOCK -->').length - 1,
    windsurf_path: fs.existsSync(path.join(fixture, '.windsurf', 'rules', 'knowledge.md')),
    devin_path: fs.existsSync(path.join(fixture, '.devin', 'rules', 'knowledge.rules'))
  };
  writeJson(path.join(out, 'integration-report.json'), integrationReport);
  if (integrationReport.status !== 'pass') throw new Error('integration coexistence check failed');

  const after = parseJson(run('install-check-after', process.execPath, [path.join(knowledge, 'tools', 'install-check.js'), '--json'], { cwd: fixture }).stdout, 'install-check-after');
  writeJson(path.join(out, 'install-check-after.json'), after);

  const flowImport = parseJson(run('flow-import', process.execPath, [path.join(knowledge, 'tools', 'flow.js'), 'import', '--json', '--no-color'], { cwd: fixture, timeout: 900000 }).stdout, 'flow-import');
  const flowRelease = parseJson(run('flow-release', process.execPath, [path.join(knowledge, 'tools', 'flow.js'), 'release', '--json', '--no-color'], { cwd: fixture, timeout: 900000 }).stdout, 'flow-release');
  const doctor = parseJson(run('doctor', process.execPath, [path.join(knowledge, 'tools', 'doctor.js'), '--json'], { cwd: fixture }).stdout, 'doctor');
  if (['broken','failed'].includes(doctor.status)) throw new Error(`Doctor semantic failure: ${doctor.status}`);
  run('inspector-build', process.execPath, [path.join(knowledge, 'tools', 'build-visual-inspector.js')], { cwd: fixture });
  await exerciseInspector(fixture);
  const routing = parseJson(run('task-routing', process.execPath, [
    path.join(knowledge, 'tools', 'task-routing.js'), 'create', '--task', 'RC55 OS/Node compatibility matrix',
    '--scope-path', '.knowledge/tools/field-report.js', '--json'
  ], { cwd: fixture }).stdout, 'task-routing');
  const field = parseJson(run('field-report-start', process.execPath, [
    path.join(knowledge, 'tools', 'field-report.js'), 'start', '--new', '--json'
  ], { cwd: fixture }).stdout, 'field-report-start');
  if (field.status !== 'needs_user_input') throw new Error(`unexpected Field Report start status: ${field.status}`);

  const lockCode = "const path=require('path');const m=require(path.resolve('.knowledge/tools/lib/contained-lock-manager.js'));const c=require(path.resolve('.knowledge/tools/lib/path-context.js')).resolveKnowledgeContext([], {cwd:process.cwd()});const r=m.inspectContextLockSafety(c);console.log(JSON.stringify(r));process.exit(r.status==='safe'?0:2);";
  const lockReport = parseJson(run('lock-safety-final', process.execPath, ['-e', lockCode], { cwd: fixture }).stdout, 'lock-safety-final');
  writeJson(path.join(out, 'lock-report.json'), lockReport);

  let upgrade = { status: 'not_run_by_scope', reason: 'exact upgrade is required on Node 22 once per OS' };
  if (upgradeEnabled) {
    if (!baseline) throw new Error('--baseline is required when --upgrade=true');
    const upgradeRaw = run('exact-upgrade', process.execPath, [
      path.join(replay, 'tools', 'conformance-install-smoke.js'), candidate,
      '--previous-artifact', baseline, '--json'
    ], { cwd: externalCwd, timeout: 900000 }).stdout;
    upgrade = parseJson(upgradeRaw, 'exact-upgrade');
    if (upgrade.status !== 'pass') throw new Error(`exact upgrade failed: ${upgrade.status}`);
  }
  writeJson(path.join(out, 'upgrade-report.json'), upgrade);

  writeJson(path.join(out, 'workflow-report.json'), {
    status: 'pass', flow_import: flowImport, flow_release: flowRelease, doctor,
    task_routing: routing, field_report: field, inspector_live: 'pass'
  });
  writeJson(path.join(out, 'commands.json'), { schema_version: 'rc55-matrix-commands.v1', commands });
  writeJson(path.join(out, 'environment.json'), {
    schema_version: 'rc55-os-node-environment.v1', os_label: osLabel,
    platform: process.platform, arch: process.arch, node: process.version,
    requested_node_major: Number(nodeLabel), candidate_sha256: candidateSha,
    baseline_sha256: baseline ? sha256File(baseline) : null,
    external_harness: true, replay_manifest_sha256: replayVerification.manifest_sha256,
    source_root_environment_variables_present: ROOT_ENV.filter((name) => Boolean(process.env[name]))
  });
  const result = {
    schema_version: 'rc55-os-node-cell.v1', status: 'pass', classification: 'candidate',
    candidate_sha256: candidateSha,
    tests: {
      shipped_self_tests: `${selfTests.passed}/${expectedSelfTests}`,
      integrations: '12/12',
      upgrade: upgrade.status
    },
    command_count: commands.length, active_locks: 0
  };
  writeJson(path.join(out, 'result.json'), result);

  const checksumFiles = walk(out, (file) => path.basename(file) !== 'checksums.sha256')
    .map((file) => portable(path.relative(out, file))).sort();
  fs.writeFileSync(path.join(out, 'checksums.sha256'), checksumFiles.map((relative) =>
    `${sha256File(path.join(out, ...relative.split('/')))}  ${relative}`).join('\n') + '\n');
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
}

main().catch((error) => {
  const result = {
    schema_version: 'rc55-os-node-cell.v1', status: 'fail', classification: 'unclassified',
    candidate_sha256: fs.existsSync(candidate) ? sha256File(candidate) : null,
    error: { message: error.message, stack: error.stack }
  };
  try { writeJson(path.join(out, 'result.json'), result); writeJson(path.join(out, 'commands.json'), { schema_version: 'rc55-matrix-commands.v1', commands }); } catch (_) {}
  process.stderr.write(`${error.stack || error.message}\n`);
  process.exitCode = 2;
});
