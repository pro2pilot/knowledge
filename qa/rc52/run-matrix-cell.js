#!/usr/bin/env node
'use strict';

// External RC52 compatibility harness. It never writes into the candidate ZIP
// or its audit bundle: the candidate is extracted into fixture/ and all shipped
// self-tests run from replay/tools outside that fixture.
const crypto = require('crypto');
const fs = require('fs');
const http = require('http');
const path = require('path');
const { spawn, spawnSync } = require('child_process');

const ROOT_ENV = [
  'KNOWLEDGE_ROOT', 'KNOWLEDGE_SYSTEM_ROOT', 'KNOWLEDGE_TARGET_ROOT',
  'KNOWLEDGE_PROJECT_KNOWLEDGE_ROOT', 'KNOWLEDGE_STATE_ROOT',
  'KNOWLEDGE_TEAM_ROOT', 'KNOWLEDGE_WORKSPACE_ID', 'KNOWLEDGE_REPO_ID',
  'KNOWLEDGE_SOURCE_ROOT'
];
const RUNTIMES = ['codex', 'claude', 'opencode', 'openclaw', 'hermes', 'gemini', 'copilot', 'devin', 'windsurf', 'continue', 'roo', 'aider'];

function arg(name) {
  const index = process.argv.indexOf(name);
  if (index >= 0) return process.argv[index + 1] || null;
  const prefix = `${name}=`;
  return process.argv.find((value) => value.startsWith(prefix))?.slice(prefix.length) || null;
}
function required(name) {
  const value = arg(name);
  if (!value) throw new Error(`${name}=<value> is required`);
  return path.resolve(value);
}
function optionalBool(name) { return arg(name) === 'true'; }
function ensure(directory) { fs.mkdirSync(directory, { recursive: true }); }
function write(file, value) { ensure(path.dirname(file)); fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`, 'utf8'); }
function sha256(file) { return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex'); }
function portable(value) { return String(value).replace(/\\/g, '/'); }
function cleanEnv() {
  const env = { ...process.env, NODE_PATH: '' };
  for (const name of ROOT_ENV) delete env[name];
  return env;
}
function safeOutput(root, relative) {
  const target = path.resolve(root, relative);
  if (target !== root && !target.startsWith(`${root}${path.sep}`)) throw new Error(`unsafe output path: ${relative}`);
  return target;
}
function parseJson(raw, id) {
  try { return JSON.parse(String(raw || '').trim() || '{}'); }
  catch (error) { throw new Error(`${id} did not emit JSON: ${error.message}`); }
}
function walk(root, predicate, output = []) {
  for (const entry of fs.readdirSync(root, { withFileTypes: true })) {
    const full = path.join(root, entry.name);
    if (entry.isDirectory()) walk(full, predicate, output);
    else if (entry.isFile() && predicate(full)) output.push(full);
  }
  return output;
}

const candidate = required('--candidate');
const replay = required('--replay');
const out = required('--out');
const osName = arg('--os') || process.platform;
const nodeMajor = arg('--node-major') || process.versions.node.split('.')[0];
const baseline = arg('--baseline') ? path.resolve(arg('--baseline')) : null;
const expectedCandidate = arg('--expected-candidate');
const expectedAudit = arg('--expected-audit');
const expectedBaseline = arg('--expected-baseline');
const audit = arg('--audit') ? path.resolve(arg('--audit')) : null;
const upgradeEnabled = optionalBool('--upgrade');

if (fs.existsSync(out)) throw new Error(`refusing existing cell output directory: ${out}`);
ensure(out);
ensure(path.join(out, 'stdout'));
ensure(path.join(out, 'stderr'));
const commands = [];

function run(id, executable, args, options = {}) {
  const started = Date.now();
  const result = spawnSync(executable, args, {
    cwd: options.cwd || path.dirname(out),
    env: options.env || cleanEnv(),
    encoding: 'utf8',
    timeout: options.timeout || 300000,
    windowsHide: true
  });
  const stdoutPath = path.join(out, 'stdout', `${id}.log`);
  const stderrPath = path.join(out, 'stderr', `${id}.log`);
  fs.writeFileSync(stdoutPath, result.stdout || '', 'utf8');
  fs.writeFileSync(stderrPath, result.stderr || (result.error ? `${result.error.stack || result.error.message}\n` : ''), 'utf8');
  const item = {
    id,
    command: [executable, ...args],
    cwd: portable(options.cwd || path.dirname(out)),
    exit_code: result.status,
    signal: result.signal || null,
    duration_ms: Date.now() - started,
    stdout: portable(path.relative(out, stdoutPath)),
    stderr: portable(path.relative(out, stderrPath)),
    spawn_error: result.error ? { code: result.error.code || null, message: result.error.message } : null,
    status: result.status === 0 && !result.error ? 'pass' : 'fail'
  };
  commands.push(item);
  if (item.status !== 'pass') throw new Error(`${id} failed (exit ${item.exit_code}): ${String(result.stderr || result.error?.message || '').slice(0, 800)}`);
  return { ...item, stdout: result.stdout || '', stderr: result.stderr || '' };
}

function checkSyntax(knowledgeRoot) {
  const files = walk(knowledgeRoot, (file) => file.endsWith('.js'));
  const failures = [];
  const stdout = [];
  for (const file of files) {
    const result = spawnSync(process.execPath, ['--check', file], { cwd: path.dirname(out), env: cleanEnv(), encoding: 'utf8', windowsHide: true });
    if (result.stdout) stdout.push(`${portable(path.relative(knowledgeRoot, file))}\n${result.stdout}`);
    if (result.status !== 0) failures.push({ file: portable(path.relative(knowledgeRoot, file)), stderr: result.stderr || '', exit_code: result.status });
  }
  fs.writeFileSync(path.join(out, 'stdout', 'javascript-syntax.log'), stdout.join('\n'), 'utf8');
  fs.writeFileSync(path.join(out, 'stderr', 'javascript-syntax.log'), failures.map((item) => `${item.file}\n${item.stderr}`).join('\n'), 'utf8');
  const report = { status: failures.length ? 'fail' : 'pass', files_checked: files.length, failures };
  write(path.join(out, 'javascript-syntax.json'), report);
  commands.push({ id: 'javascript-syntax', command: [process.execPath, '--check', '<all .knowledge/**/*.js>'], cwd: portable(knowledgeRoot), exit_code: failures.length ? 1 : 0, signal: null, duration_ms: null, stdout: 'stdout/javascript-syntax.log', stderr: 'stderr/javascript-syntax.log', spawn_error: null, status: report.status });
  if (failures.length) throw new Error(`JavaScript syntax failures: ${failures.length}`);
}

function verifyIntegrations(fixture, integrationCommand) {
  const response = parseJson(integrationCommand.stdout, 'install-agent-integrations');
  const agents = Array.isArray(response.runtimes) ? response.runtimes.slice().sort() : [];
  const agentsFile = path.join(fixture, 'AGENTS.md');
  const agentsText = fs.existsSync(agentsFile) ? fs.readFileSync(agentsFile, 'utf8') : '';
  const start = '<!-- BEGIN DOT-KNOWLEDGE MANAGED BLOCK -->';
  const end = '<!-- END DOT-KNOWLEDGE MANAGED BLOCK -->';
  const checks = {
    installer_status: response.status || null,
    runtimes: agents,
    expected_runtimes: RUNTIMES,
    all_twelve: RUNTIMES.every((item) => agents.includes(item)) && agents.length === RUNTIMES.length,
    agents_managed_block_starts: agentsText.split(start).length - 1,
    agents_managed_block_ends: agentsText.split(end).length - 1,
    legacy_managed_block_present: agentsText.includes('BEGIN KNOWLEDGE-KIT MANAGED BLOCK'),
    windsurf_path: fs.existsSync(path.join(fixture, '.windsurf', 'rules', 'knowledge.md')),
    devin_path: fs.existsSync(path.join(fixture, '.devin', 'rules', 'knowledge.rules')),
    windsurf_and_devin_separate: path.join('.windsurf', 'rules', 'knowledge.md') !== path.join('.devin', 'rules', 'knowledge.rules')
  };
  const surfaces = [agentsFile, path.join(fixture, '.windsurf', 'rules', 'knowledge.md'), path.join(fixture, '.devin', 'rules', 'knowledge.rules')].filter(fs.existsSync);
  const leakPattern = /MATRIX_SECRET_SENTINEL|C:\\MyProject\\|C:\\Users\\|\/Users\/[^/]+\/(?:knowledge-kit|\.codex)/i;
  checks.local_path_or_secret_leaks = surfaces.flatMap((file) => leakPattern.test(fs.readFileSync(file, 'utf8')) ? [portable(path.relative(fixture, file))] : []);
  checks.status = response.status === 'ok' && checks.all_twelve && checks.agents_managed_block_starts === 1 && checks.agents_managed_block_ends === 1 && !checks.legacy_managed_block_present && checks.windsurf_path && checks.devin_path && checks.windsurf_and_devin_separate && checks.local_path_or_secret_leaks.length === 0 ? 'pass' : 'fail';
  write(path.join(out, 'integration-report.json'), checks);
  if (checks.status !== 'pass') throw new Error(`integration verification failed: ${JSON.stringify(checks)}`);
}

function inspectLocks(fixture) {
  const manager = require(path.join(fixture, '.knowledge', 'tools', 'lib', 'contained-lock-manager.js'));
  const report = manager.inspectAllLockSafety({ rootPath: path.join(fixture, '.knowledge'), rootKind: 'state' });
  const active = (report.locks || []).filter((item) => item.status === 'active' || item.status === 'stale' || item.status === 'unsafe');
  const result = { ...report, active_or_unsafe: active, status: active.length === 0 && report.status === 'safe' ? 'pass' : 'fail' };
  write(path.join(out, 'lock-report.json'), result);
  if (result.status !== 'pass') throw new Error(`active or unsafe locks remain: ${active.map((item) => item.lock_name).join(', ')}`);
}

function httpJson(port, pathname, options = {}) {
  return new Promise((resolve, reject) => {
    const request = http.request({ hostname: '127.0.0.1', port, path: pathname, method: options.method || 'GET', headers: options.headers || {} }, (response) => {
      const chunks = [];
      response.on('data', (chunk) => chunks.push(chunk));
      response.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        try { resolve({ status: response.statusCode, body: JSON.parse(text) }); }
        catch (error) { reject(new Error(`invalid inspector response: ${error.message}`)); }
      });
    });
    request.once('error', reject);
    request.end(options.body || null);
  });
}

async function exerciseInspector(fixture) {
  const port = 18765;
  const stdoutPath = path.join(out, 'stdout', 'inspector-server.log');
  const stderrPath = path.join(out, 'stderr', 'inspector-server.log');
  const server = spawn(process.execPath, [path.join(fixture, '.knowledge', 'tools', 'serve-inspector.js'), `--port=${port}`], { cwd: fixture, env: cleanEnv(), windowsHide: true });
  let stdout = '';
  let stderr = '';
  server.stdout.on('data', (chunk) => { stdout += chunk.toString(); });
  server.stderr.on('data', (chunk) => { stderr += chunk.toString(); });
  const deadline = Date.now() + 20000;
  let session;
  while (Date.now() < deadline) {
    try { session = await httpJson(port, '/api/session'); if (session.status === 200 && session.body.ok) break; }
    catch (_) {}
    await new Promise((resolve) => setTimeout(resolve, 150));
  }
  let shutdown = null;
  try {
    if (!session?.body?.token) throw new Error('inspector did not provide a session token');
    const state = await httpJson(port, '/api/state', { headers: { authorization: `Bearer ${session.body.token}` } });
    shutdown = await httpJson(port, '/api/shutdown', { method: 'POST', headers: { authorization: `Bearer ${session.body.token}` } });
    if (state.status !== 200 || !state.body.ok || shutdown.status !== 200 || !shutdown.body.ok) throw new Error('inspector state or shutdown response was not successful');
  } finally {
    await new Promise((resolve) => { const timer = setTimeout(() => { server.kill(); resolve(); }, 10000); server.once('exit', () => { clearTimeout(timer); resolve(); }); });
    fs.writeFileSync(stdoutPath, stdout, 'utf8');
    fs.writeFileSync(stderrPath, stderr, 'utf8');
  }
  const report = { status: 'pass', port, session: { scope: session.body.scope, host: session.body.host }, shutdown: shutdown.body };
  write(path.join(out, 'inspector-report.json'), report);
  commands.push({ id: 'inspector-start-stop', command: [process.execPath, '.knowledge/tools/serve-inspector.js', `--port=${port}`], cwd: portable(fixture), exit_code: 0, signal: null, duration_ms: null, stdout: 'stdout/inspector-server.log', stderr: 'stderr/inspector-server.log', spawn_error: null, status: 'pass' });
}

async function main() {
  const sourceCommit = arg('--source-commit') || null;
  const candidateHash = sha256(candidate);
  if (expectedCandidate && candidateHash !== expectedCandidate) throw new Error(`candidate SHA mismatch: ${candidateHash}`);
  if (audit && expectedAudit && sha256(audit) !== expectedAudit) throw new Error('audit SHA mismatch');
  if (baseline && expectedBaseline && sha256(baseline) !== expectedBaseline) throw new Error('baseline SHA mismatch');
  const validate = require(path.join(replay, 'tools', 'validate-release-artifact.js'));
  const validation = validate.validate(candidate);
  write(path.join(out, 'candidate-integrity.json'), validation);
  if (validation.status !== 'ok') throw new Error('candidate ZIP integrity validation failed');
  const fixture = path.join(out, 'fixture');
  const externalCwd = path.join(out, 'external-cwd');
  const zip = validate.readZipEntries(candidate);
  ensure(fixture);
  ensure(externalCwd);
  for (const entry of zip.entries) {
    if (entry.name.endsWith('/')) continue;
    const destination = safeOutput(fixture, entry.name);
    ensure(path.dirname(destination));
    fs.writeFileSync(destination, entry.body);
  }
  const knowledge = path.join(fixture, '.knowledge');
  if (!fs.existsSync(knowledge)) throw new Error('candidate extraction has no .knowledge root');
  write(path.join(out, 'environment.json'), {
    schema_version: 'rc52-os-node-environment.v1', os: osName, platform: process.platform, arch: process.arch, node: process.version, node_major: Number(nodeMajor), source_commit: sourceCommit,
    candidate_sha256: candidateHash, audit_sha256: audit ? sha256(audit) : null, baseline_sha256: baseline ? sha256(baseline) : null,
    external_harness: true, node_path: process.env.NODE_PATH || '', source_root_environment_variables_present: ROOT_ENV.filter((name) => Boolean(process.env[name]))
  });
  checkSyntax(knowledge);
  const before = run('install-check-before', process.execPath, [path.join(knowledge, 'tools', 'install-check.js'), '--json'], { cwd: fixture });
  const beforeJson = parseJson(before.stdout, 'install-check-before'); write(path.join(out, 'install-check-before.json'), beforeJson);
  const selfTests = run('shipped-self-tests', process.execPath, [path.join(replay, 'tools', 'run-shipped-self-tests.js'), '--artifact', candidate, '--out', path.join(out, 'self-tests.json')], { cwd: externalCwd, timeout: 600000 });
  const selfReport = JSON.parse(fs.readFileSync(path.join(out, 'self-tests.json'), 'utf8'));
  if (selfReport.status !== 'pass' || selfReport.passed !== 26 || selfReport.failed !== 0) throw new Error('external shipped self-tests are not 26/26 pass');
  const integrations = run('install-agent-integrations', process.execPath, [path.join(knowledge, 'tools', 'install-agent-integrations.js'), '--all', '--confirm-all', '--no-package-scripts'], { cwd: fixture, timeout: 300000 });
  verifyIntegrations(fixture, integrations);
  const after = run('install-check-after', process.execPath, [path.join(knowledge, 'tools', 'install-check.js'), '--json'], { cwd: fixture });
  const afterJson = parseJson(after.stdout, 'install-check-after'); write(path.join(out, 'install-check-after.json'), afterJson);
  const flowImport = run('flow-import', process.execPath, [path.join(knowledge, 'tools', 'flow.js'), 'import', '--json', '--no-color'], { cwd: fixture, timeout: 600000 });
  const flowRelease = run('flow-release', process.execPath, [path.join(knowledge, 'tools', 'flow.js'), 'release', '--json', '--no-color'], { cwd: fixture, timeout: 600000 });
  const doctor = run('doctor', process.execPath, [path.join(knowledge, 'tools', 'doctor.js'), '--json'], { cwd: fixture, timeout: 300000 });
  const inspectorBuild = run('inspector-build', process.execPath, [path.join(knowledge, 'tools', 'build-visual-inspector.js')], { cwd: fixture, timeout: 300000 });
  await exerciseInspector(fixture);
  const routing = run('task-routing', process.execPath, [path.join(knowledge, 'tools', 'task-routing.js'), 'create', '--task', 'RC52 compatibility matrix', '--scope-path', '.knowledge/tools/flow.js', '--json'], { cwd: fixture, timeout: 300000 });
  const field = run('field-report-start', process.execPath, [path.join(knowledge, 'tools', 'field-report.js'), 'start', '--new', '--json'], { cwd: fixture, timeout: 300000 });
  inspectLocks(fixture);
  let upgrade = { status: 'not_run_by_scope', reason: 'exact upgrade runs on Node 22 once per OS', baseline_sha256: baseline ? sha256(baseline) : null };
  if (upgradeEnabled) {
    const result = run('exact-upgrade', process.execPath, [path.join(replay, 'tools', 'conformance-install-smoke.js'), candidate, '--previous-artifact', baseline, '--json'], { cwd: externalCwd, timeout: 600000 });
    upgrade = parseJson(result.stdout, 'exact-upgrade');
    if (upgrade.status !== 'pass') throw new Error('exact upgrade report is not pass');
  }
  write(path.join(out, 'upgrade-report.json'), upgrade);
  const workflow = { status: 'pass', flow_import: parseJson(flowImport.stdout, 'flow-import'), flow_release: parseJson(flowRelease.stdout, 'flow-release'), doctor: parseJson(doctor.stdout, 'doctor'), inspector_build: inspectorBuild.status, task_routing: parseJson(routing.stdout, 'task-routing'), field_report: parseJson(field.stdout, 'field-report-start') };
  write(path.join(out, 'workflow-report.json'), workflow);
  write(path.join(out, 'commands.json'), { schema_version: 'rc52-matrix-commands.v1', commands });
  const result = { schema_version: 'rc52-os-node-cell.v1', status: 'pass', classification: 'candidate', candidate_sha256: candidateHash, tests: { shipped_self_tests: `${selfReport.passed}/26`, integration_runtimes: RUNTIMES.length, upgrade: upgrade.status }, command_count: commands.length, active_locks: 0 };
  write(path.join(out, 'result.json'), result);
  const checksumFiles = walk(out, (file) => !file.endsWith('checksums.sha256')).map((file) => portable(path.relative(out, file))).sort();
  fs.writeFileSync(path.join(out, 'checksums.sha256'), checksumFiles.map((relative) => `${sha256(path.join(out, ...relative.split('/')))}  ${relative}`).join('\n') + '\n', 'utf8');
}

main().catch((error) => {
  try {
    write(path.join(out, 'commands.json'), { schema_version: 'rc52-matrix-commands.v1', commands });
    write(path.join(out, 'result.json'), { schema_version: 'rc52-os-node-cell.v1', status: 'fail', classification: 'candidate_or_harness_unclassified', error: { message: error.message, stack: error.stack || null }, command_count: commands.length });
  } catch (_) {}
  process.stderr.write(`${error.stack || error.message}\n`);
  process.exitCode = 1;
});
