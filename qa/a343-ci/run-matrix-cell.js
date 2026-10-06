#!/usr/bin/env node
'use strict';

const crypto = require('crypto');
const fs = require('fs');
const http = require('http');
const net = require('net');
const os = require('os');
const path = require('path');
const { spawn, spawnSync } = require('child_process');

const RUNTIMES = ['codex','claude','opencode','openclaw','hermes','gemini','copilot','devin','windsurf','continue','roo','aider'];
const PINNED_CANDIDATE_SHA256 = '42554f5f93fd0aa08098bf6547768876a185f4ae71b1c8f3d44fb9520699d499';
const PINNED_BASELINE_SHA256 = 'b7f4e912e8bcffff1e2ffb35756d68850a980b6b841306ac7a51c9d88fc59d79';
const EXPECTED_SELF_TESTS = 44;
const EXPECTED_SYNTAX_CHECKS = 144;

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
  const env = {
    PATH: process.env.PATH || '',
    HOME: process.env.HOME || process.env.USERPROFILE || os.homedir(),
    TMPDIR: os.tmpdir(), TMP: os.tmpdir(), TEMP: os.tmpdir(),
    LANG: process.env.LANG || 'C.UTF-8', LC_ALL: process.env.LC_ALL || 'C.UTF-8',
    NODE_PATH: '', CI: 'true',
    KNOWLEDGE_INSPECTOR_NO_OPEN: '1', KNOWLEDGE_FLOW_NO_OPEN: '1',
    GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: path.join(out, 'git-empty-config')
  };
  for (const name of ['SystemRoot', 'windir', 'COMSPEC', 'PATHEXT', 'USERPROFILE', 'APPDATA', 'LOCALAPPDATA']) {
    if (process.env[name]) env[name] = process.env[name];
  }
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
function stableStringify(value) {
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}
function manifestDigest(manifest) {
  return crypto.createHash('sha256').update(stableStringify(manifest), 'utf8').digest('hex');
}
function readContainedJson(root, relative, label) {
  const file = safeOutput(root, relative);
  if (!fs.existsSync(file)) throw new Error(`${label} is missing: ${relative}`);
  return { file, value: JSON.parse(fs.readFileSync(file, 'utf8')) };
}
function verifyAuditReplay(resultsFile, auditRunnerFile, candidateSha, zipEntries) {
  const replayRoot = path.dirname(resultsFile);
  const { value: receipt } = readContainedJson(replayRoot, path.basename(resultsFile), 'installed audit replay receipt');
  const failures = [];
  const fail = (message) => failures.push(message);
  if (receipt.status !== 'pass' || receipt.fatal_error) fail('audit replay is not a clean pass');
  if (receipt.archive_sha256 !== PINNED_CANDIDATE_SHA256 || receipt.archive_sha256_after !== PINNED_CANDIDATE_SHA256 || receipt.archive_unchanged !== true) fail('audit replay archive fingerprint is not the pinned immutable candidate');
  if (candidateSha !== PINNED_CANDIDATE_SHA256) fail('matrix candidate SHA is not the pinned 3.4.3 ZIP');
  if (receipt.source_unchanged !== true || (receipt.source_changed_paths || []).length !== 0) fail('audit replay mutated its installed snapshot');
  if (receipt.source_manifest_sha256_before !== receipt.source_manifest_sha256_after) fail('audit replay before/after source manifest fingerprints differ');
  if (receipt.node_binary_unchanged !== true || receipt.node_binary_sha256_before !== receipt.node_binary_sha256_after) fail('audit replay Node binary fingerprint changed');
  if (receipt.offline_auto_updates !== true) fail('audit replay did not use the offline auto-updates fixture profile');
  if (receipt.self_tests?.total !== EXPECTED_SELF_TESTS || receipt.self_tests?.passed !== EXPECTED_SELF_TESTS || receipt.self_tests?.failed !== 0 || receipt.self_tests?.skipped !== 0 || receipt.self_tests?.not_run !== 0) fail('audit replay self-test totals are not exactly 44/44');
  if (receipt.syntax_checks?.total !== EXPECTED_SYNTAX_CHECKS || receipt.syntax_checks?.passed !== EXPECTED_SYNTAX_CHECKS || receipt.syntax_checks?.failed !== 0 || receipt.syntax_checks?.not_run !== 0) fail('audit replay syntax totals are not exactly 144/144');

  const inventoryPath = receipt.inventory || 'inventory.json';
  const { value: inventory } = readContainedJson(replayRoot, inventoryPath, 'audit replay inventory');
  const { value: auditEnvironment } = readContainedJson(replayRoot, receipt.environment || 'environment.json', 'audit replay environment');
  const selfTests = inventory.self_tests;
  const syntaxChecks = inventory.syntax_checks;
  if (inventory.schema_version !== 'knowledge-artifact-replay-inventory.v1' || inventory.package_name !== 'dot-knowledge' || inventory.package_version !== '3.4.3') fail('audit inventory is not for the 3.4.3 package');
  if (!Array.isArray(selfTests) || selfTests.length !== EXPECTED_SELF_TESTS || new Set(selfTests).size !== EXPECTED_SELF_TESTS) fail('audit inventory self-test paths are not exactly 44 unique entries');
  if (!Array.isArray(syntaxChecks) || syntaxChecks.length !== EXPECTED_SYNTAX_CHECKS || new Set(syntaxChecks).size !== EXPECTED_SYNTAX_CHECKS) fail('audit inventory syntax paths are not exactly 144 unique entries');
  const currentNodeSha = sha256File(process.execPath);
  if (auditEnvironment.runner_sha256 !== sha256File(auditRunnerFile)) fail('audit receipt runner SHA does not match the checked-out audit runner');
  if (auditEnvironment.node_reported_identity?.platform !== process.platform || auditEnvironment.node_reported_identity?.version !== process.version || auditEnvironment.node_binary_sha256 !== currentNodeSha) fail('audit receipt runtime identity does not match the current matrix cell');
  const archiveNames = new Set(zipEntries.filter((entry) => !entry.name.endsWith('/')).map((entry) => entry.name));
  const archiveSelfTests = JSON.parse(zipEntries.find((entry) => entry.name === '.knowledge/install-manifest.json')?.body.toString('utf8') || '{}')?.release_contract?.public_self_test_paths;
  if (!Array.isArray(archiveSelfTests) || stableStringify(archiveSelfTests.slice().sort()) !== stableStringify(selfTests.slice().sort())) fail('audit inventory self-test list does not match the candidate install manifest');
  const archiveSyntax = Array.from(archiveNames).filter((name) => name.startsWith('.knowledge/') && name.endsWith('.js')).map((name) => name.slice('.knowledge/'.length)).sort();
  if (stableStringify(archiveSyntax) !== stableStringify(syntaxChecks.slice().sort())) fail('audit inventory syntax list does not match JavaScript files shipped in the candidate');

  const before = readContainedJson(replayRoot, receipt.source_manifest_before, 'audit replay source manifest').value;
  const after = readContainedJson(replayRoot, receipt.source_manifest_after, 'audit replay after-source manifest').value;
  if (stableStringify(before) !== stableStringify(after) || manifestDigest(before) !== receipt.source_manifest_sha256_before || manifestDigest(after) !== receipt.source_manifest_sha256_after) fail('audit source manifest content or digest is inconsistent');
  const archiveFiles = new Map(zipEntries.filter((entry) => !entry.name.endsWith('/') && entry.name.startsWith('.knowledge/')).map((entry) => [entry.name.slice('.knowledge/'.length), entry.body]));
  if (Object.keys(before).length !== archiveFiles.size) fail('audit source manifest entry count differs from candidate ZIP');
  for (const [relative, record] of Object.entries(before)) {
    const body = archiveFiles.get(relative);
    if (!body || body.length !== record.bytes || crypto.createHash('sha256').update(body).digest('hex') !== record.sha256) {
      fail(`audit source manifest does not match candidate bytes: ${relative}`);
      break;
    }
  }

  const commands = receipt.commands;
  if (!Array.isArray(commands) || commands.length !== 1 + EXPECTED_SELF_TESTS + EXPECTED_SYNTAX_CHECKS) fail('audit replay command list does not contain exactly 189 commands');
  const byCategory = { runtime: [], 'self-test': [], syntax: [] };
  for (const item of commands || []) {
    if (!byCategory[item.category]) { fail(`unexpected audit command category: ${item.category}`); continue; }
    byCategory[item.category].push(item);
    for (const [stream, field] of [['stdout', 'stdout_sha256'], ['stderr', 'stderr_sha256']]) {
      try {
        const file = safeOutput(replayRoot, item[stream]);
        if (sha256File(file) !== item[field]) fail(`audit ${stream} hash mismatch: ${item.name}`);
      } catch (error) { fail(`audit ${stream} unavailable: ${item.name}: ${error.message}`); }
    }
    try {
      const saved = readContainedJson(replayRoot, item.result_file, `saved audit result ${item.name}`).value;
      if (saved.status !== item.status || saved.exit_code !== item.exit_code || item.status !== 'pass' || item.exit_code !== 0 || saved.timed_out || saved.execution_error || (saved.semantic_failures || []).length) fail(`audit result is not a clean pass: ${item.name}`);
      if (item.category === 'self-test' && (!['pass', 'passed'].includes(saved.reported_summary?.status) || !selfTests.includes(saved.source_test))) fail(`audit self-test semantic receipt is invalid: ${item.name}`);
      if (item.category === 'self-test') {
        const source = before[saved.source_test];
        if (!source || source.sha256 !== saved.source_test_sha256) fail(`audit test source digest does not match frozen archive: ${item.name}`);
        const offline = (saved.configuration_overrides || []).some((override) => override.path === '.knowledge/config.yaml' && override.setting === 'updates.enabled' && override.after_value === false);
        if (!offline) fail(`audit self-test did not record updates.enabled=false: ${item.name}`);
      }
      if (item.category === 'syntax' && (!syntaxChecks.includes(saved.command?.[2]) || saved.command?.[1] !== '--check')) fail(`audit syntax receipt is invalid: ${item.name}`);
    } catch (error) { fail(`audit result unavailable: ${item.name}: ${error.message}`); }
  }
  if (byCategory.runtime.length !== 1 || byCategory['self-test'].length !== EXPECTED_SELF_TESTS || byCategory.syntax.length !== EXPECTED_SYNTAX_CHECKS) {
    fail('audit replay category counts do not match 1 runtime, 44 self-tests, and 144 syntax checks');
  }
  const actualTestPaths = byCategory['self-test'].map((item) => {
    try { return readContainedJson(replayRoot, item.result_file, item.name).value.source_test; } catch { return null; }
  });
  if (stableStringify(actualTestPaths.slice().sort()) !== stableStringify(selfTests.slice().sort())) fail('executed audit test paths do not match the 44-test inventory');
  const actualSyntaxPaths = byCategory.syntax.map((item) => {
    try { return readContainedJson(replayRoot, item.result_file, item.name).value.command?.[2]; } catch { return null; }
  });
  if (stableStringify(actualSyntaxPaths.slice().sort()) !== stableStringify(syntaxChecks.slice().sort())) fail('executed audit syntax paths do not match the 144-file inventory');
  if (failures.length) throw new Error(`installed audit replay verification failed: ${failures.slice(0, 8).join('; ')}`);
  return {
    status: 'pass', candidate_sha256: candidateSha,
    replay_results_sha256: sha256File(resultsFile),
    inventory_sha256: sha256File(path.join(replayRoot, inventoryPath)),
    source_manifest_sha256: receipt.source_manifest_sha256_before,
    self_tests: EXPECTED_SELF_TESTS, syntax_checks: EXPECTED_SYNTAX_CHECKS,
    expected_tests: selfTests.slice().sort(),
    executed_tests: actualTestPaths.slice().sort(),
    test_command_receipts: byCategory['self-test'].map((item) => {
      const saved = readContainedJson(replayRoot, item.result_file, item.name).value;
      return { test: saved.source_test, status: saved.status, exit_code: saved.exit_code, duration_seconds: saved.duration_seconds, stdout_sha256: saved.stdout_sha256, stderr_sha256: saved.stderr_sha256, stdout: item.stdout, stderr: item.stderr };
    }),
    external_replay_platform: process.platform, external_replay_node: process.version,
    offline_auto_updates: true, verified_commands: commands.length,
    verified_raw_streams: commands.length * 2,
    source_unchanged: true, archive_unchanged: true, node_binary_unchanged: true,
    replay_results: path.basename(resultsFile)
  };
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
    request.setTimeout(options.timeoutMs || 2000, () => request.destroy(new Error(`Inspector request timed out: ${pathname}`)));
    request.end(options.body || null);
  });
}
async function waitForChildExit(exitPromise, timeoutMs) {
  let timer;
  const result = await Promise.race([
    exitPromise.then(() => true),
    new Promise((resolve) => { timer = setTimeout(() => resolve(false), timeoutMs); })
  ]);
  if (timer) clearTimeout(timer);
  return result;
}

const candidate = required('--candidate');
const replay = required('--replay');
const replayResultsFile = required('--replay-results');
const auditRunnerFile = required('--audit-runner');
const baseline = arg('--baseline') ? path.resolve(arg('--baseline')) : null;
const out = required('--out');
const osLabel = arg('--os') || process.platform;
const nodeLabel = arg('--node-major') || process.versions.node.split('.')[0];
const upgradeEnabled = boolArg('--upgrade');
const offlineUpdates = process.argv.includes('--offline-auto-updates');
const githubSha = arg('--github-sha') || process.env.GITHUB_SHA || null;
const githubRunId = arg('--run-id') || process.env.GITHUB_RUN_ID || null;
const expectedCandidate = arg('--expected-candidate') || PINNED_CANDIDATE_SHA256;
const expectedBaseline = arg('--expected-baseline') || PINNED_BASELINE_SHA256;

if (!offlineUpdates) throw new Error('--offline-auto-updates is required for the synthetic fixture');
if (expectedCandidate !== PINNED_CANDIDATE_SHA256) throw new Error('candidate expectation must be the canonical 3.4.3 SHA-256');
if (baseline && expectedBaseline !== PINNED_BASELINE_SHA256) throw new Error('baseline expectation must be the pinned 3.2.11 SHA-256');
if (process.env.GITHUB_ACTIONS === 'true' && (!/^[0-9a-f]{40}$/i.test(githubSha || '') || !/^\d+$/.test(githubRunId || ''))) {
  throw new Error('GitHub Actions run requires bound GITHUB_SHA and GITHUB_RUN_ID values');
}

if (fs.existsSync(out)) throw new Error(`refusing existing output directory: ${out}`);
ensure(out); ensure(path.join(out, 'stdout')); ensure(path.join(out, 'stderr'));
fs.writeFileSync(path.join(out, 'git-empty-config'), '', 'utf8');
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
    stdout_sha256: sha256File(path.join(out, 'stdout', `${id}.log`)),
    stderr_sha256: sha256File(path.join(out, 'stderr', `${id}.log`)),
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
  let serverError = null;
  const serverExited = new Promise((resolve) => {
    server.once('exit', (code, signal) => resolve({ code, signal }));
    server.once('error', (error) => { serverError = error; resolve({ error }); });
  });
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
    let exited = server.exitCode !== null || server.signalCode !== null || serverError !== null;
    if (!exited) {
      exited = await waitForChildExit(serverExited, 8000);
    }
    if (!exited) {
      server.kill('SIGTERM');
      exited = await waitForChildExit(serverExited, 2000);
    }
    if (!exited) {
      server.kill('SIGKILL');
      exited = await waitForChildExit(serverExited, 2000);
    }
    fs.writeFileSync(path.join(out, 'stdout', 'inspector-live.log'), stdout, 'utf8');
    fs.writeFileSync(path.join(out, 'stderr', 'inspector-live.log'), stderr, 'utf8');
    if (!exited) throw new Error('Inspector child remained alive after shutdown and bounded termination attempts');
    if (serverError) throw new Error(`Inspector child failed to start: ${serverError.message}`);
  }
  const report = { status: 'pass', port, state_ok: state.body.ok, shutdown_ok: shutdown.body.ok };
  writeJson(path.join(out, 'inspector-live.json'), report);
  commands.push({
    id: 'inspector-live', command: [process.execPath, '.knowledge/tools/serve-inspector.js', `--port=${port}`],
    cwd: portable(fixture), exit_code: 0, signal: null, duration_ms: null,
    stdout: 'stdout/inspector-live.log', stderr: 'stderr/inspector-live.log', spawn_error: null, status: 'pass'
  });
  commands[commands.length - 1].stdout_sha256 = sha256File(path.join(out, 'stdout', 'inspector-live.log'));
  commands[commands.length - 1].stderr_sha256 = sha256File(path.join(out, 'stderr', 'inspector-live.log'));
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
  if (candidateSha !== expectedCandidate || candidateSha !== PINNED_CANDIDATE_SHA256) throw new Error(`candidate SHA mismatch: ${candidateSha}`);
  if (baseline && sha256File(baseline) !== PINNED_BASELINE_SHA256) throw new Error('baseline SHA mismatch');
  if (upgradeEnabled && !baseline) throw new Error('--baseline is required when --upgrade=true');

  const replayVerification = verifyReplayManifest(replay);
  writeJson(path.join(out, 'replay-manifest-verification.json'), replayVerification);

  const validator = require(path.join(replay, 'tools', 'validate-release-artifact.js'));
  const validation = validator.validate(candidate);
  writeJson(path.join(out, 'candidate-validation.json'), validation);
  if (validation.status !== 'ok') throw new Error('candidate validation failed');
  const zip = validator.readZipEntries(candidate);
  const installedAudit = verifyAuditReplay(replayResultsFile, auditRunnerFile, candidateSha, zip.entries);
  writeJson(path.join(out, 'installed-audit-verification.json'), installedAudit);

  const fixture = path.join(out, 'fixture');
  const externalCwd = path.join(out, 'external-cwd');
  ensure(fixture); ensure(externalCwd);
  for (const entry of zip.entries) {
    if (entry.name.endsWith('/')) continue;
    const target = safeOutput(fixture, entry.name);
    ensure(path.dirname(target)); fs.writeFileSync(target, entry.body);
  }
  const knowledge = path.join(fixture, '.knowledge');
  if (!fs.existsSync(knowledge)) throw new Error('candidate has no .knowledge root');
  const configPath = path.join(knowledge, 'config.yaml');
  const configBefore = fs.readFileSync(configPath, 'utf8');
  const disabledConfig = configBefore.replace(/^(updates:\r?\n[ \t]+enabled:[ \t]*)true([ \t]*\r?\n)/m, '$1false$2');
  if (disabledConfig === configBefore || (configBefore.match(/^(updates:\r?\n[ \t]+enabled:[ \t]*)true([ \t]*\r?\n)/gm) || []).length !== 1) {
    throw new Error('synthetic fixture must have exactly one updates.enabled: true setting');
  }
  fs.writeFileSync(configPath, disabledConfig, 'utf8');
  const fixtureOfflineUpdates = {
    status: 'pass', path: '.knowledge/config.yaml', setting: 'updates.enabled',
    before: true, after: false, before_sha256: crypto.createHash('sha256').update(configBefore).digest('hex'),
    after_sha256: sha256File(configPath), fixture_only: true
  };
  writeJson(path.join(out, 'fixture-offline-updates.json'), fixtureOfflineUpdates);

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
  if (syntax.status !== 'pass' || syntax.checks_total !== EXPECTED_SYNTAX_CHECKS) throw new Error(`JavaScript syntax checks not exactly ${EXPECTED_SYNTAX_CHECKS}/${EXPECTED_SYNTAX_CHECKS}: ${syntax.passed}/${syntax.checks_total}`);

  const before = parseJson(run('install-check-before', process.execPath, [path.join(knowledge, 'tools', 'install-check.js'), '--json'], { cwd: fixture }).stdout, 'install-check-before');
  writeJson(path.join(out, 'install-check-before.json'), before);

  const selfTests = {
    schema_version: 'shipped-self-tests.v1', status: 'pass',
    evidence_scope: 'same_cell_frozen_installed_asset_replay',
    candidate_sha256: candidateSha,
    expected_tests: installedAudit.expected_tests,
    executed_tests: installedAudit.executed_tests,
    passed: installedAudit.self_tests, failed: 0,
    results: installedAudit.test_command_receipts,
    external_replay: {
      platform: installedAudit.external_replay_platform,
      node: installedAudit.external_replay_node,
      replay_results_sha256: installedAudit.replay_results_sha256,
      inventory_sha256: installedAudit.inventory_sha256
    }
  };
  if (selfTests.expected_tests.length !== EXPECTED_SELF_TESTS || selfTests.executed_tests.length !== EXPECTED_SELF_TESTS || selfTests.passed !== EXPECTED_SELF_TESTS || selfTests.failed !== 0) {
    throw new Error('preverified shipped self-test evidence is not exactly 44/44');
  }
  writeJson(path.join(out, 'self-tests.json'), selfTests);

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
  if (flowImport.overall_status !== 'ok' || flowImport.steps_ok !== flowImport.steps_total) throw new Error(`Flow import semantic failure: ${flowImport.overall_status || flowImport.status}`);
  const flowRelease = parseJson(run('flow-release', process.execPath, [path.join(knowledge, 'tools', 'flow.js'), 'release', '--json', '--no-color'], { cwd: fixture, timeout: 900000 }).stdout, 'flow-release');
  if (flowRelease.overall_status !== 'ok' || flowRelease.steps_ok !== flowRelease.steps_total) throw new Error(`Flow release semantic failure: ${flowRelease.overall_status || flowRelease.status}`);
  const doctor = parseJson(run('doctor', process.execPath, [path.join(knowledge, 'tools', 'doctor.js'), '--json'], { cwd: fixture }).stdout, 'doctor');
  if (['broken','failed'].includes(doctor.status)) throw new Error(`Doctor semantic failure: ${doctor.status}`);
  run('inspector-build', process.execPath, [path.join(knowledge, 'tools', 'build-visual-inspector.js')], { cwd: fixture });
  await exerciseInspector(fixture);
  const offlineSmokeCommands = [
    ['build-routing-bundle', 'tools/build-routing-bundle.js', ['--json']],
    ['build-wiki-graph', 'tools/build-wiki-graph.js', ['--json']],
    ['memory-provider-status-all', 'tools/memory-provider.js', ['status-all', '--json']],
    ['export-debug-bundle', 'tools/export-debug-bundle.js', ['--json']],
    ['export-pro-snapshot', 'tools/export-pro-snapshot.js', ['--json']],
    ['agent-session-report', 'tools/agent-session.js', ['report', '--json']],
    ['agent-footer', 'tools/agent-footer.js', ['--json']]
  ];
  const offlineSmoke = [];
  for (const [id, relative, args] of offlineSmokeCommands) {
    const output = run(id, process.execPath, [path.join(knowledge, relative), ...args], { cwd: fixture, timeout: 120000 }).stdout;
    const parsed = parseJson(output, id);
    if (parsed.status && ['failed', 'error', 'broken'].includes(parsed.status)) throw new Error(`${id} semantic failure: ${parsed.status}`);
    offlineSmoke.push({ id, status: parsed.status || 'exit_zero_json', sha256: sha256File(path.join(out, 'stdout', `${id}.log`)) });
  }
  writeJson(path.join(out, 'offline-smoke-report.json'), {
    status: offlineSmoke.length === offlineSmokeCommands.length ? 'pass' : 'fail',
    fixture_only: true, external_provider_install_or_setup: false,
    paid_calls: false, commands: offlineSmoke
  });
  const routing = parseJson(run('task-routing', process.execPath, [
    path.join(knowledge, 'tools', 'task-routing.js'), 'create', '--task', 'RC55 OS/Node compatibility matrix',
    '--scope-path', '.knowledge/tools/field-report.js', '--json'
  ], { cwd: fixture }).stdout, 'task-routing');
  const field = parseJson(run('field-report-start', process.execPath, [
    path.join(knowledge, 'tools', 'field-report.js'), 'start', '--new', '--json'
  ], { cwd: fixture }).stdout, 'field-report-start');
  if (field.status !== 'needs_user_input') throw new Error(`unexpected Field Report start status: ${field.status}`);

  const lockCode = "const path=require('path');const m=require(path.resolve('.knowledge/tools/lib/contained-lock-manager.js'));const c=require(path.resolve('.knowledge/tools/lib/path-context.js')).resolveKnowledgeContext([], {cwd:process.cwd()});const r=m.inspectContextLockSafety(c);console.log(JSON.stringify({status:r.status,message:r.message||null}));process.exit(r.status==='safe'?0:2);";
  const lockReport = parseJson(run('lock-safety-final', process.execPath, ['-e', lockCode], { cwd: fixture }).stdout, 'lock-safety-final');
  if (lockReport.status !== 'safe') throw new Error(`lock safety semantic failure: ${lockReport.status}`);
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
    task_routing: routing, field_report: field, inspector_live: 'pass', offline_smoke: offlineSmoke
  });
  writeJson(path.join(out, 'commands.json'), { schema_version: 'rc55-matrix-commands.v1', commands });
  writeJson(path.join(out, 'environment.json'), {
    schema_version: 'rc55-os-node-environment.v1', os_label: osLabel,
    platform: process.platform, arch: process.arch, node: process.version,
    requested_node_major: Number(nodeLabel), candidate_sha256: candidateSha,
    baseline_sha256: baseline ? sha256File(baseline) : null,
    external_audit_replay: {
      receipt_sha256: installedAudit.replay_results_sha256,
      runner_sha256: sha256File(auditRunnerFile),
      source_manifest_sha256: installedAudit.source_manifest_sha256,
      self_tests: installedAudit.self_tests, syntax_checks: installedAudit.syntax_checks,
      archive_unchanged: installedAudit.archive_unchanged,
      source_unchanged: installedAudit.source_unchanged,
      node_binary_unchanged: installedAudit.node_binary_unchanged
    },
    replay_manifest_sha256: replayVerification.manifest_sha256,
    fixture_offline_updates: fixtureOfflineUpdates,
    provider_setup_or_paid_calls: false,
    github_binding: { sha: githubSha, run_id: githubRunId }
  });
  const result = {
    schema_version: 'rc55-os-node-cell.v1', status: 'pass', classification: 'candidate',
    candidate_sha256: candidateSha,
    tests: {
      shipped_self_tests: `${selfTests.passed}/${selfTests.expected_tests.length}`,
      integrations: '12/12',
      offline_smoke_commands: offlineSmoke.length,
      upgrade: upgrade.status
    },
    command_count: commands.length, active_locks: 0,
    github_binding: { sha: githubSha, run_id: githubRunId }
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
