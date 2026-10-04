#!/usr/bin/env node
'use strict';

const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const http = require('http');
const os = require('os');
const path = require('path');
const { spawn } = require('child_process');
const { PassThrough } = require('stream');
const { readJsonBody, MAX_JSON_BODY_BYTES } = require('./lib/inspector-http');
const { runAction, getRun } = require('./lib/action-runner');
const { createActionServer } = require('./lib/local-action-server');
const { runOne } = require('./flow');
const routing = require('./lib/task-routing');
const { resolveEffectiveTaskRoutingState } = require('./lib/task-routing-state');
const { systemVersion } = require('./lib/system-version');

const systemRoot = path.resolve(__dirname, '..');
const checks = [];
function check(name, fn) { fn(); checks.push(name); }
function write(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, typeof value === 'string' ? value : JSON.stringify(value));
}
function makeContext(root, name) {
  const targetRoot = path.join(root, name);
  const knowledge = path.join(targetRoot, '.knowledge');
  fs.mkdirSync(knowledge, { recursive: true });
  return { mode: 'repo', systemRoot, targetRoot, projectKnowledgeRoot: knowledge, stateRoot: knowledge, repoId: 'inspector-safety', agentId: 'inspector-safety', warnings: [], git: { changed_files: [] } };
}
function treeSnapshot(root) {
  const rows = [];
  function walk(dir) {
    for (const name of fs.readdirSync(dir).sort()) {
      const file = path.join(dir, name);
      const st = fs.lstatSync(file, { bigint: true });
      const row = { path: path.relative(root, file), type: st.isSymbolicLink() ? 'link' : st.isDirectory() ? 'dir' : 'file', mtime_ns: String(st.mtimeNs), ctime_ns: String(st.ctimeNs) };
      if (st.isFile()) row.sha256 = crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
      if (st.isSymbolicLink()) row.target = fs.readlinkSync(file);
      rows.push(row);
      if (st.isDirectory()) walk(file);
    }
  }
  walk(root);
  return rows;
}
function request(port, method, requestPath, token, rawBody, headers = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ hostname: '127.0.0.1', port, method, path: requestPath, headers: {
      ...(token ? { authorization: `Bearer ${token}` } : {}),
      ...(rawBody !== undefined ? { 'content-type': 'application/json', ...(!headers['transfer-encoding'] ? { 'content-length': Buffer.byteLength(rawBody) } : {}) } : {}),
      ...headers
    } }, (res) => {
      let body = '';
      res.on('data', (chunk) => { body += chunk; });
      res.on('end', () => {
        let json = null;
        try { json = JSON.parse(body); } catch {}
        resolve({ status: res.statusCode, body, json });
      });
    });
    req.setTimeout(10000, () => req.destroy(new Error('HTTP request timed out')));
    req.on('error', reject);
    if (rawBody !== undefined) req.write(rawBody);
    req.end();
  });
}
async function waitFor(predicate, label, duration = 5000) {
  const deadline = Date.now() + duration;
  while (Date.now() < deadline) {
    const value = predicate();
    if (value) return value;
    await new Promise(resolve => setTimeout(resolve, 25));
  }
  throw new Error(`Timed out: ${label}`);
}
async function stop(child) {
  if (child.exitCode !== null || child.signalCode !== null) return;
  child.kill('SIGTERM');
  try { await waitFor(() => child.exitCode !== null || child.signalCode !== null, 'server termination'); }
  catch (error) { child.kill('SIGKILL'); throw error; }
}
function seedRouting(context) {
  const k = context.projectKnowledgeRoot;
  const modules = [{ module_id: 'probe', path: 'src/', card: '.knowledge/modules/probe.json', key_files: ['src/probe.js'], purpose: 'fixture probe' }];
  write(path.join(context.targetRoot, 'src/probe.js'), 'module.exports = true;\n');
  write(path.join(k, 'config.yaml'), 'updates:\n  enabled: false\n  auto_check_on_inspector_open: false\n');
  write(path.join(k, 'modules/module_registry.json'), { modules });
  write(path.join(k, 'modules/probe.json'), modules[0]);
  write(path.join(k, 'project_index.json'), { project_name: 'Inspector regression', modules, primary_source_of_truth: 'code', task_routing: [] });
  write(path.join(k, 'maintenance/routing_bundle.json'), { schema_version: 'knowledge-routing-bootstrap.v1', workspace: { id: 'fixture' }, global_health: { status: 'healthy' }, task_routing: {}, pointers: {} });
  write(path.join(k, 'maintenance/trust_report.json'), { modules: { trusted: ['probe'] }, module_statuses: [{ module_id: 'probe', trust_status: 'trusted' }] });
  write(path.join(k, 'maintenance/wiki_lint_report.json'), { structural_status: 'healthy' });
  write(path.join(k, 'maps/wiki_graph.json'), { nodes: [], edges: [], structural_status: 'healthy', broken_edge_count: 0 });
  write(path.join(k, 'maps/critical_paths.json'), { paths: [] });
  write(path.join(k, 'maintenance/quality_report.json'), { status: 'healthy', quality_score: 100 });
  write(path.join(k, 'maintenance/repair_queue.json'), { queue: [] });
  write(path.join(k, 'freshness.json'), { tracked_files: [] });
  return routing.create(context, { task: 'Inspect probe source', modules: ['probe'], paths: ['src/probe.js'], scopeSource: 'explicit' });
}

async function main() {
  const incomplete = new PassThrough();
  incomplete.headers = { 'content-length': MAX_JSON_BODY_BYTES + 1 };
  const drainStarted = Date.now();
  const boundedDrain = readJsonBody(incomplete);
  // Keep the unit fixture alive just as a real HTTP socket would be.
  const keepAlive = setInterval(() => {}, 100);
  try {
    await assert.rejects(boundedDrain, error => error.code === 'request_body_too_large' && error.statusCode === 413);
    check('incomplete oversized body rejects within a bounded drain window', () => assert(Date.now() - drainStarted < 4000));
    incomplete.emit('error', new Error('late transport failure'));
    check('late transport failure after drain timeout remains handled', () => assert.equal(incomplete.listenerCount('error'), 1));
  } finally { clearInterval(keepAlive); incomplete.destroy(); }
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge-inspector-safety-'));
  let child = null;
  let local = null;
  try {
    const actionContext = makeContext(root, 'actions');
    actionContext.systemRoot = path.join(root, 'action-system');
    const script = path.join(actionContext.systemRoot, 'tools/doctor.js');
    write(script, 'console.log(JSON.stringify({status:"pass"}));\n');
    const passed = runAction(actionContext, 'doctor.run');
    check('action executes systemRoot tool with separate project data root', () => assert.equal(passed.status, 'passed'));
    check('action evidence and in-memory run agree', () => {
      assert.equal(getRun(passed.run_id).status, 'passed');
      const saved = JSON.parse(fs.readFileSync(path.join(path.dirname(passed.stdout_path), 'run.json')));
      assert.equal(saved.status, passed.status);
      assert.equal(saved.run_id, passed.run_id);
    });
    for (const [label, output] of [['failed report', '{"status":"failed","ok":false}'], ['malformed report', '{"status":'], ['null report', 'null'], ['empty report', '']]) {
      write(script, `process.stdout.write(${JSON.stringify(output)});\n`);
      const result = runAction(actionContext, 'doctor.run');
      check(`action fails closed for ${label} with exit zero`, () => { assert.equal(result.exit_code, 0); assert.equal(result.status, 'failed'); assert(result.semantic_errors.length); });
    }
    write(script, 'console.log(JSON.stringify({status:"pass"})); process.exitCode = 7;\n');
    check('nonzero action exit cannot pass through a pass report', () => assert.equal(runAction(actionContext, 'doctor.run').status, 'failed'));
    const unknown = runAction(actionContext, 'removed.action');
    check('unknown action remains blocked', () => assert.equal(unknown.status, 'blocked'));
    for (const stdout of ['{"status":', '', 'null', '[]', '{"status":"failed"}']) {
      const result = runOne('doctor.js', actionContext, { spawnSync: () => ({ status: 0, signal: null, stdout, stderr: '' }) });
      check(`flow rejects invalid or negative evidence ${JSON.stringify(stdout)}`, () => assert.equal(result.success, false));
    }
    check('flow accepts a valid successful report', () => assert.equal(runOne('doctor.js', actionContext, { spawnSync: () => ({ status: 0, signal: null, stdout: '{"status":"pass"}', stderr: '' }) }).success, true));

    write(script, 'console.log(JSON.stringify({status:"failed",ok:false}));\n');
    check('legacy local server rejects external bind before listen', () => assert.throws(() => createActionServer({ knowledgeRoot: actionContext.projectKnowledgeRoot, host: '0.0.0.0' }), /127\.0\.0\.1/));
    local = createActionServer({ knowledgeRoot: actionContext.projectKnowledgeRoot, systemRoot: actionContext.systemRoot, repoRoot: actionContext.targetRoot, port: 0, quiet: true });
    const localServer = local.start();
    await new Promise((resolve, reject) => { localServer.once('listening', resolve); localServer.once('error', reject); });
    const localPort = localServer.address().port;
    const localRun = await request(localPort, 'POST', '/api/actions/doctor.run/run', local.token, '{}');
    check('legacy local server executes real command and preserves failure', () => { assert.equal(localRun.status, 500); assert.equal(localRun.json.run.status, 'failed'); });
    const localBad = await request(localPort, 'POST', '/api/actions/doctor.run/run', local.token, '{');
    check('legacy local server rejects malformed request JSON', () => assert.equal(localBad.status, 400));
    const localHost = await request(localPort, 'GET', '/api/session', null, undefined, { host: `foreign.invalid:${localPort}` });
    check('legacy session bootstrap rejects foreign Host', () => assert.equal(localHost.status, 403));
    await new Promise(resolve => local.stop(resolve)); local = null;

    const live = makeContext(root, 'live');
    const created = seedRouting(live);
    const beforeInspect = treeSnapshot(live.targetRoot);
    const inspected = routing.inspectTask(live, created.task_scope_hash, { readOnly: true });
    const effective = resolveEffectiveTaskRoutingState({ context: live, taskScopeHash: created.task_scope_hash, readOnly: true });
    check('read-only task inspection recognizes valid canonical current', () => { assert.equal(inspected.status, 'ok'); assert(effective.pointer_consistent); });
    check('read-only task interpretation performs no filesystem writes', () => assert.deepStrictEqual(treeSnapshot(live.targetRoot), beforeInspect));
    let stdout = ''; let stderr = '';
    child = spawn(process.execPath, [path.join(systemRoot, 'tools/serve-inspector.js'), '--port', '0', '--system-root', systemRoot, '--target-root', live.targetRoot, '--project-knowledge-root', live.projectKnowledgeRoot, '--state-root', live.stateRoot], {
      cwd: live.targetRoot, env: { ...process.env, KNOWLEDGE_UPDATE_DISABLE_ON_LAUNCH: '1', KNOWLEDGE_INSPECTOR_NO_OPEN: '1' }, stdio: ['ignore', 'pipe', 'pipe']
    });
    child.stdout.on('data', chunk => { stdout += chunk; }); child.stderr.on('data', chunk => { stderr += chunk; });
    const startup = await waitFor(() => {
      if (child.exitCode !== null) throw new Error(`Inspector exited ${child.exitCode}: ${stderr}`);
      try { return JSON.parse(stdout); } catch { return null; }
    }, 'live Inspector startup');
    const port = startup.port;
    check('port zero is reported as the actual ephemeral port', () => { assert(port > 0); assert(startup.url.includes(`:${port}/`)); });
    const session = await request(port, 'GET', '/api/session');
    const token = session.json.token;
    check('session port matches launcher port', () => assert.equal(session.json.port, port));
    const beforeGet = treeSnapshot(live.targetRoot);
    for (const url of ['/', '/index.html', '/api/state', '/api/actions', '/api/trust', '/api/repair', '/api/settings/repair-on-touch', '/api/team', '/api/git/branches', '/api/update/status', '/api/files/open?path=src%2Fprobe.js']) {
      const result = await request(port, 'GET', url, token);
      check(`read-only GET ${url} succeeds`, () => assert.equal(result.status, 200, result.body));
    }
    check('all successful GET routes preserve file bytes and metadata', () => assert.deepStrictEqual(treeSnapshot(live.targetRoot), beforeGet));
    const refresh = await request(port, 'GET', '/api/update/status?refresh=1', token);
    check('update refresh cannot mutate from GET', () => { assert.equal(refresh.status, 405); assert.deepStrictEqual(treeSnapshot(live.targetRoot), beforeGet); });
    check('Inspector manual update control uses POST check endpoint', () => {
      const renderer = fs.readFileSync(path.join(systemRoot, 'tools/build-visual-inspector.js'), 'utf8');
      assert(renderer.includes("updateApi('/api/update/check',{method:'POST'"));
      assert(!renderer.includes('/api/update/status?refresh=1'));
    });
    const noToken = await request(port, 'GET', '/api/state');
    check('protected GET requires a session token', () => assert.equal(noToken.status, 401));
    for (const [label, headers] of [['foreign Host', { host: `foreign.invalid:${port}` }], ['foreign Origin', { origin: 'http://foreign.invalid' }], ['null Origin', { origin: 'null' }]]) {
      const result = await request(port, 'GET', '/api/session', null, undefined, headers);
      check(`session bootstrap rejects ${label}`, () => { assert.equal(result.status, 403); assert(!result.body.includes(token)); });
    }
    const beforeBadBody = treeSnapshot(live.targetRoot);
    for (const raw of ['{"user_mode":', 'null', '[]', 'true', '"simple"']) {
      const result = await request(port, 'POST', '/api/settings/onboarding', token, raw);
      check(`malformed onboarding body is rejected ${JSON.stringify(raw)}`, () => { assert.equal(result.status, 400); assert.deepStrictEqual(treeSnapshot(live.targetRoot), beforeBadBody); });
    }
    const large = await request(port, 'POST', '/api/settings/onboarding', token, JSON.stringify({ value: 'x'.repeat(1024 * 1024) }));
    check('oversize POST returns 413 without mutation', () => { assert.equal(large.status, 413); assert.deepStrictEqual(treeSnapshot(live.targetRoot), beforeBadBody); });
    const chunked = await request(port, 'POST', '/api/settings/onboarding', token, JSON.stringify({ value: 'x'.repeat(MAX_JSON_BODY_BYTES) }), { 'transfer-encoding': 'chunked' });
    check('chunked oversize POST returns 413 without mutation', () => { assert.equal(chunked.status, 413); assert.deepStrictEqual(treeSnapshot(live.targetRoot), beforeBadBody); });
    const missing = await request(port, 'GET', '/api/files/open?path=..%2Foutside.txt', token);
    check('file open traversal is rejected', () => assert.equal(missing.status, 404));
    const saved = await request(port, 'POST', '/api/settings/onboarding', token, '{"user_mode":"advanced","agent_id":"audit"}');
    check('valid onboarding POST remains functional', () => { assert.equal(saved.status, 200, saved.body); assert.equal(saved.json.settings.operator_profile.user_mode, 'advanced'); });
    const shutdown = await request(port, 'POST', '/api/shutdown', token, '{}');
    check('authenticated shutdown remains functional', () => assert.equal(shutdown.status, 200));
    await waitFor(() => child.exitCode !== null, 'Inspector shutdown');
    check('Inspector exits cleanly', () => assert.equal(child.exitCode, 0));
    child = null;
    console.log(JSON.stringify({ schema_version: systemVersion(), status: 'pass', checks_total: checks.length, checks }, null, 2));
  } finally {
    if (child) await stop(child);
    if (local) await new Promise(resolve => local.stop(resolve));
    fs.rmSync(root, { recursive: true, force: true });
  }
}
main().catch(error => { console.error(JSON.stringify({ status: 'failed', checks_total: checks.length, checks, error: error.stack || error.message }, null, 2)); process.exitCode = 1; });
